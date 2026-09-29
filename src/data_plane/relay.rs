//! Relaying an upstream body chunk by chunk with the idle deadline, usage
//! extraction, wire capture and end-of-exchange bookkeeping.

use std::pin::Pin;
use std::task::{Context, Poll, ready};
use std::time::Duration;

use bytes::Bytes;
use http::header::{CONNECTION, TE, TRAILER, TRANSFER_ENCODING, UPGRADE};
use http::{HeaderMap, HeaderName};
use http_body_util::combinators::BoxBody;
use hyper::body::{Body, Frame, Incoming, SizeHint};
use tokio::time::{Instant, Sleep};

use crate::capture::ExchangeCapture;

use super::usage::{Tokens, UsageExtractor};

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;
pub type ResponseBody = BoxBody<Bytes, BoxError>;

/// The connection-specific set never reaches the client.
pub fn strip_response_headers(headers: &mut HeaderMap) {
    let named: Vec<HeaderName> = headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(',').map(str::trim).map(str::to_ascii_lowercase))
        .filter_map(|n| n.parse().ok())
        .collect();
    for name in named.into_iter().chain([
        CONNECTION,
        HeaderName::from_static("keep-alive"),
        TRANSFER_ENCODING,
        UPGRADE,
        HeaderName::from_static("proxy-connection"),
        TE,
        TRAILER,
    ]) {
        headers.remove(&name);
    }
}

/// How a relayed body ended, for the audit record and usage attribution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyEnd {
    /// Upstream sent a clean end; the client got every byte.
    Complete(Tokens),
    /// Upstream failed mid-body or went idle; the client connection is dropped.
    Failed(Tokens),
    /// The client went away first; the upstream attempt is cancelled with it.
    Dropped(Tokens),
}

pub type OnEnd = Box<dyn FnOnce(BodyEnd) + Send + Sync>;

pub struct RelayBody {
    inner: Incoming,
    idle: Duration,
    deadline: Pin<Box<Sleep>>,
    usage: UsageExtractor,
    capture: Option<ExchangeCapture>,
    on_end: Option<OnEnd>,
}

impl RelayBody {
    pub fn new(
        inner: Incoming,
        idle: Duration,
        usage: UsageExtractor,
        capture: Option<ExchangeCapture>,
        on_end: OnEnd,
    ) -> Self {
        Self {
            inner,
            idle,
            deadline: Box::pin(tokio::time::sleep(idle)),
            usage,
            capture,
            on_end: Some(on_end),
        }
    }

    pub fn boxed(self) -> ResponseBody {
        BoxBody::new(self)
    }

    fn end(&mut self, how: fn(Tokens) -> BodyEnd) {
        if let Some(on_end) = self.on_end.take() {
            let tokens =
                std::mem::replace(&mut self.usage, UsageExtractor::for_content_type(None)).finish();
            on_end(how(tokens));
        }
    }
}

impl Body for RelayBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = &mut *self;
        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                // The idle deadline resets on every chunk.
                this.deadline.as_mut().reset(Instant::now() + this.idle);
                if let Some(data) = frame.data_ref() {
                    this.usage.feed(data);
                    if let Some(c) = &mut this.capture {
                        c.body_chunk(data);
                    }
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(e))) => {
                this.end(BodyEnd::Failed);
                Poll::Ready(Some(Err(Box::new(e))))
            }
            Poll::Ready(None) => {
                this.end(BodyEnd::Complete);
                Poll::Ready(None)
            }
            Poll::Pending => {
                ready!(this.deadline.as_mut().poll(cx));
                this.end(BodyEnd::Failed);
                Poll::Ready(Some(Err("upstream body idle deadline expired".into())))
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

impl Drop for RelayBody {
    fn drop(&mut self) {
        self.end(BodyEnd::Dropped);
    }
}

/// A body the proxy already read — a classified 429 — relayed as
/// one frame with the same end-of-exchange bookkeeping.
pub struct FullBody {
    bytes: Option<Bytes>,
    tokens: Tokens,
    on_end: Option<OnEnd>,
}

impl FullBody {
    pub fn new(bytes: Bytes, tokens: Tokens, on_end: OnEnd) -> Self {
        Self {
            bytes: Some(bytes),
            tokens,
            on_end: Some(on_end),
        }
    }

    pub fn boxed(self) -> ResponseBody {
        BoxBody::new(self)
    }

    fn end(&mut self, how: fn(Tokens) -> BodyEnd) {
        if let Some(on_end) = self.on_end.take() {
            on_end(how(self.tokens));
        }
    }
}

impl Body for FullBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        let this = self.get_mut();
        match this.bytes.take() {
            Some(bytes) => Poll::Ready(Some(Ok(Frame::data(bytes)))),
            None => {
                this.end(BodyEnd::Complete);
                Poll::Ready(None)
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.bytes.is_none()
    }
}

impl Drop for FullBody {
    fn drop(&mut self) {
        self.end(BodyEnd::Dropped);
    }
}
