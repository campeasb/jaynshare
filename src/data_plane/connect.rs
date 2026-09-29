//! The one transport the process opens connections with:
//! direct TLS to the origin, or — when a corporate proxy is configured — a
//! CONNECT tunnel through it with TLS end to end, or for a plain `http://`
//! target a direct connection to the proxy carrying the request in
//! absolute-form. Attempts, the token, profile and usage calls all
//! share it. Ambient proxy variables are never read: nothing here
//! consults the environment.

use std::fmt;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use http::Uri;
use hyper_util::client::legacy::connect::{Connected, Connection};
use hyper_util::rt::TokioIo;
use rustls_pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;

/// One connection. `Tls` is the origin's TLS over a direct TCP connection or
/// over a CONNECT tunnel; `Raw` is the loopback `http://` override the
/// acceptance harness stages.
pub(crate) enum Io {
    Raw {
        io: TokioIo<Wire>,
        /// Whether the wire reaches a corporate proxy — through its CONNECT
        /// tunnel or, for a plain `http://` target, as an absolute-form
        /// request on a direct connection to it: the hyper client
        /// then writes request-targets in absolute-form.
        proxied: bool,
    },
    Tls(TokioIo<Box<TlsStream<Wire>>>),
}

/// The bytes under the origin TLS: plain TCP, or TLS to the proxy itself when
/// the corporate proxy URL is `https`.
pub(crate) enum Wire {
    Plain(TcpStream),
    Tls(Box<TlsStream<TcpStream>>),
}

impl AsyncRead for Wire {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match &mut *self {
            Wire::Plain(s) => Pin::new(s).poll_read(cx, buf),
            Wire::Tls(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Wire {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match &mut *self {
            Wire::Plain(s) => Pin::new(s).poll_write(cx, buf),
            Wire::Tls(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut *self {
            Wire::Plain(s) => Pin::new(s).poll_flush(cx),
            Wire::Tls(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut *self {
            Wire::Plain(s) => Pin::new(s).poll_shutdown(cx),
            Wire::Tls(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

impl hyper::rt::Read for Io {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<std::io::Result<()>> {
        match &mut *self {
            Io::Raw { io, .. } => Pin::new(io).poll_read(cx, buf),
            Io::Tls(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl hyper::rt::Write for Io {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match &mut *self {
            Io::Raw { io, .. } => Pin::new(io).poll_write(cx, buf),
            Io::Tls(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut *self {
            Io::Raw { io, .. } => Pin::new(io).poll_flush(cx),
            Io::Tls(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut *self {
            Io::Raw { io, .. } => Pin::new(io).poll_shutdown(cx),
            Io::Tls(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

impl Connection for Io {
    fn connected(&self) -> Connected {
        match self {
            Io::Raw { proxied: true, .. } => Connected::new().proxy(true),
            _ => Connected::new(),
        }
    }
}

impl fmt::Debug for Io {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Io::Raw { .. } => "Io::Raw",
            Io::Tls(_) => "Io::Tls",
        })
    }
}

impl fmt::Debug for Wire {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Wire::Plain(_) => "Wire::Plain",
            Wire::Tls(_) => "Wire::Tls",
        })
    }
}

/// The configured corporate proxy: its `host:port` and, when the URL carries
/// user information, the `Proxy-Authorization` value the CONNECT carries.
#[derive(Clone, Debug)]
pub(crate) struct Proxy {
    pub(crate) authority: String,
    pub(crate) authorization: Option<String>,
    /// An `https://` proxy gets TLS to the proxy itself before the CONNECT.
    pub(crate) tls: bool,
}

impl Proxy {
    pub(crate) fn from_url(url: &Uri) -> Result<Self, String> {
        let Some(host) = url.host() else {
            return Err("the corporate proxy URL has no host".into());
        };
        let port = url
            .port_u16()
            .unwrap_or(if url.scheme_str() == Some("https") {
                443
            } else {
                80
            });
        let authorization = url
            .authority()
            .and_then(|a| a.as_str().split_once('@'))
            .map(|(userinfo, _)| format!("Basic {}", BASE64.encode(percent_decode(userinfo))));
        Ok(Self {
            authority: format!("{host}:{port}"),
            authorization,
            tls: url.scheme_str() == Some("https"),
        })
    }
}

/// The proxy URL's user information is percent-encoded (`RFC 3986`); the
/// credential is the decoded bytes.
fn percent_decode(s: &str) -> Vec<u8> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let Ok(byte) = u8::from_str_radix(
                std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("\0\0"),
                16,
            )
        {
            out.push(byte);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    out
}

/// TCP keep-alive on a tunnel side, so a vanished peer is noticed.
/// The OS's own probe intervals decide the rest.
pub(crate) fn enable_keepalive(stream: &TcpStream) {
    let _ = socket2::SockRef::from(stream)
        .set_tcp_keepalive(&socket2::TcpKeepalive::new().with_time(Duration::from_secs(60)));
}

/// The SNI name for a target host, IP literals included (IP literals are
/// excluded only from `no_proxy`, not from the origin itself).
fn server_name(host: &str) -> Result<ServerName<'static>, String> {
    ServerName::try_from(host.to_string())
        .map_err(|e| format!("origin host {host} is not a TLS server name: {e}"))
}

/// TLS to `host` over `stream`, with the process's trust store.
async fn tls_connect<S>(
    tls: &Arc<rustls::ClientConfig>,
    host: &str,
    stream: S,
) -> Result<TlsStream<S>, String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let name = server_name(host)?;
    let connector = tokio_rustls::TlsConnector::from(Arc::clone(tls));
    connector
        .connect(name, stream)
        .await
        .map_err(|e| format!("the TLS handshake with {host} failed: {e}"))
}

/// The CONNECT response head, read one byte at a time: everything after the
/// blank line already belongs to the tunnelled TLS stream, so this must not
/// buffer past it.
async fn read_head(stream: &mut Wire) -> Result<String, String> {
    use tokio::io::AsyncReadExt as _;
    const MAX_HEAD: usize = 8 * 1024;
    let mut head = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        if stream
            .read(&mut byte)
            .await
            .map_err(|e| format!("reading the CONNECT response failed: {e}"))?
            == 0
        {
            return Err(
                "the corporate proxy closed the connection before answering the CONNECT".to_owned(),
            );
        }
        head.push(byte[0]);
        if head.ends_with(b"\r\n\r\n") || head.ends_with(b"\n\n") {
            return Ok(String::from_utf8_lossy(&head).into_owned());
        }
        if head.len() >= MAX_HEAD {
            return Err("the corporate proxy's CONNECT response head is too long".to_owned());
        }
    }
}

/// The hyper legacy-client connector: `tower_service::Service<Uri>`.
#[derive(Clone)]
pub(crate) struct Connector {
    tls: Arc<rustls::ClientConfig>,
    proxy: Option<Proxy>,
}

impl Connector {
    pub(crate) fn new(
        tls: Arc<rustls::ClientConfig>,
        corporate_proxy_url: Option<&Uri>,
    ) -> Result<Self, String> {
        let proxy = corporate_proxy_url.map(Proxy::from_url).transpose()?;
        Ok(Self { tls, proxy })
    }

    /// TCP to the proxy, TLS to the proxy when its URL is `https`. Shared
    /// with `Connector::connect`: for a plain `http://` target this is the
    /// whole connection — the proxy is the next hop — while a
    /// tunnelled target adds the CONNECT on top.
    async fn dial_proxy(&self, proxy: &Proxy) -> Result<Wire, String> {
        let tcp = TcpStream::connect(&proxy.authority).await.map_err(|e| {
            format!(
                "the corporate proxy {} is unreachable: {e}",
                proxy.authority
            )
        })?;
        enable_keepalive(&tcp);
        if proxy.tls {
            let host = proxy.authority.split(':').next().unwrap_or_default();
            Ok(Wire::Tls(Box::new(
                tls_connect(&self.tls, host, tcp).await.map_err(|e| {
                    format!("the corporate proxy {} rejected TLS: {e}", proxy.authority)
                })?,
            )))
        } else {
            Ok(Wire::Plain(tcp))
        }
    }

    /// TCP to the proxy, TLS to the proxy when its URL is `https`, then the
    /// CONNECT. The response head is read by hand: this client speaks only
    /// enough HTTP/1.1 to tunnel. Shared with the MITM tunnel chain.
    pub(crate) async fn tunnel(&self, target: &str) -> Result<Wire, String> {
        use tokio::io::AsyncWriteExt as _;
        let proxy = self.proxy.as_ref().expect("tunnel without a proxy");
        let mut stream = self.dial_proxy(proxy).await?;
        let mut request = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n");
        if let Some(value) = &proxy.authorization {
            request.push_str(&format!("Proxy-Authorization: {value}\r\n"));
        }
        request.push_str("\r\n");
        stream
            .write_all(request.as_bytes())
            .await
            .map_err(|e| format!("writing the CONNECT failed: {e}"))?;
        let head = read_head(&mut stream).await?;
        let status_line = head.lines().next().unwrap_or_default();
        if status_line.split_whitespace().nth(1) != Some("200") {
            return Err(format!(
                "the corporate proxy {} refused the tunnel: {}",
                proxy.authority,
                status_line.trim()
            ));
        }
        Ok(stream)
    }

    /// The `Proxy-Authorization` value the corporate proxy's own
    /// CONNECT carries — an absolute-form request to it must carry it too.
    pub(crate) fn proxy_authorization(&self) -> Option<&str> {
        self.proxy.as_ref()?.authorization.as_deref()
    }

    async fn connect(self, uri: Uri) -> Result<Io, String> {
        let https = uri.scheme_str() == Some("https");
        let host = uri
            .host()
            .ok_or_else(|| "the origin has no host".to_string())?;
        let port = uri.port_u16().unwrap_or(if https { 443 } else { 80 });
        let target = format!("{host}:{port}");
        let stream = match &self.proxy {
            None => {
                let tcp = TcpStream::connect(&target)
                    .await
                    .map_err(|e| format!("the upstream origin {target} is unreachable: {e}"))?;
                Wire::Plain(tcp)
            }
            // A plain-HTTP next hop is the proxy itself — the request
            // goes to it in absolute-form, no CONNECT.
            Some(proxy) if !https => self.dial_proxy(proxy).await?,
            Some(_) => self.tunnel(&target).await?,
        };
        if https {
            let tls_stream = tls_connect(&self.tls, host, stream).await?;
            Ok(Io::Tls(TokioIo::new(Box::new(tls_stream))))
        } else {
            Ok(Io::Raw {
                io: TokioIo::new(stream),
                proxied: self.proxy.is_some(),
            })
        }
    }
}

impl tower_service::Service<Uri> for Connector {
    type Response = Io;
    type Error = String;
    type Future =
        std::pin::Pin<Box<dyn std::future::Future<Output = Result<Self::Response, String>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        Box::pin(self.clone().connect(uri))
    }
}
