//! Absolute-form forwarding: plain HTTP through the proxy listener, sent on
//! to the target — through the corporate proxy when one is configured and
//! the target is not in its no-proxy list.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use http::{HeaderValue, Request, Response, StatusCode};
use http_body_util::BodyExt as _;
use hyper::body::Incoming;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;

use crate::config::DataPlaneSettings;
use crate::data_plane::connect::Connector;
use crate::data_plane::relay::{self, BoxError, ResponseBody};
use crate::mitm::probe;
use crate::mitm::tunnel::{self, Refusal};
use crate::server::Server;

/// The two hyper clients absolute-form forwarding uses: direct, and through
/// the corporate proxy. Both are built once per server start — the corporate
/// proxy and no-proxy settings are restart keys — and the client
/// writes request-targets in absolute-form on the proxied one.
pub(crate) struct Forwarder {
    direct: Client<Connector, Incoming>,
    proxied: Option<Client<Connector, Incoming>>,
    /// The corporate proxy's own credential: an absolute-form request to it
    /// carries it, like the CONNECT does.
    proxy_authorization: Option<HeaderValue>,
}

impl Forwarder {
    pub(crate) fn new(settings: &DataPlaneSettings) -> Result<Forwarder, String> {
        let tls = crate::data_plane::tls::client_config()?;
        let direct =
            Client::builder(TokioExecutor::new()).build(Connector::new(Arc::clone(&tls), None)?);
        let proxy_authorization = match &settings.corporate_proxy_url {
            Some(url) => Connector::new(Arc::clone(&tls), Some(url))?
                .proxy_authorization()
                .map(HeaderValue::from_str)
                .transpose()
                .map_err(|e| {
                    format!("the corporate proxy's credential is not a header value: {e}")
                })?,
            None => None,
        };
        let proxied = match &settings.corporate_proxy_url {
            Some(url) => {
                Some(Client::builder(TokioExecutor::new()).build(Connector::new(tls, Some(url))?))
            }
            None => None,
        };
        Ok(Self {
            direct,
            proxied,
            proxy_authorization,
        })
    }

    /// One absolute-form request: the credential gate, the self-target rule,
    /// then the forward —
    /// method, path, query and body unchanged, no credential injected ever.
    pub(crate) async fn handle(
        &self,
        server: &Arc<Server>,
        host_addresses: &[IpAddr],
        peer: SocketAddr,
        request: Request<Incoming>,
    ) -> Response<ResponseBody> {
        let uri = request.uri().clone();
        let target = uri.authority().map(ToString::to_string).unwrap_or_default();
        let scheme = uri.scheme_str().unwrap_or_default().to_owned();
        if scheme != "http" {
            // Only http:// is forwarded plain; https:// absolute-form
            // is refused (a CONNECT through the proxy listener is the TLS path).
            return tunnel::refusal(
                peer,
                &target,
                StatusCode::BAD_REQUEST,
                "absolute-form https:// is not forwarded; tunnel TLS with CONNECT instead",
            );
        }
        let credential = match tunnel::authorize(server, peer, request.headers()) {
            Ok(credential) => credential,
            Err(response) => return *response,
        };
        let host = tunnel::target_host(&uri);
        let port = uri.port_u16().unwrap_or(80);
        if host.is_empty() {
            return tunnel::refusal(
                peer,
                &target,
                StatusCode::BAD_REQUEST,
                "the target has no host",
            );
        }
        // The probe host answers itself in this form too, with `tls`
        // false, so a client can tell a refused credential from an untrusted
        // CA. It is never forwarded and never resolved.
        if host
            .trim_end_matches('.')
            .eq_ignore_ascii_case(probe::PROBE_HOST)
        {
            return probe::answer(server, &credential, uri.path(), false);
        }
        let path = match tunnel::route_target(server, host_addresses, &host, port).await {
            Ok(path) => path,
            Err((status, message)) => return tunnel::refusal(peer, &target, status, &message),
        };
        let client = match path {
            tunnel::Path::ViaProxy => self
                .proxied
                .as_ref()
                .expect("the corporate proxy is configured for the proxy route"),
            tunnel::Path::Direct => &self.direct,
        };
        let mut request = request;
        tunnel::strip_request_hop_by_hop(request.headers_mut());
        // No proxy metadata reaches a forwarded destination either.
        tunnel::strip_proxy_metadata(request.headers_mut());
        // On the proxy route the corporate proxy is the next hop, and
        // its own credential rides the absolute-form request like the CONNECT.
        if let tunnel::Path::ViaProxy = path
            && let Some(value) = &self.proxy_authorization
        {
            request
                .headers_mut()
                .insert("proxy-authorization", value.clone());
        }
        // The request body streams straight through; hyper re-frames it. The
        // response is relayed chunk by chunk, unbuffered, headers stripped of
        // the connection-specific set.
        match client.request(request).await {
            Ok(response) => {
                let (mut parts, body) = response.into_parts();
                relay::strip_response_headers(&mut parts.headers);
                Response::from_parts(parts, body.map_err(|e| Box::new(e) as BoxError).boxed())
            }
            Err(e) => {
                let refusal: Refusal = (
                    StatusCode::BAD_GATEWAY,
                    format!("the target {target} is unreachable: {e}"),
                );
                tunnel::refusal(peer, &target, refusal.0, &refusal.1)
            }
        }
    }
}
