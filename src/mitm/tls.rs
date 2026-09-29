//! Interception: the TLS server on an intercepted tunnel's bytes. The leaf is
//! the `CONNECT` target's, so a tunnel opened before a rotation keeps the leaf
//! it started with.

use std::net::SocketAddr;
use std::sync::Arc;

use rustls::server::{Acceptor, ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{AlertDescription, ProtocolVersion, ServerConfig};
use tokio_rustls::LazyConfigAcceptor;

use crate::mitm::ca::Ca;
use crate::mitm::decode;
use crate::mitm::tunnel::Tunnel;
use crate::server::Server;

/// Both protocols offered; the negotiated one decides the framing and
/// a client offering none is served HTTP/1.1.
pub const ALPN: &[&[u8]] = &[b"h2", b"http/1.1"];

/// The class an operator looks for after a rotation, in the spelling
/// of a client that says why — it sends the unknown-CA alert, as curl does.
pub const UNKNOWN_CA: &str = "unknown_ca";
/// The same class for a client that aborts silently — it closes
/// after the server's certificate flight with no alert, as Claude Code does.
pub const CLIENT_CLOSED: &str = "client_closed_during_handshake";

/// The leaf is chosen by the `CONNECT` target, so the resolver
/// answers the same certified key whatever the hello carries — including no
/// SNI at all. The name is logged at `trace` and decides nothing.
#[derive(Debug)]
struct Leaf {
    certified: Arc<CertifiedKey>,
}

impl ResolvesServerCert for Leaf {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        tracing::trace!(
            event = "mitm_client_hello",
            server_name = hello.server_name().unwrap_or("<none>"),
            "SNI is recorded and never selects the leaf"
        );
        Some(Arc::clone(&self.certified))
    }
}

/// No client certificate is requested, TLS 1.2 and 1.3 are both
/// accepted (rustls's defaults with the `tls12` feature), and the leaf comes
/// from the CA the tunnel holds.
fn config(ca: &Ca) -> Result<ServerConfig, String> {
    let key = rustls::crypto::ring::sign::any_supported_type(ca.leaf_key())
        .map_err(|e| format!("the leaf private key is unusable: {e}"))?;
    let certified = Arc::new(CertifiedKey::new(vec![ca.leaf_certificate().clone()], key));
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(Leaf { certified }));
    config.alpn_protocols = ALPN.iter().map(|p| p.to_vec()).collect();
    Ok(config)
}

/// The intercepted tunnel's whole life: the handshake, the debug line, then
/// the decoded requests until the client goes away.
pub async fn serve(
    server: Arc<Server>,
    ca: Arc<Ca>,
    tunnel: Arc<Tunnel>,
    peer: SocketAddr,
    upgraded: hyper::upgrade::Upgraded,
) {
    let config = match config(&ca) {
        Ok(config) => Arc::new(config),
        Err(e) => {
            // The start-time check already accepted this material, so
            // a failure here is not an operator's misconfiguration.
            tracing::error!(event = "mitm_tls_unavailable", error = %e, "the leaf cannot serve TLS");
            return;
        }
    };
    // Two stages, so a failure knows whether the hello had arrived and the
    // server's flight had gone out (the silent abort).
    let hello =
        LazyConfigAcceptor::new(Acceptor::default(), hyper_util::rt::TokioIo::new(upgraded)).await;
    let stream = match hello {
        Ok(start) => start.into_stream(config).await.map_err(|e| (e, true)),
        Err(e) => Err((e, false)),
    };
    let stream = match stream {
        Ok(stream) => stream,
        Err((e, hello_read)) => {
            // One line per failed handshake, with the class apart from
            // the message; non-TLS bytes end the tunnel by returning.
            server.mitm.record_failed_handshake();
            let class = class(&e, hello_read);
            if class == CLIENT_CLOSED {
                // Every intercepted tunnel authenticated at `CONNECT`,
                // which is what makes the silent abort a probable trust failure.
                tracing::warn!(
                    event = "mitm_handshake_failed",
                    address = %peer,
                    target = %tunnel.target,
                    class,
                    error = %e,
                    "the client closed the intercepted tunnel during the TLS handshake without an alert: from an authenticated caller this is a probable trust failure — confirm the client's CA file holds the current CA"
                );
            } else {
                tracing::warn!(
                    event = "mitm_handshake_failed",
                    address = %peer,
                    target = %tunnel.target,
                    class,
                    error = %e,
                    "the TLS handshake on an intercepted tunnel failed"
                );
            }
            return;
        }
    };
    let (version, alpn) = {
        let (_, connection) = stream.get_ref();
        let version = connection
            .protocol_version()
            .map_or("unknown", version_name)
            .to_string();
        // No ALPN is HTTP/1.1.
        let alpn = connection.alpn_protocol().map_or_else(
            || "http/1.1".to_string(),
            |p| String::from_utf8_lossy(p).into_owned(),
        );
        (version, alpn)
    };
    // One line per intercepted tunnel, at `debug`.
    tracing::debug!(
        event = "mitm_tunnel",
        address = %peer,
        target = %tunnel.target,
        principal_role = tunnel.credential.principal.role(),
        principal_id = tunnel.credential.principal.id.as_deref().unwrap_or(""),
        tls_version = %version,
        alpn = %alpn,
        "intercepted tunnel"
    );
    decode::serve(server, tunnel, peer, stream, alpn == "h2").await;
}

/// The failure classes. The untrusted-CA class has two spellings, the
/// alert and the end of stream once the hello was read; everything else is
/// named well enough to tell two causes apart in a log.
fn class(error: &std::io::Error, hello_read: bool) -> String {
    let Some(tls) = error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<rustls::Error>())
    else {
        if hello_read && error.kind() == std::io::ErrorKind::UnexpectedEof {
            return CLIENT_CLOSED.to_string();
        }
        return "transport".to_string();
    };
    match tls {
        rustls::Error::AlertReceived(AlertDescription::UnknownCA) => UNKNOWN_CA.to_string(),
        rustls::Error::AlertReceived(alert) => {
            format!("alert_{}", format!("{alert:?}").to_ascii_lowercase())
        }
        // Bytes that are not a client hello.
        rustls::Error::InvalidMessage(_) => "not_a_tls_client_hello".to_string(),
        rustls::Error::PeerIncompatible(_) => "peer_incompatible".to_string(),
        rustls::Error::PeerMisbehaved(_) => "peer_misbehaved".to_string(),
        rustls::Error::NoApplicationProtocol => "no_application_protocol".to_string(),
        _ => "tls_error".to_string(),
    }
}

fn version_name(version: ProtocolVersion) -> &'static str {
    match version {
        ProtocolVersion::TLSv1_3 => "TLSv1.3",
        ProtocolVersion::TLSv1_2 => "TLSv1.2",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The acceptor the start-time material yields offers both
    /// protocols and asks for no client certificate.
    #[test]
    fn the_leaf_serves_both_protocols_and_no_client_auth() {
        let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target/l1-mitm-tls")
            .join(uuid::Uuid::new_v4().to_string());
        std::fs::create_dir_all(&dir).expect("state directory");
        let ca = Ca::generate(&dir, time::OffsetDateTime::now_utc()).expect("generated");
        let config = config(&ca).expect("the leaf serves TLS");
        assert_eq!(
            config.alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );
        assert_eq!(
            config.max_early_data_size, 0,
            "no early data on an intercepted tunnel"
        );
    }

    #[test]
    fn the_unknown_ca_alert_is_its_own_class() {
        let unknown =
            std::io::Error::other(rustls::Error::AlertReceived(AlertDescription::UnknownCA));
        assert_eq!(class(&unknown, true), UNKNOWN_CA);
        let other = std::io::Error::other(rustls::Error::AlertReceived(
            AlertDescription::BadCertificate,
        ));
        assert_eq!(class(&other, true), "alert_badcertificate");
        let plain = std::io::Error::other("connection reset");
        assert_eq!(class(&plain, true), "transport");
    }

    #[test]
    fn an_end_of_stream_is_a_silent_abort_only_after_the_hello() {
        let eof = || std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "tls handshake eof");
        assert_eq!(class(&eof(), true), CLIENT_CLOSED);
        assert_eq!(class(&eof(), false), "transport");
    }
}
