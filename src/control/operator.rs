//! The remote-operator secret:
//! provision, rotate and remove, loopback only whatever the TLS state.

use std::net::SocketAddr;
use std::sync::Arc;

use http::{Request, Response, StatusCode};
use hyper::body::Incoming;
use serde_json::json;
use time::OffsetDateTime;

use crate::audit::Principal;
use crate::data_plane::relay::ResponseBody;
use crate::server::{MutateError, Server};
use crate::timestamp::rfc3339;

use super::{
    base, error, is_loopback_peer, member_errors, mutation_body, mutation_line, persist_failed,
    refusal_line,
};

/// Provision or rotate; discloses once, and provisioning ends the
/// bootstrap exception permanently.
pub(super) async fn set(
    server: &Arc<Server>,
    peer: SocketAddr,
    principal: &Principal,
    request: Request<Incoming>,
) -> Response<ResponseBody> {
    if let Err(why) = loopback_only(peer) {
        refusal_line(server, peer, Some(principal), why.1);
        return error(why.0, why.1, why.2, None, vec![]);
    }
    let body = match mutation_body(server, peer, Some(principal), request).await {
        Ok(body) => body,
        Err(refusal) => return refusal,
    };
    let details = member_errors(&body, &[]);
    if !details.is_empty() {
        return error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "the request has invalid members",
            None,
            details,
        );
    }
    let mut disclosed = None;
    let result = server.mutate_registry(|registry| {
        disclosed = Some(registry.provision_operator_secret(OffsetDateTime::now_utc()));
        Ok::<(), std::convert::Infallible>(())
    });
    match result {
        Ok(()) => {}
        Err(MutateError::Persist(e)) => return persist_failed(server, e),
        Err(MutateError::Refused(never)) => match never {},
    }
    let rotated_at = server.registry().operator.map(|o| o.rotated_at);
    mutation_line(
        server,
        peer,
        principal,
        "operator_secret_set",
        "operator",
        "provisioned",
    );
    base(
        StatusCode::OK,
        json!({
            "operator_secret": disclosed.expect("the secret was disclosed"),
            "rotated_at": rotated_at.map(rfc3339),
        }),
    )
}

/// Remove; only loopback callers are operators again.
pub(super) async fn remove(
    server: &Arc<Server>,
    peer: SocketAddr,
    principal: &Principal,
    request: Request<Incoming>,
) -> Response<ResponseBody> {
    if let Err(why) = loopback_only(peer) {
        refusal_line(server, peer, Some(principal), why.1);
        return error(why.0, why.1, why.2, None, vec![]);
    }
    if let Some(refusal) = mutation_body(server, peer, Some(principal), request)
        .await
        .err()
    {
        return refusal;
    }
    let result = server.mutate_registry(|registry| {
        registry.remove_operator_secret();
        Ok::<(), std::convert::Infallible>(())
    });
    match result {
        Ok(()) => {}
        Err(MutateError::Persist(e)) => return persist_failed(server, e),
        Err(MutateError::Refused(never)) => match never {},
    }
    mutation_line(
        server,
        peer,
        principal,
        "operator_secret_remove",
        "operator",
        "removed",
    );
    base(StatusCode::OK, json!({}))
}

/// `403 loopback_required` for any non-loopback peer, TLS or not.
fn loopback_only(peer: SocketAddr) -> Result<(), (http::StatusCode, &'static str, &'static str)> {
    if is_loopback_peer(peer) {
        return Ok(());
    }
    Err((
        StatusCode::FORBIDDEN,
        "loopback_required",
        "the remote-operator secret is managed only from the host itself; an operator credential is the pool's master key",
    ))
}
