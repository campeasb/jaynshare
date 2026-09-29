//! The MITM certificate authority's rotate endpoint. The CA object
//! itself is `src/mitm/ca.rs`'s; this module only drives the rotation and renders
//! the three facts the answer carries. No key material is returned, and
//! the CA private key never touches the disk in the first place.

use std::net::SocketAddr;
use std::sync::Arc;

use http::{Request, Response, StatusCode};
use hyper::body::Incoming;
use serde_json::json;
use time::OffsetDateTime;

use crate::audit::Principal;
use crate::data_plane::relay::ResponseBody;
use crate::mitm::ca::Ca;
use crate::server::Server;
use crate::timestamp::rfc3339;

use super::{base, error, member_errors, mutation_body, mutation_line};

/// `GET /control/v1/ca` — the current CA, for comparison and
/// diagnosis only. Every member is `null` while MITM has never been enabled.
/// The declared principal class is **client**, so an enrolled client reads it
/// too; the router's client-or-operator arm serves it.
pub(super) fn read(server: &Arc<Server>) -> Response<ResponseBody> {
    let enabled = server.config().config.mitm.enabled;
    let ca = match enabled.then(|| server.mitm_ca()).flatten() {
        Some(ca) => json!({
            "certificate_pem": ca.certificate_pem(),
            "fingerprint": ca.fingerprint(),
            "not_after": rfc3339(ca.not_after()),
            "state": ca.expiry_state(OffsetDateTime::now_utc()),
        }),
        None => json!({
            "certificate_pem": null,
            "fingerprint": null,
            "not_after": null,
            "state": if enabled { json!("unusable") } else { json!(null) },
        }),
    };
    base(StatusCode::OK, json!({ "ca": ca }))
}

/// `POST /control/v1/mitm/ca/rotate`, a mutation with an empty body.
/// `409 mitm_disabled` when the mode is off; otherwise the rotation,
/// answered with the old and new fingerprints and the new expiry.
pub(super) async fn rotate(
    server: &Arc<Server>,
    peer: SocketAddr,
    principal: &Principal,
    request: Request<Incoming>,
) -> Response<ResponseBody> {
    let body = match mutation_body(server, peer, Some(principal), request).await {
        Ok(body) => body,
        Err(refusal) => return refusal,
    };
    // Rotate defines no members, so every member is unknown.
    let member_details = member_errors(&body, &[]);
    if !member_details.is_empty() {
        return error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "the request has invalid members",
            None,
            member_details,
        );
    }
    if !server.config().config.mitm.enabled {
        return error(
            StatusCode::CONFLICT,
            "mitm_disabled",
            "MITM mode is off; there is no certificate authority to rotate",
            None,
            vec![],
        );
    }
    // The fingerprint in force before the rotation. Unusable material still
    // rotates — that is the way out of unusable material — and then has no previous one.
    let previous = server.mitm_ca().map(|ca| ca.fingerprint());
    let state_dir = server.state_path.parent().map_or_else(
        || std::path::PathBuf::from("."),
        std::path::Path::to_path_buf,
    );
    let ca = match Ca::rotate(&state_dir, OffsetDateTime::now_utc()) {
        Ok(ca) => ca,
        Err(e) => {
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "state_unwritable",
                &format!("the certificate authority could not be rotated: {e}"),
                None,
                vec![],
            );
        }
    };
    let (fingerprint, not_after) = (ca.fingerprint(), ca.not_after());
    // Every new handshake presents the new leaf; tunnels already
    // established keep the one they negotiated, because they hold their own
    // clone of the old CA.
    server.set_mitm_ca(Some(Arc::new(ca)));
    mutation_line(server, peer, principal, "ca_rotate", "ca", "rotated");
    base(
        StatusCode::OK,
        json!({
            "previous_fingerprint": previous,
            "fingerprint": fingerprint,
            "not_after": rfc3339(not_after),
        }),
    )
}
