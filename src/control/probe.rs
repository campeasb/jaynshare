//! The operator-triggered usage sweep.

use std::net::SocketAddr;
use std::sync::Arc;

use http::{Request, Response, StatusCode};
use hyper::body::Incoming;
use serde_json::json;

use crate::audit::Principal;
use crate::data_plane::relay::ResponseBody;
use crate::pool::probe::{self, StartError};
use crate::server::Server;
use crate::timestamp::rfc3339;

use super::{base, error, member_errors, mutation_body, mutation_line};

pub(super) async fn handle(
    server: &Arc<Server>,
    peer: SocketAddr,
    principal: &Principal,
    request: Request<Incoming>,
) -> Response<ResponseBody> {
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
    match probe::trigger(server, probe::Trigger::Operator) {
        Ok(started_at) => {
            mutation_line(
                server,
                peer,
                principal,
                "probe_trigger",
                "usage_probe",
                "started",
            );
            base(
                StatusCode::ACCEPTED,
                json!({ "started_at": rfc3339(started_at) }),
            )
        }
        Err(StartError::InProgress) => {
            mutation_line(
                server,
                peer,
                principal,
                "probe_trigger",
                "usage_probe",
                "sweep_in_progress",
            );
            error(
                StatusCode::CONFLICT,
                "sweep_in_progress",
                "a usage probe sweep is already running",
                None,
                vec![],
            )
        }
    }
}
