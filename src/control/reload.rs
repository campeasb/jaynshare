//! The configuration reload, one path for the control
//! endpoint and `SIGHUP`. The file selected at start is re-read,
//! the whole candidate validated against the live pool, a restart-key change
//! rejected whole, every live key applied at one boundary; concurrent reloads
//! run one at a time and each answers with the digest it considered.

use std::net::SocketAddr;
use std::sync::Arc;

use http::{Request, Response, StatusCode};
use hyper::body::Incoming;
use serde_json::{Value, json};
use time::OffsetDateTime;

use crate::audit::Principal;
use crate::config::{self, ConfigError, LoadedConfig, references, reload as changes};
use crate::data_plane::relay::ResponseBody;
use crate::server::{ReloadOutcome, Server};
use crate::timestamp::rfc3339;

use super::{base, error, member_errors, mutation_body, mutation_line};

/// `POST /control/v1/reload`, a mutation with an empty body.
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
    // Reload defines no members, so every member is unknown.
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
    let outcome = reload(server);
    let mut body = result_object(&outcome);
    if outcome.applied {
        mutation_line(
            server,
            peer,
            principal,
            "reload",
            outcome.digest.as_deref().unwrap_or(""),
            "applied",
        );
        return base(StatusCode::OK, body);
    }
    let message = if outcome.rejected_restart_keys.is_empty() {
        "the candidate configuration is invalid; nothing was applied".to_string()
    } else {
        format!(
            "the candidate changes restart keys ({}); nothing was applied — restart the server to apply it",
            outcome.rejected_restart_keys.join(", ")
        )
    };
    body["error"] = json!({
        "code": "configuration_invalid",
        "message": message,
        "target": null,
        "details": details(&outcome),
    });
    mutation_line(
        server,
        peer,
        principal,
        "reload",
        outcome.digest.as_deref().unwrap_or(""),
        "rejected",
    );
    base(StatusCode::UNPROCESSABLE_ENTITY, body)
}

/// One reload start to finish, serialized with every other;
/// the result is logged as the endpoint returns it and kept for the
/// configuration read.
pub fn reload(server: &Server) -> ReloadOutcome {
    let mut last = server.configuration.last.lock().expect("reload lock");
    let outcome = attempt(server);
    let result = result_object(&outcome);
    if outcome.applied {
        tracing::info!(event = "reload", result = %result, "configuration reloaded");
    } else {
        let errors = outcome
            .errors
            .iter()
            .map(|error| format!("{}: {}", error.target, error.message))
            .collect::<Vec<_>>()
            .join("; ");
        tracing::warn!(event = "reload", result = %result, errors, "configuration reload rejected; the previous configuration stays in force");
    }
    *last = Some(outcome.clone());
    outcome
}

fn attempt(server: &Server) -> ReloadOutcome {
    let now = OffsetDateTime::now_utc();
    let current = server.config();
    let path = &current.path;
    let rejected =
        |digest: Option<String>, errors: Vec<ConfigError>, restart: Vec<String>| ReloadOutcome {
            at: now,
            digest,
            applied: false,
            changed_keys: Vec::new(),
            rejected_restart_keys: restart,
            errors,
        };
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) => {
            return rejected(
                None,
                vec![ConfigError {
                    target: "configuration".into(),
                    message: format!("cannot read {}: {e}", path.display()),
                }],
                Vec::new(),
            );
        }
    };
    let digest = config::sha256_hex(&bytes);
    let parsed = match config::parse_document(&bytes, config::base_dir(path)) {
        Ok(parsed) => parsed,
        Err(errors) => return rejected(Some(digest), errors.0, Vec::new()),
    };
    // The state cross-references and the swap see one pool;
    // They are reported beside the local errors, in one result.
    let mut pool = server.pool.lock().expect("pool lock");
    let mut errors = parsed.errors;
    errors.extend(references::errors(&parsed.references, &pool));
    if !errors.is_empty() {
        return rejected(Some(digest), errors, Vec::new());
    }
    let candidate = parsed.config;
    let restart = changes::changed_restart_keys(&current.config, &candidate);
    if !restart.is_empty() {
        let errors = restart
            .iter()
            .map(|key| ConfigError {
                target: (*key).to_string(),
                message: "a restart key: accepted only at process start".into(),
            })
            .collect();
        return rejected(
            Some(digest),
            errors,
            restart.iter().map(|k| (*k).to_string()).collect(),
        );
    }
    let changed_keys = changes::changed_keys(&current.config, &candidate);
    // The preference of a route the new table lacks goes with it.
    for (route, account) in pool.retain_route_preferences(&candidate.selection.routes) {
        tracing::info!(event = "route_preference_dropped", route = %route, account = %account, "route removed by reload; its preference dropped");
    }
    if candidate.logging.level != current.config.logging.level {
        crate::logging::set_level(candidate.logging.level);
    }
    let probe_settings = candidate.quota.clone();
    let egress_changed = candidate.data_plane.egress != current.config.data_plane.egress;
    server.configuration.replace(
        LoadedConfig {
            path: path.clone(),
            digest: digest.clone(),
            config: candidate,
        },
        now,
    );
    server.probes.reconfigure(probe_settings);
    if egress_changed {
        server.egress.reconfigure();
    }
    drop(pool);
    ReloadOutcome {
        at: now,
        digest: Some(digest),
        applied: true,
        changed_keys,
        rejected_restart_keys: Vec::new(),
        errors: Vec::new(),
    }
}

/// The result members, present on success and on failure.
fn result_object(outcome: &ReloadOutcome) -> Value {
    json!({
        "digest": outcome.digest,
        "applied": outcome.applied,
        "changed_keys": outcome.changed_keys,
        "rejected_restart_keys": outcome.rejected_restart_keys,
    })
}

/// One detail per independently detectable error, under its dotted key.
fn details(outcome: &ReloadOutcome) -> Vec<Value> {
    outcome
        .errors
        .iter()
        .map(|e| {
            let code = if outcome.rejected_restart_keys.contains(&e.target) {
                "restart_key"
            } else {
                "configuration_invalid"
            };
            json!({ "target": e.target, "code": code, "message": e.message })
        })
        .collect()
}

/// The last reload's result, or `null` before the first.
pub(super) fn last_reload(server: &Server) -> Value {
    match &*server.configuration.last.lock().expect("reload lock") {
        None => Value::Null,
        Some(outcome) => {
            let mut object = result_object(outcome);
            object["at"] = json!(rfc3339(outcome.at));
            object["errors"] = json!(outcome.errors);
            object
        }
    }
}
