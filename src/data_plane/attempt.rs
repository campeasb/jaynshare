//! Turning a client request into an attempt: header rules and body rewrites.
//! Everything here is pure; the exchange loop calls it.

use bytes::Bytes;
use http::header::{
    ACCEPT_ENCODING, AUTHORIZATION, CONNECTION, CONTENT_LENGTH, HOST, TE, TRAILER,
    TRANSFER_ENCODING, UPGRADE,
};
use http::{HeaderMap, HeaderName, HeaderValue};
use serde_json::Value;
use uuid::Uuid;

use crate::anthropic::{
    ANTHROPIC_BETA, COUNT_TOKENS_PATH, MESSAGES_PATH, OAUTH_BETA, X_API_KEY, X_JAYNSHARE_ACCOUNT,
};
use crate::pool::Credential;

/// The hop-by-hop set plus what the proxy consumes itself.
const HOP_BY_HOP: [HeaderName; 8] = [
    CONNECTION,
    HeaderName::from_static("keep-alive"),
    TRANSFER_ENCODING,
    TE,
    TRAILER,
    UPGRADE,
    HeaderName::from_static("proxy-connection"),
    HeaderName::from_static("proxy-authenticate"),
];
const PROXY_AUTHORIZATION: HeaderName = HeaderName::from_static("proxy-authorization");

/// Removed before the attempt is built.
pub fn strip_request_headers(headers: &mut HeaderMap) {
    let named: Vec<HeaderName> = headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(',').map(str::trim).map(str::to_ascii_lowercase))
        .filter_map(|n| n.parse().ok())
        .collect();
    for name in named.into_iter().chain(HOP_BY_HOP).chain([
        PROXY_AUTHORIZATION,
        HOST,
        AUTHORIZATION,
        X_API_KEY,
        X_JAYNSHARE_ACCOUNT,
        ACCEPT_ENCODING,
    ]) {
        headers.remove(&name);
    }
}

/// Exactly one credential header, plus the OAuth beta for a bearer.
pub fn inject_credential(headers: &mut HeaderMap, credential: &Credential) {
    match credential {
        Credential::ApiKey(key) => {
            headers.insert(X_API_KEY, header_value(key.expose()));
        }
        Credential::OAuth(c) => {
            headers.insert(
                AUTHORIZATION,
                header_value(&format!("Bearer {}", c.access_token.expose())),
            );
            append_beta(headers, OAUTH_BETA);
        }
    }
}

fn header_value(s: &str) -> HeaderValue {
    HeaderValue::from_str(s).unwrap_or_else(|_| HeaderValue::from_static(""))
}

/// Existing entries kept in order; the value appended once when absent.
fn append_beta(headers: &mut HeaderMap, beta: &str) {
    let existing: Vec<String> = headers
        .get_all(ANTHROPIC_BETA)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| {
            v.split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(String::from)
        })
        .collect();
    if existing.iter().any(|b| b == beta) {
        return;
    }
    let mut joined = existing;
    joined.push(beta.to_string());
    headers.insert(ANTHROPIC_BETA, header_value(&joined.join(",")));
}

/// `content-length` describes the attempt body.
pub fn set_content_length(headers: &mut HeaderMap, len: usize) {
    headers.insert(CONTENT_LENGTH, HeaderValue::from(len));
}

/// What the request body says about the exchange.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct BodyFacts {
    pub model: Option<String>,
    pub advisor_model: Option<String>,
}

pub fn body_facts(body: &[u8]) -> BodyFacts {
    let Ok(Value::Object(top)) = serde_json::from_slice::<Value>(body) else {
        return BodyFacts::default();
    };
    let model = top.get("model").and_then(Value::as_str).map(String::from);
    let advisor_model = top
        .get("tools")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .find(|t| {
            t.get("type")
                .and_then(Value::as_str)
                .is_some_and(|ty| ty.starts_with("advisor"))
        })
        .and_then(|t| t.get("model"))
        .and_then(Value::as_str)
        .map(String::from);
    BodyFacts {
        model,
        advisor_model,
    }
}

/// Checks and rewrites together. Returns the original bytes when nothing changed, so a
/// well-formed body is forwarded byte-for-byte.
pub fn rewrite_body(body: Bytes, path: &str, account_uuid: Option<Uuid>) -> Bytes {
    let Ok(Value::Object(mut top)) = serde_json::from_slice::<Value>(&body) else {
        return body;
    };
    let mut changed = false;
    if let Some(uuid) = account_uuid
        && rewrite_account_uuid(&mut top, uuid)
    {
        changed = true;
    }
    if (path == MESSAGES_PATH || path == COUNT_TOKENS_PATH)
        && contains_either(&body, b"tool_use", b"tool_result")
        && let Some(Value::Array(messages)) = top.get_mut("messages")
        && sanitize_tool_pairs(messages)
    {
        changed = true;
    }
    if changed {
        Bytes::from(serde_json::to_vec(&Value::Object(top)).expect("value serializes"))
    } else {
        body
    }
}

fn contains_either(haystack: &[u8], a: &[u8], b: &[u8]) -> bool {
    let find = |needle: &[u8]| haystack.windows(needle.len()).any(|w| w == needle);
    find(a) || find(b)
}

/// The account-UUID rewrite: `metadata.user_id` is a JSON string holding an object.
fn rewrite_account_uuid(top: &mut serde_json::Map<String, Value>, uuid: Uuid) -> bool {
    let Some(Value::String(user_id)) = top.get_mut("metadata").and_then(|m| m.get_mut("user_id"))
    else {
        return false;
    };
    let Ok(Value::Object(mut inner)) = serde_json::from_str::<Value>(user_id) else {
        return false;
    };
    let wanted = Value::String(uuid.to_string());
    match inner.get_mut("account_uuid") {
        Some(current) if *current != wanted => {
            *current = wanted;
            *user_id = serde_json::to_string(&Value::Object(inner)).expect("serializes");
            true
        }
        _ => false,
    }
}

fn block_ids<'a>(message: &'a Value, block_type: &str, id_key: &str) -> Vec<&'a str> {
    message
        .get("content")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|b| b.get("type").and_then(Value::as_str) == Some(block_type))
        .filter_map(|b| b.get(id_key).and_then(Value::as_str))
        .collect()
}

/// Remove orphans, drop emptied messages, merge same-role neighbours,
/// and re-examine until stable. Returns whether anything changed.
fn sanitize_tool_pairs(messages: &mut Vec<Value>) -> bool {
    let mut changed = false;
    loop {
        let mut pass_changed = false;
        for i in 0..messages.len() {
            let next_results: Vec<String> = messages
                .get(i + 1)
                .map(|m| {
                    block_ids(m, "tool_result", "tool_use_id")
                        .into_iter()
                        .map(String::from)
                        .collect()
                })
                .unwrap_or_default();
            let prev_uses: Vec<String> = i
                .checked_sub(1)
                .and_then(|p| messages.get(p))
                .map(|m| {
                    block_ids(m, "tool_use", "id")
                        .into_iter()
                        .map(String::from)
                        .collect()
                })
                .unwrap_or_default();
            let Some(Value::Array(content)) = messages[i].get_mut("content") else {
                continue;
            };
            let before = content.len();
            content.retain(|b| match b.get("type").and_then(Value::as_str) {
                Some("tool_use") => b
                    .get("id")
                    .and_then(Value::as_str)
                    .is_some_and(|id| next_results.iter().any(|r| r == id)),
                Some("tool_result") => b
                    .get("tool_use_id")
                    .and_then(Value::as_str)
                    .is_some_and(|id| prev_uses.iter().any(|u| u == id)),
                _ => true,
            });
            pass_changed |= content.len() != before;
        }
        let before = messages.len();
        messages.retain(|m| {
            m.get("content")
                .and_then(Value::as_array)
                .is_none_or(|c| !c.is_empty())
        });
        pass_changed |= messages.len() != before;
        let mut i = 1;
        while i < messages.len() {
            if messages[i].get("role") == messages[i - 1].get("role") {
                let mut moved = messages.remove(i);
                if let (Some(Value::Array(dst)), Some(Value::Array(src))) =
                    (messages[i - 1].get_mut("content"), moved.get_mut("content"))
                {
                    dst.append(src);
                }
                pass_changed = true;
            } else {
                i += 1;
            }
        }
        changed |= pass_changed;
        if !pass_changed {
            return changed;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn strips_hop_by_hop_credentials_and_connection_named_headers() {
        let mut h = HeaderMap::new();
        for (k, v) in [
            ("connection", "x-test, keep-alive"),
            ("x-test", "1"),
            ("te", "trailers"),
            ("proxy-authorization", "Basic x"),
            ("authorization", "Bearer client"),
            ("x-api-key", "client"),
            ("x-jaynshare-account", "pin.x"),
            ("accept-encoding", "gzip"),
            ("host", "proxy"),
            ("anthropic-version", "2023-06-01"),
            ("x-stainless-os", "MacOS"),
        ] {
            h.append(HeaderName::from_static(k), HeaderValue::from_static(v));
        }
        strip_request_headers(&mut h);
        let mut left: Vec<&str> = h.keys().map(HeaderName::as_str).collect();
        left.sort_unstable();
        assert_eq!(left, ["anthropic-version", "x-stainless-os"]);
    }

    #[test]
    fn oauth_injects_bearer_and_appends_beta_once_in_order() {
        let cred = Credential::OAuth(crate::pool::account::OAuthCredential {
            access_token: crate::pool::Secret::new("tok".into()),
            refresh_token: None,
            expires_at: time::OffsetDateTime::UNIX_EPOCH,
            last_refresh_attempt_at: None,
            last_refresh_success_at: None,
            refresh_not_before: None,
        });
        let mut h = HeaderMap::new();
        h.insert(ANTHROPIC_BETA, HeaderValue::from_static("a-1,b-2"));
        inject_credential(&mut h, &cred);
        assert_eq!(h[AUTHORIZATION], "Bearer tok");
        assert_eq!(h[ANTHROPIC_BETA], "a-1,b-2,oauth-2025-04-20");
        inject_credential(&mut h, &cred);
        assert_eq!(h[ANTHROPIC_BETA], "a-1,b-2,oauth-2025-04-20");
        assert!(h.get(X_API_KEY).is_none());

        let mut h = HeaderMap::new();
        h.insert(ANTHROPIC_BETA, HeaderValue::from_static("a-1"));
        inject_credential(
            &mut h,
            &Credential::ApiKey(crate::pool::Secret::new("sk".into())),
        );
        assert_eq!(h[X_API_KEY], "sk");
        assert_eq!(h[ANTHROPIC_BETA], "a-1");
        assert!(h.get(AUTHORIZATION).is_none());
    }

    #[test]
    fn model_is_top_level_only_and_advisor_is_read_from_tools() {
        let body = json!({
            "messages": [{"model": "nested"}],
            "model": "claude-haiku",
            "tools": [{"type": "advisor_20260301", "model": "claude-opus"}],
        });
        let facts = body_facts(&serde_json::to_vec(&body).unwrap());
        assert_eq!(facts.model.as_deref(), Some("claude-haiku"));
        assert_eq!(facts.advisor_model.as_deref(), Some("claude-opus"));
        assert_eq!(body_facts(b"not json"), BodyFacts::default());
        assert_eq!(
            body_facts(b"{\"messages\":[{\"model\":\"x\"}]}"),
            BodyFacts::default()
        );
    }

    #[test]
    fn account_uuid_is_rewritten_only_inside_metadata_user_id() {
        let uuid = Uuid::new_v4();
        let body = json!({
            "system": [{"type": "text", "text": "x-anthropic-billing-header: cc_version=1;"}],
            "metadata": {"user_id": "{\"device_id\":\"d\",\"account_uuid\":\"\",\"session_id\":\"s\"}"},
            "account_uuid": "elsewhere",
        });
        let out = rewrite_body(
            Bytes::from(serde_json::to_vec(&body).unwrap()),
            "/v1/messages",
            Some(uuid),
        );
        let v: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["account_uuid"], "elsewhere");
        assert_eq!(v["system"], body["system"]);
        let inner: Value =
            serde_json::from_str(v["metadata"]["user_id"].as_str().unwrap()).unwrap();
        assert_eq!(inner["account_uuid"], uuid.to_string());
        assert_eq!(inner["device_id"], "d");
    }

    #[test]
    fn well_formed_body_is_forwarded_byte_for_byte() {
        let raw = Bytes::from_static(b"{\"model\":\"m\", \"messages\":[{\"role\":\"user\",\"content\":[{\"type\":\"text\",\"text\":\"hi\"}]}]}");
        assert_eq!(
            rewrite_body(raw.clone(), "/v1/messages", Some(Uuid::nil())),
            raw
        );
    }

    #[test]
    fn orphan_tool_pairs_are_removed_and_neighbours_merged() {
        let body = json!({
            "messages": [
                {"role": "user", "content": [{"type": "text", "text": "q"}]},
                {"role": "assistant", "content": [{"type": "tool_use", "id": "a", "input": {}}]},
                {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "b", "content": "x"}]},
                {"role": "assistant", "content": [{"type": "text", "text": "done"}]},
            ]
        });
        let out = rewrite_body(
            Bytes::from(serde_json::to_vec(&body).unwrap()),
            "/v1/messages",
            None,
        );
        let v: Value = serde_json::from_slice(&out).unwrap();
        let messages = v["messages"].as_array().unwrap();
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0]["role"], "user");
        assert_eq!(messages[1]["content"][0]["text"], "done");

        let other_path = rewrite_body(
            Bytes::from(serde_json::to_vec(&body).unwrap()),
            "/v1/other",
            None,
        );
        assert_eq!(serde_json::from_slice::<Value>(&other_path).unwrap(), body);
    }

    #[test]
    fn removing_one_pair_re_examines_the_exposed_neighbour() {
        let body = json!({
            "messages": [
                {"role": "assistant", "content": [{"type": "tool_use", "id": "a", "input": {}}]},
                {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "a", "content": "x"}]},
                {"role": "assistant", "content": [{"type": "tool_use", "id": "b", "input": {}}]},
                {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "zzz", "content": "y"}]},
            ]
        });
        let out = rewrite_body(
            Bytes::from(serde_json::to_vec(&body).unwrap()),
            "/v1/messages",
            None,
        );
        let v: Value = serde_json::from_slice(&out).unwrap();
        let messages = v["messages"].as_array().unwrap();
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0]["content"][0]["id"], "a");
        assert_eq!(messages[1]["content"][0]["tool_use_id"], "a");
    }
}
