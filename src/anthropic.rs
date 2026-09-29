//! Third-party facts about the upstream API. Nothing here is ours to change.

use http::HeaderName;

/// the API host; inference and telemetry.
pub const API_ORIGIN: &str = "https://api.anthropic.com";
/// the beta an OAuth (subscription) bearer needs in `anthropic-beta`.
pub const OAUTH_BETA: &str = "oauth-2025-04-20";
/// profile endpoint path on the API host.
pub const PROFILE_PATH: &str = "/api/oauth/profile";
/// the zero-spend OAuth usage endpoint.
pub const USAGE_PATH: &str = "/api/oauth/usage";
/// Claude Code's telemetry path.
pub const TELEMETRY_PATH: &str = "/api/event_logging";
/// account-bound paths on the API host, as observed; the list is
/// open and grows with the live gates. `<org>` is one path segment.
const ACCOUNT_BOUND_PATHS: &[&str] = &[
    "/api/oauth/account/settings",
    "/api/oauth/organizations/<org>/marketplaces",
    "/api/oauth/organizations/<org>/plugins/list-plugins",
    "/api/oauth/organizations/<org>/skills/list-skills",
    "/api/claude_code_grove",
    "/v1/mcp_servers",
];

/// whether `path` (no query) answers for one account.
pub fn is_account_bound(path: &str) -> bool {
    let segments: Vec<&str> = path.split('/').collect();
    ACCOUNT_BOUND_PATHS.iter().any(|form| {
        let form: Vec<&str> = form.split('/').collect();
        form.len() == segments.len()
            && form
                .iter()
                .zip(&segments)
                .all(|(f, s)| if *f == "<org>" { !s.is_empty() } else { f == s })
    })
}

/// the two paths whose tool pairs are made consistent.
pub const MESSAGES_PATH: &str = "/v1/messages";
pub const COUNT_TOKENS_PATH: &str = "/v1/messages/count_tokens";

pub const ANTHROPIC_BETA: HeaderName = HeaderName::from_static("anthropic-beta");
pub const X_API_KEY: HeaderName = HeaderName::from_static("x-api-key");
pub const X_CLAUDE_CODE_SESSION_ID: HeaderName =
    HeaderName::from_static("x-claude-code-session-id");
pub const X_JAYNSHARE_ACCOUNT: HeaderName = HeaderName::from_static("x-jaynshare-account");
pub const RATELIMIT_PREFIX: &str = "anthropic-ratelimit-";
pub const RATELIMIT_UNIFIED_PREFIX: &str = "anthropic-ratelimit-unified-";

/// the browser authorisation page.
pub const AUTHORIZE_URL: &str = "https://claude.ai/oauth/authorize";
/// the OAuth token endpoint host and path.
pub const TOKEN_ORIGIN: &str = "https://platform.claude.com";
pub const TOKEN_PATH: &str = "/v1/oauth/token";
/// the public client id the login and refresh calls carry.
pub const OAUTH_CLIENT_ID: &str = "9d1c250a-e61b-44d9-88ed-5944d1962f5e";

/// the scopes one browser login asks for, space separated.
pub const OAUTH_SCOPES: &str = "org:create_api_key user:profile user:inference user:sessions:claude_code user:mcp_servers user:file_upload";
/// where the browser may land after a completed login.
pub const OAUTH_SUCCESS_URL: &str =
    "https://platform.claude.com/oauth/code/success?app=claude-code";

/// error classes by status, plus our own `proxy_error`.
pub mod error_type {
    pub const INVALID_REQUEST: &str = "invalid_request_error";
    pub const AUTHENTICATION: &str = "authentication_error";
    pub const REQUEST_TOO_LARGE: &str = "request_too_large";
    pub const NOT_FOUND: &str = "not_found_error";
    pub const RATE_LIMIT: &str = "rate_limit_error";
    pub const PROXY: &str = "proxy_error";
}

/// error envelope: `{"type":"error","error":{"type":…,"message":…},"request_id":…}`.
pub fn error_envelope(error_type: &str, message: &str) -> serde_json::Value {
    serde_json::json!({
        "type": "error",
        "error": { "type": error_type, "message": message },
        "request_id": serde_json::Value::Null,
    })
}

#[cfg(test)]
mod tests {
    use super::is_account_bound;

    #[test]
    fn the_listed_forms_are_account_bound() {
        assert!(is_account_bound("/api/oauth/account/settings"));
        assert!(is_account_bound(
            "/api/oauth/organizations/org-1/skills/list-skills"
        ));
        assert!(is_account_bound("/v1/mcp_servers"));
    }

    #[test]
    fn neighbours_of_the_forms_are_not() {
        assert!(!is_account_bound("/api/oauth/organizations//marketplaces"));
        assert!(!is_account_bound(
            "/api/oauth/organizations/a/b/marketplaces"
        ));
        assert!(!is_account_bound("/v1/mcp_servers/extra"));
        assert!(!is_account_bound("/api/event_logging/v2/batch"));
        assert!(!is_account_bound("/v1/messages"));
    }
}
