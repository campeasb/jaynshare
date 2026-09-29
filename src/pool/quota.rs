//! Buckets and how response headers teach them.
//! Also the 429 classification and the hold arithmetic it feeds.

use http::HeaderMap;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};

use crate::anthropic::{RATELIMIT_PREFIX, RATELIMIT_UNIFIED_PREFIX};

use super::account::Kind;

/// Bucket names. Family buckets are `weekly:<family>`.
pub const SESSION: &str = "session";
pub const WEEKLY: &str = "weekly";
pub const SPEND_CAP: &str = "spend-cap";
pub const API_KEY_BUCKETS: [&str; 4] = ["requests", "tokens", "input-tokens", "output-tokens"];
/// The one verified family and its header identifier.
pub const FAMILY_FABLE: &str = "fable";
pub const FAMILY_FABLE_HEADER: &str = "7d_oi";
pub const FAMILY_SONNET: &str = "sonnet";

pub fn is_bucket_name(name: &str) -> bool {
    name == SESSION
        || name == WEEKLY
        || name == SPEND_CAP
        || API_KEY_BUCKETS.contains(&name)
        || name
            .strip_prefix("weekly:")
            .is_some_and(|f| matches!(f, FAMILY_FABLE | FAMILY_SONNET))
}

/// The error code that classifies a 429 as organisation spend-cap exhaustion.
pub const SPEND_CAP_CODE: &str = "enforced_spend_limit_reached";

/// The buckets an account of this kind is expected to have.
pub fn expected_buckets(kind: Kind) -> Vec<Bucket> {
    match kind {
        Kind::OAuth => vec![
            Bucket::unknown(SESSION, Scope::Account),
            Bucket::unknown(WEEKLY, Scope::Account),
        ],
        Kind::ApiKey => API_KEY_BUCKETS
            .iter()
            .map(|n| Bucket::unknown(n, Scope::Account))
            .collect(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Scope {
    Account,
    Organisation,
    Family,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Source {
    ResponseHeaders,
    Usage,
    Revalidation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum State {
    Unknown,
    Available,
    Exhausted,
}

/// One bucket exactly as it is persisted.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Bucket {
    pub name: String,
    pub scope: Scope,
    pub utilization: Option<f64>,
    pub status: Option<String>,
    pub limit: Option<f64>,
    pub remaining: Option<f64>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub reset_at: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub observed_at: Option<OffsetDateTime>,
    pub source: Option<Source>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub exhaustion_hold_until: Option<OffsetDateTime>,
}

impl Bucket {
    pub fn unknown(name: &str, scope: Scope) -> Self {
        Self {
            name: name.to_string(),
            scope,
            utilization: None,
            status: None,
            limit: None,
            remaining: None,
            reset_at: None,
            observed_at: None,
            source: None,
            exhaustion_hold_until: None,
        }
    }

    pub fn state(&self, now: OffsetDateTime) -> State {
        if self.exhaustion_hold_until.is_some_and(|t| t > now) {
            State::Exhausted
        } else if self.observed_at.is_some() {
            State::Available
        } else {
            State::Unknown
        }
    }

    /// The stored fraction, or `1 - remaining / limit` for a counter bucket.
    pub fn effective_utilization(&self) -> Option<f64> {
        if let Some(u) = self.utilization {
            return Some(u);
        }
        let (limit, remaining) = (self.limit?, self.remaining?);
        (limit > 0.0 && remaining.is_finite() && (0.0..=limit).contains(&remaining))
            .then(|| 1.0 - remaining / limit)
    }

    /// At or after the reset the bucket is unknown again.
    fn expire(&mut self, now: OffsetDateTime) -> bool {
        let reset_passed = self.reset_at.is_some_and(|t| t <= now);
        let hold_passed =
            self.reset_at.is_none() && self.exhaustion_hold_until.is_some_and(|t| t <= now);
        if reset_passed || hold_passed {
            let (name, scope) = (self.name.clone(), self.scope);
            *self = Bucket::unknown(&name, scope);
            return true;
        }
        false
    }
}

/// One partial update to one bucket. `None` fields leave the older value.
#[derive(Debug, Clone, PartialEq)]
pub struct Observation {
    pub name: String,
    pub scope: Scope,
    pub utilization: Option<f64>,
    pub status: Option<String>,
    pub limit: Option<f64>,
    pub remaining: Option<f64>,
    pub reset_at: Option<OffsetDateTime>,
}

impl Observation {
    fn new(name: String, scope: Scope) -> Self {
        Self {
            name,
            scope,
            utilization: None,
            status: None,
            limit: None,
            remaining: None,
            reset_at: None,
        }
    }

    fn is_empty(&self) -> bool {
        self.utilization.is_none()
            && self.status.is_none()
            && self.limit.is_none()
            && self.remaining.is_none()
            && self.reset_at.is_none()
    }
}

/// Parse one usage response. Percent values become the
/// fractions used by the shared quota model; omitted windows remain omitted.
pub fn observe_usage(value: &Value) -> Result<Vec<Observation>, String> {
    let object = value
        .as_object()
        .ok_or_else(|| "usage response is not a JSON object".to_string())?;
    let mut observations = Vec::new();
    for (key, name, scope) in [
        ("five_hour", SESSION, Scope::Account),
        ("seven_day", WEEKLY, Scope::Account),
        ("seven_day_sonnet", "weekly:sonnet", Scope::Family),
    ] {
        let Some(window) = object.get(key).filter(|value| !value.is_null()) else {
            continue;
        };
        observations.push(usage_window(window, name, scope)?);
    }
    if let Some(limits) = object.get("limits") {
        let limits = limits
            .as_array()
            .ok_or_else(|| "usage response limits is not an array".to_string())?;
        for limit in limits {
            let is_fable = limit["group"] == "weekly"
                && limit
                    .pointer("/scope/model/display_name")
                    .and_then(Value::as_str)
                    .is_some_and(|name| name.to_ascii_lowercase().contains(FAMILY_FABLE));
            if is_fable {
                observations.push(usage_limit(limit, "weekly:fable")?);
            }
        }
    }
    observations.retain(|observation| !observation.is_empty());
    if observations.is_empty() {
        Err("usage response contains no recognised quota observations".into())
    } else {
        Ok(observations)
    }
}

fn usage_window(value: &Value, name: &str, scope: Scope) -> Result<Observation, String> {
    let object = value
        .as_object()
        .ok_or_else(|| format!("usage response {name} window is not an object"))?;
    let mut observation = Observation::new(name.to_string(), scope);
    observation.utilization = object
        .get("utilization")
        .or_else(|| object.get("used_percentage"))
        .and_then(percent);
    observation.reset_at = object.get("resets_at").and_then(reset_value);
    Ok(observation)
}

fn usage_limit(value: &Value, name: &str) -> Result<Observation, String> {
    let object = value
        .as_object()
        .ok_or_else(|| "usage response limit is not an object".to_string())?;
    let mut observation = Observation::new(name.to_string(), Scope::Family);
    observation.utilization = object.get("percent").and_then(percent);
    observation.reset_at = object.get("resets_at").and_then(reset_value);
    Ok(observation)
}

fn percent(value: &Value) -> Option<f64> {
    value
        .as_f64()
        .filter(|percent| percent.is_finite() && (0.0..=100.0).contains(percent))
        .map(|percent| percent / 100.0)
}

fn reset_value(value: &Value) -> Option<OffsetDateTime> {
    match value {
        Value::String(value) => parse_reset(value),
        Value::Number(value) => parse_reset(&value.to_string()),
        _ => None,
    }
}

/// What one attempt's response headers say about the serving account.
pub fn observe_headers(kind: Kind, headers: &HeaderMap) -> Vec<Observation> {
    let mut found: Vec<Observation> = Vec::new();
    fn slot(found: &mut Vec<Observation>, name: &str, scope: Scope) -> usize {
        match found.iter().position(|o| o.name == name) {
            Some(i) => i,
            None => {
                found.push(Observation::new(name.to_string(), scope));
                found.len() - 1
            }
        }
    }
    for (header, value) in headers {
        let Ok(value) = value.to_str() else { continue };
        let name = header.as_str();
        match kind {
            Kind::OAuth => {
                // anthropic-ratelimit-unified-<window>-<field>
                let Some(rest) = name.strip_prefix(RATELIMIT_UNIFIED_PREFIX) else {
                    continue;
                };
                let Some((window, field)) = rest.rsplit_once('-') else {
                    continue;
                };
                let (bucket, scope) = match window {
                    "5h" => (SESSION.to_string(), Scope::Account),
                    "7d" => (WEEKLY.to_string(), Scope::Account),
                    w if w == FAMILY_FABLE_HEADER => {
                        (format!("weekly:{FAMILY_FABLE}"), Scope::Family)
                    }
                    _ => continue,
                };
                let i = slot(&mut found, &bucket, scope);
                match field {
                    "utilization" => {
                        found[i].utilization =
                            value.trim().parse::<f64>().ok().filter(|u| u.is_finite())
                    }
                    "status" => found[i].status = Some(value.trim().to_string()),
                    "reset" => found[i].reset_at = parse_reset(value),
                    _ => {}
                }
            }
            Kind::ApiKey => {
                // anthropic-ratelimit-<bucket>-<limit|remaining|reset>
                let Some(rest) = name.strip_prefix(RATELIMIT_PREFIX) else {
                    continue;
                };
                if rest.starts_with("unified-") {
                    continue;
                }
                let Some((bucket, field)) = rest.rsplit_once('-') else {
                    continue;
                };
                if !API_KEY_BUCKETS.contains(&bucket) {
                    continue;
                }
                let i = slot(&mut found, bucket, Scope::Account);
                let number = || {
                    value
                        .trim()
                        .parse::<f64>()
                        .ok()
                        .filter(|n| n.is_finite() && *n >= 0.0)
                };
                match field {
                    "limit" => found[i].limit = number(),
                    "remaining" => found[i].remaining = number(),
                    "reset" => found[i].reset_at = parse_reset(value),
                    _ => {}
                }
            }
        }
    }
    found.retain(|o| !o.is_empty());
    found
}

/// What one 429 is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Classification {
    /// The named buckets are exhausted; the 429 is relayed and the bucket held.
    Exhaustion { buckets: Vec<String> },
    /// A burst throttle; admission is held and the client owns the wait.
    Throttle,
}

/// The spend-cap 429 carries the code under `error.details`.
pub fn spend_cap_429(body: Option<&[u8]>) -> bool {
    let Some(bytes) = body else { return false };
    serde_json::from_slice::<Value>(bytes)
        .ok()
        .and_then(|v| {
            v.pointer("/error/details/error_code")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .is_some_and(|code| code == SPEND_CAP_CODE)
}

/// The throttle hold length: `retry-after`, 60 s fallback, 1…300 s.
pub fn throttle_hold_seconds(retry_after: Option<u64>) -> u64 {
    retry_after.unwrap_or(60).clamp(1, 300)
}

/// The reset-less exhaustion fallback: `retry-after`, 60 s fallback, 1…3600 s.
pub fn exhaustion_fallback_seconds(retry_after: Option<u64>) -> u64 {
    retry_after.unwrap_or(60).clamp(1, 3600)
}

/// An authoritative exhaustion observation holds its bucket until the
/// reset when one is in the future; a reset-less rejection holds for the clamped
/// `retry-after`, and only ever extends a fallback hold that is still running.
pub fn hold_exhausted(bucket: &mut Bucket, retry_after: Option<u64>, now: OffsetDateTime) {
    let end = if let Some(reset) = bucket.reset_at.filter(|t| *t > now) {
        Some(reset)
    } else {
        let fallback = now + Duration::seconds(exhaustion_fallback_seconds(retry_after) as i64);
        Some(match bucket.exhaustion_hold_until.filter(|t| *t > now) {
            Some(existing) => existing.max(fallback),
            None => fallback,
        })
    };
    bucket.exhaustion_hold_until = end;
}

/// Classify one 429 from the body code and the rate-limit
/// facts, fresh from this response over the account's current observations.
/// `family` is the verified family name governing the attempted model, when
/// one is known; its bucket is `weekly:<family>`.
pub fn classify(
    kind: Kind,
    family: Option<&str>,
    observations: &[Observation],
    buckets: &[Bucket],
) -> Classification {
    let weekly = family
        .map(|f| format!("{WEEKLY}:{f}"))
        .unwrap_or_else(|| WEEKLY.to_string());
    let governed: Vec<&str> = match kind {
        Kind::OAuth => vec![SESSION, weekly.as_str()],
        Kind::ApiKey => API_KEY_BUCKETS.to_vec(),
    };
    let mut exhausted = Vec::new();
    for name in governed {
        let fresh = observations.iter().find(|o| o.name == name);
        let stored = buckets.iter().find(|b| b.name == name);
        let proved = match kind {
            // Status `rejected` (unknown words never count) or utilisation ≥ 1.
            Kind::OAuth => {
                let status = fresh
                    .and_then(|o| o.status.as_deref())
                    .or_else(|| stored.and_then(|b| b.status.as_deref()));
                let util = fresh
                    .and_then(|o| o.utilization)
                    .or_else(|| stored.and_then(|b| b.effective_utilization()));
                status == Some("rejected") || util.is_some_and(|u| u >= 1.0)
            }
            // The response makes a governing bucket's remaining zero.
            Kind::ApiKey => {
                let remaining = fresh
                    .and_then(|o| o.remaining)
                    .or_else(|| stored.and_then(|b| b.remaining));
                remaining == Some(0.0)
            }
        };
        if proved {
            exhausted.push(name.to_string());
        }
    }
    if exhausted.is_empty() {
        Classification::Throttle
    } else {
        Classification::Exhaustion { buckets: exhausted }
    }
}

/// Unix seconds, unix milliseconds or RFC 3339, all accepted.
pub fn parse_reset(value: &str) -> Option<OffsetDateTime> {
    let value = value.trim();
    if let Ok(n) = value.parse::<i64>() {
        // Below 1e11 the number cannot be milliseconds of any plausible date.
        let seconds = if n < 100_000_000_000 { n } else { n / 1000 };
        return OffsetDateTime::from_unix_timestamp(seconds).ok();
    }
    if let Ok(f) = value.parse::<f64>()
        && f.is_finite()
    {
        return OffsetDateTime::from_unix_timestamp(f as i64).ok();
    }
    OffsetDateTime::parse(value, &Rfc3339).ok()
}

/// Apply observations to the account's buckets; older observations are ignored.
pub fn apply(
    buckets: &mut Vec<Bucket>,
    observations: Vec<Observation>,
    source: Source,
    now: OffsetDateTime,
) {
    for o in observations {
        let bucket = match buckets.iter_mut().position(|b| b.name == o.name) {
            Some(i) => &mut buckets[i],
            None => {
                buckets.push(Bucket::unknown(&o.name, o.scope));
                buckets.last_mut().expect("just pushed")
            }
        };
        if bucket.observed_at.is_some_and(|t| t > now) {
            continue;
        }
        bucket.observed_at = Some(now);
        bucket.source = Some(source);
        bucket.utilization = o.utilization.or(bucket.utilization);
        bucket.status = o.status.or(bucket.status.take());
        bucket.limit = o.limit.or(bucket.limit);
        bucket.remaining = o.remaining.or(bucket.remaining);
        // An API-key reset not later than the observation (a replenished
        // token bucket "resets now") means no future reset was supplied — the
        // counters stand and no reset is stored, so reset expiry does not
        // remove them before the first snapshot. A future reset replaces the stored one.
        let replenished_now =
            API_KEY_BUCKETS.contains(&o.name.as_str()) && o.reset_at.is_some_and(|t| t <= now);
        bucket.reset_at = if replenished_now {
            None
        } else {
            o.reset_at.or(bucket.reset_at)
        };
        // Capacity seen clears an earlier exhaustion hold.
        if bucket.effective_utilization().is_some_and(|u| u < 1.0) {
            bucket.exhaustion_hold_until = None;
        }
    }
}

/// Run before any selection or snapshot. Returns whether any
/// bucket changed (the expiry is durable).
pub fn expire(buckets: &mut [Bucket], now: OffsetDateTime) -> bool {
    let mut changed = false;
    for b in buckets {
        changed |= b.expire(now);
    }
    changed
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;
    use time::macros::datetime;

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.append(
                k.parse::<http::HeaderName>().unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        h
    }

    #[test]
    fn unified_headers_become_session_and_weekly_observations() {
        let h = headers(&[
            ("anthropic-ratelimit-unified-5h-utilization", "0.42"),
            ("anthropic-ratelimit-unified-5h-status", "allowed"),
            ("anthropic-ratelimit-unified-5h-reset", "1757900000"),
            ("anthropic-ratelimit-unified-7d-utilization", "0.9"),
            ("anthropic-ratelimit-unified-7d_oi-utilization", "1.2"),
            ("anthropic-ratelimit-unified-status", "allowed"),
            (
                "anthropic-ratelimit-unified-representative-claim",
                "five_hour",
            ),
        ]);
        let obs = observe_headers(Kind::OAuth, &h);
        let names: Vec<&str> = obs.iter().map(|o| o.name.as_str()).collect();
        assert_eq!(names, ["session", "weekly", "weekly:fable"]);
        assert_eq!(obs[0].utilization, Some(0.42));
        assert_eq!(obs[0].status.as_deref(), Some("allowed"));
        assert_eq!(obs[0].reset_at.unwrap().unix_timestamp(), 1_757_900_000);
        assert_eq!(obs[2].scope, Scope::Family);
        assert_eq!(obs[2].utilization, Some(1.2));
    }

    #[test]
    fn api_key_headers_keep_four_independent_windows() {
        let h = headers(&[
            ("anthropic-ratelimit-requests-limit", "50"),
            ("anthropic-ratelimit-requests-remaining", "10"),
            ("anthropic-ratelimit-requests-reset", "2026-09-16T10:00:00Z"),
            ("anthropic-ratelimit-tokens-limit", "1000"),
            ("anthropic-ratelimit-tokens-remaining", "1000"),
            ("anthropic-ratelimit-unified-5h-utilization", "0.5"),
        ]);
        let obs = observe_headers(Kind::ApiKey, &h);
        let names: Vec<&str> = obs.iter().map(|o| o.name.as_str()).collect();
        assert_eq!(names, ["requests", "tokens"]);
        let mut buckets = expected_buckets(Kind::ApiKey);
        apply(
            &mut buckets,
            obs,
            Source::ResponseHeaders,
            datetime!(2026-09-16 09:00 UTC),
        );
        assert_eq!(buckets[0].effective_utilization(), Some(0.8));
        assert_eq!(buckets[1].effective_utilization(), Some(0.0));
        assert_eq!(buckets[2].effective_utilization(), None);
    }

    /// The live API returns `…-reset` equal to the response time for a
    /// replenished bucket; that observation must survive the reset expiry.
    #[test]
    fn an_api_key_reset_not_later_than_the_observation_stores_no_reset() {
        let now = datetime!(2026-09-20 20:33:31.5 UTC);
        let h = headers(&[
            ("anthropic-ratelimit-requests-limit", "10000"),
            ("anthropic-ratelimit-requests-remaining", "9999"),
            ("anthropic-ratelimit-requests-reset", "2026-09-20T20:33:31Z"),
            ("anthropic-ratelimit-tokens-limit", "1000"),
            ("anthropic-ratelimit-tokens-remaining", "0"),
            ("anthropic-ratelimit-tokens-reset", "2026-09-20T20:34:31Z"),
        ]);
        let mut buckets = expected_buckets(Kind::ApiKey);
        // An earlier depleted observation left a future reset on `requests`.
        buckets[0].reset_at = Some(datetime!(2026-09-20 20:40 UTC));
        apply(
            &mut buckets,
            observe_headers(Kind::ApiKey, &h),
            Source::ResponseHeaders,
            now,
        );
        assert!(
            !expire(&mut buckets, now),
            "nothing expires at the observation"
        );
        assert_eq!(buckets[0].state(now), State::Available);
        assert_eq!(
            buckets[0].reset_at, None,
            "a reset at the observation is no reset"
        );
        let u = buckets[0]
            .effective_utilization()
            .expect("derived from the counters");
        assert!((u - 0.0001).abs() < 1e-12, "{u}");
        // A genuinely future reset is stored and expires the bucket on time.
        assert_eq!(
            buckets[1].reset_at,
            Some(datetime!(2026-09-20 20:34:31 UTC))
        );
        assert_eq!(buckets[1].effective_utilization(), Some(1.0));
        assert!(expire(&mut buckets, datetime!(2026-09-20 20:34:31 UTC)));
        assert_eq!(buckets[1].state(now), State::Unknown);
        assert_eq!(
            buckets[0].state(now),
            State::Available,
            "requests keeps its facts"
        );
    }

    #[test]
    fn partial_update_keeps_older_fields_and_ignores_older_observations() {
        let mut buckets = expected_buckets(Kind::OAuth);
        let t1 = datetime!(2026-09-16 09:00 UTC);
        let first = observe_headers(
            Kind::OAuth,
            &headers(&[
                ("anthropic-ratelimit-unified-5h-utilization", "0.5"),
                ("anthropic-ratelimit-unified-5h-reset", "1757900000"),
            ]),
        );
        apply(&mut buckets, first, Source::ResponseHeaders, t1);
        let later = observe_headers(
            Kind::OAuth,
            &headers(&[("anthropic-ratelimit-unified-5h-utilization", "0.6")]),
        );
        apply(
            &mut buckets,
            later,
            Source::ResponseHeaders,
            t1 + time::Duration::seconds(1),
        );
        assert_eq!(buckets[0].utilization, Some(0.6));
        assert!(buckets[0].reset_at.is_some());
        let stale = observe_headers(
            Kind::OAuth,
            &headers(&[("anthropic-ratelimit-unified-5h-utilization", "0.1")]),
        );
        apply(
            &mut buckets,
            stale,
            Source::ResponseHeaders,
            t1 - time::Duration::seconds(1),
        );
        assert_eq!(buckets[0].utilization, Some(0.6));
        assert_eq!(buckets[1].state(t1), State::Unknown);
    }

    #[test]
    fn reset_expiry_leaves_the_bucket_unknown() {
        let mut buckets = expected_buckets(Kind::OAuth);
        let obs = observe_headers(
            Kind::OAuth,
            &headers(&[
                ("anthropic-ratelimit-unified-5h-utilization", "1.0"),
                ("anthropic-ratelimit-unified-5h-reset", "1757900000"),
            ]),
        );
        apply(
            &mut buckets,
            obs,
            Source::ResponseHeaders,
            datetime!(2026-09-14 00:00 UTC),
        );
        expire(
            &mut buckets,
            OffsetDateTime::from_unix_timestamp(1_757_900_000).unwrap(),
        );
        assert_eq!(buckets[0], Bucket::unknown(SESSION, Scope::Account));
    }

    #[test]
    fn reset_accepts_seconds_milliseconds_and_rfc3339() {
        let t = 1_757_900_000;
        assert_eq!(parse_reset("1757900000").unwrap().unix_timestamp(), t);
        assert_eq!(parse_reset("1757900000123").unwrap().unix_timestamp(), t);
        assert_eq!(
            parse_reset("2025-09-15T01:33:20Z")
                .unwrap()
                .unix_timestamp(),
            t
        );
        assert!(parse_reset("soon").is_none());
    }

    #[test]
    fn usage_percent_and_reset_shapes_become_shared_observations() {
        let usage = serde_json::json!({
            "five_hour": { "utilization": 25.0, "resets_at": 1_757_900_000 },
            "seven_day": { "used_percentage": 40.0, "resets_at": 1_757_900_000_123_i64 },
            "seven_day_sonnet": { "utilization": 12.5, "resets_at": "2025-09-15T01:33:20Z" },
            "limits": [{
                "group": "weekly",
                "scope": { "model": { "display_name": "Claude Fable" } },
                "percent": 110.0,
                "resets_at": "2025-09-15T01:33:20Z",
            }],
        });

        let observations = observe_usage(&usage).expect("valid usage response");

        assert_eq!(
            observations
                .iter()
                .map(|observation| observation.name.as_str())
                .collect::<Vec<_>>(),
            ["session", "weekly", "weekly:sonnet", "weekly:fable"]
        );
        assert_eq!(observations[0].utilization, Some(0.25));
        assert_eq!(observations[1].utilization, Some(0.4));
        assert_eq!(observations[2].utilization, Some(0.125));
        assert_eq!(
            observations[3].utilization, None,
            "percent is bounded to 0…100"
        );
        assert_eq!(observations[0].reset_at, observations[1].reset_at);
        assert_eq!(observations[1].reset_at, observations[2].reset_at);
    }
}
