//! The egress guard: when a pin is configured, no
//! attempt goes out while the server's public address is not one of the pinned
//! ones. Off — and the check URL unfetched — when no pin is configured.

use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use bytes::Bytes;
use http::{Method, Request};
use http_body_util::{BodyExt, Full};
use serde::Serialize;
use time::OffsetDateTime;

use crate::config::{EgressMode, EgressSettings};
use crate::server::Server;

/// The check timeout and the hold poll are constants; only the cache and
/// the hold budget are configurable.
const CHECK_TIMEOUT: Duration = Duration::from_secs(5);
const HOLD_POLL: Duration = Duration::from_secs(3);
/// `retry-after` on the 503.
pub const HOLD_RETRY_AFTER: u64 = 30;

/// What one check observed, cached for `cache_seconds`. `None` is an
/// observation too: a failed or timed-out check is *unknown*, and unknown never
/// blocks — the cache stops a dead check service being hammered per exchange.
#[derive(Debug, Default)]
struct Shared {
    observed: Option<(Option<IpAddr>, OffsetDateTime)>,
    /// `auto` pins the first address observed after start.
    auto_pin: Option<IpAddr>,
}

#[derive(Debug, Default)]
struct PolicyState {
    shared: StdMutex<Shared>,
    inflight: tokio::sync::Mutex<()>,
}

/// The guard's state in the status snapshot.
#[derive(Debug, Clone, Serialize)]
pub struct View {
    pub pinned_addresses: Vec<IpAddr>,
    pub observed_address: Option<IpAddr>,
    pub observed_at: Option<OffsetDateTime>,
    pub held_now: usize,
}

pub struct Guard {
    /// A reload replaces this state. Exchanges already holding an `Arc` keep
    /// the policy snapshot they started with, while the next exchange
    /// performs a fresh check for the new policy.
    policy: StdMutex<Arc<PolicyState>>,
    /// how many exchanges are held right now.
    held: AtomicUsize,
    client: hyper_util::client::legacy::Client<
        hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
        Full<Bytes>,
    >,
}

impl Default for Guard {
    fn default() -> Self {
        // The upstream connector's trust store (`tls::client_config`). A host
        // with no root bundle gets an empty store, so the address check fails
        // as a TLS error and is reported, instead of the server panicking at
        // startup.
        let tls = super::tls::client_config()
            .map(|config| (*config).clone())
            .unwrap_or_else(|_| {
                rustls::ClientConfig::builder()
                    .with_root_certificates(rustls::RootCertStore::empty())
                    .with_no_client_auth()
            });
        let https = hyper_rustls::HttpsConnectorBuilder::new()
            .with_tls_config(tls)
            .https_or_http()
            .enable_http1()
            .build();
        Self {
            policy: StdMutex::new(Arc::new(PolicyState::default())),
            held: AtomicUsize::new(0),
            client: hyper_util::client::legacy::Client::builder(
                hyper_util::rt::TokioExecutor::new(),
            )
            .build(https),
        }
    }
}

/// The hold ran out while the address stayed wrong.
#[derive(Debug)]
pub struct Held {
    pub observed: IpAddr,
    pub pinned: Vec<IpAddr>,
}

impl std::fmt::Display for Held {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "the server's public address is {}, not one of the pinned {}",
            self.observed,
            self.pinned
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        )
    }
}

/// Counts the exchange in `held` for as long as it lives; a client that
/// leaves mid-hold releases its slot through the drop.
struct Holding<'a> {
    guard: &'a Guard,
}

impl Drop for Holding<'_> {
    fn drop(&mut self) {
        self.guard.held.fetch_sub(1, Ordering::Relaxed);
    }
}

impl Guard {
    fn policy(&self) -> Arc<PolicyState> {
        Arc::clone(&self.policy.lock().expect("guard policy lock"))
    }

    /// A changed live policy starts with no cached observation or automatic
    /// pin. Existing exchanges retain the old state through their `Arc`.
    pub fn reconfigure(&self) {
        *self.policy.lock().expect("guard policy lock") = Arc::new(PolicyState::default());
    }

    fn pinned(policy: &PolicyState, settings: &EgressSettings) -> Vec<IpAddr> {
        match settings.mode {
            EgressMode::Off | EgressMode::AllowList => settings.addresses.clone(),
            EgressMode::Auto => policy
                .shared
                .lock()
                .expect("guard lock")
                .auto_pin
                .into_iter()
                .collect(),
        }
    }

    /// One observation, cached `cache_seconds`; `fresh` skips the cache (the
    /// hold loop re-checks every 3 s). Callers arriving together share
    /// the fetch through the in-flight lock.
    async fn observe(
        &self,
        policy: &PolicyState,
        settings: &EgressSettings,
        fresh: bool,
    ) -> Option<IpAddr> {
        let previous = policy
            .shared
            .lock()
            .expect("guard lock")
            .observed
            .map(|(_, at)| at);
        if !fresh && let Some(address) = Self::cached(policy, settings) {
            return address;
        }
        let _inflight = policy.inflight.lock().await;
        if fresh {
            let shared = policy.shared.lock().expect("guard lock");
            if shared.observed.map(|(_, at)| at) != previous {
                return shared.observed.and_then(|(address, _)| address);
            }
        } else if let Some(address) = Self::cached(policy, settings) {
            return address;
        }
        let observed = self.fetch(&settings.check_url).await;
        let mut shared = policy.shared.lock().expect("guard lock");
        shared.observed = Some((observed, OffsetDateTime::now_utc()));
        observed
    }

    /// The outer option says whether a fresh cached observation exists; the
    /// inner option is the observed address. A failed check is cached too.
    fn cached(policy: &PolicyState, settings: &EgressSettings) -> Option<Option<IpAddr>> {
        policy
            .shared
            .lock()
            .expect("guard lock")
            .observed
            .filter(|(_, at)| {
                OffsetDateTime::now_utc() - *at
                    < time::Duration::seconds(settings.cache_seconds as i64)
            })
            .map(|(address, _)| address)
    }

    /// A plain-text single-line answer, 5 s deadline; any failure is unknown.
    async fn fetch(&self, url: &http::Uri) -> Option<IpAddr> {
        match self.try_fetch(url).await {
            Ok(address) => Some(address),
            Err(reason) => {
                // A failed check is unknown, never a block; say why.
                tracing::warn!(event = "egress_check_failed", reason = %reason, "the egress check failed; the address is unknown until the next check");
                None
            }
        }
    }

    async fn try_fetch(&self, url: &http::Uri) -> Result<IpAddr, String> {
        let request = Request::builder()
            .method(Method::GET)
            .uri(url.clone())
            .body(Full::new(Bytes::new()))
            .expect("a fixed URL builds");
        let response = tokio::time::timeout(CHECK_TIMEOUT, self.client.request(request))
            .await
            .map_err(|_| "timed out".to_string())?
            .map_err(|e| format!("request failed: {e}"))?;
        let status = response.status();
        let body = tokio::time::timeout(CHECK_TIMEOUT, response.into_body().collect())
            .await
            .map_err(|_| "timed out reading the body".to_string())?
            .map_err(|e| format!("body failed: {e}"))?
            .to_bytes();
        if !status.is_success() {
            return Err(format!("HTTP {status}"));
        }
        String::from_utf8_lossy(&body)
            .lines()
            .next()
            .ok_or_else(|| "empty body".to_string())?
            .trim()
            .parse()
            .map_err(|_| "body is not an IP address".to_string())
    }

    /// The state `status --json` shows.
    pub fn view(&self, settings: &EgressSettings) -> View {
        let policy = self.policy();
        let shared = policy.shared.lock().expect("guard lock");
        let (observed_address, observed_at) = shared
            .observed
            .map_or((None, None), |(address, at)| (address, Some(at)));
        let pinned_addresses = match settings.mode {
            EgressMode::Off | EgressMode::AllowList => settings.addresses.clone(),
            EgressMode::Auto => shared.auto_pin.into_iter().collect(),
        };
        View {
            pinned_addresses,
            observed_address,
            observed_at,
            held_now: self.held.load(Ordering::Relaxed),
        }
    }
}

/// Hold the exchange until the observed address is one of the pinned
/// ones, at most `hold_seconds`. Unknown never blocks; mode
/// off never fetches.
pub async fn gate(server: &Server, settings: &EgressSettings) -> Result<(), Held> {
    if settings.mode == EgressMode::Off {
        return Ok(());
    }
    let policy = server.egress.policy();
    let budget = tokio::time::Instant::now() + Duration::from_secs(settings.hold_seconds);
    let mut holding: Option<Holding> = None;
    loop {
        // `auto` pins the first address observed after start.
        if settings.mode == EgressMode::Auto
            && policy.shared.lock().expect("guard lock").auto_pin.is_none()
        {
            return match server.egress.observe(&policy, settings, true).await {
                None => Ok(()), // unknown never blocks
                Some(address) => {
                    {
                        let mut shared = policy.shared.lock().expect("guard lock");
                        shared.auto_pin.get_or_insert(address);
                        shared.observed = Some((Some(address), OffsetDateTime::now_utc()));
                    }
                    tracing::info!(event = "egress_pinned", address = %address, "the first observed address is now the pin");
                    Ok(())
                }
            };
        }
        let pinned = Guard::pinned(&policy, settings);
        match server
            .egress
            .observe(&policy, settings, holding.is_some())
            .await
        {
            None => return Ok(()), // unknown never blocks (see the auto branch above)
            Some(observed) if pinned.contains(&observed) => {
                if let Some(h) = holding.take() {
                    tracing::info!(event = "egress_returned", observed = %observed, pinned = ?pinned, "the public address is pinned again");
                    drop(h);
                }
                return Ok(());
            }
            Some(observed) => {
                if holding.is_none() {
                    server.egress.held.fetch_add(1, Ordering::Relaxed);
                    holding = Some(Holding {
                        guard: &server.egress,
                    });
                    tracing::warn!(event = "egress_hold", observed = %observed, pinned = ?pinned, "the public address is not pinned; holding attempts");
                }
                let now = tokio::time::Instant::now();
                if now >= budget {
                    drop(holding.take());
                    return Err(Held { observed, pinned });
                }
                // The last recheck lands at the budget's end, not one poll past it.
                tokio::time::sleep(HOLD_POLL.min(budget - now)).await;
            }
        }
    }
}
