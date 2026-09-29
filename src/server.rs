//! The running instance: configuration in force, the pool, the audit log, the
//! upstream client and shutdown. Everything the listeners share.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use time::OffsetDateTime;
use tokio::sync::watch;

use crate::audit::{AuditLog, Record};
use crate::capture::Capture;
use crate::config::{AccountSettings, ConfigError, LoadedConfig};
use crate::data_plane::{egress, upstream::Upstream};
use crate::login::Logins;
use crate::pool::{Pool, probe::Probes, refresh::Refreshes};
use crate::registry::Registry;
use crate::state::{self, State};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const COMMIT: &str = env!("JAYNSHARE_COMMIT");
pub const TARGET: &str = env!("JAYNSHARE_TARGET");

/// Why the server is stopping (the exit codes of the CLI's table).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stop {
    /// A stop signal: exit 0 after the flush.
    Signal,
    /// Audit or state became unwritable; exit 23.
    Unwritable,
}

/// What the last reload decided — a control reload call or SIGHUP.
#[derive(Debug, Clone)]
pub struct ReloadOutcome {
    pub at: OffsetDateTime,
    /// `None` when the file could not be read: no bytes, no digest.
    pub digest: Option<String>,
    pub applied: bool,
    pub changed_keys: Vec<String>,
    pub rejected_restart_keys: Vec<String>,
    /// One entry per independently detectable error.
    pub errors: Vec<ConfigError>,
}

/// The configuration in force and its history. Readers clone the
/// `Arc` when they begin — that clone is the snapshot one exchange sees —
/// and reloads run one at a time under `last`.
pub struct Configuration {
    loaded: RwLock<Arc<LoadedConfig>>,
    /// When the bytes in force were loaded: start, or the last applied reload.
    pub loaded_at: RwLock<OffsetDateTime>,
    pub last: Mutex<Option<ReloadOutcome>>,
}

impl Configuration {
    /// The configuration in force now; a caller keeps it for the whole of
    /// one exchange, probe or ramp.
    pub fn current(&self) -> Arc<LoadedConfig> {
        Arc::clone(&self.loaded.read().expect("configuration lock"))
    }

    /// An atomic boundary. Called under the pool lock so a cross-
    /// reference verdict and the swap see one pool.
    pub fn replace(&self, loaded: LoadedConfig, now: OffsetDateTime) {
        *self.loaded.write().expect("configuration lock") = Arc::new(loaded);
        *self.loaded_at.write().expect("configuration lock") = now;
    }
}

pub struct Server {
    pub configuration: Configuration,
    pub pool: Mutex<Pool>,
    pub audit: AuditLog,
    pub capture: Option<Capture>,
    pub upstream: Upstream,
    /// The started browser logins.
    pub logins: Logins,
    pub refreshes: Refreshes,
    pub probes: Probes,
    /// The egress guard and its state.
    pub egress: egress::Guard,
    pub started_at: OffsetDateTime,
    pub state_path: PathBuf,
    /// The start-time verdict on the trust material, `None` when
    /// the mode is off or the material is unusable. The rotate path
    /// is the only thing that replaces it while serving.
    mitm_ca: Mutex<Option<Arc<crate::mitm::ca::Ca>>>,
    /// The open-tunnel gauges and the counters since start.
    pub mitm: Arc<crate::mitm::counters::Counters>,
    carried: Mutex<State>,
    quota_dirty: AtomicBool,
    /// When the fallback line was last written, per advisor model.
    advisor_fallback_logged: Mutex<HashMap<String, Instant>>,
    stop: watch::Sender<Option<Stop>>,
}

#[derive(Debug)]
pub enum MutateError<E> {
    Refused(E),
    /// The state write failed; the live pool is unchanged.
    Persist(std::io::Error),
}

impl Server {
    pub fn new(
        loaded: LoadedConfig,
        state: State,
        pool: Pool,
        audit: AuditLog,
        capture: Option<Capture>,
        upstream: Upstream,
    ) -> Self {
        let (stop, _) = watch::channel(None);
        let state_path = loaded.config.storage.state_file.clone();
        let probe_settings = loaded.config.quota.clone();
        let started_at = OffsetDateTime::now_utc();
        Self {
            configuration: Configuration {
                loaded: RwLock::new(Arc::new(loaded)),
                loaded_at: RwLock::new(started_at),
                last: Mutex::new(None),
            },
            pool: Mutex::new(pool),
            audit,
            capture,
            upstream,
            logins: Logins::default(),
            refreshes: Refreshes::default(),
            probes: Probes::new(probe_settings),
            egress: egress::Guard::default(),
            started_at,
            state_path,
            mitm_ca: Mutex::new(None),
            mitm: Arc::new(crate::mitm::counters::Counters::default()),
            carried: Mutex::new(State {
                accounts: Vec::new(),
                ..state
            }),
            quota_dirty: AtomicBool::new(false),
            advisor_fallback_logged: Mutex::new(HashMap::new()),
            stop,
        }
    }

    /// The configuration in force when the caller begins.
    pub fn config(&self) -> Arc<LoadedConfig> {
        self.configuration.current()
    }

    /// The start-time verdict, installed before the startup line.
    pub fn set_mitm_ca(&self, ca: Option<Arc<crate::mitm::ca::Ca>>) {
        *self.mitm_ca.lock().expect("mitm ca lock") = ca;
    }

    /// The CA in force, or `None` when the mode is off or the material is
    /// unusable. A tunnel that already holds one keeps it.
    pub fn mitm_ca(&self) -> Option<Arc<crate::mitm::ca::Ca>> {
        self.mitm_ca.lock().expect("mitm ca lock").clone()
    }

    /// A refresh takes the settings in force when it starts.
    pub fn refresh_settings(&self) -> AccountSettings {
        self.config().config.accounts.clone()
    }

    /// One line per advisor model per minute when the second pass served.
    pub fn log_advisor_fallback(&self, advisor_model: &str) {
        let mut logged = self.advisor_fallback_logged.lock().expect("fallback lock");
        let now = Instant::now();
        let due = logged
            .get(advisor_model)
            .is_none_or(|last| now.duration_since(*last) >= Duration::from_secs(60));
        if due {
            logged.insert(advisor_model.to_string(), now);
            tracing::info!(
                event = "advisor_fallback",
                advisor_model,
                "no account serves both models; the request model alone selected"
            );
        }
    }

    /// The bootstrap exception holds until the first client or operator secret exists.
    pub fn bootstrap(&self) -> bool {
        let carried = self.carried.lock().expect("state lock");
        carried.clients.is_empty() && carried.operator.is_none()
    }

    /// The registry in force, cloned for a read (principal resolution, the snapshot).
    pub fn registry(&self) -> Registry {
        let carried = self.carried.lock().expect("state lock");
        Registry {
            clients: carried.clients.clone(),
            operator: carried.operator.clone(),
        }
    }

    /// A registry mutation is written durably before it takes effect
    /// or reports success; a failed write leaves both unchanged.
    pub fn mutate_registry<T, E>(
        &self,
        f: impl FnOnce(&mut Registry) -> Result<T, E>,
    ) -> Result<T, MutateError<E>> {
        // The pool lock first, the same order `mutate_pool` uses.
        let accounts = self.pool.lock().expect("pool lock").accounts().to_vec();
        let mut carried = self.carried.lock().expect("state lock");
        let mut candidate = Registry {
            clients: carried.clients.clone(),
            operator: carried.operator.clone(),
        };
        let out = f(&mut candidate).map_err(MutateError::Refused)?;
        let organization_quota = {
            let pool = self.pool.lock().expect("pool lock");
            pool.organisation_quota_records()
        };
        state::write(
            &self.state_path,
            &State {
                accounts,
                organization_quota,
                clients: candidate.clients.clone(),
                operator: candidate.operator.clone(),
            },
        )
        .map_err(MutateError::Persist)?;
        carried.clients = candidate.clients;
        carried.operator = candidate.operator;
        Ok(out)
    }

    pub fn stop_signal(&self) -> watch::Receiver<Option<Stop>> {
        self.stop.subscribe()
    }

    pub fn request_stop(&self, why: Stop) {
        self.stop.send_if_modified(|current| {
            if current.is_none() {
                *current = Some(why);
                true
            } else {
                false
            }
        });
    }

    pub fn stopping(&self) -> bool {
        self.stop.borrow().is_some()
    }

    fn durable_state(&self, pool: &Pool) -> State {
        let carried = self.carried.lock().expect("state lock");
        State {
            accounts: pool.accounts().to_vec(),
            // The pool's organisation entries are the durable quota.
            organization_quota: pool.organisation_quota_records(),
            clients: carried.clients.clone(),
            operator: carried.operator.clone(),
        }
    }

    /// The candidate is written durably before it becomes the live pool.
    pub fn mutate_pool<T, E>(
        &self,
        f: impl FnOnce(&mut Pool) -> Result<T, E>,
    ) -> Result<T, MutateError<E>> {
        let mut live = self.pool.lock().expect("pool lock");
        let mut candidate = live.clone();
        let out = f(&mut candidate).map_err(MutateError::Refused)?;
        state::write(&self.state_path, &self.durable_state(&candidate))
            .map_err(MutateError::Persist)?;
        *live = candidate;
        Ok(out)
    }

    /// Quota changes coalesce into one write within a second.
    pub fn mark_quota_dirty(&self) {
        self.quota_dirty.store(true, Ordering::Release);
    }

    /// Quota changes coalesce into one write within a second;
    /// reset expiry is written with them, request counters alone never
    /// dirty the file. A clean shutdown flushes through here too.
    pub fn flush_quota(&self) -> std::io::Result<()> {
        let dirty = {
            let mut pool = self.pool.lock().expect("pool lock");
            let expired = pool.expire_quota(OffsetDateTime::now_utc());
            let marked = self.quota_dirty.swap(false, Ordering::AcqRel);
            expired || marked
        };
        if !dirty {
            return Ok(());
        }
        let snapshot = {
            let pool = self.pool.lock().expect("pool lock");
            self.durable_state(&pool)
        };
        state::write(&self.state_path, &snapshot)
    }

    /// A failed audit append stops admission and the process.
    pub fn record_exchange(&self, record: &Record) {
        if let Err(e) = self.audit.append(record) {
            tracing::error!(event = "audit_write_failed", error = %e, "audit append failed; stopping admission");
            self.request_stop(Stop::Unwritable);
        }
    }
}
