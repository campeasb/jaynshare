//! The live numbers: the open-tunnel gauges and the counters since
//! start. One instance per server; every surface reads [`Counters::snapshot`].

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use http::StatusCode;
use serde::Serialize;

/// Open tunnels are a gauge — an [`Open`] guard decrements on drop, so a
/// relay task that panics or is cancelled still leaves the count right.
#[derive(Default)]
pub struct Counters {
    intercepted_open: AtomicU64,
    tunnelled_open: AtomicU64,
    intercepted_exchanges: AtomicU64,
    tunnels_opened: AtomicU64,
    connect_refused_407: AtomicU64,
    connect_refused_403: AtomicU64,
    connect_unreachable: AtomicU64,
    failed_handshakes: AtomicU64,
}

/// What `status` shows.
#[derive(Debug, Clone, Serialize)]
pub struct Snapshot {
    pub tunnels: Tunnels,
    pub counters: Totals,
}

#[derive(Debug, Clone, Serialize)]
pub struct Tunnels {
    pub intercepted: u64,
    pub tunnelled: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Totals {
    pub intercepted_exchanges: u64,
    pub tunnels_opened: u64,
    pub connect_refused_407: u64,
    pub connect_refused_403: u64,
    pub connect_unreachable: u64,
    pub failed_handshakes: u64,
}

/// Which gauge an open tunnel belongs to (the snapshot splits the two).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Intercepted,
    Tunnelled,
}

impl Counters {
    /// One tunnel's life: taken when the `200` goes out, released when the
    /// relay or the intercepted session ends.
    pub fn open(self: &Arc<Self>, kind: Kind) -> Open {
        self.tunnels_opened.fetch_add(1, Ordering::Relaxed);
        self.gauge(kind).fetch_add(1, Ordering::Relaxed);
        Open {
            counters: Arc::clone(self),
            kind,
        }
    }

    /// Refused `CONNECT`s by class. A `200` counts nothing here;
    /// `502` and `504` are both the unreachable class.
    pub fn record_connect(&self, status: StatusCode) {
        let counter = match status {
            StatusCode::PROXY_AUTHENTICATION_REQUIRED => &self.connect_refused_407,
            StatusCode::FORBIDDEN => &self.connect_refused_403,
            StatusCode::BAD_GATEWAY | StatusCode::GATEWAY_TIMEOUT => &self.connect_unreachable,
            _ => return,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// One per failed handshake, beside its log line.
    pub fn record_failed_handshake(&self) {
        self.failed_handshakes.fetch_add(1, Ordering::Relaxed);
    }

    /// One per request decoded from an intercepted tunnel, whatever
    /// the data plane then answers.
    pub fn record_intercepted_exchange(&self) {
        self.intercepted_exchanges.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            tunnels: Tunnels {
                intercepted: self.intercepted_open.load(Ordering::Relaxed),
                tunnelled: self.tunnelled_open.load(Ordering::Relaxed),
            },
            counters: Totals {
                intercepted_exchanges: self.intercepted_exchanges.load(Ordering::Relaxed),
                tunnels_opened: self.tunnels_opened.load(Ordering::Relaxed),
                connect_refused_407: self.connect_refused_407.load(Ordering::Relaxed),
                connect_refused_403: self.connect_refused_403.load(Ordering::Relaxed),
                connect_unreachable: self.connect_unreachable.load(Ordering::Relaxed),
                failed_handshakes: self.failed_handshakes.load(Ordering::Relaxed),
            },
        }
    }

    fn gauge(&self, kind: Kind) -> &AtomicU64 {
        match kind {
            Kind::Intercepted => &self.intercepted_open,
            Kind::Tunnelled => &self.tunnelled_open,
        }
    }
}

/// An open tunnel's place in the gauge, released on drop.
pub struct Open {
    counters: Arc<Counters>,
    kind: Kind,
}

impl Drop for Open {
    fn drop(&mut self) {
        self.counters
            .gauge(self.kind)
            .fetch_sub(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_gauge_follows_open_tunnels_and_the_totals_only_rise() {
        let counters = Arc::new(Counters::default());
        let intercepted = counters.open(Kind::Intercepted);
        {
            let _tunnelled = counters.open(Kind::Tunnelled);
            let now = counters.snapshot();
            assert_eq!((now.tunnels.intercepted, now.tunnels.tunnelled), (1, 1));
            assert_eq!(now.counters.tunnels_opened, 2);
        }
        drop(intercepted);
        let now = counters.snapshot();
        assert_eq!((now.tunnels.intercepted, now.tunnels.tunnelled), (0, 0));
        assert_eq!(now.counters.tunnels_opened, 2);
    }

    #[test]
    fn every_refusal_class_has_its_own_counter_and_a_200_none() {
        let counters = Counters::default();
        for status in [
            StatusCode::PROXY_AUTHENTICATION_REQUIRED,
            StatusCode::FORBIDDEN,
            StatusCode::BAD_GATEWAY,
            StatusCode::GATEWAY_TIMEOUT,
            StatusCode::OK,
            StatusCode::BAD_REQUEST,
        ] {
            counters.record_connect(status);
        }
        let now = counters.snapshot().counters;
        assert_eq!(now.connect_refused_407, 1);
        assert_eq!(now.connect_refused_403, 1);
        assert_eq!(now.connect_unreachable, 2, "502 and 504 are one class");
    }
}
