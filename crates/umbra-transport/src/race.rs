//! The connection race of Part 3 §3.8: TCP/443 against QUIC/443 with a
//! head start for TCP, and a cached winner for each network under a
//! 24-hour lifetime.
//!
//! The policy is pure. The runtime asks it what to start and when, and
//! tells it what won.

use alloc::{string::String, vec::Vec};

/// The head start of TCP, in milliseconds.
pub const TCP_HEAD_START_MS: u64 = 250;
/// The lifetime of a cached winner, in seconds.
pub const WINNER_TTL: u64 = 24 * 3_600;

/// The two transports of L1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Wire {
    /// TLS 1.3 over TCP with the WebSocket upgrade.
    Tcp,
    /// QUIC over UDP.
    Quic,
}

/// What the runtime starts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Plan {
    /// Use one transport and race nothing, from a cached winner.
    Only(Wire),
    /// Start TCP now and QUIC after the head start.
    Race {
        /// The delay before the QUIC attempt starts, in milliseconds.
        quic_after_ms: u64,
    },
}

/// The winner cache, keyed by the network identifier the platform gives:
/// an SSID or a PLMN.
#[derive(Default)]
pub struct WinnerCache {
    entries: Vec<(String, Wire, u64)>,
}

impl WinnerCache {
    /// The plan for `network` at `now`.
    pub fn plan(&self, network: &str, now: u64) -> Plan {
        match self.lookup(network, now) {
            Some(wire) => Plan::Only(wire),
            None => Plan::Race {
                quic_after_ms: TCP_HEAD_START_MS,
            },
        }
    }

    /// The cached winner for `network`, if it is inside `WINNER_TTL`.
    pub fn lookup(&self, network: &str, now: u64) -> Option<Wire> {
        self.entries
            .iter()
            .find(|(n, _, at)| n == network && now.saturating_sub(*at) < WINNER_TTL)
            .map(|(_, w, _)| *w)
    }

    /// Records the transport that completed first on `network` at `now`.
    pub fn record(&mut self, network: &str, wire: Wire, now: u64) {
        self.entries.retain(|(n, _, _)| n != network);
        self.entries.push((String::from(network), wire, now));
    }

    /// Forgets a winner that then failed, thus the next connection races
    /// again.
    pub fn forget(&mut self, network: &str) {
        self.entries.retain(|(n, _, _)| n != network);
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic
)]
mod tests {
    use super::*;

    #[test]
    fn the_winner_is_cached_for_a_day_on_its_network() {
        let mut cache = WinnerCache::default();
        assert_eq!(
            cache.plan("home", 0),
            Plan::Race {
                quic_after_ms: TCP_HEAD_START_MS
            }
        );
        cache.record("home", Wire::Quic, 100);
        assert_eq!(cache.plan("home", 200), Plan::Only(Wire::Quic));
        assert!(matches!(cache.plan("office", 200), Plan::Race { .. }));
        assert!(matches!(
            cache.plan("home", 100 + WINNER_TTL),
            Plan::Race { .. }
        ));
        cache.record("home", Wire::Tcp, 500);
        assert_eq!(cache.lookup("home", 600), Some(Wire::Tcp));
        cache.forget("home");
        assert_eq!(cache.lookup("home", 600), None);
    }
}
