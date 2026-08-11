//! The live coordinator state (bead S6 / bridge plan Phase S): the
//! first live mounts of the D024 [`TargetLeaseRegistry`], the D031
//! [`DestinationArbiter`], and a singleflight table keyed by the Epic F
//! action key. One binary, structural authority split (plan §10): the
//! edge routes every consult through THIS state in-process, and the
//! coord region owns its lifecycle.
//!
//! ## Shadow-tier singleflight window
//!
//! Production singleflight closes a flight when the action COMPLETES.
//! In shadow tier nothing completes through us — the wrapper execs the
//! compiler and its connection closes (fds are CLOEXEC). The flight
//! window is therefore CONNECTION-SCOPED: begin at consult, end when
//! the connection drops. Two overlapping consults for one key yield
//! exactly one leader and N followers, observable and receipted. (This
//! is also the design direction: a serving wrapper will hold its
//! connection through the compile, making the window the real one.)
//!
//! ## Degraded mode
//!
//! If the coord region is down (lab-injected today, crashed tomorrow),
//! edge consults DO NOT fail: they answer in the typed
//! `shadow-coord-degraded` mode — fail-open extends to the authority
//! split itself, and the shutdown receipt shows the coord region
//! abandoned so nothing hides.

use crate::coord::target_lease::TargetLeaseRegistry;
use crate::edge::destination_arbiter::DestinationArbiter;
use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

/// The role a consult played in its key's flight.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlightRole {
    /// First open flight for the key.
    Leader,
    /// Joined while the leader's flight is still open.
    Follower,
    /// Coord unavailable: no flight accounting (typed, never silent).
    Degraded,
}

impl FlightRole {
    /// Receipt/report label.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Leader => "leader",
            Self::Follower => "follower",
            Self::Degraded => "degraded",
        }
    }
}

/// The live coordinator state shared edge↔coord in-process.
#[derive(Debug, Default)]
pub struct CoordLive {
    available: AtomicBool,
    leases: Mutex<TargetLeaseRegistry>,
    arbiter: Mutex<DestinationArbiter>,
    flights: Mutex<HashMap<String, u64>>,
}

impl CoordLive {
    /// New (unavailable until the coord region marks itself up).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The coord region is up (called from coord work at boot).
    pub fn mark_up(&self) {
        self.available.store(true, Ordering::Release);
    }

    /// The coord region is down (shutdown or crash).
    pub fn mark_down(&self) {
        self.available.store(false, Ordering::Release);
    }

    /// Whether the authority split is live.
    #[must_use]
    pub fn available(&self) -> bool {
        self.available.load(Ordering::Acquire)
    }

    /// Begin a flight for `key` (connection-scoped window).
    #[must_use]
    pub fn begin_flight(&self, key: &str) -> FlightRole {
        if !self.available() {
            return FlightRole::Degraded;
        }
        let Ok(mut flights) = self.flights.lock() else {
            return FlightRole::Degraded;
        };
        let count = flights.entry(key.to_string()).or_insert(0);
        *count += 1;
        if *count == 1 {
            FlightRole::Leader
        } else {
            FlightRole::Follower
        }
    }

    /// End one flight participation for `key` (connection closed).
    pub fn end_flight(&self, key: &str) {
        if let Ok(mut flights) = self.flights.lock()
            && let Some(count) = flights.get_mut(key)
        {
            *count = count.saturating_sub(1);
            if *count == 0 {
                flights.remove(key);
            }
        }
    }

    /// Coord status as one JSON line (`--coord-status` surface).
    #[must_use]
    pub fn status_json(&self) -> String {
        let open_flights = self.flights.lock().map(|f| f.len()).unwrap_or(0);
        let (lease_holders, reservations) = (
            // The registries expose no len today; report mount state —
            // the numbers arrive when Phase 1 gives them real traffic.
            self.leases.lock().is_ok(),
            self.arbiter.lock().is_ok(),
        );
        format!(
            "{{\"v\":1,\"kind\":\"coord-status\",\"available\":{},\"open_flights\":{open_flights},\
             \"lease_registry_mounted\":{lease_holders},\"destination_arbiter_mounted\":{reservations}}}",
            self.available()
        )
    }

    /// Exclusive access to the lease registry (Phase 1 serving path).
    pub fn leases(&self) -> &Mutex<TargetLeaseRegistry> {
        &self.leases
    }

    /// Exclusive access to the destination arbiter (Phase 1 path).
    pub fn arbiter(&self) -> &Mutex<DestinationArbiter> {
        &self.arbiter
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overlapping_flights_one_leader_then_followers() {
        let coord = CoordLive::new();
        coord.mark_up();
        assert_eq!(coord.begin_flight("k1"), FlightRole::Leader);
        assert_eq!(coord.begin_flight("k1"), FlightRole::Follower);
        assert_eq!(coord.begin_flight("k1"), FlightRole::Follower);
        // A different key gets its own leader.
        assert_eq!(coord.begin_flight("k2"), FlightRole::Leader);
        // Window closes only when every participant ends.
        coord.end_flight("k1");
        coord.end_flight("k1");
        assert_eq!(
            coord.begin_flight("k1"),
            FlightRole::Follower,
            "leader still open"
        );
        coord.end_flight("k1");
        coord.end_flight("k1");
        assert_eq!(
            coord.begin_flight("k1"),
            FlightRole::Leader,
            "window closed"
        );
    }

    #[test]
    fn degraded_mode_is_typed_never_silent() {
        let coord = CoordLive::new(); // never marked up
        assert_eq!(coord.begin_flight("k"), FlightRole::Degraded);
        coord.mark_up();
        assert_eq!(coord.begin_flight("k"), FlightRole::Leader);
        coord.mark_down();
        assert_eq!(coord.begin_flight("k"), FlightRole::Degraded);
    }

    #[test]
    fn status_reports_mounts_and_open_flights() {
        let coord = CoordLive::new();
        coord.mark_up();
        let _ = coord.begin_flight("k1");
        let status = coord.status_json();
        assert!(status.contains("\"available\":true"), "{status}");
        assert!(status.contains("\"open_flights\":1"), "{status}");
        assert!(
            status.contains("\"lease_registry_mounted\":true"),
            "{status}"
        );
        assert!(
            status.contains("\"destination_arbiter_mounted\":true"),
            "{status}"
        );
    }
}
