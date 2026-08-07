//! Monotonic TTL/renewal lease semantics (bead J026; risk R73; the
//! F023 renewal-sequence rule + coordinator-clock expiry composed).
//!
//! Authority NEVER hinges on comparing unsynchronized wall clocks:
//!
//! - the coordinator issues TTLs as DURATIONS; each host arms a
//!   MONOTONIC local timer from its own receipt instant — no host
//!   ever evaluates another host's timestamp;
//! - renewals carry strictly-increasing sequence numbers (F023's
//!   `LeaseRenewalSeq`); a renewal's authority is its sequence, not
//!   its arrival time;
//! - wall-clock timestamps may ride messages as DIAGNOSTICS — the
//!   lease evaluator here takes no wall-clock parameter, so a skewed
//!   clock cannot flip authority even in principle;
//! - expiry is judged by each side on ITS OWN monotonic clock: the
//!   coordinator's judgment governs authority; the worker's judgment
//!   governs self-fencing (stop offering when the local timer says
//!   expired — conservative, may only under-claim).

use crate::generation::LeaseRenewalSeq;

/// One side's monotonic lease view (all instants are THAT side's own
/// monotonic milliseconds; no cross-host comparison exists).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MonotonicLease {
    /// TTL duration the coordinator issued (ms).
    pub ttl_ms: u64,
    /// This side's OWN monotonic instant at receipt/renewal.
    pub armed_at_own_monotonic_ms: u64,
    /// Last accepted renewal sequence.
    pub renewal_seq: LeaseRenewalSeq,
}

/// Renewal outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RenewalOutcome {
    /// Strictly newer sequence: accepted, timer re-armed.
    Accepted,
    /// Stale/replayed sequence: refused, timer untouched.
    RefusedStaleSequence,
}

impl MonotonicLease {
    /// Whether the lease is live at `now` on THIS side's monotonic
    /// clock. Conservative at the edge: expired exactly at TTL.
    #[must_use]
    pub const fn live(&self, own_monotonic_now_ms: u64) -> bool {
        own_monotonic_now_ms.saturating_sub(self.armed_at_own_monotonic_ms) < self.ttl_ms
    }

    /// Apply a renewal: SEQUENCE decides, never arrival time.
    pub fn renew(
        &mut self,
        seq: LeaseRenewalSeq,
        own_monotonic_now_ms: u64,
        new_ttl_ms: u64,
    ) -> RenewalOutcome {
        if seq <= self.renewal_seq {
            return RenewalOutcome::RefusedStaleSequence;
        }
        self.renewal_seq = seq;
        self.armed_at_own_monotonic_ms = own_monotonic_now_ms;
        self.ttl_ms = new_ttl_ms;
        RenewalOutcome::Accepted
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lease(armed_at: u64, seq: u64) -> MonotonicLease {
        MonotonicLease {
            ttl_ms: 5_000,
            armed_at_own_monotonic_ms: armed_at,
            renewal_seq: LeaseRenewalSeq(seq),
        }
    }

    #[test]
    fn expiry_is_judged_on_each_sides_own_monotonic_clock() {
        let coordinator_view = lease(1_000, 1);
        // Live inside the window, expired at/after TTL — on the
        // coordinator's OWN clock.
        assert!(coordinator_view.live(5_999));
        assert!(!coordinator_view.live(6_000));
        // The worker armed the SAME lease at a completely different
        // monotonic origin (its own boot clock): its judgment uses its
        // own numbers — no cross-host comparison ever occurs.
        let worker_view = lease(777_000, 1);
        assert!(worker_view.live(781_999));
        assert!(!worker_view.live(782_000));
    }

    #[test]
    fn clock_skew_chaos_never_flips_authority() {
        // THE acceptance: wall clocks are wildly skewed (hours apart,
        // running backwards) — IRRELEVANT, because the evaluator has
        // no wall-clock parameter. Authority follows renewal
        // sequences alone.
        let mut lease_state = lease(0, 5);
        // A "late" renewal (imagine its wall-clock stamp is from
        // yesterday): sequence 6 > 5, ACCEPTED.
        assert_eq!(
            lease_state.renew(LeaseRenewalSeq(6), 100, 5_000),
            RenewalOutcome::Accepted
        );
        // A "fresh-looking" replay (wall-clock stamp from the future,
        // if anyone looked): sequence 6 again — REFUSED, timer
        // untouched.
        let before = lease_state;
        assert_eq!(
            lease_state.renew(LeaseRenewalSeq(6), 200, 5_000),
            RenewalOutcome::RefusedStaleSequence
        );
        assert_eq!(lease_state, before, "a refused renewal changes nothing");
        // Monotonic regression on the caller side cannot resurrect an
        // expired lease: saturating age math means now < armed_at
        // reads as age 0 — the lease looks LIVE (conservative for the
        // worker's self-fence) but authority still requires the
        // coordinator's own judgment, which never regressed.
        let armed = lease(1_000, 1);
        assert!(
            armed.live(500),
            "saturating math: never panics, never negative"
        );
    }

    #[test]
    fn renewals_re_arm_the_local_timer_with_the_issued_ttl() {
        let mut lease_state = lease(0, 1);
        assert!(!lease_state.live(5_000), "about to expire");
        assert_eq!(
            lease_state.renew(LeaseRenewalSeq(2), 4_999, 10_000),
            RenewalOutcome::Accepted
        );
        // Re-armed from the renewal instant with the NEW ttl.
        assert!(lease_state.live(14_998));
        assert!(!lease_state.live(14_999));
    }

    #[test]
    fn no_wall_clock_parameter_exists() {
        // Structural: the lease type carries durations + own-monotonic
        // instants + sequences — no unix/wall field exists to compare.
        let MonotonicLease {
            ttl_ms: _,
            armed_at_own_monotonic_ms: _,
            renewal_seq: _,
        } = lease(0, 1);
    }
}
