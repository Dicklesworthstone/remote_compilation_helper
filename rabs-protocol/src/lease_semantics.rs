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

/// Negotiated request-scoped execution liveness protocol. This is not an
/// action-generation lease and grants no result publication authority.
pub const REQUEST_EXECUTION_LEASE_VERSION: &str = "request-renewal-v1";
/// Normal worker-local lease duration, independent of the command timeout.
pub const DEFAULT_TTL_MS: u64 = 30_000;
/// Smallest supported lease duration.
pub const MIN_TTL_MS: u64 = 1_000;
/// Largest supported lease duration; negotiation cannot authorize an unbounded run.
pub const MAX_TTL_MS: u64 = 60_000;
/// Coordinator renewal cadence for the default lease.
pub const RENEW_INTERVAL_MS: u64 = 10_000;

/// Exact execution owner selected over one authenticated worker session.
///
/// The request digest names the unchanged canonical request, not an ActionKey.
/// The session and lease IDs are fresh transport scope; the worker incarnation
/// prevents a grant for a previous process from being reused after restart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestExecutionLeaseIdentity {
    /// Authenticated session that selected this lease.
    pub session_id: u64,
    /// Fresh lease ID issued by this session's coordinator.
    pub lease_id: u64,
    /// Durable canonical execution request ID. Zero is valid in the existing
    /// canonical request protocol and remains an exact correlation identity.
    pub request_id: u64,
    /// SHA-256 of the complete original request's agreed encoding.
    pub request_sha256: [u8; 32],
    /// Worker durable boot generation named by the authenticated hello.
    pub boot_generation: u64,
    /// Worker process incarnation named by the authenticated hello.
    pub incarnation: u128,
}

impl RequestExecutionLeaseIdentity {
    /// Refuse sentinel identities before any execution lease can be armed.
    pub fn validate(&self) -> Result<(), RequestLeaseError> {
        if self.session_id == 0
            || self.lease_id == 0
            || self.request_sha256 == [0; 32]
            || self.boot_generation == 0
            || self.incarnation == 0
        {
            Err(RequestLeaseError::InvalidIdentity)
        } else {
            Ok(())
        }
    }
}

/// Why an execution lease could not be created, observed, or renewed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestLeaseError {
    /// An identity field uses its forbidden zero sentinel.
    InvalidIdentity,
    /// TTL is outside the negotiated protocol's supported range.
    InvalidTtl,
    /// The renewal names another session, request, lease, or worker incarnation.
    IdentityMismatch,
    /// Renewal sequence was already accepted or is older than the current one.
    StaleSequence,
    /// No larger sequence can be represented; this lease is permanently closed.
    SequenceExhausted,
    /// The worker's own clock regressed; this lease is permanently closed.
    ClockRegressed,
    /// The next local expiry is not representable; no lease remains live.
    ClockOverflow,
    /// The worker observed its local TTL boundary; renewal cannot revive it.
    Expired,
    /// The owner explicitly closed the lease for cancellation or completion.
    Closed,
}

impl std::fmt::Display for RequestLeaseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidIdentity => "invalid request execution lease identity",
            Self::InvalidTtl => "request execution lease TTL is outside protocol bounds",
            Self::IdentityMismatch => "request execution lease identity mismatch",
            Self::StaleSequence => "stale request execution lease renewal",
            Self::SequenceExhausted => "request execution lease sequence exhausted",
            Self::ClockRegressed => "request execution lease local clock regressed",
            Self::ClockOverflow => "request execution lease local expiry overflow",
            Self::Expired => "request execution lease expired",
            Self::Closed => "request execution lease closed",
        })
    }
}

impl std::error::Error for RequestLeaseError {}

/// Bounded, non-revivable execution liveness for one unchanged request.
///
/// The worker adapter supplies milliseconds from its own monotonic clock and
/// serializes access with execution completion/cancellation. This type performs
/// no I/O and reads no clocks. It composes the existing monotonic TTL primitive
/// with the terminal-state and identity checks required by a live process.
/// Neither a renewal nor a protocol error may extend the command's independent
/// maximum execution duration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestExecutionLease {
    identity: RequestExecutionLeaseIdentity,
    lease: MonotonicLease,
    expires_at_ms: u64,
    last_observed_ms: u64,
    closed: Option<RequestLeaseError>,
}

impl RequestExecutionLease {
    /// Arm sequence zero at this worker's own receipt instant. The TTL is fixed
    /// for the lifetime of this lease and cannot be changed by renewal frames.
    pub fn new(
        identity: RequestExecutionLeaseIdentity,
        ttl_ms: u64,
        own_now_ms: u64,
    ) -> Result<Self, RequestLeaseError> {
        identity.validate()?;
        if !(MIN_TTL_MS..=MAX_TTL_MS).contains(&ttl_ms) {
            return Err(RequestLeaseError::InvalidTtl);
        }
        let expires_at_ms = own_now_ms
            .checked_add(ttl_ms)
            .ok_or(RequestLeaseError::ClockOverflow)?;
        Ok(Self {
            identity,
            lease: MonotonicLease {
                ttl_ms,
                armed_at_own_monotonic_ms: own_now_ms,
                renewal_seq: LeaseRenewalSeq(0),
            },
            expires_at_ms,
            last_observed_ms: own_now_ms,
            closed: None,
        })
    }

    /// Exact owner; renewals cannot replace any of its fields.
    #[must_use]
    pub const fn identity(&self) -> &RequestExecutionLeaseIdentity {
        &self.identity
    }

    /// Fixed negotiated TTL, in milliseconds on the worker's own clock.
    #[must_use]
    pub const fn ttl_ms(&self) -> u64 {
        self.lease.ttl_ms
    }

    /// Last accepted sequence. Initial admission is zero; the first renewal is
    /// newer than zero. Gaps are harmless, while replays never rearm the timer.
    #[must_use]
    pub const fn renewal_seq(&self) -> u64 {
        self.lease.renewal_seq.0
    }

    /// Whether expiry, cancellation, completion, or a local clock failure has
    /// permanently closed this lease. This does not sample the local clock.
    #[must_use]
    pub const fn is_closed(&self) -> bool {
        self.closed.is_some()
    }

    /// Check the local deadline and permanently close on expiry or regression.
    /// A later clock value or renewal cannot erase that observed terminal state.
    pub fn live(&mut self, own_now_ms: u64) -> Result<(), RequestLeaseError> {
        if let Some(reason) = self.closed {
            return Err(reason);
        }
        if own_now_ms < self.last_observed_ms {
            self.closed = Some(RequestLeaseError::ClockRegressed);
            return Err(RequestLeaseError::ClockRegressed);
        }
        self.last_observed_ms = own_now_ms;
        if own_now_ms >= self.expires_at_ms || !self.lease.live(own_now_ms) {
            self.closed = Some(RequestLeaseError::Expired);
            return Err(RequestLeaseError::Expired);
        }
        Ok(())
    }

    /// Renew the same live owner with a strictly newer sequence. Foreign
    /// identities never mutate this lease. Replays do not move its deadline;
    /// checking their receipt time may still observe and retain real expiry.
    pub fn renew(
        &mut self,
        identity: &RequestExecutionLeaseIdentity,
        sequence: u64,
        own_now_ms: u64,
    ) -> Result<(), RequestLeaseError> {
        if identity != &self.identity {
            return Err(RequestLeaseError::IdentityMismatch);
        }
        self.live(own_now_ms)?;
        if self.renewal_seq() == u64::MAX {
            self.closed = Some(RequestLeaseError::SequenceExhausted);
            return Err(RequestLeaseError::SequenceExhausted);
        }
        if sequence <= self.renewal_seq() {
            return Err(RequestLeaseError::StaleSequence);
        }
        let Some(expires_at_ms) = own_now_ms.checked_add(self.ttl_ms()) else {
            self.closed = Some(RequestLeaseError::ClockOverflow);
            return Err(RequestLeaseError::ClockOverflow);
        };
        // The identity, lifetime, clock, and sequence checks above precede this
        // primitive, whose standalone renewal API intentionally has no closure.
        let outcome = self
            .lease
            .renew(LeaseRenewalSeq(sequence), own_now_ms, self.lease.ttl_ms);
        debug_assert_eq!(outcome, RenewalOutcome::Accepted);
        self.expires_at_ms = expires_at_ms;
        Ok(())
    }

    /// Close once when the process owner cancels or freezes its terminal result.
    /// Existing expiry/clock failures retain their original reason.
    pub fn close(&mut self) -> bool {
        if self.closed.is_some() {
            return false;
        }
        self.closed = Some(RequestLeaseError::Closed);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request_identity() -> RequestExecutionLeaseIdentity {
        RequestExecutionLeaseIdentity {
            session_id: 7,
            lease_id: 19,
            request_id: 41,
            request_sha256: [0xab; 32],
            boot_generation: 3,
            incarnation: 99,
        }
    }

    #[test]
    fn request_lease_requires_complete_identity_and_bounded_ttl() {
        let identity = request_identity();
        for field in 0..5 {
            let mut invalid = identity;
            match field {
                0 => invalid.session_id = 0,
                1 => invalid.lease_id = 0,
                2 => invalid.request_sha256 = [0; 32],
                3 => invalid.boot_generation = 0,
                4 => invalid.incarnation = 0,
                _ => unreachable!(),
            }
            assert_eq!(
                RequestExecutionLease::new(invalid, DEFAULT_TTL_MS, 0),
                Err(RequestLeaseError::InvalidIdentity),
            );
        }
        let mut zero_request = identity;
        zero_request.request_id = 0;
        assert!(RequestExecutionLease::new(zero_request, DEFAULT_TTL_MS, 0).is_ok());
        for ttl in [0, MIN_TTL_MS - 1, MAX_TTL_MS + 1, u64::MAX] {
            assert_eq!(
                RequestExecutionLease::new(identity, ttl, 0),
                Err(RequestLeaseError::InvalidTtl),
            );
        }
        for ttl in [MIN_TTL_MS, DEFAULT_TTL_MS, MAX_TTL_MS] {
            let mut lease = RequestExecutionLease::new(identity, ttl, 1_234).unwrap();
            assert_eq!(lease.identity(), &identity);
            assert_eq!(lease.ttl_ms(), ttl);
            assert_eq!(lease.renewal_seq(), 0);
            assert_eq!(lease.live(1_234 + ttl - 1), Ok(()));
            assert_eq!(lease.live(1_234 + ttl), Err(RequestLeaseError::Expired));
        }
    }

    #[test]
    fn quiet_execution_stays_live_only_while_its_owner_renews() {
        let identity = request_identity();
        let mut lease = RequestExecutionLease::new(identity, DEFAULT_TTL_MS, 0).unwrap();
        // Three renewals keep a quiet compiler alive beyond its initial TTL.
        // Nothing in this model changes the caller's separate command budget.
        for sequence in 1..=3 {
            let received = sequence * RENEW_INTERVAL_MS;
            assert_eq!(lease.renew(&identity, sequence, received), Ok(()));
            assert_eq!(lease.ttl_ms(), DEFAULT_TTL_MS);
        }
        assert_eq!(
            lease.live(3 * RENEW_INTERVAL_MS + DEFAULT_TTL_MS - 1),
            Ok(())
        );
        assert_eq!(
            lease.live(3 * RENEW_INTERVAL_MS + DEFAULT_TTL_MS),
            Err(RequestLeaseError::Expired),
        );
        assert_eq!(lease.renewal_seq(), 3);
    }

    #[test]
    fn foreign_renewals_cannot_retarget_an_existing_execution() {
        let identity = request_identity();
        let original = RequestExecutionLease::new(identity, DEFAULT_TTL_MS, 500).unwrap();
        for field in 0..6 {
            let mut foreign = identity;
            match field {
                0 => foreign.session_id += 1,
                1 => foreign.lease_id += 1,
                2 => foreign.request_id += 1,
                3 => foreign.request_sha256[0] ^= 1,
                4 => foreign.boot_generation += 1,
                5 => foreign.incarnation += 1,
                _ => unreachable!(),
            }
            let mut lease = original.clone();
            assert_eq!(
                lease.renew(&foreign, 1, 1_000),
                Err(RequestLeaseError::IdentityMismatch),
            );
            assert_eq!(
                lease, original,
                "identity field {field} changed the real owner"
            );
            assert_eq!(lease.renew(&identity, 1, 1_000), Ok(()));
        }
    }

    #[test]
    fn replayed_or_reordered_renewals_do_not_delay_expiry() {
        let identity = request_identity();
        let mut lease = RequestExecutionLease::new(identity, MIN_TTL_MS, 0).unwrap();
        assert_eq!(
            lease.renew(&identity, 0, 1),
            Err(RequestLeaseError::StaleSequence)
        );
        assert_eq!(lease.renew(&identity, 5, 500), Ok(()));
        for (sequence, now) in [(5, 750), (4, 1_000), (0, 1_499)] {
            assert_eq!(
                lease.renew(&identity, sequence, now),
                Err(RequestLeaseError::StaleSequence),
            );
            assert_eq!(lease.renewal_seq(), 5);
        }
        assert_eq!(lease.live(1_500), Err(RequestLeaseError::Expired));
    }

    #[test]
    fn newer_sequence_cannot_revive_expiry_even_without_an_earlier_expiry_poll() {
        let identity = request_identity();
        for observe_first in [false, true] {
            let mut lease = RequestExecutionLease::new(identity, MIN_TTL_MS, 100).unwrap();
            if observe_first {
                assert_eq!(lease.live(1_100), Err(RequestLeaseError::Expired));
            }
            assert_eq!(
                lease.renew(&identity, 1, 1_100),
                Err(RequestLeaseError::Expired)
            );
            assert_eq!(
                lease.renew(&identity, 2, 100),
                Err(RequestLeaseError::Expired)
            );
            assert_eq!(lease.live(100), Err(RequestLeaseError::Expired));
            assert_eq!(lease.renewal_seq(), 0);
            assert!(lease.is_closed());
            assert!(
                !lease.close(),
                "closing again must retain the expiry reason"
            );
        }
    }

    #[test]
    fn cancellation_or_completion_permanently_closes_renewal() {
        let identity = request_identity();
        let mut lease = RequestExecutionLease::new(identity, DEFAULT_TTL_MS, 100).unwrap();
        assert_eq!(lease.renew(&identity, 1, 200), Ok(()));
        assert!(lease.close());
        assert!(!lease.close());
        for now in [0, 200, 300, u64::MAX] {
            assert_eq!(lease.live(now), Err(RequestLeaseError::Closed));
            assert_eq!(
                lease.renew(&identity, 2, now),
                Err(RequestLeaseError::Closed)
            );
        }
        assert_eq!(lease.renewal_seq(), 1);
    }

    #[test]
    fn regressing_local_clock_fences_instead_of_extending_a_live_lease() {
        let identity = request_identity();
        for regression_in_renewal in [false, true] {
            let mut lease = RequestExecutionLease::new(identity, DEFAULT_TTL_MS, 500).unwrap();
            assert_eq!(lease.live(1_000), Ok(()));
            let result = if regression_in_renewal {
                lease.renew(&identity, 1, 999)
            } else {
                lease.live(999)
            };
            assert_eq!(result, Err(RequestLeaseError::ClockRegressed));
            assert_eq!(lease.live(1_001), Err(RequestLeaseError::ClockRegressed));
            assert_eq!(
                lease.renew(&identity, 2, 1_002),
                Err(RequestLeaseError::ClockRegressed)
            );
            assert_eq!(lease.renewal_seq(), 0);
        }
    }

    #[test]
    fn local_deadline_overflow_never_wraps_into_a_new_valid_lease() {
        let identity = request_identity();
        assert_eq!(
            RequestExecutionLease::new(identity, MIN_TTL_MS, u64::MAX - MIN_TTL_MS + 1),
            Err(RequestLeaseError::ClockOverflow),
        );
        let mut last =
            RequestExecutionLease::new(identity, MIN_TTL_MS, u64::MAX - MIN_TTL_MS).unwrap();
        assert_eq!(last.live(u64::MAX - 1), Ok(()));
        assert_eq!(last.live(u64::MAX), Err(RequestLeaseError::Expired));

        let mut lease = RequestExecutionLease::new(identity, 2_000, u64::MAX - 3_000).unwrap();
        assert_eq!(
            lease.renew(&identity, 1, u64::MAX - 1_500),
            Err(RequestLeaseError::ClockOverflow),
        );
        assert_eq!(lease.renewal_seq(), 0);
        assert_eq!(
            lease.live(u64::MAX - 1_499),
            Err(RequestLeaseError::ClockOverflow)
        );
    }

    #[test]
    fn sequence_exhaustion_closes_without_wrapping_to_initial_admission() {
        let identity = request_identity();
        let mut lease = RequestExecutionLease::new(identity, DEFAULT_TTL_MS, 0).unwrap();
        assert_eq!(lease.renew(&identity, u64::MAX, 1_000), Ok(()));
        assert_eq!(lease.renewal_seq(), u64::MAX);
        assert_eq!(
            lease.renew(&identity, 0, 2_000),
            Err(RequestLeaseError::SequenceExhausted)
        );
        assert_eq!(
            lease.renew(&identity, u64::MAX, 3_000),
            Err(RequestLeaseError::SequenceExhausted)
        );
        assert!(lease.is_closed());
        assert_eq!(lease.renewal_seq(), u64::MAX);
    }

    #[test]
    fn request_leases_use_only_their_local_monotonic_origin() {
        let identity = request_identity();
        for origin in [0, 123_456, u64::MAX - 100_000] {
            let mut lease = RequestExecutionLease::new(identity, DEFAULT_TTL_MS, origin).unwrap();
            assert_eq!(lease.renew(&identity, 1, origin + 20_000), Ok(()));
            assert_eq!(lease.live(origin + 49_999), Ok(()));
            assert_eq!(lease.live(origin + 50_000), Err(RequestLeaseError::Expired));
        }
    }

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
