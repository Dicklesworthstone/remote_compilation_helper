//! RABS-owned causal-time, deadline-budget, peer, and sequence-domain wire
//! types (bead A023; invariants I14 and I52).
//!
//! Stable wire and persistence schemas use **RABS-owned** timestamps,
//! budgets, durations, peer IDs, and sequence domains — never a foreign
//! runtime's implementation types. In particular, cross-host deadlines are
//! **relative budgets** plus causal/wall-clock *diagnostic* metadata, never
//! a process-local `Instant` (which is meaningless on another host and
//! unserializable by design).
//!
//! Sequence domains realize invariant I52: authority/control, action
//! lifecycle, subscriber delivery, object transfer, and telemetry each own
//! an independent monotonic sequence; cross-domain ordering claims are a
//! type error here, so a missing bulk-transfer range can never be expressed
//! as "blocking" a cancellation (risk R109).

use std::fmt;

/// Milliseconds of *remaining* budget for an operation, decremented as work
/// proceeds. Saturating: exhaustion is a state, not an overflow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct DeadlineBudget {
    /// Remaining milliseconds.
    pub remaining_ms: u64,
}

impl DeadlineBudget {
    /// A budget with the given remaining milliseconds.
    #[must_use]
    pub const fn from_ms(remaining_ms: u64) -> Self {
        Self { remaining_ms }
    }

    /// Spend part of the budget (saturating at zero).
    #[must_use]
    pub const fn spend_ms(self, ms: u64) -> Self {
        Self {
            remaining_ms: self.remaining_ms.saturating_sub(ms),
        }
    }

    /// Whether the budget is exhausted.
    #[must_use]
    pub const fn is_exhausted(self) -> bool {
        self.remaining_ms == 0
    }
}

/// A causal timestamp: a Lamport-style logical counter scoped to its
/// issuing peer, plus optional wall-clock microseconds carried strictly as
/// DIAGNOSTIC metadata (lease validity and authority decisions never
/// compare unsynchronized wall clocks — plan §22/§52; risk R73).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CausalTimestamp {
    /// The issuing peer.
    pub peer: PeerId,
    /// Monotonic logical counter at that peer.
    pub logical: u64,
    /// Optional wall-clock microseconds since the Unix epoch — diagnostic
    /// only, never an ordering or validity input across hosts.
    pub wall_clock_diagnostic_us: Option<i64>,
}

impl CausalTimestamp {
    /// Causal ordering against another stamp FROM THE SAME PEER.
    /// Cross-peer stamps are causally incomparable without message edges,
    /// so this returns `None` rather than inventing an order.
    #[must_use]
    pub fn same_peer_ordering(&self, other: &Self) -> Option<std::cmp::Ordering> {
        (self.peer == other.peer).then(|| self.logical.cmp(&other.logical))
    }
}

/// Durable peer identity (public-key derived in the transport; opaque
/// string here). Configuration labels are aliases, never identity proof.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PeerId(pub String);

impl fmt::Display for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The independent reliable sequence domains (invariant I52). Critical
/// cancellation/lease/fencing traffic never waits behind a missing
/// bulk-data sequence "merely to preserve a fictitious global total order".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SequenceDomain {
    /// Coordinator authority, fencing, lease renewal, cancellation.
    AuthorityControl,
    /// Per-attempt action lifecycle events.
    ActionLifecycle,
    /// Per-subscriber delivery stream (transcript + stateful items).
    SubscriberDelivery,
    /// Per-transfer object movement.
    ObjectTransfer,
    /// Best-effort telemetry (loss-tolerant; no replay window).
    TelemetryBestEffort,
}

/// A sequence number bound to its domain. Comparisons across domains are
/// refused at the type level of the API (`Option`), which is the point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DomainSequence {
    /// The domain this sequence belongs to.
    pub domain: SequenceDomain,
    /// Monotonic sequence within the domain.
    pub seq: u64,
}

impl DomainSequence {
    /// Ordering within the SAME domain; `None` across domains — there is no
    /// global total order to appeal to (risk R109).
    #[must_use]
    pub fn same_domain_ordering(&self, other: &Self) -> Option<std::cmp::Ordering> {
        (self.domain == other.domain).then(|| self.seq.cmp(&other.seq))
    }

    /// The next sequence in this domain (saturating; a domain that actually
    /// reaches u64::MAX must roll a new session, never wrap — wrap would be
    /// an ABA hazard).
    #[must_use]
    pub const fn next(self) -> Self {
        Self {
            domain: self.domain,
            seq: self.seq.saturating_add(1),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cmp::Ordering;

    #[test]
    fn budgets_spend_saturating_and_report_exhaustion() {
        let b = DeadlineBudget::from_ms(100);
        let b = b.spend_ms(60);
        assert_eq!(b.remaining_ms, 40);
        let b = b.spend_ms(500);
        assert!(b.is_exhausted());
        assert_eq!(b.remaining_ms, 0, "saturating, never wrapping");
    }

    #[test]
    fn causal_stamps_only_order_within_one_peer() {
        let a1 = CausalTimestamp {
            peer: PeerId("edge-a".into()),
            logical: 1,
            wall_clock_diagnostic_us: Some(1_000),
        };
        let a2 = CausalTimestamp {
            peer: PeerId("edge-a".into()),
            logical: 2,
            // Wall clock went BACKWARD; ordering must not care.
            wall_clock_diagnostic_us: Some(500),
        };
        let b1 = CausalTimestamp {
            peer: PeerId("edge-b".into()),
            logical: 99,
            wall_clock_diagnostic_us: None,
        };
        assert_eq!(a1.same_peer_ordering(&a2), Some(Ordering::Less));
        assert_eq!(
            a1.same_peer_ordering(&b1),
            None,
            "cross-peer stamps are causally incomparable"
        );
    }

    #[test]
    fn sequences_never_compare_across_domains() {
        let cancel = DomainSequence {
            domain: SequenceDomain::AuthorityControl,
            seq: 3,
        };
        let bulk = DomainSequence {
            domain: SequenceDomain::ObjectTransfer,
            seq: 1_000_000,
        };
        assert_eq!(
            cancel.same_domain_ordering(&bulk),
            None,
            "a bulk gap must be inexpressible as blocking a cancellation (R109)"
        );
        let cancel2 = cancel.next();
        assert_eq!(cancel.same_domain_ordering(&cancel2), Some(Ordering::Less));
    }

    #[test]
    fn sequence_next_saturates_instead_of_wrapping() {
        let max = DomainSequence {
            domain: SequenceDomain::SubscriberDelivery,
            seq: u64::MAX,
        };
        assert_eq!(max.next().seq, u64::MAX, "wrap would be an ABA hazard");
    }
}
