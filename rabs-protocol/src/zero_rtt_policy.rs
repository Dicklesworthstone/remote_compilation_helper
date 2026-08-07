//! State-changing QUIC 0-RTT prohibition (bead J022; risk R60).
//!
//! 0-RTT data is REPLAYABLE by design: an attacker (or a lossy
//! network) can replay the first flight, so anything state-changing
//! inside it may execute twice. The policy:
//!
//! - action submission, lease changes, cancellation, and publication
//!   require a FULLY AUTHENTICATED live session (1-RTT complete);
//! - session resumption is welcome for handshake cost;
//! - 0-RTT is permitted only for operations on an explicit
//!   idempotent read-only allowlist that passed a separate
//!   replay-safety review — allowlisted BY NAME with the review ID;
//! - defense in depth: even if a state-changing message somehow rode
//!   0-RTT, the J023 sequence windows make the replayed duplicate a
//!   no-op — the replay test proves state cannot change twice.

/// Message classes for the 0-RTT admission decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum MessageClass {
    ActionSubmission,
    LeaseChange,
    Cancellation,
    Publication,
    ReadOnlyQuery,
}

/// One allowlisted 0-RTT operation (read-only + reviewed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZeroRttAllowlistEntry {
    /// The operation name.
    pub operation: &'static str,
    /// The replay-safety review that admitted it.
    pub review_id: &'static str,
}

/// The current allowlist (each entry names its review).
pub const ZERO_RTT_ALLOWLIST: [ZeroRttAllowlistEntry; 2] = [
    ZeroRttAllowlistEntry {
        operation: "rabs.worker.probe.v1",
        review_id: "rabs-review.zero-rtt.probe.v1",
    },
    ZeroRttAllowlistEntry {
        operation: "rabs.worker.query_attempt.v1",
        review_id: "rabs-review.zero-rtt.query-attempt.v1",
    },
];

/// 0-RTT admission decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZeroRttDecision {
    /// Admitted in 0-RTT (allowlisted read-only operation).
    Admit,
    /// Refused: requires the fully authenticated session (1-RTT).
    RequireFullSession,
}

/// Decide whether a message may ride 0-RTT.
#[must_use]
pub fn admit_zero_rtt(class: MessageClass, operation: &str) -> ZeroRttDecision {
    match class {
        MessageClass::ActionSubmission
        | MessageClass::LeaseChange
        | MessageClass::Cancellation
        | MessageClass::Publication => ZeroRttDecision::RequireFullSession,
        MessageClass::ReadOnlyQuery => {
            if ZERO_RTT_ALLOWLIST.iter().any(|e| e.operation == operation) {
                ZeroRttDecision::Admit
            } else {
                ZeroRttDecision::RequireFullSession
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sequence_domains::{DomainWindow, ReceiveOutcome, SequenceDomain};

    #[test]
    fn every_state_changing_class_requires_the_full_session() {
        for class in [
            MessageClass::ActionSubmission,
            MessageClass::LeaseChange,
            MessageClass::Cancellation,
            MessageClass::Publication,
        ] {
            assert_eq!(
                admit_zero_rtt(class, "anything"),
                ZeroRttDecision::RequireFullSession,
                "{class:?} must never ride 0-RTT"
            );
        }
        // Even a read-only query OFF the allowlist waits for 1-RTT.
        assert_eq!(
            admit_zero_rtt(MessageClass::ReadOnlyQuery, "rabs.worker.execute_action.v1"),
            ZeroRttDecision::RequireFullSession
        );
        // Allowlisted reviewed read-only operations admit.
        assert_eq!(
            admit_zero_rtt(MessageClass::ReadOnlyQuery, "rabs.worker.probe.v1"),
            ZeroRttDecision::Admit
        );
    }

    #[test]
    fn allowlist_entries_are_read_only_reviewed_registry_operations() {
        use crate::computation_registry::{Idempotency, lookup};
        for entry in ZERO_RTT_ALLOWLIST {
            let contract =
                lookup(entry.operation).expect("allowlist entries must exist in the J006 registry");
            assert_eq!(
                contract.idempotency,
                Idempotency::ReadOnly,
                "{}: only read-only operations may ride 0-RTT",
                entry.operation
            );
            assert!(
                entry.review_id.starts_with("rabs-review.zero-rtt."),
                "{}: a named replay-safety review is mandatory",
                entry.operation
            );
        }
    }

    #[test]
    fn replayed_state_change_cannot_change_state_twice() {
        // THE acceptance: defense in depth — even if a state-changing
        // message rode 0-RTT and was REPLAYED, the J023 sequence
        // window delivers it exactly once. Simulate: a cancellation at
        // seq 5 arrives, is replayed byte-identically, and the second
        // copy is an idempotent no-op.
        let mut window = DomainWindow::new(SequenceDomain::AuthorityControl, 16);
        for seq in 1..=4 {
            assert_eq!(window.receive(seq), ReceiveOutcome::Deliver);
        }
        let mut state_changes = 0;
        // First flight.
        if window.receive(5) == ReceiveOutcome::Deliver {
            state_changes += 1;
        }
        // The replay of the same flight.
        if window.receive(5) == ReceiveOutcome::Deliver {
            state_changes += 1;
        }
        assert_eq!(window.receive(5), ReceiveOutcome::DuplicateIgnored);
        assert_eq!(
            state_changes, 1,
            "a replayed state-changing attempt changes state exactly once"
        );
    }
}
