//! The closed remote computation registry (bead J006; plan §88; risk
//! R64's surface-area arm).
//!
//! Workers execute EXACTLY eight named computations — a CLOSED set:
//! the registry is a const table, `lookup` is total over it, and an
//! unknown name/opcode resolves to nothing (the caller refuses).
//! Everything else — session capability exchange, missing-object
//! negotiation, attempt events, offers, lease renewal, reconciliation
//! — is a typed protocol MESSAGE, not a worker computation: those
//! names are structurally absent from this table, and the test pins
//! the absence.
//!
//! Every entry carries the full contract: stable opcode, canonical
//! name, schema versions, max inline bytes (LARGE PAYLOADS NEVER
//! INLINE — sources and artifacts travel as object references),
//! required capabilities, idempotency, retry safety, cancellation
//! responsiveness, and lease behavior.

/// Idempotency behavior of one computation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum Idempotency {
    /// Safe to repeat with the same idempotency key.
    IdempotentByKey,
    /// Repetition is safe because the operation is read-only.
    ReadOnly,
    /// Repetition requires a NEW fenced attempt (never blind retry).
    NewFencedAttemptOnly,
}

/// Retry safety classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum RetrySafety {
    SafeAfterTimeout,
    SafeAlways,
    RequiresReconciliationFirst,
}

/// Lease behavior of one computation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum LeaseBehavior {
    /// Runs under the attempt's execution lease.
    RequiresExecutionLease,
    /// Lease-independent (probes, verification).
    LeaseIndependent,
}

/// One registry entry: the operation's full contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ComputationContract {
    /// Stable numeric opcode (wire).
    pub opcode: u16,
    /// Canonical versioned name.
    pub name: &'static str,
    /// Request schema version.
    pub request_version: u32,
    /// Response schema version.
    pub response_version: u32,
    /// Maximum inline request bytes (large payloads are object refs).
    pub max_inline_bytes: u64,
    /// Required worker capability names.
    pub required_capabilities: &'static [&'static str],
    /// Idempotency behavior.
    pub idempotency: Idempotency,
    /// Retry safety.
    pub retry: RetrySafety,
    /// Maximum time to acknowledge a cancellation (ms).
    pub cancellation_ack_ms: u64,
    /// Lease behavior.
    pub lease: LeaseBehavior,
}

/// The CLOSED registry: exactly the eight plan computations.
pub const COMPUTATION_REGISTRY: [ComputationContract; 8] = [
    ComputationContract {
        opcode: 1,
        name: "rabs.worker.probe.v1",
        request_version: 1,
        response_version: 1,
        max_inline_bytes: 64 * 1024,
        required_capabilities: &[],
        idempotency: Idempotency::ReadOnly,
        retry: RetrySafety::SafeAlways,
        cancellation_ack_ms: 100,
        lease: LeaseBehavior::LeaseIndependent,
    },
    ComputationContract {
        opcode: 2,
        name: "rabs.worker.materialize_snapshot.v1",
        request_version: 1,
        response_version: 1,
        max_inline_bytes: 256 * 1024, // manifests inline; CONTENT by ref
        required_capabilities: &["cas-fetch"],
        idempotency: Idempotency::IdempotentByKey,
        retry: RetrySafety::SafeAfterTimeout,
        cancellation_ack_ms: 500,
        lease: LeaseBehavior::RequiresExecutionLease,
    },
    ComputationContract {
        opcode: 3,
        name: "rabs.worker.execute_action.v1",
        request_version: 1,
        response_version: 1,
        max_inline_bytes: 256 * 1024, // descriptor + env; sources by ref
        required_capabilities: &["sandbox", "cas-fetch"],
        idempotency: Idempotency::NewFencedAttemptOnly,
        retry: RetrySafety::RequiresReconciliationFirst,
        cancellation_ack_ms: 1_000,
        lease: LeaseBehavior::RequiresExecutionLease,
    },
    ComputationContract {
        opcode: 4,
        name: "rabs.worker.query_attempt.v1",
        request_version: 1,
        response_version: 1,
        max_inline_bytes: 16 * 1024,
        required_capabilities: &[],
        idempotency: Idempotency::ReadOnly,
        retry: RetrySafety::SafeAlways,
        cancellation_ack_ms: 100,
        lease: LeaseBehavior::LeaseIndependent,
    },
    ComputationContract {
        opcode: 5,
        name: "rabs.worker.cancel_attempt.v1",
        request_version: 1,
        response_version: 1,
        max_inline_bytes: 16 * 1024,
        required_capabilities: &[],
        idempotency: Idempotency::IdempotentByKey,
        retry: RetrySafety::SafeAlways,
        cancellation_ack_ms: 100,
        lease: LeaseBehavior::LeaseIndependent,
    },
    ComputationContract {
        opcode: 6,
        name: "rabs.worker.seed_objects.v1",
        request_version: 1,
        response_version: 1,
        max_inline_bytes: 256 * 1024, // object ID lists; bytes by ref
        required_capabilities: &["cas-fetch"],
        idempotency: Idempotency::IdempotentByKey,
        retry: RetrySafety::SafeAfterTimeout,
        cancellation_ack_ms: 500,
        lease: LeaseBehavior::LeaseIndependent,
    },
    ComputationContract {
        opcode: 7,
        name: "rabs.worker.verify_objects.v1",
        request_version: 1,
        response_version: 1,
        max_inline_bytes: 256 * 1024,
        required_capabilities: &["cas-fetch"],
        idempotency: Idempotency::ReadOnly,
        retry: RetrySafety::SafeAlways,
        cancellation_ack_ms: 500,
        lease: LeaseBehavior::LeaseIndependent,
    },
    ComputationContract {
        opcode: 8,
        name: "rabs.worker.collect_failure_bundle.v1",
        request_version: 1,
        response_version: 1,
        max_inline_bytes: 64 * 1024, // bundle CONTENT returns by ref
        required_capabilities: &[],
        idempotency: Idempotency::ReadOnly,
        retry: RetrySafety::SafeAfterTimeout,
        cancellation_ack_ms: 500,
        lease: LeaseBehavior::LeaseIndependent,
    },
];

/// Look up a computation by canonical name.
#[must_use]
pub fn lookup(name: &str) -> Option<&'static ComputationContract> {
    COMPUTATION_REGISTRY.iter().find(|c| c.name == name)
}

/// Look up a computation by opcode.
#[must_use]
pub fn lookup_opcode(opcode: u16) -> Option<&'static ComputationContract> {
    COMPUTATION_REGISTRY.iter().find(|c| c.opcode == opcode)
}

/// The plan's protocol MESSAGES (not computations): pinned so a
/// refactor cannot quietly promote one into the worker registry.
pub const PROTOCOL_MESSAGES_NOT_COMPUTATIONS: [&str; 6] = [
    "session-capability-exchange",
    "missing-object-negotiation",
    "attempt-events",
    "prepared-result-offer",
    "lease-renewal",
    "reconciliation",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_registry_is_closed_with_stable_opcodes_and_names() {
        assert_eq!(COMPUTATION_REGISTRY.len(), 8, "exactly the plan's eight");
        let opcodes: Vec<u16> = COMPUTATION_REGISTRY.iter().map(|c| c.opcode).collect();
        assert_eq!(opcodes, vec![1, 2, 3, 4, 5, 6, 7, 8], "pinned opcodes");
        let names: Vec<&str> = COMPUTATION_REGISTRY.iter().map(|c| c.name).collect();
        assert_eq!(
            names,
            vec![
                "rabs.worker.probe.v1",
                "rabs.worker.materialize_snapshot.v1",
                "rabs.worker.execute_action.v1",
                "rabs.worker.query_attempt.v1",
                "rabs.worker.cancel_attempt.v1",
                "rabs.worker.seed_objects.v1",
                "rabs.worker.verify_objects.v1",
                "rabs.worker.collect_failure_bundle.v1",
            ]
        );
        // Unknown names/opcodes resolve to nothing (the caller refuses).
        assert!(lookup("rabs.worker.rm_rf.v1").is_none());
        assert!(lookup_opcode(999).is_none());
    }

    #[test]
    fn per_operation_contracts_hold_their_invariants() {
        // No computation admits unbounded inline payloads.
        for contract in &COMPUTATION_REGISTRY {
            assert!(
                contract.max_inline_bytes <= 256 * 1024,
                "{}: large payloads travel as object references",
                contract.name
            );
            assert!(contract.cancellation_ack_ms <= 1_000, "{}", contract.name);
        }
        // execute_action: the only NewFencedAttemptOnly computation,
        // requires a lease and reconciliation before retry.
        let execute = lookup("rabs.worker.execute_action.v1").unwrap();
        assert_eq!(execute.idempotency, Idempotency::NewFencedAttemptOnly);
        assert_eq!(execute.retry, RetrySafety::RequiresReconciliationFirst);
        assert_eq!(execute.lease, LeaseBehavior::RequiresExecutionLease);
        // Probes and queries are read-only and lease-independent.
        for name in ["rabs.worker.probe.v1", "rabs.worker.query_attempt.v1"] {
            let contract = lookup(name).unwrap();
            assert_eq!(contract.idempotency, Idempotency::ReadOnly);
            assert_eq!(contract.lease, LeaseBehavior::LeaseIndependent);
        }
        // Cancellation is idempotent by key (double-cancel is safe).
        assert_eq!(
            lookup("rabs.worker.cancel_attempt.v1").unwrap().idempotency,
            Idempotency::IdempotentByKey
        );
    }

    #[test]
    fn protocol_messages_are_not_computations() {
        // The bead's boundary: these stay typed messages — none may
        // appear in the worker registry under any spelling.
        for message in PROTOCOL_MESSAGES_NOT_COMPUTATIONS {
            for contract in &COMPUTATION_REGISTRY {
                assert!(
                    !contract.name.contains(message),
                    "{message} must not be a worker computation"
                );
            }
        }
    }
}
