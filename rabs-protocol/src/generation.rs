//! Action generations, attempts, and execution leases (bead F023; plan
//! §22; invariants I31/I51).
//!
//! The structured identities that make fencing decidable:
//!
//! - one missing action key gets ONE active [`ActionGeneration`] whose
//!   `generation_id` is opaque and **never reused** within a cluster
//!   authority lineage (I51: failed generations, eviction, restart,
//!   database repair, or ordinal wraparound can never recreate an
//!   authority tuple accepted for an earlier attempt — tombstones and the
//!   high-water registry in F031 back this);
//! - every attempt — normal, retry, hedge, or pre-commit verification —
//!   carries a unique [`AttemptId`] and its own [`ExecutionLeaseId`];
//!   renewing, revoking, or expiring one lease never touches sibling
//!   hedges (I31; risk R62);
//! - lease freshness is a **renewal sequence**, not a wall-clock
//!   comparison (risk R73): a renewal must carry a strictly larger
//!   sequence than the last accepted one;
//! - `BuildOperationId` and `SubscriberId` travel on request/delivery
//!   messages and are deliberately NOT fields of these authority types.

use crate::authority::CoordinatorAuthority;
use crate::result_identity::TypedDigest;
use crate::wire_time::PeerId;

/// Opaque, never-reused generation identity (random 128-bit; the
/// coordinator mints it, tombstones prevent reuse — F031).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ActionGenerationId(pub u128);

/// One active execution generation for a missing action key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionGeneration {
    /// Never-reused opaque identity (the ABA fence).
    pub generation_id: ActionGenerationId,
    /// Monotonic per-key ordinal — diagnostic and fencing AID, never the
    /// sole identity (plan rev 1.6).
    pub per_key_ordinal: u64,
    /// Canonical digest of the coordinator authority that created this
    /// generation (must equal the digest of the attempt's full authority
    /// value — the F033 equality check).
    pub created_under_authority_digest: TypedDigest,
}

/// Unique attempt identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AttemptId(pub u128);

/// Per-attempt execution lease identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ExecutionLeaseId(pub u128);

/// Monotonic lease renewal sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct LeaseRenewalSeq(pub u64);

/// Durable worker boot generation (increments every worker restart).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct WorkerBootGeneration(pub u64);

/// Fresh-per-process worker incarnation (fences clones/overlaps — I47;
/// detection, not legitimacy proof — I54).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WorkerIncarnationId(pub u128);

/// The full authority an attempt carries on every authority-bearing
/// message (plan §22). One full coordinator-authority value; the
/// generation binds to it by digest only (risk R117: two independently
/// mutable full copies are forbidden by construction).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttemptAuthority {
    /// The full coordinator authority (sole full copy).
    pub coordinator: CoordinatorAuthority,
    /// The action key this attempt executes.
    pub action_key: TypedDigest,
    /// The generation this attempt belongs to.
    pub action_generation: ActionGeneration,
    /// Unique attempt identity.
    pub attempt_id: AttemptId,
    /// This attempt's own execution lease.
    pub execution_lease_id: ExecutionLeaseId,
    /// Last accepted renewal sequence.
    pub lease_renewal_seq: LeaseRenewalSeq,
    /// Executing worker.
    pub worker_peer_id: PeerId,
    /// Worker durable boot generation.
    pub worker_boot_generation: WorkerBootGeneration,
    /// Worker process incarnation.
    pub worker_incarnation_id: WorkerIncarnationId,
}

/// A lease renewal offer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeaseRenewal {
    /// Which lease.
    pub lease: ExecutionLeaseId,
    /// The proposed new sequence.
    pub seq: LeaseRenewalSeq,
}

/// Outcome of evaluating a lease renewal against an attempt's state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RenewalDecision {
    /// Strictly newer sequence for THIS lease: accept.
    Accept,
    /// Replayed or stale sequence: refuse (idempotency lives at the
    /// message layer, never by overwriting).
    RefuseStaleSequence,
    /// Renewal names a different lease: it cannot touch this attempt —
    /// in particular a sibling hedge's renewal is inert here (I31/R62).
    RefuseWrongLease,
}

impl AttemptAuthority {
    /// Evaluate a lease renewal. Sibling-hedge independence is the point:
    /// a renewal for any OTHER lease is `RefuseWrongLease`, never a state
    /// change here.
    #[must_use]
    pub fn evaluate_renewal(&self, renewal: LeaseRenewal) -> RenewalDecision {
        if renewal.lease != self.execution_lease_id {
            return RenewalDecision::RefuseWrongLease;
        }
        if renewal.seq <= self.lease_renewal_seq {
            return RenewalDecision::RefuseStaleSequence;
        }
        RenewalDecision::Accept
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority::{ClusterId, CoordinatorIncarnationId};
    use crate::result_identity::DigestAlgorithm;

    fn digest(tag: u8) -> TypedDigest {
        TypedDigest {
            algorithm: DigestAlgorithm::Sha256V1,
            domain: "rabs.coordinator-authority.v1",
            bytes: [tag; 32],
        }
    }

    fn authority() -> CoordinatorAuthority {
        CoordinatorAuthority {
            cluster_id: ClusterId("fleet-1".into()),
            credential_generation: 1,
            term: 3,
            incarnation_id: CoordinatorIncarnationId(7),
        }
    }

    fn attempt(lease: u128, seq: u64) -> AttemptAuthority {
        AttemptAuthority {
            coordinator: authority(),
            action_key: TypedDigest {
                algorithm: DigestAlgorithm::Sha256V1,
                domain: "rabs.action-key.sha256.v1",
                bytes: [1; 32],
            },
            action_generation: ActionGeneration {
                generation_id: ActionGenerationId(42),
                per_key_ordinal: 1,
                created_under_authority_digest: digest(9),
            },
            attempt_id: AttemptId(100),
            execution_lease_id: ExecutionLeaseId(lease),
            lease_renewal_seq: LeaseRenewalSeq(seq),
            worker_peer_id: PeerId("wkr-1".into()),
            worker_boot_generation: WorkerBootGeneration(2),
            worker_incarnation_id: WorkerIncarnationId(555),
        }
    }

    #[test]
    fn renewals_are_monotonic_never_wall_clock() {
        let a = attempt(1, 5);
        assert_eq!(
            a.evaluate_renewal(LeaseRenewal {
                lease: ExecutionLeaseId(1),
                seq: LeaseRenewalSeq(6)
            }),
            RenewalDecision::Accept
        );
        // Equal sequence = replay; lower = stale. Both refused.
        assert_eq!(
            a.evaluate_renewal(LeaseRenewal {
                lease: ExecutionLeaseId(1),
                seq: LeaseRenewalSeq(5)
            }),
            RenewalDecision::RefuseStaleSequence
        );
        assert_eq!(
            a.evaluate_renewal(LeaseRenewal {
                lease: ExecutionLeaseId(1),
                seq: LeaseRenewalSeq(4)
            }),
            RenewalDecision::RefuseStaleSequence
        );
    }

    #[test]
    fn sibling_hedge_leases_are_independent() {
        // Two hedge attempts share a generation but own different leases:
        // a renewal (or revocation expressed as one) for hedge B's lease
        // is inert against hedge A (I31; risk R62).
        let hedge_a = attempt(1, 5);
        let hedge_b_renewal = LeaseRenewal {
            lease: ExecutionLeaseId(2),
            seq: LeaseRenewalSeq(999),
        };
        assert_eq!(
            hedge_a.evaluate_renewal(hedge_b_renewal),
            RenewalDecision::RefuseWrongLease
        );
    }

    #[test]
    fn generation_ids_are_opaque_and_ordinals_are_aids_not_identity() {
        // Two generations with the SAME per-key ordinal but different
        // opaque IDs are different generations (the ABA point of I51):
        // identity lives in generation_id, the ordinal is diagnostic.
        let g1 = ActionGeneration {
            generation_id: ActionGenerationId(1),
            per_key_ordinal: 7,
            created_under_authority_digest: digest(9),
        };
        let g2 = ActionGeneration {
            generation_id: ActionGenerationId(2),
            per_key_ordinal: 7,
            created_under_authority_digest: digest(9),
        };
        assert_ne!(g1, g2);
    }

    #[test]
    fn authority_types_carry_no_operation_or_subscriber_fields() {
        // Exhaustive destructure: BuildOperationId/SubscriberId are NOT
        // representable in attempt authority (plan sec 22 rule). Adding
        // such a field makes this destructure fail to compile.
        let AttemptAuthority {
            coordinator: _,
            action_key: _,
            action_generation: _,
            attempt_id: _,
            execution_lease_id: _,
            lease_renewal_seq: _,
            worker_peer_id: _,
            worker_boot_generation: _,
            worker_incarnation_id: _,
        } = attempt(1, 1);
    }
}
