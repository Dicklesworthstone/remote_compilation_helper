//! Generation ↔ authority digest binding and its admission check
//! (bead F033; plan §22 rules; risk R117).
//!
//! An [`ActionGeneration`] does not carry a second full copy of the
//! coordinator authority — it carries the **canonical digest** of the
//! authority that created it, and every attempt/publication carries the
//! ONE full authority value. Admission recomputes the digest from the
//! full value and requires equality:
//!
//! ```text
//! generation.created_under_authority_digest
//!     == H_domain("rabs.coordinator-authority.v1", canonical(coordinator))
//! ```
//!
//! Any mismatch is malformed or stale authority and is rejected **before
//! lease admission or result preparation** — a generation created under a
//! previous term can never admit an attempt claiming the new term (and
//! vice versa), which is also how G020/R120 close prior-authority
//! generations: their digests simply stop matching.

use rabs_protocol::authority::CoordinatorAuthority;
use rabs_protocol::generation::AttemptAuthority;
use rabs_protocol::result_identity::TypedDigest;

use crate::canonical::CanonicalEncoder;
use crate::typed_digest::{DOMAIN_COORDINATOR_AUTHORITY, compute};

/// Canonical digest of a coordinator authority value.
#[must_use]
pub fn coordinator_authority_digest(authority: &CoordinatorAuthority) -> TypedDigest {
    let CoordinatorAuthority {
        cluster_id,
        credential_generation,
        term,
        incarnation_id,
    } = authority;
    let mut enc = CanonicalEncoder::new();
    enc.str(&cluster_id.0)
        .u64(*credential_generation)
        .u64(*term);
    // u128 incarnation as two fixed-width u64 halves (LE order).
    enc.u64((incarnation_id.0 & u128::from(u64::MAX)) as u64)
        .u64((incarnation_id.0 >> 64) as u64);
    compute(DOMAIN_COORDINATOR_AUTHORITY, &enc.finish())
}

/// Admission outcome for the binding check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingCheck {
    /// The generation was created under exactly this authority.
    Bound,
    /// Digest mismatch: malformed or stale authority. Reject before lease
    /// admission or result preparation; the attempt may still contribute
    /// verified immutable blobs but can never publish (R120 posture).
    RejectAuthorityMismatch,
}

/// Verify an attempt's generation↔authority binding.
#[must_use]
pub fn check_attempt_binding(attempt: &AttemptAuthority) -> BindingCheck {
    let recomputed = coordinator_authority_digest(&attempt.coordinator);
    if attempt.action_generation.created_under_authority_digest == recomputed {
        BindingCheck::Bound
    } else {
        BindingCheck::RejectAuthorityMismatch
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rabs_protocol::authority::{ClusterId, CoordinatorIncarnationId};
    use rabs_protocol::generation::{
        ActionGeneration, ActionGenerationId, AttemptId, ExecutionLeaseId, LeaseRenewalSeq,
        WorkerBootGeneration, WorkerIncarnationId,
    };
    use rabs_protocol::result_identity::DigestAlgorithm;
    use rabs_protocol::wire_time::PeerId;

    fn authority(term: u64) -> CoordinatorAuthority {
        CoordinatorAuthority {
            cluster_id: ClusterId("fleet-1".into()),
            credential_generation: 1,
            term,
            incarnation_id: CoordinatorIncarnationId(7),
        }
    }

    fn attempt_under(
        coordinator: CoordinatorAuthority,
        generation_digest: TypedDigest,
    ) -> AttemptAuthority {
        AttemptAuthority {
            coordinator,
            action_key: TypedDigest {
                algorithm: DigestAlgorithm::Sha256V1,
                domain: "rabs.action-key.sha256.v1",
                bytes: [1; 32],
            },
            action_generation: ActionGeneration {
                generation_id: ActionGenerationId(42),
                per_key_ordinal: 1,
                created_under_authority_digest: generation_digest,
            },
            attempt_id: AttemptId(100),
            execution_lease_id: ExecutionLeaseId(1),
            lease_renewal_seq: LeaseRenewalSeq(1),
            worker_peer_id: PeerId("wkr-1".into()),
            worker_boot_generation: WorkerBootGeneration(1),
            worker_incarnation_id: WorkerIncarnationId(9),
        }
    }

    #[test]
    fn matching_binding_admits() {
        let coord = authority(3);
        let attempt = attempt_under(coord.clone(), coordinator_authority_digest(&coord));
        assert_eq!(check_attempt_binding(&attempt), BindingCheck::Bound);
    }

    #[test]
    fn stale_term_generation_is_rejected_after_restart() {
        // G020/R120: a generation minted under term 3 cannot admit an
        // attempt whose full authority claims term 4 — the digest simply
        // no longer matches after the coordinator restart.
        let old = authority(3);
        let new = authority(4);
        let attempt = attempt_under(new, coordinator_authority_digest(&old));
        assert_eq!(
            check_attempt_binding(&attempt),
            BindingCheck::RejectAuthorityMismatch
        );
    }

    #[test]
    fn forged_or_corrupted_digests_are_rejected() {
        let coord = authority(3);
        let forged = TypedDigest {
            algorithm: DigestAlgorithm::Sha256V1,
            domain: "rabs.coordinator-authority.v1",
            bytes: [0xAB; 32],
        };
        let attempt = attempt_under(coord, forged);
        assert_eq!(
            check_attempt_binding(&attempt),
            BindingCheck::RejectAuthorityMismatch
        );
    }

    #[test]
    fn every_authority_field_participates_in_the_digest() {
        let base = coordinator_authority_digest(&authority(3));
        let mut cluster = authority(3);
        cluster.cluster_id = ClusterId("fleet-2".into());
        assert_ne!(base, coordinator_authority_digest(&cluster));
        let mut cred = authority(3);
        cred.credential_generation = 2;
        assert_ne!(base, coordinator_authority_digest(&cred));
        assert_ne!(base, coordinator_authority_digest(&authority(4)));
        let mut inc = authority(3);
        inc.incarnation_id = CoordinatorIncarnationId(8);
        assert_ne!(base, coordinator_authority_digest(&inc));
        // High u64 half of the incarnation participates too.
        let mut inc_high = authority(3);
        inc_high.incarnation_id = CoordinatorIncarnationId(7 | (1u128 << 64));
        assert_ne!(base, coordinator_authority_digest(&inc_high));
    }
}
