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

/// Domain tag for cluster-root-signed operator reset proof seals (bead S020; risk R88).
pub const DOMAIN_OPERATOR_RESET_PROOF: &str = "rabs.operator-reset-proof.sha256.v1";

/// Cluster-root-signed operator reset proof authorizing a peer to fence a prior
/// coordinator authority and accept a restored or new coordinator incarnation
/// (beads S020, S024, T042; invariant I40; risk R88).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClusterRootSignedOperatorResetProof {
    /// Cluster identity this reset proof applies to.
    pub cluster_id: rabs_protocol::authority::ClusterId,
    /// Monotonically advancing operator reset generation.
    pub reset_generation: rabs_protocol::authority::OperatorResetGeneration,
    /// Digest of the prior coordinator authority being fenced out.
    pub fenced_authority_digest: TypedDigest,
    /// New coordinator authority being authorized by the operator reset.
    pub new_authority: CoordinatorAuthority,
    /// Canonical seal computed under the cluster root key digest.
    pub cluster_root_seal: TypedDigest,
}

/// Refusal reasons when verifying a [`ClusterRootSignedOperatorResetProof`] (bead S020).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperatorResetError {
    /// Reset proof is for a different cluster than the peer's high-water mark.
    ClusterMismatch,
    /// Reset proof authorizes a different coordinator authority than the one offered.
    TargetAuthorityMismatch,
    /// Reset generation is not strictly greater than the peer's consumed reset generation.
    StaleResetGeneration,
    /// Cluster-root seal verification failed (forged or wrong root key).
    InvalidClusterRootSignature,
}

impl ClusterRootSignedOperatorResetProof {
    /// Compute the canonical seal over `(cluster_root_key, cluster_id, reset_generation,
    /// fenced_authority_digest, new_authority_digest)`.
    #[must_use]
    pub fn compute_seal(
        cluster_root_key: &TypedDigest,
        cluster_id: &rabs_protocol::authority::ClusterId,
        reset_generation: rabs_protocol::authority::OperatorResetGeneration,
        fenced_authority_digest: &TypedDigest,
        new_authority: &CoordinatorAuthority,
    ) -> TypedDigest {
        let new_digest = coordinator_authority_digest(new_authority);
        let mut enc = CanonicalEncoder::new();
        enc.str(cluster_root_key.domain)
            .bytes(&cluster_root_key.bytes)
            .str(&cluster_id.0)
            .u64(reset_generation.0)
            .str(fenced_authority_digest.domain)
            .bytes(&fenced_authority_digest.bytes)
            .str(new_digest.domain)
            .bytes(&new_digest.bytes);
        compute(DOMAIN_OPERATOR_RESET_PROOF, &enc.finish())
    }

    /// Construct a cluster-root-signed operator reset proof (bead S020).
    #[must_use]
    pub fn sign(
        cluster_root_key: &TypedDigest,
        reset_generation: rabs_protocol::authority::OperatorResetGeneration,
        fenced_authority: &CoordinatorAuthority,
        new_authority: CoordinatorAuthority,
    ) -> Self {
        let fenced_authority_digest = coordinator_authority_digest(fenced_authority);
        let cluster_id = new_authority.cluster_id.clone();
        let cluster_root_seal = Self::compute_seal(
            cluster_root_key,
            &cluster_id,
            reset_generation,
            &fenced_authority_digest,
            &new_authority,
        );
        Self {
            cluster_id,
            reset_generation,
            fenced_authority_digest,
            new_authority,
            cluster_root_seal,
        }
    }

    /// Verify this operator reset proof against `cluster_root_key`, `high_water`,
    /// and the `offered` coordinator authority (bead S020).
    ///
    /// # Errors
    /// Returns [`OperatorResetError`] on cluster mismatch, authority mismatch,
    /// stale reset generation, or invalid cluster-root seal.
    pub fn verify(
        &self,
        cluster_root_key: &TypedDigest,
        high_water: &rabs_protocol::authority::PeerAuthorityHighWaterMark,
        offered: &CoordinatorAuthority,
    ) -> Result<rabs_protocol::authority::OperatorResetGeneration, OperatorResetError> {
        if self.cluster_id != high_water.cluster_id || offered.cluster_id != high_water.cluster_id {
            return Err(OperatorResetError::ClusterMismatch);
        }
        if self.new_authority != *offered {
            return Err(OperatorResetError::TargetAuthorityMismatch);
        }
        if self.reset_generation <= high_water.operator_reset_generation {
            return Err(OperatorResetError::StaleResetGeneration);
        }
        let expected_seal = Self::compute_seal(
            cluster_root_key,
            &self.cluster_id,
            self.reset_generation,
            &self.fenced_authority_digest,
            &self.new_authority,
        );
        if self.cluster_root_seal != expected_seal {
            return Err(OperatorResetError::InvalidClusterRootSignature);
        }
        Ok(self.reset_generation)
    }
}

/// Combined outcome of evaluating lexicographic coordinator authority (with
/// optional operator-reset and credential-chain proofs) and optional bounded
/// predecessor-naming edge handoff (beads S020, S024, T042).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionAuthorityAndHandoffAdmission {
    /// Authority (and optional edge handoff) admitted; peer high-water mark
    /// and edge ownership state updated.
    Admitted {
        /// Lexicographic authority decision.
        authority_decision: rabs_protocol::authority::AuthorityDecision,
        /// Canonical digest of the admitted coordinator authority.
        authority_digest: TypedDigest,
    },
    /// Rejected because the operator reset proof failed verification.
    RejectedInvalidOperatorReset(OperatorResetError),
    /// Rejected because `credential_generation` advanced without a verified
    /// credential-chain proof (S024).
    RejectedMissingCredentialChainProof,
    /// Rejected by lexicographic high-water comparison (stale credential
    /// generation, stale term, incarnation conflict, or cluster mismatch).
    RejectedStaleAuthority(rabs_protocol::authority::AuthorityDecision),
    /// Rejected by bounded predecessor-naming edge handoff fencing (R118/S024).
    RejectedEdgeHandoff(rabs_protocol::edge_fence::FenceError),
}

/// Evaluate an offered [`CoordinatorAuthority`] against `high_water` using
/// lexicographic `(credential_generation, term)` rules (S024), verifying any
/// [`ClusterRootSignedOperatorResetProof`] against `cluster_root_key` (S020),
/// requiring `credential_chain_verified` when `credential_generation` advances,
/// and optionally opening a bounded predecessor-naming edge handoff window on
/// `edge` (S024 / T042).
#[allow(clippy::too_many_arguments)]
pub fn admit_session_authority_and_edge_handoff(
    high_water: &mut rabs_protocol::authority::PeerAuthorityHighWaterMark,
    cluster_root_key: &TypedDigest,
    offered: &CoordinatorAuthority,
    operator_reset_proof: Option<&ClusterRootSignedOperatorResetProof>,
    credential_chain_verified: bool,
    edge_handoff: Option<(
        &mut rabs_protocol::edge_fence::EdgeOwnership,
        rabs_protocol::edge_fence::HandoffToken,
        u64,
    )>,
) -> SessionAuthorityAndHandoffAdmission {
    use rabs_protocol::authority::AuthorityDecision;

    let verified_reset = match operator_reset_proof {
        Some(proof) => match proof.verify(cluster_root_key, high_water, offered) {
            Ok(reset_gen) => Some(reset_gen),
            Err(err) => {
                return SessionAuthorityAndHandoffAdmission::RejectedInvalidOperatorReset(err);
            }
        },
        None => None,
    };

    let decision = high_water.evaluate(offered, verified_reset);
    match decision {
        AuthorityDecision::RejectClusterMismatch
        | AuthorityDecision::RejectStaleCredentialGeneration
        | AuthorityDecision::RejectStaleTerm
        | AuthorityDecision::RejectIncarnationConflict => {
            return SessionAuthorityAndHandoffAdmission::RejectedStaleAuthority(decision);
        }
        AuthorityDecision::AcceptNewGenerationPendingCredentialProof => {
            if !credential_chain_verified {
                return SessionAuthorityAndHandoffAdmission::RejectedMissingCredentialChainProof;
            }
        }
        AuthorityDecision::AcceptAdvanceTerm
        | AuthorityDecision::AcceptSameIncarnation
        | AuthorityDecision::AcceptViaOperatorReset => {}
    }

    let authority_digest = coordinator_authority_digest(offered);

    if let Some((edge, token, deadline_seq)) = edge_handoff
        && let Err(fence_err) = edge.begin_handoff(token, &authority_digest, deadline_seq)
    {
        return SessionAuthorityAndHandoffAdmission::RejectedEdgeHandoff(fence_err);
    }

    // Advance the peer high-water mark now that both authority and optional
    // edge handoff checks have succeeded.
    if let Some(reset_gen) = verified_reset {
        high_water.operator_reset_generation = reset_gen;
    }
    high_water.credential_generation = offered.credential_generation;
    high_water.highest_term_within_generation = offered.term;
    high_water.last_incarnation_id = offered.incarnation_id;

    SessionAuthorityAndHandoffAdmission::Admitted {
        authority_decision: decision,
        authority_digest,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rabs_protocol::authority::{
        AuthorityDecision, ClusterId, CoordinatorIncarnationId, OperatorResetGeneration,
        PeerAuthorityHighWaterMark,
    };
    use rabs_protocol::edge_fence::{EdgeOwnership, FenceError, HandoffToken};
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

    #[test]
    fn t042_s020_s024_authority_digest_mismatch_lexicographic_rollback_and_edge_handoff_overlap() {
        let root_key = TypedDigest {
            algorithm: DigestAlgorithm::Sha256V1,
            domain: "rabs.cluster-root-key.sha256.v1",
            bytes: [0x55; 32],
        };
        let wrong_root_key = TypedDigest {
            algorithm: DigestAlgorithm::Sha256V1,
            domain: "rabs.cluster-root-key.sha256.v1",
            bytes: [0x99; 32],
        };

        let mut high_water = PeerAuthorityHighWaterMark {
            cluster_id: ClusterId("fleet-1".into()),
            credential_generation: 2,
            highest_term_within_generation: 10,
            last_incarnation_id: CoordinatorIncarnationId(100),
            operator_reset_generation: OperatorResetGeneration(0),
        };

        // 1. R117: Authority-copy disagreement between ActionGeneration.created_under_authority_digest
        //    and AttemptAuthority.coordinator is rejected before lease admission or publication.
        let active_coord = CoordinatorAuthority {
            cluster_id: ClusterId("fleet-1".into()),
            credential_generation: 2,
            term: 10,
            incarnation_id: CoordinatorIncarnationId(100),
        };
        let mismatched_coord = CoordinatorAuthority {
            cluster_id: ClusterId("fleet-1".into()),
            credential_generation: 2,
            term: 11,
            incarnation_id: CoordinatorIncarnationId(101),
        };
        let mismatched_attempt = attempt_under(
            mismatched_coord,
            coordinator_authority_digest(&active_coord),
        );
        assert_eq!(
            check_attempt_binding(&mismatched_attempt),
            BindingCheck::RejectAuthorityMismatch
        );

        // 2. S024: Lexicographic rollback — lower credential_generation (1 < 2) is rejected even
        //    with a huge term (999 > 10); lower term within generation 2 (9 < 10) is rejected;
        //    same (2, 10) with different incarnation (101 != 100) is rejected.
        let stale_cred = CoordinatorAuthority {
            cluster_id: ClusterId("fleet-1".into()),
            credential_generation: 1,
            term: 999,
            incarnation_id: CoordinatorIncarnationId(200),
        };
        assert_eq!(
            admit_session_authority_and_edge_handoff(
                &mut high_water,
                &root_key,
                &stale_cred,
                None,
                true,
                None,
            ),
            SessionAuthorityAndHandoffAdmission::RejectedStaleAuthority(
                AuthorityDecision::RejectStaleCredentialGeneration
            )
        );
        let stale_term = CoordinatorAuthority {
            cluster_id: ClusterId("fleet-1".into()),
            credential_generation: 2,
            term: 9,
            incarnation_id: CoordinatorIncarnationId(100),
        };
        assert_eq!(
            admit_session_authority_and_edge_handoff(
                &mut high_water,
                &root_key,
                &stale_term,
                None,
                true,
                None,
            ),
            SessionAuthorityAndHandoffAdmission::RejectedStaleAuthority(
                AuthorityDecision::RejectStaleTerm
            )
        );
        let clone_conflict = CoordinatorAuthority {
            cluster_id: ClusterId("fleet-1".into()),
            credential_generation: 2,
            term: 10,
            incarnation_id: CoordinatorIncarnationId(999),
        };
        assert_eq!(
            admit_session_authority_and_edge_handoff(
                &mut high_water,
                &root_key,
                &clone_conflict,
                None,
                true,
                None,
            ),
            SessionAuthorityAndHandoffAdmission::RejectedStaleAuthority(
                AuthorityDecision::RejectIncarnationConflict
            )
        );

        // 3. S024: Higher credential_generation (3 > 2, term=1) opens a new term namespace ONLY
        //    when credential_chain_verified == true.
        let rotated_cred = CoordinatorAuthority {
            cluster_id: ClusterId("fleet-1".into()),
            credential_generation: 3,
            term: 1,
            incarnation_id: CoordinatorIncarnationId(300),
        };
        assert_eq!(
            admit_session_authority_and_edge_handoff(
                &mut high_water,
                &root_key,
                &rotated_cred,
                None,
                false,
                None,
            ),
            SessionAuthorityAndHandoffAdmission::RejectedMissingCredentialChainProof
        );
        assert_eq!(
            admit_session_authority_and_edge_handoff(
                &mut high_water,
                &root_key,
                &rotated_cred,
                None,
                true,
                None,
            ),
            SessionAuthorityAndHandoffAdmission::Admitted {
                authority_decision: AuthorityDecision::AcceptNewGenerationPendingCredentialProof,
                authority_digest: coordinator_authority_digest(&rotated_cred),
            }
        );
        assert_eq!(high_water.credential_generation, 3);
        assert_eq!(high_water.highest_term_within_generation, 1);

        // 4. S020: Restored DB / lower term recovery requires a valid cluster-root-signed
        //    operator reset proof; wrong root key or replayed reset generation is rejected.
        let restored_coord = CoordinatorAuthority {
            cluster_id: ClusterId("fleet-1".into()),
            credential_generation: 3,
            term: 1,
            incarnation_id: CoordinatorIncarnationId(777),
        };
        let bad_proof = ClusterRootSignedOperatorResetProof::sign(
            &wrong_root_key,
            OperatorResetGeneration(1),
            &rotated_cred,
            restored_coord.clone(),
        );
        assert_eq!(
            admit_session_authority_and_edge_handoff(
                &mut high_water,
                &root_key,
                &restored_coord,
                Some(&bad_proof),
                false,
                None,
            ),
            SessionAuthorityAndHandoffAdmission::RejectedInvalidOperatorReset(
                OperatorResetError::InvalidClusterRootSignature
            )
        );

        let valid_proof = ClusterRootSignedOperatorResetProof::sign(
            &root_key,
            OperatorResetGeneration(1),
            &rotated_cred,
            restored_coord.clone(),
        );
        assert_eq!(
            admit_session_authority_and_edge_handoff(
                &mut high_water,
                &root_key,
                &restored_coord,
                Some(&valid_proof),
                false,
                None,
            ),
            SessionAuthorityAndHandoffAdmission::Admitted {
                authority_decision: AuthorityDecision::AcceptViaOperatorReset,
                authority_digest: coordinator_authority_digest(&restored_coord),
            }
        );
        assert_eq!(
            high_water.operator_reset_generation,
            OperatorResetGeneration(1)
        );
        assert_eq!(
            high_water.last_incarnation_id,
            CoordinatorIncarnationId(777)
        );

        // Replaying the same reset proof is rejected as StaleResetGeneration:
        assert_eq!(
            admit_session_authority_and_edge_handoff(
                &mut high_water,
                &root_key,
                &restored_coord,
                Some(&valid_proof),
                false,
                None,
            ),
            SessionAuthorityAndHandoffAdmission::RejectedInvalidOperatorReset(
                OperatorResetError::StaleResetGeneration
            )
        );

        // 5. S024 / R118: Bounded predecessor-naming edge handoff admits the 1-active + 1-named-predecessor
        //    pair under the active coordinator authority digest and rejects any 3rd overlapping
        //    incarnation or mismatched predecessor.
        let mut edge = EdgeOwnership::cold_boot("edge-1", 1, 50);
        let handoff_50_to_51 = HandoffToken {
            edge_id: "edge-1".into(),
            predecessor_incarnation: 50,
            successor_incarnation: 51,
            session_set: vec![1, 2],
            authorized_by: coordinator_authority_digest(&restored_coord),
        };
        assert_eq!(
            admit_session_authority_and_edge_handoff(
                &mut high_water,
                &root_key,
                &restored_coord,
                None,
                false,
                Some((&mut edge, handoff_50_to_51, 100)),
            ),
            SessionAuthorityAndHandoffAdmission::Admitted {
                authority_decision: AuthorityDecision::AcceptSameIncarnation,
                authority_digest: coordinator_authority_digest(&restored_coord),
            }
        );

        // Overlapping handoff beyond the admitted (50, 51) pair is rejected:
        let overlapping_50_to_52 = HandoffToken {
            edge_id: "edge-1".into(),
            predecessor_incarnation: 50,
            successor_incarnation: 52,
            session_set: vec![1, 2],
            authorized_by: coordinator_authority_digest(&restored_coord),
        };
        assert_eq!(
            admit_session_authority_and_edge_handoff(
                &mut high_water,
                &root_key,
                &restored_coord,
                None,
                false,
                Some((&mut edge, overlapping_50_to_52, 100)),
            ),
            SessionAuthorityAndHandoffAdmission::RejectedEdgeHandoff(
                FenceError::HandoffAlreadyActive
            )
        );
    }
}
