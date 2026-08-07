//! Mutable serving disposition and versioned trust evaluation, layered
//! over immutable publication history (bead A020; invariants I42/I50;
//! risks R99/R126).
//!
//! A committed `ActionPublicationRecord` is history and never changes.
//! Everything that CAN change — eligibility, evidence expiry, quarantine,
//! object availability, retention eviction, trust tier — lives in the
//! records here, keyed by a monotonic `state_revision` and bound to the
//! evaluating coordinator authority. Changing serving never rewrites
//! canonical result identity; the types make the mutation target explicit.
//!
//! Clock discipline (risk R126): durable TTLs use `ServingValidity` with a
//! coordinator clock epoch and an uncertainty bound; wall-clock rollback,
//! epoch discontinuity, or uncertainty that crosses the not-after bound
//! expires serving **conservatively** (deny), never optimistically.

use crate::result_identity::{ObjectId, TypedDigest};

/// Current serving disposition for one committed publication (plan §178).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionServingDisposition {
    /// Servable to subscribers whose requirements the trust evaluation meets.
    Eligible,
    /// Committed but awaiting required evidence.
    EvidencePending,
    /// Validity elapsed (e.g. deterministic-failure TTL); revalidation
    /// required before serving resumes.
    ExpiredNeedsRevalidation,
    /// Blocked by one or more quarantine incidents.
    Quarantined,
    /// Result closure objects not currently available locally/fleet-wide.
    ObjectsUnavailable,
    /// Evicted from the active index (tombstone retains result digests for
    /// divergence detection — bead H034).
    EvictedFromActiveIndex,
}

/// Durable validity with conservative clock handling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServingValidity {
    /// Coordinator wall-clock microseconds at evaluation (diagnostic +
    /// TTL base within one clock epoch).
    pub evaluated_at_unix_micros: i64,
    /// Maximum age in microseconds; `None` = no expiry.
    pub maximum_age_micros: Option<u64>,
    /// Clock uncertainty bound at evaluation time.
    pub clock_uncertainty_micros: u64,
    /// Coordinator clock epoch (bumped on detected discontinuity/rollback).
    pub coordinator_clock_epoch: u64,
}

impl ServingValidity {
    /// Conservative validity check at `now` within `now_epoch`.
    ///
    /// Denies when: the clock epoch changed (discontinuity), the clock ran
    /// backward, or `now + uncertainty` crosses the not-after bound.
    #[must_use]
    pub const fn still_valid(&self, now_unix_micros: i64, now_epoch: u64) -> bool {
        if now_epoch != self.coordinator_clock_epoch {
            return false;
        }
        if now_unix_micros < self.evaluated_at_unix_micros {
            return false;
        }
        match self.maximum_age_micros {
            None => true,
            Some(max_age) => {
                let age = now_unix_micros.saturating_sub(self.evaluated_at_unix_micros);
                let age_with_uncertainty =
                    (age as u64).saturating_add(self.clock_uncertainty_micros);
                age_with_uncertainty <= max_age
            }
        }
    }
}

/// The mutable serving-state record (revisioned, authority-bound).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionServingStateRecord {
    /// Which publication this disposition governs (immutable target).
    pub publication_record_id: ObjectId,
    /// Current disposition.
    pub disposition: ActionServingDisposition,
    /// Quarantine incidents blocking serving (IDs are the authority; a
    /// reason string is never the gate — risk R126).
    pub blocking_quarantine_ids: Vec<u64>,
    /// Monotonic revision; replays with a stale revision are rejected.
    pub state_revision: u64,
    /// Digest of the coordinator authority that evaluated this state.
    pub coordinator_authority_digest: TypedDigest,
    /// Conservative validity window.
    pub validity: ServingValidity,
}

impl ActionServingStateRecord {
    /// Whether `update` may replace `self`: same publication, strictly newer
    /// revision. A stale or equal revision is a replay and is refused —
    /// idempotency lives at the message layer, not by overwriting state.
    #[must_use]
    pub fn accepts_update(&self, update: &Self) -> bool {
        self.publication_record_id == update.publication_record_id
            && update.state_revision > self.state_revision
    }

    /// Whether this record permits serving right now.
    #[must_use]
    pub const fn may_serve_now(&self, now_unix_micros: i64, now_epoch: u64) -> bool {
        matches!(self.disposition, ActionServingDisposition::Eligible)
            && self.blocking_quarantine_ids.is_empty()
            && self.validity.still_valid(now_unix_micros, now_epoch)
    }
}

/// Evidence tiers (labels of observed evidence + policy approval — never
/// assertions of semantic correctness; plan §113).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TrustEvidenceTier {
    /// Produced, not yet verified.
    UnverifiedCandidate,
    /// Matched an authoritative stock execution under the recorded profile.
    ShadowMatched,
    /// Repeated executions matched on the same worker.
    ReproducibleSameWorker,
    /// Repeated executions matched across workers.
    ReproducibleCrossWorker,
    /// Produced/verified by an authorized CI lane.
    CiPolicyApproved,
    /// Project policy grants release eligibility (a policy decision; RABS
    /// does not claim compilation equivalence proves app correctness).
    ProjectReleaseEligible,
}

/// One immutable, versioned trust evaluation over an append-only evidence
/// set (I42: promotion/demotion never rewrites the publication).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionTrustEvaluationRecord {
    /// The canonical result being evaluated.
    pub canonical_result_manifest_id: ObjectId,
    /// Digest over the canonically sorted + deduplicated evidence-bundle
    /// ID set (see [`evidence_set_digest_input`]).
    pub evidence_set_digest: TypedDigest,
    /// The evaluated tier.
    pub evaluated_tier: TrustEvidenceTier,
    /// Monotonic evaluation sequence (later evaluations supersede).
    pub evaluated_causal_sequence: u64,
}

/// Canonicalize an evidence-ID set for digesting: sorted, deduplicated.
/// Append-only growth therefore changes the digest deterministically, and
/// insertion order can never produce two names for one set.
#[must_use]
pub fn evidence_set_digest_input(mut ids: Vec<[u8; 32]>) -> Vec<[u8; 32]> {
    ids.sort_unstable();
    ids.dedup();
    ids
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::result_identity::DigestAlgorithm;

    fn digest(tag: u8) -> TypedDigest {
        TypedDigest {
            algorithm: DigestAlgorithm::Sha256V1,
            domain: "rabs.coordinator-authority.v1",
            bytes: [tag; 32],
        }
    }

    fn object(tag: u8) -> ObjectId {
        ObjectId(TypedDigest {
            algorithm: DigestAlgorithm::Sha256V1,
            domain: "rabs.object.v1",
            bytes: [tag; 32],
        })
    }

    fn validity(evaluated_at: i64, max_age: Option<u64>, uncertainty: u64) -> ServingValidity {
        ServingValidity {
            evaluated_at_unix_micros: evaluated_at,
            maximum_age_micros: max_age,
            clock_uncertainty_micros: uncertainty,
            coordinator_clock_epoch: 1,
        }
    }

    #[test]
    fn ttl_expires_conservatively_under_uncertainty() {
        let v = validity(1_000, Some(500), 100);
        // Well inside: age 300 + uncertainty 100 <= 500.
        assert!(v.still_valid(1_300, 1));
        // Age 450 + uncertainty 100 crosses the bound: DENY, even though the
        // naive age alone would still pass.
        assert!(!v.still_valid(1_450, 1));
        // No expiry configured: valid at any forward time.
        let forever = validity(1_000, None, 100);
        assert!(forever.still_valid(i64::MAX, 1));
    }

    #[test]
    fn clock_rollback_and_epoch_discontinuity_deny() {
        let v = validity(1_000, Some(1_000_000), 0);
        // Wall clock ran backward: deny.
        assert!(!v.still_valid(999, 1));
        // Clock epoch changed (restart/discontinuity): deny regardless.
        assert!(!v.still_valid(2_000, 2));
    }

    #[test]
    fn stale_revision_replays_are_refused() {
        let current = ActionServingStateRecord {
            publication_record_id: object(1),
            disposition: ActionServingDisposition::Eligible,
            blocking_quarantine_ids: vec![],
            state_revision: 5,
            coordinator_authority_digest: digest(7),
            validity: validity(0, None, 0),
        };
        let newer = ActionServingStateRecord {
            state_revision: 6,
            disposition: ActionServingDisposition::Quarantined,
            ..current.clone()
        };
        let replay = ActionServingStateRecord {
            state_revision: 5,
            ..current.clone()
        };
        let other_pub = ActionServingStateRecord {
            publication_record_id: object(2),
            state_revision: 9,
            ..current.clone()
        };
        assert!(current.accepts_update(&newer));
        assert!(!current.accepts_update(&replay), "equal revision = replay");
        assert!(!current.accepts_update(&other_pub), "wrong publication");
    }

    #[test]
    fn quarantine_ids_block_serving_even_when_eligible() {
        let mut r = ActionServingStateRecord {
            publication_record_id: object(1),
            disposition: ActionServingDisposition::Eligible,
            blocking_quarantine_ids: vec![42],
            state_revision: 1,
            coordinator_authority_digest: digest(7),
            validity: validity(0, None, 0),
        };
        assert!(!r.may_serve_now(10, 1), "blocking incident denies serving");
        r.blocking_quarantine_ids.clear();
        assert!(r.may_serve_now(10, 1));
        r.disposition = ActionServingDisposition::ExpiredNeedsRevalidation;
        assert!(!r.may_serve_now(10, 1));
    }

    #[test]
    fn evidence_sets_are_order_insensitive_and_deduplicated() {
        let a = evidence_set_digest_input(vec![[3; 32], [1; 32], [2; 32]]);
        let b = evidence_set_digest_input(vec![[2; 32], [3; 32], [1; 32], [2; 32]]);
        assert_eq!(a, b, "insertion order and duplicates never rename a set");
        assert_eq!(a.len(), 3);
    }

    #[test]
    fn trust_tiers_order_and_never_touch_publication_types() {
        assert!(TrustEvidenceTier::ShadowMatched < TrustEvidenceTier::CiPolicyApproved);
        // Type-level separation (I50): a trust evaluation references the
        // canonical result by ID; there is no field through which it could
        // mutate a CanonicalActionResultManifest or ActionPublicationRecord.
        let eval = ActionTrustEvaluationRecord {
            canonical_result_manifest_id: object(1),
            evidence_set_digest: digest(9),
            evaluated_tier: TrustEvidenceTier::ReproducibleCrossWorker,
            evaluated_causal_sequence: 3,
        };
        assert_eq!(
            eval.evaluated_tier,
            TrustEvidenceTier::ReproducibleCrossWorker
        );
    }
}
