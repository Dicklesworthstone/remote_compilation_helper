//! Serving-disposition transition legality + expiry/revalidation flow
//! (bead F032; invariants I42/I50; risks R99/R113/R126).
//!
//! The publication slot (`Absent → Executing → Committed`, A017) is
//! append-only history; everything that changes afterward is the
//! **serving disposition** — a separate versioned record (A020). This
//! module owns the ONE legality table for disposition changes, keyed by
//! typed triggers. Rules the table encodes:
//!
//! - deterministic-failure TTL expiry suppresses serving and schedules
//!   revalidation **without rewriting the publication** — `Eligible →
//!   ExpiredNeedsRevalidation`, never a delete;
//! - byte-identical revalidation appends attempt evidence and renews the
//!   disposition (`→ Eligible`); a byte MISMATCH is a **divergence
//!   incident** (quarantine + incident record), never a silent
//!   replacement of the committed result;
//! - quarantine release requires a verified repair receipt — a bare
//!   "looks fine now" trigger is refused;
//! - `EvictedFromActiveIndex` is terminal for this serving record: the
//!   tombstone retains result digests for divergence detection (H034),
//!   and a re-executed action commits a NEW publication under a fresh
//!   generation (I51) rather than resurrecting this one;
//! - unlisted (disposition, trigger) pairs are refused — the default is
//!   denial, not passage.
//!
//! Applying an approved transition still goes through the A020 revision
//! gate (`ActionServingStateRecord::accepts_update`): decisions here say
//! what MAY happen; a strictly newer `state_revision` says it DID.

use rabs_protocol::serving::ActionServingDisposition;

/// Verified repair receipt reference (the incident-resolution authority;
/// an ID, never a prose reason — risk R126).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RepairReceiptId(pub u64);

/// Typed causes of a serving-disposition change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServingTransitionTrigger {
    /// Required evidence bundle completed for the committed publication.
    EvidenceComplete,
    /// A quarantine incident opened against this publication.
    QuarantineOpened,
    /// An operator/policy release of the LAST blocking quarantine,
    /// carrying its verified repair receipt (`None` = unverified ask).
    QuarantineReleased(Option<RepairReceiptId>),
    /// The conservative validity window elapsed (TTL, clock rollback, or
    /// epoch discontinuity — all deny-shaped, R126).
    ValidityExpired,
    /// A revalidation execution finished byte-identical to the committed
    /// canonical result.
    RevalidationByteIdentical,
    /// A revalidation execution produced DIFFERENT bytes.
    RevalidationMismatch,
    /// Result-closure objects became unavailable locally/fleet-wide.
    ObjectsMissing,
    /// The missing closure objects were re-fetched and digest-verified.
    ObjectsRefetched,
    /// Retention/compaction evicted the entry from the active index.
    RetentionEvicted,
}

/// Outcome of consulting the legality table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransitionDecision {
    /// Legal: apply by writing a strictly-newer-revision serving record
    /// with this disposition.
    Apply(ActionServingDisposition),
    /// Revalidation bytes diverged from the committed result: quarantine
    /// AND raise a divergence incident. The publication record itself is
    /// untouched — divergence is evidence, not an edit.
    QuarantineWithDivergenceIncident,
    /// Illegal for this (disposition, trigger) pair.
    Refuse(RefuseReason),
}

/// Why a transition was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefuseReason {
    /// The serving record is evicted; the tombstone never revives (a new
    /// publication supersedes it instead — I51/H034).
    TerminalEvicted,
    /// Quarantine release without a verified repair receipt.
    ReleaseWithoutReceipt,
    /// The pair is not in the legality table (denial default).
    NotInTable,
}

/// The single serving-disposition legality table.
#[must_use]
pub fn evaluate(
    current: ActionServingDisposition,
    trigger: ServingTransitionTrigger,
) -> TransitionDecision {
    use ActionServingDisposition as D;
    use ServingTransitionTrigger as T;
    use TransitionDecision::{Apply, QuarantineWithDivergenceIncident, Refuse};

    // Eviction tombstones are terminal regardless of trigger.
    if current == D::EvictedFromActiveIndex {
        return Refuse(RefuseReason::TerminalEvicted);
    }
    match (current, trigger) {
        // Retention may evict from ANY live disposition; the tombstone
        // keeps the digests (H034) and F031 keeps the generation fence.
        (_, T::RetentionEvicted) => Apply(D::EvictedFromActiveIndex),
        // Quarantine incidents dominate every live disposition.
        (_, T::QuarantineOpened) => Apply(D::Quarantined),

        // Evidence completion activates a committed-but-pending slot.
        (D::EvidencePending, T::EvidenceComplete) => Apply(D::Eligible),

        // TTL expiry suppresses serving and schedules revalidation.
        (D::Eligible, T::ValidityExpired) => Apply(D::ExpiredNeedsRevalidation),

        // Revalidation: byte-identical renews; mismatch is an incident.
        (D::ExpiredNeedsRevalidation, T::RevalidationByteIdentical) => Apply(D::Eligible),
        (D::ExpiredNeedsRevalidation, T::RevalidationMismatch) => QuarantineWithDivergenceIncident,

        // Object availability: loss suppresses, verified refetch restores.
        (D::Eligible | D::ExpiredNeedsRevalidation, T::ObjectsMissing) => {
            Apply(D::ObjectsUnavailable)
        }
        (D::ObjectsUnavailable, T::ObjectsRefetched) => Apply(D::Eligible),

        // Quarantine release needs the verified repair receipt.
        (D::Quarantined, T::QuarantineReleased(Some(_))) => Apply(D::Eligible),
        (D::Quarantined, T::QuarantineReleased(None)) => {
            Refuse(RefuseReason::ReleaseWithoutReceipt)
        }

        // Everything else: denied by default.
        _ => Refuse(RefuseReason::NotInTable),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ActionServingDisposition as D;
    use ServingTransitionTrigger as T;

    const ALL_DISPOSITIONS: [D; 6] = [
        D::Eligible,
        D::EvidencePending,
        D::ExpiredNeedsRevalidation,
        D::Quarantined,
        D::ObjectsUnavailable,
        D::EvictedFromActiveIndex,
    ];
    const ALL_TRIGGERS: [T; 10] = [
        T::EvidenceComplete,
        T::QuarantineOpened,
        T::QuarantineReleased(Some(RepairReceiptId(1))),
        T::QuarantineReleased(None),
        T::ValidityExpired,
        T::RevalidationByteIdentical,
        T::RevalidationMismatch,
        T::ObjectsMissing,
        T::ObjectsRefetched,
        T::RetentionEvicted,
    ];

    #[test]
    fn expiry_revalidation_loop_never_rewrites_publication() {
        // The canonical F032 flow: TTL elapses → serving suppressed →
        // byte-identical revalidation renews. Every step is a NEW
        // disposition, never a publication edit (the decision type has
        // no publication field to mutate — I50 by construction).
        assert_eq!(
            evaluate(D::Eligible, T::ValidityExpired),
            TransitionDecision::Apply(D::ExpiredNeedsRevalidation)
        );
        assert_eq!(
            evaluate(D::ExpiredNeedsRevalidation, T::RevalidationByteIdentical),
            TransitionDecision::Apply(D::Eligible)
        );
    }

    #[test]
    fn revalidation_mismatch_is_a_divergence_incident() {
        // Different bytes on revalidation must NEVER silently replace or
        // re-serve: quarantine + incident, publication untouched.
        assert_eq!(
            evaluate(D::ExpiredNeedsRevalidation, T::RevalidationMismatch),
            TransitionDecision::QuarantineWithDivergenceIncident
        );
        // And the mismatch trigger has no legal Apply from ANY state.
        for d in ALL_DISPOSITIONS {
            assert!(
                !matches!(
                    evaluate(d, T::RevalidationMismatch),
                    TransitionDecision::Apply(_)
                ),
                "mismatch must never directly Apply from {d:?}"
            );
        }
    }

    #[test]
    fn eviction_is_terminal_for_the_serving_record() {
        // Property: NO trigger moves an evicted tombstone anywhere. A
        // re-executed action publishes a NEW record instead (I51/H034).
        for t in ALL_TRIGGERS {
            assert_eq!(
                evaluate(D::EvictedFromActiveIndex, t),
                TransitionDecision::Refuse(RefuseReason::TerminalEvicted),
                "evicted record moved on {t:?}"
            );
        }
    }

    #[test]
    fn quarantine_release_requires_verified_repair_receipt() {
        assert_eq!(
            evaluate(D::Quarantined, T::QuarantineReleased(None)),
            TransitionDecision::Refuse(RefuseReason::ReleaseWithoutReceipt)
        );
        assert_eq!(
            evaluate(
                D::Quarantined,
                T::QuarantineReleased(Some(RepairReceiptId(7)))
            ),
            TransitionDecision::Apply(D::Eligible)
        );
    }

    #[test]
    fn quarantine_dominates_and_eviction_reaches_every_live_state() {
        for d in ALL_DISPOSITIONS {
            if d == D::EvictedFromActiveIndex {
                continue;
            }
            assert_eq!(
                evaluate(d, T::QuarantineOpened),
                TransitionDecision::Apply(D::Quarantined)
            );
            assert_eq!(
                evaluate(d, T::RetentionEvicted),
                TransitionDecision::Apply(D::EvictedFromActiveIndex)
            );
        }
    }

    #[test]
    fn exhaustive_table_denies_by_default() {
        // Property over the full (disposition × trigger) product: every
        // pair yields a decision (total function), and the ONLY legal
        // entries to Eligible are evidence completion, byte-identical
        // revalidation, verified refetch, and receipted release. (A new
        // incident while already Quarantined legitimately re-applies
        // Quarantined — the revision bump records the added blocker.)
        let mut applies = 0;
        for d in ALL_DISPOSITIONS {
            for t in ALL_TRIGGERS {
                match evaluate(d, t) {
                    TransitionDecision::Apply(next) => {
                        applies += 1;
                        if next == D::Eligible {
                            assert!(
                                matches!(
                                    t,
                                    T::EvidenceComplete
                                        | T::RevalidationByteIdentical
                                        | T::ObjectsRefetched
                                        | T::QuarantineReleased(Some(_))
                                ),
                                "illegitimate path to Eligible: {d:?} on {t:?}"
                            );
                        }
                    }
                    TransitionDecision::QuarantineWithDivergenceIncident
                    | TransitionDecision::Refuse(_) => {}
                }
            }
        }
        // Planted count: 5 live states × (evict + quarantine) = 10, plus
        // EvidenceComplete(1) + ValidityExpired(1) + ByteIdentical(1) +
        // ObjectsMissing(2) + ObjectsRefetched(1) + receipted release(1)
        // = 17. A silently widened table fails here.
        assert_eq!(applies, 17, "legality table size changed");
    }
}
