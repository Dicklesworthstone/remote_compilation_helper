//! Admission next-action recommendations
//! (bd-session-history-remediation-ocv9i.6.4).
//!
//! A decisive admission denial is only half the answer an agent needs — the
//! other half is *what to do about it*. This module maps every rejection
//! category in the session-history taxonomy ([`AdmissionRejectionCategory`],
//! from 6.2) to a short, machine-readable [`NextAction`]: queue the proof, defer,
//! shrink scope, wait for bypass recovery, refresh capabilities, force resync,
//! fix a concrete worker capability, or contact the operator.
//!
//! [`recommend`] is the pure per-category rule (proof-mode aware: a transient
//! capacity denial becomes "queue the proof" under proof mode rather than a
//! plain defer). [`recommend_for_summary`] turns an aggregated
//! [`AdmissionRejectionSummary`] into the deduplicated set of recommendations to
//! surface in admission output.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::admission_rejection::{AdmissionRejectionCategory, AdmissionRejectionSummary};

/// The concrete next action an agent can take after a denial. Machine-readable
/// and short enough to act on directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NextAction {
    /// Enqueue the work as a deferred proof and reattach later.
    QueueProof,
    /// Defer — retry once the transient condition clears.
    Defer,
    /// Reduce the command's scope (fewer crates/targets) and retry.
    ShrinkScope,
    /// A worker was temporarily bypassed; wait for it to recover.
    WaitForBypassRecovery,
    /// Refresh worker capability facts / classifier state, then retry.
    RefreshCapabilities,
    /// Force a path-dependency / source resync, then retry.
    ForceResync,
    /// Fix a concrete worker capability (install runtime/toolchain/target).
    FixWorkerCapability,
    /// Escalate to a human operator (structural / config issue).
    ContactOperator,
}

impl NextAction {
    /// Every action, for coverage/uniqueness tests.
    pub const ALL: &'static [NextAction] = &[
        Self::QueueProof,
        Self::Defer,
        Self::ShrinkScope,
        Self::WaitForBypassRecovery,
        Self::RefreshCapabilities,
        Self::ForceResync,
        Self::FixWorkerCapability,
        Self::ContactOperator,
    ];

    /// Stable lowercase token (matches the serde representation).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            NextAction::QueueProof => "queue_proof",
            NextAction::Defer => "defer",
            NextAction::ShrinkScope => "shrink_scope",
            NextAction::WaitForBypassRecovery => "wait_for_bypass_recovery",
            NextAction::RefreshCapabilities => "refresh_capabilities",
            NextAction::ForceResync => "force_resync",
            NextAction::FixWorkerCapability => "fix_worker_capability",
            NextAction::ContactOperator => "contact_operator",
        }
    }

    /// A short imperative hint an agent can act on (kept terse on purpose).
    #[must_use]
    pub fn agent_hint(self) -> &'static str {
        match self {
            NextAction::QueueProof => "queue the proof and reattach with the job id",
            NextAction::Defer => "defer and retry when capacity frees up",
            NextAction::ShrinkScope => "shrink command scope (fewer crates/targets) and retry",
            NextAction::WaitForBypassRecovery => "wait for the bypassed worker to recover",
            NextAction::RefreshCapabilities => "refresh capabilities/classifier, then retry",
            NextAction::ForceResync => "force a source/path-dependency resync, then retry",
            NextAction::FixWorkerCapability => "install the missing runtime/toolchain/target on a worker",
            NextAction::ContactOperator => "contact an operator (structural/config issue)",
        }
    }
}

/// The recommended next action for one rejection category.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Recommendation {
    pub category: AdmissionRejectionCategory,
    pub action: NextAction,
    /// Short machine/agent-actionable hint.
    pub hint: String,
}

/// Recommend the next action for a rejection category. `proof_mode` flips a
/// transient capacity denial from a plain defer to queueing the proof.
#[must_use]
pub fn recommend(category: AdmissionRejectionCategory, proof_mode: bool) -> NextAction {
    use AdmissionRejectionCategory as C;
    match category {
        C::CriticalPressure => NextAction::WaitForBypassRecovery,
        C::InsufficientSlots => {
            if proof_mode {
                NextAction::QueueProof
            } else {
                NextAction::Defer
            }
        }
        C::CircuitOpen => NextAction::WaitForBypassRecovery,
        C::TelemetryStale => NextAction::RefreshCapabilities,
        // A hard preflight rejection usually means the command/scope is too
        // large or unsafe to offload as-is — shrinking scope is the lever.
        C::HardPreflight => NextAction::ShrinkScope,
        C::MissingRuntime | C::MissingToolchain | C::MissingRustTarget => {
            NextAction::FixWorkerCapability
        }
        // OS/arch can't be fixed on the existing worker; a matching host is an
        // operator/fleet decision.
        C::OsArchMismatch => NextAction::ContactOperator,
        C::ClassifierLocalDrift => NextAction::RefreshCapabilities,
        C::ActiveProjectExclusion => NextAction::ForceResync,
        C::ProjectExcluded => NextAction::ContactOperator,
    }
}

/// Build a [`Recommendation`] for a category.
#[must_use]
pub fn recommendation_for(
    category: AdmissionRejectionCategory,
    proof_mode: bool,
) -> Recommendation {
    let action = recommend(category, proof_mode);
    Recommendation {
        category,
        action,
        hint: action.agent_hint().to_string(),
    }
}

/// Turn an aggregated rejection summary into the deduplicated, deterministically
/// ordered set of recommendations to surface in admission output (one per
/// distinct category that occurred).
#[must_use]
pub fn recommend_for_summary(
    summary: &AdmissionRejectionSummary,
    proof_mode: bool,
) -> Vec<Recommendation> {
    // by_category keys are stable category tokens; recover the categories that
    // actually occurred, in the enum's stable order.
    let present: BTreeSet<&str> = summary.by_category.keys().map(String::as_str).collect();
    AdmissionRejectionCategory::ALL
        .iter()
        .filter(|c| present.contains(c.as_str()))
        .map(|c| recommendation_for(*c, proof_mode))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admission_rejection::{CandidateRejection, aggregate_rejections};

    #[test]
    fn every_taxonomy_reason_has_a_recommendation() {
        // The bead's coverage requirement: every rejection category in the
        // session-history taxonomy maps to a decisive next action, in BOTH
        // proof and non-proof modes.
        for category in AdmissionRejectionCategory::ALL {
            for proof_mode in [false, true] {
                let rec = recommendation_for(*category, proof_mode);
                assert_eq!(rec.category, *category);
                assert!(!rec.hint.is_empty());
            }
        }
    }

    #[test]
    fn proof_mode_queues_proof_for_transient_capacity() {
        assert_eq!(
            recommend(AdmissionRejectionCategory::InsufficientSlots, true),
            NextAction::QueueProof
        );
        assert_eq!(
            recommend(AdmissionRejectionCategory::InsufficientSlots, false),
            NextAction::Defer
        );
    }

    #[test]
    fn missing_capability_says_fix_worker_capability() {
        for c in [
            AdmissionRejectionCategory::MissingRuntime,
            AdmissionRejectionCategory::MissingToolchain,
            AdmissionRejectionCategory::MissingRustTarget,
        ] {
            assert_eq!(recommend(c, false), NextAction::FixWorkerCapability);
        }
    }

    #[test]
    fn structural_reasons_contact_operator() {
        assert_eq!(
            recommend(AdmissionRejectionCategory::OsArchMismatch, false),
            NextAction::ContactOperator
        );
        assert_eq!(
            recommend(AdmissionRejectionCategory::ProjectExcluded, true),
            NextAction::ContactOperator
        );
    }

    #[test]
    fn drift_and_stale_refresh_capabilities() {
        assert_eq!(
            recommend(AdmissionRejectionCategory::ClassifierLocalDrift, false),
            NextAction::RefreshCapabilities
        );
        assert_eq!(
            recommend(AdmissionRejectionCategory::TelemetryStale, false),
            NextAction::RefreshCapabilities
        );
    }

    #[test]
    fn active_project_exclusion_recommends_force_resync() {
        assert_eq!(
            recommend(AdmissionRejectionCategory::ActiveProjectExclusion, false),
            NextAction::ForceResync
        );
    }

    #[test]
    fn health_reasons_wait_for_recovery() {
        assert_eq!(
            recommend(AdmissionRejectionCategory::CircuitOpen, false),
            NextAction::WaitForBypassRecovery
        );
        assert_eq!(
            recommend(AdmissionRejectionCategory::CriticalPressure, false),
            NextAction::WaitForBypassRecovery
        );
    }

    #[test]
    fn all_eight_actions_are_reachable_from_the_taxonomy() {
        // Across all categories and both modes, every NextAction variant is
        // produced — the recommendation vocabulary has no dead entries.
        let mut seen = BTreeSet::new();
        for category in AdmissionRejectionCategory::ALL {
            for proof_mode in [false, true] {
                seen.insert(recommend(*category, proof_mode));
            }
        }
        for action in NextAction::ALL {
            assert!(seen.contains(action), "{} unreachable", action.as_str());
        }
    }

    #[test]
    fn hints_are_short_enough_to_act_on() {
        for action in NextAction::ALL {
            assert!(
                action.agent_hint().len() <= 80,
                "hint too long: {}",
                action.as_str()
            );
        }
    }

    #[test]
    fn action_tokens_are_unique() {
        let mut tokens: Vec<&str> = NextAction::ALL.iter().map(|a| a.as_str()).collect();
        tokens.sort_unstable();
        let before = tokens.len();
        tokens.dedup();
        assert_eq!(before, tokens.len());
    }

    #[test]
    fn recommend_for_summary_dedups_and_orders() {
        // Two MissingRustTarget + one CircuitOpen => two distinct recommendations
        // in stable enum order (CircuitOpen before MissingRustTarget).
        let summary = aggregate_rejections(
            3,
            &[
                CandidateRejection {
                    worker_id: "a".into(),
                    category: AdmissionRejectionCategory::MissingRustTarget,
                },
                CandidateRejection {
                    worker_id: "b".into(),
                    category: AdmissionRejectionCategory::MissingRustTarget,
                },
                CandidateRejection {
                    worker_id: "c".into(),
                    category: AdmissionRejectionCategory::CircuitOpen,
                },
            ],
        );
        let recs = recommend_for_summary(&summary, false);
        assert_eq!(recs.len(), 2, "deduped to distinct categories");
        assert_eq!(recs[0].category, AdmissionRejectionCategory::CircuitOpen);
        assert_eq!(recs[0].action, NextAction::WaitForBypassRecovery);
        assert_eq!(recs[1].category, AdmissionRejectionCategory::MissingRustTarget);
        assert_eq!(recs[1].action, NextAction::FixWorkerCapability);
    }

    #[test]
    fn recommendation_serializes_with_stable_tokens() {
        let rec = recommendation_for(AdmissionRejectionCategory::MissingToolchain, false);
        let value = serde_json::to_value(&rec).unwrap();
        assert_eq!(value["category"], "missing_toolchain");
        assert_eq!(value["action"], "fix_worker_capability");
        let back: Recommendation = serde_json::from_value(value).unwrap();
        assert_eq!(back, rec);
    }
}
