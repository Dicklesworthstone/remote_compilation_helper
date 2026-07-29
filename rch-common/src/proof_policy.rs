//! Proof-mode fail-closed execution policy
//! (bd-session-history-remediation-ocv9i.5.1).
//!
//! Proof mode exists to *prove* a command ran on a remote worker. Its cardinal
//! rule, learned from session history where a local fallback was silently
//! stamped "success": **proof mode must never run locally and must never report
//! a local fallback as success.** It either proceeds with genuine remote
//! execution or refuses *before* anything runs, with a durable, machine-readable
//! reason.
//!
//! [`ProofVerdict`] encodes that guarantee in the type system — it has only
//! `ProceedRemote` and `Refuse`; there is deliberately no `Local` variant, so no
//! code path can accidentally satisfy proof mode locally. [`evaluate_proof_mode`]
//! is the pure decision over observable [`ProofInputs`]; [`ProofRefusal`] is the
//! durable JSON envelope that records the refusal and marks it an *admission /
//! policy denial*, distinct from a product compile/test failure (which is a
//! separate, post-execution outcome — see
//! [`crate::disk_pressure_report::classify_exec_failure`]).

use serde::{Deserialize, Serialize};

use crate::admit_preflight::AdmitRecommendation;
use crate::incident::IncidentReasonCode;

/// Why proof mode refused to proceed. Each is a refusal *before* execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofRefusalReason {
    /// No worker was admissible for the command.
    NoAdmissibleWorker,
    /// Classifier/preflight state would run the command locally — proof mode
    /// cannot be satisfied locally.
    ClassifierChoseLocal,
    /// The command shape is unsafe to prove remotely (e.g. not a clean,
    /// reproducible compilation).
    UnsafeCommandShape,
    /// The requested placement profile (specific worker/profile) cannot be
    /// honored.
    PlacementProfileUnhonored,
}

impl ProofRefusalReason {
    /// Stable lowercase token.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            ProofRefusalReason::NoAdmissibleWorker => "no_admissible_worker",
            ProofRefusalReason::ClassifierChoseLocal => "classifier_chose_local",
            ProofRefusalReason::UnsafeCommandShape => "unsafe_command_shape",
            ProofRefusalReason::PlacementProfileUnhonored => "placement_profile_unhonored",
        }
    }

    /// All refusal reasons, declaration order (for coverage tests).
    pub const ALL: &'static [ProofRefusalReason] = &[
        Self::NoAdmissibleWorker,
        Self::ClassifierChoseLocal,
        Self::UnsafeCommandShape,
        Self::PlacementProfileUnhonored,
    ];

    /// Operator-facing explanation.
    #[must_use]
    pub fn detail(self) -> &'static str {
        match self {
            ProofRefusalReason::NoAdmissibleWorker => {
                "proof mode requires remote execution but no worker is admissible"
            }
            ProofRefusalReason::ClassifierChoseLocal => {
                "classifier/preflight would run this locally; proof mode cannot be satisfied locally"
            }
            ProofRefusalReason::UnsafeCommandShape => {
                "command shape is unsafe to prove remotely (not a clean reproducible compilation)"
            }
            ProofRefusalReason::PlacementProfileUnhonored => {
                "requested placement profile cannot be honored"
            }
        }
    }
}

/// The proof-mode decision. Note the absence of any `Local` variant: proof mode
/// is fail-closed by construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProofVerdict {
    /// Proceed with genuine remote execution.
    ProceedRemote,
    /// Refuse before running anything.
    Refuse(ProofRefusalReason),
}

impl ProofVerdict {
    /// Whether proof mode will proceed (to remote execution).
    #[must_use]
    pub fn proceeds(&self) -> bool {
        matches!(self, ProofVerdict::ProceedRemote)
    }

    /// The refusal reason, if refused.
    #[must_use]
    pub fn refusal(&self) -> Option<ProofRefusalReason> {
        match self {
            ProofVerdict::ProceedRemote => None,
            ProofVerdict::Refuse(reason) => Some(*reason),
        }
    }
}

/// Observable inputs for the proof-mode decision. Plain data so the policy is
/// pure and unit-testable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProofInputs {
    /// The preflight recommendation for the command.
    pub recommendation: AdmitRecommendation,
    /// At least one worker was admissible for the command.
    pub any_admissible: bool,
    /// The command shape is safe to prove remotely.
    pub command_safe_for_proof: bool,
    /// The requested placement profile can be honored.
    pub placement_honored: bool,
}

impl ProofInputs {
    /// Inputs for a clean, offload-eligible, admissible, honorable command.
    #[must_use]
    pub fn ready() -> Self {
        Self {
            recommendation: AdmitRecommendation::Offload,
            any_admissible: true,
            command_safe_for_proof: true,
            placement_honored: true,
        }
    }
}

/// Decide proof mode. Pure and total — and, by the [`ProofVerdict`] type, can
/// only ever proceed-remote or refuse, never run locally.
///
/// Refusal precedence (most fundamental first): a `Local` recommendation means
/// the classifier would never even attempt remote, so that is reported first;
/// then an unsafe command shape; then no admissible worker; then an unhonored
/// placement profile. A `Defer`/`Queue` recommendation with no admissible
/// worker also refuses (proof mode does not wait or queue — it must run now).
#[must_use]
pub fn evaluate_proof_mode(inputs: &ProofInputs) -> ProofVerdict {
    if inputs.recommendation == AdmitRecommendation::Local {
        return ProofVerdict::Refuse(ProofRefusalReason::ClassifierChoseLocal);
    }
    if !inputs.command_safe_for_proof {
        return ProofVerdict::Refuse(ProofRefusalReason::UnsafeCommandShape);
    }
    if !inputs.any_admissible {
        return ProofVerdict::Refuse(ProofRefusalReason::NoAdmissibleWorker);
    }
    if !inputs.placement_honored {
        return ProofVerdict::Refuse(ProofRefusalReason::PlacementProfileUnhonored);
    }
    ProofVerdict::ProceedRemote
}

/// The durable JSON envelope for a proof-mode refusal. `category` is fixed to
/// `admission_denial` so a consumer never confuses a proof *refusal* (nothing
/// ran) with a product compile/test *failure* (something ran and failed).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofRefusal {
    /// Always true — this envelope only exists for refusals.
    pub refused: bool,
    /// Fixed discriminator distinguishing this from a product failure.
    pub category: String,
    /// The refusal reason token.
    pub reason: ProofRefusalReason,
    /// The stable incident reason code (`RCH-I012` proof refusal).
    pub incident_reason: IncidentReasonCode,
    /// Operator-facing detail.
    pub detail: String,
}

impl ProofRefusal {
    /// The fixed category discriminator.
    pub const CATEGORY: &'static str = "admission_denial";

    /// Build a refusal envelope from a reason.
    #[must_use]
    pub fn new(reason: ProofRefusalReason) -> Self {
        Self {
            refused: true,
            category: Self::CATEGORY.to_string(),
            reason,
            incident_reason: IncidentReasonCode::ProofRefusal,
            detail: reason.detail().to_string(),
        }
    }

    /// Build a refusal envelope from a verdict, if it refused.
    #[must_use]
    pub fn from_verdict(verdict: &ProofVerdict) -> Option<Self> {
        verdict.refusal().map(Self::new)
    }

    /// Whether this denial is an admission/policy denial (always true) — i.e.
    /// NOT a product compile/test failure.
    #[must_use]
    pub fn is_admission_denial(&self) -> bool {
        self.category == Self::CATEGORY
    }

    /// Human-readable line.
    #[must_use]
    pub fn render(&self) -> String {
        format!(
            "proof refused ({}, {}): {}",
            self.reason.as_str(),
            self.incident_reason.code(),
            self.detail
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proceeds_only_when_remote_admissible_safe_and_honored() {
        assert_eq!(
            evaluate_proof_mode(&ProofInputs::ready()),
            ProofVerdict::ProceedRemote
        );
    }

    #[test]
    fn refuses_when_classifier_chose_local() {
        // The headline guarantee: proof mode never runs locally.
        let inputs = ProofInputs {
            recommendation: AdmitRecommendation::Local,
            ..ProofInputs::ready()
        };
        let v = evaluate_proof_mode(&inputs);
        assert_eq!(
            v,
            ProofVerdict::Refuse(ProofRefusalReason::ClassifierChoseLocal)
        );
        assert!(!v.proceeds());
    }

    #[test]
    fn refuses_when_no_admissible_worker() {
        let inputs = ProofInputs {
            any_admissible: false,
            ..ProofInputs::ready()
        };
        assert_eq!(
            evaluate_proof_mode(&inputs),
            ProofVerdict::Refuse(ProofRefusalReason::NoAdmissibleWorker)
        );
    }

    #[test]
    fn refuses_when_command_shape_unsafe() {
        let inputs = ProofInputs {
            command_safe_for_proof: false,
            ..ProofInputs::ready()
        };
        assert_eq!(
            evaluate_proof_mode(&inputs),
            ProofVerdict::Refuse(ProofRefusalReason::UnsafeCommandShape)
        );
    }

    #[test]
    fn refuses_when_placement_profile_unhonored() {
        let inputs = ProofInputs {
            placement_honored: false,
            ..ProofInputs::ready()
        };
        assert_eq!(
            evaluate_proof_mode(&inputs),
            ProofVerdict::Refuse(ProofRefusalReason::PlacementProfileUnhonored)
        );
    }

    #[test]
    fn defer_recommendation_without_admissible_still_refuses_never_waits() {
        // Proof mode does not queue/defer; a Defer recommendation with no
        // admissible worker refuses now rather than waiting.
        let inputs = ProofInputs {
            recommendation: AdmitRecommendation::Defer,
            any_admissible: false,
            ..ProofInputs::ready()
        };
        assert_eq!(
            evaluate_proof_mode(&inputs),
            ProofVerdict::Refuse(ProofRefusalReason::NoAdmissibleWorker)
        );
    }

    #[test]
    fn local_recommendation_outranks_other_refusals() {
        // Even with everything else also wrong, a Local recommendation reports
        // ClassifierChoseLocal (the most fundamental: it would never go remote).
        let inputs = ProofInputs {
            recommendation: AdmitRecommendation::Local,
            any_admissible: false,
            command_safe_for_proof: false,
            placement_honored: false,
        };
        assert_eq!(
            evaluate_proof_mode(&inputs).refusal(),
            Some(ProofRefusalReason::ClassifierChoseLocal)
        );
    }

    #[test]
    fn verdict_type_has_no_local_variant() {
        // Exhaustive match proves the type can only proceed-remote or refuse —
        // there is no way to express "ran locally and proved".
        for inputs in [
            ProofInputs::ready(),
            ProofInputs {
                any_admissible: false,
                ..ProofInputs::ready()
            },
        ] {
            match evaluate_proof_mode(&inputs) {
                ProofVerdict::ProceedRemote | ProofVerdict::Refuse(_) => {}
            }
        }
    }

    #[test]
    fn refusal_envelope_is_durable_and_marks_admission_denial() {
        let verdict = evaluate_proof_mode(&ProofInputs {
            any_admissible: false,
            ..ProofInputs::ready()
        });
        let refusal = ProofRefusal::from_verdict(&verdict).expect("refused");
        assert!(refusal.refused);
        assert!(refusal.is_admission_denial());
        assert_eq!(refusal.incident_reason, IncidentReasonCode::ProofRefusal);
        let value = serde_json::to_value(&refusal).unwrap();
        assert_eq!(value["category"], "admission_denial");
        assert_eq!(value["reason"], "no_admissible_worker");
        assert_eq!(value["incident_reason"], "RCH-I012");
        // Durable round-trip.
        let back: ProofRefusal = serde_json::from_value(value).unwrap();
        assert_eq!(back, refusal);
    }

    #[test]
    fn proceed_verdict_has_no_refusal_envelope() {
        let verdict = evaluate_proof_mode(&ProofInputs::ready());
        assert!(ProofRefusal::from_verdict(&verdict).is_none());
    }

    #[test]
    fn every_refusal_reason_has_token_and_detail() {
        let mut tokens: Vec<&str> = ProofRefusalReason::ALL.iter().map(|r| r.as_str()).collect();
        tokens.sort_unstable();
        let before = tokens.len();
        tokens.dedup();
        assert_eq!(before, tokens.len(), "duplicate refusal tokens");
        for r in ProofRefusalReason::ALL {
            assert!(!r.detail().is_empty());
        }
    }
}
