//! Agent-facing proof handoff output
//! (bd-session-history-remediation-ocv9i.5.4).
//!
//! When proof is denied or queued, a Beads / Agent-Mail handoff must not rely on
//! prose like "RCH had no admissible workers". This module emits a concise,
//! machine-readable [`ProofHandoff`]: the proof-intent id, a decisive incident
//! reason code, the next action to take, a replay command, and — critically — a
//! [`ProofFailureClass`] discriminator that tells a downstream agent whether the
//! failure was the product's, the infrastructure's, an admission denial, or a
//! refused local fallback.
//!
//! The handoff is a plain serializable value with **no Beads dependency** — a
//! handoff consumer embeds its JSON; proof storage never depends on Beads. It
//! reuses the proof-mode policy ([`crate::proof_policy`]), the next-action
//! vocabulary ([`crate::admission_recommendation`]), the incident registry, and
//! the exec failure classifier ([`crate::disk_pressure_report`]).

use serde::{Deserialize, Serialize};

use crate::admission_recommendation::NextAction;
use crate::disk_pressure_report::ExecFailureClass;
use crate::incident::IncidentReasonCode;
use crate::proof_policy::{ProofRefusal, ProofRefusalReason};

/// The top-level class of a proof failure — the discriminator the bead requires.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofFailureClass {
    /// The command ran remotely and the product failed (compile/test error).
    ProductFailure,
    /// A worker/transport/daemon/environment problem (not the product).
    InfrastructureFailure,
    /// Refused before execution (no admissible worker, policy, capability).
    AdmissionDenial,
    /// Proof mode refused to accept a local fallback.
    LocalFallbackRefused,
}

impl ProofFailureClass {
    /// Stable lowercase token.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            ProofFailureClass::ProductFailure => "product_failure",
            ProofFailureClass::InfrastructureFailure => "infrastructure_failure",
            ProofFailureClass::AdmissionDenial => "admission_denial",
            ProofFailureClass::LocalFallbackRefused => "local_fallback_refused",
        }
    }

    /// All four classes (for coverage tests).
    pub const ALL: &'static [ProofFailureClass] = &[
        Self::ProductFailure,
        Self::InfrastructureFailure,
        Self::AdmissionDenial,
        Self::LocalFallbackRefused,
    ];

    /// Class of an exec failure (a command that ran on a worker).
    #[must_use]
    pub fn from_exec_failure(class: ExecFailureClass) -> Self {
        match class {
            ExecFailureClass::ProductCompile => Self::ProductFailure,
            ExecFailureClass::WorkerEnvironment => Self::InfrastructureFailure,
            ExecFailureClass::Indeterminate => Self::InfrastructureFailure,
        }
    }

    /// Class implied by an incident reason code (for pre-execution incidents).
    #[must_use]
    pub fn from_incident_reason(code: IncidentReasonCode) -> Self {
        match code {
            // Worker/transport/environment infrastructure.
            IncidentReasonCode::DaemonSocketRefused
            | IncidentReasonCode::RsyncVanishedFile
            | IncidentReasonCode::DiskFull
            | IncidentReasonCode::CriticalPressure
            | IncidentReasonCode::WrongUserPathWorkerBinary
            | IncidentReasonCode::ArtifactMiss => Self::InfrastructureFailure,
            // Proof refused to accept a local fallback.
            IncidentReasonCode::LocalFallback => Self::LocalFallbackRefused,
            // Everything else is an admission/policy denial.
            _ => Self::AdmissionDenial,
        }
    }
}

/// Map a proof refusal reason to its failure class and next action.
fn refusal_class(reason: ProofRefusalReason) -> ProofFailureClass {
    match reason {
        // The classifier would run local; proof refused that fallback.
        ProofRefusalReason::ClassifierChoseLocal => ProofFailureClass::LocalFallbackRefused,
        // No admissible worker / unsafe shape / unhonored placement: admission denial.
        ProofRefusalReason::NoAdmissibleWorker
        | ProofRefusalReason::UnsafeCommandShape
        | ProofRefusalReason::PlacementProfileUnhonored => ProofFailureClass::AdmissionDenial,
    }
}

/// The next action an agent should take for a refusal reason.
#[must_use]
pub fn next_action_for_refusal(reason: ProofRefusalReason) -> NextAction {
    match reason {
        ProofRefusalReason::NoAdmissibleWorker => NextAction::QueueProof,
        ProofRefusalReason::ClassifierChoseLocal => NextAction::RefreshCapabilities,
        ProofRefusalReason::UnsafeCommandShape => NextAction::ShrinkScope,
        ProofRefusalReason::PlacementProfileUnhonored => NextAction::ContactOperator,
    }
}

/// The concise, machine-readable proof handoff for Beads / Agent-Mail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofHandoff {
    /// Durable proof-intent id (see [`crate::proof_intent`]).
    pub proof_intent_id: String,
    /// The top-level failure discriminator.
    pub failure_class: ProofFailureClass,
    /// Decisive incident reason code (`RCH-Innn`).
    pub reason_code: IncidentReasonCode,
    /// The next action an agent should take.
    pub next_action: NextAction,
    /// A command the agent can run to retry/replay.
    pub replay_command: String,
    /// Concise human/agent-facing detail.
    pub detail: String,
}

impl ProofHandoff {
    /// Build a handoff for a proof refusal.
    #[must_use]
    pub fn for_refusal(
        intent_id: impl Into<String>,
        command: &str,
        refusal: &ProofRefusal,
    ) -> Self {
        let next_action = next_action_for_refusal(refusal.reason);
        Self {
            proof_intent_id: intent_id.into(),
            failure_class: refusal_class(refusal.reason),
            reason_code: refusal.incident_reason,
            next_action,
            replay_command: format!("rch exec --proof -- {command}"),
            detail: refusal.detail.clone(),
        }
    }

    /// Build a handoff for a proof that was queued (deferred). The replay
    /// command reattaches by intent id.
    #[must_use]
    pub fn for_queued(intent_id: impl Into<String>, command: &str) -> Self {
        let intent_id = intent_id.into();
        Self {
            replay_command: format!("rch exec --proof -- {command}"),
            detail: format!("proof queued; reattach with intent {intent_id}"),
            proof_intent_id: intent_id,
            failure_class: ProofFailureClass::AdmissionDenial,
            reason_code: IncidentReasonCode::InsufficientSlots,
            next_action: NextAction::QueueProof,
        }
    }

    /// Whether this handoff blames the product (vs infra/admission/fallback).
    #[must_use]
    pub fn is_product_failure(&self) -> bool {
        self.failure_class == ProofFailureClass::ProductFailure
    }

    /// One-line summary for logs.
    #[must_use]
    pub fn render(&self) -> String {
        format!(
            "proof handoff [{}] {} ({}) -> {} | replay: {}",
            self.proof_intent_id,
            self.failure_class.as_str(),
            self.reason_code.code(),
            self.next_action.as_str(),
            self.replay_command,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refusal_for_no_admissible_worker_is_admission_denial_queue() {
        let refusal = ProofRefusal::new(ProofRefusalReason::NoAdmissibleWorker);
        let handoff = ProofHandoff::for_refusal("intent-1", "cargo build", &refusal);
        assert_eq!(handoff.failure_class, ProofFailureClass::AdmissionDenial);
        assert_eq!(handoff.reason_code, IncidentReasonCode::ProofRefusal);
        assert_eq!(handoff.next_action, NextAction::QueueProof);
        assert_eq!(handoff.replay_command, "rch exec --proof -- cargo build");
        assert_eq!(handoff.proof_intent_id, "intent-1");
    }

    #[test]
    fn classifier_chose_local_is_local_fallback_refused() {
        let refusal = ProofRefusal::new(ProofRefusalReason::ClassifierChoseLocal);
        let handoff = ProofHandoff::for_refusal("i2", "cargo fmt", &refusal);
        assert_eq!(
            handoff.failure_class,
            ProofFailureClass::LocalFallbackRefused
        );
        assert_eq!(handoff.next_action, NextAction::RefreshCapabilities);
    }

    #[test]
    fn unsafe_shape_and_placement_reasons_map_through() {
        let unsafe_h = ProofHandoff::for_refusal(
            "i",
            "x",
            &ProofRefusal::new(ProofRefusalReason::UnsafeCommandShape),
        );
        assert_eq!(unsafe_h.next_action, NextAction::ShrinkScope);
        assert_eq!(unsafe_h.failure_class, ProofFailureClass::AdmissionDenial);
        let place_h = ProofHandoff::for_refusal(
            "i",
            "x",
            &ProofRefusal::new(ProofRefusalReason::PlacementProfileUnhonored),
        );
        assert_eq!(place_h.next_action, NextAction::ContactOperator);
    }

    #[test]
    fn queued_handoff_reattaches_by_intent() {
        let handoff = ProofHandoff::for_queued("intent-q", "cargo test");
        assert_eq!(handoff.next_action, NextAction::QueueProof);
        assert!(handoff.detail.contains("intent-q"));
        assert!(handoff.replay_command.contains("cargo test"));
    }

    #[test]
    fn failure_class_from_exec_failure() {
        assert_eq!(
            ProofFailureClass::from_exec_failure(ExecFailureClass::ProductCompile),
            ProofFailureClass::ProductFailure
        );
        assert_eq!(
            ProofFailureClass::from_exec_failure(ExecFailureClass::WorkerEnvironment),
            ProofFailureClass::InfrastructureFailure
        );
    }

    #[test]
    fn failure_class_from_incident_reason() {
        assert_eq!(
            ProofFailureClass::from_incident_reason(IncidentReasonCode::DaemonSocketRefused),
            ProofFailureClass::InfrastructureFailure
        );
        assert_eq!(
            ProofFailureClass::from_incident_reason(IncidentReasonCode::DiskFull),
            ProofFailureClass::InfrastructureFailure
        );
        assert_eq!(
            ProofFailureClass::from_incident_reason(IncidentReasonCode::NoAdmissibleWorkers),
            ProofFailureClass::AdmissionDenial
        );
        assert_eq!(
            ProofFailureClass::from_incident_reason(IncidentReasonCode::LocalFallback),
            ProofFailureClass::LocalFallbackRefused
        );
    }

    #[test]
    fn json_carries_all_four_discriminators() {
        // Every required discriminator is representable and stable.
        let tokens: Vec<&str> = ProofFailureClass::ALL.iter().map(|c| c.as_str()).collect();
        assert!(tokens.contains(&"product_failure"));
        assert!(tokens.contains(&"infrastructure_failure"));
        assert!(tokens.contains(&"admission_denial"));
        assert!(tokens.contains(&"local_fallback_refused"));
    }

    #[test]
    fn handoff_serializes_standalone_without_beads() {
        // The handoff is a plain value — it serializes with no Beads coupling.
        let refusal = ProofRefusal::new(ProofRefusalReason::NoAdmissibleWorker);
        let handoff = ProofHandoff::for_refusal("intent-1", "cargo build", &refusal);
        let value = serde_json::to_value(&handoff).unwrap();
        assert_eq!(value["failure_class"], "admission_denial");
        assert_eq!(value["reason_code"], "RCH-I012");
        assert_eq!(value["next_action"], "queue_proof");
        assert_eq!(value["proof_intent_id"], "intent-1");
        let back: ProofHandoff = serde_json::from_value(value).unwrap();
        assert_eq!(back, handoff);
    }

    #[test]
    fn render_is_concise_and_machine_greppable() {
        let refusal = ProofRefusal::new(ProofRefusalReason::NoAdmissibleWorker);
        let line = ProofHandoff::for_refusal("intent-1", "cargo build", &refusal).render();
        assert!(line.contains("intent-1"));
        assert!(line.contains("admission_denial"));
        assert!(line.contains("queue_proof"));
        assert!(line.contains("replay:"));
    }
}
