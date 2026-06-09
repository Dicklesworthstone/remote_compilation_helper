//! `rch exec` execution-location contract
//! (bd-session-history-remediation-ocv9i.13.3).
//!
//! Agents kept inferring *where* a command ran from log prose. Every explicit
//! `rch exec` JSON response must instead state it outright: local-or-remote, the
//! selected worker, the classification, a decisive reason code, the admission
//! summary, the proof/fallback policy, and the remediation. This module is that
//! composite contract — [`ExecResponse`] — assembled from the pieces already
//! landed: the exec policy ([`crate::exec_policy`]), the admission vocabulary +
//! aggregation ([`crate::admission_rejection`]), and the next-action
//! recommendations ([`crate::admission_recommendation`]).
//!
//! The cardinal invariant: `local_or_remote` is always present and definite, and
//! a `selected_worker` exists **iff** the location is `Remote` — never the
//! ambiguity that motivated the bead.

use serde::{Deserialize, Serialize};

use crate::admission_recommendation::{Recommendation, recommend_for_summary};
use crate::admission_rejection::AdmissionRejectionSummary;
use crate::exec_policy::ExecDisposition;
use crate::incident::IncidentReasonCode;

/// Where a command definitively executed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionLocation {
    /// Ran on a remote worker.
    Remote,
    /// Ran locally (fallback or non-compilation).
    Local,
    /// Did not run (rejected / fail-closed).
    NotExecuted,
}

impl ExecutionLocation {
    /// Stable lowercase token.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            ExecutionLocation::Remote => "remote",
            ExecutionLocation::Local => "local",
            ExecutionLocation::NotExecuted => "not_executed",
        }
    }
}

/// The composite `rch exec` machine response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecResponse {
    /// Definite execution location.
    pub local_or_remote: ExecutionLocation,
    /// The worker, present iff `local_or_remote == Remote`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected_worker: Option<String>,
    /// Whether the command classified as a compilation.
    pub is_compilation: bool,
    /// Compilation family (e.g. `cargo_build`), when classified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
    /// Decisive incident reason code, when there is one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<IncidentReasonCode>,
    /// Aggregated admission rejection summary, when admission was attempted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admission: Option<AdmissionRejectionSummary>,
    /// The exec-policy disposition that produced this outcome.
    pub disposition: ExecDisposition,
    /// Whether proof/strict mode was in force.
    pub proof_mode: bool,
    /// Next-action remediation (may be empty on success).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub remediation: Vec<Recommendation>,
    /// Concise human/agent-facing detail.
    pub detail: String,
}

impl ExecResponse {
    /// The contract invariant: a worker is recorded iff the location is remote.
    #[must_use]
    pub fn invariant_holds(&self) -> bool {
        match self.local_or_remote {
            ExecutionLocation::Remote => self.selected_worker.is_some(),
            ExecutionLocation::Local | ExecutionLocation::NotExecuted => {
                self.selected_worker.is_none()
            }
        }
    }

    /// A successful remote execution on `worker`.
    #[must_use]
    pub fn remote_success(worker: impl Into<String>, family: impl Into<String>) -> Self {
        Self {
            local_or_remote: ExecutionLocation::Remote,
            selected_worker: Some(worker.into()),
            is_compilation: true,
            family: Some(family.into()),
            reason_code: None,
            admission: None,
            disposition: ExecDisposition::RunRemote,
            proof_mode: false,
            remediation: Vec::new(),
            detail: "ran on remote worker".to_string(),
        }
    }

    /// A local fallback (with the reason it fell back).
    #[must_use]
    pub fn local_fallback(
        is_compilation: bool,
        reason_code: IncidentReasonCode,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            local_or_remote: ExecutionLocation::Local,
            selected_worker: None,
            is_compilation,
            family: None,
            reason_code: Some(reason_code),
            admission: None,
            disposition: ExecDisposition::RunLocalFallback,
            proof_mode: false,
            remediation: Vec::new(),
            detail: detail.into(),
        }
    }

    /// A fail-closed proof refusal (nothing ran), with the admission summary and
    /// derived remediation.
    #[must_use]
    pub fn proof_refused(admission: AdmissionRejectionSummary) -> Self {
        let remediation = recommend_for_summary(&admission, true);
        Self {
            local_or_remote: ExecutionLocation::NotExecuted,
            selected_worker: None,
            is_compilation: true,
            family: None,
            reason_code: Some(IncidentReasonCode::ProofRefusal),
            admission: Some(admission),
            disposition: ExecDisposition::Reject,
            proof_mode: true,
            remediation,
            detail: "proof mode refused before execution".to_string(),
        }
    }

    /// An explicit proof-mode non-compilation rejection.
    #[must_use]
    pub fn non_compilation_rejected() -> Self {
        Self {
            local_or_remote: ExecutionLocation::NotExecuted,
            selected_worker: None,
            is_compilation: false,
            family: None,
            reason_code: Some(IncidentReasonCode::ProofRefusal),
            admission: None,
            disposition: ExecDisposition::Reject,
            proof_mode: true,
            remediation: Vec::new(),
            detail: "non-compilation command rejected under proof mode".to_string(),
        }
    }

    /// Daemon unavailable — fell back to local (fail-open).
    #[must_use]
    pub fn daemon_unavailable() -> Self {
        Self {
            local_or_remote: ExecutionLocation::Local,
            selected_worker: None,
            is_compilation: true,
            family: None,
            reason_code: Some(IncidentReasonCode::DaemonSocketRefused),
            admission: None,
            disposition: ExecDisposition::RunLocalFallback,
            proof_mode: false,
            remediation: Vec::new(),
            detail: "daemon unreachable; ran locally (fail-open)".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admission_rejection::{
        AdmissionRejectionCategory, CandidateRejection, aggregate_rejections,
    };

    fn assert_invariant(r: &ExecResponse) {
        assert!(
            r.invariant_holds(),
            "location/worker invariant violated: {r:?}"
        );
    }

    // --- The five required golden scenarios ---------------------------------

    #[test]
    fn golden_remote_success() {
        let r = ExecResponse::remote_success("css", "cargo_build");
        assert_invariant(&r);
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["local_or_remote"], "remote");
        assert_eq!(v["selected_worker"], "css");
        assert_eq!(v["disposition"], "run_remote");
        assert!(v.get("reason_code").is_none());
        assert!(v.get("remediation").is_none(), "no remediation on success");
    }

    #[test]
    fn golden_local_fallback() {
        let r = ExecResponse::local_fallback(
            true,
            IncidentReasonCode::LocalFallback,
            "no admissible worker; ran locally",
        );
        assert_invariant(&r);
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["local_or_remote"], "local");
        assert!(v.get("selected_worker").is_none());
        assert_eq!(v["disposition"], "run_local_fallback");
        assert_eq!(v["reason_code"], "RCH-I011");
    }

    #[test]
    fn golden_fail_closed_proof_refusal() {
        let admission = aggregate_rejections(
            2,
            &[
                CandidateRejection {
                    worker_id: "a".into(),
                    category: AdmissionRejectionCategory::MissingRustTarget,
                },
                CandidateRejection {
                    worker_id: "b".into(),
                    category: AdmissionRejectionCategory::OsArchMismatch,
                },
            ],
        );
        let r = ExecResponse::proof_refused(admission);
        assert_invariant(&r);
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["local_or_remote"], "not_executed");
        assert_eq!(v["disposition"], "reject");
        assert_eq!(v["proof_mode"], true);
        assert_eq!(v["reason_code"], "RCH-I012");
        // Admission summary + remediation are present for the handoff.
        assert_eq!(v["admission"]["rejected"], 2);
        assert!(!r.remediation.is_empty());
        assert_eq!(v["remediation"][0]["action"], "fix_worker_capability");
    }

    #[test]
    fn golden_non_compilation_rejection() {
        let r = ExecResponse::non_compilation_rejected();
        assert_invariant(&r);
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["local_or_remote"], "not_executed");
        assert_eq!(v["is_compilation"], false);
        assert_eq!(v["disposition"], "reject");
    }

    #[test]
    fn golden_daemon_unavailable() {
        let r = ExecResponse::daemon_unavailable();
        assert_invariant(&r);
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["local_or_remote"], "local");
        assert_eq!(v["reason_code"], "RCH-I010");
        assert_eq!(v["disposition"], "run_local_fallback");
    }

    // --- The contract invariant --------------------------------------------

    #[test]
    fn worker_present_iff_remote() {
        assert_invariant(&ExecResponse::remote_success("w", "cargo_build"));
        assert_invariant(&ExecResponse::local_fallback(
            true,
            IncidentReasonCode::LocalFallback,
            "x",
        ));
        assert_invariant(&ExecResponse::non_compilation_rejected());
        assert_invariant(&ExecResponse::daemon_unavailable());
        // A hand-built inconsistent record fails the invariant.
        let bad = ExecResponse {
            local_or_remote: ExecutionLocation::Remote,
            selected_worker: None,
            ..ExecResponse::remote_success("w", "cargo_build")
        };
        assert!(!bad.invariant_holds());
    }

    #[test]
    fn response_round_trips() {
        let r = ExecResponse::daemon_unavailable();
        let v = serde_json::to_value(&r).unwrap();
        let back: ExecResponse = serde_json::from_value(v).unwrap();
        assert_eq!(back, r);
    }

    #[test]
    fn required_fields_are_always_present() {
        // local_or_remote, is_compilation, disposition, proof_mode, detail are
        // never omitted from the wire form.
        for r in [
            ExecResponse::remote_success("w", "cargo_build"),
            ExecResponse::non_compilation_rejected(),
            ExecResponse::daemon_unavailable(),
        ] {
            let v = serde_json::to_value(&r).unwrap();
            for key in [
                "local_or_remote",
                "is_compilation",
                "disposition",
                "proof_mode",
                "detail",
            ] {
                assert!(v.get(key).is_some(), "missing required field {key}");
            }
        }
    }
}
