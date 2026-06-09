//! Golden-artifact + cross-contract metamorphic tests for the admission / proof
//! / exec / readiness surface (bd-review-test-admission-goldens).
//!
//! Two layers:
//! 1. **Goldens** — committed `json!` expectations pin the serialized SHAPE and
//!    token vocabulary of each agent-facing envelope; a renamed field or changed
//!    token diverges from the golden (structural `serde_json::Value` equality).
//! 2. **Cross-contract metamorphic invariants** — the consistency relations that
//!    tie the separate contracts together (every rejection category has exactly
//!    one action/class/reason; eligibility reasons bridge to categories;
//!    ExecResponse worker-iff-remote; readiness remote_ready ⇒ admissible>0;
//!    proof handoff totality; incident reason-code stability).

use proptest::prelude::*;
use rch_common::admission_recommendation::{NextAction, recommend, recommend_for_summary};
use rch_common::admission_rejection::{
    AdmissionRejectionCategory, CandidateRejection, RejectionClass, aggregate_rejections,
};
use rch_common::admit_preflight::preflight;
use rch_common::capability_probe::EligibilityVerdict;
use rch_common::exec_response::ExecResponse;
use rch_common::incident::IncidentReasonCode;
use rch_common::proof_handoff::{ProofFailureClass, ProofHandoff};
use rch_common::proof_policy::{ProofRefusal, ProofRefusalReason};
use rch_common::readiness::{
    IncidentChainEntry, ReadinessInputs, ReadinessSplit, assess_readiness,
};
use serde_json::{Value, json};

fn assert_golden<T: serde::Serialize>(name: &str, value: &T, expected: Value) {
    let actual = serde_json::to_value(value).expect("serializes");
    assert_eq!(
        actual,
        expected,
        "golden drift in {name}: a field/value/token changed. If intentional, update the json! block.\nactual:\n{}",
        serde_json::to_string_pretty(&actual).unwrap()
    );
}

// =============================================================================
// Goldens — pinned serialized shape/tokens of each envelope
// =============================================================================

#[test]
fn golden_admission_rejection_summary() {
    let summary = aggregate_rejections(
        3,
        &[
            CandidateRejection {
                worker_id: "a".into(),
                category: AdmissionRejectionCategory::MissingRustTarget,
            },
            CandidateRejection {
                worker_id: "b".into(),
                category: AdmissionRejectionCategory::CircuitOpen,
            },
        ],
    );
    assert_golden(
        "AdmissionRejectionSummary",
        &summary,
        json!({
            "total_candidates": 3,
            "rejected": 2,
            "by_category": { "missing_rust_target": 1, "circuit_open": 1 },
            "by_class": { "command_admissibility": 1, "worker_health": 1 },
        }),
    );
}

#[test]
fn golden_proof_handoff_refusal() {
    let handoff = ProofHandoff::for_refusal(
        "intent-1",
        "cargo build",
        &ProofRefusal::new(ProofRefusalReason::NoAdmissibleWorker),
    );
    assert_golden(
        "ProofHandoff",
        &handoff,
        json!({
            "proof_intent_id": "intent-1",
            "failure_class": "admission_denial",
            "reason_code": "RCH-I012",
            "next_action": "queue_proof",
            "replay_command": "rch exec --proof -- cargo build",
            "detail": "proof mode requires remote execution but no worker is admissible",
        }),
    );
}

#[test]
fn golden_exec_response_remote_success() {
    assert_golden(
        "ExecResponse::remote_success",
        &ExecResponse::remote_success("css", "cargo_build"),
        json!({
            "local_or_remote": "remote",
            "selected_worker": "css",
            "is_compilation": true,
            "family": "cargo_build",
            "disposition": "run_remote",
            "proof_mode": false,
            "detail": "ran on remote worker",
        }),
    );
}

#[test]
fn golden_readiness_daemon_down() {
    let inputs = ReadinessInputs {
        split: ReadinessSplit {
            daemon_reachable: false,
            desired_fleet_workers: 3,
            live_healthy_workers: 0,
            command_admissible_workers: 0,
        },
        proof_refused: false,
        dominant_rejection: None,
        recent_incidents: Vec::new(),
    };
    let report = assess_readiness(&inputs);
    assert_golden(
        "ReadinessReport(daemon_down)",
        &report,
        json!({
            "split": {
                "daemon_reachable": false,
                "desired_fleet_workers": 3,
                "live_healthy_workers": 0,
                "command_admissible_workers": 0,
            },
            "remote_ready": false,
            "blocker": "daemon_down",
            "incident_chain": [],
            "detail": "daemon socket unreachable",
        }),
    );
}

#[test]
fn golden_admit_preflight_wasm() {
    let p = preflight("cargo build --target wasm32-unknown-unknown", false);
    assert_golden(
        "AdmitPreflight",
        &p,
        json!({
            "command": "cargo build --target wasm32-unknown-unknown",
            "compound": ["cargo build --target wasm32-unknown-unknown"],
            "is_compilation": true,
            "family": "cargo_build",
            "required": {
                "needs_cargo": true,
                "needs_bun": false,
                "needs_targets": ["wasm32-unknown-unknown"],
                "needs_toolchains": [],
            },
            "proof_policy": false,
            "base_recommendation": "offload",
            "detail": "offload-eligible (family=cargo_build)",
        }),
    );
}

// =============================================================================
// Cross-contract metamorphic invariants
// =============================================================================

#[test]
fn every_rejection_category_maps_to_exactly_one_action_class_reason() {
    assert_eq!(
        AdmissionRejectionCategory::ALL.len(),
        12,
        "rejection taxonomy size changed — update goldens/recommendations"
    );
    let mut tokens = std::collections::BTreeSet::new();
    for &c in AdmissionRejectionCategory::ALL {
        // Each mapping is total and deterministic.
        assert_eq!(recommend(c, false), recommend(c, false));
        let _class: RejectionClass = c.class();
        let _reason: IncidentReasonCode = c.incident_reason();
        let _a0 = recommend(c, false);
        let _a1 = recommend(c, true);
        assert!(tokens.insert(c.as_str()), "duplicate category token {}", c.as_str());
    }
}

#[test]
fn unambiguous_incident_reasons_round_trip_to_categories() {
    for &c in AdmissionRejectionCategory::ALL {
        let code = c.incident_reason();
        match AdmissionRejectionCategory::from_incident_reason(code) {
            Some(back) => {
                // 1:1 codes must round-trip to a category that maps back to the
                // same code.
                assert_eq!(back.incident_reason(), code, "{} reason mismatch", c.as_str());
            }
            None => {
                // Non-invertible codes are the coarse runtime code (shared by
                // the three Missing* categories) and QueueAmbiguity (used by
                // ClassifierLocalDrift) — both are documented as not 1:1.
                assert!(
                    matches!(
                        code,
                        IncidentReasonCode::MissingRuntimeToolchainTarget
                            | IncidentReasonCode::QueueAmbiguity
                    ),
                    "{} has non-invertible code {code:?} outside the documented ambiguous set",
                    c.as_str()
                );
            }
        }
    }
}

#[test]
fn eligibility_verdict_reasons_bridge_to_admission_vocabulary() {
    // Every reason an EligibilityVerdict can carry either maps to an admission
    // category (1:1) or is one of the two documented non-aggregation codes
    // (the coarse runtime code, refined by the caller; or the wrong-binary code).
    let verdicts = [
        EligibilityVerdict::StaleTelemetry,
        EligibilityVerdict::Unhealthy,
        EligibilityVerdict::Busy,
        EligibilityVerdict::MissingCapability {
            reason: IncidentReasonCode::OsArchMismatch,
            detail: "os".into(),
        },
        EligibilityVerdict::MissingCapability {
            reason: IncidentReasonCode::MissingRuntimeToolchainTarget,
            detail: "rt".into(),
        },
    ];
    for v in verdicts {
        let code = v.reason().expect("non-eligible verdict has a reason");
        let mapped = AdmissionRejectionCategory::from_incident_reason(code);
        assert!(
            mapped.is_some() || code == IncidentReasonCode::MissingRuntimeToolchainTarget,
            "eligibility reason {code:?} does not bridge to the admission vocabulary"
        );
    }
    // Eligible carries no reason.
    assert_eq!(EligibilityVerdict::Eligible.reason(), None);
}

#[test]
fn exec_response_builders_all_satisfy_worker_iff_remote_invariant() {
    let summary = aggregate_rejections(
        1,
        &[CandidateRejection {
            worker_id: "a".into(),
            category: AdmissionRejectionCategory::OsArchMismatch,
        }],
    );
    let responses = [
        ExecResponse::remote_success("css", "cargo_build"),
        ExecResponse::local_fallback(true, IncidentReasonCode::LocalFallback, "x"),
        ExecResponse::proof_refused(summary),
        ExecResponse::non_compilation_rejected(),
        ExecResponse::daemon_unavailable(),
    ];
    for r in &responses {
        assert!(r.invariant_holds(), "worker-iff-remote violated: {r:?}");
    }
}

#[test]
fn proof_handoff_is_total_over_all_refusal_reasons() {
    assert_eq!(ProofFailureClass::ALL.len(), 4);
    for &reason in ProofRefusalReason::ALL {
        let handoff = ProofHandoff::for_refusal("i", "cargo build", &ProofRefusal::new(reason));
        assert_eq!(handoff.reason_code, IncidentReasonCode::ProofRefusal);
        // failure_class and next_action are always populated and serialize.
        let v = serde_json::to_value(&handoff).unwrap();
        assert!(v["failure_class"].is_string());
        assert!(v["next_action"].is_string());
        assert!(v["replay_command"].as_str().unwrap().contains("cargo build"));
    }
}

#[test]
fn incident_reason_codes_are_stable_and_sequential() {
    // Guards against an RCH-Innn renumber/removal that would silently break
    // every persisted ledger entry and the goldens above.
    let all = IncidentReasonCode::ALL;
    assert!(all.len() >= 17, "reason code registry shrank: {}", all.len());
    let mut seen = std::collections::BTreeSet::new();
    for (i, r) in all.iter().enumerate() {
        let expected = format!("RCH-I{:03}", i + 1);
        assert_eq!(r.code(), expected, "reason code out of sequence at {i}");
        assert!(seen.insert(r.code()), "duplicate reason code {}", r.code());
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1024))]

    /// Readiness invariant over a generated split/proof/incident matrix:
    /// `remote_ready` is impossible without at least one admissible worker, and
    /// the report's own invariant always holds.
    #[test]
    fn readiness_remote_ready_implies_admissible(
        daemon in any::<bool>(),
        desired in 0u32..8,
        healthy in 0u32..8,
        admissible in 0u32..8,
        proof_refused in any::<bool>(),
        pressure_dominant in any::<bool>(),
        artifact_miss_last in any::<bool>(),
    ) {
        let dominant = pressure_dominant.then_some(AdmissionRejectionCategory::CriticalPressure);
        let incidents = if artifact_miss_last {
            vec![IncidentChainEntry { reason_code: IncidentReasonCode::ArtifactMiss, occurred_at_unix_ms: 1 }]
        } else {
            Vec::new()
        };
        let inputs = ReadinessInputs {
            split: ReadinessSplit {
                daemon_reachable: daemon,
                desired_fleet_workers: desired,
                live_healthy_workers: healthy,
                command_admissible_workers: admissible,
            },
            proof_refused,
            dominant_rejection: dominant,
            recent_incidents: incidents,
        };
        let report = assess_readiness(&inputs);
        prop_assert!(report.invariant_holds());
        if report.remote_ready {
            prop_assert!(admissible > 0, "remote_ready with zero admissible workers");
        }
    }

    /// recommend_for_summary only ever surfaces categories that actually occurred,
    /// deduped, and each recommendation matches the per-category rule.
    #[test]
    fn recommend_for_summary_is_consistent(
        cats in proptest::collection::vec(0usize..12, 0..6),
        proof in any::<bool>(),
    ) {
        let rejections: Vec<CandidateRejection> = cats
            .iter()
            .map(|&i| CandidateRejection {
                worker_id: format!("w{i}"),
                category: AdmissionRejectionCategory::ALL[i],
            })
            .collect();
        let summary = aggregate_rejections(rejections.len(), &rejections);
        let recs = recommend_for_summary(&summary, proof);
        // No duplicate categories; each action matches recommend(); every rec's
        // category actually occurred.
        let mut seen = std::collections::BTreeSet::new();
        for rec in &recs {
            prop_assert!(seen.insert(rec.category.as_str()), "duplicate category in recommendations");
            prop_assert_eq!(rec.action, recommend(rec.category, proof));
            prop_assert!(summary.by_category.contains_key(rec.category.as_str()));
        }
        prop_assert_eq!(recs.len(), seen.len());
    }
}
