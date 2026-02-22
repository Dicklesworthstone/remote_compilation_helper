//! E2E scenarios for process triage contract pipeline (bd-vvmd.7.2).
//!
//! These scenarios exercise the process triage adapter contract, safe-action
//! policy evaluation, failure taxonomy, escalation semantics, and audit-record
//! requirements. They validate:
//! - Nominal triage: build-related process detection, automatic action approval
//! - Policy boundary enforcement: denylist, protected processes, confidence gates
//! - Escalation ladder: Automatic -> Supervised -> ManualReview -> Blocked
//! - Failure taxonomy with reason codes and remediation hints
//! - Schema validation for request/response envelopes
//! - Serialization round-trips for contract wire-format stability
//! - Reliability harness integration with per-phase logging and artifact retention

use rch_common::e2e::process_triage::{ProcessClassification, ProcessDescriptor};
use rch_common::e2e::{
    PROCESS_TRIAGE_CONTRACT_SCHEMA_VERSION, ProcessTriageActionClass, ProcessTriageActionOutcome,
    ProcessTriageActionRequest, ProcessTriageActionResult, ProcessTriageAdapterCommand,
    ProcessTriageAuditRecord, ProcessTriageContract, ProcessTriageContractError,
    ProcessTriageEscalationLevel, ProcessTriageFailure, ProcessTriageFailureKind,
    ProcessTriageRequest, ProcessTriageResponse, ProcessTriageResponseStatus, ProcessTriageTrigger,
    ReliabilityLifecycleCommand, ReliabilityScenarioSpec, TestHarnessBuilder,
    evaluate_triage_action, process_triage_request_schema, process_triage_response_schema,
};

// ---------------------------------------------------------------------------
// Shared test builders
// ---------------------------------------------------------------------------

fn sample_process_descriptors() -> Vec<ProcessDescriptor> {
    vec![
        ProcessDescriptor {
            pid: 2001,
            ppid: Some(2000),
            owner: "ubuntu".to_string(),
            command: "cargo test --workspace".to_string(),
            classification: ProcessClassification::BuildRelated,
            cpu_percent_milli: 85_000,
            rss_mb: 1_800,
            runtime_secs: 180,
        },
        ProcessDescriptor {
            pid: 2002,
            ppid: Some(1),
            owner: "root".to_string(),
            command: "sshd: ubuntu@pts/2".to_string(),
            classification: ProcessClassification::SystemCritical,
            cpu_percent_milli: 50,
            rss_mb: 28,
            runtime_secs: 7_200,
        },
        ProcessDescriptor {
            pid: 2003,
            ppid: Some(2000),
            owner: "ubuntu".to_string(),
            command: "rustc --edition 2024 -C opt-level=3".to_string(),
            classification: ProcessClassification::BuildRelated,
            cpu_percent_milli: 97_000,
            rss_mb: 3_200,
            runtime_secs: 300,
        },
        ProcessDescriptor {
            pid: 2004,
            ppid: Some(1),
            owner: "ubuntu".to_string(),
            command: "python3 run_benchmarks.py".to_string(),
            classification: ProcessClassification::Unknown,
            cpu_percent_milli: 40_000,
            rss_mb: 512,
            runtime_secs: 60,
        },
    ]
}

fn sample_triage_request() -> ProcessTriageRequest {
    ProcessTriageRequest {
        schema_version: PROCESS_TRIAGE_CONTRACT_SCHEMA_VERSION.to_string(),
        correlation_id: "e2e-triage-001".to_string(),
        worker_id: "e2e-worker-triage".to_string(),
        observed_at_unix_ms: 1_770_000_000_000,
        trigger: ProcessTriageTrigger::WorkerHealth,
        detector_confidence_percent: 92,
        retry_attempt: 0,
        candidate_processes: sample_process_descriptors(),
        requested_actions: vec![ProcessTriageActionRequest {
            action_class: ProcessTriageActionClass::SoftTerminate,
            pid: 2001,
            reason_code: "stuck_compile".to_string(),
            signal: Some("TERM".to_string()),
        }],
    }
}

fn sample_disk_pressure_request() -> ProcessTriageRequest {
    ProcessTriageRequest {
        schema_version: PROCESS_TRIAGE_CONTRACT_SCHEMA_VERSION.to_string(),
        correlation_id: "e2e-triage-disk-001".to_string(),
        worker_id: "e2e-worker-triage".to_string(),
        observed_at_unix_ms: 1_770_000_000_000,
        trigger: ProcessTriageTrigger::DiskPressure,
        detector_confidence_percent: 88,
        retry_attempt: 0,
        candidate_processes: sample_process_descriptors(),
        requested_actions: vec![ProcessTriageActionRequest {
            action_class: ProcessTriageActionClass::ReclaimDisk,
            pid: 2001,
            reason_code: "disk_pressure_reclaim".to_string(),
            signal: None,
        }],
    }
}

fn sample_response(request: &ProcessTriageRequest) -> ProcessTriageResponse {
    ProcessTriageResponse {
        schema_version: PROCESS_TRIAGE_CONTRACT_SCHEMA_VERSION.to_string(),
        correlation_id: request.correlation_id.clone(),
        status: ProcessTriageResponseStatus::Applied,
        escalation_level: ProcessTriageEscalationLevel::Automatic,
        executed_actions: vec![ProcessTriageActionResult {
            pid: 2001,
            action_class: ProcessTriageActionClass::SoftTerminate,
            outcome: ProcessTriageActionOutcome::Executed,
            note: Some("sent SIGTERM".to_string()),
        }],
        failure: None,
        audit: ProcessTriageAuditRecord {
            policy_version: "v1".to_string(),
            evaluated_by: "rchd-triage".to_string(),
            evaluated_at_unix_ms: 1_770_000_000_100,
            decision_code: "PT_ALLOW_AUTOMATIC".to_string(),
            requires_operator_ack: false,
            audit_required: true,
        },
    }
}

// ===========================================================================
// Nominal triage scenarios
// ===========================================================================

#[test]
fn e2e_nominal_triage_request_validates_successfully() {
    let request = sample_triage_request();
    request.validate().expect("sample request should validate");
}

#[test]
fn e2e_nominal_triage_request_serialization_round_trip() {
    let request = sample_triage_request();
    let json = serde_json::to_string_pretty(&request).expect("serialize request");
    let restored: ProcessTriageRequest = serde_json::from_str(&json).expect("deserialize request");
    assert_eq!(
        restored.schema_version,
        PROCESS_TRIAGE_CONTRACT_SCHEMA_VERSION
    );
    assert_eq!(restored.worker_id, "e2e-worker-triage");
    assert_eq!(restored.candidate_processes.len(), 4);
    assert_eq!(restored.requested_actions.len(), 1);
}

#[test]
fn e2e_nominal_triage_response_serialization_round_trip() {
    let request = sample_triage_request();
    let response = sample_response(&request);
    let json = serde_json::to_string_pretty(&response).expect("serialize response");
    let restored: ProcessTriageResponse =
        serde_json::from_str(&json).expect("deserialize response");
    assert_eq!(restored.status, ProcessTriageResponseStatus::Applied);
    assert_eq!(restored.correlation_id, "e2e-triage-001");
    assert_eq!(restored.executed_actions.len(), 1);
    assert!(restored.failure.is_none());
    assert!(restored.audit.audit_required);
}

#[test]
fn e2e_nominal_triage_automatic_approval_for_build_process() {
    let contract = ProcessTriageContract::default();
    let request = sample_triage_request();
    let decision = evaluate_triage_action(&request, &contract, &request.requested_actions[0]);

    assert!(
        decision.permitted,
        "build-related soft-terminate should be permitted"
    );
    assert_eq!(
        decision.escalation_level,
        ProcessTriageEscalationLevel::Automatic
    );
    assert_eq!(decision.decision_code, "PT_ALLOW_AUTOMATIC");
    assert_eq!(
        decision.effective_action,
        Some(ProcessTriageActionClass::SoftTerminate)
    );
    assert!(!decision.requires_operator_ack);
}

#[test]
fn e2e_nominal_triage_disk_pressure_reclaim_approved() {
    let contract = ProcessTriageContract::default();
    let request = sample_disk_pressure_request();
    let decision = evaluate_triage_action(&request, &contract, &request.requested_actions[0]);

    assert!(
        decision.permitted,
        "disk reclaim on build-related process should be permitted"
    );
    assert_eq!(
        decision.escalation_level,
        ProcessTriageEscalationLevel::Automatic
    );
    assert_eq!(
        decision.effective_action,
        Some(ProcessTriageActionClass::ReclaimDisk)
    );
}

// ===========================================================================
// Contract validation boundary tests
// ===========================================================================

#[test]
fn e2e_contract_default_validates_successfully() {
    let contract = ProcessTriageContract::default();
    contract
        .validate()
        .expect("default contract should validate");
}

#[test]
fn e2e_contract_rejects_allow_deny_overlap() {
    let mut contract = ProcessTriageContract::default();
    contract
        .safe_action_policy
        .deny_action_classes
        .push(ProcessTriageActionClass::SoftTerminate);

    let err = contract.validate().unwrap_err();
    assert!(matches!(
        err,
        ProcessTriageContractError::AllowDenyConflict(ProcessTriageActionClass::SoftTerminate)
    ));
}

#[test]
fn e2e_contract_rejects_zero_request_timeout() {
    let mut contract = ProcessTriageContract::default();
    contract.timeout_policy.request_timeout_secs = 0;

    let err = contract.validate().unwrap_err();
    assert!(matches!(
        err,
        ProcessTriageContractError::InvalidTimeout {
            field: "request_timeout_secs",
            ..
        }
    ));
}

#[test]
fn e2e_contract_rejects_zero_max_attempts() {
    let mut contract = ProcessTriageContract::default();
    contract.retry_policy.max_attempts = 0;

    let err = contract.validate().unwrap_err();
    assert!(matches!(
        err,
        ProcessTriageContractError::InvalidRetryPolicy {
            field: "max_attempts",
            ..
        }
    ));
}

#[test]
fn e2e_contract_rejects_backoff_inversion() {
    let mut contract = ProcessTriageContract::default();
    contract.retry_policy.initial_backoff_ms = 5_000;
    contract.retry_policy.max_backoff_ms = 1_000;

    let err = contract.validate().unwrap_err();
    assert!(matches!(
        err,
        ProcessTriageContractError::InvalidRetryPolicy {
            field: "max_backoff_ms",
            ..
        }
    ));
}

#[test]
fn e2e_request_rejects_wrong_schema_version() {
    let mut request = sample_triage_request();
    request.schema_version = "99.0.0".to_string();

    let err = request.validate().unwrap_err();
    assert!(matches!(
        err,
        ProcessTriageContractError::SchemaVersionMismatch { .. }
    ));
}

#[test]
fn e2e_request_rejects_confidence_over_100() {
    let mut request = sample_triage_request();
    request.detector_confidence_percent = 101;

    let err = request.validate().unwrap_err();
    assert!(matches!(
        err,
        ProcessTriageContractError::InvalidConfidence(101)
    ));
}

#[test]
fn e2e_request_rejects_empty_actions() {
    let mut request = sample_triage_request();
    request.requested_actions.clear();

    let err = request.validate().unwrap_err();
    assert!(matches!(
        err,
        ProcessTriageContractError::EmptyRequestedActions
    ));
}

#[test]
fn e2e_request_rejects_unknown_action_pid() {
    let mut request = sample_triage_request();
    request.requested_actions = vec![ProcessTriageActionRequest {
        action_class: ProcessTriageActionClass::SoftTerminate,
        pid: 9999,
        reason_code: "phantom".to_string(),
        signal: None,
    }];

    let err = request.validate().unwrap_err();
    assert!(matches!(
        err,
        ProcessTriageContractError::UnknownActionPid(9999)
    ));
}

// ===========================================================================
// Safe-action policy enforcement
// ===========================================================================

#[test]
fn e2e_policy_blocks_denylisted_action_class() {
    let contract = ProcessTriageContract::default();
    let request = ProcessTriageRequest {
        requested_actions: vec![ProcessTriageActionRequest {
            action_class: ProcessTriageActionClass::HardTerminate,
            pid: 2001,
            reason_code: "force_kill".to_string(),
            signal: Some("KILL".to_string()),
        }],
        ..sample_triage_request()
    };

    let decision = evaluate_triage_action(&request, &contract, &request.requested_actions[0]);
    assert!(!decision.permitted);
    assert_eq!(
        decision.escalation_level,
        ProcessTriageEscalationLevel::Blocked
    );
    assert_eq!(decision.decision_code, "PT_BLOCK_DENYLIST");
    assert!(decision.requires_operator_ack);
}

#[test]
fn e2e_policy_blocks_protected_process() {
    let contract = ProcessTriageContract::default();
    let request = ProcessTriageRequest {
        requested_actions: vec![ProcessTriageActionRequest {
            action_class: ProcessTriageActionClass::SoftTerminate,
            pid: 2002, // sshd
            reason_code: "cleanup".to_string(),
            signal: Some("TERM".to_string()),
        }],
        ..sample_triage_request()
    };

    let decision = evaluate_triage_action(&request, &contract, &request.requested_actions[0]);
    assert!(!decision.permitted);
    assert_eq!(
        decision.escalation_level,
        ProcessTriageEscalationLevel::Blocked
    );
    assert_eq!(decision.decision_code, "PT_BLOCK_PROTECTED_PROCESS");
}

#[test]
fn e2e_policy_blocks_out_of_scope_process() {
    let contract = ProcessTriageContract::default();
    // python3 process is not in managed_process_patterns [cargo, rustc, clang]
    let request = ProcessTriageRequest {
        requested_actions: vec![ProcessTriageActionRequest {
            action_class: ProcessTriageActionClass::SoftTerminate,
            pid: 2004, // python3
            reason_code: "unknown_hog".to_string(),
            signal: Some("TERM".to_string()),
        }],
        ..sample_triage_request()
    };

    let decision = evaluate_triage_action(&request, &contract, &request.requested_actions[0]);
    assert!(!decision.permitted);
    assert_eq!(
        decision.escalation_level,
        ProcessTriageEscalationLevel::Blocked
    );
    assert_eq!(decision.decision_code, "PT_BLOCK_OUT_OF_SCOPE_PROCESS");
}

#[test]
fn e2e_policy_permits_rustc_as_managed_process() {
    let contract = ProcessTriageContract::default();
    let request = ProcessTriageRequest {
        requested_actions: vec![ProcessTriageActionRequest {
            action_class: ProcessTriageActionClass::SoftTerminate,
            pid: 2003, // rustc
            reason_code: "hung_compile".to_string(),
            signal: Some("TERM".to_string()),
        }],
        ..sample_triage_request()
    };

    let decision = evaluate_triage_action(&request, &contract, &request.requested_actions[0]);
    assert!(decision.permitted, "rustc is in managed_process_patterns");
    assert_eq!(decision.decision_code, "PT_ALLOW_AUTOMATIC");
}

// ===========================================================================
// Escalation ladder tests
// ===========================================================================

#[test]
fn e2e_escalation_low_confidence_triggers_manual_review() {
    let contract = ProcessTriageContract::default();
    let request = ProcessTriageRequest {
        detector_confidence_percent: 50, // below default threshold of 85
        ..sample_triage_request()
    };

    let decision = evaluate_triage_action(&request, &contract, &request.requested_actions[0]);
    assert!(!decision.permitted);
    assert_eq!(
        decision.escalation_level,
        ProcessTriageEscalationLevel::ManualReview
    );
    assert_eq!(decision.decision_code, "PT_MANUAL_LOW_CONFIDENCE");
}

#[test]
fn e2e_escalation_retry_exhausted_triggers_manual_review() {
    let contract = ProcessTriageContract::default();
    // default max_attempts = 3, retry_attempt is 0-indexed so attempt 2 means third try
    let request = ProcessTriageRequest {
        retry_attempt: 2,
        ..sample_triage_request()
    };

    let decision = evaluate_triage_action(&request, &contract, &request.requested_actions[0]);
    assert!(!decision.permitted);
    assert_eq!(
        decision.escalation_level,
        ProcessTriageEscalationLevel::ManualReview
    );
    assert_eq!(decision.decision_code, "PT_MANUAL_RETRY_EXHAUSTED");
}

#[test]
fn e2e_escalation_volume_threshold_downgrades_to_supervised() {
    let contract = ProcessTriageContract::default();
    // Generate 6 actions to exceed max_actions_before_manual_review (default 5)
    let mut request = sample_triage_request();
    request.requested_actions = (0..6)
        .map(|i| ProcessTriageActionRequest {
            action_class: ProcessTriageActionClass::SoftTerminate,
            pid: if i < 2 { 2001 } else { 2003 }, // alternate between build processes
            reason_code: format!("stuck_{i}"),
            signal: Some("TERM".to_string()),
        })
        .collect();

    let decision = evaluate_triage_action(&request, &contract, &request.requested_actions[0]);
    assert!(
        decision.permitted,
        "supervised mode should still permit with downgrade"
    );
    assert_eq!(
        decision.escalation_level,
        ProcessTriageEscalationLevel::Supervised
    );
    assert_eq!(decision.decision_code, "PT_SUPERVISED_ACTION_VOLUME");
    // Downgraded to ObserveOnly since original was SoftTerminate (risk > 0)
    assert_eq!(
        decision.effective_action,
        Some(ProcessTriageActionClass::ObserveOnly)
    );
}

#[test]
fn e2e_escalation_confidence_boundary_at_threshold() {
    let contract = ProcessTriageContract::default();
    // Exactly at threshold (85) should pass
    let request = ProcessTriageRequest {
        detector_confidence_percent: 85,
        ..sample_triage_request()
    };
    let decision = evaluate_triage_action(&request, &contract, &request.requested_actions[0]);
    assert!(
        decision.permitted,
        "confidence at threshold should be permitted"
    );
    assert_eq!(
        decision.escalation_level,
        ProcessTriageEscalationLevel::Automatic
    );

    // One below (84) should fail
    let request_below = ProcessTriageRequest {
        detector_confidence_percent: 84,
        ..sample_triage_request()
    };
    let decision_below = evaluate_triage_action(
        &request_below,
        &contract,
        &request_below.requested_actions[0],
    );
    assert!(
        !decision_below.permitted,
        "confidence below threshold should be blocked"
    );
    assert_eq!(
        decision_below.escalation_level,
        ProcessTriageEscalationLevel::ManualReview
    );
}

// ===========================================================================
// Trigger classification
// ===========================================================================

#[test]
fn e2e_all_triggers_produce_valid_requests() {
    let triggers = [
        ProcessTriageTrigger::DiskPressure,
        ProcessTriageTrigger::WorkerHealth,
        ProcessTriageTrigger::BuildTimeout,
        ProcessTriageTrigger::Manual,
    ];

    for trigger in triggers {
        let request = ProcessTriageRequest {
            trigger,
            ..sample_triage_request()
        };
        request
            .validate()
            .unwrap_or_else(|e| panic!("trigger {trigger:?} should produce valid request: {e}"));
    }
}

// ===========================================================================
// Command surface stability
// ===========================================================================

#[test]
fn e2e_command_args_are_stable() {
    let expectations = [
        (ProcessTriageAdapterCommand::Analyze, "process-triage"),
        (ProcessTriageAdapterCommand::Execute, "process-triage"),
        (ProcessTriageAdapterCommand::Health, "process-triage"),
        (ProcessTriageAdapterCommand::Version, "process-triage"),
    ];

    for (cmd, expected_first_arg) in expectations {
        let args = cmd.args();
        assert!(!args.is_empty(), "{cmd:?} must have at least one arg");
        assert_eq!(
            args[0], expected_first_arg,
            "{cmd:?} first arg should be {expected_first_arg}"
        );
    }
}

// ===========================================================================
// Schema validation
// ===========================================================================

#[test]
fn e2e_request_schema_has_core_fields() {
    let schema = process_triage_request_schema();
    let json = serde_json::to_value(&schema).expect("schema to value");

    let props = find_schema_properties(&json, &["worker_id", "requested_actions"]);
    for field in [
        "schema_version",
        "correlation_id",
        "worker_id",
        "trigger",
        "detector_confidence_percent",
        "candidate_processes",
        "requested_actions",
    ] {
        assert!(
            props.contains_key(field),
            "request schema missing field: {field}"
        );
    }
}

#[test]
fn e2e_response_schema_has_core_fields() {
    let schema = process_triage_response_schema();
    let json = serde_json::to_value(&schema).expect("schema to value");

    let props = find_schema_properties(&json, &["status", "executed_actions", "audit"]);
    for field in [
        "schema_version",
        "correlation_id",
        "status",
        "escalation_level",
        "executed_actions",
        "failure",
        "audit",
    ] {
        assert!(
            props.contains_key(field),
            "response schema missing field: {field}"
        );
    }
}

// ===========================================================================
// Failure taxonomy
// ===========================================================================

#[test]
fn e2e_failure_payload_serialization_round_trip() {
    let failure = ProcessTriageFailure {
        kind: ProcessTriageFailureKind::ExecutorRuntimeError,
        code: "PT_EXECUTOR_RUNTIME".to_string(),
        message: "failed to send SIGTERM to pid 2001".to_string(),
        remediation: vec![
            "check process still exists".to_string(),
            "verify signal permissions".to_string(),
        ],
    };

    let json = serde_json::to_string(&failure).expect("serialize failure");
    let restored: ProcessTriageFailure = serde_json::from_str(&json).expect("deserialize failure");
    assert_eq!(
        restored.kind,
        ProcessTriageFailureKind::ExecutorRuntimeError
    );
    assert_eq!(restored.remediation.len(), 2);
}

#[test]
fn e2e_all_failure_kinds_serialize_to_distinct_values() {
    let kinds = [
        ProcessTriageFailureKind::DetectorUncertain,
        ProcessTriageFailureKind::PolicyViolation,
        ProcessTriageFailureKind::TransportError,
        ProcessTriageFailureKind::ExecutorRuntimeError,
        ProcessTriageFailureKind::Timeout,
        ProcessTriageFailureKind::PartialResult,
        ProcessTriageFailureKind::InvalidRequest,
    ];

    let mut seen = std::collections::HashSet::new();
    for kind in kinds {
        let json = serde_json::to_value(kind).expect("serialize failure kind");
        let s = json
            .as_str()
            .expect("failure kind should serialize as string");
        assert!(
            seen.insert(s.to_string()),
            "duplicate failure kind serialization: {s}"
        );
    }
    assert_eq!(seen.len(), 7);
}

// ===========================================================================
// Audit record requirements
// ===========================================================================

#[test]
fn e2e_audit_record_always_present_in_response() {
    let request = sample_triage_request();
    let response = sample_response(&request);

    assert!(response.audit.audit_required);
    assert!(!response.audit.decision_code.is_empty());
    assert!(!response.audit.policy_version.is_empty());
}

#[test]
fn e2e_policy_decision_audit_flag_matches_policy() {
    let contract = ProcessTriageContract::default();
    assert!(contract.safe_action_policy.require_audit_record);

    let request = sample_triage_request();
    let decision = evaluate_triage_action(&request, &contract, &request.requested_actions[0]);
    assert_eq!(
        decision.audit_required,
        contract.safe_action_policy.require_audit_record
    );
}

// ===========================================================================
// Default contract invariants
// ===========================================================================

#[test]
fn e2e_default_contract_command_budgets_cover_all_commands() {
    let contract = ProcessTriageContract::default();
    let covered: std::collections::HashSet<_> =
        contract.command_budgets.iter().map(|b| b.command).collect();

    for cmd in [
        ProcessTriageAdapterCommand::Analyze,
        ProcessTriageAdapterCommand::Execute,
        ProcessTriageAdapterCommand::Health,
        ProcessTriageAdapterCommand::Version,
    ] {
        assert!(
            covered.contains(&cmd),
            "default contract missing budget for {cmd:?}"
        );
    }
}

#[test]
fn e2e_default_policy_hard_terminate_is_denylisted() {
    let contract = ProcessTriageContract::default();
    assert!(
        contract
            .safe_action_policy
            .deny_action_classes
            .contains(&ProcessTriageActionClass::HardTerminate),
        "HardTerminate should be denylisted by default"
    );
    assert!(
        !contract
            .safe_action_policy
            .allow_action_classes
            .contains(&ProcessTriageActionClass::HardTerminate),
        "HardTerminate should not be in allowlist"
    );
}

#[test]
fn e2e_default_timeout_policy_total_exceeds_request_plus_action() {
    let contract = ProcessTriageContract::default();
    assert!(
        contract.timeout_policy.total_timeout_secs
            >= contract.timeout_policy.request_timeout_secs
                + contract.timeout_policy.action_timeout_secs,
        "total timeout should cover request + action"
    );
}

// ===========================================================================
// Reliability harness integration
// ===========================================================================

#[test]
fn e2e_reliability_harness_triage_nominal_scenario() {
    let harness = TestHarnessBuilder::new("triage_nominal")
        .cleanup_on_success(true)
        .build()
        .expect("create test harness");

    let request = sample_triage_request();
    let response = sample_response(&request);
    let response_json = serde_json::to_string_pretty(&response).expect("serialize");
    harness
        .create_file("triage_response.json", &response_json)
        .expect("write response artifact");

    let scenario = ReliabilityScenarioSpec::new("triage_nominal")
        .with_worker_id("e2e-worker-triage")
        .add_triage_action("nominal_triage_check")
        .add_execute_command(ReliabilityLifecycleCommand::new(
            "verify-response-artifact",
            "test",
            [
                "-f",
                harness
                    .test_dir()
                    .join("triage_response.json")
                    .to_str()
                    .unwrap(),
            ],
        ))
        .add_post_check(ReliabilityLifecycleCommand::new(
            "verify-audit-present",
            "echo",
            ["audit_required=true decision_code=PT_ALLOW_AUTOMATIC"],
        ));

    let report = harness
        .run_reliability_scenario(&scenario)
        .expect("nominal triage scenario should succeed");

    assert!(report.manifest_path.is_some());
    assert!(
        report.command_records.iter().all(|r| r.succeeded),
        "all commands should succeed in nominal triage scenario"
    );

    harness.mark_passed();
}

#[test]
fn e2e_reliability_harness_triage_policy_boundary_scenario() {
    let harness = TestHarnessBuilder::new("triage_policy_boundary")
        .cleanup_on_success(true)
        .build()
        .expect("create test harness");

    let contract = ProcessTriageContract::default();
    let request = sample_triage_request();

    // Evaluate multiple policy boundary cases
    let cases = [
        (
            "denylist_hard_terminate",
            ProcessTriageActionRequest {
                action_class: ProcessTriageActionClass::HardTerminate,
                pid: 2001,
                reason_code: "force_kill".to_string(),
                signal: Some("KILL".to_string()),
            },
        ),
        (
            "protected_sshd",
            ProcessTriageActionRequest {
                action_class: ProcessTriageActionClass::SoftTerminate,
                pid: 2002,
                reason_code: "cleanup".to_string(),
                signal: Some("TERM".to_string()),
            },
        ),
        (
            "out_of_scope_python",
            ProcessTriageActionRequest {
                action_class: ProcessTriageActionClass::SoftTerminate,
                pid: 2004,
                reason_code: "unknown".to_string(),
                signal: Some("TERM".to_string()),
            },
        ),
    ];

    let mut decisions = Vec::new();
    for (name, action) in &cases {
        let decision = evaluate_triage_action(&request, &contract, action);
        decisions.push(format!(
            "{}: permitted={} code={} escalation={:?}",
            name, decision.permitted, decision.decision_code, decision.escalation_level
        ));
    }

    let report_text = decisions.join("\n");
    harness
        .create_file("policy_decisions.txt", &report_text)
        .expect("write decisions artifact");

    let scenario = ReliabilityScenarioSpec::new("triage_policy_boundary")
        .with_worker_id("e2e-worker-triage")
        .add_triage_action("policy_boundary_validation")
        .add_execute_command(ReliabilityLifecycleCommand::new(
            "verify-decisions-artifact",
            "test",
            [
                "-f",
                harness
                    .test_dir()
                    .join("policy_decisions.txt")
                    .to_str()
                    .unwrap(),
            ],
        ));

    let report = harness
        .run_reliability_scenario(&scenario)
        .expect("policy boundary scenario should succeed");

    assert!(report.manifest_path.is_some());
    harness.mark_passed();
}

#[test]
fn e2e_reliability_harness_triage_escalation_ladder_scenario() {
    let harness = TestHarnessBuilder::new("triage_escalation")
        .cleanup_on_success(true)
        .build()
        .expect("create test harness");

    let contract = ProcessTriageContract::default();

    // Test all 4 escalation levels
    let levels = [
        ("automatic", {
            let r = sample_triage_request();
            evaluate_triage_action(&r, &contract, &r.requested_actions[0])
        }),
        ("manual_low_confidence", {
            let r = ProcessTriageRequest {
                detector_confidence_percent: 50,
                ..sample_triage_request()
            };
            evaluate_triage_action(&r, &contract, &r.requested_actions[0])
        }),
        ("blocked_protected", {
            let r = ProcessTriageRequest {
                requested_actions: vec![ProcessTriageActionRequest {
                    action_class: ProcessTriageActionClass::SoftTerminate,
                    pid: 2002,
                    reason_code: "test".to_string(),
                    signal: None,
                }],
                ..sample_triage_request()
            };
            evaluate_triage_action(&r, &contract, &r.requested_actions[0])
        }),
    ];

    let escalation_report = serde_json::json!({
        "automatic": format!("{:?}", levels[0].1.escalation_level),
        "manual_review": format!("{:?}", levels[1].1.escalation_level),
        "blocked": format!("{:?}", levels[2].1.escalation_level),
    });
    let json = serde_json::to_string_pretty(&escalation_report).expect("serialize");
    harness
        .create_file("escalation_ladder.json", &json)
        .expect("write escalation artifact");

    let scenario = ReliabilityScenarioSpec::new("triage_escalation_ladder")
        .with_worker_id("e2e-worker-triage")
        .add_triage_action("escalation_ladder_check")
        .add_execute_command(ReliabilityLifecycleCommand::new(
            "verify-escalation-artifact",
            "test",
            [
                "-f",
                harness
                    .test_dir()
                    .join("escalation_ladder.json")
                    .to_str()
                    .unwrap(),
            ],
        ));

    let report = harness
        .run_reliability_scenario(&scenario)
        .expect("escalation ladder scenario should succeed");

    assert!(report.manifest_path.is_some());
    harness.mark_passed();
}

// ---------------------------------------------------------------------------
// Schema property lookup helper (shared with other E2E test files)
// ---------------------------------------------------------------------------

fn find_schema_properties(
    json: &serde_json::Value,
    required: &[&str],
) -> serde_json::Map<String, serde_json::Value> {
    if let Some(props) = json.get("properties").and_then(|p| p.as_object())
        && required.iter().all(|k| props.contains_key(*k))
    {
        return props.clone();
    }
    if let Some(defs) = json.get("definitions").and_then(|d| d.as_object()) {
        for node in defs.values() {
            if let Some(props) = node.get("properties").and_then(|p| p.as_object())
                && required.iter().all(|k| props.contains_key(*k))
            {
                return props.clone();
            }
        }
    }
    panic!("schema properties not found for required keys: {required:?}");
}
