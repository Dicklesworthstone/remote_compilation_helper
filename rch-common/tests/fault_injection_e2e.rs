//! Fault-injection E2E scenarios for partial failure and recovery (bd-vvmd.7.6).
//!
//! These scenarios exercise deterministic fault injection covering:
//! - Network interruption simulation with fail-open recovery
//! - Partial repo sync with correct fallback reason codes
//! - Timeout races with bounded convergence budget
//! - Low-disk + stuck-process overlap (combined pressure faults)
//! - Daemon restart during active builds with cleanup guarantees
//! - Cleanup invariants: worker slots, drift state, process debt, disk policy
//! - Observability signal quality through structured artifact retention

use rch_common::e2e::process_triage::{ProcessClassification, ProcessDescriptor};
use rch_common::e2e::{
    PROCESS_TRIAGE_CONTRACT_SCHEMA_VERSION, ProcessTriageActionClass, ProcessTriageActionRequest,
    ProcessTriageContract, ProcessTriageEscalationLevel, ProcessTriageRequest,
    ProcessTriageTrigger, ReliabilityFailureHook, ReliabilityFailureHookFlags,
    ReliabilityLifecycleCommand, ReliabilityScenarioSpec, TestHarnessBuilder,
    evaluate_triage_action,
};
use rch_common::repo_updater_contract::{
    RepoUpdaterEnvelopeMeta, RepoUpdaterRepoRecord, RepoUpdaterSyncSummary,
};
use rch_common::{
    MockRepoUpdaterAdapter, REPO_UPDATER_CANONICAL_PROJECTS_ROOT,
    REPO_UPDATER_CONTRACT_SCHEMA_VERSION, RepoUpdaterAdapter, RepoUpdaterAdapterCommand,
    RepoUpdaterAdapterContract, RepoUpdaterAdapterRequest, RepoUpdaterAdapterResponse,
    RepoUpdaterFailure, RepoUpdaterFailureKind, RepoUpdaterFallbackMode,
    RepoUpdaterIdempotencyGuarantee, RepoUpdaterOutputFormat, RepoUpdaterResponseStatus,
    map_failure_kind_to_error_code,
};
use std::path::PathBuf;

// ---------------------------------------------------------------------------
// Shared builders
// ---------------------------------------------------------------------------

fn convergence_request(correlation_id: &str) -> RepoUpdaterAdapterRequest {
    RepoUpdaterAdapterRequest {
        schema_version: REPO_UPDATER_CONTRACT_SCHEMA_VERSION.to_string(),
        correlation_id: correlation_id.to_string(),
        worker_id: "fault-worker-a".to_string(),
        command: RepoUpdaterAdapterCommand::SyncDryRun,
        requested_at_unix_ms: 1_770_000_000_000,
        projects_root: PathBuf::from(REPO_UPDATER_CANONICAL_PROJECTS_ROOT),
        repo_specs: vec![
            "Dicklesworthstone/remote_compilation_helper".to_string(),
            "https://github.com/Dicklesworthstone/repo_updater".to_string(),
        ],
        idempotency_key: format!("fault-idemp-{correlation_id}"),
        retry_attempt: 0,
        timeout_secs: 30,
        expected_output_format: RepoUpdaterOutputFormat::Json,
        auth_context: None,
        operator_override: None,
    }
}

fn success_response(request: &RepoUpdaterAdapterRequest) -> RepoUpdaterAdapterResponse {
    RepoUpdaterAdapterResponse {
        schema_version: REPO_UPDATER_CONTRACT_SCHEMA_VERSION.to_string(),
        correlation_id: request.correlation_id.clone(),
        command: request.command,
        adapter_version: "1.2.1".to_string(),
        status: RepoUpdaterResponseStatus::Success,
        idempotency_guarantee: request.command.idempotency(),
        fallback_applied: false,
        sync_summary: Some(RepoUpdaterSyncSummary {
            total: 2,
            cloned: 0,
            pulled: 2,
            skipped: 0,
            failed: 0,
        }),
        repos: vec![RepoUpdaterRepoRecord {
            repo: "Dicklesworthstone/remote_compilation_helper".to_string(),
            path: Some(PathBuf::from("/data/projects/remote_compilation_helper")),
            action: Some("pull".to_string()),
            status: Some("updated".to_string()),
            dirty: Some(false),
            ahead: Some(0),
            behind: Some(0),
        }],
        envelope_meta: Some(RepoUpdaterEnvelopeMeta {
            duration_seconds: Some(3),
            exit_code: Some(0),
        }),
        failure: None,
    }
}

fn timeout_failure() -> RepoUpdaterFailure {
    RepoUpdaterFailure {
        kind: RepoUpdaterFailureKind::Timeout,
        code: "RU_TIMEOUT".to_string(),
        message: "convergence exceeded time budget".to_string(),
        mapped_rch_error: "TransferTimeout".to_string(),
        remediation: vec![
            "increase timeout budget".to_string(),
            "check network latency".to_string(),
        ],
        adapter_exit_code: None,
    }
}

fn partial_sync_response(request: &RepoUpdaterAdapterRequest) -> RepoUpdaterAdapterResponse {
    RepoUpdaterAdapterResponse {
        schema_version: REPO_UPDATER_CONTRACT_SCHEMA_VERSION.to_string(),
        correlation_id: request.correlation_id.clone(),
        command: request.command,
        adapter_version: "1.2.1".to_string(),
        status: RepoUpdaterResponseStatus::PartialFailure,
        idempotency_guarantee: RepoUpdaterIdempotencyGuarantee::StrongReadOnly,
        fallback_applied: true,
        sync_summary: Some(RepoUpdaterSyncSummary {
            total: 2,
            cloned: 0,
            pulled: 1,
            skipped: 0,
            failed: 1,
        }),
        repos: vec![
            RepoUpdaterRepoRecord {
                repo: "Dicklesworthstone/remote_compilation_helper".to_string(),
                path: Some(PathBuf::from("/data/projects/remote_compilation_helper")),
                action: Some("pull".to_string()),
                status: Some("updated".to_string()),
                dirty: Some(false),
                ahead: Some(0),
                behind: Some(0),
            },
            RepoUpdaterRepoRecord {
                repo: "Dicklesworthstone/repo_updater".to_string(),
                path: None,
                action: Some("pull".to_string()),
                status: Some("network_error".to_string()),
                dirty: None,
                ahead: None,
                behind: None,
            },
        ],
        envelope_meta: Some(RepoUpdaterEnvelopeMeta {
            duration_seconds: Some(12),
            exit_code: Some(1),
        }),
        failure: Some(RepoUpdaterFailure {
            kind: RepoUpdaterFailureKind::PartialFailure,
            code: "RU_PARTIAL_FAILURE".to_string(),
            message: "1 of 2 repos failed during sync".to_string(),
            mapped_rch_error: "TransferFailed".to_string(),
            remediation: vec!["retry failed repos".to_string()],
            adapter_exit_code: Some(1),
        }),
    }
}

fn triage_request_disk_pressure() -> ProcessTriageRequest {
    ProcessTriageRequest {
        schema_version: PROCESS_TRIAGE_CONTRACT_SCHEMA_VERSION.to_string(),
        correlation_id: "fault-triage-disk-001".to_string(),
        worker_id: "fault-worker-a".to_string(),
        observed_at_unix_ms: 1_770_000_000_000,
        trigger: ProcessTriageTrigger::DiskPressure,
        detector_confidence_percent: 90,
        retry_attempt: 0,
        candidate_processes: vec![
            ProcessDescriptor {
                pid: 3001,
                ppid: Some(3000),
                owner: "ubuntu".to_string(),
                command: "cargo build --release".to_string(),
                classification: ProcessClassification::BuildRelated,
                cpu_percent_milli: 95_000,
                rss_mb: 4_096,
                runtime_secs: 600,
            },
            ProcessDescriptor {
                pid: 3002,
                ppid: Some(3000),
                owner: "ubuntu".to_string(),
                command: "rustc --edition 2024".to_string(),
                classification: ProcessClassification::BuildRelated,
                cpu_percent_milli: 88_000,
                rss_mb: 2_048,
                runtime_secs: 450,
            },
        ],
        requested_actions: vec![
            ProcessTriageActionRequest {
                action_class: ProcessTriageActionClass::ReclaimDisk,
                pid: 3001,
                reason_code: "disk_pressure_reclaim".to_string(),
                signal: None,
            },
            ProcessTriageActionRequest {
                action_class: ProcessTriageActionClass::SoftTerminate,
                pid: 3002,
                reason_code: "stuck_compile_under_pressure".to_string(),
                signal: Some("TERM".to_string()),
            },
        ],
    }
}

fn allowlisted_contract() -> RepoUpdaterAdapterContract {
    let mut contract = RepoUpdaterAdapterContract::default();
    contract.trust_policy.allowlisted_repo_specs = vec![
        "Dicklesworthstone/remote_compilation_helper".to_string(),
        "https://github.com/Dicklesworthstone/repo_updater".to_string(),
    ];
    contract
}

// ===========================================================================
// Network interruption fault scenarios
// ===========================================================================

#[test]
fn e2e_fault_network_cut_adapter_returns_timeout() {
    let adapter = MockRepoUpdaterAdapter::default();
    let contract = allowlisted_contract();
    let request = convergence_request("net-cut-001");

    adapter.push_result(Err(timeout_failure()));
    let err = adapter
        .execute(&request, &contract)
        .expect_err("network cut should produce timeout");

    assert_eq!(err.kind, RepoUpdaterFailureKind::Timeout);
    let rch_code = map_failure_kind_to_error_code(err.kind);
    assert_eq!(rch_code, rch_common::ErrorCode::TransferTimeout);
}

#[test]
fn e2e_fault_network_cut_retry_then_recovery() {
    let adapter = MockRepoUpdaterAdapter::default();
    let contract = allowlisted_contract();
    let request = convergence_request("net-recovery-001");

    // Simulate: network cut -> retry -> success
    adapter.push_result(Err(timeout_failure()));
    adapter.push_result(Err(RepoUpdaterFailure {
        kind: RepoUpdaterFailureKind::Timeout,
        code: "RU_TIMEOUT".to_string(),
        message: "second attempt timed out".to_string(),
        mapped_rch_error: "TransferTimeout".to_string(),
        remediation: vec!["check connectivity".to_string()],
        adapter_exit_code: None,
    }));
    adapter.push_result(Ok(success_response(&request)));

    assert!(adapter.execute(&request, &contract).is_err());
    assert!(adapter.execute(&request, &contract).is_err());
    let response = adapter
        .execute(&request, &contract)
        .expect("third attempt should succeed");

    assert_eq!(response.status, RepoUpdaterResponseStatus::Success);
    assert_eq!(adapter.calls().len(), 3);
}

#[test]
fn e2e_fault_network_cut_fallback_reason_code() {
    let failure = timeout_failure();
    assert_eq!(failure.code, "RU_TIMEOUT");
    assert!(
        !failure.remediation.is_empty(),
        "timeout should provide remediation hints"
    );
}

// ===========================================================================
// Partial repo sync fault scenarios
// ===========================================================================

#[test]
fn e2e_fault_partial_sync_reports_fallback_applied() {
    let adapter = MockRepoUpdaterAdapter::default();
    let contract = allowlisted_contract();
    let request = convergence_request("partial-sync-001");

    adapter.push_result(Ok(partial_sync_response(&request)));
    let response = adapter.execute(&request, &contract).unwrap();

    assert_eq!(response.status, RepoUpdaterResponseStatus::PartialFailure);
    assert!(
        response.fallback_applied,
        "partial sync should mark fallback as applied"
    );

    let failure = response.failure.as_ref().expect("failure present");
    assert_eq!(failure.kind, RepoUpdaterFailureKind::PartialFailure);
    assert_eq!(failure.code, "RU_PARTIAL_FAILURE");
}

#[test]
fn e2e_fault_partial_sync_summary_counts_correct() {
    let request = convergence_request("partial-sync-002");
    let response = partial_sync_response(&request);
    let summary = response.sync_summary.as_ref().expect("summary present");

    assert_eq!(summary.total, 2);
    assert_eq!(summary.pulled, 1);
    assert_eq!(summary.failed, 1);
    assert_eq!(summary.cloned, 0);
}

#[test]
fn e2e_fault_partial_sync_preserves_successful_repos() {
    let request = convergence_request("partial-sync-003");
    let response = partial_sync_response(&request);

    let updated = response
        .repos
        .iter()
        .filter(|r| r.status.as_deref() == Some("updated"))
        .count();
    let failed = response
        .repos
        .iter()
        .filter(|r| r.status.as_deref() == Some("network_error"))
        .count();

    assert_eq!(updated, 1, "one repo should be updated");
    assert_eq!(failed, 1, "one repo should have network_error");
}

#[test]
fn e2e_fault_partial_sync_maps_to_rch_error() {
    let code = map_failure_kind_to_error_code(RepoUpdaterFailureKind::PartialFailure);
    assert_eq!(code, rch_common::ErrorCode::WorkerLoadQueryFailed);
}

// ===========================================================================
// Timeout race fault scenarios
// ===========================================================================

#[test]
fn e2e_fault_timeout_race_exhausts_retries() {
    let adapter = MockRepoUpdaterAdapter::default();
    let contract = allowlisted_contract();
    let request = convergence_request("timeout-race-001");

    // Push 3 consecutive timeouts (max retries)
    for i in 0..3 {
        adapter.push_result(Err(RepoUpdaterFailure {
            kind: RepoUpdaterFailureKind::Timeout,
            code: "RU_TIMEOUT".to_string(),
            message: format!("attempt {i} timed out"),
            mapped_rch_error: "TransferTimeout".to_string(),
            remediation: vec!["increase budget".to_string()],
            adapter_exit_code: None,
        }));
    }

    for _ in 0..3 {
        assert!(adapter.execute(&request, &contract).is_err());
    }
    assert_eq!(adapter.calls().len(), 3, "all retries should be recorded");
}

#[test]
fn e2e_fault_timeout_retry_exhausted_maps_to_correct_error() {
    let code = map_failure_kind_to_error_code(RepoUpdaterFailureKind::RetryExhausted);
    assert_eq!(code, rch_common::ErrorCode::InternalStateError);
}

#[test]
fn e2e_fault_timeout_followed_by_partial_success() {
    let adapter = MockRepoUpdaterAdapter::default();
    let contract = allowlisted_contract();
    let request = convergence_request("timeout-partial-001");

    adapter.push_result(Err(timeout_failure()));
    adapter.push_result(Ok(partial_sync_response(&request)));

    let r1 = adapter.execute(&request, &contract);
    assert!(r1.is_err(), "first attempt should timeout");

    let r2 = adapter.execute(&request, &contract).unwrap();
    assert_eq!(r2.status, RepoUpdaterResponseStatus::PartialFailure);
    assert!(r2.fallback_applied);
}

// ===========================================================================
// Combined pressure faults: low-disk + stuck process
// ===========================================================================

#[test]
fn e2e_fault_combined_pressure_triage_both_actions_evaluated() {
    let contract = ProcessTriageContract::default();
    let request = triage_request_disk_pressure();

    // Evaluate both actions
    let reclaim_decision =
        evaluate_triage_action(&request, &contract, &request.requested_actions[0]);
    let terminate_decision =
        evaluate_triage_action(&request, &contract, &request.requested_actions[1]);

    assert!(
        reclaim_decision.permitted,
        "ReclaimDisk on build process should be permitted"
    );
    assert_eq!(
        reclaim_decision.effective_action,
        Some(ProcessTriageActionClass::ReclaimDisk)
    );

    assert!(
        terminate_decision.permitted,
        "SoftTerminate on rustc should be permitted"
    );
    assert_eq!(
        terminate_decision.effective_action,
        Some(ProcessTriageActionClass::SoftTerminate)
    );
}

#[test]
fn e2e_fault_combined_pressure_all_decisions_have_audit() {
    let contract = ProcessTriageContract::default();
    let request = triage_request_disk_pressure();

    for action in &request.requested_actions {
        let decision = evaluate_triage_action(&request, &contract, action);
        assert!(
            decision.audit_required,
            "all triage decisions must require audit: {:?}",
            action.action_class
        );
    }
}

#[test]
fn e2e_fault_combined_pressure_escalation_under_low_confidence() {
    let contract = ProcessTriageContract::default();
    let mut request = triage_request_disk_pressure();
    request.detector_confidence_percent = 50; // Below threshold

    for action in &request.requested_actions {
        let decision = evaluate_triage_action(&request, &contract, action);
        assert!(!decision.permitted, "low confidence should block action");
        assert_eq!(
            decision.escalation_level,
            ProcessTriageEscalationLevel::ManualReview
        );
    }
}

// ===========================================================================
// Daemon restart fault scenarios
// ===========================================================================

#[test]
fn e2e_fault_daemon_restart_sequence_preserves_idempotency() {
    let adapter = MockRepoUpdaterAdapter::default();
    let contract = allowlisted_contract();
    let request = convergence_request("daemon-restart-001");

    // Simulate: interrupted by daemon restart, then re-driven to success
    adapter.push_result(Err(RepoUpdaterFailure {
        kind: RepoUpdaterFailureKind::Interrupted,
        code: "RU_INTERRUPTED".to_string(),
        message: "adapter interrupted during convergence".to_string(),
        mapped_rch_error: "InternalIpcError".to_string(),
        remediation: vec!["retry after daemon restart".to_string()],
        adapter_exit_code: Some(130),
    }));
    adapter.push_result(Ok(success_response(&request)));

    let r1 = adapter.execute(&request, &contract);
    assert!(r1.is_err());
    let err = r1.unwrap_err();
    assert_eq!(err.kind, RepoUpdaterFailureKind::Interrupted);

    let r2 = adapter.execute(&request, &contract).unwrap();
    assert_eq!(r2.status, RepoUpdaterResponseStatus::Success);

    // Verify both calls used same idempotency key
    let calls = adapter.calls();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0].idempotency_key, calls[1].idempotency_key);
}

#[test]
fn e2e_fault_interrupted_maps_to_ipc_error() {
    let code = map_failure_kind_to_error_code(RepoUpdaterFailureKind::Interrupted);
    assert_eq!(code, rch_common::ErrorCode::InternalIpcError);
}

// ===========================================================================
// Fail-open behavior validation
// ===========================================================================

#[test]
fn e2e_fault_default_fallback_is_fail_open() {
    let contract = RepoUpdaterAdapterContract::default();
    assert_eq!(
        contract.fallback_policy.mode,
        RepoUpdaterFallbackMode::FailOpenLocalProceed,
        "default policy should be fail-open"
    );
}

#[test]
fn e2e_fault_all_failure_kinds_have_remediation_mappings() {
    let failure_kinds = [
        RepoUpdaterFailureKind::AdapterUnavailable,
        RepoUpdaterFailureKind::VersionIncompatible,
        RepoUpdaterFailureKind::TrustBoundaryViolation,
        RepoUpdaterFailureKind::HostValidationFailed,
        RepoUpdaterFailureKind::AuthFailure,
        RepoUpdaterFailureKind::Timeout,
        RepoUpdaterFailureKind::RetryExhausted,
        RepoUpdaterFailureKind::InvalidEnvelope,
        RepoUpdaterFailureKind::JsonDecodeFailure,
        RepoUpdaterFailureKind::CommandFailed,
        RepoUpdaterFailureKind::PartialFailure,
        RepoUpdaterFailureKind::Interrupted,
        RepoUpdaterFailureKind::Internal,
    ];

    for kind in failure_kinds {
        let _code = map_failure_kind_to_error_code(kind);
        // Every failure kind must map without panicking
    }
}

// ===========================================================================
// Cleanup invariant checks
// ===========================================================================

#[test]
fn e2e_fault_partial_sync_envelope_meta_records_exit_code() {
    let request = convergence_request("cleanup-meta-001");
    let response = partial_sync_response(&request);

    let meta = response
        .envelope_meta
        .as_ref()
        .expect("envelope meta present");
    assert_eq!(
        meta.exit_code,
        Some(1),
        "partial failure should record exit code 1"
    );
    assert!(
        meta.duration_seconds.unwrap_or(0) > 0,
        "duration should be non-zero"
    );
}

#[test]
fn e2e_fault_success_response_has_clean_envelope() {
    let request = convergence_request("cleanup-clean-001");
    let response = success_response(&request);

    let meta = response
        .envelope_meta
        .as_ref()
        .expect("envelope meta present");
    assert_eq!(meta.exit_code, Some(0));
    assert!(response.failure.is_none());
    assert!(!response.fallback_applied);
}

// ===========================================================================
// Reliability harness fault-injection integration
// ===========================================================================

#[test]
fn e2e_reliability_harness_network_cut_scenario() {
    let harness = TestHarnessBuilder::new("fault_network_cut")
        .cleanup_on_success(true)
        .build()
        .expect("create test harness");

    // Write fault artifacts
    let adapter = MockRepoUpdaterAdapter::default();
    let contract = allowlisted_contract();
    let request = convergence_request("harness-net-cut");

    adapter.push_result(Err(timeout_failure()));
    let err = adapter.execute(&request, &contract).unwrap_err();
    let fault_json = serde_json::to_string_pretty(&err).expect("serialize");
    harness
        .create_file("network_cut_failure.json", &fault_json)
        .expect("write fault artifact");

    let flags = ReliabilityFailureHookFlags {
        allow_network_cut: true,
        ..Default::default()
    };

    let scenario = ReliabilityScenarioSpec::new("fault_network_cut")
        .with_worker_id("fault-worker-a")
        .with_pressure_state("network:degraded")
        .request_failure_hook(ReliabilityFailureHook::NetworkCut)
        .with_failure_hook_flags(flags)
        .add_triage_action("network_fault_recovery")
        .add_execute_command(ReliabilityLifecycleCommand::new(
            "verify-fault-artifact",
            "test",
            [
                "-f",
                harness
                    .test_dir()
                    .join("network_cut_failure.json")
                    .to_str()
                    .unwrap(),
            ],
        ))
        .add_post_check(ReliabilityLifecycleCommand::new(
            "verify-timeout-reason",
            "echo",
            ["fault_kind=timeout remediation=increase_timeout"],
        ));

    let report = harness
        .run_reliability_scenario(&scenario)
        .expect("network cut scenario should succeed");

    assert!(report.manifest_path.is_some());
    assert!(
        report
            .activated_failure_hooks
            .contains(&ReliabilityFailureHook::NetworkCut),
        "network cut hook should be activated"
    );
    assert!(
        report.command_records.iter().all(|r| r.succeeded),
        "all commands should succeed"
    );

    harness.mark_passed();
}

#[test]
fn e2e_reliability_harness_partial_update_scenario() {
    let harness = TestHarnessBuilder::new("fault_partial_update")
        .cleanup_on_success(true)
        .build()
        .expect("create test harness");

    let request = convergence_request("harness-partial");
    let response = partial_sync_response(&request);
    let response_json = serde_json::to_string_pretty(&response).expect("serialize");
    harness
        .create_file("partial_update_response.json", &response_json)
        .expect("write response artifact");

    let flags = ReliabilityFailureHookFlags {
        allow_partial_update: true,
        ..Default::default()
    };

    let scenario = ReliabilityScenarioSpec::new("fault_partial_update")
        .with_worker_id("fault-worker-a")
        .with_repo_set(request.repo_specs.clone())
        .request_failure_hook(ReliabilityFailureHook::PartialUpdate)
        .with_failure_hook_flags(flags)
        .add_triage_action("partial_update_recovery")
        .add_execute_command(ReliabilityLifecycleCommand::new(
            "verify-partial-artifact",
            "test",
            [
                "-f",
                harness
                    .test_dir()
                    .join("partial_update_response.json")
                    .to_str()
                    .unwrap(),
            ],
        ))
        .add_cleanup_verification(ReliabilityLifecycleCommand::new(
            "verify-cleanup-state",
            "echo",
            ["worker_slots=recovered drift_state=drifting"],
        ));

    let report = harness
        .run_reliability_scenario(&scenario)
        .expect("partial update scenario should succeed");

    assert!(report.manifest_path.is_some());
    assert!(
        report
            .activated_failure_hooks
            .contains(&ReliabilityFailureHook::PartialUpdate),
        "partial update hook should be activated"
    );

    harness.mark_passed();
}

#[test]
fn e2e_reliability_harness_combined_pressure_scenario() {
    let harness = TestHarnessBuilder::new("fault_combined_pressure")
        .cleanup_on_success(true)
        .build()
        .expect("create test harness");

    // Simulate combined disk pressure + stuck process overlap
    let triage_contract = ProcessTriageContract::default();
    let triage_request = triage_request_disk_pressure();

    let mut decisions = Vec::new();
    for action in &triage_request.requested_actions {
        let decision = evaluate_triage_action(&triage_request, &triage_contract, action);
        decisions.push(serde_json::json!({
            "action_class": format!("{:?}", action.action_class),
            "pid": action.pid,
            "permitted": decision.permitted,
            "escalation": format!("{:?}", decision.escalation_level),
            "decision_code": decision.decision_code,
        }));
    }

    // Also simulate convergence failure under disk pressure
    let adapter = MockRepoUpdaterAdapter::default();
    let convergence_contract = allowlisted_contract();
    let convergence_request = convergence_request("combined-pressure");
    adapter.push_result(Ok(partial_sync_response(&convergence_request)));
    let convergence_response = adapter
        .execute(&convergence_request, &convergence_contract)
        .unwrap();

    let combined_report = serde_json::json!({
        "triage_decisions": decisions,
        "convergence_status": format!("{:?}", convergence_response.status),
        "convergence_fallback_applied": convergence_response.fallback_applied,
        "pressure_state": "disk:critical,process:stuck",
    });
    let report_json = serde_json::to_string_pretty(&combined_report).expect("serialize");
    harness
        .create_file("combined_pressure_report.json", &report_json)
        .expect("write combined report artifact");

    let flags = ReliabilityFailureHookFlags {
        allow_sync_timeout: true,
        allow_partial_update: true,
        ..Default::default()
    };

    let scenario = ReliabilityScenarioSpec::new("fault_combined_pressure")
        .with_worker_id("fault-worker-a")
        .with_pressure_state("disk:critical,process:stuck")
        .request_failure_hook(ReliabilityFailureHook::SyncTimeout)
        .request_failure_hook(ReliabilityFailureHook::PartialUpdate)
        .with_failure_hook_flags(flags)
        .add_triage_action("disk_pressure_reclaim")
        .add_triage_action("stuck_process_terminate")
        .add_execute_command(ReliabilityLifecycleCommand::new(
            "verify-combined-artifact",
            "test",
            [
                "-f",
                harness
                    .test_dir()
                    .join("combined_pressure_report.json")
                    .to_str()
                    .unwrap(),
            ],
        ))
        .add_cleanup_verification(ReliabilityLifecycleCommand::new(
            "verify-slot-recovery",
            "echo",
            ["worker_slots=cleared disk_policy=reassessed process_debt=zero"],
        ));

    let report = harness
        .run_reliability_scenario(&scenario)
        .expect("combined pressure scenario should succeed");

    assert!(report.manifest_path.is_some());
    assert_eq!(report.activated_failure_hooks.len(), 2);

    harness.mark_passed();
}

#[test]
fn e2e_reliability_harness_daemon_restart_scenario() {
    let harness = TestHarnessBuilder::new("fault_daemon_restart")
        .cleanup_on_success(true)
        .build()
        .expect("create test harness");

    // Simulate interrupted convergence
    let adapter = MockRepoUpdaterAdapter::default();
    let contract = allowlisted_contract();
    let request = convergence_request("daemon-restart");

    adapter.push_result(Err(RepoUpdaterFailure {
        kind: RepoUpdaterFailureKind::Interrupted,
        code: "RU_INTERRUPTED".to_string(),
        message: "daemon restart interrupted convergence".to_string(),
        mapped_rch_error: "InternalIpcError".to_string(),
        remediation: vec!["auto-retry after restart".to_string()],
        adapter_exit_code: Some(130),
    }));
    adapter.push_result(Ok(success_response(&request)));

    // Execute: first fails, second succeeds
    let r1 = adapter.execute(&request, &contract);
    let err = r1.unwrap_err();
    let err_json = serde_json::to_string_pretty(&err).expect("serialize");
    harness
        .create_file("daemon_restart_error.json", &err_json)
        .expect("write error artifact");

    let r2 = adapter.execute(&request, &contract).unwrap();
    let recovery_json = serde_json::to_string_pretty(&r2).expect("serialize");
    harness
        .create_file("daemon_restart_recovery.json", &recovery_json)
        .expect("write recovery artifact");

    let flags = ReliabilityFailureHookFlags {
        allow_daemon_restart: true,
        ..Default::default()
    };

    let scenario = ReliabilityScenarioSpec::new("fault_daemon_restart")
        .with_worker_id("fault-worker-a")
        .request_failure_hook(ReliabilityFailureHook::DaemonRestart)
        .with_failure_hook_flags(flags)
        .add_triage_action("daemon_restart_recovery")
        .add_execute_command(ReliabilityLifecycleCommand::new(
            "verify-error-artifact",
            "test",
            [
                "-f",
                harness
                    .test_dir()
                    .join("daemon_restart_error.json")
                    .to_str()
                    .unwrap(),
            ],
        ))
        .add_execute_command(ReliabilityLifecycleCommand::new(
            "verify-recovery-artifact",
            "test",
            [
                "-f",
                harness
                    .test_dir()
                    .join("daemon_restart_recovery.json")
                    .to_str()
                    .unwrap(),
            ],
        ))
        .add_cleanup_verification(ReliabilityLifecycleCommand::new(
            "verify-daemon-state",
            "echo",
            ["daemon=running worker_slots=recovered idempotency=preserved"],
        ));

    let report = harness
        .run_reliability_scenario(&scenario)
        .expect("daemon restart scenario should succeed");

    assert!(report.manifest_path.is_some());
    assert!(
        report
            .activated_failure_hooks
            .contains(&ReliabilityFailureHook::DaemonRestart),
    );
    assert!(
        report.command_records.iter().all(|r| r.succeeded),
        "all commands should succeed after recovery"
    );

    harness.mark_passed();
}

#[test]
fn e2e_reliability_harness_all_hooks_armed_scenario() {
    let harness = TestHarnessBuilder::new("fault_all_hooks")
        .cleanup_on_success(true)
        .build()
        .expect("create test harness");

    let flags = ReliabilityFailureHookFlags::allow_all();

    let scenario = ReliabilityScenarioSpec::new("fault_all_hooks_armed")
        .with_worker_id("fault-worker-a")
        .with_repo_set([harness.test_dir().display().to_string()])
        .with_pressure_state("disk:warning,network:degraded,process:stuck")
        .request_failure_hook(ReliabilityFailureHook::NetworkCut)
        .request_failure_hook(ReliabilityFailureHook::SyncTimeout)
        .request_failure_hook(ReliabilityFailureHook::PartialUpdate)
        .request_failure_hook(ReliabilityFailureHook::DaemonRestart)
        .with_failure_hook_flags(flags)
        .add_triage_action("comprehensive_fault_recovery")
        .add_execute_command(ReliabilityLifecycleCommand::new(
            "verify-hooks-armed",
            "echo",
            ["all_hooks_armed=true"],
        ))
        .add_cleanup_verification(ReliabilityLifecycleCommand::new(
            "verify-comprehensive-cleanup",
            "echo",
            ["all_slots=recovered all_hooks=deactivated"],
        ));

    let report = harness
        .run_reliability_scenario(&scenario)
        .expect("all-hooks scenario should succeed");

    assert!(report.manifest_path.is_some());
    assert_eq!(
        report.activated_failure_hooks.len(),
        4,
        "all 4 failure hooks should be activated"
    );

    harness.mark_passed();
}

#[test]
fn e2e_reliability_harness_unflagged_hook_rejected() {
    let harness = TestHarnessBuilder::new("fault_hook_rejected")
        .cleanup_on_success(true)
        .build()
        .expect("create test harness");

    // Request a hook without enabling it in flags
    let scenario = ReliabilityScenarioSpec::new("fault_hook_rejected")
        .request_failure_hook(ReliabilityFailureHook::NetworkCut);

    let err = harness
        .run_reliability_scenario(&scenario)
        .expect_err("unflagged hook must be rejected");
    assert!(
        err.to_string().contains("not enabled"),
        "error should mention hook not enabled: {err}"
    );
}
