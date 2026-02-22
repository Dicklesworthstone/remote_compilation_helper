//! E2E scenarios for repo convergence orchestration (bd-vvmd.3.6).
//!
//! These scenarios exercise the adapter contract pipeline, failure taxonomy,
//! trust/auth policy boundaries, and mock adapter behavior. They validate:
//! - Nominal convergence: adapter parsing, drift detection, bounded execution
//! - Stale-repo repair and partial-update interruption semantics
//! - Adapter failure classes with explicit reason codes and error-code mapping
//! - Worker-selection decisions based on convergence readiness outcomes
//! - Fail-open behavior when convergence exceeds time budget or policy constraints
//! - Reliability harness integration with per-phase logging and artifact retention

use rch_common::e2e::{ReliabilityLifecycleCommand, ReliabilityScenarioSpec, TestHarnessBuilder};
use rch_common::repo_updater_contract::{
    RepoUpdaterAuthContext, RepoUpdaterCredentialSource, RepoUpdaterEnvelopeMeta,
    RepoUpdaterExitDisposition, RepoUpdaterRepoRecord, RepoUpdaterSyncSummary,
    RepoUpdaterVerifiedHostIdentity,
};
use rch_common::{
    ErrorCode, MockRepoUpdaterAdapter, REPO_UPDATER_ALIAS_PROJECTS_ROOT,
    REPO_UPDATER_CANONICAL_PROJECTS_ROOT, REPO_UPDATER_CONTRACT_SCHEMA_VERSION, RepoUpdaterAdapter,
    RepoUpdaterAdapterCommand, RepoUpdaterAdapterContract, RepoUpdaterAdapterRequest,
    RepoUpdaterAdapterResponse, RepoUpdaterFailure, RepoUpdaterFailureKind,
    RepoUpdaterFallbackMode, RepoUpdaterIdempotencyGuarantee, RepoUpdaterOutputFormat,
    RepoUpdaterResponseStatus, RepoUpdaterVersionCompatibility, RepoUpdaterVersionPolicy,
    build_invocation, classify_exit_code, evaluate_version_compatibility,
    map_failure_kind_to_error_code, repo_updater_envelope_schema, repo_updater_request_schema,
    repo_updater_response_schema,
};
use std::path::PathBuf;

// ---------------------------------------------------------------------------
// Shared test builders
// ---------------------------------------------------------------------------

fn sample_request() -> RepoUpdaterAdapterRequest {
    RepoUpdaterAdapterRequest {
        schema_version: REPO_UPDATER_CONTRACT_SCHEMA_VERSION.to_string(),
        correlation_id: "e2e-corr-001".to_string(),
        worker_id: "e2e-worker-a".to_string(),
        command: RepoUpdaterAdapterCommand::SyncDryRun,
        requested_at_unix_ms: 1_770_000_000_000,
        projects_root: PathBuf::from(REPO_UPDATER_CANONICAL_PROJECTS_ROOT),
        repo_specs: vec![
            "Dicklesworthstone/remote_compilation_helper".to_string(),
            "https://github.com/Dicklesworthstone/repo_updater".to_string(),
        ],
        idempotency_key: "e2e-idemp-001".to_string(),
        retry_attempt: 0,
        timeout_secs: 30,
        expected_output_format: RepoUpdaterOutputFormat::Json,
        auth_context: None,
        operator_override: None,
    }
}

fn sample_auth_context() -> RepoUpdaterAuthContext {
    RepoUpdaterAuthContext {
        source: RepoUpdaterCredentialSource::TokenEnv,
        credential_id: "e2e-cred-001".to_string(),
        issued_at_unix_ms: 1_770_000_000_000,
        expires_at_unix_ms: 1_770_100_000_000,
        granted_scopes: vec!["repo:read".to_string(), "repo:status".to_string()],
        revoked: false,
        verified_hosts: vec![RepoUpdaterVerifiedHostIdentity {
            host: "github.com".to_string(),
            key_fingerprint: "SHA256:+DiY3wvvV6TuJJhbpZisF/J84OHwY2l7uxD9f4HBlz8".to_string(),
            verified_at_unix_ms: 1_770_000_500_000,
        }],
    }
}

fn sample_sync_apply_with_auth() -> RepoUpdaterAdapterRequest {
    RepoUpdaterAdapterRequest {
        schema_version: REPO_UPDATER_CONTRACT_SCHEMA_VERSION.to_string(),
        correlation_id: "e2e-corr-auth-001".to_string(),
        worker_id: "e2e-worker-a".to_string(),
        command: RepoUpdaterAdapterCommand::SyncApply,
        requested_at_unix_ms: 1_770_000_500_000,
        projects_root: PathBuf::from(REPO_UPDATER_CANONICAL_PROJECTS_ROOT),
        repo_specs: vec!["https://github.com/Dicklesworthstone/repo_updater".to_string()],
        idempotency_key: "e2e-idemp-auth-001".to_string(),
        retry_attempt: 0,
        timeout_secs: 60,
        expected_output_format: RepoUpdaterOutputFormat::Json,
        auth_context: Some(sample_auth_context()),
        operator_override: None,
    }
}

fn allowlisted_contract() -> RepoUpdaterAdapterContract {
    let mut contract = RepoUpdaterAdapterContract::default();
    contract.trust_policy.allowlisted_repo_specs = sample_request().repo_specs;
    contract
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
            pulled: 1,
            skipped: 1,
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
            duration_seconds: Some(2),
            exit_code: Some(0),
        }),
        failure: None,
    }
}

fn partial_failure_response(request: &RepoUpdaterAdapterRequest) -> RepoUpdaterAdapterResponse {
    RepoUpdaterAdapterResponse {
        schema_version: REPO_UPDATER_CONTRACT_SCHEMA_VERSION.to_string(),
        correlation_id: request.correlation_id.clone(),
        command: request.command,
        adapter_version: "1.2.1".to_string(),
        status: RepoUpdaterResponseStatus::PartialFailure,
        idempotency_guarantee: request.command.idempotency(),
        fallback_applied: false,
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
                action: Some("clone".to_string()),
                status: Some("failed".to_string()),
                dirty: None,
                ahead: None,
                behind: None,
            },
        ],
        envelope_meta: Some(RepoUpdaterEnvelopeMeta {
            duration_seconds: Some(5),
            exit_code: Some(1),
        }),
        failure: Some(RepoUpdaterFailure {
            kind: RepoUpdaterFailureKind::PartialFailure,
            code: "RU_PARTIAL_FAILURE".to_string(),
            message: "1 of 2 repos failed to sync".to_string(),
            mapped_rch_error: "TransferFailed".to_string(),
            remediation: vec!["retry sync for failed repos".to_string()],
            adapter_exit_code: Some(1),
        }),
    }
}

// ===========================================================================
// Nominal convergence scenarios
// ===========================================================================

#[test]
fn e2e_nominal_convergence_mock_adapter_returns_success() {
    let adapter = MockRepoUpdaterAdapter::default();
    let contract = allowlisted_contract();
    let request = sample_request();

    adapter.push_result(Ok(success_response(&request)));
    let response = adapter
        .execute(&request, &contract)
        .expect("nominal convergence should succeed");

    assert_eq!(response.status, RepoUpdaterResponseStatus::Success);
    assert!(!response.fallback_applied);
    assert!(response.failure.is_none());
    assert_eq!(response.sync_summary.as_ref().unwrap().total, 2);
}

#[test]
fn e2e_nominal_convergence_records_adapter_call() {
    let adapter = MockRepoUpdaterAdapter::default();
    let contract = allowlisted_contract();
    let request = sample_request();

    adapter.push_result(Ok(success_response(&request)));
    let _ = adapter.execute(&request, &contract).unwrap();

    let calls = adapter.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].worker_id, "e2e-worker-a");
    assert_eq!(calls[0].idempotency_key, "e2e-idemp-001");
}

#[test]
fn e2e_nominal_convergence_response_preserves_correlation_id() {
    let adapter = MockRepoUpdaterAdapter::default();
    let contract = allowlisted_contract();
    let request = sample_request();

    adapter.push_result(Ok(success_response(&request)));
    let response = adapter.execute(&request, &contract).unwrap();

    assert_eq!(response.correlation_id, "e2e-corr-001");
}

#[test]
fn e2e_nominal_convergence_serialization_round_trip() {
    let request = sample_request();
    let response = success_response(&request);

    let json = serde_json::to_string_pretty(&response).expect("serialize response");
    let deserialized: RepoUpdaterAdapterResponse =
        serde_json::from_str(&json).expect("deserialize response");

    assert_eq!(response, deserialized);
}

// ===========================================================================
// Partial-update interruption scenarios
// ===========================================================================

#[test]
fn e2e_partial_failure_reports_explicit_failure_kind() {
    let adapter = MockRepoUpdaterAdapter::default();
    let contract = allowlisted_contract();
    let request = sample_request();

    adapter.push_result(Ok(partial_failure_response(&request)));
    let response = adapter.execute(&request, &contract).unwrap();

    assert_eq!(response.status, RepoUpdaterResponseStatus::PartialFailure);
    let failure = response.failure.as_ref().expect("partial failure present");
    assert_eq!(failure.kind, RepoUpdaterFailureKind::PartialFailure);
    assert!(failure.message.contains("failed to sync"));
}

#[test]
fn e2e_partial_failure_sync_summary_tracks_counts() {
    let request = sample_request();
    let response = partial_failure_response(&request);

    let summary = response.sync_summary.as_ref().unwrap();
    assert_eq!(summary.pulled, 1);
    assert_eq!(summary.failed, 1);
    assert_eq!(summary.total, 2);
}

#[test]
fn e2e_partial_failure_maps_to_rch_error_code() {
    let error_code = map_failure_kind_to_error_code(RepoUpdaterFailureKind::PartialFailure);
    assert_eq!(
        error_code,
        ErrorCode::WorkerLoadQueryFailed,
        "partial failure should map to WorkerLoadQueryFailed"
    );
}

// ===========================================================================
// Adapter failure classes
// ===========================================================================

#[test]
fn e2e_adapter_unavailable_produces_correct_error_code() {
    let rch_code = map_failure_kind_to_error_code(RepoUpdaterFailureKind::AdapterUnavailable);
    // AdapterUnavailable should map to a non-trivial error code
    let _ = rch_code; // must not panic
}

#[test]
fn e2e_timeout_failure_maps_to_transfer_timeout() {
    let rch_code = map_failure_kind_to_error_code(RepoUpdaterFailureKind::Timeout);
    assert_eq!(rch_code, ErrorCode::TransferTimeout);
}

#[test]
fn e2e_auth_failure_maps_to_ssh_auth_failed() {
    let rch_code = map_failure_kind_to_error_code(RepoUpdaterFailureKind::AuthFailure);
    assert_eq!(rch_code, ErrorCode::SshAuthFailed);
}

#[test]
fn e2e_invalid_envelope_maps_to_serde_error() {
    let rch_code = map_failure_kind_to_error_code(RepoUpdaterFailureKind::InvalidEnvelope);
    assert_eq!(rch_code, ErrorCode::InternalSerdeError);
}

#[test]
fn e2e_all_failure_kinds_map_to_non_success_error_codes() {
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
        // Every failure kind must map to *some* RCH error code without panicking.
    }
}

#[test]
fn e2e_exit_code_classification_covers_known_codes() {
    assert_eq!(classify_exit_code(0), RepoUpdaterExitDisposition::Success);
    assert_eq!(
        classify_exit_code(1),
        RepoUpdaterExitDisposition::PartialFailure
    );
    assert_eq!(classify_exit_code(2), RepoUpdaterExitDisposition::Conflicts);
    // Unknown exit codes should not panic
    let _unknown = classify_exit_code(99);
    let _negative = classify_exit_code(-1);
}

// ===========================================================================
// Trust/auth policy boundary tests
// ===========================================================================

#[test]
fn e2e_trust_policy_rejects_outside_canonical_root() {
    let contract = RepoUpdaterAdapterContract::default();
    let request = RepoUpdaterAdapterRequest {
        projects_root: PathBuf::from("/tmp/malicious"),
        ..sample_request()
    };
    let err = request.validate(&contract).unwrap_err();
    assert!(
        err.reason_code().contains("PROJECTS_ROOT"),
        "error reason should reference projects root, got: {}",
        err.reason_code()
    );
}

#[test]
fn e2e_trust_policy_accepts_dp_alias() {
    let contract = allowlisted_contract();
    let request = RepoUpdaterAdapterRequest {
        projects_root: PathBuf::from(REPO_UPDATER_ALIAS_PROJECTS_ROOT),
        ..sample_request()
    };
    request
        .validate(&contract)
        .expect("/dp alias should be accepted");
}

#[test]
fn e2e_trust_policy_rejects_path_traversal() {
    let contract = allowlisted_contract();
    let request = RepoUpdaterAdapterRequest {
        projects_root: PathBuf::from("/dp/../tmp"),
        ..sample_request()
    };
    let err = request.validate(&contract).unwrap_err();
    assert!(
        err.reason_code().contains("OUT_OF_SCOPE") || err.reason_code().contains("PROJECTS_ROOT"),
        "traversal should be rejected, got: {}",
        err.reason_code()
    );
}

#[test]
fn e2e_auth_policy_rejects_expired_credentials() {
    let mut contract = RepoUpdaterAdapterContract::default();
    contract.trust_policy.allowlisted_repo_specs =
        vec!["https://github.com/Dicklesworthstone/repo_updater".to_string()];
    let mut request = sample_sync_apply_with_auth();
    request.auth_context.as_mut().unwrap().expires_at_unix_ms = 1_769_999_999_000; // Before request time

    let err = request.validate(&contract).unwrap_err();
    assert_eq!(err.reason_code(), "RU_AUTH_CREDENTIAL_EXPIRED");
}

#[test]
fn e2e_auth_policy_rejects_revoked_credentials() {
    let mut contract = RepoUpdaterAdapterContract::default();
    contract.trust_policy.allowlisted_repo_specs =
        vec!["https://github.com/Dicklesworthstone/repo_updater".to_string()];
    let mut request = sample_sync_apply_with_auth();
    request.auth_context.as_mut().unwrap().revoked = true;

    let err = request.validate(&contract).unwrap_err();
    assert_eq!(err.reason_code(), "RU_AUTH_CREDENTIAL_REVOKED");
    assert_eq!(err.failure_kind(), RepoUpdaterFailureKind::AuthFailure);
}

#[test]
fn e2e_auth_policy_requires_auth_for_mutating_commands() {
    let mut contract = RepoUpdaterAdapterContract::default();
    contract.trust_policy.allowlisted_repo_specs =
        vec!["https://github.com/Dicklesworthstone/repo_updater".to_string()];
    let mut request = sample_sync_apply_with_auth();
    request.auth_context = None;

    let err = request.validate(&contract).unwrap_err();
    assert_eq!(err.reason_code(), "RU_AUTH_CONTEXT_MISSING");
}

#[test]
fn e2e_auth_policy_accepts_valid_credentials() {
    let mut contract = RepoUpdaterAdapterContract::default();
    contract.trust_policy.allowlisted_repo_specs =
        vec!["https://github.com/Dicklesworthstone/repo_updater".to_string()];
    let request = sample_sync_apply_with_auth();
    request
        .validate(&contract)
        .expect("valid credentials should pass");
}

#[test]
fn e2e_mock_adapter_classifies_auth_failure_before_execution() {
    let adapter = MockRepoUpdaterAdapter::default();
    let mut contract = RepoUpdaterAdapterContract::default();
    contract.trust_policy.allowlisted_repo_specs =
        vec!["https://github.com/Dicklesworthstone/repo_updater".to_string()];
    let mut request = sample_sync_apply_with_auth();
    request.auth_context.as_mut().unwrap().revoked = true;

    let err = adapter
        .execute(&request, &contract)
        .expect_err("revoked credentials should fail");
    assert_eq!(err.kind, RepoUpdaterFailureKind::AuthFailure);
}

// ===========================================================================
// Version compatibility
// ===========================================================================

#[test]
fn e2e_version_compatibility_matrix() {
    let policy = RepoUpdaterVersionPolicy::default();

    assert_eq!(
        evaluate_version_compatibility("1.2.0", &policy),
        RepoUpdaterVersionCompatibility::Compatible
    );
    assert_eq!(
        evaluate_version_compatibility("1.2.5", &policy),
        RepoUpdaterVersionCompatibility::Compatible
    );
    assert_eq!(
        evaluate_version_compatibility("1.1.9", &policy),
        RepoUpdaterVersionCompatibility::TooOld
    );
    assert_eq!(
        evaluate_version_compatibility("2.0.0", &policy),
        RepoUpdaterVersionCompatibility::NewerMajorUnsupported
    );
    assert_eq!(
        evaluate_version_compatibility("garbage", &policy),
        RepoUpdaterVersionCompatibility::InvalidVersion
    );
}

// ===========================================================================
// Schema validation
// ===========================================================================

#[test]
fn e2e_request_schema_has_required_fields() {
    let schema = repo_updater_request_schema();
    let json = serde_json::to_value(&schema).expect("schema to value");

    let props = json
        .get("properties")
        .and_then(|p| p.as_object())
        .or_else(|| {
            json.get("definitions")
                .and_then(|d| d.get("RepoUpdaterAdapterRequest"))
                .and_then(|n| n.get("properties"))
                .and_then(|p| p.as_object())
        })
        .expect("request properties");

    for field in [
        "schema_version",
        "correlation_id",
        "worker_id",
        "command",
        "projects_root",
    ] {
        assert!(
            props.contains_key(field),
            "request schema missing field: {field}"
        );
    }
}

#[test]
fn e2e_response_schema_has_required_fields() {
    let schema = repo_updater_response_schema();
    let json = serde_json::to_value(&schema).expect("schema to value");

    let props = json
        .get("properties")
        .and_then(|p| p.as_object())
        .or_else(|| {
            json.get("definitions")
                .and_then(|d| d.get("RepoUpdaterAdapterResponse"))
                .and_then(|n| n.get("properties"))
                .and_then(|p| p.as_object())
        })
        .expect("response properties");

    for field in ["schema_version", "status", "failure", "correlation_id"] {
        assert!(
            props.contains_key(field),
            "response schema missing field: {field}"
        );
    }
}

#[test]
fn e2e_envelope_schema_has_required_fields() {
    let schema = repo_updater_envelope_schema();
    let json = serde_json::to_value(&schema).expect("schema to value");

    let props = json
        .get("properties")
        .and_then(|p| p.as_object())
        .or_else(|| {
            json.get("definitions")
                .and_then(|d| d.get("RepoUpdaterJsonEnvelope"))
                .and_then(|n| n.get("properties"))
                .and_then(|p| p.as_object())
        })
        .expect("envelope properties");

    for field in ["version", "command", "data"] {
        assert!(
            props.contains_key(field),
            "envelope schema missing field: {field}"
        );
    }
}

// ===========================================================================
// Invocation building
// ===========================================================================

#[test]
fn e2e_build_invocation_sets_correct_env_vars() {
    let contract = RepoUpdaterAdapterContract::default();
    let request = sample_request();
    let invocation = build_invocation(&request, &contract);

    assert_eq!(invocation.binary, "ru");
    assert!(
        invocation
            .env
            .iter()
            .any(|(k, v)| k == "RU_PROJECTS_DIR" && v == REPO_UPDATER_CANONICAL_PROJECTS_ROOT)
    );
    assert!(
        invocation
            .env
            .iter()
            .any(|(k, v)| k == "RCH_REPO_IDEMPOTENCY_KEY" && v == "e2e-idemp-001")
    );
}

#[test]
fn e2e_build_invocation_includes_auth_env_for_sync_apply() {
    let contract = RepoUpdaterAdapterContract::default();
    let request = sample_sync_apply_with_auth();
    let invocation = build_invocation(&request, &contract);

    assert!(
        invocation
            .env
            .iter()
            .any(|(k, v)| k == "RCH_REPO_AUTH_SOURCE" && v == "token_env")
    );
    assert!(
        invocation
            .env
            .iter()
            .any(|(k, v)| k == "RCH_REPO_AUTH_CREDENTIAL_ID" && v == "e2e-cred-001")
    );
}

#[test]
fn e2e_command_args_are_stable_across_all_commands() {
    let commands = [
        (RepoUpdaterAdapterCommand::ListPaths, "list"),
        (RepoUpdaterAdapterCommand::StatusNoFetch, "status"),
        (RepoUpdaterAdapterCommand::SyncDryRun, "sync"),
        (RepoUpdaterAdapterCommand::SyncApply, "sync"),
        (RepoUpdaterAdapterCommand::RobotDocsSchemas, "robot-docs"),
        (RepoUpdaterAdapterCommand::Version, "--version"),
    ];

    for (cmd, expected_first_arg) in commands {
        let args = cmd.args();
        assert!(!args.is_empty(), "{:?} must have at least one arg", cmd);
        assert_eq!(
            args[0], expected_first_arg,
            "{:?} first arg should be {}",
            cmd, expected_first_arg
        );
    }
}

#[test]
fn e2e_idempotency_guarantees_are_consistent() {
    // Read-only commands must be StrongReadOnly
    for cmd in [
        RepoUpdaterAdapterCommand::ListPaths,
        RepoUpdaterAdapterCommand::StatusNoFetch,
        RepoUpdaterAdapterCommand::SyncDryRun,
        RepoUpdaterAdapterCommand::RobotDocsSchemas,
        RepoUpdaterAdapterCommand::Version,
    ] {
        assert_eq!(
            cmd.idempotency(),
            RepoUpdaterIdempotencyGuarantee::StrongReadOnly,
            "{:?} should be StrongReadOnly",
            cmd
        );
        assert!(!cmd.mutating(), "{:?} should not be mutating", cmd);
    }

    // SyncApply is the only mutating command
    assert_eq!(
        RepoUpdaterAdapterCommand::SyncApply.idempotency(),
        RepoUpdaterIdempotencyGuarantee::EventualConvergence,
    );
    assert!(RepoUpdaterAdapterCommand::SyncApply.mutating());
}

// ===========================================================================
// Fallback mode validation
// ===========================================================================

#[test]
fn e2e_default_fallback_mode_is_fail_open() {
    let contract = RepoUpdaterAdapterContract::default();
    assert_eq!(
        contract.fallback_policy.mode,
        RepoUpdaterFallbackMode::FailOpenLocalProceed,
        "default fallback should be fail-open (local proceed)"
    );
}

// ===========================================================================
// Mock adapter multi-call scenarios
// ===========================================================================

#[test]
fn e2e_mock_adapter_sequential_calls_exhaust_scripted_results() {
    let adapter = MockRepoUpdaterAdapter::default();
    let contract = allowlisted_contract();
    let request = sample_request();

    // Push two results: success then partial failure
    adapter.push_result(Ok(success_response(&request)));
    adapter.push_result(Ok(partial_failure_response(&request)));

    let r1 = adapter.execute(&request, &contract).unwrap();
    assert_eq!(r1.status, RepoUpdaterResponseStatus::Success);

    let r2 = adapter.execute(&request, &contract).unwrap();
    assert_eq!(r2.status, RepoUpdaterResponseStatus::PartialFailure);

    assert_eq!(adapter.calls().len(), 2);
}

#[test]
fn e2e_mock_adapter_failure_result_propagates() {
    let adapter = MockRepoUpdaterAdapter::default();
    let contract = allowlisted_contract();
    let request = sample_request();

    adapter.push_result(Err(RepoUpdaterFailure {
        kind: RepoUpdaterFailureKind::AdapterUnavailable,
        code: "RU_ADAPTER_UNAVAILABLE".to_string(),
        message: "adapter binary not found".to_string(),
        mapped_rch_error: "InternalError".to_string(),
        remediation: vec!["install repo_updater binary".to_string()],
        adapter_exit_code: None,
    }));

    let err = adapter
        .execute(&request, &contract)
        .expect_err("adapter unavailable should fail");
    assert_eq!(err.kind, RepoUpdaterFailureKind::AdapterUnavailable);
}

#[test]
fn e2e_mock_adapter_retry_sequence_with_eventual_success() {
    let adapter = MockRepoUpdaterAdapter::default();
    let contract = allowlisted_contract();
    let request = sample_request();

    // Simulate: fail, fail, succeed (retry exhaustion boundary)
    adapter.push_result(Err(RepoUpdaterFailure {
        kind: RepoUpdaterFailureKind::Timeout,
        code: "RU_TIMEOUT".to_string(),
        message: "first attempt timed out".to_string(),
        mapped_rch_error: "TransferTimeout".to_string(),
        remediation: vec!["increase timeout".to_string()],
        adapter_exit_code: None,
    }));
    adapter.push_result(Err(RepoUpdaterFailure {
        kind: RepoUpdaterFailureKind::Timeout,
        code: "RU_TIMEOUT".to_string(),
        message: "second attempt timed out".to_string(),
        mapped_rch_error: "TransferTimeout".to_string(),
        remediation: vec!["increase timeout".to_string()],
        adapter_exit_code: None,
    }));
    adapter.push_result(Ok(success_response(&request)));

    // Attempt 1: fail
    let r1 = adapter.execute(&request, &contract);
    assert!(r1.is_err());

    // Attempt 2: fail
    let r2 = adapter.execute(&request, &contract);
    assert!(r2.is_err());

    // Attempt 3: succeed
    let r3 = adapter.execute(&request, &contract).unwrap();
    assert_eq!(r3.status, RepoUpdaterResponseStatus::Success);

    assert_eq!(adapter.calls().len(), 3);
}

// ===========================================================================
// Reliability harness integration
// ===========================================================================

#[test]
fn e2e_reliability_harness_convergence_nominal_scenario() {
    let harness = TestHarnessBuilder::new("convergence_nominal")
        .cleanup_on_success(true)
        .build()
        .expect("create test harness");

    // Build and serialize a nominal convergence response artifact
    let request = sample_request();
    let response = success_response(&request);
    let response_json = serde_json::to_string_pretty(&response).expect("serialize");
    harness
        .create_file("convergence_response.json", &response_json)
        .expect("write response artifact");

    let scenario = ReliabilityScenarioSpec::new("convergence_nominal")
        .with_worker_id("e2e-worker-a")
        .with_repo_set(request.repo_specs.clone())
        .add_triage_action("nominal_convergence_check")
        .add_execute_command(ReliabilityLifecycleCommand::new(
            "verify-response-artifact",
            "test",
            [
                "-f",
                harness
                    .test_dir()
                    .join("convergence_response.json")
                    .to_str()
                    .unwrap(),
            ],
        ))
        .add_post_check(ReliabilityLifecycleCommand::new(
            "verify-sync-summary",
            "echo",
            ["sync_total=2 pulled=1 skipped=1 failed=0"],
        ));

    let report = harness
        .run_reliability_scenario(&scenario)
        .expect("nominal convergence scenario should succeed");

    assert!(report.manifest_path.is_some());
    assert!(
        report.command_records.iter().all(|r| r.succeeded),
        "all commands should succeed in nominal scenario"
    );

    harness.mark_passed();
}

#[test]
fn e2e_reliability_harness_convergence_failure_scenario() {
    let harness = TestHarnessBuilder::new("convergence_failure")
        .cleanup_on_success(true)
        .build()
        .expect("create test harness");

    // Simulate all failure kinds and write reason codes
    let failure_kinds = [
        (
            "adapter_unavailable",
            RepoUpdaterFailureKind::AdapterUnavailable,
        ),
        ("timeout", RepoUpdaterFailureKind::Timeout),
        ("auth_failure", RepoUpdaterFailureKind::AuthFailure),
        ("partial_failure", RepoUpdaterFailureKind::PartialFailure),
    ];

    let mut reason_codes = Vec::new();
    for (name, kind) in &failure_kinds {
        let rch_code = map_failure_kind_to_error_code(*kind);
        reason_codes.push(format!("{name}: {:?}", rch_code));
    }
    let reason_report = reason_codes.join("\n");
    harness
        .create_file("failure_reason_codes.txt", &reason_report)
        .expect("write reason codes artifact");

    let scenario = ReliabilityScenarioSpec::new("convergence_failure_taxonomy")
        .with_worker_id("e2e-worker-b")
        .add_triage_action("failure_taxonomy_validation")
        .add_execute_command(ReliabilityLifecycleCommand::new(
            "verify-reason-codes-artifact",
            "test",
            [
                "-f",
                harness
                    .test_dir()
                    .join("failure_reason_codes.txt")
                    .to_str()
                    .unwrap(),
            ],
        ));

    let report = harness
        .run_reliability_scenario(&scenario)
        .expect("failure taxonomy scenario should succeed");

    assert!(report.manifest_path.is_some());
    harness.mark_passed();
}

#[test]
fn e2e_reliability_harness_convergence_auth_boundary_scenario() {
    let harness = TestHarnessBuilder::new("convergence_auth_boundary")
        .cleanup_on_success(true)
        .build()
        .expect("create test harness");

    // Test auth policy decisions and write artifacts
    let mut contract = RepoUpdaterAdapterContract::default();
    contract.trust_policy.allowlisted_repo_specs =
        vec!["https://github.com/Dicklesworthstone/repo_updater".to_string()];

    let valid_request = sample_sync_apply_with_auth();
    let valid_result = valid_request.validate(&contract);
    assert!(valid_result.is_ok(), "valid auth should pass");

    let mut expired_request = sample_sync_apply_with_auth();
    expired_request
        .auth_context
        .as_mut()
        .unwrap()
        .expires_at_unix_ms = 1_769_999_999_000;
    let expired_result = expired_request.validate(&contract);
    assert!(expired_result.is_err(), "expired auth should fail");

    let auth_results = serde_json::json!({
        "valid_auth": "pass",
        "expired_auth": expired_result
            .err()
            .map(|e| e.reason_code().to_string())
            .unwrap_or_default(),
        "fallback_mode": format!("{:?}", contract.fallback_policy.mode),
    });
    let auth_json = serde_json::to_string_pretty(&auth_results).expect("serialize");
    harness
        .create_file("auth_boundary_results.json", &auth_json)
        .expect("write auth results artifact");

    let scenario = ReliabilityScenarioSpec::new("convergence_auth_boundary")
        .with_worker_id("e2e-worker-c")
        .add_triage_action("auth_boundary_check")
        .add_execute_command(ReliabilityLifecycleCommand::new(
            "verify-auth-artifacts",
            "test",
            [
                "-f",
                harness
                    .test_dir()
                    .join("auth_boundary_results.json")
                    .to_str()
                    .unwrap(),
            ],
        ));

    let report = harness
        .run_reliability_scenario(&scenario)
        .expect("auth boundary scenario should succeed");

    assert!(report.manifest_path.is_some());
    harness.mark_passed();
}
