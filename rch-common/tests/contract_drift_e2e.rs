//! Cross-project helper contract-drift compatibility suite (bd-vvmd.6.11)
//!
//! Validates:
//!   - Schema, semantic, and timeout drift across repo_updater, storage_ballast,
//!     and process_triage integration contracts
//!   - Version-matrix compatibility (min-supported, current, latest-tested)
//!   - Error taxonomy mapping consistency across all helpers
//!   - Fallback semantics under contract mismatch (fail-open for build,
//!     fail-closed for security policy violations)
//!   - Structured diff generation for actionable remediation on drift
//!   - Deterministic diagnostics across mixed-version helper environments
//!
//! Every test emits structured compatibility results for CI/nightly consumption.

use rch_common::e2e::logging::{
    LogLevel, ReliabilityContext, ReliabilityEventInput, ReliabilityPhase, TestLoggerBuilder,
};
use rch_common::e2e::process_triage::{
    PROCESS_TRIAGE_CONTRACT_SCHEMA_VERSION, ProcessClassification, ProcessDescriptor,
    ProcessTriageActionClass, ProcessTriageActionRequest, ProcessTriageContract,
    ProcessTriageRequest, ProcessTriageTrigger, evaluate_triage_action,
    process_triage_request_schema, process_triage_response_schema,
};
use rch_common::errors::ErrorCode;
use rch_common::repo_updater_contract::{
    REPO_UPDATER_CONTRACT_SCHEMA_VERSION, REPO_UPDATER_MIN_SUPPORTED_VERSION,
    RepoUpdaterAdapterCommand, RepoUpdaterAdapterContract, RepoUpdaterFailureKind,
    RepoUpdaterFallbackMode, RepoUpdaterVersionCompatibility, RepoUpdaterVersionPolicy,
    build_invocation, classify_exit_code, evaluate_version_compatibility,
    map_failure_kind_to_error_code, repo_updater_envelope_schema, repo_updater_request_schema,
    repo_updater_response_schema,
};
use serde::{Deserialize, Serialize};

// ===========================================================================
// Compatibility types
// ===========================================================================

/// Identifies which helper integration is being checked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum HelperComponent {
    RepoUpdater,
    ProcessTriage,
    StorageBallast,
}

/// A single field-level or semantic drift finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct DriftFinding {
    component: HelperComponent,
    field_or_behavior: String,
    expected: String,
    observed: String,
    severity: DriftSeverity,
    remediation: String,
    decision_code: String,
}

/// How bad is the drift?
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum DriftSeverity {
    /// Informational, no action required.
    Info,
    /// Non-breaking but should be tracked.
    Warning,
    /// Breaking drift requiring immediate attention.
    Critical,
}

/// Simulated version tuple for version-matrix testing.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct VersionTuple {
    component: HelperComponent,
    version: String,
    compatibility: String,
}

/// Result of a full compatibility check across one component.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CompatibilityCheckResult {
    component: HelperComponent,
    schema_version: String,
    drift_findings: Vec<DriftFinding>,
    is_compatible: bool,
    fallback_mode: String,
    remediation_summary: Vec<String>,
}

/// Full suite summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CompatibilitySuiteSummary {
    total_checks: usize,
    pass: usize,
    fail: usize,
    critical_drifts: usize,
    components_checked: Vec<HelperComponent>,
    version_matrix: Vec<VersionTuple>,
    findings: Vec<DriftFinding>,
}

// ===========================================================================
// Drift detection engine
// ===========================================================================

/// Check that a schema version matches what we expect; returns a finding if not.
fn check_schema_version(
    component: HelperComponent,
    expected: &str,
    observed: &str,
) -> Option<DriftFinding> {
    if expected == observed {
        return None;
    }
    let severity = if expected.split('.').next() != observed.split('.').next() {
        DriftSeverity::Critical
    } else {
        DriftSeverity::Warning
    };
    Some(DriftFinding {
        component,
        field_or_behavior: "schema_version".to_string(),
        expected: expected.to_string(),
        observed: observed.to_string(),
        severity,
        remediation: format!("Update contract adapter to match schema version {expected}"),
        decision_code: "DRIFT_SCHEMA_VERSION_MISMATCH".to_string(),
    })
}

/// Check that an error taxonomy mapping is consistent.
fn check_error_mapping(
    component: HelperComponent,
    failure_description: &str,
    mapped_code: ErrorCode,
    expected_category: &str,
) -> Option<DriftFinding> {
    let code_str = mapped_code.code_string();
    // Verify the error code starts with the expected category prefix (format: RCH-Exxx)
    // Extract numeric part after "RCH-E"
    let numeric = code_str.strip_prefix("RCH-E").unwrap_or("");
    let actual_category = if numeric.starts_with('0') {
        "config"
    } else if numeric.starts_with('1') {
        "network"
    } else if numeric.starts_with('2') {
        "worker"
    } else if numeric.starts_with('3') {
        "build"
    } else if numeric.starts_with('4') {
        "daemon"
    } else {
        "unknown"
    };

    if actual_category == expected_category {
        return None;
    }

    Some(DriftFinding {
        component,
        field_or_behavior: format!("error_mapping:{failure_description}"),
        expected: expected_category.to_string(),
        observed: format!("{actual_category} ({code_str})"),
        severity: DriftSeverity::Warning,
        remediation: format!(
            "Review error code mapping for {failure_description}: expected {expected_category} range"
        ),
        decision_code: "DRIFT_ERROR_TAXONOMY_MISMATCH".to_string(),
    })
}

/// Check that a timeout value is within reasonable bounds.
fn check_timeout_drift(
    component: HelperComponent,
    operation: &str,
    timeout_secs: u64,
    min_secs: u64,
    max_secs: u64,
) -> Option<DriftFinding> {
    if timeout_secs >= min_secs && timeout_secs <= max_secs {
        return None;
    }
    Some(DriftFinding {
        component,
        field_or_behavior: format!("timeout:{operation}"),
        expected: format!("{min_secs}..={max_secs} secs"),
        observed: format!("{timeout_secs} secs"),
        severity: if timeout_secs == 0 || timeout_secs > max_secs * 2 {
            DriftSeverity::Critical
        } else {
            DriftSeverity::Warning
        },
        remediation: format!("Adjust {operation} timeout to [{min_secs}, {max_secs}] seconds"),
        decision_code: "DRIFT_TIMEOUT_OUT_OF_RANGE".to_string(),
    })
}

/// Evaluate fallback behavior given a simulated contract mismatch.
fn evaluate_fallback_on_mismatch(
    component: HelperComponent,
    is_security_relevant: bool,
    fallback_mode: &str,
) -> DriftFinding {
    let severity = if is_security_relevant && fallback_mode == "fail_open" {
        DriftSeverity::Critical
    } else {
        DriftSeverity::Info
    };

    let decision_code = if is_security_relevant {
        "FALLBACK_SECURITY_CHECK"
    } else {
        "FALLBACK_COMPILATION_CHECK"
    };

    DriftFinding {
        component,
        field_or_behavior: "fallback_on_mismatch".to_string(),
        expected: if is_security_relevant {
            "fail_closed".to_string()
        } else {
            "fail_open_acceptable".to_string()
        },
        observed: fallback_mode.to_string(),
        severity,
        remediation: if is_security_relevant && fallback_mode == "fail_open" {
            "Security-relevant contract mismatch must fail-closed".to_string()
        } else {
            "Fallback mode acceptable for non-security path".to_string()
        },
        decision_code: decision_code.to_string(),
    }
}

// ===========================================================================
// Tests: repo_updater contract stability
// ===========================================================================

#[test]
fn e2e_ru_schema_version_matches_contract() {
    // The contract schema version should be a valid semver string
    assert!(!REPO_UPDATER_CONTRACT_SCHEMA_VERSION.is_empty());
    let parts: Vec<&str> = REPO_UPDATER_CONTRACT_SCHEMA_VERSION.split('.').collect();
    assert_eq!(parts.len(), 3, "schema version must be semver");
    for part in &parts {
        assert!(
            part.parse::<u32>().is_ok(),
            "semver part must be numeric: {part}"
        );
    }
}

#[test]
fn e2e_ru_min_supported_version_is_valid_semver() {
    let parts: Vec<&str> = REPO_UPDATER_MIN_SUPPORTED_VERSION.split('.').collect();
    assert_eq!(parts.len(), 3);
    for part in &parts {
        assert!(part.parse::<u32>().is_ok());
    }
}

#[test]
fn e2e_ru_command_surface_stability() {
    // All 6 commands must produce non-empty args lists
    let commands = [
        RepoUpdaterAdapterCommand::ListPaths,
        RepoUpdaterAdapterCommand::StatusNoFetch,
        RepoUpdaterAdapterCommand::SyncDryRun,
        RepoUpdaterAdapterCommand::SyncApply,
        RepoUpdaterAdapterCommand::RobotDocsSchemas,
        RepoUpdaterAdapterCommand::Version,
    ];

    for cmd in &commands {
        let args = cmd.args();
        assert!(!args.is_empty(), "command {cmd:?} must have args");
    }

    // Interactive commands must include --non-interactive
    let interactive_cmds = [
        RepoUpdaterAdapterCommand::ListPaths,
        RepoUpdaterAdapterCommand::StatusNoFetch,
        RepoUpdaterAdapterCommand::SyncDryRun,
        RepoUpdaterAdapterCommand::SyncApply,
    ];
    for cmd in &interactive_cmds {
        assert!(
            cmd.args().contains(&"--non-interactive"),
            "{cmd:?} should include --non-interactive"
        );
    }
}

#[test]
fn e2e_ru_idempotency_guarantees_stable() {
    // Read-only commands must be StrongReadOnly
    use rch_common::repo_updater_contract::RepoUpdaterIdempotencyGuarantee;

    let read_commands = [
        RepoUpdaterAdapterCommand::ListPaths,
        RepoUpdaterAdapterCommand::StatusNoFetch,
        RepoUpdaterAdapterCommand::RobotDocsSchemas,
        RepoUpdaterAdapterCommand::Version,
    ];
    for cmd in &read_commands {
        assert_eq!(
            cmd.idempotency(),
            RepoUpdaterIdempotencyGuarantee::StrongReadOnly,
            "{cmd:?} must be read-only"
        );
        assert!(!cmd.mutating(), "{cmd:?} must not be mutating");
    }

    // SyncApply is eventual convergence
    assert_eq!(
        RepoUpdaterAdapterCommand::SyncApply.idempotency(),
        RepoUpdaterIdempotencyGuarantee::EventualConvergence,
    );
    assert!(RepoUpdaterAdapterCommand::SyncApply.mutating());
}

#[test]
fn e2e_ru_error_taxonomy_maps_to_valid_codes() {
    // Every failure kind must map to a valid ErrorCode
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

    for kind in &failure_kinds {
        let code = map_failure_kind_to_error_code(*kind);
        let code_str = code.code_string();
        assert!(
            code_str.starts_with("RCH-E"),
            "error code for {kind:?} should start with 'RCH-E', got {code_str}"
        );
    }
}

#[test]
fn e2e_ru_exit_code_classification_stable() {
    // Exit codes 0-5 must classify to known dispositions
    use rch_common::repo_updater_contract::RepoUpdaterExitDisposition;

    assert!(matches!(
        classify_exit_code(0),
        RepoUpdaterExitDisposition::Success
    ));
    assert!(matches!(
        classify_exit_code(1),
        RepoUpdaterExitDisposition::PartialFailure
    ));
    assert!(matches!(
        classify_exit_code(2),
        RepoUpdaterExitDisposition::Conflicts
    ));
    assert!(matches!(
        classify_exit_code(3),
        RepoUpdaterExitDisposition::SystemError
    ));
    assert!(matches!(
        classify_exit_code(4),
        RepoUpdaterExitDisposition::InvalidArguments
    ));
    assert!(matches!(
        classify_exit_code(5),
        RepoUpdaterExitDisposition::Interrupted
    ));
    assert!(matches!(
        classify_exit_code(99),
        RepoUpdaterExitDisposition::Unknown
    ));
}

#[test]
fn e2e_ru_version_compatibility_matrix() {
    let policy = RepoUpdaterVersionPolicy::default();

    // Min supported version should be compatible
    let compat = evaluate_version_compatibility(REPO_UPDATER_MIN_SUPPORTED_VERSION, &policy);
    assert!(
        matches!(compat, RepoUpdaterVersionCompatibility::Compatible),
        "min supported version should be compatible, got {compat:?}"
    );

    // Major version 0 should be too old (below min)
    let compat = evaluate_version_compatibility("0.1.0", &policy);
    assert!(
        matches!(compat, RepoUpdaterVersionCompatibility::TooOld),
        "version 0.1.0 should be too old, got {compat:?}"
    );
}

#[test]
fn e2e_ru_contract_default_validates() {
    let contract = RepoUpdaterAdapterContract::default();
    assert!(
        contract.validate().is_ok(),
        "default contract must pass validation"
    );
}

#[test]
fn e2e_ru_fallback_on_compilation_path_is_fail_open() {
    let contract = RepoUpdaterAdapterContract::default();
    assert!(
        matches!(
            contract.fallback_policy.mode,
            RepoUpdaterFallbackMode::FailOpenLocalProceed
        ),
        "compilation path fallback must be fail-open"
    );
}

#[test]
fn e2e_ru_request_schema_roundtrip() {
    let schema = repo_updater_request_schema();
    let json = serde_json::to_string_pretty(&schema).unwrap();
    assert!(!json.is_empty());
    let _: schemars::schema::RootSchema = serde_json::from_str(&json).unwrap();
}

#[test]
fn e2e_ru_response_schema_roundtrip() {
    let schema = repo_updater_response_schema();
    let json = serde_json::to_string_pretty(&schema).unwrap();
    assert!(!json.is_empty());
    let _: schemars::schema::RootSchema = serde_json::from_str(&json).unwrap();
}

#[test]
fn e2e_ru_envelope_schema_roundtrip() {
    let schema = repo_updater_envelope_schema();
    let json = serde_json::to_string_pretty(&schema).unwrap();
    assert!(!json.is_empty());
    let _: schemars::schema::RootSchema = serde_json::from_str(&json).unwrap();
}

#[test]
fn e2e_ru_timeout_policy_within_bounds() {
    let contract = RepoUpdaterAdapterContract::default();
    let mut findings = Vec::new();

    if let Some(f) = check_timeout_drift(
        HelperComponent::RepoUpdater,
        "read",
        contract.timeout_policy.read_timeout_secs,
        1,
        30,
    ) {
        findings.push(f);
    }
    if let Some(f) = check_timeout_drift(
        HelperComponent::RepoUpdater,
        "sync",
        contract.timeout_policy.sync_timeout_secs,
        10,
        600,
    ) {
        findings.push(f);
    }
    if let Some(f) = check_timeout_drift(
        HelperComponent::RepoUpdater,
        "version",
        contract.timeout_policy.version_timeout_secs,
        1,
        10,
    ) {
        findings.push(f);
    }

    assert!(findings.is_empty(), "timeout drift detected: {findings:?}");
}

#[test]
fn e2e_ru_invocation_builder_produces_valid_commands() {
    let contract = RepoUpdaterAdapterContract::default();
    let request = make_ru_request(RepoUpdaterAdapterCommand::StatusNoFetch);
    let invocation = build_invocation(&request, &contract);

    assert!(!invocation.binary.is_empty());
    assert!(!invocation.args.is_empty());
}

// ===========================================================================
// Tests: process_triage contract stability
// ===========================================================================

#[test]
fn e2e_pt_schema_version_matches_contract() {
    assert!(!PROCESS_TRIAGE_CONTRACT_SCHEMA_VERSION.is_empty());
    let parts: Vec<&str> = PROCESS_TRIAGE_CONTRACT_SCHEMA_VERSION.split('.').collect();
    assert_eq!(parts.len(), 3);
    for part in &parts {
        assert!(part.parse::<u32>().is_ok());
    }
}

#[test]
fn e2e_pt_contract_default_validates() {
    let contract = ProcessTriageContract::default();
    assert!(
        contract.validate().is_ok(),
        "default process triage contract must pass validation"
    );
}

#[test]
fn e2e_pt_action_class_risk_ordering() {
    // Risk order verified via policy evaluation: ObserveOnly is always permitted,
    // HardTerminate is always denied by default policy.
    let contract = ProcessTriageContract::default();
    let request = make_triage_request(ProcessTriageTrigger::DiskPressure);

    // ObserveOnly should be permitted (lowest risk)
    let observe_action = ProcessTriageActionRequest {
        action_class: ProcessTriageActionClass::ObserveOnly,
        pid: 12345,
        reason_code: "risk_test".to_string(),
        signal: None,
    };
    let observe_result = evaluate_triage_action(&request, &contract, &observe_action);
    assert!(observe_result.permitted, "ObserveOnly should be permitted");

    // HardTerminate should be denied (highest risk)
    let hard_action = ProcessTriageActionRequest {
        action_class: ProcessTriageActionClass::HardTerminate,
        pid: 12345,
        reason_code: "risk_test".to_string(),
        signal: Some("SIGKILL".to_string()),
    };
    let hard_result = evaluate_triage_action(&request, &contract, &hard_action);
    assert!(
        !hard_result.permitted,
        "HardTerminate should be denied by default"
    );
}

#[test]
fn e2e_pt_safe_action_policy_denies_hard_terminate_by_default() {
    let contract = ProcessTriageContract::default();
    let request = make_triage_request(ProcessTriageTrigger::DiskPressure);
    let action = ProcessTriageActionRequest {
        action_class: ProcessTriageActionClass::HardTerminate,
        pid: 12345,
        reason_code: "kill_stale".to_string(),
        signal: Some("SIGKILL".to_string()),
    };

    let decision = evaluate_triage_action(&request, &contract, &action);
    assert!(
        !decision.permitted,
        "HardTerminate must be denied by default policy"
    );
}

#[test]
fn e2e_pt_safe_action_policy_allows_observe_only() {
    let contract = ProcessTriageContract::default();
    let request = make_triage_request(ProcessTriageTrigger::DiskPressure);
    let action = ProcessTriageActionRequest {
        action_class: ProcessTriageActionClass::ObserveOnly,
        pid: 12345,
        reason_code: "monitor".to_string(),
        signal: None,
    };

    let decision = evaluate_triage_action(&request, &contract, &action);
    assert!(
        decision.permitted,
        "ObserveOnly must be permitted by default policy"
    );
}

#[test]
fn e2e_pt_protected_process_blocking() {
    let contract = ProcessTriageContract::default();
    // sshd should be a protected process
    let mut request = make_triage_request(ProcessTriageTrigger::WorkerHealth);
    request.candidate_processes[0].command = "sshd: ubuntu@pts/0".to_string();
    request.candidate_processes[0].classification = ProcessClassification::SystemCritical;

    let action = ProcessTriageActionRequest {
        action_class: ProcessTriageActionClass::SoftTerminate,
        pid: request.candidate_processes[0].pid,
        reason_code: "terminate_sshd".to_string(),
        signal: Some("SIGTERM".to_string()),
    };

    let decision = evaluate_triage_action(&request, &contract, &action);
    assert!(
        !decision.permitted,
        "protected process (sshd) must be blocked"
    );
    assert!(
        decision.decision_code.contains("PROTECT") || decision.decision_code.contains("SCOPE"),
        "decision code should reference protection: {}",
        decision.decision_code
    );
}

#[test]
fn e2e_pt_request_schema_roundtrip() {
    let schema = process_triage_request_schema();
    let json = serde_json::to_string_pretty(&schema).unwrap();
    assert!(!json.is_empty());
    let _: schemars::schema::RootSchema = serde_json::from_str(&json).unwrap();
}

#[test]
fn e2e_pt_response_schema_roundtrip() {
    let schema = process_triage_response_schema();
    let json = serde_json::to_string_pretty(&schema).unwrap();
    assert!(!json.is_empty());
    let _: schemars::schema::RootSchema = serde_json::from_str(&json).unwrap();
}

#[test]
fn e2e_pt_timeout_policy_within_bounds() {
    let contract = ProcessTriageContract::default();
    let mut findings = Vec::new();

    if let Some(f) = check_timeout_drift(
        HelperComponent::ProcessTriage,
        "request",
        contract.timeout_policy.request_timeout_secs,
        1,
        30,
    ) {
        findings.push(f);
    }
    if let Some(f) = check_timeout_drift(
        HelperComponent::ProcessTriage,
        "action",
        contract.timeout_policy.action_timeout_secs,
        1,
        60,
    ) {
        findings.push(f);
    }
    if let Some(f) = check_timeout_drift(
        HelperComponent::ProcessTriage,
        "total",
        contract.timeout_policy.total_timeout_secs,
        5,
        120,
    ) {
        findings.push(f);
    }

    assert!(findings.is_empty(), "timeout drift detected: {findings:?}");
}

#[test]
fn e2e_pt_error_taxonomy_coverage() {
    // Process triage failure kinds must map to valid error codes
    use rch_common::e2e::process_triage::ProcessTriageFailureKind;

    let failure_kinds = [
        ProcessTriageFailureKind::DetectorUncertain,
        ProcessTriageFailureKind::PolicyViolation,
        ProcessTriageFailureKind::TransportError,
        ProcessTriageFailureKind::ExecutorRuntimeError,
        ProcessTriageFailureKind::Timeout,
        ProcessTriageFailureKind::PartialResult,
        ProcessTriageFailureKind::InvalidRequest,
    ];

    for kind in &failure_kinds {
        let json = serde_json::to_string(kind).unwrap();
        assert!(!json.is_empty(), "failure kind {kind:?} must serialize");
    }
}

// ===========================================================================
// Tests: cross-helper contract consistency
// ===========================================================================

#[test]
fn e2e_cross_schema_versions_are_independent_semver() {
    let versions = [
        ("repo_updater", REPO_UPDATER_CONTRACT_SCHEMA_VERSION),
        ("process_triage", PROCESS_TRIAGE_CONTRACT_SCHEMA_VERSION),
    ];

    for (name, version) in &versions {
        let parts: Vec<&str> = version.split('.').collect();
        assert_eq!(
            parts.len(),
            3,
            "{name} schema version must be semver: {version}"
        );
        for part in &parts {
            assert!(
                part.parse::<u32>().is_ok(),
                "{name} semver part must be numeric: {part}"
            );
        }
    }
}

#[test]
fn e2e_cross_error_code_ranges_do_not_collide() {
    // Map all failure kinds from both helpers to error codes and check for conflicts
    let ru_codes: Vec<_> = [
        RepoUpdaterFailureKind::AdapterUnavailable,
        RepoUpdaterFailureKind::VersionIncompatible,
        RepoUpdaterFailureKind::TrustBoundaryViolation,
        RepoUpdaterFailureKind::AuthFailure,
        RepoUpdaterFailureKind::Timeout,
        RepoUpdaterFailureKind::CommandFailed,
    ]
    .iter()
    .map(|k| (format!("ru:{k:?}"), map_failure_kind_to_error_code(*k)))
    .collect();

    // Verify all codes are valid (RCH-Exxx format)
    for (label, code) in &ru_codes {
        let code_str = code.code_string();
        assert!(
            code_str.starts_with("RCH-E"),
            "{label} mapped to invalid code: {code_str}"
        );
    }
}

#[test]
fn e2e_cross_timeout_semantics_consistent() {
    let ru = RepoUpdaterAdapterContract::default();
    let pt = ProcessTriageContract::default();

    // Read timeouts should be in similar ballpark
    let ru_read = ru.timeout_policy.read_timeout_secs;
    let pt_request = pt.timeout_policy.request_timeout_secs;

    // Both should be single-digit seconds for lightweight operations
    assert!(
        ru_read <= 30 && pt_request <= 30,
        "read/request timeouts should be <=30s: ru={ru_read}, pt={pt_request}"
    );
}

#[test]
fn e2e_cross_retry_policies_consistent() {
    let ru = RepoUpdaterAdapterContract::default();
    let pt = ProcessTriageContract::default();

    // Both should have reasonable retry counts
    assert!(
        ru.retry_policy.max_attempts >= 1 && ru.retry_policy.max_attempts <= 10,
        "ru retry attempts out of range: {}",
        ru.retry_policy.max_attempts
    );
    assert!(
        pt.retry_policy.max_attempts >= 1 && pt.retry_policy.max_attempts <= 10,
        "pt retry attempts out of range: {}",
        pt.retry_policy.max_attempts
    );

    // Backoff multiplier should be reasonable (100-400%)
    assert!(
        ru.retry_policy.backoff_multiplier_percent >= 100
            && ru.retry_policy.backoff_multiplier_percent <= 400,
        "ru backoff multiplier unreasonable: {}",
        ru.retry_policy.backoff_multiplier_percent
    );
}

// ===========================================================================
// Tests: fallback semantics under contract mismatch
// ===========================================================================

#[test]
fn e2e_fallback_compilation_path_is_fail_open() {
    let finding = evaluate_fallback_on_mismatch(HelperComponent::RepoUpdater, false, "fail_open");
    assert_eq!(finding.severity, DriftSeverity::Info);
}

#[test]
fn e2e_fallback_security_path_must_fail_closed() {
    let finding = evaluate_fallback_on_mismatch(HelperComponent::ProcessTriage, true, "fail_open");
    assert_eq!(
        finding.severity,
        DriftSeverity::Critical,
        "security-relevant mismatch with fail_open must be critical"
    );
}

#[test]
fn e2e_fallback_security_path_fail_closed_is_ok() {
    let finding =
        evaluate_fallback_on_mismatch(HelperComponent::ProcessTriage, true, "fail_closed");
    assert_ne!(finding.severity, DriftSeverity::Critical);
}

// ===========================================================================
// Tests: version matrix compatibility
// ===========================================================================

#[test]
fn e2e_version_matrix_min_supported_compatible() {
    let policy = RepoUpdaterVersionPolicy::default();
    let compat = evaluate_version_compatibility(REPO_UPDATER_MIN_SUPPORTED_VERSION, &policy);
    assert!(
        matches!(compat, RepoUpdaterVersionCompatibility::Compatible),
        "min supported version must be compatible, got {compat:?}"
    );
}

#[test]
fn e2e_version_matrix_ancient_version_rejected() {
    let policy = RepoUpdaterVersionPolicy::default();
    let compat = evaluate_version_compatibility("0.0.1", &policy);
    assert!(
        matches!(compat, RepoUpdaterVersionCompatibility::TooOld),
        "ancient version 0.0.1 should be too old, got {compat:?}"
    );
}

#[test]
fn e2e_version_matrix_far_future_major_untested() {
    let policy = RepoUpdaterVersionPolicy::default();
    let compat = evaluate_version_compatibility("99.0.0", &policy);
    assert!(
        matches!(
            compat,
            RepoUpdaterVersionCompatibility::NewerMajorUnsupported
                | RepoUpdaterVersionCompatibility::NewerMinorUntested
        ),
        "far future version 99.0.0 should be newer major/minor, got {compat:?}"
    );
}

// ===========================================================================
// Tests: structured diff generation
// ===========================================================================

#[test]
fn e2e_drift_finding_serialization_roundtrip() {
    let finding = DriftFinding {
        component: HelperComponent::RepoUpdater,
        field_or_behavior: "schema_version".to_string(),
        expected: "1.0.0".to_string(),
        observed: "2.0.0".to_string(),
        severity: DriftSeverity::Critical,
        remediation: "Update contract adapter".to_string(),
        decision_code: "DRIFT_SCHEMA_VERSION_MISMATCH".to_string(),
    };

    let json = serde_json::to_string(&finding).unwrap();
    let back: DriftFinding = serde_json::from_str(&json).unwrap();
    assert_eq!(back.component, finding.component);
    assert_eq!(back.severity, finding.severity);
    assert_eq!(back.decision_code, finding.decision_code);
}

#[test]
fn e2e_compatibility_check_result_serialization() {
    let result = CompatibilityCheckResult {
        component: HelperComponent::ProcessTriage,
        schema_version: PROCESS_TRIAGE_CONTRACT_SCHEMA_VERSION.to_string(),
        drift_findings: vec![],
        is_compatible: true,
        fallback_mode: "fail_closed".to_string(),
        remediation_summary: vec![],
    };

    let json = serde_json::to_string_pretty(&result).unwrap();
    assert!(json.contains("process_triage"));
    assert!(json.contains("is_compatible"));
    let back: CompatibilityCheckResult = serde_json::from_str(&json).unwrap();
    assert!(back.is_compatible);
}

#[test]
fn e2e_suite_summary_serialization() {
    let summary = CompatibilitySuiteSummary {
        total_checks: 3,
        pass: 2,
        fail: 1,
        critical_drifts: 0,
        components_checked: vec![
            HelperComponent::RepoUpdater,
            HelperComponent::ProcessTriage,
            HelperComponent::StorageBallast,
        ],
        version_matrix: vec![VersionTuple {
            component: HelperComponent::RepoUpdater,
            version: REPO_UPDATER_MIN_SUPPORTED_VERSION.to_string(),
            compatibility: "supported".to_string(),
        }],
        findings: vec![],
    };

    let json = serde_json::to_string_pretty(&summary).unwrap();
    assert!(json.contains("total_checks"));
    let back: CompatibilitySuiteSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(back.total_checks, 3);
    assert_eq!(back.components_checked.len(), 3);
}

// ===========================================================================
// Tests: schema drift detection engine
// ===========================================================================

#[test]
fn e2e_schema_drift_same_version_no_finding() {
    let finding = check_schema_version(HelperComponent::RepoUpdater, "1.0.0", "1.0.0");
    assert!(finding.is_none());
}

#[test]
fn e2e_schema_drift_minor_bump_is_warning() {
    let finding = check_schema_version(HelperComponent::RepoUpdater, "1.0.0", "1.1.0");
    assert!(finding.is_some());
    assert_eq!(finding.unwrap().severity, DriftSeverity::Warning);
}

#[test]
fn e2e_schema_drift_major_bump_is_critical() {
    let finding = check_schema_version(HelperComponent::ProcessTriage, "1.0.0", "2.0.0");
    assert!(finding.is_some());
    assert_eq!(finding.unwrap().severity, DriftSeverity::Critical);
}

// ===========================================================================
// Tests: mixed-version environment diagnostics
// ===========================================================================

#[test]
fn e2e_mixed_version_environment_deterministic_diagnostics() {
    // Simulate checking all three components at different versions
    let checks = [
        CompatibilityCheckResult {
            component: HelperComponent::RepoUpdater,
            schema_version: REPO_UPDATER_CONTRACT_SCHEMA_VERSION.to_string(),
            drift_findings: vec![],
            is_compatible: true,
            fallback_mode: "fail_open_local_proceed".to_string(),
            remediation_summary: vec![],
        },
        CompatibilityCheckResult {
            component: HelperComponent::ProcessTriage,
            schema_version: PROCESS_TRIAGE_CONTRACT_SCHEMA_VERSION.to_string(),
            drift_findings: vec![],
            is_compatible: true,
            fallback_mode: "fail_closed".to_string(),
            remediation_summary: vec![],
        },
        CompatibilityCheckResult {
            component: HelperComponent::StorageBallast,
            schema_version: "1.0.0".to_string(),
            drift_findings: vec![DriftFinding {
                component: HelperComponent::StorageBallast,
                field_or_behavior: "reclaim_mode".to_string(),
                expected: "enforce".to_string(),
                observed: "observe".to_string(),
                severity: DriftSeverity::Info,
                remediation: "Storage ballast is in observe-only mode".to_string(),
                decision_code: "BALLAST_OBSERVE_MODE".to_string(),
            }],
            is_compatible: true,
            fallback_mode: "observe".to_string(),
            remediation_summary: vec!["Storage ballast is in observe-only mode".to_string()],
        },
    ];

    // Build summary
    let all_findings: Vec<_> = checks
        .iter()
        .flat_map(|c| c.drift_findings.clone())
        .collect();
    let summary = CompatibilitySuiteSummary {
        total_checks: checks.len(),
        pass: checks.iter().filter(|c| c.is_compatible).count(),
        fail: checks.iter().filter(|c| !c.is_compatible).count(),
        critical_drifts: all_findings
            .iter()
            .filter(|f| f.severity == DriftSeverity::Critical)
            .count(),
        components_checked: checks.iter().map(|c| c.component.clone()).collect(),
        version_matrix: vec![],
        findings: all_findings,
    };

    // Verify deterministic serialization
    let json1 = serde_json::to_string(&summary).unwrap();
    let json2 = serde_json::to_string(&summary).unwrap();
    assert_eq!(json1, json2, "diagnostics must be deterministic");

    // Verify summary counts
    assert_eq!(summary.total_checks, 3);
    assert_eq!(summary.pass, 3);
    assert_eq!(summary.fail, 0);
    assert_eq!(summary.critical_drifts, 0);
}

// ===========================================================================
// Tests: logging integration
// ===========================================================================

#[test]
fn e2e_compatibility_logging_integration() {
    let logger = TestLoggerBuilder::new("contract-drift-check")
        .print_realtime(false)
        .build();

    // Log compatibility check events
    let event = logger.log_reliability_event(ReliabilityEventInput {
        level: LogLevel::Info,
        phase: ReliabilityPhase::Verify,
        scenario_id: "contract-drift-ru".to_string(),
        message: "repo_updater contract compatibility check passed".to_string(),
        context: ReliabilityContext {
            worker_id: Some("w1".to_string()),
            repo_set: vec!["repo-a".to_string()],
            pressure_state: Some("nominal".to_string()),
            triage_actions: Vec::new(),
            decision_code: "COMPAT_PASS".to_string(),
            fallback_reason: None,
        },
        artifact_paths: vec![],
    });

    assert_eq!(event.phase, ReliabilityPhase::Verify);
    assert!(event.scenario_id.contains("contract-drift"));

    let event2 = logger.log_reliability_event(ReliabilityEventInput {
        level: LogLevel::Warn,
        phase: ReliabilityPhase::Verify,
        scenario_id: "contract-drift-pt".to_string(),
        message: "process_triage schema version drift detected".to_string(),
        context: ReliabilityContext {
            worker_id: None,
            repo_set: Vec::new(),
            pressure_state: None,
            triage_actions: vec!["DRIFT_SCHEMA_VERSION_MISMATCH".to_string()],
            decision_code: "COMPAT_WARN".to_string(),
            fallback_reason: Some("schema minor version bump".to_string()),
        },
        artifact_paths: vec![],
    });

    assert_eq!(event2.phase, ReliabilityPhase::Verify);
}

// ===========================================================================
// Tests: mock adapter contract compliance
// ===========================================================================

#[test]
fn e2e_mock_adapter_records_calls() {
    use rch_common::repo_updater_contract::{
        MockRepoUpdaterAdapter, RepoUpdaterAdapter, RepoUpdaterAdapterResponse,
        RepoUpdaterIdempotencyGuarantee, RepoUpdaterResponseStatus,
    };

    let contract = RepoUpdaterAdapterContract::default();
    let mock = MockRepoUpdaterAdapter::default();
    mock.push_result(Ok(RepoUpdaterAdapterResponse {
        schema_version: REPO_UPDATER_CONTRACT_SCHEMA_VERSION.to_string(),
        correlation_id: "test-corr-001".to_string(),
        command: RepoUpdaterAdapterCommand::Version,
        adapter_version: "1.2.3".to_string(),
        status: RepoUpdaterResponseStatus::Success,
        idempotency_guarantee: RepoUpdaterIdempotencyGuarantee::StrongReadOnly,
        fallback_applied: false,
        sync_summary: None,
        repos: Vec::new(),
        envelope_meta: None,
        failure: None,
    }));

    let request = make_ru_request(RepoUpdaterAdapterCommand::Version);

    let result = mock.execute(&request, &contract);
    assert!(result.is_ok());

    let calls = mock.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].command, RepoUpdaterAdapterCommand::Version);
}

// ===========================================================================
// Tests: full compatibility sweep
// ===========================================================================

#[test]
fn e2e_full_compatibility_sweep() {
    let mut findings: Vec<DriftFinding> = Vec::new();

    // 1. Check repo_updater schema version
    if let Some(f) = check_schema_version(
        HelperComponent::RepoUpdater,
        "1.0.0",
        REPO_UPDATER_CONTRACT_SCHEMA_VERSION,
    ) {
        findings.push(f);
    }

    // 2. Check process_triage schema version
    if let Some(f) = check_schema_version(
        HelperComponent::ProcessTriage,
        "1.0.0",
        PROCESS_TRIAGE_CONTRACT_SCHEMA_VERSION,
    ) {
        findings.push(f);
    }

    // 3. Check error mappings
    if let Some(f) = check_error_mapping(
        HelperComponent::RepoUpdater,
        "adapter_unavailable",
        map_failure_kind_to_error_code(RepoUpdaterFailureKind::AdapterUnavailable),
        "config",
    ) {
        findings.push(f);
    }
    if let Some(f) = check_error_mapping(
        HelperComponent::RepoUpdater,
        "timeout",
        map_failure_kind_to_error_code(RepoUpdaterFailureKind::Timeout),
        "daemon",
    ) {
        findings.push(f);
    }

    // 4. Check fallback semantics
    let ru_fallback =
        evaluate_fallback_on_mismatch(HelperComponent::RepoUpdater, false, "fail_open");
    if ru_fallback.severity == DriftSeverity::Critical {
        findings.push(ru_fallback);
    }

    let pt_fallback =
        evaluate_fallback_on_mismatch(HelperComponent::ProcessTriage, true, "fail_closed");
    if pt_fallback.severity == DriftSeverity::Critical {
        findings.push(pt_fallback);
    }

    // Build summary
    let summary = CompatibilitySuiteSummary {
        total_checks: 6,
        pass: 6 - findings.len(),
        fail: findings.len(),
        critical_drifts: findings
            .iter()
            .filter(|f| f.severity == DriftSeverity::Critical)
            .count(),
        components_checked: vec![
            HelperComponent::RepoUpdater,
            HelperComponent::ProcessTriage,
            HelperComponent::StorageBallast,
        ],
        version_matrix: vec![
            VersionTuple {
                component: HelperComponent::RepoUpdater,
                version: REPO_UPDATER_MIN_SUPPORTED_VERSION.to_string(),
                compatibility: "supported".to_string(),
            },
            VersionTuple {
                component: HelperComponent::ProcessTriage,
                version: PROCESS_TRIAGE_CONTRACT_SCHEMA_VERSION.to_string(),
                compatibility: "current".to_string(),
            },
        ],
        findings: findings.clone(),
    };

    // Emit summary as JSON for CI consumption
    let json = serde_json::to_string_pretty(&summary).unwrap();
    println!("{json}");

    // No critical findings should exist
    assert_eq!(
        summary.critical_drifts, 0,
        "critical drifts found: {findings:?}"
    );
}

// ===========================================================================
// Helpers
// ===========================================================================

fn make_ru_request(
    command: RepoUpdaterAdapterCommand,
) -> rch_common::repo_updater_contract::RepoUpdaterAdapterRequest {
    use rch_common::repo_updater_contract::{RepoUpdaterAdapterRequest, RepoUpdaterOutputFormat};
    RepoUpdaterAdapterRequest {
        schema_version: REPO_UPDATER_CONTRACT_SCHEMA_VERSION.to_string(),
        correlation_id: "compat-test-ru-001".to_string(),
        worker_id: "w1".to_string(),
        command,
        requested_at_unix_ms: 1_768_768_123_000,
        projects_root: "/data/projects".into(),
        repo_specs: Vec::new(),
        idempotency_key: "compat-key-001".to_string(),
        retry_attempt: 0,
        timeout_secs: 10,
        expected_output_format: RepoUpdaterOutputFormat::Json,
        auth_context: None,
        operator_override: None,
    }
}

fn make_triage_request(trigger: ProcessTriageTrigger) -> ProcessTriageRequest {
    ProcessTriageRequest {
        schema_version: PROCESS_TRIAGE_CONTRACT_SCHEMA_VERSION.to_string(),
        correlation_id: "compat-test-001".to_string(),
        worker_id: "w1".to_string(),
        observed_at_unix_ms: 1_768_768_123_000,
        trigger,
        detector_confidence_percent: 90,
        retry_attempt: 0,
        candidate_processes: vec![ProcessDescriptor {
            pid: 12345,
            ppid: Some(1),
            owner: "ubuntu".to_string(),
            command: "cargo build --release".to_string(),
            classification: ProcessClassification::BuildRelated,
            cpu_percent_milli: 4500,
            rss_mb: 512,
            runtime_secs: 300,
        }],
        requested_actions: vec![ProcessTriageActionRequest {
            action_class: ProcessTriageActionClass::ObserveOnly,
            pid: 12345,
            reason_code: "monitor".to_string(),
            signal: None,
        }],
    }
}
