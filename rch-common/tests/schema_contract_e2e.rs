//! Schema Contract E2E Tests (bd-vvmd.6.8)
//!
//! Golden tests verifying JSON/log schema contracts for reliability outputs.
//! Covers:
//!   - API response envelope conformance (success/error)
//!   - Error payload structure across all categories
//!   - Hook protocol output variant stability
//!   - Reliability event schema versioning & backward compatibility
//!   - Error catalog completeness & category range invariants
//!   - Machine parser compatibility for emitted output artifacts
//!   - Legacy error code migration fidelity

use rch_common::api::schema::{
    generate_api_error_schema, generate_api_response_schema, generate_error_catalog,
};
use rch_common::api::{ApiError, ApiResponse, LegacyErrorCode, API_VERSION};
use rch_common::e2e::logging::{
    LogLevel, LogSource, ReliabilityContext, ReliabilityEventInput, ReliabilityPhase,
    ReliabilityPhaseEvent, TestLoggerBuilder, RELIABILITY_EVENT_SCHEMA_VERSION,
};
use rch_common::errors::catalog::{ErrorCategory, ErrorCode};
use rch_common::protocol::{HookInput, HookOutput};
use serde_json::Value;

// ===========================================================================
// 1. API Response Envelope Contract Tests
// ===========================================================================

#[test]
fn e2e_api_response_success_envelope_has_required_fields() {
    let response = ApiResponse::ok("workers list", vec!["worker-a", "worker-b"]);
    let json_str = serde_json::to_string(&response).unwrap();
    let val: Value = serde_json::from_str(&json_str).unwrap();

    assert_eq!(val["api_version"].as_str().unwrap(), API_VERSION);
    assert!(val["timestamp"].as_u64().unwrap() > 0);
    assert!(val["success"].as_bool().unwrap());
    assert!(val["data"].is_array());
    assert!(val.get("error").is_none() || val["error"].is_null());
    assert_eq!(val["command"].as_str().unwrap(), "workers list");
}

#[test]
fn e2e_api_response_error_envelope_has_required_fields() {
    let error = ApiError::from_code(ErrorCode::SshConnectionFailed)
        .with_message("Connection refused")
        .with_context("worker_id", "css")
        .with_context("host", "192.168.1.100");
    let response: ApiResponse<()> = ApiResponse::err("workers probe", error);
    let json_str = serde_json::to_string(&response).unwrap();
    let val: Value = serde_json::from_str(&json_str).unwrap();

    assert_eq!(val["api_version"].as_str().unwrap(), API_VERSION);
    assert!(val["timestamp"].as_u64().unwrap() > 0);
    assert!(!val["success"].as_bool().unwrap());
    assert!(val.get("data").is_none() || val["data"].is_null());

    let err = &val["error"];
    assert_eq!(err["code"].as_str().unwrap(), "RCH-E100");
    assert_eq!(err["category"].as_str().unwrap(), "network");
    assert!(err["message"].as_str().is_some());
    assert_eq!(err["details"].as_str().unwrap(), "Connection refused");
    assert!(err["remediation"].as_array().is_some());
    assert_eq!(err["context"]["worker_id"].as_str().unwrap(), "css");
    assert_eq!(err["context"]["host"].as_str().unwrap(), "192.168.1.100");
}

#[test]
fn e2e_api_response_empty_success_omits_data() {
    let response = ApiResponse::ok_empty("shutdown");
    let json_str = serde_json::to_string(&response).unwrap();
    let val: Value = serde_json::from_str(&json_str).unwrap();

    assert!(val["success"].as_bool().unwrap());
    assert!(val.get("data").is_none() || val["data"].is_null());
    assert!(val.get("error").is_none() || val["error"].is_null());
}

#[test]
fn e2e_api_response_with_request_id_preserves_correlation() {
    let response = ApiResponse::ok("status", "healthy").with_request_id("req-abc-123");
    let json_str = serde_json::to_string(&response).unwrap();
    let val: Value = serde_json::from_str(&json_str).unwrap();

    assert_eq!(val["request_id"].as_str().unwrap(), "req-abc-123");
}

#[test]
fn e2e_api_response_roundtrip_success() {
    #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
    struct WorkerInfo {
        id: String,
        slots: u32,
    }

    let original = ApiResponse::ok(
        "workers get",
        WorkerInfo {
            id: "css".to_string(),
            slots: 8,
        },
    );
    let json = serde_json::to_string(&original).unwrap();
    // Parse as generic Value to verify roundtrip (ApiResponse has 'static api_version)
    let val: Value = serde_json::from_str(&json).unwrap();

    assert!(val["success"].as_bool().unwrap());
    assert_eq!(val["data"]["id"].as_str().unwrap(), "css");
    assert_eq!(val["data"]["slots"].as_u64().unwrap(), 8);
    assert_eq!(val["api_version"].as_str().unwrap(), API_VERSION);
}

#[test]
fn e2e_api_response_roundtrip_error() {
    let error = ApiError::from_code(ErrorCode::ConfigNotFound)
        .with_message("~/.config/rch/config.toml not found");
    let original: ApiResponse<()> = ApiResponse::err("config show", error);
    let json = serde_json::to_string(&original).unwrap();
    // Parse as generic Value to verify roundtrip (ApiResponse has 'static api_version)
    let val: Value = serde_json::from_str(&json).unwrap();

    assert!(!val["success"].as_bool().unwrap());
    assert_eq!(val["error"]["code"].as_str().unwrap(), "RCH-E001");
    assert_eq!(val["error"]["category"].as_str().unwrap(), "config");
}

// ===========================================================================
// 2. Error Payload Contract Tests (all 6 categories)
// ===========================================================================

#[test]
fn e2e_error_payload_config_category_structure() {
    let error = ApiError::from_code(ErrorCode::ConfigNotFound);
    let json_str = serde_json::to_string(&error).unwrap();
    let val: Value = serde_json::from_str(&json_str).unwrap();

    assert_eq!(val["code"].as_str().unwrap(), "RCH-E001");
    assert_eq!(val["category"].as_str().unwrap(), "config");
    assert!(!val["message"].as_str().unwrap().is_empty());
    let remediation = val["remediation"].as_array().unwrap();
    assert!(!remediation.is_empty(), "config errors must have remediation");
}

#[test]
fn e2e_error_payload_network_category_structure() {
    let error = ApiError::from_code(ErrorCode::SshAuthFailed)
        .with_context("worker_id", "w1")
        .with_context("key_path", "~/.ssh/id_ed25519");
    let json_str = serde_json::to_string(&error).unwrap();
    let val: Value = serde_json::from_str(&json_str).unwrap();

    assert_eq!(val["code"].as_str().unwrap(), "RCH-E101");
    assert_eq!(val["category"].as_str().unwrap(), "network");
    assert_eq!(val["context"]["worker_id"].as_str().unwrap(), "w1");
}

#[test]
fn e2e_error_payload_worker_category_structure() {
    let error = ApiError::from_code(ErrorCode::WorkerAtCapacity).with_retry_after(30);
    let json_str = serde_json::to_string(&error).unwrap();
    let val: Value = serde_json::from_str(&json_str).unwrap();

    assert_eq!(val["code"].as_str().unwrap(), "RCH-E204");
    assert_eq!(val["category"].as_str().unwrap(), "worker");
    assert_eq!(val["retry_after_secs"].as_u64().unwrap(), 30);
}

#[test]
fn e2e_error_payload_build_category_structure() {
    let error = ApiError::from_code(ErrorCode::BuildCompilationFailed)
        .with_message("cargo build exited with code 101");
    let json_str = serde_json::to_string(&error).unwrap();
    let val: Value = serde_json::from_str(&json_str).unwrap();

    assert_eq!(val["code"].as_str().unwrap(), "RCH-E300");
    assert_eq!(val["category"].as_str().unwrap(), "build");
    assert!(val["details"]
        .as_str()
        .unwrap()
        .contains("exited with code 101"));
}

#[test]
fn e2e_error_payload_transfer_category_structure() {
    let error = ApiError::from_code(ErrorCode::TransferRsyncFailed)
        .with_context("src", "/data/projects/myapp")
        .with_context("dest", "worker:/home/user/myapp");
    let json_str = serde_json::to_string(&error).unwrap();
    let val: Value = serde_json::from_str(&json_str).unwrap();

    assert_eq!(val["code"].as_str().unwrap(), "RCH-E400");
    assert_eq!(val["category"].as_str().unwrap(), "transfer");
    assert_eq!(val["context"]["src"].as_str().unwrap(), "/data/projects/myapp");
}

#[test]
fn e2e_error_payload_internal_category_structure() {
    let error = ApiError::from_code(ErrorCode::InternalStateError)
        .with_message("unexpected state transition");
    let json_str = serde_json::to_string(&error).unwrap();
    let val: Value = serde_json::from_str(&json_str).unwrap();

    assert_eq!(val["code"].as_str().unwrap(), "RCH-E504");
    assert_eq!(val["category"].as_str().unwrap(), "internal");
}

#[test]
fn e2e_error_payload_disk_pressure_subcategory() {
    let error = ApiError::from_code(ErrorCode::WorkerDiskPressureCritical)
        .with_context("disk_free_gb", "3.2")
        .with_context("threshold_gb", "10.0");
    let json_str = serde_json::to_string(&error).unwrap();
    let val: Value = serde_json::from_str(&json_str).unwrap();

    assert_eq!(val["code"].as_str().unwrap(), "RCH-E210");
    assert_eq!(val["category"].as_str().unwrap(), "worker");
    assert_eq!(val["context"]["disk_free_gb"].as_str().unwrap(), "3.2");
}

#[test]
fn e2e_error_payload_process_triage_subcategory() {
    let error = ApiError::from_code(ErrorCode::ProcessTriagePolicyViolation)
        .with_context("action", "HardTerminate")
        .with_context("decision_code", "PT_BLOCK_DENYLIST");
    let json_str = serde_json::to_string(&error).unwrap();
    let val: Value = serde_json::from_str(&json_str).unwrap();

    assert_eq!(val["code"].as_str().unwrap(), "RCH-E312");
    assert_eq!(val["category"].as_str().unwrap(), "build");
    assert_eq!(val["context"]["action"].as_str().unwrap(), "HardTerminate");
    assert_eq!(val["context"]["decision_code"].as_str().unwrap(), "PT_BLOCK_DENYLIST");
}

#[test]
fn e2e_error_payload_cancellation_subcategory() {
    let error = ApiError::from_code(ErrorCode::CancelEscalatedKill)
        .with_context("pid", "12345")
        .with_context("timeout_ms", "5000");
    let json_str = serde_json::to_string(&error).unwrap();
    let val: Value = serde_json::from_str(&json_str).unwrap();

    assert_eq!(val["code"].as_str().unwrap(), "RCH-E321");
    assert_eq!(val["category"].as_str().unwrap(), "build");
}

// ===========================================================================
// 3. Hook Protocol Output Contract Tests
// ===========================================================================

#[test]
fn e2e_hook_protocol_allow_output_is_empty_object() {
    let output = HookOutput::allow();
    let json = serde_json::to_string(&output).unwrap();
    assert_eq!(json, "{}");
}

#[test]
fn e2e_hook_protocol_deny_output_structure() {
    let output = HookOutput::deny("remote build failed: exit code 101");
    let json = serde_json::to_string(&output).unwrap();
    let val: Value = serde_json::from_str(&json).unwrap();

    let hook_output = &val["hookSpecificOutput"];
    assert_eq!(
        hook_output["hookEventName"].as_str().unwrap(),
        "PreToolUse"
    );
    assert_eq!(
        hook_output["permissionDecision"].as_str().unwrap(),
        "deny"
    );
    assert_eq!(
        hook_output["permissionDecisionReason"].as_str().unwrap(),
        "remote build failed: exit code 101"
    );
}

#[test]
fn e2e_hook_protocol_allow_with_modified_command_structure() {
    let output = HookOutput::allow_with_modified_command("true");
    let json = serde_json::to_string(&output).unwrap();
    let val: Value = serde_json::from_str(&json).unwrap();

    let hook_output = &val["hookSpecificOutput"];
    assert_eq!(
        hook_output["hookEventName"].as_str().unwrap(),
        "PreToolUse"
    );
    assert_eq!(
        hook_output["permissionDecision"].as_str().unwrap(),
        "allow"
    );
    let updated = &hook_output["updatedInput"];
    assert_eq!(updated["command"].as_str().unwrap(), "true");
}

#[test]
fn e2e_hook_protocol_input_parsing_contract() {
    // Verify the exact shape Claude Code sends to the hook
    let payload = serde_json::json!({
        "tool_name": "Bash",
        "tool_input": {
            "command": "cargo build --release",
            "description": "Build in release mode"
        },
        "session_id": "session-xyz-789"
    });

    let input: HookInput = serde_json::from_value(payload).unwrap();
    assert_eq!(input.tool_name, "Bash");
    assert_eq!(input.tool_input.command, "cargo build --release");
    assert_eq!(
        input.tool_input.description.as_deref(),
        Some("Build in release mode")
    );
    assert_eq!(input.session_id.as_deref(), Some("session-xyz-789"));
}

#[test]
fn e2e_hook_protocol_input_minimal_contract() {
    // Minimal payload: only required fields
    let payload = serde_json::json!({
        "tool_name": "Bash",
        "tool_input": { "command": "ls" }
    });

    let input: HookInput = serde_json::from_value(payload).unwrap();
    assert_eq!(input.tool_name, "Bash");
    assert_eq!(input.tool_input.command, "ls");
    assert!(input.tool_input.description.is_none());
    assert!(input.session_id.is_none());
}

// ===========================================================================
// 4. Reliability Event Schema Contract Tests
// ===========================================================================

#[test]
fn e2e_reliability_event_schema_version_is_stable() {
    assert_eq!(RELIABILITY_EVENT_SCHEMA_VERSION, "1.0.0");
}

#[test]
fn e2e_reliability_event_all_phases_roundtrip() {
    let phases = [
        ReliabilityPhase::Setup,
        ReliabilityPhase::Execute,
        ReliabilityPhase::Verify,
        ReliabilityPhase::Cleanup,
    ];

    for phase in phases {
        let event = ReliabilityPhaseEvent {
            schema_version: RELIABILITY_EVENT_SCHEMA_VERSION.to_string(),
            timestamp: chrono::Utc::now(),
            elapsed_ms: 42,
            level: LogLevel::Info,
            phase,
            scenario_id: format!("scenario-{phase}"),
            message: format!("{phase} completed"),
            context: ReliabilityContext::decision_only("TEST_OK"),
            artifact_paths: vec![],
        };

        let json = serde_json::to_string(&event).unwrap();
        let parsed: ReliabilityPhaseEvent = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.schema_version, "1.0.0");
        assert_eq!(parsed.phase, phase);
        assert_eq!(parsed.context.decision_code, "TEST_OK");
    }
}

#[test]
fn e2e_reliability_event_backward_compat_with_all_optional_context() {
    // Verify events with all optional context fields populated parse correctly
    let json = serde_json::json!({
        "schema_version": "1.0.0",
        "timestamp": "2026-02-20T12:00:00Z",
        "elapsed_ms": 100,
        "level": "warn",
        "phase": "execute",
        "scenario_id": "scenario-convergence",
        "message": "partial update detected",
        "context": {
            "worker_id": "worker-css",
            "repo_set": ["/data/projects/repo-a", "/dp/repo-b"],
            "pressure_state": "disk:warning,memory:normal",
            "triage_actions": ["trim-cache", "soft-terminate-stale"],
            "decision_code": "PARTIAL_UPDATE",
            "fallback_reason": "adapter-timeout"
        },
        "artifact_paths": ["/tmp/trace.json", "/tmp/snapshot.txt"]
    });

    let event: ReliabilityPhaseEvent = serde_json::from_value(json).unwrap();
    assert_eq!(event.schema_version, "1.0.0");
    assert_eq!(event.phase, ReliabilityPhase::Execute);
    assert_eq!(event.level, LogLevel::Warn);
    assert_eq!(
        event.context.worker_id.as_deref(),
        Some("worker-css")
    );
    assert_eq!(event.context.repo_set.len(), 2);
    assert_eq!(
        event.context.pressure_state.as_deref(),
        Some("disk:warning,memory:normal")
    );
    assert_eq!(event.context.triage_actions.len(), 2);
    assert_eq!(event.context.decision_code, "PARTIAL_UPDATE");
    assert_eq!(
        event.context.fallback_reason.as_deref(),
        Some("adapter-timeout")
    );
    assert_eq!(event.artifact_paths.len(), 2);
}

#[test]
fn e2e_reliability_event_minimal_context_parses() {
    // Verify event with minimal context (only required decision_code) parses
    let json = serde_json::json!({
        "schema_version": "1.0.0",
        "timestamp": "2026-02-20T12:00:00Z",
        "elapsed_ms": 0,
        "level": "info",
        "phase": "setup",
        "scenario_id": "scenario-minimal",
        "message": "setup ok",
        "context": {
            "worker_id": null,
            "repo_set": [],
            "pressure_state": null,
            "triage_actions": [],
            "decision_code": "SETUP_OK",
            "fallback_reason": null
        },
        "artifact_paths": []
    });

    let event: ReliabilityPhaseEvent = serde_json::from_value(json).unwrap();
    assert_eq!(event.context.decision_code, "SETUP_OK");
    assert!(event.context.worker_id.is_none());
    assert!(event.context.repo_set.is_empty());
    assert!(event.context.triage_actions.is_empty());
    assert!(event.artifact_paths.is_empty());
}

#[test]
fn e2e_reliability_event_logger_emits_correct_schema() {
    let temp_dir = tempfile::tempdir().expect("temp dir");
    let logger = TestLoggerBuilder::new("schema_contract_test")
        .log_dir(temp_dir.path())
        .print_realtime(false)
        .build();

    let event = logger.log_reliability_event(ReliabilityEventInput {
        level: LogLevel::Info,
        phase: ReliabilityPhase::Verify,
        scenario_id: "schema-golden-test".to_string(),
        message: "verification complete".to_string(),
        context: ReliabilityContext {
            worker_id: Some("css".to_string()),
            repo_set: vec!["/data/projects/rch".to_string()],
            pressure_state: Some("healthy".to_string()),
            triage_actions: vec![],
            decision_code: "VERIFY_PASS".to_string(),
            fallback_reason: None,
        },
        artifact_paths: vec!["/tmp/report.json".to_string()],
    });

    assert_eq!(event.schema_version, RELIABILITY_EVENT_SCHEMA_VERSION);
    assert_eq!(event.phase, ReliabilityPhase::Verify);
    assert_eq!(event.scenario_id, "schema-golden-test");
    assert_eq!(event.context.decision_code, "VERIFY_PASS");
    assert_eq!(event.artifact_paths.len(), 1);

    // Verify JSONL file was written and parses back
    if let Some(rel_path) = logger.reliability_log_path() {
        let contents = std::fs::read_to_string(rel_path).unwrap();
        let first_line = contents.lines().next().unwrap();
        let parsed: ReliabilityPhaseEvent = serde_json::from_str(first_line).unwrap();
        assert_eq!(parsed.schema_version, "1.0.0");
        assert_eq!(parsed.phase, ReliabilityPhase::Verify);
        assert_eq!(parsed.context.worker_id, Some("css".to_string()));
    }
}

#[test]
fn e2e_reliability_event_decision_only_constructor() {
    let ctx = ReliabilityContext::decision_only("REMOTE_OK");
    assert_eq!(ctx.decision_code, "REMOTE_OK");
    assert!(ctx.worker_id.is_none());
    assert!(ctx.repo_set.is_empty());
    assert!(ctx.pressure_state.is_none());
    assert!(ctx.triage_actions.is_empty());
    assert!(ctx.fallback_reason.is_none());
}

// ===========================================================================
// 5. Error Catalog Completeness & Category Range Invariants
// ===========================================================================

#[test]
fn e2e_error_catalog_covers_all_error_codes() {
    let catalog = generate_error_catalog();
    let all_codes = ErrorCode::all();

    assert_eq!(
        catalog.errors.len(),
        all_codes.len(),
        "catalog must include every ErrorCode variant"
    );

    for (i, code) in all_codes.iter().enumerate() {
        assert_eq!(
            catalog.errors[i].code,
            code.code_string(),
            "catalog entry {i} must match ErrorCode::all() ordering"
        );
    }
}

#[test]
fn e2e_error_catalog_has_six_categories() {
    let catalog = generate_error_catalog();
    assert_eq!(catalog.categories.len(), 6);

    let expected = [
        ("config", "001-099"),
        ("network", "100-199"),
        ("worker", "200-299"),
        ("build", "300-399"),
        ("transfer", "400-499"),
        ("internal", "500-599"),
    ];

    for (id, range) in expected {
        let cat = catalog
            .categories
            .iter()
            .find(|c| c.id == id)
            .unwrap_or_else(|| panic!("missing category: {id}"));
        assert_eq!(
            cat.code_range, range,
            "category {id} must have range {range}"
        );
    }
}

#[test]
fn e2e_error_catalog_category_range_invariants() {
    // Every error code must fall within its declared category range
    for code in ErrorCode::all() {
        let num = code.code_number();
        let cat = code.category();
        let (min, max) = match cat {
            ErrorCategory::Config => (1, 99),
            ErrorCategory::Network => (100, 199),
            ErrorCategory::Worker => (200, 299),
            ErrorCategory::Build => (300, 399),
            ErrorCategory::Transfer => (400, 499),
            ErrorCategory::Internal => (500, 599),
        };
        assert!(
            num >= min && num <= max,
            "ErrorCode {} (num={}) must be in range [{}, {}] for category {:?}",
            code.code_string(),
            num,
            min,
            max,
            cat,
        );
    }
}

#[test]
fn e2e_error_catalog_no_duplicate_codes() {
    let all_codes = ErrorCode::all();
    let mut seen = std::collections::HashSet::new();
    for code in all_codes {
        let num = code.code_number();
        assert!(
            seen.insert(num),
            "duplicate error code number: {} ({})",
            num,
            code.code_string()
        );
    }
}

#[test]
fn e2e_error_catalog_all_have_nonempty_message() {
    for code in ErrorCode::all() {
        let msg = code.message();
        assert!(
            !msg.is_empty(),
            "ErrorCode {} must have a non-empty message",
            code.code_string()
        );
    }
}

#[test]
fn e2e_error_catalog_serialization_roundtrip() {
    let catalog = generate_error_catalog();
    let json = serde_json::to_string_pretty(&catalog).unwrap();

    // Parse as generic Value to verify structure
    let val: Value = serde_json::from_str(&json).unwrap();
    assert_eq!(val["schema_version"].as_str().unwrap(), "1.0");
    assert_eq!(val["api_version"].as_str().unwrap(), API_VERSION);
    assert!(val["categories"].as_array().unwrap().len() == 6);
    assert!(val["errors"].as_array().unwrap().len() > 50);

    // Roundtrip back to typed struct
    let parsed: rch_common::api::schema::ErrorCatalog = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.errors.len(), catalog.errors.len());
}

// ===========================================================================
// 6. JSON Schema Generation Contract Tests
// ===========================================================================

#[test]
fn e2e_api_response_schema_has_required_properties() {
    let schema = generate_api_response_schema();
    let json = serde_json::to_value(&schema).unwrap();

    // The root schema should define key properties
    let json_str = serde_json::to_string(&json).unwrap();
    assert!(json_str.contains("api_version"), "schema must include api_version");
    assert!(json_str.contains("success"), "schema must include success");
    assert!(json_str.contains("timestamp"), "schema must include timestamp");
}

#[test]
fn e2e_api_error_schema_has_required_properties() {
    let schema = generate_api_error_schema();
    let json_str = serde_json::to_string(&schema).unwrap();

    assert!(json_str.contains("code"), "schema must include code");
    assert!(
        json_str.contains("category"),
        "schema must include category"
    );
    assert!(json_str.contains("message"), "schema must include message");
    assert!(
        json_str.contains("remediation"),
        "schema must include remediation"
    );
}

#[test]
fn e2e_schema_export_produces_valid_json() {
    let temp_dir = tempfile::tempdir().expect("temp dir");
    let result = rch_common::api::schema::export_schemas(temp_dir.path()).unwrap();

    assert_eq!(result.files_generated, 3);

    for file_path in &result.files {
        let content = std::fs::read_to_string(file_path).unwrap();
        let _: Value = serde_json::from_str(&content)
            .unwrap_or_else(|e| panic!("invalid JSON in {file_path}: {e}"));
    }
}

// ===========================================================================
// 7. Legacy Error Code Migration Contract Tests
// ===========================================================================

#[test]
fn e2e_legacy_code_migration_all_map_to_valid_modern_codes() {
    let legacy_mappings = [
        ("WORKER_UNREACHABLE", "RCH-E100"),
        ("WORKER_NOT_FOUND", "RCH-E008"),
        ("CONFIG_INVALID", "RCH-E004"),
        ("CONFIG_NOT_FOUND", "RCH-E001"),
        ("DAEMON_NOT_RUNNING", "RCH-E502"),
        ("DAEMON_CONNECTION_FAILED", "RCH-E500"),
        ("SSH_CONNECTION_FAILED", "RCH-E100"),
        ("BENCHMARK_FAILED", "RCH-E203"),
        ("HOOK_INSTALL_FAILED", "RCH-E506"),
        ("INTERNAL_ERROR", "RCH-E504"),
    ];

    for (legacy_str, expected_modern) in legacy_mappings {
        let parsed = LegacyErrorCode::parse(legacy_str)
            .unwrap_or_else(|| panic!("failed to parse legacy code: {legacy_str}"));
        let modern = parsed.to_error_code();
        assert_eq!(
            modern.code_string(),
            expected_modern,
            "legacy {legacy_str} -> expected {expected_modern}, got {}",
            modern.code_string()
        );
    }
}

#[test]
fn e2e_legacy_code_roundtrip_through_api_error() {
    // Verify legacy codes produce correct ApiError via LegacyErrorCode
    let legacy = LegacyErrorCode::parse("WORKER_UNREACHABLE").unwrap();
    let error = ApiError::new(legacy.to_error_code(), "Connection refused to worker-1");
    assert_eq!(error.code, "RCH-E100");
    assert_eq!(error.category, ErrorCategory::Network);
    assert_eq!(
        error.details,
        Some("Connection refused to worker-1".to_string())
    );
}

#[test]
fn e2e_legacy_unknown_code_falls_back_to_internal() {
    // Unknown legacy codes should return None from parse
    let parsed = LegacyErrorCode::parse("TOTALLY_UNKNOWN_CODE");
    assert!(parsed.is_none());

    // Using default fallback: InternalStateError
    let fallback_code = parsed
        .map(|l| l.to_error_code())
        .unwrap_or(ErrorCode::InternalStateError);
    let error = ApiError::new(fallback_code, "mystery error");
    assert_eq!(error.code, "RCH-E504");
    assert_eq!(error.category, ErrorCategory::Internal);
}

// ===========================================================================
// 8. Machine Parser Compatibility Tests
// ===========================================================================

#[test]
fn e2e_machine_parser_can_extract_error_code_from_response() {
    // Simulate what an external parser (e.g., agent, CI script) would do
    let error = ApiError::from_code(ErrorCode::TransferTimeout)
        .with_context("timeout_secs", "120");
    let response: ApiResponse<()> = ApiResponse::err("exec", error);
    let json = serde_json::to_string(&response).unwrap();

    // Parse as generic Value (no internal types)
    let val: Value = serde_json::from_str(&json).unwrap();

    let success = val["success"].as_bool().unwrap();
    assert!(!success);

    let error_code = val["error"]["code"].as_str().unwrap();
    assert!(error_code.starts_with("RCH-E"));

    let category = val["error"]["category"].as_str().unwrap();
    assert!(
        ["config", "network", "worker", "build", "transfer", "internal"].contains(&category)
    );

    let empty_vec = vec![];
    let remediation = val["error"]["remediation"]
        .as_array()
        .unwrap_or(&empty_vec);
    for step in remediation {
        assert!(step.as_str().is_some(), "remediation steps must be strings");
    }
}

#[test]
fn e2e_machine_parser_can_extract_hook_decision() {
    // Parse deny output as generic JSON
    let output = HookOutput::deny("command blocked: not a build command");
    let json = serde_json::to_string(&output).unwrap();
    let val: Value = serde_json::from_str(&json).unwrap();

    let decision = val["hookSpecificOutput"]["permissionDecision"]
        .as_str()
        .unwrap();
    assert_eq!(decision, "deny");

    let reason = val["hookSpecificOutput"]["permissionDecisionReason"]
        .as_str()
        .unwrap();
    assert!(!reason.is_empty());
}

#[test]
fn e2e_machine_parser_can_extract_reliability_event_fields() {
    // Parse reliability event as generic JSON
    let event = ReliabilityPhaseEvent {
        schema_version: RELIABILITY_EVENT_SCHEMA_VERSION.to_string(),
        timestamp: chrono::Utc::now(),
        elapsed_ms: 500,
        level: LogLevel::Error,
        phase: ReliabilityPhase::Execute,
        scenario_id: "scenario-disk-pressure".to_string(),
        message: "disk pressure critical during build".to_string(),
        context: ReliabilityContext {
            worker_id: Some("worker-css".to_string()),
            repo_set: vec!["/data/projects/rch".to_string()],
            pressure_state: Some("critical".to_string()),
            triage_actions: vec!["evict-cache".to_string()],
            decision_code: "PRESSURE_CRITICAL".to_string(),
            fallback_reason: Some("disk-full".to_string()),
        },
        artifact_paths: vec!["/tmp/pressure-snapshot.json".to_string()],
    };

    let json = serde_json::to_string(&event).unwrap();
    let val: Value = serde_json::from_str(&json).unwrap();

    // Extract fields like a machine parser would
    assert_eq!(val["schema_version"].as_str().unwrap(), "1.0.0");
    assert!(val["timestamp"].as_str().is_some());
    assert_eq!(val["level"].as_str().unwrap(), "error");
    assert_eq!(val["phase"].as_str().unwrap(), "execute");
    assert_eq!(val["scenario_id"].as_str().unwrap(), "scenario-disk-pressure");
    assert_eq!(
        val["context"]["decision_code"].as_str().unwrap(),
        "PRESSURE_CRITICAL"
    );
    assert_eq!(
        val["context"]["pressure_state"].as_str().unwrap(),
        "critical"
    );
    assert_eq!(val["context"]["triage_actions"].as_array().unwrap().len(), 1);
    assert_eq!(val["artifact_paths"].as_array().unwrap().len(), 1);
}

// ===========================================================================
// 9. Log Entry JSONL Conformance Tests
// ===========================================================================

#[test]
fn e2e_log_entry_jsonl_format_conformance() {
    let temp_dir = tempfile::tempdir().expect("temp dir");
    let logger = TestLoggerBuilder::new("jsonl_conformance")
        .log_dir(temp_dir.path())
        .print_realtime(false)
        .build();

    logger.info("first message");
    logger.warn("second message");
    logger.log_with_context(
        LogLevel::Error,
        LogSource::Worker {
            id: "css".to_string(),
        },
        "third message",
        vec![("key".to_string(), "value".to_string())],
    );

    drop(logger);

    // Find and read the log file
    let entries: Vec<_> = std::fs::read_dir(temp_dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            name.starts_with("jsonl_conformance") && name.ends_with(".jsonl")
        })
        .collect();

    assert!(!entries.is_empty(), "should have created a JSONL log file");

    let contents = std::fs::read_to_string(entries[0].path()).unwrap();
    let lines: Vec<&str> = contents.lines().collect();
    assert_eq!(lines.len(), 3, "should have 3 log lines");

    // Each line must be valid JSON with required fields
    for (i, line) in lines.iter().enumerate() {
        let val: Value = serde_json::from_str(line)
            .unwrap_or_else(|e| panic!("line {i} is not valid JSON: {e}"));
        assert!(
            val["timestamp"].as_str().is_some(),
            "line {i}: missing timestamp"
        );
        assert!(
            val["elapsed_ms"].as_u64().is_some(),
            "line {i}: missing elapsed_ms"
        );
        assert!(val["level"].as_str().is_some(), "line {i}: missing level");
        assert!(
            val["message"].as_str().is_some(),
            "line {i}: missing message"
        );
        // source is an object (tagged enum)
        assert!(
            val.get("source").is_some(),
            "line {i}: missing source"
        );
    }

    // Verify the third line has context
    let third: Value = serde_json::from_str(lines[2]).unwrap();
    let ctx = third["context"].as_array().unwrap();
    assert_eq!(ctx.len(), 1);
    assert_eq!(ctx[0][0].as_str().unwrap(), "key");
    assert_eq!(ctx[0][1].as_str().unwrap(), "value");
}

// ===========================================================================
// 10. Cross-Schema Consistency Tests
// ===========================================================================

#[test]
fn e2e_error_code_string_format_is_consistent() {
    // All error codes must follow RCH-Exxx pattern (3 digits, zero-padded)
    let re = regex::Regex::new(r"^RCH-E\d{3}$").unwrap();
    for code in ErrorCode::all() {
        let code_str = code.code_string();
        assert!(
            re.is_match(&code_str),
            "ErrorCode string '{}' does not match RCH-Exxx format",
            code_str
        );
    }
}

#[test]
fn e2e_api_error_from_code_roundtrips_through_json() {
    // For every error code, verify ApiError -> JSON -> parse preserves code/category
    for code in ErrorCode::all() {
        let error = ApiError::from_code(*code);
        let json = serde_json::to_string(&error).unwrap();
        let parsed: ApiError = serde_json::from_str(&json).unwrap();

        assert_eq!(
            parsed.code,
            error.code,
            "code mismatch for {:?}",
            code
        );
        assert_eq!(
            parsed.category,
            error.category,
            "category mismatch for {:?}",
            code
        );
        assert_eq!(
            parsed.message,
            error.message,
            "message mismatch for {:?}",
            code
        );
    }
}

#[test]
fn e2e_api_version_matches_catalog_api_version() {
    let catalog = generate_error_catalog();
    assert_eq!(
        catalog.api_version, API_VERSION,
        "catalog api_version must match API_VERSION constant"
    );
}
