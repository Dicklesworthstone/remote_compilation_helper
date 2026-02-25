//! Deterministic Replay Workflow E2E Tests (bd-vvmd.7.12)
//!
//! Tests for replaying failed reliability scenarios from captured artifact bundles.
//! Validates:
//!   - Scenario bundle capture and reconstruction
//!   - Schema/version compatibility checks before replay
//!   - Side-by-side original-vs-replay decision trace comparison
//!   - Partial bundle corruption handling
//!   - Non-determinism detection paths

use rch_common::e2e::harness::{
    ReliabilityCommandRecord, ReliabilityFailureHook, ReliabilityFailureHookFlags,
    ReliabilityLifecycleCommand, ReliabilityScenarioReport, ReliabilityScenarioSpec,
};
use rch_common::e2e::logging::{
    LogLevel, RELIABILITY_EVENT_SCHEMA_VERSION, ReliabilityContext, ReliabilityEventInput,
    ReliabilityPhase, TestLoggerBuilder,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ===========================================================================
// Replay bundle types
// ===========================================================================

/// A captured scenario bundle for deterministic replay.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ReplayBundle {
    /// Bundle format version.
    schema_version: String,
    /// Original scenario spec.
    scenario_spec: ReliabilityScenarioSpec,
    /// Original execution report.
    original_report: ReliabilityScenarioReport,
    /// Decision trace from original run.
    decision_trace: Vec<DecisionTraceEntry>,
    /// Environment snapshot at time of capture.
    env_snapshot: EnvironmentSnapshot,
    /// Artifact manifest (paths and hashes).
    artifact_manifest: Vec<ArtifactEntry>,
}

/// Single decision point recorded during a scenario run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct DecisionTraceEntry {
    phase: ReliabilityPhase,
    step_index: usize,
    decision_code: String,
    context: HashMap<String, String>,
    timestamp_offset_ms: u64,
}

/// Environment snapshot for replay compatibility checks.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct EnvironmentSnapshot {
    schema_version: String,
    toolchain: String,
    os_version: String,
    worker_id: Option<String>,
    env_vars: HashMap<String, String>,
}

/// Artifact entry in the bundle manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ArtifactEntry {
    name: String,
    path: String,
    hash: String,
    size_bytes: u64,
}

/// Result of a replay comparison.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ReplayComparisonResult {
    bundle_id: String,
    replay_success: bool,
    decisions_match: bool,
    divergence_points: Vec<DivergencePoint>,
    compatibility_issues: Vec<String>,
}

/// A point where replay diverged from original.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct DivergencePoint {
    phase: ReliabilityPhase,
    step_index: usize,
    original_decision: String,
    replay_decision: String,
    likely_cause: String,
}

// ===========================================================================
// Replay logic
// ===========================================================================

/// Check bundle schema/version compatibility before replay.
fn check_bundle_compatibility(bundle: &ReplayBundle, current_schema: &str) -> Vec<String> {
    let mut issues = Vec::new();

    if bundle.schema_version != current_schema {
        issues.push(format!(
            "bundle schema version '{}' differs from current '{}'",
            bundle.schema_version, current_schema
        ));
    }

    if bundle.original_report.schema_version != current_schema {
        issues.push(format!(
            "report schema version '{}' differs from current '{}'",
            bundle.original_report.schema_version, current_schema
        ));
    }

    if bundle.env_snapshot.schema_version != current_schema {
        issues.push(format!(
            "env snapshot schema version '{}' differs from current '{}'",
            bundle.env_snapshot.schema_version, current_schema
        ));
    }

    issues
}

/// Simulate replaying a scenario and producing a decision trace.
fn simulate_replay(
    spec: &ReliabilityScenarioSpec,
    inject_nondeterminism: bool,
) -> Vec<DecisionTraceEntry> {
    let mut trace = Vec::new();
    let mut offset_ms = 0u64;

    // Setup phase
    for (i, cmd) in spec.lifecycle.pre_checks.iter().enumerate() {
        let decision = if inject_nondeterminism && i == 0 {
            "REPLAY_SETUP_DIVERGED".to_string()
        } else {
            "SETUP_OK".to_string()
        };

        trace.push(DecisionTraceEntry {
            phase: ReliabilityPhase::Setup,
            step_index: i,
            decision_code: decision,
            context: {
                let mut m = HashMap::new();
                m.insert("command".to_string(), cmd.name.clone());
                m
            },
            timestamp_offset_ms: offset_ms,
        });
        offset_ms += 50;
    }

    // Execute phase
    for (i, cmd) in spec.execute_commands.iter().enumerate() {
        let decision = if inject_nondeterminism && i == 0 {
            "REPLAY_EXEC_DIVERGED".to_string()
        } else {
            "EXEC_OK".to_string()
        };

        trace.push(DecisionTraceEntry {
            phase: ReliabilityPhase::Execute,
            step_index: i,
            decision_code: decision,
            context: {
                let mut m = HashMap::new();
                m.insert("command".to_string(), cmd.name.clone());
                m
            },
            timestamp_offset_ms: offset_ms,
        });
        offset_ms += 200;
    }

    // Verify phase
    for (i, cmd) in spec.lifecycle.post_checks.iter().enumerate() {
        trace.push(DecisionTraceEntry {
            phase: ReliabilityPhase::Verify,
            step_index: i,
            decision_code: "VERIFY_OK".to_string(),
            context: {
                let mut m = HashMap::new();
                m.insert("command".to_string(), cmd.name.clone());
                m
            },
            timestamp_offset_ms: offset_ms,
        });
        offset_ms += 30;
    }

    // Cleanup phase
    trace.push(DecisionTraceEntry {
        phase: ReliabilityPhase::Cleanup,
        step_index: 0,
        decision_code: "CLEANUP_OK".to_string(),
        context: HashMap::new(),
        timestamp_offset_ms: offset_ms,
    });

    trace
}

/// Compare original and replay decision traces.
fn compare_traces(
    original: &[DecisionTraceEntry],
    replay: &[DecisionTraceEntry],
) -> Vec<DivergencePoint> {
    let mut divergences = Vec::new();

    let max_len = original.len().max(replay.len());
    for i in 0..max_len {
        match (original.get(i), replay.get(i)) {
            (Some(orig), Some(rep)) => {
                if orig.decision_code != rep.decision_code {
                    divergences.push(DivergencePoint {
                        phase: orig.phase,
                        step_index: orig.step_index,
                        original_decision: orig.decision_code.clone(),
                        replay_decision: rep.decision_code.clone(),
                        likely_cause: if orig.phase == ReliabilityPhase::Setup {
                            "environment state differs at setup time".to_string()
                        } else {
                            "non-deterministic execution path".to_string()
                        },
                    });
                }
            }
            (Some(orig), None) => {
                divergences.push(DivergencePoint {
                    phase: orig.phase,
                    step_index: orig.step_index,
                    original_decision: orig.decision_code.clone(),
                    replay_decision: "<missing>".to_string(),
                    likely_cause: "replay trace shorter than original".to_string(),
                });
            }
            (None, Some(rep)) => {
                divergences.push(DivergencePoint {
                    phase: rep.phase,
                    step_index: rep.step_index,
                    original_decision: "<missing>".to_string(),
                    replay_decision: rep.decision_code.clone(),
                    likely_cause: "replay trace longer than original".to_string(),
                });
            }
            (None, None) => break,
        }
    }

    divergences
}

/// Build a sample scenario spec for replay tests.
fn build_sample_spec(scenario_id: &str) -> ReliabilityScenarioSpec {
    ReliabilityScenarioSpec::new(scenario_id)
        .with_worker_id("css")
        .with_repo_set(["/data/projects/rch"])
        .with_pressure_state("disk:normal,memory:normal")
        .add_pre_check(ReliabilityLifecycleCommand::new(
            "disk-check",
            "echo",
            ["df -h"],
        ))
        .add_pre_check(ReliabilityLifecycleCommand::new(
            "env-check",
            "echo",
            ["env"],
        ))
        .add_execute_command(
            ReliabilityLifecycleCommand::new("build", "echo", ["cargo build"])
                .with_timeout_secs(300),
        )
        .add_execute_command(
            ReliabilityLifecycleCommand::new("test", "echo", ["cargo test"]).with_timeout_secs(600),
        )
        .add_post_check(ReliabilityLifecycleCommand::new(
            "verify-artifacts",
            "echo",
            ["ls target/"],
        ))
}

/// Build a sample report from a decision trace.
fn build_sample_report(
    scenario_id: &str,
    trace: &[DecisionTraceEntry],
) -> ReliabilityScenarioReport {
    let command_records: Vec<ReliabilityCommandRecord> = trace
        .iter()
        .map(|t| ReliabilityCommandRecord {
            phase: t.phase,
            stage: format!("{:?}", t.phase).to_lowercase(),
            command_name: t
                .context
                .get("command")
                .cloned()
                .unwrap_or_else(|| "cleanup".to_string()),
            invoked_program: "echo".to_string(),
            invoked_args: vec!["test".to_string()],
            exit_code: if t.decision_code.contains("OK") { 0 } else { 1 },
            duration_ms: 100,
            required_success: true,
            succeeded: t.decision_code.contains("OK"),
            artifact_paths: vec![],
        })
        .collect();

    ReliabilityScenarioReport {
        schema_version: RELIABILITY_EVENT_SCHEMA_VERSION.to_string(),
        scenario_id: scenario_id.to_string(),
        phase_order: vec![
            ReliabilityPhase::Setup,
            ReliabilityPhase::Execute,
            ReliabilityPhase::Verify,
            ReliabilityPhase::Cleanup,
        ],
        activated_failure_hooks: vec![],
        command_records,
        artifact_paths: vec![],
        manifest_path: None,
    }
}

/// Build a sample replay bundle.
fn build_sample_bundle(scenario_id: &str) -> ReplayBundle {
    let spec = build_sample_spec(scenario_id);
    let trace = simulate_replay(&spec, false);
    let report = build_sample_report(scenario_id, &trace);

    ReplayBundle {
        schema_version: RELIABILITY_EVENT_SCHEMA_VERSION.to_string(),
        scenario_spec: spec,
        original_report: report,
        decision_trace: trace,
        env_snapshot: EnvironmentSnapshot {
            schema_version: RELIABILITY_EVENT_SCHEMA_VERSION.to_string(),
            toolchain: "rustc-1.85.0".to_string(),
            os_version: "Linux 6.17.0".to_string(),
            worker_id: Some("css".to_string()),
            env_vars: {
                let mut m = HashMap::new();
                m.insert(
                    "CARGO_TARGET_DIR".to_string(),
                    "/data/tmp/cargo-target".to_string(),
                );
                m.insert("HOME".to_string(), "/home/ubuntu".to_string());
                m
            },
        },
        artifact_manifest: vec![ArtifactEntry {
            name: "build-log".to_string(),
            path: "/tmp/build.log".to_string(),
            hash: "sha256:abc123".to_string(),
            size_bytes: 4096,
        }],
    }
}

// ===========================================================================
// 1. Bundle Capture & Reconstruction
// ===========================================================================

#[test]
fn e2e_replay_bundle_capture_roundtrip() {
    let bundle = build_sample_bundle("replay-roundtrip");

    let json = serde_json::to_string_pretty(&bundle).unwrap();
    let parsed: ReplayBundle = serde_json::from_str(&json).unwrap();

    assert_eq!(parsed.schema_version, RELIABILITY_EVENT_SCHEMA_VERSION);
    assert_eq!(parsed.scenario_spec.scenario_id, "replay-roundtrip");
    assert_eq!(parsed.original_report.scenario_id, "replay-roundtrip");
    assert!(!parsed.decision_trace.is_empty());
    assert_eq!(parsed.env_snapshot.toolchain, "rustc-1.85.0");
    assert_eq!(parsed.artifact_manifest.len(), 1);
}

#[test]
fn e2e_replay_bundle_contains_all_phases() {
    let bundle = build_sample_bundle("replay-phases");

    let phases: Vec<ReliabilityPhase> = bundle.decision_trace.iter().map(|t| t.phase).collect();

    assert!(phases.contains(&ReliabilityPhase::Setup));
    assert!(phases.contains(&ReliabilityPhase::Execute));
    assert!(phases.contains(&ReliabilityPhase::Verify));
    assert!(phases.contains(&ReliabilityPhase::Cleanup));
}

#[test]
fn e2e_replay_bundle_decision_trace_ordered() {
    let bundle = build_sample_bundle("replay-ordered");

    // Timestamps should be monotonically increasing
    for window in bundle.decision_trace.windows(2) {
        assert!(
            window[1].timestamp_offset_ms >= window[0].timestamp_offset_ms,
            "decision trace timestamps should be monotonically increasing"
        );
    }
}

// ===========================================================================
// 2. Schema/Version Compatibility Checks
// ===========================================================================

#[test]
fn e2e_replay_compatibility_check_matching_versions() {
    let bundle = build_sample_bundle("replay-compat-ok");
    let issues = check_bundle_compatibility(&bundle, RELIABILITY_EVENT_SCHEMA_VERSION);
    assert!(
        issues.is_empty(),
        "compatible bundle should have no issues: {:?}",
        issues
    );
}

#[test]
fn e2e_replay_compatibility_check_version_mismatch() {
    let mut bundle = build_sample_bundle("replay-compat-mismatch");
    bundle.schema_version = "0.9.0".to_string();

    let issues = check_bundle_compatibility(&bundle, RELIABILITY_EVENT_SCHEMA_VERSION);
    assert!(!issues.is_empty());
    assert!(
        issues[0].contains("0.9.0"),
        "should mention mismatched version"
    );
}

#[test]
fn e2e_replay_compatibility_check_report_version_mismatch() {
    let mut bundle = build_sample_bundle("replay-compat-report");
    bundle.original_report.schema_version = "2.0.0".to_string();

    let issues = check_bundle_compatibility(&bundle, RELIABILITY_EVENT_SCHEMA_VERSION);
    assert!(!issues.is_empty());
    assert!(
        issues.iter().any(|i| i.contains("report schema version")),
        "should report schema version mismatch"
    );
}

#[test]
fn e2e_replay_compatibility_check_env_version_mismatch() {
    let mut bundle = build_sample_bundle("replay-compat-env");
    bundle.env_snapshot.schema_version = "0.5.0".to_string();

    let issues = check_bundle_compatibility(&bundle, RELIABILITY_EVENT_SCHEMA_VERSION);
    assert!(!issues.is_empty());
    assert!(
        issues.iter().any(|i| i.contains("env snapshot")),
        "should report env snapshot version mismatch"
    );
}

// ===========================================================================
// 3. Successful Replay (Deterministic)
// ===========================================================================

#[test]
fn e2e_replay_successful_deterministic_replay() {
    let bundle = build_sample_bundle("replay-success");
    let spec = &bundle.scenario_spec;

    // Replay without nondeterminism
    let replay_trace = simulate_replay(spec, false);
    let divergences = compare_traces(&bundle.decision_trace, &replay_trace);

    assert!(
        divergences.is_empty(),
        "deterministic replay should produce zero divergences"
    );

    let result = ReplayComparisonResult {
        bundle_id: "replay-success".to_string(),
        replay_success: true,
        decisions_match: divergences.is_empty(),
        divergence_points: divergences,
        compatibility_issues: vec![],
    };

    assert!(result.replay_success);
    assert!(result.decisions_match);
}

#[test]
fn e2e_replay_same_spec_same_trace() {
    let spec = build_sample_spec("replay-determinism");

    let trace1 = simulate_replay(&spec, false);
    let trace2 = simulate_replay(&spec, false);

    assert_eq!(trace1.len(), trace2.len());
    for (a, b) in trace1.iter().zip(trace2.iter()) {
        assert_eq!(a.decision_code, b.decision_code);
        assert_eq!(a.phase, b.phase);
        assert_eq!(a.step_index, b.step_index);
    }
}

// ===========================================================================
// 4. Non-Determinism Detection
// ===========================================================================

#[test]
fn e2e_replay_nondeterminism_detection() {
    let bundle = build_sample_bundle("replay-nondet");
    let spec = &bundle.scenario_spec;

    // Replay WITH nondeterminism injection
    let replay_trace = simulate_replay(spec, true);
    let divergences = compare_traces(&bundle.decision_trace, &replay_trace);

    assert!(
        !divergences.is_empty(),
        "replay with nondeterminism should detect divergences"
    );

    // Verify divergence details
    let first = &divergences[0];
    assert!(first.original_decision.contains("OK"));
    assert!(first.replay_decision.contains("DIVERGED"));
    assert!(!first.likely_cause.is_empty());
}

#[test]
fn e2e_replay_nondeterminism_divergence_report_structure() {
    let bundle = build_sample_bundle("replay-nondet-report");
    let replay_trace = simulate_replay(&bundle.scenario_spec, true);
    let divergences = compare_traces(&bundle.decision_trace, &replay_trace);

    let result = ReplayComparisonResult {
        bundle_id: "replay-nondet-report".to_string(),
        replay_success: false,
        decisions_match: false,
        divergence_points: divergences,
        compatibility_issues: vec![],
    };

    let json = serde_json::to_string_pretty(&result).unwrap();
    let val: serde_json::Value = serde_json::from_str(&json).unwrap();

    assert!(!val["replay_success"].as_bool().unwrap());
    assert!(!val["decisions_match"].as_bool().unwrap());
    assert!(!val["divergence_points"].as_array().unwrap().is_empty());

    let first_div = &val["divergence_points"][0];
    assert!(first_div["original_decision"].as_str().is_some());
    assert!(first_div["replay_decision"].as_str().is_some());
    assert!(first_div["likely_cause"].as_str().is_some());
}

// ===========================================================================
// 5. Partial Bundle Corruption
// ===========================================================================

#[test]
fn e2e_replay_partial_bundle_missing_trace() {
    let mut bundle = build_sample_bundle("replay-corrupt-trace");
    bundle.decision_trace.clear(); // Corrupt: empty trace

    let replay_trace = simulate_replay(&bundle.scenario_spec, false);
    let divergences = compare_traces(&bundle.decision_trace, &replay_trace);

    // All replay entries should appear as divergences (original is empty)
    assert!(!divergences.is_empty());
    for div in &divergences {
        assert_eq!(div.original_decision, "<missing>");
    }
}

#[test]
fn e2e_replay_partial_bundle_truncated_trace() {
    let mut bundle = build_sample_bundle("replay-corrupt-truncated");
    // Truncate to only first 2 entries
    bundle.decision_trace.truncate(2);

    let replay_trace = simulate_replay(&bundle.scenario_spec, false);
    let divergences = compare_traces(&bundle.decision_trace, &replay_trace);

    // Should detect that replay has more entries than original
    let extra = divergences
        .iter()
        .filter(|d| d.original_decision == "<missing>")
        .count();
    assert!(extra > 0, "should detect extra replay entries");
}

#[test]
fn e2e_replay_partial_bundle_missing_artifacts() {
    let mut bundle = build_sample_bundle("replay-corrupt-artifacts");
    bundle.artifact_manifest.clear();

    // Bundle should still serialize/deserialize
    let json = serde_json::to_string(&bundle).unwrap();
    let parsed: ReplayBundle = serde_json::from_str(&json).unwrap();
    assert!(parsed.artifact_manifest.is_empty());

    // Replay should still work (artifacts are optional for replay)
    let replay_trace = simulate_replay(&parsed.scenario_spec, false);
    let divergences = compare_traces(&parsed.decision_trace, &replay_trace);
    assert!(divergences.is_empty());
}

#[test]
fn e2e_replay_malformed_json_detected() {
    let malformed = r#"{"schema_version": "1.0.0", "scenario_spec": "not an object"}"#;
    let result = serde_json::from_str::<ReplayBundle>(malformed);
    assert!(result.is_err(), "malformed JSON should fail to parse");
}

// ===========================================================================
// 6. Side-by-Side Trace Comparison
// ===========================================================================

#[test]
fn e2e_replay_side_by_side_identical_traces() {
    let spec = build_sample_spec("replay-sidebyside-ok");
    let trace_a = simulate_replay(&spec, false);
    let trace_b = simulate_replay(&spec, false);

    let divergences = compare_traces(&trace_a, &trace_b);
    assert!(divergences.is_empty());
}

#[test]
fn e2e_replay_side_by_side_diverged_traces() {
    let spec = build_sample_spec("replay-sidebyside-div");
    let trace_original = simulate_replay(&spec, false);
    let trace_replay = simulate_replay(&spec, true);

    let divergences = compare_traces(&trace_original, &trace_replay);
    assert!(!divergences.is_empty());

    // Each divergence should have complete diagnostic info
    for div in &divergences {
        assert!(!div.original_decision.is_empty());
        assert!(!div.replay_decision.is_empty());
        assert!(!div.likely_cause.is_empty());
    }
}

#[test]
fn e2e_replay_divergence_point_serialization() {
    let div = DivergencePoint {
        phase: ReliabilityPhase::Execute,
        step_index: 0,
        original_decision: "EXEC_OK".to_string(),
        replay_decision: "REPLAY_EXEC_DIVERGED".to_string(),
        likely_cause: "non-deterministic execution path".to_string(),
    };

    let json = serde_json::to_string_pretty(&div).unwrap();
    let val: serde_json::Value = serde_json::from_str(&json).unwrap();

    assert_eq!(val["phase"].as_str().unwrap(), "execute");
    assert_eq!(val["step_index"].as_u64().unwrap(), 0);
    assert_eq!(val["original_decision"].as_str().unwrap(), "EXEC_OK");
    assert_eq!(
        val["replay_decision"].as_str().unwrap(),
        "REPLAY_EXEC_DIVERGED"
    );

    // Roundtrip
    let parsed: DivergencePoint = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.phase, ReliabilityPhase::Execute);
}

// ===========================================================================
// 7. Replay Comparison Result Schema
// ===========================================================================

#[test]
fn e2e_replay_comparison_result_schema() {
    let result = ReplayComparisonResult {
        bundle_id: "test-bundle-001".to_string(),
        replay_success: false,
        decisions_match: false,
        divergence_points: vec![DivergencePoint {
            phase: ReliabilityPhase::Setup,
            step_index: 0,
            original_decision: "SETUP_OK".to_string(),
            replay_decision: "REPLAY_SETUP_DIVERGED".to_string(),
            likely_cause: "environment state differs".to_string(),
        }],
        compatibility_issues: vec!["toolchain version mismatch".to_string()],
    };

    let json = serde_json::to_string_pretty(&result).unwrap();
    let val: serde_json::Value = serde_json::from_str(&json).unwrap();

    assert_eq!(val["bundle_id"].as_str().unwrap(), "test-bundle-001");
    assert!(!val["replay_success"].as_bool().unwrap());
    assert!(!val["decisions_match"].as_bool().unwrap());
    assert_eq!(val["divergence_points"].as_array().unwrap().len(), 1);
    assert_eq!(val["compatibility_issues"].as_array().unwrap().len(), 1);
}

// ===========================================================================
// 8. Replay with Failure Hooks
// ===========================================================================

#[test]
fn e2e_replay_bundle_with_failure_hooks_roundtrip() {
    let spec = build_sample_spec("replay-hooks")
        .request_failure_hook(ReliabilityFailureHook::NetworkCut)
        .request_failure_hook(ReliabilityFailureHook::SyncTimeout)
        .with_failure_hook_flags(ReliabilityFailureHookFlags {
            allow_network_cut: true,
            allow_sync_timeout: true,
            allow_partial_update: false,
            allow_daemon_restart: false,
        });

    let trace = simulate_replay(&spec, false);
    let report = build_sample_report("replay-hooks", &trace);

    let bundle = ReplayBundle {
        schema_version: RELIABILITY_EVENT_SCHEMA_VERSION.to_string(),
        scenario_spec: spec.clone(),
        original_report: report,
        decision_trace: trace,
        env_snapshot: EnvironmentSnapshot {
            schema_version: RELIABILITY_EVENT_SCHEMA_VERSION.to_string(),
            toolchain: "rustc-1.85.0".to_string(),
            os_version: "Linux 6.17.0".to_string(),
            worker_id: Some("css".to_string()),
            env_vars: HashMap::new(),
        },
        artifact_manifest: vec![],
    };

    let json = serde_json::to_string(&bundle).unwrap();
    let parsed: ReplayBundle = serde_json::from_str(&json).unwrap();

    assert_eq!(parsed.scenario_spec.requested_failure_hooks.len(), 2);
    assert!(
        parsed
            .scenario_spec
            .failure_hook_flags
            .allows(ReliabilityFailureHook::NetworkCut)
    );
    assert!(
        parsed
            .scenario_spec
            .failure_hook_flags
            .allows(ReliabilityFailureHook::SyncTimeout)
    );
    assert!(
        !parsed
            .scenario_spec
            .failure_hook_flags
            .allows(ReliabilityFailureHook::DaemonRestart)
    );
}

// ===========================================================================
// 9. Replay Logging Integration
// ===========================================================================

#[test]
fn e2e_replay_events_logged_correctly() {
    let temp_dir = tempfile::tempdir().expect("temp dir");
    let logger = TestLoggerBuilder::new("replay_logging")
        .log_dir(temp_dir.path())
        .print_realtime(false)
        .build();

    let bundle = build_sample_bundle("replay-logged");
    let replay_trace = simulate_replay(&bundle.scenario_spec, true);
    let divergences = compare_traces(&bundle.decision_trace, &replay_trace);

    // Log replay result as reliability event
    let event = logger.log_reliability_event(ReliabilityEventInput {
        level: if divergences.is_empty() {
            LogLevel::Info
        } else {
            LogLevel::Warn
        },
        phase: ReliabilityPhase::Verify,
        scenario_id: "replay-logged".to_string(),
        message: format!("replay complete: {} divergences", divergences.len()),
        context: ReliabilityContext {
            worker_id: Some("css".to_string()),
            repo_set: vec!["/data/projects/rch".to_string()],
            pressure_state: None,
            triage_actions: divergences
                .iter()
                .map(|d| format!("{}:{}", d.original_decision, d.replay_decision))
                .collect(),
            decision_code: if divergences.is_empty() {
                "REPLAY_MATCH".to_string()
            } else {
                "REPLAY_DIVERGED".to_string()
            },
            fallback_reason: None,
        },
        artifact_paths: vec![],
    });

    assert_eq!(event.schema_version, RELIABILITY_EVENT_SCHEMA_VERSION);
    assert_eq!(event.context.decision_code, "REPLAY_DIVERGED");
}

// ===========================================================================
// 10. Artifact Manifest Validation
// ===========================================================================

#[test]
fn e2e_replay_artifact_manifest_validation() {
    let bundle = build_sample_bundle("replay-artifacts");

    for artifact in &bundle.artifact_manifest {
        assert!(!artifact.name.is_empty(), "artifact name must not be empty");
        assert!(!artifact.path.is_empty(), "artifact path must not be empty");
        assert!(
            artifact.hash.starts_with("sha256:"),
            "artifact hash must start with sha256:"
        );
        assert!(artifact.size_bytes > 0, "artifact size must be positive");
    }
}

#[test]
fn e2e_replay_artifact_entry_serialization() {
    let entry = ArtifactEntry {
        name: "build-output".to_string(),
        path: "/tmp/build.log".to_string(),
        hash: "sha256:deadbeef".to_string(),
        size_bytes: 8192,
    };

    let json = serde_json::to_string(&entry).unwrap();
    let parsed: ArtifactEntry = serde_json::from_str(&json).unwrap();

    assert_eq!(parsed.name, "build-output");
    assert_eq!(parsed.hash, "sha256:deadbeef");
    assert_eq!(parsed.size_bytes, 8192);
}

// ===========================================================================
// 11. Environment Snapshot Tests
// ===========================================================================

#[test]
fn e2e_replay_env_snapshot_serialization() {
    let snap = EnvironmentSnapshot {
        schema_version: "1.0.0".to_string(),
        toolchain: "rustc-1.85.0-nightly".to_string(),
        os_version: "Linux 6.17.0-14-generic".to_string(),
        worker_id: Some("css".to_string()),
        env_vars: {
            let mut m = HashMap::new();
            m.insert(
                "CARGO_TARGET_DIR".to_string(),
                "/data/tmp/cargo-target".to_string(),
            );
            m.insert("RUSTFLAGS".to_string(), "-C target-cpu=native".to_string());
            m
        },
    };

    let json = serde_json::to_string_pretty(&snap).unwrap();
    let val: serde_json::Value = serde_json::from_str(&json).unwrap();

    assert_eq!(val["schema_version"].as_str().unwrap(), "1.0.0");
    assert_eq!(val["toolchain"].as_str().unwrap(), "rustc-1.85.0-nightly");
    assert!(val["env_vars"].is_object());
    assert_eq!(
        val["env_vars"]["CARGO_TARGET_DIR"].as_str().unwrap(),
        "/data/tmp/cargo-target"
    );
}

#[test]
fn e2e_replay_env_snapshot_without_worker_id() {
    let snap = EnvironmentSnapshot {
        schema_version: "1.0.0".to_string(),
        toolchain: "rustc-1.85.0".to_string(),
        os_version: "Linux 6.17.0".to_string(),
        worker_id: None,
        env_vars: HashMap::new(),
    };

    let json = serde_json::to_string(&snap).unwrap();
    let parsed: EnvironmentSnapshot = serde_json::from_str(&json).unwrap();
    assert!(parsed.worker_id.is_none());
}
