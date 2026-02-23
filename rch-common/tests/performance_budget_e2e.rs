//! Performance Budget E2E Tests (bd-vvmd.6.6)
//!
//! Enforces the AGENTS.md performance budgets as hard-gated assertions:
//!
//! | Operation                        | Budget      | Panic Threshold |
//! |----------------------------------|-------------|-----------------|
//! | Hook decision (non-compilation)  | <1ms        | 5ms             |
//! | Hook decision (compilation)      | <5ms        | 10ms            |
//! | Worker selection                 | <10ms       | 50ms            |
//! | Full pipeline                    | <15% ovhd   | 50% overhead    |
//!
//! Also validates:
//!   - Error catalog lookup latency
//!   - Scenario spec construction/serialization throughput
//!   - Reliability event logging throughput
//!   - Triage policy evaluation latency
//!   - Regression detection via timing statistics

use rch_common::api::{ApiError, ApiResponse};
use rch_common::e2e::harness::{
    ReliabilityCommandRecord, ReliabilityFailureHook, ReliabilityFailureHookFlags,
    ReliabilityLifecycleCommand, ReliabilityScenarioReport, ReliabilityScenarioSpec,
};
use rch_common::e2e::logging::{
    LogLevel, ReliabilityContext, ReliabilityEventInput, ReliabilityPhase, TestLoggerBuilder,
    RELIABILITY_EVENT_SCHEMA_VERSION,
};
use rch_common::e2e::process_triage::{
    ProcessClassification, ProcessDescriptor, ProcessTriageActionClass,
    ProcessTriageActionRequest, ProcessTriageContract, ProcessTriageRequest,
    ProcessTriageTrigger, PROCESS_TRIAGE_CONTRACT_SCHEMA_VERSION, evaluate_triage_action,
};
use rch_common::errors::ErrorCode;
use rch_common::protocol::HookOutput;
use rch_common::{HookInput, classify_command};
use serde::{Deserialize, Serialize};
use std::time::Instant;

// ===========================================================================
// Budget constants from AGENTS.md
// ===========================================================================

/// Budget: non-compilation hook decision must complete under 1ms.
const BUDGET_HOOK_NONCOMPILATION_MS: u128 = 1;
/// Panic threshold for non-compilation hook decision.
const PANIC_HOOK_NONCOMPILATION_MS: u128 = 5;

/// Budget: compilation hook decision must complete under 5ms.
const BUDGET_HOOK_COMPILATION_MS: u128 = 5;
/// Panic threshold for compilation hook decision.
const PANIC_HOOK_COMPILATION_MS: u128 = 10;

/// Budget: error catalog full iteration under 1ms.
const BUDGET_ERROR_CATALOG_MS: u128 = 1;

/// Budget: scenario spec serialize/deserialize roundtrip under 1ms.
const BUDGET_SPEC_ROUNDTRIP_MS: u128 = 1;

/// Budget: 100 reliability events logged under 50ms.
const BUDGET_LOGGING_100_EVENTS_MS: u128 = 50;

/// Budget: triage policy evaluation under 500µs (0.5ms).
const BUDGET_TRIAGE_EVAL_US: u128 = 500;

/// Budget: API response envelope construction + serialization under 500µs.
const BUDGET_API_RESPONSE_US: u128 = 500;

/// Budget: full pipeline simulation (classify + spec + triage + response) under 1ms.
const BUDGET_FULL_PIPELINE_MS: u128 = 1;

/// Number of warmup iterations before measurement.
const WARMUP_ITERATIONS: usize = 10;
/// Number of measured iterations.
const MEASURE_ITERATIONS: usize = 100;

// ===========================================================================
// Timing helpers
// ===========================================================================

/// Statistical summary of a timing measurement.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct TimingSummary {
    operation: String,
    iterations: usize,
    min_us: u128,
    max_us: u128,
    mean_us: u128,
    p50_us: u128,
    p95_us: u128,
    p99_us: u128,
    budget_us: u128,
    within_budget: bool,
}

fn measure_us<F: FnMut()>(mut f: F, warmup: usize, iterations: usize) -> Vec<u128> {
    // Warmup
    for _ in 0..warmup {
        f();
    }

    // Measure
    let mut durations = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let start = Instant::now();
        f();
        durations.push(start.elapsed().as_micros());
    }
    durations.sort();
    durations
}

fn summarize(operation: &str, durations: &[u128], budget_us: u128) -> TimingSummary {
    let n = durations.len();
    let min_us = durations[0];
    let max_us = durations[n - 1];
    let mean_us = durations.iter().sum::<u128>() / n as u128;
    let p50_us = durations[n / 2];
    let p95_us = durations[(n as f64 * 0.95) as usize];
    let p99_us = durations[(n as f64 * 0.99) as usize];

    TimingSummary {
        operation: operation.to_string(),
        iterations: n,
        min_us,
        max_us,
        mean_us,
        p50_us,
        p95_us,
        p99_us,
        budget_us,
        within_budget: p95_us <= budget_us,
    }
}

// ===========================================================================
// Fixture helpers
// ===========================================================================

fn make_triage_request() -> ProcessTriageRequest {
    ProcessTriageRequest {
        schema_version: PROCESS_TRIAGE_CONTRACT_SCHEMA_VERSION.to_string(),
        correlation_id: "perf-corr-001".to_string(),
        worker_id: "w1".to_string(),
        observed_at_unix_ms: 1_768_768_123_000,
        trigger: ProcessTriageTrigger::DiskPressure,
        detector_confidence_percent: 85,
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

fn make_full_spec() -> ReliabilityScenarioSpec {
    ReliabilityScenarioSpec::new("perf-budget-spec")
        .with_worker_id("w1")
        .with_repo_set(["repo-a", "repo-b"])
        .with_pressure_state("nominal")
        .add_pre_check(ReliabilityLifecycleCommand {
            name: "check-ssh".to_string(),
            program: "ssh".to_string(),
            args: vec!["w1".into(), "true".into()],
            timeout_secs: Some(10),
            required_success: true,
            via_rch_exec: false,
        })
        .add_execute_command(ReliabilityLifecycleCommand {
            name: "cargo-build".to_string(),
            program: "cargo".to_string(),
            args: vec!["build".into(), "--release".into()],
            timeout_secs: Some(300),
            required_success: true,
            via_rch_exec: true,
        })
        .request_failure_hook(ReliabilityFailureHook::NetworkCut)
        .with_failure_hook_flags(ReliabilityFailureHookFlags::allow_all())
}

// ===========================================================================
// Tests: Hook decision latency (non-compilation)
// ===========================================================================

#[test]
fn e2e_budget_hook_noncompilation_within_budget() {
    let non_compilation_commands = [
        "ls -la",
        "cd /tmp",
        "git status",
        "echo hello",
        "cat file.txt",
        "pwd",
        "whoami",
        "date",
        "env",
        "export FOO=bar",
    ];

    for cmd in &non_compilation_commands {
        let durations = measure_us(
            || {
                let _ = classify_command(cmd);
            },
            WARMUP_ITERATIONS,
            MEASURE_ITERATIONS,
        );

        let summary = summarize(
            &format!("hook_noncompilation({cmd})"),
            &durations,
            BUDGET_HOOK_NONCOMPILATION_MS * 1000,
        );

        assert!(
            summary.p95_us <= PANIC_HOOK_NONCOMPILATION_MS * 1000,
            "PANIC: non-compilation hook for '{cmd}' p95={} µs exceeds panic threshold {} ms",
            summary.p95_us,
            PANIC_HOOK_NONCOMPILATION_MS
        );
    }
}

#[test]
fn e2e_budget_hook_noncompilation_batch_throughput() {
    let commands = [
        "ls", "cd /tmp", "git status", "echo hi", "cat f", "pwd", "whoami", "date", "env",
        "export X=1",
    ];

    let durations = measure_us(
        || {
            for cmd in &commands {
                let _ = classify_command(cmd);
            }
        },
        WARMUP_ITERATIONS,
        MEASURE_ITERATIONS,
    );

    let summary = summarize(
        "hook_noncompilation_batch_10",
        &durations,
        BUDGET_HOOK_NONCOMPILATION_MS * 1000 * 10,
    );

    // 10 non-compilation commands should complete well under 10ms total
    assert!(
        summary.p95_us <= 10_000, // 10ms for 10 commands
        "batch of 10 non-compilation commands p95={} µs exceeds 10ms",
        summary.p95_us
    );
}

// ===========================================================================
// Tests: Hook decision latency (compilation)
// ===========================================================================

#[test]
fn e2e_budget_hook_compilation_within_budget() {
    let compilation_commands = [
        "cargo build",
        "cargo build --release",
        "cargo test",
        "cargo check",
        "cargo clippy",
        "cargo run",
        "rustc lib.rs",
        "gcc main.c -o main",
        "g++ main.cpp -o main",
        "make all",
    ];

    for cmd in &compilation_commands {
        let durations = measure_us(
            || {
                let _ = classify_command(cmd);
            },
            WARMUP_ITERATIONS,
            MEASURE_ITERATIONS,
        );

        let summary = summarize(
            &format!("hook_compilation({cmd})"),
            &durations,
            BUDGET_HOOK_COMPILATION_MS * 1000,
        );

        assert!(
            summary.p95_us <= PANIC_HOOK_COMPILATION_MS * 1000,
            "PANIC: compilation hook for '{cmd}' p95={} µs exceeds panic threshold {} ms",
            summary.p95_us,
            PANIC_HOOK_COMPILATION_MS
        );
    }
}

#[test]
fn e2e_budget_hook_compilation_complex_commands() {
    let complex_commands = [
        "RUSTFLAGS=\"-C target-cpu=native\" cargo build --release --features all",
        "cargo build --release --target x86_64-unknown-linux-musl",
        "cargo test --workspace --all-features -- --test-threads=1",
        "cargo clippy --all-targets --all-features -- -D warnings",
    ];

    for cmd in &complex_commands {
        let durations = measure_us(
            || {
                let _ = classify_command(cmd);
            },
            WARMUP_ITERATIONS,
            MEASURE_ITERATIONS,
        );

        let summary = summarize(
            &format!("hook_complex({cmd})"),
            &durations,
            BUDGET_HOOK_COMPILATION_MS * 1000,
        );

        assert!(
            summary.p95_us <= PANIC_HOOK_COMPILATION_MS * 1000,
            "PANIC: complex compilation hook for '{cmd}' p95={} µs exceeds panic threshold {} ms",
            summary.p95_us,
            PANIC_HOOK_COMPILATION_MS
        );
    }
}

// ===========================================================================
// Tests: Error catalog latency
// ===========================================================================

#[test]
fn e2e_budget_error_catalog_full_iteration() {
    let durations = measure_us(
        || {
            for code in ErrorCode::all() {
                let _ = code.entry();
            }
        },
        WARMUP_ITERATIONS,
        MEASURE_ITERATIONS,
    );

    let summary = summarize(
        "error_catalog_full_iteration",
        &durations,
        BUDGET_ERROR_CATALOG_MS * 1000,
    );

    assert!(
        summary.p95_us <= BUDGET_ERROR_CATALOG_MS * 1000,
        "error catalog full iteration p95={} µs exceeds budget {} ms",
        summary.p95_us,
        BUDGET_ERROR_CATALOG_MS
    );
}

#[test]
fn e2e_budget_api_error_from_code() {
    let codes = [
        ErrorCode::ConfigNotFound,
        ErrorCode::SshConnectionFailed,
        ErrorCode::WorkerNoneAvailable,
        ErrorCode::WorkerHealthCheckFailed,
    ];

    for code in &codes {
        let durations = measure_us(
            || {
                let _ = ApiError::from_code(*code);
            },
            WARMUP_ITERATIONS,
            MEASURE_ITERATIONS,
        );

        let summary = summarize(
            &format!("api_error_from_code({code:?})"),
            &durations,
            BUDGET_API_RESPONSE_US,
        );

        assert!(
            summary.p95_us <= BUDGET_API_RESPONSE_US,
            "ApiError::from_code({code:?}) p95={} µs exceeds budget {} µs",
            summary.p95_us,
            BUDGET_API_RESPONSE_US
        );
    }
}

// ===========================================================================
// Tests: Scenario spec roundtrip
// ===========================================================================

#[test]
fn e2e_budget_scenario_spec_roundtrip() {
    let spec = make_full_spec();

    let durations = measure_us(
        || {
            let json = serde_json::to_string(&spec).unwrap();
            let _: ReliabilityScenarioSpec = serde_json::from_str(&json).unwrap();
        },
        WARMUP_ITERATIONS,
        MEASURE_ITERATIONS,
    );

    let summary = summarize(
        "scenario_spec_roundtrip",
        &durations,
        BUDGET_SPEC_ROUNDTRIP_MS * 1000,
    );

    assert!(
        summary.p95_us <= BUDGET_SPEC_ROUNDTRIP_MS * 1000,
        "scenario spec roundtrip p95={} µs exceeds budget {} ms",
        summary.p95_us,
        BUDGET_SPEC_ROUNDTRIP_MS
    );
}

#[test]
fn e2e_budget_scenario_report_roundtrip() {
    let report = {
        let mut r = ReliabilityScenarioReport {
            schema_version: RELIABILITY_EVENT_SCHEMA_VERSION.to_string(),
            scenario_id: "perf-report".to_string(),
            phase_order: vec![
                ReliabilityPhase::Setup,
                ReliabilityPhase::Execute,
                ReliabilityPhase::Verify,
                ReliabilityPhase::Cleanup,
            ],
            activated_failure_hooks: vec![ReliabilityFailureHook::NetworkCut],
            command_records: Vec::new(),
            artifact_paths: vec!["/tmp/build.log".to_string()],
            manifest_path: None,
        };
        for i in 0..10u64 {
            r.command_records.push(ReliabilityCommandRecord {
                phase: ReliabilityPhase::Execute,
                stage: format!("stage-{i}"),
                command_name: format!("cmd-{i}"),
                invoked_program: "cargo".to_string(),
                invoked_args: vec!["build".into()],
                exit_code: 0,
                duration_ms: 100 + i * 20,
                required_success: true,
                succeeded: true,
                artifact_paths: vec![],
            });
        }
        r
    };

    let durations = measure_us(
        || {
            let json = serde_json::to_string(&report).unwrap();
            let _: ReliabilityScenarioReport = serde_json::from_str(&json).unwrap();
        },
        WARMUP_ITERATIONS,
        MEASURE_ITERATIONS,
    );

    // 10-command report roundtrip should be well under 1ms
    let summary = summarize("scenario_report_roundtrip_10cmd", &durations, 1000);

    assert!(
        summary.p95_us <= 1000,
        "scenario report roundtrip (10 commands) p95={} µs exceeds 1ms",
        summary.p95_us
    );
}

// ===========================================================================
// Tests: Reliability event logging throughput
// ===========================================================================

#[test]
fn e2e_budget_logging_throughput_100_events() {
    let logger = TestLoggerBuilder::new("perf-budget-logging")
        .print_realtime(false)
        .build();

    let durations = measure_us(
        || {
            for i in 0..100 {
                logger.log_reliability_event(ReliabilityEventInput {
                    level: LogLevel::Info,
                    phase: ReliabilityPhase::Execute,
                    scenario_id: format!("perf-{i}"),
                    message: "build step completed".to_string(),
                    context: ReliabilityContext {
                        worker_id: Some("w1".to_string()),
                        repo_set: vec!["repo-a".to_string()],
                        pressure_state: None,
                        triage_actions: Vec::new(),
                        decision_code: "proceed".to_string(),
                        fallback_reason: None,
                    },
                    artifact_paths: vec![],
                });
            }
        },
        WARMUP_ITERATIONS / 2,
        MEASURE_ITERATIONS / 2,
    );

    let summary = summarize(
        "logging_throughput_100_events",
        &durations,
        BUDGET_LOGGING_100_EVENTS_MS * 1000,
    );

    assert!(
        summary.p95_us <= BUDGET_LOGGING_100_EVENTS_MS * 1000,
        "100 reliability events p95={} µs exceeds budget {} ms",
        summary.p95_us,
        BUDGET_LOGGING_100_EVENTS_MS
    );
}

// ===========================================================================
// Tests: Triage policy evaluation
// ===========================================================================

#[test]
fn e2e_budget_triage_evaluation() {
    let contract = ProcessTriageContract::default();
    let request = make_triage_request();
    let action = ProcessTriageActionRequest {
        action_class: ProcessTriageActionClass::ObserveOnly,
        pid: 12345,
        reason_code: "monitor".to_string(),
        signal: None,
    };

    let durations = measure_us(
        || {
            let _ = evaluate_triage_action(&request, &contract, &action);
        },
        WARMUP_ITERATIONS,
        MEASURE_ITERATIONS,
    );

    let summary = summarize("triage_evaluation", &durations, BUDGET_TRIAGE_EVAL_US);

    assert!(
        summary.p95_us <= BUDGET_TRIAGE_EVAL_US,
        "triage evaluation p95={} µs exceeds budget {} µs",
        summary.p95_us,
        BUDGET_TRIAGE_EVAL_US
    );
}

#[test]
fn e2e_budget_triage_denied_action() {
    let contract = ProcessTriageContract::default();
    let request = make_triage_request();
    let action = ProcessTriageActionRequest {
        action_class: ProcessTriageActionClass::HardTerminate,
        pid: 12345,
        reason_code: "kill_stale".to_string(),
        signal: Some("SIGKILL".to_string()),
    };

    let durations = measure_us(
        || {
            let _ = evaluate_triage_action(&request, &contract, &action);
        },
        WARMUP_ITERATIONS,
        MEASURE_ITERATIONS,
    );

    let summary = summarize(
        "triage_denied_evaluation",
        &durations,
        BUDGET_TRIAGE_EVAL_US,
    );

    assert!(
        summary.p95_us <= BUDGET_TRIAGE_EVAL_US,
        "triage denied action p95={} µs exceeds budget {} µs",
        summary.p95_us,
        BUDGET_TRIAGE_EVAL_US
    );
}

// ===========================================================================
// Tests: API response envelope
// ===========================================================================

#[test]
fn e2e_budget_api_response_ok_serialize() {
    let data = serde_json::json!({"workers": 4, "healthy": 3, "builds_queued": 2});
    let resp = ApiResponse::ok("status", data);

    let durations = measure_us(
        || {
            let _ = serde_json::to_string(&resp).unwrap();
        },
        WARMUP_ITERATIONS,
        MEASURE_ITERATIONS,
    );

    let summary = summarize(
        "api_response_ok_serialize",
        &durations,
        BUDGET_API_RESPONSE_US,
    );

    assert!(
        summary.p95_us <= BUDGET_API_RESPONSE_US,
        "API response serialize p95={} µs exceeds budget {} µs",
        summary.p95_us,
        BUDGET_API_RESPONSE_US
    );
}

#[test]
fn e2e_budget_api_response_err_serialize() {
    let err = ApiError::from_code(ErrorCode::SshConnectionFailed);
    let resp = ApiResponse::<()>::err("build", err);

    let durations = measure_us(
        || {
            let _ = serde_json::to_string(&resp).unwrap();
        },
        WARMUP_ITERATIONS,
        MEASURE_ITERATIONS,
    );

    let summary = summarize(
        "api_response_err_serialize",
        &durations,
        BUDGET_API_RESPONSE_US,
    );

    assert!(
        summary.p95_us <= BUDGET_API_RESPONSE_US,
        "API error response serialize p95={} µs exceeds budget {} µs",
        summary.p95_us,
        BUDGET_API_RESPONSE_US
    );
}

// ===========================================================================
// Tests: Hook protocol output serialization
// ===========================================================================

#[test]
fn e2e_budget_hook_output_serialization() {
    let allow = HookOutput::allow();
    let deny = HookOutput::deny("worker unavailable");

    let durations_allow = measure_us(
        || {
            let _ = serde_json::to_string(&allow).unwrap();
        },
        WARMUP_ITERATIONS,
        MEASURE_ITERATIONS,
    );

    let durations_deny = measure_us(
        || {
            let _ = serde_json::to_string(&deny).unwrap();
        },
        WARMUP_ITERATIONS,
        MEASURE_ITERATIONS,
    );

    let summary_allow = summarize("hook_output_allow_serialize", &durations_allow, 100);
    let summary_deny = summarize("hook_output_deny_serialize", &durations_deny, 500);

    assert!(
        summary_allow.p95_us <= 100,
        "hook allow serialize p95={} µs exceeds 100 µs",
        summary_allow.p95_us
    );
    assert!(
        summary_deny.p95_us <= 500,
        "hook deny serialize p95={} µs exceeds 500 µs",
        summary_deny.p95_us
    );
}

#[test]
fn e2e_budget_hook_input_deserialize() {
    let input_json = serde_json::json!({
        "tool_name": "Bash",
        "tool_input": {
            "command": "cargo build --release",
            "description": "Build the project"
        },
        "session_id": "test-session-001"
    });
    let json_str = serde_json::to_string(&input_json).unwrap();

    let durations = measure_us(
        || {
            let _: HookInput = serde_json::from_str(&json_str).unwrap();
        },
        WARMUP_ITERATIONS,
        MEASURE_ITERATIONS,
    );

    let summary = summarize("hook_input_deserialize", &durations, 500);

    assert!(
        summary.p95_us <= 500,
        "hook input deserialize p95={} µs exceeds 500 µs",
        summary.p95_us
    );
}

// ===========================================================================
// Tests: Full pipeline simulation
// ===========================================================================

#[test]
fn e2e_budget_full_pipeline_simulation() {
    let contract = ProcessTriageContract::default();

    let durations = measure_us(
        || {
            // 1. Classify command
            let _classification = classify_command("cargo build --release");

            // 2. Build scenario spec
            let spec = ReliabilityScenarioSpec::new("pipeline-perf")
                .with_worker_id("w1")
                .with_repo_set(["repo-a"])
                .with_pressure_state("nominal");

            // 3. Serialize/deserialize (simulates daemon transmission)
            let json = serde_json::to_string(&spec).unwrap();
            let _: ReliabilityScenarioSpec = serde_json::from_str(&json).unwrap();

            // 4. Triage evaluation
            let request = make_triage_request();
            let action = ProcessTriageActionRequest {
                action_class: ProcessTriageActionClass::ObserveOnly,
                pid: 12345,
                reason_code: "monitor".to_string(),
                signal: None,
            };
            let _ = evaluate_triage_action(&request, &contract, &action);

            // 5. Error response construction
            let err = ApiError::from_code(ErrorCode::WorkerHealthCheckFailed);
            let resp = ApiResponse::<()>::err("build", err);
            let _ = serde_json::to_string(&resp).unwrap();
        },
        WARMUP_ITERATIONS,
        MEASURE_ITERATIONS,
    );

    let summary = summarize(
        "full_pipeline_simulation",
        &durations,
        BUDGET_FULL_PIPELINE_MS * 1000,
    );

    assert!(
        summary.p95_us <= BUDGET_FULL_PIPELINE_MS * 1000,
        "full pipeline simulation p95={} µs exceeds budget {} ms",
        summary.p95_us,
        BUDGET_FULL_PIPELINE_MS
    );
}

// ===========================================================================
// Tests: Regression detection via timing statistics
// ===========================================================================

#[test]
fn e2e_budget_timing_summary_schema() {
    let durations = measure_us(
        || {
            let _ = classify_command("cargo build");
        },
        WARMUP_ITERATIONS,
        MEASURE_ITERATIONS,
    );

    let summary = summarize("schema_check", &durations, 5000);

    // Verify the summary is serializable (for CI artifact capture)
    let json = serde_json::to_string_pretty(&summary).unwrap();
    let restored: TimingSummary = serde_json::from_str(&json).unwrap();

    assert_eq!(restored.operation, "schema_check");
    assert_eq!(restored.iterations, MEASURE_ITERATIONS);
    assert!(restored.min_us <= restored.p50_us);
    assert!(restored.p50_us <= restored.p95_us);
    assert!(restored.p95_us <= restored.p99_us);
    assert!(restored.p99_us <= restored.max_us);
}

#[test]
fn e2e_budget_timing_determinism_across_runs() {
    // Run the same measurement twice; results should be in the same order of magnitude.
    let durations_a = measure_us(
        || {
            let _ = classify_command("cargo build --release");
        },
        WARMUP_ITERATIONS,
        MEASURE_ITERATIONS,
    );

    let durations_b = measure_us(
        || {
            let _ = classify_command("cargo build --release");
        },
        WARMUP_ITERATIONS,
        MEASURE_ITERATIONS,
    );

    let summary_a = summarize("run_a", &durations_a, 5000);
    let summary_b = summarize("run_b", &durations_b, 5000);

    // Median should be within 10x of each other (very loose bound for CI stability)
    let ratio = if summary_a.p50_us > summary_b.p50_us {
        summary_a.p50_us as f64 / summary_b.p50_us.max(1) as f64
    } else {
        summary_b.p50_us as f64 / summary_a.p50_us.max(1) as f64
    };

    assert!(
        ratio < 10.0,
        "timing variance too high: run_a p50={} µs, run_b p50={} µs, ratio={:.1}x",
        summary_a.p50_us,
        summary_b.p50_us,
        ratio
    );
}

// ===========================================================================
// Tests: Regression deltas and top contributors
// ===========================================================================

#[test]
fn e2e_budget_regression_report_generation() {
    // Collect timing summaries for all operations in a single report
    type BenchOp<'a> = (&'a str, Box<dyn FnMut()>, u128);
    let operations: Vec<BenchOp<'_>> = vec![
        (
            "classify_noncompilation",
            Box::new(|| {
                let _ = classify_command("ls -la");
            }),
            BUDGET_HOOK_NONCOMPILATION_MS * 1000,
        ),
        (
            "classify_compilation",
            Box::new(|| {
                let _ = classify_command("cargo build --release");
            }),
            BUDGET_HOOK_COMPILATION_MS * 1000,
        ),
        (
            "error_catalog_lookup",
            Box::new(|| {
                let _ = ErrorCode::WorkerHealthCheckFailed.entry();
            }),
            100, // 100 µs
        ),
        (
            "api_error_from_code",
            Box::new(|| {
                let _ = ApiError::from_code(ErrorCode::SshConnectionFailed);
            }),
            BUDGET_API_RESPONSE_US,
        ),
    ];

    let mut report: Vec<TimingSummary> = Vec::new();
    for (name, mut f, budget_us) in operations {
        let durations = measure_us(&mut f, WARMUP_ITERATIONS, MEASURE_ITERATIONS);
        report.push(summarize(name, &durations, budget_us));
    }

    // All operations should be within budget
    for summary in &report {
        assert!(
            summary.within_budget,
            "regression: '{}' p95={} µs exceeds budget {} µs",
            summary.operation, summary.p95_us, summary.budget_us
        );
    }

    // Report should be serializable for CI artifact capture
    let report_json = serde_json::to_string_pretty(&report).unwrap();
    let restored: Vec<TimingSummary> = serde_json::from_str(&report_json).unwrap();
    assert_eq!(restored.len(), report.len());
}

#[test]
fn e2e_budget_top_contributors_identification() {
    // Measure multiple pipeline stages and identify the slowest
    type StageOp<'a> = (&'a str, Box<dyn FnMut()>);
    let stages: Vec<StageOp<'_>> = vec![
        (
            "classification",
            Box::new(|| {
                let _ = classify_command("cargo build --release");
            }),
        ),
        (
            "spec_construction",
            Box::new(|| {
                let _ = make_full_spec();
            }),
        ),
        (
            "spec_serialization",
            Box::new(|| {
                let spec = make_full_spec();
                let _ = serde_json::to_string(&spec).unwrap();
            }),
        ),
        (
            "triage_evaluation",
            Box::new(|| {
                let contract = ProcessTriageContract::default();
                let request = make_triage_request();
                let action = ProcessTriageActionRequest {
                    action_class: ProcessTriageActionClass::ObserveOnly,
                    pid: 12345,
                    reason_code: "monitor".to_string(),
                    signal: None,
                };
                let _ = evaluate_triage_action(&request, &contract, &action);
            }),
        ),
        (
            "api_response",
            Box::new(|| {
                let err = ApiError::from_code(ErrorCode::WorkerHealthCheckFailed);
                let resp = ApiResponse::<()>::err("build", err);
                let _ = serde_json::to_string(&resp).unwrap();
            }),
        ),
    ];

    let mut summaries: Vec<TimingSummary> = Vec::new();
    for (name, mut f) in stages {
        let durations = measure_us(&mut f, WARMUP_ITERATIONS, MEASURE_ITERATIONS);
        summaries.push(summarize(name, &durations, 5000));
    }

    // Sort by p95 descending to identify top contributors
    summaries.sort_by_key(|s| std::cmp::Reverse(s.p95_us));

    // The slowest stage (top contributor) should still be under 1ms
    assert!(
        summaries[0].p95_us <= 1000,
        "top contributor '{}' p95={} µs exceeds 1ms",
        summaries[0].operation,
        summaries[0].p95_us
    );
}
