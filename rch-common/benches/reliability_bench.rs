//! Criterion microbenchmarks for the reliability pipeline (bd-vvmd.6.6).
//!
//! Benchmarks cover:
//!   - Scenario spec construction and serialization
//!   - Error catalog lookups (all codes, single code, entry generation)
//!   - API error/response envelope creation and serialization
//!   - Reliability phase event creation and JSONL serialization
//!   - Process triage policy evaluation
//!   - Scenario report construction and serialization
//!   - Hook protocol output serialization
//!   - Full pipeline simulation (classification → spec → triage → response)

use criterion::{Criterion, criterion_group, criterion_main};
use rch_common::api::{ApiError, ApiResponse};
use rch_common::e2e::harness::{
    ReliabilityCommandRecord, ReliabilityFailureHook, ReliabilityFailureHookFlags,
    ReliabilityLifecycleCommand, ReliabilityScenarioReport, ReliabilityScenarioSpec,
};
use rch_common::e2e::logging::{
    ReliabilityContext, ReliabilityEventInput, ReliabilityPhase, TestLoggerBuilder,
    RELIABILITY_EVENT_SCHEMA_VERSION,
};
use rch_common::e2e::process_triage::{
    ProcessClassification, ProcessDescriptor, ProcessTriageActionClass,
    ProcessTriageActionRequest, ProcessTriageContract, ProcessTriageRequest,
    ProcessTriageTrigger, PROCESS_TRIAGE_CONTRACT_SCHEMA_VERSION, evaluate_triage_action,
};
use rch_common::errors::ErrorCode;
use rch_common::protocol::HookOutput;
use rch_common::HookInput;
use std::hint::black_box;

// ---------------------------------------------------------------------------
// Helpers: build realistic fixtures once
// ---------------------------------------------------------------------------

fn make_triage_request() -> ProcessTriageRequest {
    ProcessTriageRequest {
        schema_version: PROCESS_TRIAGE_CONTRACT_SCHEMA_VERSION.to_string(),
        correlation_id: "bench-corr-001".to_string(),
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
            action_class: ProcessTriageActionClass::SoftTerminate,
            pid: 12345,
            reason_code: "stale_build".to_string(),
            signal: Some("SIGTERM".to_string()),
        }],
    }
}

fn make_allowed_action() -> ProcessTriageActionRequest {
    ProcessTriageActionRequest {
        action_class: ProcessTriageActionClass::ObserveOnly,
        pid: 12345,
        reason_code: "monitor_stale".to_string(),
        signal: None,
    }
}

fn make_denied_action() -> ProcessTriageActionRequest {
    ProcessTriageActionRequest {
        action_class: ProcessTriageActionClass::HardTerminate,
        pid: 12345,
        reason_code: "kill_stale".to_string(),
        signal: Some("SIGKILL".to_string()),
    }
}

// ---------------------------------------------------------------------------
// Scenario spec construction
// ---------------------------------------------------------------------------

fn bench_scenario_spec_construction(c: &mut Criterion) {
    let mut group = c.benchmark_group("reliability/scenario_spec");

    group.bench_function("minimal", |b| {
        b.iter(|| {
            black_box(
                ReliabilityScenarioSpec::new("bench-minimal")
                    .with_worker_id("w1")
                    .with_repo_set(["repo-a"]),
            )
        })
    });

    group.bench_function("full_lifecycle", |b| {
        b.iter(|| {
            black_box(
                ReliabilityScenarioSpec::new("bench-full")
                    .with_worker_id("w1")
                    .with_repo_set(["repo-a", "repo-b", "repo-c"])
                    .with_pressure_state("nominal")
                    .add_triage_action("kill_stale")
                    .add_pre_check(ReliabilityLifecycleCommand {
                        name: "check-ssh".to_string(),
                        program: "ssh".to_string(),
                        args: vec![
                            "-o".into(),
                            "ConnectTimeout=5".into(),
                            "w1".into(),
                            "true".into(),
                        ],
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
                    .add_post_check(ReliabilityLifecycleCommand {
                        name: "verify-binary".to_string(),
                        program: "test".to_string(),
                        args: vec!["-f".into(), "target/release/myapp".into()],
                        timeout_secs: Some(5),
                        required_success: true,
                        via_rch_exec: false,
                    })
                    .request_failure_hook(ReliabilityFailureHook::NetworkCut)
                    .with_failure_hook_flags(ReliabilityFailureHookFlags::allow_all()),
            )
        })
    });

    group.finish();
}

fn bench_scenario_spec_serialization(c: &mut Criterion) {
    let spec = ReliabilityScenarioSpec::new("bench-serialize")
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
            args: vec!["build".into()],
            timeout_secs: Some(300),
            required_success: true,
            via_rch_exec: true,
        });

    let mut group = c.benchmark_group("reliability/scenario_spec_serde");

    group.bench_function("serialize", |b| {
        b.iter(|| black_box(serde_json::to_string(&spec).unwrap()))
    });

    let json = serde_json::to_string(&spec).unwrap();
    group.bench_function("deserialize", |b| {
        b.iter(|| {
            black_box(serde_json::from_str::<ReliabilityScenarioSpec>(&json).unwrap())
        })
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Error catalog lookups
// ---------------------------------------------------------------------------

fn bench_error_catalog(c: &mut Criterion) {
    let mut group = c.benchmark_group("reliability/error_catalog");

    group.bench_function("all_codes_iterate", |b| {
        b.iter(|| {
            for code in ErrorCode::all() {
                black_box(code.code_string());
            }
        })
    });

    group.bench_function("single_entry_lookup", |b| {
        b.iter(|| black_box(ErrorCode::WorkerHealthCheckFailed.entry()))
    });

    group.bench_function("api_error_from_code", |b| {
        b.iter(|| black_box(ApiError::from_code(ErrorCode::WorkerHealthCheckFailed)))
    });

    group.bench_function("api_error_serialize", |b| {
        let err = ApiError::from_code(ErrorCode::WorkerHealthCheckFailed);
        b.iter(|| black_box(serde_json::to_string(&err).unwrap()))
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// API response envelope
// ---------------------------------------------------------------------------

fn bench_api_response(c: &mut Criterion) {
    let mut group = c.benchmark_group("reliability/api_response");

    group.bench_function("ok_empty", |b| {
        b.iter(|| black_box(ApiResponse::<()>::ok_empty("status")))
    });

    group.bench_function("ok_data_serialize", |b| {
        let resp = ApiResponse::ok("status", serde_json::json!({"workers": 4, "healthy": 3}));
        b.iter(|| black_box(serde_json::to_string(&resp).unwrap()))
    });

    group.bench_function("err_serialize", |b| {
        let err = ApiError::from_code(ErrorCode::SshConnectionFailed);
        let resp = ApiResponse::<()>::err("build", err);
        b.iter(|| black_box(serde_json::to_string(&resp).unwrap()))
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Reliability phase event logging
// ---------------------------------------------------------------------------

fn bench_phase_event_logging(c: &mut Criterion) {
    let mut group = c.benchmark_group("reliability/phase_event");

    group.bench_function("create_event_input", |b| {
        b.iter(|| {
            black_box(ReliabilityEventInput {
                level: rch_common::e2e::logging::LogLevel::Info,
                phase: ReliabilityPhase::Execute,
                scenario_id: "bench-event".to_string(),
                message: "executing build command".to_string(),
                context: ReliabilityContext {
                    worker_id: Some("w1".to_string()),
                    repo_set: vec!["repo-a".to_string()],
                    pressure_state: Some("nominal".to_string()),
                    triage_actions: Vec::new(),
                    decision_code: "proceed".to_string(),
                    fallback_reason: None,
                },
                artifact_paths: vec![],
            })
        })
    });

    group.bench_function("logger_throughput_100_events", |b| {
        let logger = TestLoggerBuilder::new("bench-throughput")
            .print_realtime(false)
            .build();
        b.iter(|| {
            for i in 0..100 {
                logger.log_reliability_event(ReliabilityEventInput {
                    level: rch_common::e2e::logging::LogLevel::Info,
                    phase: ReliabilityPhase::Execute,
                    scenario_id: format!("bench-{i}"),
                    message: "executing build command".to_string(),
                    context: ReliabilityContext {
                        worker_id: Some("w1".to_string()),
                        repo_set: Vec::new(),
                        pressure_state: None,
                        triage_actions: Vec::new(),
                        decision_code: "proceed".to_string(),
                        fallback_reason: None,
                    },
                    artifact_paths: vec![],
                });
            }
        })
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Process triage policy evaluation
// ---------------------------------------------------------------------------

fn bench_process_triage(c: &mut Criterion) {
    let contract = ProcessTriageContract::default();
    let request = make_triage_request();
    let allowed_action = make_allowed_action();
    let denied_action = make_denied_action();

    let mut group = c.benchmark_group("reliability/process_triage");

    group.bench_function("evaluate_allowed_action", |b| {
        b.iter(|| black_box(evaluate_triage_action(&request, &contract, &allowed_action)))
    });

    group.bench_function("evaluate_denied_action", |b| {
        b.iter(|| black_box(evaluate_triage_action(&request, &contract, &denied_action)))
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Scenario report construction & serialization
// ---------------------------------------------------------------------------

fn bench_scenario_report(c: &mut Criterion) {
    let mut group = c.benchmark_group("reliability/scenario_report");

    let report = {
        let mut r = ReliabilityScenarioReport {
            schema_version: RELIABILITY_EVENT_SCHEMA_VERSION.to_string(),
            scenario_id: "bench-report".to_string(),
            phase_order: vec![
                ReliabilityPhase::Setup,
                ReliabilityPhase::Execute,
                ReliabilityPhase::Verify,
                ReliabilityPhase::Cleanup,
            ],
            activated_failure_hooks: vec![ReliabilityFailureHook::NetworkCut],
            command_records: Vec::new(),
            artifact_paths: vec![
                "/tmp/artifacts/build.log".to_string(),
                "/tmp/artifacts/test-report.json".to_string(),
            ],
            manifest_path: None,
        };
        for i in 0..10u64 {
            r.command_records.push(ReliabilityCommandRecord {
                phase: if i < 2 {
                    ReliabilityPhase::Setup
                } else if i < 7 {
                    ReliabilityPhase::Execute
                } else if i < 9 {
                    ReliabilityPhase::Verify
                } else {
                    ReliabilityPhase::Cleanup
                },
                stage: format!("stage-{i}"),
                command_name: format!("cmd-{i}"),
                invoked_program: "cargo".to_string(),
                invoked_args: vec!["build".into(), "--release".into()],
                exit_code: 0,
                duration_ms: 150 + i * 30,
                required_success: true,
                succeeded: true,
                artifact_paths: vec![],
            });
        }
        r
    };

    group.bench_function("serialize_10_commands", |b| {
        b.iter(|| black_box(serde_json::to_string(&report).unwrap()))
    });

    let json = serde_json::to_string(&report).unwrap();
    group.bench_function("deserialize_10_commands", |b| {
        b.iter(|| {
            black_box(serde_json::from_str::<ReliabilityScenarioReport>(&json).unwrap())
        })
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Hook protocol output serialization
// ---------------------------------------------------------------------------

fn bench_hook_protocol(c: &mut Criterion) {
    let mut group = c.benchmark_group("reliability/hook_protocol");

    group.bench_function("hook_input_deserialize", |b| {
        let input_json = serde_json::json!({
            "tool_name": "Bash",
            "tool_input": {
                "command": "cargo build --release",
                "description": "Build the project"
            },
            "session_id": "test-session-001"
        });
        let json_str = serde_json::to_string(&input_json).unwrap();
        b.iter(|| black_box(serde_json::from_str::<HookInput>(&json_str).unwrap()))
    });

    group.bench_function("hook_output_allow_serialize", |b| {
        let output = HookOutput::allow();
        b.iter(|| black_box(serde_json::to_string(&output).unwrap()))
    });

    group.bench_function("hook_output_deny_serialize", |b| {
        let output = HookOutput::deny("worker unavailable");
        b.iter(|| black_box(serde_json::to_string(&output).unwrap()))
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Batch: full reliability pipeline simulation
// ---------------------------------------------------------------------------

fn bench_full_pipeline_simulation(c: &mut Criterion) {
    c.bench_function("reliability/pipeline_full_cycle", |b| {
        b.iter(|| {
            // 1. Classify the command
            let classification = rch_common::classify_command(black_box("cargo build --release"));

            // 2. Build scenario spec
            let spec = ReliabilityScenarioSpec::new("pipeline-bench")
                .with_worker_id("w1")
                .with_repo_set(["repo-a"])
                .with_pressure_state("nominal");

            // 3. Serialize spec (simulates daemon transmission)
            let spec_json = serde_json::to_string(&spec).unwrap();
            let _spec_back: ReliabilityScenarioSpec =
                serde_json::from_str(&spec_json).unwrap();

            // 4. Evaluate triage action
            let contract = ProcessTriageContract::default();
            let request = make_triage_request();
            let action = make_allowed_action();
            let _decision = evaluate_triage_action(&request, &contract, &action);

            // 5. Create error response
            let err = ApiError::from_code(ErrorCode::WorkerHealthCheckFailed);
            let resp = ApiResponse::<()>::err("build", err);
            let _resp_json = serde_json::to_string(&resp).unwrap();

            black_box((classification, _resp_json))
        })
    });
}

criterion_group!(
    benches,
    bench_scenario_spec_construction,
    bench_scenario_spec_serialization,
    bench_error_catalog,
    bench_api_response,
    bench_phase_event_logging,
    bench_process_triage,
    bench_scenario_report,
    bench_hook_protocol,
    bench_full_pipeline_simulation,
);

criterion_main!(benches);
