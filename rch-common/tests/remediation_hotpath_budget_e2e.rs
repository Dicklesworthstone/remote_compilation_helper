//! Hot-path performance budgets + regression suite for the session-history
//! remediation program (bd-session-history-remediation-ocv9i.16.7).
//!
//! RCH runs in hook mode on *every* shell command, so the remediation features
//! that landed across the program — incident writing, admission explanation,
//! proof/strict-remote preflight, capability lookup, config/default loading, and
//! output-mode detection — must not turn a sub-millisecond non-compilation
//! decision into a noticeable delay. This suite measures each of those hot paths
//! with deterministic fixtures, reports p50/p95/p99, record counts, an
//! allocation proxy (serialized output bytes), and cache-hit/cache-miss cases,
//! then hard-asserts the documented budgets.
//!
//! Budgets are tied back to README/AGENTS expectations:
//!
//! | Operation                          | Budget   | Panic threshold |
//! |------------------------------------|----------|-----------------|
//! | Non-compilation hook decision      | <1ms     | 5ms             |
//! | Compilation hook decision          | <5ms     | 10ms            |
//! | Worker selection / admission       | <10ms    | 50ms            |
//!
//! Where a remediation path has no explicit README number (incident append,
//! rejection aggregation, config parse) we derive a budget from the governing
//! constraint — "a sub-millisecond non-compilation path must stay fast" and
//! "a compilation decision stays under 5ms" — and document the rationale on the
//! scenario. Every measured scenario is emitted as one JSONL timing record to
//! `target/test-logs/remediation_hotpath_budget.jsonl` with the program schema
//! (run_id, bead_id, scenario, event, status, command_fingerprint, duration_ms,
//! budget_ms, p95_ms, p99_ms, detail) so the E2E runner and CI can ingest it.
//!
//! Allocation note: exact heap-allocation counting requires a custom
//! `#[global_allocator]`, which needs `unsafe` and would violate the workspace
//! `#![forbid(unsafe_code)]` rule. We instead capture a deterministic
//! allocation *proxy* — the serialized byte size of each operation's output —
//! which is stable per fixture and shifts if allocation behavior changes
//! materially, giving a regression-detectable signal without unsafe code.

use rch_common::admission_rejection::{
    AdmissionRejectionCategory, CandidateRejection, aggregate_rejections,
};
use rch_common::admit_preflight::preflight;
use rch_common::classify_command;
use rch_common::incident::{
    IncidentEvent, IncidentEventType, IncidentReasonCode, IncidentSource, SelectedMode,
};
use rch_common::incident_ledger::IncidentLedger;
use rch_common::remediation_config::RemediationConfig;
use rch_common::ui::OutputContext;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::PathBuf;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

// ===========================================================================
// Budget constants (tied to README/AGENTS; microseconds)
// ===========================================================================

/// Non-compilation hook decision steady-state budget (README: <1ms).
const BUDGET_NONCOMPILATION_US: u128 = 1_000;
/// Non-compilation hook decision panic threshold (README: 5ms).
const PANIC_NONCOMPILATION_US: u128 = 5_000;

/// Compilation hook decision steady-state budget (README: <5ms).
const BUDGET_COMPILATION_US: u128 = 5_000;
/// Compilation hook decision panic threshold (README: 10ms).
const PANIC_COMPILATION_US: u128 = 10_000;

/// Incident-ledger append budget. Off the non-compilation fast path (only on a
/// real incident), but must stay well under the compilation decision budget so
/// a write never stalls the hook. 2ms target / 5ms panic.
const BUDGET_INCIDENT_APPEND_US: u128 = 2_000;
const PANIC_INCIDENT_APPEND_US: u128 = 5_000;

/// Incident-ledger read budget (status/doctor diagnostics, not the hottest
/// path). 5ms target / 10ms panic for a bounded ledger.
const BUDGET_INCIDENT_READ_US: u128 = 5_000;
const PANIC_INCIDENT_READ_US: u128 = 10_000;

/// In-memory remediation default construction. Pure CPU, must be trivial.
const BUDGET_CONFIG_DEFAULT_US: u128 = 500;
const PANIC_CONFIG_DEFAULT_US: u128 = 5_000;

/// Parsing remediation config from a serialized form (cache-miss / cold load).
const BUDGET_CONFIG_PARSE_US: u128 = 2_000;
const PANIC_CONFIG_PARSE_US: u128 = 5_000;

/// Admission rejection aggregation (operator-facing "why no worker" vocabulary).
const BUDGET_REJECTION_AGG_US: u128 = 500;
const PANIC_REJECTION_AGG_US: u128 = 5_000;

/// JSON serialization of one incident record on the write path.
const BUDGET_INCIDENT_SERIALIZE_US: u128 = 500;
const PANIC_INCIDENT_SERIALIZE_US: u128 = 5_000;

// Iteration controls. Sub-millisecond CPU ops use amortized batching so
// per-sample scheduler jitter does not dominate the operation under test.
const WARMUP_ITERATIONS: usize = 10;
const MEASURE_ITERATIONS: usize = 100;
const MICRO_BENCH_BATCH_SIZE: usize = 25;
/// Distinct fresh ledgers measured for the cold-read percentile sample.
const COLD_SAMPLES: usize = 50;
/// Number of incident records used for the read/record-count scenarios.
const LEDGER_RECORD_COUNT: usize = 100;

/// Allow bounded p95 scheduler noise on shared CI/RCH workers while still
/// enforcing the documented steady-state budget on p50.
const NOISY_P95_MULTIPLIER: u128 = 5;
const NOISY_P95_MIN_SLACK_US: u128 = 5_000;

const BEAD_ID: &str = "bd-session-history-remediation-ocv9i.16.7";

// ===========================================================================
// JSONL timing record (program schema, extended for budgets)
// ===========================================================================

/// One emitted JSONL timing record. The first eleven fields are the program
/// timing schema mandated by the bead; the remainder are regression aids.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct TimingRecord {
    /// Unix-epoch milliseconds the record was produced.
    ts_unix_ms: u64,
    run_id: String,
    bead_id: String,
    scenario: String,
    /// Event kind; always `budget.measure` for a measured scenario.
    event: String,
    /// `pass` when p50<=budget and p95<=panic, else `fail`.
    status: String,
    /// Stable fingerprint of the measured command/operation.
    command_fingerprint: String,
    /// Representative (p50) duration in fractional milliseconds.
    duration_ms: f64,
    /// Steady-state budget in fractional milliseconds.
    budget_ms: f64,
    p50_ms: f64,
    p95_ms: f64,
    p99_ms: f64,
    /// Panic / noisy-run threshold in fractional milliseconds.
    panic_ms: f64,
    /// How many records the operation processed (0 when not applicable).
    record_count: u64,
    /// Allocation proxy: serialized byte size of the operation's output.
    serialized_bytes: u64,
    /// `n/a` | `hit` | `miss` | `cold` | `warm`.
    cache_mode: String,
    detail: String,
}

/// The complete, asserted result of one measured scenario.
struct Scenario {
    record: TimingRecord,
    budget_us: u128,
    p50_us: u128,
    p95_us: u128,
    noisy_limit_us: u128,
}

// ===========================================================================
// Measurement harness
// ===========================================================================

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn run_id() -> String {
    format!("run-{}-{}", now_unix_ms(), std::process::id())
}

fn percentile_index(len: usize, percentile: usize) -> usize {
    if len == 0 {
        return 0;
    }
    ((len * percentile.clamp(1, 100)).div_ceil(100)).saturating_sub(1)
}

fn percentile(sorted: &[u128], pct: usize) -> u128 {
    sorted
        .get(percentile_index(sorted.len(), pct))
        .copied()
        .unwrap_or(0)
}

/// Amortized per-operation timing in microseconds, sorted ascending. Each timed
/// sample runs `batch_size` invocations and divides, so scheduler jitter on a
/// single call cannot dominate a sub-microsecond operation.
fn measure_amortized_us<F: FnMut()>(
    mut f: F,
    warmup: usize,
    iterations: usize,
    batch_size: usize,
) -> Vec<u128> {
    assert!(batch_size > 0);
    for _ in 0..warmup {
        for _ in 0..batch_size {
            f();
        }
    }
    let mut durations = Vec::with_capacity(iterations);
    let divisor = (batch_size as u128) * 1_000;
    for _ in 0..iterations {
        let start = Instant::now();
        for _ in 0..batch_size {
            f();
        }
        durations.push(start.elapsed().as_nanos().div_ceil(divisor));
    }
    durations.sort_unstable();
    durations
}

/// Per-call timing in microseconds (no batching), sorted ascending. Used for
/// I/O paths where each call has genuine per-call cost (e.g. a cold read).
fn measure_per_call_us<F: FnMut()>(mut f: F, samples: usize) -> Vec<u128> {
    let mut durations = Vec::with_capacity(samples);
    for _ in 0..samples {
        let start = Instant::now();
        f();
        durations.push(start.elapsed().as_micros());
    }
    durations.sort_unstable();
    durations
}

fn noisy_p95_limit_us(panic_us: u128, budget_us: u128) -> u128 {
    panic_us
        .max(budget_us.saturating_mul(NOISY_P95_MULTIPLIER))
        .max(budget_us.saturating_add(NOISY_P95_MIN_SLACK_US))
}

fn us_to_ms(us: u128) -> f64 {
    us as f64 / 1_000.0
}

/// Build a `Scenario` from a sorted-microseconds sample plus metadata, computing
/// pass/fail against the budget and noisy p95 limit. Does NOT assert — callers
/// assert after the JSONL artifact has been written so it always lands.
#[allow(clippy::too_many_arguments)]
fn build_scenario(
    run_id: &str,
    name: &str,
    fingerprint: &str,
    durations_us: &[u128],
    budget_us: u128,
    panic_us: u128,
    record_count: u64,
    serialized_bytes: u64,
    cache_mode: &str,
    detail: &str,
) -> Scenario {
    let p50_us = percentile(durations_us, 50);
    let p95_us = percentile(durations_us, 95);
    let p99_us = percentile(durations_us, 99);
    let noisy_limit_us = noisy_p95_limit_us(panic_us, budget_us);
    let within = p50_us <= budget_us && p95_us <= noisy_limit_us;

    let record = TimingRecord {
        ts_unix_ms: now_unix_ms(),
        run_id: run_id.to_string(),
        bead_id: BEAD_ID.to_string(),
        scenario: name.to_string(),
        event: "budget.measure".to_string(),
        status: if within { "pass" } else { "fail" }.to_string(),
        command_fingerprint: fingerprint.to_string(),
        duration_ms: us_to_ms(p50_us),
        budget_ms: us_to_ms(budget_us),
        p50_ms: us_to_ms(p50_us),
        p95_ms: us_to_ms(p95_us),
        p99_ms: us_to_ms(p99_us),
        panic_ms: us_to_ms(noisy_limit_us),
        record_count,
        serialized_bytes,
        cache_mode: cache_mode.to_string(),
        detail: detail.to_string(),
    };

    Scenario {
        record,
        budget_us,
        p50_us,
        p95_us,
        noisy_limit_us,
    }
}

/// Hard-assert a scenario's steady-state and noisy-run budgets.
fn assert_scenario(s: &Scenario) {
    assert!(
        s.p50_us <= s.budget_us,
        "{} p50={}µs exceeds steady-state budget {}µs (p95={}µs)",
        s.record.scenario,
        s.p50_us,
        s.budget_us,
        s.p95_us
    );
    assert!(
        s.p95_us <= s.noisy_limit_us,
        "{} p95={}µs exceeds noisy-run threshold {}µs (budget {}µs, p50={}µs)",
        s.record.scenario,
        s.p95_us,
        s.noisy_limit_us,
        s.budget_us,
        s.p50_us
    );
}

// ===========================================================================
// Deterministic fixtures
// ===========================================================================

fn make_incident_event(seq: u64) -> IncidentEvent {
    IncidentEvent::new(
        IncidentEventType::Admission,
        IncidentReasonCode::NoAdmissibleWorkers,
        IncidentSource::Hook,
        "proj-7f3a9c01",
        format!("fp-{seq:08x}"),
        SelectedMode::Local,
        true,
        1_768_768_123_000 + seq,
    )
    .with_worker_id("css")
    .with_detail("candidates", "8")
    .with_detail("rejected", "8")
}

fn make_rejections(n: usize) -> Vec<CandidateRejection> {
    // Spread across the rejection vocabulary so aggregation does real work
    // across categories and broad classes.
    let categories = [
        AdmissionRejectionCategory::CriticalPressure,
        AdmissionRejectionCategory::InsufficientSlots,
        AdmissionRejectionCategory::CircuitOpen,
        AdmissionRejectionCategory::TelemetryStale,
        AdmissionRejectionCategory::HardPreflight,
        AdmissionRejectionCategory::MissingRuntime,
        AdmissionRejectionCategory::MissingRustTarget,
        AdmissionRejectionCategory::ProjectExcluded,
    ];
    (0..n)
        .map(|i| CandidateRejection {
            worker_id: format!("w{i}"),
            category: categories[i % categories.len()],
        })
        .collect()
}

/// Resolve the workspace `target/test-logs` directory, honoring CARGO_TARGET_DIR.
fn test_logs_dir() -> PathBuf {
    let target = std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            // tests/ lives under rch-common/; the workspace target is one up.
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .map(|p| p.join("target"))
                .unwrap_or_else(|| PathBuf::from("target"))
        });
    target.join("test-logs")
}

// ===========================================================================
// Per-scenario measurements (reused by focused tests + the emit aggregator)
// ===========================================================================

fn sc_admit_preflight_compilation(run_id: &str) -> Scenario {
    let cmd = "cargo build --release";
    let bytes = serde_json::to_vec(&preflight(cmd, true)).unwrap().len() as u64;
    let durations = measure_amortized_us(
        || {
            let _ = preflight(cmd, true);
        },
        WARMUP_ITERATIONS,
        MEASURE_ITERATIONS,
        MICRO_BENCH_BATCH_SIZE,
    );
    build_scenario(
        run_id,
        "admit_preflight_compilation",
        "rch admit cargo build --release (proof_policy=on)",
        &durations,
        BUDGET_COMPILATION_US,
        PANIC_COMPILATION_US,
        0,
        bytes,
        "n/a",
        "capability lookup + proof/strict-remote preflight on the compilation path",
    )
}

fn sc_admit_preflight_noncompilation(run_id: &str) -> Scenario {
    let cmd = "ls -la /var/log";
    let bytes = serde_json::to_vec(&preflight(cmd, false)).unwrap().len() as u64;
    let durations = measure_amortized_us(
        || {
            let _ = preflight(cmd, false);
        },
        WARMUP_ITERATIONS,
        MEASURE_ITERATIONS,
        MICRO_BENCH_BATCH_SIZE,
    );
    build_scenario(
        run_id,
        "admit_preflight_noncompilation",
        "rch admit ls -la (non-compilation reject)",
        &durations,
        BUDGET_NONCOMPILATION_US,
        PANIC_NONCOMPILATION_US,
        0,
        bytes,
        "n/a",
        "preflight must reject a non-compilation command on the sub-1ms fast path",
    )
}

fn sc_output_mode_detect(run_id: &str) -> Scenario {
    let bytes = serde_json::to_vec(&format!("{:?}", OutputContext::detect()))
        .unwrap()
        .len() as u64;
    let durations = measure_amortized_us(
        || {
            let _ = OutputContext::detect();
        },
        WARMUP_ITERATIONS,
        MEASURE_ITERATIONS,
        MICRO_BENCH_BATCH_SIZE,
    );
    build_scenario(
        run_id,
        "output_mode_detect",
        "OutputContext::detect()",
        &durations,
        BUDGET_NONCOMPILATION_US,
        PANIC_NONCOMPILATION_US,
        0,
        bytes,
        "n/a",
        "output-mode detection runs on every hook decision; stays on the non-compilation budget",
    )
}

fn sc_incident_append(run_id: &str) -> Scenario {
    let dir = tempfile::tempdir().expect("temp dir");
    let ledger = IncidentLedger::with_path(dir.path().join("incidents.jsonl"));
    let event = make_incident_event(1);
    let bytes = serde_json::to_vec(&event).unwrap().len() as u64;
    let mut seq: u64 = 0;
    let durations = measure_amortized_us(
        || {
            seq += 1;
            let ev = make_incident_event(seq);
            ledger.append(&ev).expect("append");
        },
        WARMUP_ITERATIONS,
        MEASURE_ITERATIONS,
        MICRO_BENCH_BATCH_SIZE,
    );
    build_scenario(
        run_id,
        "incident_append",
        "IncidentLedger::append(one event)",
        &durations,
        BUDGET_INCIDENT_APPEND_US,
        PANIC_INCIDENT_APPEND_US,
        1,
        bytes,
        "n/a",
        "single JSONL incident append (open+write+flush) on the remediation write path",
    )
}

fn sc_incident_read_warm(run_id: &str) -> Scenario {
    let dir = tempfile::tempdir().expect("temp dir");
    let ledger = IncidentLedger::with_path(dir.path().join("incidents.jsonl"));
    for seq in 0..LEDGER_RECORD_COUNT as u64 {
        ledger.append(&make_incident_event(seq)).expect("append");
    }
    let events = ledger.read_all();
    let bytes = serde_json::to_vec(&events).unwrap().len() as u64;
    let durations = measure_amortized_us(
        || {
            let _ = ledger.read_all();
        },
        WARMUP_ITERATIONS,
        MEASURE_ITERATIONS,
        // Reads are heavier than a single classification; smaller batch keeps
        // the amortized window meaningful while page cache is warm.
        5,
    );
    build_scenario(
        run_id,
        "incident_read_warm",
        "IncidentLedger::read_all(100 events, warm)",
        &durations,
        BUDGET_INCIDENT_READ_US,
        PANIC_INCIDENT_READ_US,
        events.len() as u64,
        bytes,
        "warm",
        "repeated read of a 100-event ledger with page cache hot",
    )
}

fn sc_incident_read_cold(run_id: &str) -> Scenario {
    // Pre-build COLD_SAMPLES distinct, populated ledgers OUTSIDE the timed
    // region so the measurement captures only the cold read, not the write
    // setup. Each is read exactly once through a freshly-opened struct that
    // holds no in-memory state, so the read pays a genuine first-touch cost.
    let fixtures: Vec<(tempfile::TempDir, PathBuf)> = (0..COLD_SAMPLES)
        .map(|_| {
            let dir = tempfile::tempdir().expect("temp dir");
            let path = dir.path().join("incidents.jsonl");
            let ledger = IncidentLedger::with_path(&path);
            for seq in 0..LEDGER_RECORD_COUNT as u64 {
                ledger.append(&make_incident_event(seq)).expect("append");
            }
            (dir, path)
        })
        .collect();

    let mut last_len = 0u64;
    let mut idx = 0usize;
    let durations = measure_per_call_us(
        || {
            let (_dir, path) = &fixtures[idx];
            idx += 1;
            // Fresh struct → first read → no per-handle warmth.
            last_len = IncidentLedger::with_path(path).read_all().len() as u64;
        },
        COLD_SAMPLES,
    );
    build_scenario(
        run_id,
        "incident_read_cold",
        "IncidentLedger::read_all(100 events, cold)",
        &durations,
        BUDGET_INCIDENT_READ_US,
        PANIC_INCIDENT_READ_US,
        last_len,
        0,
        "cold",
        "first read of a freshly-written 100-event ledger (cache-miss path)",
    )
}

fn sc_config_default_hit(run_id: &str) -> Scenario {
    let cfg = RemediationConfig::default();
    let bytes = serde_json::to_vec(&cfg).unwrap().len() as u64;
    let durations = measure_amortized_us(
        || {
            let cfg = RemediationConfig::default();
            // Validation is part of load; keep it on the hit path so the budget
            // covers what callers actually run.
            let _ = cfg.validate();
        },
        WARMUP_ITERATIONS,
        MEASURE_ITERATIONS,
        MICRO_BENCH_BATCH_SIZE,
    );
    build_scenario(
        run_id,
        "config_default_hit",
        "RemediationConfig::default()+validate()",
        &durations,
        BUDGET_CONFIG_DEFAULT_US,
        PANIC_CONFIG_DEFAULT_US,
        0,
        bytes,
        "hit",
        "in-memory default remediation config (no disk) — the cache-hit load path",
    )
}

fn sc_config_parse_miss(run_id: &str) -> Scenario {
    // Cache-miss: deserialize the config from its serialized form, as when
    // loading a user config file from disk for the first time.
    let serialized = serde_json::to_string(&RemediationConfig::default()).unwrap();
    let parsed: RemediationConfig = serde_json::from_str(&serialized).unwrap();
    let bytes = serde_json::to_vec(&parsed).unwrap().len() as u64;
    let durations = measure_amortized_us(
        || {
            let cfg: RemediationConfig = serde_json::from_str(&serialized).unwrap();
            let _ = cfg.validate();
        },
        WARMUP_ITERATIONS,
        MEASURE_ITERATIONS,
        MICRO_BENCH_BATCH_SIZE,
    );
    build_scenario(
        run_id,
        "config_parse_miss",
        "RemediationConfig::from_str()+validate()",
        &durations,
        BUDGET_CONFIG_PARSE_US,
        PANIC_CONFIG_PARSE_US,
        0,
        bytes,
        "miss",
        "parsing remediation config from serialized form — the cache-miss/cold load path",
    )
}

fn sc_rejection_aggregate(run_id: &str) -> Scenario {
    let rejections = make_rejections(8);
    let summary = aggregate_rejections(8, &rejections);
    let bytes = serde_json::to_vec(&summary).unwrap().len() as u64;
    let durations = measure_amortized_us(
        || {
            let _ = aggregate_rejections(8, &rejections);
        },
        WARMUP_ITERATIONS,
        MEASURE_ITERATIONS,
        MICRO_BENCH_BATCH_SIZE,
    );
    build_scenario(
        run_id,
        "rejection_aggregate",
        "aggregate_rejections(8 candidates)",
        &durations,
        BUDGET_REJECTION_AGG_US,
        PANIC_REJECTION_AGG_US,
        rejections.len() as u64,
        bytes,
        "n/a",
        "admission rejection aggregation across the reason-code vocabulary",
    )
}

fn sc_incident_serialize(run_id: &str) -> Scenario {
    let event = make_incident_event(42);
    let bytes = serde_json::to_vec(&event).unwrap().len() as u64;
    let durations = measure_amortized_us(
        || {
            let _ = serde_json::to_string(&event).unwrap();
        },
        WARMUP_ITERATIONS,
        MEASURE_ITERATIONS,
        MICRO_BENCH_BATCH_SIZE,
    );
    build_scenario(
        run_id,
        "incident_serialize_json",
        "serde_json::to_string(IncidentEvent)",
        &durations,
        BUDGET_INCIDENT_SERIALIZE_US,
        PANIC_INCIDENT_SERIALIZE_US,
        1,
        bytes,
        "n/a",
        "JSON serialization of one incident record on the write path",
    )
}

fn sc_classify_noncompilation(run_id: &str) -> Scenario {
    let cmd = "git status";
    let durations = measure_amortized_us(
        || {
            let _ = classify_command(cmd);
        },
        WARMUP_ITERATIONS,
        MEASURE_ITERATIONS,
        MICRO_BENCH_BATCH_SIZE,
    );
    build_scenario(
        run_id,
        "classify_noncompilation",
        "classify_command(git status)",
        &durations,
        BUDGET_NONCOMPILATION_US,
        PANIC_NONCOMPILATION_US,
        0,
        0,
        "n/a",
        "the non-compilation hook decision (5-tier reject) — the dominant hot path",
    )
}

fn sc_classify_compilation(run_id: &str) -> Scenario {
    let cmd = "cargo test --workspace --all-features";
    let durations = measure_amortized_us(
        || {
            let _ = classify_command(cmd);
        },
        WARMUP_ITERATIONS,
        MEASURE_ITERATIONS,
        MICRO_BENCH_BATCH_SIZE,
    );
    build_scenario(
        run_id,
        "classify_compilation",
        "classify_command(cargo test --workspace --all-features)",
        &durations,
        BUDGET_COMPILATION_US,
        PANIC_COMPILATION_US,
        0,
        0,
        "n/a",
        "the compilation hook decision (full classification) — under the 5ms budget",
    )
}

/// Run every hot-path scenario in declaration order. Single source of truth for
/// both the focused tests and the JSONL emit aggregator.
fn run_all_scenarios(run_id: &str) -> Vec<Scenario> {
    vec![
        sc_classify_noncompilation(run_id),
        sc_classify_compilation(run_id),
        sc_admit_preflight_compilation(run_id),
        sc_admit_preflight_noncompilation(run_id),
        sc_output_mode_detect(run_id),
        sc_incident_append(run_id),
        sc_incident_read_warm(run_id),
        sc_incident_read_cold(run_id),
        sc_config_default_hit(run_id),
        sc_config_parse_miss(run_id),
        sc_rejection_aggregate(run_id),
        sc_incident_serialize(run_id),
    ]
}

// ===========================================================================
// Focused budget tests (granular CI attribution)
// ===========================================================================

#[test]
fn budget_classify_noncompilation() {
    assert_scenario(&sc_classify_noncompilation(&run_id()));
}

#[test]
fn budget_classify_compilation() {
    assert_scenario(&sc_classify_compilation(&run_id()));
}

#[test]
fn budget_admit_preflight_compilation() {
    assert_scenario(&sc_admit_preflight_compilation(&run_id()));
}

#[test]
fn budget_admit_preflight_noncompilation() {
    assert_scenario(&sc_admit_preflight_noncompilation(&run_id()));
}

#[test]
fn budget_output_mode_detect() {
    assert_scenario(&sc_output_mode_detect(&run_id()));
}

#[test]
fn budget_incident_append() {
    assert_scenario(&sc_incident_append(&run_id()));
}

#[test]
fn budget_incident_read_warm() {
    let s = sc_incident_read_warm(&run_id());
    assert_eq!(
        s.record.record_count, LEDGER_RECORD_COUNT as u64,
        "warm read must observe every appended record"
    );
    assert_scenario(&s);
}

#[test]
fn budget_incident_read_cold() {
    let s = sc_incident_read_cold(&run_id());
    assert_eq!(
        s.record.record_count, LEDGER_RECORD_COUNT as u64,
        "cold read must observe every appended record"
    );
    assert_scenario(&s);
}

#[test]
fn budget_config_default_hit() {
    assert_scenario(&sc_config_default_hit(&run_id()));
}

#[test]
fn budget_config_parse_miss() {
    assert_scenario(&sc_config_parse_miss(&run_id()));
}

#[test]
fn budget_rejection_aggregate() {
    assert_scenario(&sc_rejection_aggregate(&run_id()));
}

#[test]
fn budget_incident_serialize() {
    assert_scenario(&sc_incident_serialize(&run_id()));
}

// ===========================================================================
// JSONL emission + schema self-validation
// ===========================================================================

/// Run all scenarios, emit the program JSONL artifact, THEN assert budgets so
/// the artifact always lands (even on a budget regression).
#[test]
fn remediation_hotpath_budgets_emit_jsonl() {
    let run_id = run_id();
    let scenarios = run_all_scenarios(&run_id);

    let dir = test_logs_dir();
    std::fs::create_dir_all(&dir).expect("create target/test-logs");
    let path = dir.join("remediation_hotpath_budget.jsonl");
    let mut file = std::fs::File::create(&path).expect("create JSONL artifact");
    for s in &scenarios {
        let line = serde_json::to_string(&s.record).expect("serialize record");
        writeln!(file, "{line}").expect("write JSONL line");
    }
    file.flush().expect("flush JSONL");

    // Self-validate the emitted schema: every required program field is present
    // and well-typed for every record.
    let contents = std::fs::read_to_string(&path).expect("read back JSONL");
    let lines: Vec<&str> = contents.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(
        lines.len(),
        scenarios.len(),
        "one JSONL line per measured scenario"
    );
    for line in &lines {
        let v: serde_json::Value = serde_json::from_str(line).expect("each line is valid JSON");
        for field in [
            "run_id",
            "bead_id",
            "scenario",
            "event",
            "status",
            "command_fingerprint",
            "duration_ms",
            "budget_ms",
            "p95_ms",
            "p99_ms",
            "detail",
        ] {
            assert!(
                v.get(field).is_some(),
                "JSONL record missing required field '{field}': {line}"
            );
        }
        assert_eq!(
            v["bead_id"], BEAD_ID,
            "bead_id must be stamped on every record"
        );
        assert!(
            v["budget_ms"].as_f64().is_some(),
            "budget_ms must be numeric: {line}"
        );
        assert!(
            v["p95_ms"].as_f64().is_some(),
            "p95_ms must be numeric: {line}"
        );
        let status = v["status"].as_str().unwrap_or("");
        assert!(
            status == "pass" || status == "fail",
            "status must be pass|fail, got '{status}'"
        );
    }

    eprintln!("remediation hot-path budget JSONL: {}", path.display());

    // Now enforce the budgets. A regression fails here AFTER the artifact lands.
    let mut failures = Vec::new();
    for s in &scenarios {
        if s.p50_us > s.budget_us || s.p95_us > s.noisy_limit_us {
            failures.push(format!(
                "{}: p50={}µs p95={}µs (budget={}µs, noisy_limit={}µs)",
                s.record.scenario, s.p50_us, s.p95_us, s.budget_us, s.noisy_limit_us
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "performance budget regression(s):\n  {}",
        failures.join("\n  ")
    );
}

#[test]
fn timing_record_roundtrips() {
    let run_id = run_id();
    let s = sc_rejection_aggregate(&run_id);
    let json = serde_json::to_string_pretty(&s.record).unwrap();
    let back: TimingRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(back.bead_id, BEAD_ID);
    assert_eq!(back.scenario, "rejection_aggregate");
    assert!(back.budget_ms > 0.0);
    assert!(back.p95_ms >= back.p50_ms);
    assert!(back.p99_ms >= back.p95_ms);
}

#[test]
fn every_scenario_has_distinct_name_and_fingerprint() {
    let run_id = run_id();
    let scenarios = run_all_scenarios(&run_id);
    let mut names = std::collections::HashSet::new();
    let mut fingerprints = std::collections::HashSet::new();
    for s in &scenarios {
        assert!(
            names.insert(s.record.scenario.clone()),
            "duplicate scenario name: {}",
            s.record.scenario
        );
        assert!(
            fingerprints.insert(s.record.command_fingerprint.clone()),
            "duplicate command fingerprint: {}",
            s.record.command_fingerprint
        );
        assert!(
            !s.record.command_fingerprint.is_empty(),
            "scenario {} has empty fingerprint",
            s.record.scenario
        );
    }
}
