//! Criterion benchmarks for the remediation-program hot paths
//! (bd-session-history-remediation-ocv9i.16.7).
//!
//! These feed the CI `cargo bench` budget gate (scripts/check_benchmark_budgets.py)
//! so a regression in any remediation hot path — admit preflight, incident
//! append/serialize, output-mode detection, config load, or admission-rejection
//! aggregation — fails the benchmark job, not just the integration test.
//!
//! Budgets are derived from README/AGENTS expectations: every operation here is
//! on (or adjacent to) the hook decision path and must stay well under the
//! compilation budget (<5ms); the pure-CPU paths target microseconds. The exact
//! numeric budgets live in scripts/check_benchmark_budgets.py keyed by the group
//! names below.

use criterion::{Criterion, criterion_group, criterion_main};
use rch_common::admission_rejection::{
    AdmissionRejectionCategory, CandidateRejection, aggregate_rejections,
};
use rch_common::admit_preflight::preflight;
use rch_common::incident::{
    IncidentEvent, IncidentEventType, IncidentReasonCode, IncidentSource, SelectedMode,
};
use rch_common::incident_ledger::IncidentLedger;
use rch_common::remediation_config::RemediationConfig;
use rch_common::ui::OutputContext;
use std::hint::black_box;

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

fn bench_admit_preflight(c: &mut Criterion) {
    let mut group = c.benchmark_group("remediation");
    group.bench_function("admit_preflight_compilation", |b| {
        b.iter(|| {
            black_box(preflight(
                black_box("cargo build --release"),
                black_box(true),
            ))
        });
    });
    group.bench_function("admit_preflight_noncompilation", |b| {
        b.iter(|| black_box(preflight(black_box("ls -la /var/log"), black_box(false))));
    });
    group.finish();
}

fn bench_output_mode_detect(c: &mut Criterion) {
    let mut group = c.benchmark_group("remediation");
    group.bench_function("output_mode_detect", |b| {
        b.iter(|| black_box(OutputContext::detect()));
    });
    group.finish();
}

fn bench_incident(c: &mut Criterion) {
    let mut group = c.benchmark_group("remediation");

    let event = make_incident_event(42);
    group.bench_function("incident_serialize", |b| {
        b.iter(|| black_box(serde_json::to_string(black_box(&event)).unwrap()));
    });

    let dir = tempfile::tempdir().expect("temp dir");
    let ledger = IncidentLedger::with_path(dir.path().join("bench-incidents.jsonl"));
    let mut seq: u64 = 0;
    group.bench_function("incident_append", |b| {
        b.iter(|| {
            seq += 1;
            ledger.append(black_box(&make_incident_event(seq))).unwrap();
        });
    });

    // A populated, warm ledger for the read path.
    let read_dir = tempfile::tempdir().expect("temp dir");
    let read_ledger = IncidentLedger::with_path(read_dir.path().join("bench-read.jsonl"));
    for s in 0..100u64 {
        read_ledger.append(&make_incident_event(s)).unwrap();
    }
    group.bench_function("incident_read_warm", |b| {
        b.iter(|| black_box(read_ledger.read_all()));
    });

    group.finish();
}

fn bench_config(c: &mut Criterion) {
    let mut group = c.benchmark_group("remediation");
    group.bench_function("config_default", |b| {
        b.iter(|| {
            let cfg = black_box(RemediationConfig::default());
            black_box(cfg.validate())
        });
    });
    let serialized = serde_json::to_string(&RemediationConfig::default()).unwrap();
    group.bench_function("config_parse", |b| {
        b.iter(|| {
            let cfg: RemediationConfig = serde_json::from_str(black_box(&serialized)).unwrap();
            black_box(cfg.validate())
        });
    });
    group.finish();
}

fn bench_rejection_aggregate(c: &mut Criterion) {
    let mut group = c.benchmark_group("remediation");
    let rejections = make_rejections(8);
    group.bench_function("rejection_aggregate", |b| {
        b.iter(|| black_box(aggregate_rejections(black_box(8), black_box(&rejections))));
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_admit_preflight,
    bench_output_mode_detect,
    bench_incident,
    bench_config,
    bench_rejection_aggregate,
);
criterion_main!(benches);
