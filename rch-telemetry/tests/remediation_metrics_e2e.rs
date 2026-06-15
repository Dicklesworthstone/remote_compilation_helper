//! End-to-end validation for remediation observability
//! (bd-session-history-remediation-ocv9i.14.5).
//!
//! Drives every remediation metric family through a mock scenario, scrapes the
//! Prometheus text endpoint, inspects the emitted OpenTelemetry-compatible spans
//! via a capturing `tracing` layer, and proves:
//!
//! 1. Every metric family appears in a scrape with bounded labels.
//! 2. Span attributes carry the stable, redacted identity fields.
//! 3. No raw command text, absolute/home paths, or secret-shaped values leak
//!    into metric labels or span attributes.
//!
//! It writes JSONL evidence to `target/test-logs/remediation_metrics.jsonl`
//! with one record per scenario: `run_id`, `bead_id`, `scenario`,
//! `metric_name`, `labels`, `value`, `status`, and `detail`.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use prometheus::{Encoder, Registry, TextEncoder};
use serde::Serialize;
use tracing::Subscriber;
use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing_subscriber::layer::{Context, Layer};
use tracing_subscriber::prelude::*;
use tracing_subscriber::registry::LookupSpan;

use rch_common::BypassFailureClass;
use rch_common::bypass_recovery::CanaryOutcome;
use rch_common::disk_pressure_report::{DiskRootKind, PressureLevel};
use rch_common::incident::{IncidentEventType, IncidentReasonCode, IncidentSource, SelectedMode};
use rch_common::proof_replay::{ProofState, ReplayOutcome};
use rch_common::queue_contract::QueueContractOutcome;
use rch_common::telemetry_freshness::FreshnessVerdict;
use rch_telemetry::remediation::{
    AdmissionDecision, BypassTransition, RemediationAttributes, RemediationMetrics,
    SelfHealingAction, SelfHealingOutcome,
};

const BEAD_ID: &str = "bd-session-history-remediation-ocv9i.14.5";

// ---------------------------------------------------------------------------
// JSONL evidence record (matches the program schema for 14.5)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
struct EvidenceRecord {
    ts_unix_ms: u64,
    run_id: String,
    bead_id: String,
    scenario: String,
    metric_name: String,
    labels: BTreeMap<String, String>,
    value: f64,
    status: String,
    detail: String,
}

fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

fn run_id() -> String {
    format!("run-{}-{}", now_unix_ms(), std::process::id())
}

/// Resolve the workspace `target/test-logs` directory, honoring CARGO_TARGET_DIR.
fn test_logs_dir() -> PathBuf {
    let target = std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            // tests/ lives under rch-telemetry/; the workspace target is one up.
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .map(|p| p.join("target"))
                .unwrap_or_else(|| PathBuf::from("target"))
        });
    target.join("test-logs")
}

// ---------------------------------------------------------------------------
// Span-capturing tracing layer (the "inspect traces" surface)
// ---------------------------------------------------------------------------

#[derive(Default)]
struct CapturedFields(BTreeMap<String, String>);

struct FieldVisitor<'a>(&'a mut BTreeMap<String, String>);

impl Visit for FieldVisitor<'_> {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.0.insert(field.name().to_string(), value.to_string());
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        // `%`-recorded (Display) fields arrive here as a format_args debug, which
        // prints the Display string without surrounding quotes.
        self.0
            .entry(field.name().to_string())
            .or_insert_with(|| format!("{value:?}"));
    }
}

#[derive(Clone, Default)]
struct SpanCapture {
    spans: Arc<Mutex<Vec<BTreeMap<String, String>>>>,
}

impl<S> Layer<S> for SpanCapture
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_new_span(&self, attrs: &Attributes<'_>, id: &Id, ctx: Context<'_, S>) {
        let span = ctx.span(id).expect("span must exist on creation");
        let mut fields = BTreeMap::new();
        fields.insert("__name__".to_string(), span.name().to_string());
        attrs.record(&mut FieldVisitor(&mut fields));
        span.extensions_mut().insert(CapturedFields(fields));
    }

    fn on_record(&self, id: &Id, values: &Record<'_>, ctx: Context<'_, S>) {
        let span = ctx.span(id).expect("span must exist on record");
        let mut ext = span.extensions_mut();
        if let Some(CapturedFields(map)) = ext.get_mut::<CapturedFields>() {
            values.record(&mut FieldVisitor(map));
        }
    }

    fn on_close(&self, id: Id, ctx: Context<'_, S>) {
        let span = ctx.span(&id).expect("span must exist on close");
        if let Some(CapturedFields(map)) = span.extensions().get::<CapturedFields>() {
            self.spans.lock().expect("capture lock").push(map.clone());
        }
    }
}

// ---------------------------------------------------------------------------
// Scrape helpers
// ---------------------------------------------------------------------------

fn gather_text(registry: &Registry) -> String {
    let encoder = TextEncoder::new();
    let mut buffer = Vec::new();
    encoder
        .encode(&registry.gather(), &mut buffer)
        .expect("encode metrics");
    String::from_utf8(buffer).expect("utf8 metrics")
}

/// Find the value for an exact `name{labels}` (or label-less name) line in a
/// Prometheus text scrape. Returns `None` if the series is absent.
fn scrape_value(text: &str, exact_series: &str) -> Option<f64> {
    for line in text.lines() {
        if line.starts_with('#') {
            continue;
        }
        if let Some(rest) = line.strip_prefix(exact_series) {
            let rest = rest.trim_start();
            // Guard against prefix collisions: a real match leaves only the value.
            if let Ok(value) = rest.parse::<f64>() {
                return Some(value);
            }
        }
    }
    None
}

fn labels(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect()
}

/// Render labels the way the Prometheus text format does: `{k="v",k2="v2"}`,
/// keys in sorted order (BTreeMap iterates sorted, matching the encoder).
fn series(name: &str, labels: &BTreeMap<String, String>) -> String {
    if labels.is_empty() {
        return name.to_string();
    }
    let inner = labels
        .iter()
        .map(|(k, v)| format!("{k}=\"{v}\""))
        .collect::<Vec<_>>()
        .join(",");
    format!("{name}{{{inner}}}")
}

#[test]
fn remediation_metrics_scrape_traces_and_evidence() {
    let run = run_id();
    let metrics = RemediationMetrics::new().expect("construct remediation metrics");
    let registry = Registry::new();
    metrics.register(&registry).expect("register");

    let capture = SpanCapture::default();
    let subscriber = tracing_subscriber::registry().with(capture.clone());

    // Drive every metric family under the span-capturing subscriber so the
    // incident recordings also produce inspectable spans.
    tracing::subscriber::with_default(subscriber, || {
        // Incident (admission, no admissible workers) — carries a worker id.
        metrics.record_incident(
            &RemediationAttributes::new(
                IncidentEventType::Admission,
                IncidentReasonCode::NoAdmissibleWorkers,
                IncidentSource::Daemon,
                SelectedMode::Local,
                "cargo build --release",
                "proj-7f3a9c01",
            )
            .with_worker("ovh-a")
            .with_queue("q-42")
            .with_job("job-99"),
        );

        // Redaction guard: a secret-laden fingerprint + absolute home path must
        // never reach the span.
        metrics.record_incident(&RemediationAttributes::new(
            IncidentEventType::Fallback,
            IncidentReasonCode::LocalFallback,
            IncidentSource::Hook,
            SelectedMode::Local,
            "cargo build ghp_ABCDEFGHIJKLMNOPQRSTUVWX",
            "/home/alice/projects/secret-app",
        ));

        metrics.record_admission(AdmissionDecision::Local, "all_workers_busy");
        metrics.set_proof_state(ProofState::Queued, 4);
        metrics.record_proof_transition(ProofState::Queued, ProofState::Replaying);
        metrics.record_proof_outcome(ReplayOutcome::Succeeded);
        metrics.set_queue_depth(5);
        metrics.observe_queue_wait(1.5);
        metrics.record_queue_outcome(&QueueContractOutcome::TimedOutQueued);
        metrics.record_worker_ineligible(BypassFailureClass::DiskInodePressure);
        metrics.record_bypass_transition(BypassTransition::ReadyForCanary);
        metrics.record_canary(CanaryOutcome::Failed);
        metrics.set_disk_pressure(DiskRootKind::CargoHome, PressureLevel::Warning);
        metrics.record_telemetry_freshness(FreshnessVerdict::SlowObserver, 0.7);
        metrics.record_artifact_retrieval(
            rch_common::artifact_cost::RetrievalMode::Glob,
            100,
            1_048_576,
        );
        metrics.record_self_healing(SelfHealingAction::WorkerRejoin, SelfHealingOutcome::Success);
    });

    let text = gather_text(&registry);

    // ---- Scenarios: one JSONL evidence record per metric family ----
    struct Scenario {
        scenario: &'static str,
        metric_name: &'static str,
        labels: Vec<(&'static str, &'static str)>,
        expected: f64,
        detail: &'static str,
    }

    let scenarios = vec![
        Scenario {
            scenario: "incident_admission_no_admissible_workers",
            metric_name: "rch_remediation_incident_total",
            labels: vec![
                ("event_type", "admission"),
                ("reason_code", "RCH-I001"),
                ("source", "daemon"),
            ],
            expected: 1.0,
            detail: "admission incident keyed by stable reason code",
        },
        Scenario {
            scenario: "incident_local_fallback_redaction_guard",
            metric_name: "rch_remediation_incident_total",
            labels: vec![
                ("event_type", "fallback"),
                ("reason_code", "RCH-I011"),
                ("source", "hook"),
            ],
            expected: 1.0,
            detail: "local-fallback incident; secret/path redacted before span",
        },
        Scenario {
            scenario: "admission_local_fallback_all_workers_busy",
            metric_name: "rch_remediation_admission_total",
            labels: vec![("decision", "local"), ("reason", "all_workers_busy")],
            expected: 1.0,
            detail: "selection fallback to local, normalized reason",
        },
        Scenario {
            scenario: "proof_state_queued_gauge",
            metric_name: "rch_remediation_proof_state",
            labels: vec![("state", "queued")],
            expected: 4.0,
            detail: "proof intents currently queued",
        },
        Scenario {
            scenario: "proof_transition_queued_to_replaying",
            metric_name: "rch_remediation_proof_transition_total",
            labels: vec![("from", "queued"), ("to", "replaying")],
            expected: 1.0,
            detail: "conveyor promoted a queued intent to replaying",
        },
        Scenario {
            scenario: "proof_outcome_succeeded",
            metric_name: "rch_remediation_proof_outcome_total",
            labels: vec![("outcome", "succeeded")],
            expected: 1.0,
            detail: "replay attempt resolved as product success",
        },
        Scenario {
            scenario: "queue_depth_gauge",
            metric_name: "rch_remediation_queue_depth",
            labels: vec![],
            expected: 5.0,
            detail: "pending placements in the capacity queue",
        },
        Scenario {
            scenario: "queue_wait_histogram",
            metric_name: "rch_remediation_queue_wait_seconds_count",
            labels: vec![],
            expected: 1.0,
            detail: "one placement wait observed",
        },
        Scenario {
            scenario: "queue_outcome_timed_out",
            metric_name: "rch_remediation_queue_outcome_total",
            labels: vec![("outcome", "timed_out_queued")],
            expected: 1.0,
            detail: "queued placement timed out waiting",
        },
        Scenario {
            scenario: "worker_ineligible_disk_inode_pressure",
            metric_name: "rch_remediation_worker_ineligible_total",
            labels: vec![("reason", "disk_inode_pressure")],
            expected: 1.0,
            detail: "worker rejected for disk/inode pressure",
        },
        Scenario {
            scenario: "bypass_transition_ready_for_canary",
            metric_name: "rch_remediation_bypass_transition_total",
            labels: vec![("transition", "ready_for_canary")],
            expected: 1.0,
            detail: "bypassed worker passed probes; canary scheduled",
        },
        Scenario {
            scenario: "canary_failed",
            metric_name: "rch_remediation_canary_total",
            labels: vec![("outcome", "failed")],
            expected: 1.0,
            detail: "auto-rejoin canary build failed",
        },
        Scenario {
            scenario: "disk_pressure_cargo_home_warning",
            metric_name: "rch_remediation_disk_pressure_level",
            labels: vec![("root_kind", "cargo_home")],
            expected: 2.0,
            detail: "cargo home at warning severity (rank 2)",
        },
        Scenario {
            scenario: "telemetry_freshness_slow_observer",
            metric_name: "rch_remediation_telemetry_freshness_total",
            labels: vec![("verdict", "slow_observer")],
            expected: 1.0,
            detail: "telemetry old but explained by a slow observer",
        },
        Scenario {
            scenario: "telemetry_confidence_histogram",
            metric_name: "rch_remediation_telemetry_confidence_count",
            labels: vec![],
            expected: 1.0,
            detail: "one freshness-confidence sample observed",
        },
        Scenario {
            scenario: "artifact_files_glob",
            metric_name: "rch_remediation_artifact_files_total",
            labels: vec![("mode", "glob")],
            expected: 100.0,
            detail: "files retrieved via glob",
        },
        Scenario {
            scenario: "artifact_bytes_glob",
            metric_name: "rch_remediation_artifact_bytes_total",
            labels: vec![("mode", "glob")],
            expected: 1_048_576.0,
            detail: "bytes retrieved via glob",
        },
        Scenario {
            scenario: "self_healing_worker_rejoin_success",
            metric_name: "rch_remediation_self_healing_total",
            labels: vec![("action", "worker_rejoin"), ("outcome", "success")],
            expected: 1.0,
            detail: "bypassed worker auto-rejoined the pool",
        },
    ];

    let mut evidence = Vec::new();
    for s in &scenarios {
        let label_map = labels(&s.labels);
        let needle = series(s.metric_name, &label_map);
        let observed = scrape_value(&text, &needle);
        let status = if observed == Some(s.expected) {
            "pass"
        } else {
            "fail"
        };
        evidence.push(EvidenceRecord {
            ts_unix_ms: now_unix_ms(),
            run_id: run.clone(),
            bead_id: BEAD_ID.to_string(),
            scenario: s.scenario.to_string(),
            metric_name: s.metric_name.to_string(),
            labels: label_map,
            value: observed.unwrap_or(f64::NAN),
            status: status.to_string(),
            detail: s.detail.to_string(),
        });
        assert_eq!(
            observed,
            Some(s.expected),
            "scenario {} expected {} {} = {}, scrape:\n{}",
            s.scenario,
            s.metric_name,
            needle,
            s.expected,
            text
        );
    }

    // ---- Bounded cardinality + no-leak guarantees on the scrape ----
    assert!(
        !text.contains("/home/") && !text.contains("alice"),
        "scrape must not leak home paths or usernames:\n{text}"
    );
    assert!(
        !text.contains("ghp_ABCDEFGHIJKLMNOPQRSTUVWX"),
        "scrape must not leak secret-shaped values:\n{text}"
    );
    // The whole remediation inventory stays within a small, fixed series count.
    let remediation_series = text
        .lines()
        .filter(|l| l.starts_with("rch_remediation_"))
        .count();
    assert!(
        remediation_series < 200,
        "remediation series count {remediation_series} unexpectedly large"
    );

    // ---- Span inspection: stable, redacted attributes ----
    let spans = capture.spans.lock().expect("capture lock").clone();
    let incident_spans: Vec<_> = spans
        .iter()
        .filter(|s| s.get("__name__").map(String::as_str) == Some("remediation.incident"))
        .collect();
    assert_eq!(
        incident_spans.len(),
        2,
        "expected two remediation.incident spans, got {}: {spans:?}",
        incident_spans.len()
    );
    // Every incident span carries the stable identity attributes.
    for span in &incident_spans {
        for key in [
            "event_type",
            "reason_code",
            "source",
            "selected_mode",
            "command_fingerprint",
            "project_id",
        ] {
            assert!(span.contains_key(key), "span missing {key}: {span:?}");
        }
        // No raw secret / home path / username on any span attribute.
        for value in span.values() {
            assert!(!value.contains("/home/"), "span leaked home path: {span:?}");
            assert!(!value.contains("alice"), "span leaked username: {span:?}");
            assert!(
                !value.contains("ghp_ABCDEFGHIJKLMNOPQRSTUVWX"),
                "span leaked secret: {span:?}"
            );
        }
    }
    // The admission incident span carried the worker/queue/job correlation ids.
    let with_worker = incident_spans
        .iter()
        .find(|s| s.get("worker_id").map(String::as_str) == Some("ovh-a"))
        .expect("an incident span should carry worker_id=ovh-a");
    assert_eq!(
        with_worker.get("queue_id").map(String::as_str),
        Some("q-42")
    );
    assert_eq!(
        with_worker.get("job_id").map(String::as_str),
        Some("job-99")
    );
    assert_eq!(
        with_worker.get("reason_code").map(String::as_str),
        Some("RCH-I001")
    );
    // The redaction-guard span hashed the project path and masked the token.
    let redacted = incident_spans
        .iter()
        .find(|s| s.get("reason_code").map(String::as_str) == Some("RCH-I011"))
        .expect("the fallback incident span");
    assert!(
        redacted
            .get("project_id")
            .map(|p| p.starts_with("blake3:"))
            .unwrap_or(false),
        "project path must be hashed: {redacted:?}"
    );

    // ---- Write + validate JSONL evidence ----
    let dir = test_logs_dir();
    std::fs::create_dir_all(&dir).expect("create target/test-logs");
    let path = dir.join("remediation_metrics.jsonl");
    let mut file = std::fs::File::create(&path).expect("create JSONL artifact");
    for record in &evidence {
        let line = serde_json::to_string(record).expect("serialize evidence");
        writeln!(file, "{line}").expect("write JSONL line");
    }
    file.flush().expect("flush JSONL");

    let contents = std::fs::read_to_string(&path).expect("read back JSONL");
    let lines: Vec<&str> = contents.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(lines.len(), scenarios.len(), "one JSONL line per scenario");
    for line in &lines {
        let v: serde_json::Value = serde_json::from_str(line).expect("valid JSON evidence");
        for field in [
            "run_id",
            "bead_id",
            "scenario",
            "metric_name",
            "status",
            "detail",
        ] {
            assert!(
                v[field].is_string(),
                "evidence field {field} must be a string"
            );
        }
        assert!(v["labels"].is_object(), "labels must be an object");
        assert!(v["value"].is_number(), "value must be a number");
        assert_eq!(v["bead_id"], BEAD_ID, "evidence must be keyed to the bead");
        assert_eq!(v["status"], "pass", "every scenario must pass");
    }
}
