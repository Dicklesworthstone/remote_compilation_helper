//! Golden-schema and reason-code regression tests for the stable agent-facing
//! surfaces in `rch-common` (bd-session-history-remediation-ocv9i.16.4).
//!
//! Covers the incident event schema + reason-code registry, the adaptive
//! telemetry freshness model, and the telemetry "why-unhealthy" explanation
//! model. Each machine-readable surface has a golden for success, degraded, and
//! failure cases. A renamed field, a changed reason code, or an altered
//! vocabulary makes the serialized output diverge from the committed golden and
//! fails the test — exactly the "schema export fails if a field is renamed
//! without an intentional version bump" gate.
//!
//! Goldens are inline canonical JSON (`json!`) rather than external fixture
//! files: comparison is structural (`serde_json::Value` equality, so key order
//! is irrelevant) and the expected values live in version control next to the
//! constructors they pin. To update a golden after a reviewed, intentional
//! change, edit the corresponding `json!` block and bump the schema version.

use rch_common::bypass_record::{AutoRejoinCriteria, BypassFailureClass, BypassRecord};
use rch_common::incident::{
    ControlState, IncidentEvent, IncidentEventType, IncidentReasonCode, IncidentSource,
    SelectedMode,
};
use rch_common::telemetry_explain::{ProbeOutcome, TelemetrySignals, WhyUnhealthy};
use rch_common::telemetry_freshness::{FreshnessInputs, assess};
use serde_json::{Value, json};
use std::time::Duration;

const FIXED_TS: u64 = 1_700_000_000_000;

/// Assert a value's serialization equals its golden, with a blessable diff.
fn assert_golden<T: serde::Serialize>(name: &str, value: &T, expected: Value) {
    let actual = serde_json::to_value(value).expect("value serializes");
    assert_eq!(
        actual,
        expected,
        "golden drift in {name}: a field/value/vocabulary changed. If intentional, \
         bump the schema version and update the json! block.\nactual:\n{}",
        serde_json::to_string_pretty(&actual).unwrap()
    );
}

// ---------------------------------------------------------------------------
// Incident event schema (success / degraded / failure)
// ---------------------------------------------------------------------------

#[test]
fn golden_incident_local_fallback_success() {
    let event = IncidentEvent::new(
        IncidentEventType::Fallback,
        IncidentReasonCode::LocalFallback,
        IncidentSource::Hook,
        "proj-fixture",
        "cargo test",
        SelectedMode::Local,
        true,
        FIXED_TS,
    );
    assert_golden(
        "incident_local_fallback_success",
        &event,
        json!({
            "schema_version": "1.0.0",
            "event_type": "fallback",
            "reason_code": "RCH-I011",
            "project_id": "proj-fixture",
            "command_fingerprint": "cargo test",
            "selected_mode": "local",
            "local_fallback_allowed": true,
            "source": "hook",
            "occurred_at_unix_ms": 1_700_000_000_000_u64,
        }),
    );
}

#[test]
fn golden_incident_circuit_open_degraded() {
    let event = IncidentEvent::new(
        IncidentEventType::WorkerLifecycle,
        IncidentReasonCode::CircuitOpen,
        IncidentSource::Daemon,
        "proj-fixture",
        "cargo build",
        SelectedMode::Remote,
        true,
        FIXED_TS,
    )
    .with_worker_id("css");
    assert_golden(
        "incident_circuit_open_degraded",
        &event,
        json!({
            "schema_version": "1.0.0",
            "event_type": "worker_lifecycle",
            "reason_code": "RCH-I009",
            "project_id": "proj-fixture",
            "command_fingerprint": "cargo build",
            "worker_id": "css",
            "selected_mode": "remote",
            "local_fallback_allowed": true,
            "source": "daemon",
            "occurred_at_unix_ms": 1_700_000_000_000_u64,
        }),
    );
}

#[test]
fn golden_incident_no_admissible_workers_failure() {
    let event = IncidentEvent::new(
        IncidentEventType::Admission,
        IncidentReasonCode::NoAdmissibleWorkers,
        IncidentSource::Daemon,
        "proj-fixture",
        "cargo build",
        SelectedMode::Local,
        false,
        FIXED_TS,
    )
    .with_control(ControlState {
        requested_worker: Some("css".to_string()),
        strict_remote_policy: true,
        ..ControlState::default()
    })
    .with_detail("candidates", "3");
    assert_golden(
        "incident_no_admissible_workers_failure",
        &event,
        json!({
            "schema_version": "1.0.0",
            "event_type": "admission",
            "reason_code": "RCH-I001",
            "project_id": "proj-fixture",
            "command_fingerprint": "cargo build",
            "selected_mode": "local",
            "local_fallback_allowed": false,
            "source": "daemon",
            "occurred_at_unix_ms": 1_700_000_000_000_u64,
            "control": { "requested_worker": "css", "strict_remote_policy": true },
            "details": { "candidates": "3" },
        }),
    );
}

// ---------------------------------------------------------------------------
// Worker temporary-bypass record (success / degraded / failure)
// ---------------------------------------------------------------------------

/// A freshly-bypassed worker (transient SSH failure). The "success" case: the
/// recovery path quarantined it cleanly with a stable reason code and a probe
/// already scheduled.
#[test]
fn golden_bypass_fresh_ssh() {
    let record = BypassRecord::new(
        "css",
        "203.0.113.20",
        "ubuntu",
        BypassFailureClass::Ssh,
        FIXED_TS,
    )
    .with_diagnostic("ssh: connection timed out");
    assert_golden(
        "bypass_fresh_ssh",
        &record,
        json!({
            "schema_version": "1.0.0",
            "worker_id": "css",
            "host": "203.0.113.20",
            "user": "ubuntu",
            "failure_class": "ssh",
            "reason_code": "RCH-I004",
            "state": "temporary_bypass",
            "first_failure_unix_ms": 1_700_000_000_000_u64,
            "last_failure_unix_ms": 1_700_000_000_000_u64,
            "next_probe_unix_ms": 1_700_000_030_000_u64,
            "backoff": { "current_ms": 30_000, "attempts": 0, "max_ms": 900_000 },
            "consecutive_failures": 1,
            "consecutive_passes": 0,
            "last_diagnostic": "ssh: connection timed out",
            "auto_rejoin": { "required_consecutive_passes": 2, "canary_required": true },
            "local_fallback_allowed": true,
        }),
    );
}

/// A worker that passed recovery and is awaiting its canary build. The
/// "degraded" middle state: out of normal scheduling but on its way back.
#[test]
fn golden_bypass_recovered_pending_canary() {
    let mut record = BypassRecord::new(
        "bil",
        "203.0.113.21",
        "ubuntu",
        BypassFailureClass::CircuitBreaker,
        FIXED_TS,
    );
    // Two passing probes meet the default criteria → pending canary.
    assert!(!record.record_probe_pass(FIXED_TS + 30_000));
    assert!(record.record_probe_pass(FIXED_TS + 60_000));
    assert_golden(
        "bypass_recovered_pending_canary",
        &record,
        json!({
            "schema_version": "1.0.0",
            "worker_id": "bil",
            "host": "203.0.113.21",
            "user": "ubuntu",
            "failure_class": "circuit_breaker",
            "reason_code": "RCH-I009",
            "state": "recovered_pending_canary",
            "first_failure_unix_ms": 1_700_000_000_000_u64,
            "last_failure_unix_ms": 1_700_000_000_000_u64,
            "next_probe_unix_ms": 1_700_000_090_000_u64,
            "backoff": { "current_ms": 30_000, "attempts": 0, "max_ms": 900_000 },
            "consecutive_failures": 0,
            "consecutive_passes": 2,
            "last_diagnostic": "",
            "auto_rejoin": { "required_consecutive_passes": 2, "canary_required": true },
            "local_fallback_allowed": true,
        }),
    );
}

/// A worker repeatedly failing on disk pressure with local fallback denied
/// (strict-remote). The "failure" case: backoff has grown, details are carried,
/// and the record reflects a worker that keeps failing its probes.
#[test]
fn golden_bypass_disk_pressure_repeated_failure() {
    let mut record = BypassRecord::new(
        "vmi",
        "203.0.113.22",
        "ubuntu",
        BypassFailureClass::DiskInodePressure,
        FIXED_TS,
    )
    .with_local_fallback_allowed(false)
    .with_detail("free_gb", "0.4");
    // One additional failed probe doubles the backoff (30s → 60s).
    record.record_failure(FIXED_TS + 30_000, "no space left on device");
    assert_golden(
        "bypass_disk_pressure_repeated_failure",
        &record,
        json!({
            "schema_version": "1.0.0",
            "worker_id": "vmi",
            "host": "203.0.113.22",
            "user": "ubuntu",
            "failure_class": "disk_inode_pressure",
            "reason_code": "RCH-I016",
            "state": "temporary_bypass",
            "first_failure_unix_ms": 1_700_000_000_000_u64,
            "last_failure_unix_ms": 1_700_000_030_000_u64,
            "next_probe_unix_ms": 1_700_000_090_000_u64,
            "backoff": { "current_ms": 60_000, "attempts": 1, "max_ms": 900_000 },
            "consecutive_failures": 2,
            "consecutive_passes": 0,
            "last_diagnostic": "no space left on device",
            "auto_rejoin": { "required_consecutive_passes": 2, "canary_required": true },
            "local_fallback_allowed": false,
            "details": { "free_gb": "0.4" },
        }),
    );
}

/// The auto-rejoin criteria default is part of the contract dashboards key off.
#[test]
fn golden_bypass_custom_auto_rejoin() {
    let record = BypassRecord::new(
        "css",
        "h",
        "u",
        BypassFailureClass::StaleTelemetry,
        FIXED_TS,
    )
    .with_auto_rejoin(AutoRejoinCriteria {
        required_consecutive_passes: 3,
        canary_required: false,
    });
    let value = serde_json::to_value(&record).unwrap();
    assert_eq!(value["state"], "temporary_bypass");
    assert_eq!(value["reason_code"], "RCH-I008");
    assert_eq!(
        value["auto_rejoin"],
        json!({ "required_consecutive_passes": 3, "canary_required": false })
    );
}

// ---------------------------------------------------------------------------
// Adaptive telemetry freshness (success / degraded / failure)
// ---------------------------------------------------------------------------

#[test]
fn golden_freshness_fresh_success() {
    let a = assess(&FreshnessInputs::new(
        Duration::from_secs(30),
        Duration::from_secs(20),
        Duration::from_secs(10),
    ));
    assert_golden("freshness_fresh_success", &a, freshness_fresh_value());
}

#[test]
fn golden_freshness_slow_observer_degraded() {
    let a = assess(&FreshnessInputs {
        host_rtt: Some(Duration::from_secs(8)),
        age: Some(Duration::from_secs(56)),
        ..FreshnessInputs::new(
            Duration::from_secs(30),
            Duration::from_secs(20),
            Duration::from_secs(56),
        )
    });
    assert_golden(
        "freshness_slow_observer_degraded",
        &a,
        json!({
            "verdict": "slow_observer",
            "expected_next_sample_ms": 46_000,
            "tolerated_age_ms": 66_000,
            "last_poll_duration_ms": 30_000,
            "timeout_count": 0,
            "confidence": 0.5,
            "age_ms": 56_000,
            "usable": true,
            "reason": "high host latency",
        }),
    );
}

#[test]
fn golden_freshness_stale_failure() {
    let a = assess(&FreshnessInputs::new(
        Duration::from_secs(30),
        Duration::from_secs(20),
        Duration::from_secs(600),
    ));
    assert_golden(
        "freshness_stale_failure",
        &a,
        json!({
            "verdict": "stale",
            "expected_next_sample_ms": 30_000,
            "tolerated_age_ms": 50_000,
            "last_poll_duration_ms": 30_000,
            "timeout_count": 0,
            "confidence": 0.0,
            "age_ms": 600_000,
            "usable": false,
            "reason": "telemetry genuinely stale beyond adaptive tolerance",
        }),
    );
}

/// The fresh-assessment golden, reused by the WhyUnhealthy nested golden.
fn freshness_fresh_value() -> Value {
    json!({
        "verdict": "fresh",
        "expected_next_sample_ms": 30_000,
        "tolerated_age_ms": 50_000,
        "last_poll_duration_ms": 30_000,
        "timeout_count": 0,
        "confidence": 1.0,
        "age_ms": 10_000,
        "usable": true,
        "reason": "within expected sampling window",
    })
}

// ---------------------------------------------------------------------------
// Why-unhealthy explanation (success / degraded / failure)
// ---------------------------------------------------------------------------

#[test]
fn golden_why_unhealthy_healthy_success() {
    let a = assess(&FreshnessInputs::new(
        Duration::from_secs(30),
        Duration::from_secs(20),
        Duration::from_secs(10),
    ));
    let w =
        WhyUnhealthy::from_freshness("css", a, ProbeOutcome::Ok, ProbeOutcome::Ok, Some(20_000));
    assert_golden(
        "why_unhealthy_healthy_success",
        &w,
        json!({
            "worker_id": "css",
            "healthy": true,
            "freshness": freshness_fresh_value(),
            "last_probe_result": "ok",
            "last_telemetry_result": "ok",
            "next_probe_in_ms": 20_000,
            "observer_behind": false,
            "explanation": "usable: within expected sampling window",
        }),
    );
}

#[test]
fn golden_why_unhealthy_observer_degraded() {
    let w = WhyUnhealthy::from_missing(
        "css",
        &TelemetrySignals {
            poller_behind: true,
            ..TelemetrySignals::default()
        },
        ProbeOutcome::Ok,
        ProbeOutcome::Timeout,
        Some(15_000),
    );
    assert_golden(
        "why_unhealthy_observer_degraded",
        &w,
        json!({
            "worker_id": "css",
            "healthy": false,
            "unavailability": "poller_overloaded",
            "last_probe_result": "ok",
            "last_telemetry_result": "timeout",
            "next_probe_in_ms": 15_000,
            "observer_behind": true,
            "explanation": "telemetry unknown — the telemetry poll loop is saturated/behind; this is an observer issue, not the worker (observer-side)",
        }),
    );
}

#[test]
fn golden_why_unhealthy_worker_failure() {
    let w = WhyUnhealthy::from_missing(
        "css",
        &TelemetrySignals {
            worker_supports_telemetry: Some(false),
            ..TelemetrySignals::default()
        },
        ProbeOutcome::Ok,
        ProbeOutcome::NotAttempted,
        None,
    );
    assert_golden(
        "why_unhealthy_worker_failure",
        &w,
        json!({
            "worker_id": "css",
            "healthy": false,
            "unavailability": "worker_lacks_telemetry",
            "last_probe_result": "ok",
            "last_telemetry_result": "not_attempted",
            "observer_behind": false,
            "explanation": "telemetry unknown — worker binary does not provide `rch-wkr telemetry` (upgrade the worker) (worker-side)",
        }),
    );
}

// ---------------------------------------------------------------------------
// Frozen reason-code vocabularies — rename/reorder/renumber detection.
// ---------------------------------------------------------------------------

#[test]
fn incident_reason_code_vocabulary_is_frozen() {
    let actual: Vec<(String, String)> = IncidentReasonCode::ALL
        .iter()
        .map(|r| (r.code().to_string(), r.failure_class().to_string()))
        .collect();
    let expected: Vec<(String, String)> = [
        ("RCH-I001", "no admissible workers"),
        ("RCH-I002", "critical pressure"),
        ("RCH-I003", "insufficient slots"),
        ("RCH-I004", "hard preflight"),
        ("RCH-I005", "active project exclusion"),
        ("RCH-I006", "missing runtime/toolchain/Rust target"),
        ("RCH-I007", "OS/arch mismatch"),
        ("RCH-I008", "telemetry stale/age unknown"),
        ("RCH-I009", "circuit open"),
        ("RCH-I010", "daemon socket refused"),
        ("RCH-I011", "local fallback"),
        ("RCH-I012", "proof refusal"),
        ("RCH-I013", "rsync vanished file"),
        ("RCH-I014", "artifact miss"),
        ("RCH-I015", "queue ambiguity"),
        ("RCH-I016", "disk full"),
        ("RCH-I017", "wrong user/path worker binary"),
        // RCH-I018 added by bd-784xt (self-test canary tolerates heterogeneous
        // toolchain codegen drift): an advisory pass distinct from a real
        // miscompile/corruption. Intentional vocabulary extension.
        ("RCH-I018", "toolchain drift"),
    ]
    .into_iter()
    .map(|(c, f)| (c.to_string(), f.to_string()))
    .collect();
    assert_eq!(
        actual, expected,
        "incident reason-code vocabulary drifted; this is the stable agent-facing \
         contract — only edit with an intentional version bump"
    );
}

#[test]
fn telemetry_unavailability_vocabulary_is_frozen() {
    use rch_common::telemetry_explain::TelemetryUnavailabilityReason as R;
    let all = [
        R::WorkerLacksTelemetry,
        R::ParseFailed,
        R::Pruned,
        R::DaemonRestarted,
        R::PollerOverloaded,
        R::NeverArrived,
    ];
    let actual: Vec<(String, bool)> = all
        .iter()
        .map(|r| (r.as_str().to_string(), r.is_observer_side()))
        .collect();
    let expected: Vec<(String, bool)> = [
        ("worker_lacks_telemetry", false),
        ("parse_failed", false),
        ("pruned", true),
        ("daemon_restarted", true),
        ("poller_overloaded", true),
        ("never_arrived", false),
    ]
    .into_iter()
    .map(|(s, o)| (s.to_string(), o))
    .collect();
    assert_eq!(
        actual, expected,
        "telemetry unavailability vocabulary drifted"
    );
}

// ---------------------------------------------------------------------------
// Envelope field-name freeze — top-level keys per surface.
// ---------------------------------------------------------------------------

fn top_level_keys(value: &Value) -> Vec<String> {
    let mut keys: Vec<String> = value.as_object().expect("object").keys().cloned().collect();
    keys.sort_unstable();
    keys
}

#[test]
fn incident_event_field_names_are_stable() {
    let event = IncidentEvent::new(
        IncidentEventType::Admission,
        IncidentReasonCode::NoAdmissibleWorkers,
        IncidentSource::Daemon,
        "p",
        "cmd",
        SelectedMode::Local,
        false,
        FIXED_TS,
    )
    .with_worker_id("css")
    .with_control(ControlState {
        strict_remote_policy: true,
        ..ControlState::default()
    })
    .with_detail("k", "v");
    assert_eq!(
        top_level_keys(&serde_json::to_value(&event).unwrap()),
        vec![
            "command_fingerprint",
            "control",
            "details",
            "event_type",
            "local_fallback_allowed",
            "occurred_at_unix_ms",
            "project_id",
            "reason_code",
            "schema_version",
            "selected_mode",
            "source",
            "worker_id",
        ]
    );
}

#[test]
fn freshness_assessment_field_names_are_stable() {
    let a = assess(&FreshnessInputs::new(
        Duration::from_secs(30),
        Duration::from_secs(20),
        Duration::from_secs(10),
    ));
    assert_eq!(
        top_level_keys(&serde_json::to_value(&a).unwrap()),
        vec![
            "age_ms",
            "confidence",
            "expected_next_sample_ms",
            "last_poll_duration_ms",
            "reason",
            "timeout_count",
            "tolerated_age_ms",
            "usable",
            "verdict",
        ]
    );
}

#[test]
fn why_unhealthy_field_names_are_stable() {
    let w = WhyUnhealthy::from_missing(
        "css",
        &TelemetrySignals {
            poller_behind: true,
            ..TelemetrySignals::default()
        },
        ProbeOutcome::Ok,
        ProbeOutcome::Timeout,
        Some(15_000),
    );
    assert_eq!(
        top_level_keys(&serde_json::to_value(&w).unwrap()),
        vec![
            "explanation",
            "healthy",
            "last_probe_result",
            "last_telemetry_result",
            "next_probe_in_ms",
            "observer_behind",
            "unavailability",
            "worker_id",
        ]
    );
}
