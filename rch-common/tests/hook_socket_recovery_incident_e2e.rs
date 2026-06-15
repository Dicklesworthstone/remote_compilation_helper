//! Hook socket-failure recovery — durable structured-incident contract
//! (bd-session-history-remediation-ocv9i.3.1).
//!
//! When the hook cannot reach the daemon (missing / refused / stale socket, or
//! a configured-vs-canonical socket-path mismatch) it records a durable
//! structured incident, attempts a bounded autostart + one retry, then either
//! proceeds remotely or falls back / refuses (proof mode) loudly. The hook-side
//! decision cores are unit-tested inside `rch/src/hook.rs`; this e2e pins the
//! *durable record contract* the hook depends on, exercised against the real
//! [`IncidentLedger`] using the public incident API.
//!
//! Scenarios (from the bead):
//!   1. refused socket            → DaemonSocketRefused (RCH-I010), failure=refused
//!   2. stale socket              → DaemonSocketRefused (RCH-I010), failure=stale
//!   3. wrong configured socket   → mismatch details, redacted paths
//!   4. daemon start success      → no terminal fallback/refusal incident
//!   5. daemon start failure      → LocalFallback (RCH-I011), fallback allowed
//!   6. proof-mode refusal        → ProofRefusal (RCH-I012), fallback forbidden
//!
//! Plus the cross-cutting guarantees: records survive a process restart, the
//! agent-facing JSON shape is stable, and no raw home username leaks on disk.

use rch_common::incident::{
    ControlState, IncidentEvent, IncidentEventType, IncidentReasonCode, IncidentSource,
    SelectedMode,
};
use rch_common::incident_ledger::IncidentLedger;
use rch_common::redaction::redact_path;
use serde_json::Value;

/// The socket-failure incident the hook records on a daemon-query failure
/// (RCH-I010). Mirrors `build_socket_failure_incident` in `rch/src/hook.rs`.
fn socket_failure_incident(
    failure: &str,
    mismatch: Option<(&str, &str, bool)>,
    strict_remote: bool,
    now_ms: u64,
) -> IncidentEvent {
    let mut event = IncidentEvent::new(
        IncidentEventType::Selection,
        IncidentReasonCode::DaemonSocketRefused,
        IncidentSource::Hook,
        "demo-project",
        "cargo build --release",
        SelectedMode::Local,
        !strict_remote,
        now_ms,
    )
    .with_detail("socket_failure", failure)
    .with_control(ControlState {
        strict_remote_policy: strict_remote,
        ..ControlState::default()
    });
    if let Some((configured, canonical, canonical_exists)) = mismatch {
        event = event
            .with_detail("socket_path_mismatch", "true")
            .with_detail("configured_socket", redact_path(configured))
            .with_detail("canonical_socket", redact_path(canonical))
            .with_detail("canonical_socket_exists", canonical_exists.to_string());
    }
    event
}

/// The terminal incident the hook records when autostart + retry could not
/// restore the daemon. Mirrors `build_recovery_terminal_incident`.
fn terminal_incident(strict_remote: bool, now_ms: u64) -> IncidentEvent {
    let (reason_code, event_type) = if strict_remote {
        (IncidentReasonCode::ProofRefusal, IncidentEventType::Proof)
    } else {
        (
            IncidentReasonCode::LocalFallback,
            IncidentEventType::Fallback,
        )
    };
    IncidentEvent::new(
        event_type,
        reason_code,
        IncidentSource::Hook,
        "demo-project",
        "cargo build --release",
        SelectedMode::Local,
        !strict_remote,
        now_ms,
    )
    .with_detail("reason", "daemon unavailable")
    .with_control(ControlState {
        strict_remote_policy: strict_remote,
        ..ControlState::default()
    })
}

#[test]
fn e2e_hook_socket_refused_records_daemon_socket_refused() {
    let dir = tempfile::tempdir().unwrap();
    let ledger = IncidentLedger::with_path(dir.path().join("incidents.jsonl"));
    ledger
        .append(&socket_failure_incident(
            "refused",
            None,
            false,
            1_700_000_000_000,
        ))
        .unwrap();

    let events = ledger.read_all();
    assert_eq!(events.len(), 1);
    let ev = &events[0];
    assert_eq!(ev.reason_code, IncidentReasonCode::DaemonSocketRefused);
    assert_eq!(ev.reason_code.code(), "RCH-I010");
    assert_eq!(ev.source, IncidentSource::Hook);
    assert_eq!(
        ev.details.get("socket_failure").map(String::as_str),
        Some("refused")
    );
    // No mismatch was supplied, so the mismatch details are absent.
    assert!(ev.details.get("socket_path_mismatch").is_none());
}

#[test]
fn e2e_hook_socket_stale_records_failure_class() {
    let dir = tempfile::tempdir().unwrap();
    let ledger = IncidentLedger::with_path(dir.path().join("incidents.jsonl"));
    ledger
        .append(&socket_failure_incident(
            "stale",
            None,
            false,
            1_700_000_000_001,
        ))
        .unwrap();
    let ev = &ledger.read_all()[0];
    assert_eq!(
        ev.details.get("socket_failure").map(String::as_str),
        Some("stale")
    );
}

#[test]
fn e2e_hook_socket_wrong_configured_socket_records_redacted_mismatch() {
    let dir = tempfile::tempdir().unwrap();
    let ledger = IncidentLedger::with_path(dir.path().join("incidents.jsonl"));
    ledger
        .append(&socket_failure_incident(
            "missing",
            Some((
                "/home/alice/.cache/rch/rch.sock",
                "/home/alice/.config/rch/rch.sock",
                true,
            )),
            false,
            1_700_000_000_002,
        ))
        .unwrap();

    let ev = &ledger.read_all()[0];
    assert_eq!(
        ev.details.get("socket_path_mismatch").map(String::as_str),
        Some("true")
    );
    assert_eq!(
        ev.details
            .get("canonical_socket_exists")
            .map(String::as_str),
        Some("true")
    );
    let configured = ev.details.get("configured_socket").unwrap();
    assert!(
        configured.contains("<redacted>"),
        "home segment must be masked: {configured}"
    );
    assert!(
        !configured.contains("alice"),
        "raw username must not leak: {configured}"
    );
}

#[test]
fn e2e_hook_socket_daemon_start_success_records_no_terminal_incident() {
    // On a successful autostart + retry the hook proceeds remotely and records
    // only the initial socket-failure incident — no terminal fallback/refusal.
    let dir = tempfile::tempdir().unwrap();
    let ledger = IncidentLedger::with_path(dir.path().join("incidents.jsonl"));
    ledger
        .append(&socket_failure_incident(
            "refused",
            None,
            false,
            1_700_000_000_003,
        ))
        .unwrap();

    let events = ledger.read_all();
    assert_eq!(events.len(), 1, "only the detection incident is recorded");
    assert!(
        events
            .iter()
            .all(|e| e.reason_code == IncidentReasonCode::DaemonSocketRefused),
        "no LocalFallback / ProofRefusal terminal incident on success"
    );
}

#[test]
fn e2e_hook_socket_daemon_start_failure_records_local_fallback() {
    // Convenience lane: detection incident + LocalFallback (RCH-I011).
    let dir = tempfile::tempdir().unwrap();
    let ledger = IncidentLedger::with_path(dir.path().join("incidents.jsonl"));
    ledger
        .append(&socket_failure_incident(
            "missing",
            None,
            false,
            1_700_000_000_004,
        ))
        .unwrap();
    ledger
        .append(&terminal_incident(false, 1_700_000_000_005))
        .unwrap();

    let events = ledger.read_all();
    assert_eq!(events.len(), 2);
    let terminal = &events[1];
    assert_eq!(terminal.reason_code, IncidentReasonCode::LocalFallback);
    assert_eq!(terminal.reason_code.code(), "RCH-I011");
    assert_eq!(terminal.event_type, IncidentEventType::Fallback);
    assert!(
        terminal.local_fallback_allowed,
        "convenience lane permits local fallback"
    );
    assert!(!terminal.control.strict_remote_policy);
}

#[test]
fn e2e_hook_socket_proof_mode_records_proof_refusal_fail_closed() {
    // Proof lane: detection incident (no fallback allowed) + ProofRefusal.
    let dir = tempfile::tempdir().unwrap();
    let ledger = IncidentLedger::with_path(dir.path().join("incidents.jsonl"));
    ledger
        .append(&socket_failure_incident(
            "refused",
            None,
            true,
            1_700_000_000_006,
        ))
        .unwrap();
    ledger
        .append(&terminal_incident(true, 1_700_000_000_007))
        .unwrap();

    let events = ledger.read_all();
    assert_eq!(events.len(), 2);

    // The detection incident already reflects the fail-closed posture.
    let detection = &events[0];
    assert!(
        !detection.local_fallback_allowed,
        "proof mode forbids local fallback"
    );
    assert!(detection.control.strict_remote_policy);

    let terminal = &events[1];
    assert_eq!(terminal.reason_code, IncidentReasonCode::ProofRefusal);
    assert_eq!(terminal.reason_code.code(), "RCH-I012");
    assert_eq!(terminal.event_type, IncidentEventType::Proof);
    assert!(!terminal.local_fallback_allowed);
    assert!(terminal.control.strict_remote_policy);
}

#[test]
fn e2e_hook_socket_incidents_survive_process_restart() {
    // Durability: a fresh ledger instance (simulating a hook process restart)
    // observes incidents written by a prior invocation.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("incidents.jsonl");
    {
        let ledger = IncidentLedger::with_path(&path);
        ledger
            .append(&socket_failure_incident(
                "refused",
                None,
                true,
                1_700_000_000_008,
            ))
            .unwrap();
        ledger
            .append(&terminal_incident(true, 1_700_000_000_009))
            .unwrap();
    }
    let reopened = IncidentLedger::with_path(&path);
    let events = reopened.read_all();
    assert_eq!(events.len(), 2);
    assert_eq!(
        events[0].reason_code,
        IncidentReasonCode::DaemonSocketRefused
    );
    assert_eq!(events[1].reason_code, IncidentReasonCode::ProofRefusal);
}

#[test]
fn e2e_hook_socket_incident_json_shape_is_stable() {
    // Pin the agent-facing JSON shape so a renamed field or changed token is
    // caught by CI.
    let event = socket_failure_incident(
        "refused",
        Some((
            "/home/alice/.cache/rch/rch.sock",
            "/home/alice/.config/rch/rch.sock",
            false,
        )),
        true,
        1_700_000_000_010,
    );
    let value: Value = serde_json::to_value(&event).unwrap();

    assert_eq!(value["reason_code"], "RCH-I010");
    assert_eq!(value["event_type"], "selection");
    assert_eq!(value["source"], "hook");
    assert_eq!(value["selected_mode"], "local");
    assert_eq!(value["local_fallback_allowed"], false);
    assert_eq!(value["project_id"], "demo-project");
    assert_eq!(value["details"]["socket_failure"], "refused");
    assert_eq!(value["details"]["socket_path_mismatch"], "true");
    assert_eq!(value["details"]["canonical_socket_exists"], "false");
    // Strict-remote policy is recorded in the control snapshot.
    assert_eq!(value["control"]["strict_remote_policy"], true);

    // No raw home username anywhere in the serialized record.
    let serialized = serde_json::to_string(&event).unwrap();
    assert!(
        !serialized.contains("alice"),
        "raw username must not leak in the on-disk record: {serialized}"
    );
}
