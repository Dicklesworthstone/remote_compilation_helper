//! Golden JSON / schema checks for the remediation config schema and default
//! policy (bd-session-history-remediation-ocv9i.17.1).
//!
//! This is the required-proof artifact named by the program validation matrix
//! (`docs/guides/session-history-remediation-validation.md`): a golden of the
//! canonical `RemediationConfig::default()` plus a schema structural check and a
//! redaction golden. If any default changes, the default-policy golden fails
//! loudly so the change is a conscious decision, not silent drift.
//!
//! Goldens are inline `json!` blocks compared as `serde_json::Value` (key order
//! irrelevant), matching the convention in `admission_goldens_e2e.rs`.

use rch_common::remediation_config::RemediationConfig;
use serde_json::{Value, json};

/// Structural equality against an inline canonical JSON value.
fn assert_golden<T: serde::Serialize>(name: &str, value: &T, expected: Value) {
    let actual = serde_json::to_value(value).expect("serializes");
    assert_eq!(
        actual,
        expected,
        "golden drift in {name}: a field/value changed. If intentional, update the json! block.\nactual:\n{}",
        serde_json::to_string_pretty(&actual).unwrap()
    );
}

#[test]
fn golden_remediation_config_default_policy() {
    let cfg = RemediationConfig::default();
    assert_golden(
        "RemediationConfig::default()",
        &cfg,
        json!({
            "policy": {
                "hook_exec_fail_open": true,
                "proof_mode_fail_closed": true
            },
            "temporary_bypass": {
                "backoff_initial_secs": 30,
                "backoff_max_secs": 900
            },
            "auto_rejoin": {
                "required_consecutive_passes": 2,
                "canary_required": true,
                "check_interval_secs": 30,
                "probe_timeout_secs": 10,
                "min_disk_free_gb": 5.0,
                "min_disk_inodes": 10000,
                "disk_roots": ["/tmp", "/tmp/rch"],
                "max_load_per_core": 4.0,
                "min_protocol": 0,
                "required_targets": [],
                "required_toolchains": [],
                "canary_command": "rustc --version"
            },
            "reconciliation": {
                "max_attempts": 3,
                "time_budget_secs": 120,
                "state_hysteresis_ms": 5000,
                "max_transition_history": 64,
                "max_outcome_history": 256,
                "staleness_threshold_secs": 300
            },
            "proof": {
                "default_stale_source_policy": "reject_if_changed",
                "default_replay_constraints": {
                    "require_same_revision": false,
                    "require_unchanged_sources": false
                }
            },
            "incident_ledger": {
                "max_entries": 5000,
                "max_bytes": 4194304
            },
            "build_root": {
                "min_free_bytes": 2147483648u64,
                "min_free_inodes": 50000
            },
            "pooled_target": {
                "pooling_enabled": true,
                "reaper_enabled": false,
                "reaper_idle_hours": 12,
                "reaper_interval_mins": 120,
                "remote_base": "/data/projects"
            },
            "telemetry_freshness": {
                "max_age_secs": 120
            },
            "log_retention": {
                "max_file_bytes": 16777216,
                "keep_rotated": 3,
                "warn_total_bytes": 67108864,
                "critical_total_bytes": 268435456u64
            },
            "disk_pressure": {
                "warning_avail_pct": 15.0,
                "critical_avail_pct": 5.0,
                "warning_avail_inodes": 100000,
                "critical_avail_inodes": 10000
            },
            "smoke": {
                "iterations": 20,
                "seed": 42
            }
        }),
    );
}

#[test]
fn golden_remediation_config_redacted_paths() {
    // A config carrying operator paths with home/user segments redacts to a
    // stable, machine-independent form.
    let mut cfg = RemediationConfig::default();
    cfg.incident_ledger.path = Some("/home/alice/.local/state/rch/incidents.jsonl".to_string());
    cfg.proof.store_path = Some("/Users/bob/work/proofs.jsonl".to_string());
    cfg.auto_rejoin.disk_roots = vec!["/home/carol/builds".to_string(), "/tmp/rch".to_string()];

    let redacted = cfg.redacted();
    assert_golden(
        "RemediationConfig::redacted() path fields",
        &json!({
            "incident_ledger_path": redacted.incident_ledger.path,
            "proof_store_path": redacted.proof.store_path,
            "disk_roots": redacted.auto_rejoin.disk_roots,
        }),
        json!({
            "incident_ledger_path": "/home/<redacted>/.local/state/rch/incidents.jsonl",
            "proof_store_path": "/Users/<redacted>/work/proofs.jsonl",
            "disk_roots": ["/home/<redacted>/builds", "/tmp/rch"]
        }),
    );
}

#[test]
fn schema_has_all_sections_and_describes_policy() {
    let schema = RemediationConfig::schema_json();

    // It is an object schema with our 12 sections as properties.
    let props = schema
        .get("properties")
        .and_then(Value::as_object)
        .expect("schema exposes object properties");
    let expected_sections = [
        "policy",
        "temporary_bypass",
        "auto_rejoin",
        "reconciliation",
        "proof",
        "incident_ledger",
        "build_root",
        "pooled_target",
        "telemetry_freshness",
        "log_retention",
        "disk_pressure",
        "smoke",
    ];
    for section in expected_sections {
        assert!(
            props.contains_key(section),
            "schema missing section {section}"
        );
    }

    // The schema must be self-describing enough that the failure-mode policy is
    // discoverable by an agent reading the schema (definitions or inline).
    let schema_text = serde_json::to_string(&schema).expect("schema serializes");
    assert!(schema_text.contains("hook_exec_fail_open"));
    assert!(schema_text.contains("proof_mode_fail_closed"));
}
