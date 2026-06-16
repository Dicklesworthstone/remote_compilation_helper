//! Config rollout for remediation defaults across install/init/upgrade/doctor
//! surfaces (bd-session-history-remediation-ocv9i.17.2).
//!
//! Two layers:
//!   - Pure merge/upgrade behavior (old config without [remediation], partial
//!     sections, disabled policy flags, unsafe values) via `RchConfig` deser.
//!   - Surface wiring: `rch config validate|lint|doctor|diff|export` and the
//!     top-level `rch doctor` actually report / show / redact the [remediation]
//!     section when pointed at a crafted config via RCH_CONFIG_DIR.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

use rch_common::RchConfig;
use rch_common::remediation_config::{IssueSeverity, RemediationConfig};

use super::common::init_test_logging;

static COUNTER: AtomicU32 = AtomicU32::new(0);

/// Create a unique temp config dir containing `config.toml` with `body`.
fn temp_config_dir(body: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("rch-172-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create temp config dir");
    std::fs::write(dir.join("config.toml"), body).expect("write config.toml");
    dir
}

/// Run `rch <args>` against a config dir, returning (success, stdout).
fn run_config(config_dir: &Path, args: &[&str]) -> (bool, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_rch"))
        .args(args)
        .env("NO_COLOR", "1")
        .env("RCH_CONFIG_DIR", config_dir)
        .env_remove("RCH_JSON")
        .env_remove("RCH_OUTPUT_FORMAT")
        .env_remove("TOON_DEFAULT_FORMAT")
        .output()
        .expect("failed to run rch");
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
    )
}

/// Run `rch <args>` with a user config dir AND a project CWD (so a CWD-relative
/// `.rch/config.toml` is honored), returning (success, stdout).
fn run_config_in(config_dir: &Path, cwd: &Path, args: &[&str]) -> (bool, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_rch"))
        .args(args)
        .current_dir(cwd)
        .env("NO_COLOR", "1")
        .env("RCH_CONFIG_DIR", config_dir)
        .env_remove("RCH_JSON")
        .env_remove("RCH_OUTPUT_FORMAT")
        .env_remove("TOON_DEFAULT_FORMAT")
        .output()
        .expect("failed to run rch");
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
    )
}

/// Create a unique temp project dir containing `.rch/config.toml` with `body`.
fn temp_project_dir(body: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("rch-172-proj-{}-{n}", std::process::id()));
    std::fs::create_dir_all(dir.join(".rch")).expect("create project .rch dir");
    std::fs::write(dir.join(".rch/config.toml"), body).expect("write project config");
    dir
}

/// Create an empty (config-free) temp user dir.
fn empty_config_dir() -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("rch-172-user-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create empty user dir");
    dir
}

fn data(stdout: &str) -> serde_json::Value {
    let parsed: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("stdout is one JSON document");
    parsed
        .get("data")
        .cloned()
        .expect("envelope carries data payload")
}

// ---------------------------------------------------------------------------
// Layer 1: merge / upgrade behavior (AC4)
// ---------------------------------------------------------------------------

#[test]
fn old_config_without_remediation_uses_defaults() {
    init_test_logging();
    // An "old" config predating the [remediation] section deserializes with the
    // whole section defaulted — no migration step required.
    let cfg: RchConfig =
        toml::from_str("[general]\nenabled = true\nlog_level = \"info\"\n").expect("parse");
    assert_eq!(cfg.remediation, RemediationConfig::default());
    assert!(
        cfg.remediation
            .validate()
            .iter()
            .all(|i| i.severity != IssueSeverity::Error),
        "default remediation must validate without errors"
    );
}

#[test]
fn partial_remediation_merges_with_defaults() {
    init_test_logging();
    // Only one sub-field set; every other section keeps its default.
    let cfg: RchConfig =
        toml::from_str("[remediation.policy]\nhook_exec_fail_open = false\n").expect("parse");
    assert!(
        !cfg.remediation.policy.hook_exec_fail_open,
        "override applied"
    );
    let def = RemediationConfig::default();
    assert_eq!(
        cfg.remediation.auto_rejoin, def.auto_rejoin,
        "untouched sections keep defaults"
    );
    assert_eq!(cfg.remediation.proof, def.proof);
    assert_eq!(cfg.remediation.disk_pressure, def.disk_pressure);
}

#[test]
fn disabled_policy_flags_load_and_validate_clean() {
    init_test_logging();
    // Disabling fail-open / proof-fail-closed is a legitimate operator choice and
    // must not produce a validation error.
    let cfg: RchConfig = toml::from_str(
        "[remediation.policy]\nhook_exec_fail_open = false\nproof_mode_fail_closed = false\n",
    )
    .expect("parse");
    assert!(!cfg.remediation.policy.hook_exec_fail_open);
    assert!(!cfg.remediation.policy.proof_mode_fail_closed);
    let errors: Vec<_> = cfg
        .remediation
        .validate()
        .into_iter()
        .filter(|i| i.severity == IssueSeverity::Error)
        .collect();
    assert!(
        errors.is_empty(),
        "disabling policy flags must not error; got {errors:?}"
    );
}

#[test]
fn out_of_range_remediation_value_is_an_error() {
    init_test_logging();
    let cfg: RchConfig =
        toml::from_str("[remediation.auto_rejoin]\ncheck_interval_secs = 0\n").expect("parse");
    let issues = cfg.remediation.validate();
    assert!(
        issues
            .iter()
            .any(|i| i.severity == IssueSeverity::Error && i.field.contains("check_interval_secs")),
        "check_interval_secs=0 must be an error; got {issues:?}"
    );
}

#[test]
fn operator_path_outside_managed_roots_is_a_warning() {
    init_test_logging();
    // An absolute path outside the RCH-managed roots is accepted but flagged.
    let cfg: RchConfig = toml::from_str(
        "[remediation.incident_ledger]\npath = \"/var/tmp/operator/ledger.jsonl\"\n",
    )
    .expect("parse");
    let issues = cfg.remediation.validate();
    assert!(
        issues
            .iter()
            .any(|i| i.severity == IssueSeverity::Warning && i.field.contains("incident_ledger")),
        "operator path outside managed roots should warn; got {issues:?}"
    );
}

// ---------------------------------------------------------------------------
// Layer 2: surface wiring (AC1/AC2/AC3)
// ---------------------------------------------------------------------------

#[test]
fn config_validate_reports_remediation_error() {
    init_test_logging();
    let dir = temp_config_dir("[remediation.auto_rejoin]\ncheck_interval_secs = 0\n");
    let (ok, stdout) = run_config(&dir, &["config", "validate", "--json"]);
    assert!(
        !ok,
        "config validate must fail with an invalid remediation knob"
    );
    let d = data(&stdout);
    let blob = serde_json::to_string(&d).unwrap();
    assert!(
        blob.contains("check_interval_secs"),
        "config validate must name the offending remediation field; got {blob}"
    );
    assert_eq!(d.get("valid").and_then(|v| v.as_bool()), Some(false));
}

#[test]
fn config_lint_surfaces_remediation_finding() {
    init_test_logging();
    let dir = temp_config_dir("[remediation.auto_rejoin]\ncheck_interval_secs = 0\n");
    let (_ok, stdout) = run_config(&dir, &["config", "lint", "--json"]);
    let d = data(&stdout);
    let codes: Vec<String> = d
        .get("issues")
        .and_then(|v| v.as_array())
        .expect("issues array")
        .iter()
        .filter_map(|i| i.get("code").and_then(|c| c.as_str()).map(String::from))
        .collect();
    assert!(
        codes.iter().any(|c| c == "LINT-E101"),
        "lint must emit LINT-E101 for an invalid remediation knob; got {codes:?}"
    );
}

#[test]
fn config_doctor_surfaces_remediation_finding() {
    init_test_logging();
    let dir = temp_config_dir("[remediation.auto_rejoin]\ncheck_interval_secs = 0\n");
    let (_ok, stdout) = run_config(&dir, &["config", "doctor", "--json"]);
    // `config doctor --json` emits the ConfigDoctorResponse directly (no
    // ApiResponse `data` envelope), so parse it flat.
    let parsed: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("config doctor emits one JSON document");
    let blob = serde_json::to_string(&parsed).unwrap();
    assert!(
        blob.contains("DOC-E100") && blob.contains("check_interval_secs"),
        "config doctor must emit DOC-E100 for the invalid knob; got {blob}"
    );
}

#[test]
fn top_level_doctor_reports_remediation() {
    init_test_logging();
    // Valid config: top-level doctor (run by the installer) reports the section
    // was checked. Use --json so we can assert on a check result.
    let dir = temp_config_dir("[general]\nenabled = true\n");
    let (_ok, stdout) = run_config(&dir, &["doctor", "--json"]);
    assert!(
        stdout.contains("remediation_config"),
        "top-level doctor must include a remediation_config check; got {stdout}"
    );
}

#[test]
fn config_diff_shows_remediation_override() {
    init_test_logging();
    let dir = temp_config_dir("[remediation.policy]\nhook_exec_fail_open = false\n");
    let (ok, stdout) = run_config(&dir, &["config", "diff", "--json"]);
    assert!(ok, "config diff should succeed");
    let d = data(&stdout);
    let entry = d
        .get("entries")
        .and_then(|v| v.as_array())
        .expect("entries array")
        .iter()
        .find(|e| {
            e.get("key").and_then(|k| k.as_str()) == Some("remediation.policy.hook_exec_fail_open")
        })
        .expect("remediation.policy.hook_exec_fail_open must appear in the diff");
    assert_eq!(entry.get("current").and_then(|v| v.as_str()), Some("false"));
    assert_eq!(entry.get("default").and_then(|v| v.as_str()), Some("true"));
}

#[test]
fn config_export_json_includes_redacted_remediation() {
    init_test_logging();
    let dir = temp_config_dir("[remediation.policy]\nhook_exec_fail_open = false\n");
    let (ok, stdout) = run_config(&dir, &["config", "export", "--format", "json"]);
    assert!(ok, "config export --format json should succeed");
    let d = data(&stdout);
    let rem = d
        .get("remediation")
        .expect("export carries remediation section");
    assert_eq!(
        rem.pointer("/policy/hook_exec_fail_open")
            .and_then(|v| v.as_bool()),
        Some(false),
        "export must reflect the remediation override"
    );
}

#[test]
fn config_export_redacts_operator_paths() {
    init_test_logging();
    // A home/user path segment must be redacted to a stable, machine-independent
    // form (`/home/<user>/` -> `/home/<redacted>/`), proving export applies
    // RemediationConfig::redacted() rather than exporting the raw path.
    let dir = temp_config_dir(
        "[remediation.incident_ledger]\npath = \"/home/alice/secret/ledger.jsonl\"\n",
    );
    let (ok, stdout) = run_config(&dir, &["config", "export", "--format", "json"]);
    assert!(ok, "config export should succeed");
    let d = data(&stdout);
    let path = d
        .pointer("/remediation/incident_ledger/path")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    assert!(
        path.contains("/home/<redacted>/") && !path.contains("/home/alice/"),
        "operator home path must be redacted in export; got {path:?}"
    );
}

// ---------------------------------------------------------------------------
// Layer 3: default-install + project-override scenarios (17.3 AC2)
// ---------------------------------------------------------------------------

#[test]
fn default_install_writes_and_loads_remediation_section() {
    init_test_logging();
    // Fresh install: `rch config init --non-interactive` writes a config.toml that
    // carries the documented [remediation] block and then validates cleanly.
    let dir = empty_config_dir();
    let (ok, _out) = run_config(&dir, &["config", "init", "--non-interactive"]);
    assert!(ok, "config init --non-interactive should succeed");
    let written = std::fs::read_to_string(dir.join("config.toml")).expect("config.toml written");
    assert!(
        written.contains("[remediation]"),
        "fresh config must document the [remediation] section; got:\n{written}"
    );
    // The freshly-written config validates without remediation errors.
    let (validate_ok, vstdout) = run_config(&dir, &["config", "validate", "--json"]);
    let vd = data(&vstdout);
    let blob = serde_json::to_string(&vd).unwrap();
    assert!(
        !blob.contains("remediation."),
        "fresh-install config must not raise remediation validation errors; got {blob}"
    );
    let _ = validate_ok; // workers.toml-missing may still flag; remediation is what we assert
}

#[test]
fn project_override_is_attributed_to_project_source() {
    init_test_logging();
    // A project `.rch/config.toml` override must win over the (empty) user config
    // and `config show --sources` must attribute it to the project file.
    let user = empty_config_dir();
    let proj = temp_project_dir("[general]\nforce_remote = true\n");
    let (ok, stdout) = run_config_in(&user, &proj, &["config", "show", "--sources", "--json"]);
    assert!(ok, "config show --sources should succeed");
    let d = data(&stdout);
    let entry = d
        .get("value_sources")
        .and_then(|v| v.as_array())
        .expect("value_sources present with --sources")
        .iter()
        .find(|e| e.get("key").and_then(|k| k.as_str()) == Some("general.force_remote"))
        .expect("general.force_remote attributed");
    assert_eq!(entry.get("value").and_then(|v| v.as_str()), Some("true"));
    assert!(
        entry
            .get("source")
            .and_then(|v| v.as_str())
            .is_some_and(|s| s.starts_with("project:")),
        "project override must be attributed to the project file; got {entry:?}"
    );
}

// ---------------------------------------------------------------------------
// Layer 4: golden envelope stability + TOON parity + remediation text (17.3 AC4)
// ---------------------------------------------------------------------------

/// A config dir whose only lint finding is the remediation warning: a minimal
/// valid workers.toml suppresses the workers-missing lint so the output is a
/// single, stable issue suitable for golden assertions.
fn lint_golden_config_dir() -> PathBuf {
    let dir = temp_config_dir(
        "[remediation.incident_ledger]\npath = \"/var/tmp/operator/ledger.jsonl\"\n",
    );
    let workers = "[[workers]]\nid = \"golden\"\nhost = \"192.0.2.10\"\nuser = \"ubuntu\"\n\
         identity_file = \"~/.ssh/id_rsa\"\ntotal_slots = 4\n";
    std::fs::write(dir.join("workers.toml"), workers).expect("write workers.toml");
    dir
}

#[test]
fn config_lint_golden_envelope_and_remediation_text() {
    init_test_logging();
    let dir = lint_golden_config_dir();
    let (_ok, stdout) = run_config(&dir, &["config", "lint", "--json"]);
    let parsed: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("config lint emits one JSON document");

    // Envelope stability: the standard ApiResponse keys are present and stable.
    assert_eq!(
        parsed.get("success").and_then(|v| v.as_bool()),
        Some(true),
        "envelope success flag stable"
    );
    assert_eq!(
        parsed.get("command").and_then(|v| v.as_str()),
        Some("config lint"),
        "envelope command field stable"
    );
    assert!(
        parsed.get("api_version").is_some(),
        "envelope carries api_version"
    );

    // Exactly one issue (the remediation warning) — workers.toml suppresses the
    // workers-missing finding, so this is a stable golden.
    let issues = parsed
        .pointer("/data/issues")
        .and_then(|v| v.as_array())
        .expect("issues array present");
    let rem: Vec<&serde_json::Value> = issues
        .iter()
        .filter(|i| {
            i.get("message")
                .and_then(|m| m.as_str())
                .is_some_and(|m| m.contains("remediation."))
        })
        .collect();
    assert_eq!(
        rem.len(),
        1,
        "exactly one remediation lint issue; got {issues:?}"
    );
    let issue = rem[0];
    // LintSeverity serializes lowercase (rename_all = "lowercase") — a stable
    // envelope detail.
    assert_eq!(
        issue.get("severity").and_then(|v| v.as_str()),
        Some("warning")
    );
    assert_eq!(
        issue.get("code").and_then(|v| v.as_str()),
        Some("LINT-W101")
    );
    assert!(
        issue
            .get("message")
            .and_then(|v| v.as_str())
            .is_some_and(|m| m.starts_with("remediation.incident_ledger.path:")),
        "message names the offending field; got {issue:?}"
    );
    // Useful remediation text: points at the field + how to re-check.
    let remediation = issue
        .get("remediation")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    assert!(
        remediation.contains("remediation.incident_ledger.path")
            && remediation.contains("rch config doctor"),
        "remediation text must be actionable; got {remediation:?}"
    );
}

#[test]
fn config_lint_toon_parity() {
    init_test_logging();
    let dir = lint_golden_config_dir();
    // The same lint payload renders as TOON and still carries the stable code and
    // the offending field (TOON parity where supported).
    let (json_ok, json_out) = run_config(&dir, &["config", "lint", "--json"]);
    assert!(json_ok, "config lint --json should succeed");
    assert!(json_out.contains("LINT-W101"));

    let (toon_ok, toon_out) = run_config(&dir, &["config", "lint", "--format", "toon"]);
    assert!(toon_ok, "config lint --format toon should succeed");
    assert!(
        toon_out.contains("LINT-W101") && toon_out.contains("incident_ledger"),
        "TOON output must carry the stable code and field; got {toon_out}"
    );
}
