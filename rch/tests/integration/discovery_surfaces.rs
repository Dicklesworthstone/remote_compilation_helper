//! Agent discovery-surface contract tests (bd-session-history-remediation-ocv9i.13.4).
//!
//! Proves that the machine-readable discovery surfaces an agent is promised in
//! the README — `rch capabilities --json`, `rch robot-docs guide`,
//! `rch --help-json <path>`, and shell completions — actually expose the new
//! remediation workflows, reason-code families, fallback policies, and stable
//! envelope. These run the real built binary; none require a daemon.
//!
//! Coverage asserted here (REQ-DISCOVERY-001 in the reliability coverage matrix):
//!   - capabilities lists reason-code families (RCH-E/R/I) and placement policies
//!   - robot-docs guide carries the 7 remediation workflows with next-action text
//!   - --help-json resolves and is structurally valid for every real nested path
//!   - stdout is pure JSON, diagnostics stay on stderr (stream separation)
//!   - TOON parity for the capability payload
//!   - completions include the new remediation commands/flags

use std::process::Command;

use super::common::init_test_logging;

/// Run the built `rch` binary with a clean, deterministic env and capture
/// (status_success, stdout, stderr).
fn run_rch(args: &[&str]) -> (bool, String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_rch"))
        .args(args)
        .env("NO_COLOR", "1")
        .env_remove("RCH_HOOK_MODE")
        .env_remove("RCH_JSON")
        .output()
        .expect("failed to spawn the rch binary");
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

/// Parse stdout as JSON and return the `data` payload from the standard
/// ApiResponse envelope.
fn envelope_data(stdout: &str) -> serde_json::Value {
    let parsed: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("stdout should be a single JSON document");
    assert_eq!(
        parsed.get("success").and_then(|v| v.as_bool()),
        Some(true),
        "envelope should report success=true"
    );
    parsed
        .get("data")
        .cloned()
        .expect("envelope should carry a data payload")
}

#[test]
fn test_capabilities_lists_reason_code_families_and_policies() {
    init_test_logging();
    crate::test_log!("TEST START: test_capabilities_lists_reason_code_families_and_policies");

    let (ok, stdout, _stderr) = run_rch(&["capabilities", "--json"]);
    assert!(ok, "rch capabilities --json should succeed");
    let data = envelope_data(&stdout);

    // Additive schema bump signalling the new sections.
    assert_eq!(
        data.get("schema_version").and_then(|v| v.as_str()),
        Some("1.1"),
        "capabilities schema_version should be bumped to 1.1 for the new sections"
    );

    // Reason-code families: all three namespaces present.
    let families = data
        .get("reason_code_families")
        .and_then(|v| v.as_array())
        .expect("reason_code_families must be present");
    let family_ids: Vec<&str> = families
        .iter()
        .filter_map(|f| f.get("family").and_then(|v| v.as_str()))
        .collect();
    for expected in ["RCH-E", "RCH-R", "RCH-I"] {
        assert!(
            family_ids.contains(&expected),
            "reason_code_families must include {expected}; got {family_ids:?}"
        );
    }

    // RCH-I is enumerated in full from the incident registry — the proof-refusal
    // and local-fallback codes must be discoverable here.
    let incident = families
        .iter()
        .find(|f| f.get("family").and_then(|v| v.as_str()) == Some("RCH-I"))
        .expect("RCH-I family present");
    let incident_codes: Vec<&str> = incident
        .get("examples")
        .and_then(|v| v.as_array())
        .expect("RCH-I examples present")
        .iter()
        .filter_map(|e| e.get("code").and_then(|v| v.as_str()))
        .collect();
    for code in ["RCH-I011", "RCH-I012"] {
        assert!(
            incident_codes.contains(&code),
            "RCH-I family must enumerate {code}; got {incident_codes:?}"
        );
    }

    // Policies: proof (require_remote) is fail-closed with RCH-I012; force/fail-open present.
    let policies = data
        .get("policies")
        .and_then(|v| v.as_array())
        .expect("policies must be present");
    let policy_ids: Vec<&str> = policies
        .iter()
        .filter_map(|p| p.get("id").and_then(|v| v.as_str()))
        .collect();
    for expected in [
        "fail_open",
        "force_remote",
        "require_remote",
        "queue_when_busy",
    ] {
        assert!(
            policy_ids.contains(&expected),
            "policies must include {expected}; got {policy_ids:?}"
        );
    }
    let require_remote = policies
        .iter()
        .find(|p| p.get("id").and_then(|v| v.as_str()) == Some("require_remote"))
        .expect("require_remote policy present");
    assert_eq!(
        require_remote.get("reason_code").and_then(|v| v.as_str()),
        Some("RCH-I012"),
        "proof mode (require_remote) refusal must reference RCH-I012"
    );
    assert!(
        require_remote
            .get("next_action")
            .and_then(|v| v.as_str())
            .is_some_and(|s| !s.is_empty()),
        "require_remote must carry useful next-action text"
    );

    // The new remediation commands and the proof env vars are discoverable.
    let command_names: Vec<&str> = data
        .get("commands")
        .and_then(|v| v.as_array())
        .expect("commands present")
        .iter()
        .filter_map(|c| c.get("name").and_then(|v| v.as_str()))
        .collect();
    for cmd in ["admit", "exec", "self-test", "fleet"] {
        assert!(
            command_names.contains(&cmd),
            "capabilities commands must include {cmd}; got {command_names:?}"
        );
    }
    let env_names: Vec<&str> = data
        .get("env_vars")
        .and_then(|v| v.as_array())
        .expect("env_vars present")
        .iter()
        .filter_map(|e| e.get("name").and_then(|v| v.as_str()))
        .collect();
    for env in ["RCH_REQUIRE_REMOTE", "RCH_FORCE_REMOTE"] {
        assert!(
            env_names.contains(&env),
            "capabilities env_vars must include {env}; got {env_names:?}"
        );
    }

    crate::test_log!("TEST PASS: test_capabilities_lists_reason_code_families_and_policies");
}

#[test]
fn test_robot_docs_guide_covers_remediation_workflows() {
    init_test_logging();
    crate::test_log!("TEST START: test_robot_docs_guide_covers_remediation_workflows");

    let (ok, stdout, _stderr) = run_rch(&["robot-docs", "guide", "--json"]);
    assert!(ok, "rch robot-docs guide --json should succeed");
    let data = envelope_data(&stdout);

    let workflows = data
        .get("remediation_workflows")
        .and_then(|v| v.as_array())
        .expect("remediation_workflows must be present");
    let ids: Vec<&str> = workflows
        .iter()
        .filter_map(|w| w.get("id").and_then(|v| v.as_str()))
        .collect();
    for expected in [
        "admit_before_proof",
        "proof_mode",
        "worker_bypass_rejoin",
        "fleet_status",
        "force_resync",
        "queue_attach_cancel",
        "real_fleet_smoke",
    ] {
        assert!(
            ids.contains(&expected),
            "remediation_workflows must include {expected}; got {ids:?}"
        );
    }

    // Every workflow carries at least one runnable command and a summary.
    for w in workflows {
        let id = w.get("id").and_then(|v| v.as_str()).unwrap_or("<none>");
        let has_command = w
            .get("commands")
            .and_then(|v| v.as_array())
            .is_some_and(|c| !c.is_empty());
        assert!(has_command, "workflow {id} must list at least one command");
        assert!(
            w.get("summary")
                .and_then(|v| v.as_str())
                .is_some_and(|s| !s.is_empty()),
            "workflow {id} must have a summary"
        );
    }

    // Proof mode must point at the fail-closed env + the RCH-I012 refusal code.
    let proof = workflows
        .iter()
        .find(|w| w.get("id").and_then(|v| v.as_str()) == Some("proof_mode"))
        .expect("proof_mode present");
    let proof_blob = serde_json::to_string(proof).unwrap();
    assert!(
        proof_blob.contains("RCH_REQUIRE_REMOTE"),
        "proof_mode must reference RCH_REQUIRE_REMOTE"
    );
    assert!(
        proof_blob.contains("RCH-I012"),
        "proof_mode must reference the RCH-I012 refusal code"
    );

    // The human guide text mentions the real entry points too.
    let guide = data
        .get("guide")
        .and_then(|v| v.as_str())
        .expect("guide text present");
    for needle in [
        "rch admit",
        "RCH_REQUIRE_REMOTE",
        "rch self-test",
        "rch queue",
    ] {
        assert!(
            guide.contains(needle),
            "robot-docs guide text must mention {needle:?}"
        );
    }

    crate::test_log!("TEST PASS: test_robot_docs_guide_covers_remediation_workflows");
}

#[test]
fn test_help_json_schema_checks_all_remediation_paths() {
    init_test_logging();
    crate::test_log!("TEST START: test_help_json_schema_checks_all_remediation_paths");

    // (path-as-args, expected leaf command name). Every entry is a REAL command
    // path on the current CLI surface — aspirational names from the bead that do
    // not exist as commands (proof, jobs, sync) are intentionally excluded.
    let cases: &[(&[&str], &str)] = &[
        (&["admit"], "admit"),
        (&["exec"], "exec"),
        (&["status"], "status"),
        (&["queue"], "queue"),
        (&["cancel"], "cancel"),
        (&["self-test"], "self-test"),
        (&["capabilities"], "capabilities"),
        (&["workers", "capabilities"], "capabilities"),
        (&["fleet", "status"], "status"),
        (&["config", "validate"], "validate"),
        (&["robot-docs", "guide"], "guide"),
    ];

    for (path, leaf) in cases {
        let mut args = vec!["--help-json"];
        args.extend_from_slice(path);
        let (ok, stdout, stderr) = run_rch(&args);
        assert!(
            ok,
            "rch --help-json {path:?} should succeed; stderr={stderr}"
        );
        let parsed: Result<serde_json::Value, _> = serde_json::from_str(stdout.trim());
        assert!(
            parsed.is_ok(),
            "--help-json {path:?} should emit valid JSON; got: {stdout}"
        );
        let parsed = parsed.expect("validated as Ok above");
        // Schema check: object with the leaf name and a subcommands array.
        assert!(parsed.is_object(), "--help-json {path:?} must be an object");
        assert_eq!(
            parsed.get("name").and_then(|v| v.as_str()),
            Some(*leaf),
            "--help-json {path:?} should resolve to leaf command {leaf:?}"
        );
        assert!(
            parsed.get("subcommands").is_some(),
            "--help-json {path:?} must carry a subcommands field"
        );
    }

    crate::test_log!("TEST PASS: test_help_json_schema_checks_all_remediation_paths");
}

#[test]
fn test_help_json_rejects_unknown_path() {
    init_test_logging();
    crate::test_log!("TEST START: test_help_json_rejects_unknown_path");

    let (ok, _stdout, stderr) = run_rch(&["--help-json", "proof/replay"]);
    assert!(
        !ok,
        "rch --help-json on a non-existent path must fail (exit non-zero)"
    );
    assert!(
        stderr.contains("Unknown subcommand path"),
        "unknown --help-json path must explain the failure on stderr; got {stderr}"
    );

    crate::test_log!("TEST PASS: test_help_json_rejects_unknown_path");
}

#[test]
fn test_discovery_surfaces_stdout_stderr_separation() {
    init_test_logging();
    crate::test_log!("TEST START: test_discovery_surfaces_stdout_stderr_separation");

    // stdout must be a single parseable JSON document; the payload must not leak
    // onto stderr (diagnostics-only channel).
    let (ok, stdout, stderr) = run_rch(&["robot-docs", "guide", "--json"]);
    assert!(ok, "rch robot-docs guide --json should succeed");
    let _ = envelope_data(&stdout);
    assert!(
        !stderr.contains("remediation_workflows"),
        "data payload must not appear on stderr; stderr={stderr}"
    );

    crate::test_log!("TEST PASS: test_discovery_surfaces_stdout_stderr_separation");
}

#[test]
fn test_capabilities_toon_parity() {
    init_test_logging();
    crate::test_log!("TEST START: test_capabilities_toon_parity");

    // JSON and TOON render the same capability payload; both must succeed and
    // surface the contract identity and the new sections.
    let (json_ok, json_out, _) = run_rch(&["capabilities", "--json"]);
    assert!(json_ok, "capabilities --json should succeed");
    assert!(json_out.contains("rch.capabilities.v1"));

    let (toon_ok, toon_out, toon_err) = run_rch(&["capabilities", "--format", "toon"]);
    assert!(
        toon_ok,
        "capabilities --format toon should succeed; stderr={toon_err}"
    );
    assert!(
        !toon_out.trim().is_empty(),
        "TOON capability output must not be empty"
    );
    for needle in ["reason_code_families", "policies"] {
        assert!(
            toon_out.contains(needle),
            "TOON capability output must carry the {needle:?} section"
        );
    }

    crate::test_log!("TEST PASS: test_capabilities_toon_parity");
}

#[test]
fn test_completions_include_remediation_commands() {
    init_test_logging();
    crate::test_log!("TEST START: test_completions_include_remediation_commands");

    let (ok, stdout, stderr) = run_rch(&["completions", "generate", "bash"]);
    assert!(
        ok,
        "rch completions generate bash should succeed; stderr={stderr}"
    );
    // clap_complete derives from the live command tree, so the new remediation
    // commands and flags must appear automatically. This locks that contract.
    for needle in [
        "admit",
        "exec",
        "self-test",
        "drain",
        "enable",
        "fleet",
        "--remediation",
    ] {
        assert!(
            stdout.contains(needle),
            "bash completions must include {needle:?}"
        );
    }

    crate::test_log!("TEST PASS: test_completions_include_remediation_commands");
}
