use std::process::Command;

use super::common::{assert_contains, init_test_logging};

// =============================================================================
// Help and Version Tests
// =============================================================================

#[test]
fn test_rch_help_includes_description() {
    init_test_logging();
    crate::test_log!("TEST START: test_rch_help_includes_description");

    let output = Command::new(env!("CARGO_BIN_EXE_rch"))
        .arg("--help")
        .output()
        .expect("Failed to run rch --help");

    assert!(output.status.success(), "rch --help failed");
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert_contains(&stdout, "Remote Compilation Helper");
    crate::test_log!("TEST PASS: test_rch_help_includes_description");
}

#[test]
fn test_rch_version_output() {
    init_test_logging();
    crate::test_log!("TEST START: test_rch_version_output");

    let output = Command::new(env!("CARGO_BIN_EXE_rch"))
        .arg("--version")
        .output()
        .expect("Failed to run rch --version");

    assert!(output.status.success(), "rch --version failed");
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Version string should contain "rch" and a version number pattern
    assert_contains(&stdout, "rch");
    crate::test_log!("Version output: {}", stdout.trim());
    crate::test_log!("TEST PASS: test_rch_version_output");
}

// =============================================================================
// Subcommand Help Tests
// =============================================================================

#[test]
fn test_daemon_subcommand_help() {
    init_test_logging();
    crate::test_log!("TEST START: test_daemon_subcommand_help");

    let output = Command::new(env!("CARGO_BIN_EXE_rch"))
        .args(["daemon", "--help"])
        .output()
        .expect("Failed to run rch daemon --help");

    assert!(output.status.success(), "rch daemon --help failed");
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert_contains(&stdout, "daemon");
    crate::test_log!("TEST PASS: test_daemon_subcommand_help");
}

#[test]
fn test_workers_subcommand_help() {
    init_test_logging();
    crate::test_log!("TEST START: test_workers_subcommand_help");

    let output = Command::new(env!("CARGO_BIN_EXE_rch"))
        .args(["workers", "--help"])
        .output()
        .expect("Failed to run rch workers --help");

    assert!(output.status.success(), "rch workers --help failed");
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert_contains(&stdout, "workers");
    crate::test_log!("TEST PASS: test_workers_subcommand_help");
}

#[test]
fn test_config_subcommand_help() {
    init_test_logging();
    crate::test_log!("TEST START: test_config_subcommand_help");

    let output = Command::new(env!("CARGO_BIN_EXE_rch"))
        .args(["config", "--help"])
        .output()
        .expect("Failed to run rch config --help");

    assert!(output.status.success(), "rch config --help failed");
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert_contains(&stdout, "config");
    crate::test_log!("TEST PASS: test_config_subcommand_help");
}

#[test]
fn test_hook_subcommand_help() {
    init_test_logging();
    crate::test_log!("TEST START: test_hook_subcommand_help");

    let output = Command::new(env!("CARGO_BIN_EXE_rch"))
        .args(["hook", "--help"])
        .output()
        .expect("Failed to run rch hook --help");

    assert!(output.status.success(), "rch hook --help failed");
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert_contains(&stdout, "hook");
    crate::test_log!("TEST PASS: test_hook_subcommand_help");
}

#[test]
fn test_status_subcommand_help() {
    init_test_logging();
    crate::test_log!("TEST START: test_status_subcommand_help");

    let output = Command::new(env!("CARGO_BIN_EXE_rch"))
        .args(["status", "--help"])
        .output()
        .expect("Failed to run rch status --help");

    assert!(output.status.success(), "rch status --help failed");
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert_contains(&stdout, "status");
    crate::test_log!("TEST PASS: test_status_subcommand_help");
}

#[test]
fn test_diagnose_subcommand_help() {
    init_test_logging();
    crate::test_log!("TEST START: test_diagnose_subcommand_help");

    let output = Command::new(env!("CARGO_BIN_EXE_rch"))
        .args(["diagnose", "--help"])
        .output()
        .expect("Failed to run rch diagnose --help");

    assert!(output.status.success(), "rch diagnose --help failed");
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert_contains(&stdout, "diagnose");
    crate::test_log!("TEST PASS: test_diagnose_subcommand_help");
}

#[test]
fn test_doctor_subcommand_help() {
    init_test_logging();
    crate::test_log!("TEST START: test_doctor_subcommand_help");

    let output = Command::new(env!("CARGO_BIN_EXE_rch"))
        .args(["doctor", "--help"])
        .output()
        .expect("Failed to run rch doctor --help");

    assert!(output.status.success(), "rch doctor --help failed");
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert_contains(&stdout, "doctor");
    crate::test_log!("TEST PASS: test_doctor_subcommand_help");
}

#[test]
fn test_doctor_handles_closed_stdout_pipe() {
    init_test_logging();
    crate::test_log!("TEST START: test_doctor_handles_closed_stdout_pipe");

    let output = Command::new("bash")
        .args([
            "-o",
            "pipefail",
            "-c",
            "\"$RCH_BIN\" doctor 2>&1 | head -20",
        ])
        .env("RCH_BIN", env!("CARGO_BIN_EXE_rch"))
        .output()
        .expect("Failed to run rch doctor pipe regression");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "rch doctor should exit cleanly when stdout closes early; status={:?}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        stdout,
        stderr
    );
    assert_contains(&stdout, "RCH Diagnostic Report");
    assert!(
        !stderr.contains("panicked") && !stderr.contains("core dumped"),
        "rch doctor should not report a panic or abort when piped to head; stderr:\n{stderr}"
    );
    crate::test_log!("TEST PASS: test_doctor_handles_closed_stdout_pipe");
}

#[test]
fn test_speedscore_subcommand_help() {
    init_test_logging();
    crate::test_log!("TEST START: test_speedscore_subcommand_help");

    let output = Command::new(env!("CARGO_BIN_EXE_rch"))
        .args(["speedscore", "--help"])
        .output()
        .expect("Failed to run rch speedscore --help");

    assert!(output.status.success(), "rch speedscore --help failed");
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert_contains(&stdout, "speedscore");
    crate::test_log!("TEST PASS: test_speedscore_subcommand_help");
}

// =============================================================================
// Invalid Command Tests
// =============================================================================

#[test]
fn test_invalid_subcommand_fails() {
    init_test_logging();
    crate::test_log!("TEST START: test_invalid_subcommand_fails");

    let output = Command::new(env!("CARGO_BIN_EXE_rch"))
        .arg("nonexistent-command")
        .output()
        .expect("Failed to run rch nonexistent-command");

    assert!(
        !output.status.success(),
        "Expected failure for invalid subcommand"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Should contain error message about unrecognized command
    assert!(
        stderr.contains("error") || stderr.contains("unrecognized"),
        "Expected error message in stderr: {}",
        stderr
    );
    crate::test_log!("TEST PASS: test_invalid_subcommand_fails");
}

#[test]
fn test_invalid_flag_fails() {
    init_test_logging();
    crate::test_log!("TEST START: test_invalid_flag_fails");

    let output = Command::new(env!("CARGO_BIN_EXE_rch"))
        .arg("--nonexistent-flag")
        .output()
        .expect("Failed to run rch --nonexistent-flag");

    assert!(
        !output.status.success(),
        "Expected failure for invalid flag"
    );
    crate::test_log!("TEST PASS: test_invalid_flag_fails");
}

// =============================================================================
// Global Flag Tests
// =============================================================================

#[test]
fn test_global_verbose_flag_accepted() {
    init_test_logging();
    crate::test_log!("TEST START: test_global_verbose_flag_accepted");

    // --verbose should be accepted with --help (doesn't actually run command)
    let output = Command::new(env!("CARGO_BIN_EXE_rch"))
        .args(["--verbose", "--help"])
        .output()
        .expect("Failed to run rch --verbose --help");

    assert!(output.status.success(), "rch --verbose --help failed");
    crate::test_log!("TEST PASS: test_global_verbose_flag_accepted");
}

#[test]
fn test_global_quiet_flag_accepted() {
    init_test_logging();
    crate::test_log!("TEST START: test_global_quiet_flag_accepted");

    let output = Command::new(env!("CARGO_BIN_EXE_rch"))
        .args(["--quiet", "--help"])
        .output()
        .expect("Failed to run rch --quiet --help");

    assert!(output.status.success(), "rch --quiet --help failed");
    crate::test_log!("TEST PASS: test_global_quiet_flag_accepted");
}

#[test]
fn test_global_json_flag_accepted() {
    init_test_logging();
    crate::test_log!("TEST START: test_global_json_flag_accepted");

    let output = Command::new(env!("CARGO_BIN_EXE_rch"))
        .args(["--json", "--help"])
        .output()
        .expect("Failed to run rch --json --help");

    assert!(output.status.success(), "rch --json --help failed");
    crate::test_log!("TEST PASS: test_global_json_flag_accepted");
}

#[test]
fn test_global_color_flag_accepted() -> Result<(), Box<dyn std::error::Error>> {
    init_test_logging();
    crate::test_log!("TEST START: test_global_color_flag_accepted");

    for mode in ["auto", "always", "never"] {
        let output = Command::new(env!("CARGO_BIN_EXE_rch"))
            .args(["--color", mode, "--help"])
            .output()?;

        assert!(
            output.status.success(),
            "rch --color {} --help failed",
            mode
        );
    }
    crate::test_log!("TEST PASS: test_global_color_flag_accepted");
    Ok(())
}

#[test]
fn test_global_format_flag_accepted() -> Result<(), Box<dyn std::error::Error>> {
    init_test_logging();
    crate::test_log!("TEST START: test_global_format_flag_accepted");

    for format in ["json", "toon"] {
        let output = Command::new(env!("CARGO_BIN_EXE_rch"))
            .args(["--format", format, "--help"])
            .output()?;

        assert!(
            output.status.success(),
            "rch --format {} --help failed",
            format
        );
    }
    crate::test_log!("TEST PASS: test_global_format_flag_accepted");
    Ok(())
}

// =============================================================================
// Diagnose Command Tests
// =============================================================================

#[test]
fn test_diagnose_cargo_build_command() {
    init_test_logging();
    crate::test_log!("TEST START: test_diagnose_cargo_build_command");

    let output = Command::new(env!("CARGO_BIN_EXE_rch"))
        .args(["diagnose", "cargo", "build", "--release"])
        .output()
        .expect("Failed to run rch diagnose cargo build --release");

    // Command should succeed (even without daemon running, it can classify)
    // It may fail if daemon is not running, but parsing should work
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    crate::test_log!("stdout: {}", stdout);
    crate::test_log!("stderr: {}", stderr);

    // The command should at least attempt to classify
    crate::test_log!("TEST PASS: test_diagnose_cargo_build_command");
}

#[test]
fn test_diagnose_quoted_command() {
    init_test_logging();
    crate::test_log!("TEST START: test_diagnose_quoted_command");

    let output = Command::new(env!("CARGO_BIN_EXE_rch"))
        .args(["diagnose", "cargo build --release"])
        .output()
        .expect("Failed to run rch diagnose 'cargo build --release'");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    crate::test_log!("stdout: {}", stdout);
    crate::test_log!("stderr: {}", stderr);

    crate::test_log!("TEST PASS: test_diagnose_quoted_command");
}

#[test]
fn test_diagnose_non_compilation_command() {
    init_test_logging();
    crate::test_log!("TEST START: test_diagnose_non_compilation_command");

    let output = Command::new(env!("CARGO_BIN_EXE_rch"))
        .args(["diagnose", "ls", "-la"])
        .output()
        .expect("Failed to run rch diagnose ls -la");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    crate::test_log!("stdout: {}", stdout);
    crate::test_log!("stderr: {}", stderr);

    crate::test_log!("TEST PASS: test_diagnose_non_compilation_command");
}

#[test]
fn test_diagnose_json_output() {
    init_test_logging();
    crate::test_log!("TEST START: test_diagnose_json_output");

    let output = Command::new(env!("CARGO_BIN_EXE_rch"))
        .args(["--json", "diagnose", "cargo", "build"])
        .output()
        .expect("Failed to run rch --json diagnose cargo build");

    let stdout = String::from_utf8_lossy(&output.stdout);
    crate::test_log!("JSON output: {}", stdout);

    // If output is non-empty, it should be valid JSON structure
    if !stdout.trim().is_empty() {
        // Basic check that it looks like JSON (starts with { or [)
        let trimmed = stdout.trim();
        assert!(
            trimmed.starts_with('{') || trimmed.starts_with('['),
            "Expected JSON output to start with {{ or [, got: {}",
            &trimmed[..trimmed.len().min(100)]
        );
    }

    crate::test_log!("TEST PASS: test_diagnose_json_output");
}

// =============================================================================
// Workers Subcommand Tests
// =============================================================================

#[test]
fn test_workers_list_help() {
    init_test_logging();
    crate::test_log!("TEST START: test_workers_list_help");

    let output = Command::new(env!("CARGO_BIN_EXE_rch"))
        .args(["workers", "list", "--help"])
        .output()
        .expect("Failed to run rch workers list --help");

    assert!(output.status.success(), "rch workers list --help failed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_contains(&stdout, "list");
    crate::test_log!("TEST PASS: test_workers_list_help");
}

#[test]
fn test_workers_probe_help() {
    init_test_logging();
    crate::test_log!("TEST START: test_workers_probe_help");

    let output = Command::new(env!("CARGO_BIN_EXE_rch"))
        .args(["workers", "probe", "--help"])
        .output()
        .expect("Failed to run rch workers probe --help");

    assert!(output.status.success(), "rch workers probe --help failed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_contains(&stdout, "probe");
    crate::test_log!("TEST PASS: test_workers_probe_help");
}

#[test]
fn test_workers_capabilities_help() {
    init_test_logging();
    crate::test_log!("TEST START: test_workers_capabilities_help");

    let output = Command::new(env!("CARGO_BIN_EXE_rch"))
        .args(["workers", "capabilities", "--help"])
        .output()
        .expect("Failed to run rch workers capabilities --help");

    assert!(
        output.status.success(),
        "rch workers capabilities --help failed"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_contains(&stdout, "capabilities");
    crate::test_log!("TEST PASS: test_workers_capabilities_help");
}

// =============================================================================
// Daemon Subcommand Tests
// =============================================================================

#[test]
fn test_daemon_start_help() {
    init_test_logging();
    crate::test_log!("TEST START: test_daemon_start_help");

    let output = Command::new(env!("CARGO_BIN_EXE_rch"))
        .args(["daemon", "start", "--help"])
        .output()
        .expect("Failed to run rch daemon start --help");

    assert!(output.status.success(), "rch daemon start --help failed");
    crate::test_log!("TEST PASS: test_daemon_start_help");
}

#[test]
fn test_daemon_status_help() {
    init_test_logging();
    crate::test_log!("TEST START: test_daemon_status_help");

    let output = Command::new(env!("CARGO_BIN_EXE_rch"))
        .args(["daemon", "status", "--help"])
        .output()
        .expect("Failed to run rch daemon status --help");

    assert!(output.status.success(), "rch daemon status --help failed");
    crate::test_log!("TEST PASS: test_daemon_status_help");
}

// =============================================================================
// Config Subcommand Tests
// =============================================================================

#[test]
fn test_config_show_help() {
    init_test_logging();
    crate::test_log!("TEST START: test_config_show_help");

    let output = Command::new(env!("CARGO_BIN_EXE_rch"))
        .args(["config", "show", "--help"])
        .output()
        .expect("Failed to run rch config show --help");

    assert!(output.status.success(), "rch config show --help failed");
    crate::test_log!("TEST PASS: test_config_show_help");
}

#[test]
fn test_config_validate_help() {
    init_test_logging();
    crate::test_log!("TEST START: test_config_validate_help");

    let output = Command::new(env!("CARGO_BIN_EXE_rch"))
        .args(["config", "validate", "--help"])
        .output()
        .expect("Failed to run rch config validate --help");

    assert!(output.status.success(), "rch config validate --help failed");
    crate::test_log!("TEST PASS: test_config_validate_help");
}

// =============================================================================
// Hook Subcommand Tests
// =============================================================================

#[test]
fn test_hook_install_help() {
    init_test_logging();
    crate::test_log!("TEST START: test_hook_install_help");

    let output = Command::new(env!("CARGO_BIN_EXE_rch"))
        .args(["hook", "install", "--help"])
        .output()
        .expect("Failed to run rch hook install --help");

    assert!(output.status.success(), "rch hook install --help failed");
    crate::test_log!("TEST PASS: test_hook_install_help");
}

#[test]
fn test_hook_uninstall_help() {
    init_test_logging();
    crate::test_log!("TEST START: test_hook_uninstall_help");

    let output = Command::new(env!("CARGO_BIN_EXE_rch"))
        .args(["hook", "uninstall", "--help"])
        .output()
        .expect("Failed to run rch hook uninstall --help");

    assert!(output.status.success(), "rch hook uninstall --help failed");
    crate::test_log!("TEST PASS: test_hook_uninstall_help");
}

// =============================================================================
// Short Alias Tests
// =============================================================================

#[test]
fn test_short_verbose_flag() {
    init_test_logging();
    crate::test_log!("TEST START: test_short_verbose_flag");

    let output = Command::new(env!("CARGO_BIN_EXE_rch"))
        .args(["-v", "--help"])
        .output()
        .expect("Failed to run rch -v --help");

    assert!(output.status.success(), "rch -v --help failed");
    crate::test_log!("TEST PASS: test_short_verbose_flag");
}

#[test]
fn test_short_quiet_flag() {
    init_test_logging();
    crate::test_log!("TEST START: test_short_quiet_flag");

    let output = Command::new(env!("CARGO_BIN_EXE_rch"))
        .args(["-q", "--help"])
        .output()
        .expect("Failed to run rch -q --help");

    assert!(output.status.success(), "rch -q --help failed");
    crate::test_log!("TEST PASS: test_short_quiet_flag");
}

// =============================================================================
// Environment Variable Tests
// =============================================================================

#[test]
fn test_rch_verbose_env_var() {
    init_test_logging();
    crate::test_log!("TEST START: test_rch_verbose_env_var");

    // RCH_VERBOSE environment variable should be respected
    let output = Command::new(env!("CARGO_BIN_EXE_rch"))
        .env("RCH_VERBOSE", "true")
        .arg("--help")
        .output()
        .expect("Failed to run rch with RCH_VERBOSE=true");

    assert!(
        output.status.success(),
        "rch with RCH_VERBOSE=true --help failed"
    );
    crate::test_log!("TEST PASS: test_rch_verbose_env_var");
}

#[test]
fn test_rch_output_format_env_var() {
    init_test_logging();
    crate::test_log!("TEST START: test_rch_output_format_env_var");

    let output = Command::new(env!("CARGO_BIN_EXE_rch"))
        .env("RCH_OUTPUT_FORMAT", "json")
        .arg("--help")
        .output()
        .expect("Failed to run rch with RCH_OUTPUT_FORMAT=json");

    assert!(
        output.status.success(),
        "rch with RCH_OUTPUT_FORMAT=json --help failed"
    );
    crate::test_log!("TEST PASS: test_rch_output_format_env_var");
}

// =============================================================================
// Machine Discovery Flags Tests (--help-json, --capabilities)
// =============================================================================

#[test]
fn test_help_json_outputs_valid_json() {
    init_test_logging();
    crate::test_log!("TEST START: test_help_json_outputs_valid_json");

    let output = Command::new(env!("CARGO_BIN_EXE_rch"))
        .arg("--help-json")
        .output()
        .expect("Failed to run rch --help-json");

    assert!(output.status.success(), "rch --help-json failed");
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Should be valid JSON
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("--help-json should output valid JSON");

    // Should have expected structure
    assert!(parsed.get("name").is_some(), "Missing 'name' field");
    assert!(
        parsed.get("subcommands").is_some(),
        "Missing 'subcommands' field"
    );
    assert!(parsed.get("version").is_some(), "Missing 'version' field");

    crate::test_log!("TEST PASS: test_help_json_outputs_valid_json");
}

#[test]
fn test_help_json_with_subcommand() {
    init_test_logging();
    crate::test_log!("TEST START: test_help_json_with_subcommand");

    let output = Command::new(env!("CARGO_BIN_EXE_rch"))
        .args(["--help-json", "workers"])
        .output()
        .expect("Failed to run rch --help-json workers");

    assert!(output.status.success(), "rch --help-json workers failed");
    let stdout = String::from_utf8_lossy(&output.stdout);

    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("--help-json workers should output valid JSON");

    // Should be for the workers subcommand
    assert_eq!(
        parsed.get("name").and_then(|v| v.as_str()),
        Some("workers"),
        "Should be 'workers' subcommand"
    );

    // Should have nested subcommands
    let subcommands = parsed.get("subcommands").and_then(|v| v.as_array());
    assert!(subcommands.is_some(), "workers should have subcommands");
    assert!(
        !subcommands.unwrap().is_empty(),
        "workers should have subcommands"
    );

    crate::test_log!("TEST PASS: test_help_json_with_subcommand");
}

#[test]
fn test_capabilities_outputs_valid_json() {
    init_test_logging();
    crate::test_log!("TEST START: test_capabilities_outputs_valid_json");

    let output = Command::new(env!("CARGO_BIN_EXE_rch"))
        .arg("--capabilities")
        .output()
        .expect("Failed to run rch --capabilities");

    assert!(output.status.success(), "rch --capabilities failed");
    let stdout = String::from_utf8_lossy(&output.stdout);

    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("--capabilities should output valid JSON");

    // Should have expected structure
    assert!(parsed.get("version").is_some(), "Missing 'version' field");
    assert!(parsed.get("runtimes").is_some(), "Missing 'runtimes' field");
    assert!(parsed.get("commands").is_some(), "Missing 'commands' field");
    assert!(parsed.get("features").is_some(), "Missing 'features' field");

    crate::test_log!("TEST PASS: test_capabilities_outputs_valid_json");
}

#[test]
fn test_capabilities_lists_supported_runtimes() {
    init_test_logging();
    crate::test_log!("TEST START: test_capabilities_lists_supported_runtimes");

    let output = Command::new(env!("CARGO_BIN_EXE_rch"))
        .arg("--capabilities")
        .output()
        .expect("Failed to run rch --capabilities");

    assert!(output.status.success(), "rch --capabilities failed");
    let stdout = String::from_utf8_lossy(&output.stdout);

    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let runtimes = parsed.get("runtimes").and_then(|v| v.as_array()).unwrap();

    // Should list rust, bun, and node runtimes
    let runtime_names: Vec<&str> = runtimes
        .iter()
        .filter_map(|r| r.get("name").and_then(|n| n.as_str()))
        .collect();

    assert!(
        runtime_names.contains(&"rust"),
        "Should support rust runtime"
    );
    assert!(runtime_names.contains(&"bun"), "Should support bun runtime");
    assert!(
        runtime_names.contains(&"node"),
        "Should support node runtime"
    );

    crate::test_log!("TEST PASS: test_capabilities_lists_supported_runtimes");
}

#[test]
fn test_capabilities_lists_all_commands() {
    init_test_logging();
    crate::test_log!("TEST START: test_capabilities_lists_all_commands");

    let output = Command::new(env!("CARGO_BIN_EXE_rch"))
        .arg("--capabilities")
        .output()
        .expect("Failed to run rch --capabilities");

    assert!(output.status.success(), "rch --capabilities failed");
    let stdout = String::from_utf8_lossy(&output.stdout);

    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let commands = parsed.get("commands").and_then(|v| v.as_array()).unwrap();

    let command_names: Vec<&str> = commands
        .iter()
        .filter_map(|c| c.get("name").and_then(|n| n.as_str()))
        .collect();

    // Verify key commands are listed
    assert!(command_names.contains(&"init"), "Should list init command");
    assert!(
        command_names.contains(&"daemon"),
        "Should list daemon command"
    );
    assert!(
        command_names.contains(&"workers"),
        "Should list workers command"
    );
    assert!(
        command_names.contains(&"status"),
        "Should list status command"
    );
    assert!(
        command_names.contains(&"config"),
        "Should list config command"
    );

    crate::test_log!("TEST PASS: test_capabilities_lists_all_commands");
}
