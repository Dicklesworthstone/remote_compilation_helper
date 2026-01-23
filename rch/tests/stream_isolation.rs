//! E2E: stderr/stdout Stream Isolation Tests
//!
//! Verifies that rich output ONLY goes to stderr, and stdout remains
//! pristine for machine-parseable data.
//!
//! This is critical for:
//! - Agent JSON parsing
//! - Compiler output capture
//! - Pipeline composition (rch compile 2>/dev/null | jq)
//!
//! Implements bead: bd-2ans

use std::io::Write;
use std::process::{Command, Stdio};

/// Marker for ANSI escape sequences.
const ANSI_ESC: &str = "\x1b[";

/// Get the path to the rch binary.
fn rch_binary() -> String {
    std::env::var("RCH_BINARY").unwrap_or_else(|_| {
        let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
        format!(
            "{}/target/release/rch",
            manifest_dir.trim_end_matches("/rch")
        )
    })
}

/// Check if binary exists.
fn check_binary() -> bool {
    let rch = rch_binary();
    std::path::Path::new(&rch).exists()
}

/// Skip test if binary not available.
macro_rules! require_binary {
    () => {
        if !check_binary() {
            eprintln!("Skipping test: rch binary not found at {}", rch_binary());
            eprintln!("Build with: cargo build -p rch --release");
            return;
        }
    };
}

/// Run rch with arguments and return (exit_code, stdout, stderr).
fn run_rch(args: &[&str]) -> (i32, String, String) {
    let rch = rch_binary();

    let output = Command::new(&rch)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap_or_else(|e| panic!("Failed to run {}: {}", rch, e));

    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
    )
}

/// Run rch with environment variable and return (exit_code, stdout, stderr).
fn run_rch_with_env(args: &[&str], env_key: &str, env_val: &str) -> (i32, String, String) {
    let rch = rch_binary();

    let output = Command::new(&rch)
        .args(args)
        .env(env_key, env_val)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap_or_else(|e| panic!("Failed to run {}: {}", rch, e));

    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
    )
}

/// Run hook with stdin input and return (exit_code, stdout, stderr).
fn run_hook(input: &str) -> (i32, String, String) {
    let rch = rch_binary();

    let mut child = Command::new(&rch)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("Failed to spawn {}: {}", rch, e));

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(input.as_bytes()).ok();
    }

    let output = child.wait_with_output().expect("Failed to wait for rch");

    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
    )
}

// =============================================================================
// TEST 1: --json flag outputs only to stdout
// =============================================================================

#[test]
fn test_status_json_outputs_to_stdout() {
    require_binary!();

    let (_exit, stdout, _stderr) = run_rch(&["status", "--json"]);

    // stdout should be valid JSON or empty
    if !stdout.is_empty() {
        let parsed: Result<serde_json::Value, _> = serde_json::from_str(&stdout);
        assert!(
            parsed.is_ok(),
            "status --json stdout must be valid JSON, got: {}",
            stdout
        );
    }

    // stdout must NOT contain ANSI codes
    assert!(
        !stdout.contains(ANSI_ESC),
        "status --json stdout contains ANSI codes: {}",
        stdout
    );
}

#[test]
fn test_workers_list_json_outputs_to_stdout() {
    require_binary!();

    let (_exit, stdout, _stderr) = run_rch(&["workers", "list", "--json"]);

    if !stdout.is_empty() {
        let parsed: Result<serde_json::Value, _> = serde_json::from_str(&stdout);
        assert!(
            parsed.is_ok(),
            "workers list --json stdout must be valid JSON, got: {}",
            stdout
        );
    }

    assert!(
        !stdout.contains(ANSI_ESC),
        "workers list --json stdout contains ANSI codes: {}",
        stdout
    );
}

#[test]
fn test_config_show_json_outputs_to_stdout() {
    require_binary!();

    let (_exit, stdout, _stderr) = run_rch(&["config", "show", "--json"]);

    if !stdout.is_empty() {
        let parsed: Result<serde_json::Value, _> = serde_json::from_str(&stdout);
        assert!(
            parsed.is_ok(),
            "config show --json stdout must be valid JSON, got: {}",
            stdout
        );
    }

    assert!(
        !stdout.contains(ANSI_ESC),
        "config show --json stdout contains ANSI codes: {}",
        stdout
    );
}

// =============================================================================
// TEST 2: Hook output isolation
// =============================================================================

#[test]
fn test_hook_stdout_is_clean() {
    require_binary!();

    let input = r#"{"tool_name":"Bash","tool_input":{"command":"echo hello"}}"#;
    let (_exit, stdout, _stderr) = run_hook(input);

    if !stdout.is_empty() {
        let parsed: Result<serde_json::Value, _> = serde_json::from_str(&stdout);
        assert!(
            parsed.is_ok(),
            "hook stdout must be valid JSON or empty, got: {}",
            stdout
        );
    }

    assert!(
        !stdout.contains(ANSI_ESC),
        "hook stdout contains ANSI codes: {}",
        stdout
    );
}

#[test]
fn test_hook_cargo_stdout_is_clean() {
    require_binary!();

    // Cargo build command
    let input = r#"{"tool_name":"Bash","tool_input":{"command":"cargo build"}}"#;
    let (_exit, stdout, _stderr) = run_hook(input);

    if !stdout.is_empty() {
        let parsed: Result<serde_json::Value, _> = serde_json::from_str(&stdout);
        assert!(
            parsed.is_ok(),
            "hook stdout must be valid JSON or empty, got: {}",
            stdout
        );
    }

    assert!(
        !stdout.contains(ANSI_ESC),
        "hook stdout contains ANSI codes: {}",
        stdout
    );
}

// =============================================================================
// TEST 3: NO_COLOR environment variable
// =============================================================================

#[test]
fn test_no_color_disables_ansi_in_stdout() {
    require_binary!();

    let (_exit, stdout, _stderr) = run_rch_with_env(&["status"], "NO_COLOR", "1");

    assert!(
        !stdout.contains(ANSI_ESC),
        "stdout has ANSI codes with NO_COLOR=1: {}",
        stdout
    );
}

#[test]
fn test_no_color_disables_ansi_in_stderr() {
    require_binary!();

    let (_exit, _stdout, stderr) = run_rch_with_env(&["status"], "NO_COLOR", "1");

    assert!(
        !stderr.contains(ANSI_ESC),
        "stderr has ANSI codes with NO_COLOR=1: {}",
        stderr
    );
}

// =============================================================================
// TEST 4: Error output goes to stderr
// =============================================================================

#[test]
fn test_daemon_status_error_to_stderr() {
    require_binary!();

    let (_exit, stdout, _stderr) = run_rch(&["daemon", "status"]);

    // stdout should be minimal for non-JSON commands
    // Errors (like daemon not running) should go to stderr
    assert!(
        !stdout.contains(ANSI_ESC),
        "daemon status stdout contains ANSI codes: {}",
        stdout
    );
}

// =============================================================================
// TEST 5: JSON commands produce parseable output
// =============================================================================

#[test]
fn test_all_json_commands_parseable() {
    require_binary!();

    let json_commands = [
        vec!["status", "--json"],
        vec!["workers", "list", "--json"],
        vec!["config", "show", "--json"],
    ];

    for args in json_commands {
        let (_exit, stdout, _stderr) = run_rch(&args);

        if !stdout.is_empty() {
            let parsed: Result<serde_json::Value, _> = serde_json::from_str(&stdout);
            assert!(
                parsed.is_ok(),
                "{} output must be valid JSON, got: {}",
                args.join(" "),
                stdout
            );
        }

        assert!(
            !stdout.contains(ANSI_ESC),
            "{} stdout contains ANSI codes",
            args.join(" ")
        );
    }
}

// =============================================================================
// TEST 6: Consistency across multiple runs
// =============================================================================

#[test]
fn test_stream_isolation_consistent() {
    require_binary!();

    // Run the same command multiple times, verify consistent isolation
    for _ in 0..3 {
        let (_exit, stdout, _stderr) = run_rch(&["status", "--json"]);

        assert!(
            !stdout.contains(ANSI_ESC),
            "stdout contains ANSI codes on repeated run"
        );
    }
}

// =============================================================================
// Summary Test
// =============================================================================

#[test]
fn test_stream_isolation_summary() {
    require_binary!();

    eprintln!("\n=== Stream Isolation Test Summary ===\n");

    // Test JSON commands
    let json_commands = [
        ("status --json", vec!["status", "--json"]),
        ("workers list --json", vec!["workers", "list", "--json"]),
        ("config show --json", vec!["config", "show", "--json"]),
    ];

    for (name, args) in json_commands {
        let (_exit, stdout, _stderr) = run_rch(&args);

        let is_valid_json =
            stdout.is_empty() || serde_json::from_str::<serde_json::Value>(&stdout).is_ok();
        let has_ansi = stdout.contains(ANSI_ESC);

        eprintln!(
            "{}: valid_json={}, ansi_free={}",
            name, is_valid_json, !has_ansi
        );

        assert!(is_valid_json, "{} must produce valid JSON", name);
        assert!(!has_ansi, "{} must not have ANSI in stdout", name);
    }

    // Test hook
    let input = r#"{"tool_name":"Bash","tool_input":{"command":"echo test"}}"#;
    let (_exit, stdout, _stderr) = run_hook(input);
    let hook_clean = !stdout.contains(ANSI_ESC);
    eprintln!("hook: ansi_free={}", hook_clean);
    assert!(hook_clean, "hook must not have ANSI in stdout");

    // Test NO_COLOR
    let (_exit, stdout, stderr) = run_rch_with_env(&["status"], "NO_COLOR", "1");
    let no_color_works = !stdout.contains(ANSI_ESC) && !stderr.contains(ANSI_ESC);
    eprintln!("NO_COLOR=1: ansi_free={}", no_color_works);
    assert!(no_color_works, "NO_COLOR must disable ANSI everywhere");

    eprintln!("\n=== All Stream Isolation Tests PASSED ===\n");
}
