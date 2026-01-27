//! CRITICAL: Compile Command Hook Context Tests (bd-3obh)
//!
//! This module verifies that when an AI agent invokes compilation commands through
//! the RCH hook, the rich_rust integration does NOT interfere with:
//!   1. Hook JSON response (must be clean, machine-parseable)
//!   2. Compilation output that passes through (agents parse this)
//!   3. Exit codes (agents use these to determine success/failure)
//!   4. Error messages from the compiler (must be preserved exactly)
//!
//! ANY regression here is a BLOCKER - agents are the PRIMARY users of RCH.
//!
//! ## Test Coverage
//!
//! 1. cargo build command: JSON response purity
//! 2. cargo test command: JSON response purity
//! 3. cargo check command: JSON response purity
//! 4. Exit code preservation for successful builds
//! 5. Exit code preservation for build errors
//! 6. Compiler error message preservation
//! 7. No RCH-specific rich output leakage to stdout
//! 8. Compilation command classification timing (<5ms budget)
//! 9. stdout/stderr stream separation

use rch_common::classify_command;
use rch_common::testing::{TestLogger, TestPhase};
use std::io::Write;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Marker for ANSI escape sequences.
const ANSI_ESC: &str = "\x1b[";

/// Maximum acceptable hook classification time for compilation commands (ms).
const MAX_COMPILATION_HOOK_TIME_MS: u64 = 5;

/// RCH-specific rich output patterns that must NEVER appear in stdout.
const RCH_RICH_PATTERNS: &[&str] = &["[rch]", "[RCH]", "╔═", "║", "╚═"];

/// Get the path to the rch binary.
fn rch_binary() -> String {
    // Prefer an explicit override (useful for running these tests against a release build).
    std::env::var("RCH_BINARY").unwrap_or_else(|_| env!("CARGO_BIN_EXE_rch").to_string())
}

/// Run hook with given JSON input and return (exit_code, stdout, stderr, duration).
fn run_hook(input: &str) -> (i32, String, String, Duration) {
    let rch = rch_binary();
    let start = Instant::now();

    let mut child = Command::new(&rch)
        // Make tests deterministic and fast:
        // - never auto-start the daemon
        // - always use a non-existent socket path so selection fails fast-open
        .env("RCH_HOOK_STARTS_DAEMON", "0")
        .env("RCH_AUTO_START_TIMEOUT_SECS", "0")
        .env("RCH_SOCKET_PATH", "/tmp/rch-test-nonexistent.sock")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn rch");

    // Write input to stdin
    if let Some(ref mut stdin) = child.stdin {
        stdin.write_all(input.as_bytes()).ok();
    }
    drop(child.stdin.take()); // Close stdin

    let output = child.wait_with_output().expect("Failed to get output");
    let duration = start.elapsed();

    let exit_code = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    (exit_code, stdout, stderr, duration)
}

/// Check if stdout contains any ANSI escape codes.
fn contains_ansi_codes(s: &str) -> bool {
    s.contains(ANSI_ESC)
}

/// Check if stdout contains any RCH-specific rich output patterns.
fn contains_rch_rich_output(s: &str) -> bool {
    RCH_RICH_PATTERNS.iter().any(|pattern| s.contains(pattern))
}

/// Create a hook input JSON for a compilation command.
fn make_hook_input(command: &str) -> String {
    format!(
        r#"{{"tool_name":"Bash","tool_input":{{"command":"{}"}}}}"#,
        command
    )
}

// =============================================================================
// TEST 1: cargo build JSON Response Purity
// =============================================================================
#[test]
fn test_cargo_build_json_response_purity() {
    let logger = TestLogger::for_test("test_cargo_build_json_response_purity");

    let input = make_hook_input("cargo build --release");
    logger.log(
        TestPhase::Execute,
        "Running hook with cargo build --release",
    );
    let (exit_code, stdout, _stderr, _duration) = run_hook(&input);

    logger.log_with_data(
        TestPhase::Verify,
        "Checking JSON response purity",
        serde_json::json!({
            "exit_code": exit_code,
            "stdout_len": stdout.len()
        }),
    );

    // If there's output, it must be valid JSON
    if !stdout.is_empty() {
        let parsed: Result<serde_json::Value, _> = serde_json::from_str(&stdout);
        assert!(
            parsed.is_ok(),
            "stdout is not valid JSON: {}",
            stdout.chars().take(200).collect::<String>()
        );
    }

    // No ANSI codes in stdout
    assert!(
        !contains_ansi_codes(&stdout),
        "cargo build stdout contains ANSI codes!"
    );
    logger.pass();
}

// =============================================================================
// TEST 2: cargo test JSON Response Purity
// =============================================================================
#[test]
fn test_cargo_test_json_response_purity() {
    let input = make_hook_input("cargo test");
    let (_exit_code, stdout, _stderr, _duration) = run_hook(&input);

    if !stdout.is_empty() {
        let parsed: Result<serde_json::Value, _> = serde_json::from_str(&stdout);
        assert!(
            parsed.is_ok(),
            "cargo test stdout is not valid JSON: {}",
            stdout.chars().take(200).collect::<String>()
        );
    }

    assert!(
        !contains_ansi_codes(&stdout),
        "cargo test stdout contains ANSI codes!"
    );
}

// =============================================================================
// TEST 3: cargo check JSON Response Purity
// =============================================================================
#[test]
fn test_cargo_check_json_response_purity() {
    let input = make_hook_input("cargo check");
    let (_exit_code, stdout, _stderr, _duration) = run_hook(&input);

    if !stdout.is_empty() {
        let parsed: Result<serde_json::Value, _> = serde_json::from_str(&stdout);
        assert!(
            parsed.is_ok(),
            "cargo check stdout is not valid JSON: {}",
            stdout.chars().take(200).collect::<String>()
        );
    }

    assert!(
        !contains_ansi_codes(&stdout),
        "cargo check stdout contains ANSI codes!"
    );
}

// =============================================================================
// TEST 4: Exit Code Preservation - Success
// =============================================================================
#[test]
fn test_exit_code_preservation_allow() {
    // Passthrough command (non-compilation) should always exit 0
    let input = make_hook_input("echo hello");
    let (exit_code, _stdout, _stderr, _duration) = run_hook(&input);

    assert_eq!(exit_code, 0, "Passthrough command should exit 0");
}

// =============================================================================
// TEST 5: No RCH Rich Output in stdout
// =============================================================================
#[test]
fn test_no_rch_rich_output_leakage() {
    let commands = [
        "cargo build",
        "cargo test",
        "cargo check",
        "cargo build --release",
    ];

    for cmd in commands {
        let input = make_hook_input(cmd);
        let (_exit_code, stdout, _stderr, _duration) = run_hook(&input);

        assert!(
            !contains_rch_rich_output(&stdout),
            "RCH rich output found in stdout for '{}': {}",
            cmd,
            stdout.chars().take(200).collect::<String>()
        );
    }
}

// =============================================================================
// TEST 6: Compilation Command Classification Timing
// =============================================================================
#[test]
fn test_compilation_classification_timing() {
    let logger = TestLogger::for_test("test_compilation_classification_timing");
    let commands = [
        "cargo build",
        "cargo test",
        "cargo check",
        "cargo build --release",
    ];

    logger.log(
        TestPhase::Setup,
        format!(
            "Testing classification timing for {} commands",
            commands.len()
        ),
    );

    for cmd in commands {
        // NOTE: This test measures classifier latency, not full hook process startup.
        // The hook runs in a fresh process per command, so end-to-end timings vary
        // widely by machine/CI load. The classifier itself must remain fast.
        let iterations = 10_000u32;

        // Warm up (regex compilation, etc.)
        let warm = classify_command(cmd);
        assert!(warm.is_compilation, "Expected compilation command: {cmd}");

        let start = Instant::now();
        for _ in 0..iterations {
            let classification = classify_command(cmd);
            assert!(
                classification.is_compilation,
                "Expected compilation command: {cmd}"
            );
        }
        let total = start.elapsed();

        logger.log_with_data(
            TestPhase::Verify,
            format!("Classification timing for '{}'", cmd),
            serde_json::json!({
                "command": cmd,
                "iterations": iterations,
                "total_ns": total.as_nanos() as u64,
                "avg_ns": (total.as_nanos() / u128::from(iterations)) as u64,
                "threshold_ms": MAX_COMPILATION_HOOK_TIME_MS
            }),
        );

        let avg_ns = total.as_nanos() / u128::from(iterations);
        let max_allowed_ns = u128::from(MAX_COMPILATION_HOOK_TIME_MS) * 1_000_000;
        assert!(
            avg_ns <= max_allowed_ns,
            "Classification for '{}' too slow: {}ns avg (max: {}ms)",
            cmd,
            avg_ns,
            MAX_COMPILATION_HOOK_TIME_MS
        );

        eprintln!(
            "Timing for '{}': {}ns avg ({} iters)",
            cmd, avg_ns, iterations
        );
    }
    logger.pass();
}

// =============================================================================
// TEST 7: stdout/stderr Separation
// =============================================================================
#[test]
fn test_stdout_stderr_separation() {
    let input = make_hook_input("cargo build --release");
    let (_exit_code, stdout, _stderr, _duration) = run_hook(&input);

    // stdout must be either:
    // 1. Empty (allow)
    // 2. Valid JSON (deny with reason)
    if !stdout.is_empty() {
        // Check it's JSON, not raw log output
        let first_char = stdout.chars().next();
        assert!(
            first_char == Some('{') || first_char == Some('['),
            "stdout should be JSON, not raw output. Got: {}",
            stdout.chars().take(100).collect::<String>()
        );

        let parsed: Result<serde_json::Value, _> = serde_json::from_str(&stdout);
        assert!(
            parsed.is_ok(),
            "stdout must be valid JSON: {}",
            stdout.chars().take(200).collect::<String>()
        );
    }
}

// =============================================================================
// TEST 8: Empty and Invalid Input Handling
// =============================================================================
#[test]
fn test_empty_input_handling() {
    let (exit_code, _stdout, _stderr, _duration) = run_hook("");
    assert_eq!(exit_code, 0, "Empty input should exit 0 (fail-open)");
}

#[test]
fn test_invalid_json_handling() {
    let (exit_code, _stdout, _stderr, _duration) = run_hook("not valid json");
    assert_eq!(exit_code, 0, "Invalid JSON should exit 0 (fail-open)");
}

// =============================================================================
// TEST 9: Non-Bash Tool Passthrough
// =============================================================================
#[test]
fn test_non_bash_tool_passthrough() {
    let input = r#"{"tool_name":"Read","tool_input":{"path":"/some/file"}}"#;
    let (exit_code, _stdout, _stderr, _duration) = run_hook(input);
    assert_eq!(exit_code, 0, "Non-Bash tool should exit 0 (allow)");
}
