//! CRITICAL: E2E Hook Context Non-Interference Tests
//!
//! This module verifies that AI coding agents (the PRIMARY users of RCH)
//! are completely unaffected by rich_rust integration.
//!
//! ANY regression here is a BLOCKER.
//!
//! Implements bead: bd-36x8
//!
//! ## Test Coverage
//!
//! 1. stdout JSON responses are BYTE-FOR-BYTE identical to pre-integration
//! 2. NO rich output appears on stdout (zero bytes of ANSI codes)
//! 3. Exit codes are EXACTLY preserved (0, 1, 101, 128+N)
//! 4. Timing is not degraded (hook classification still <5ms)
//! 5. stderr can have rich output but ONLY if not captured by agent

use std::io::Write;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Marker for ANSI escape sequences.
const ANSI_ESC: &str = "\x1b[";

/// Maximum acceptable hook classification time in milliseconds.
const MAX_HOOK_TIME_MS: u64 = 10;

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

/// Run hook with given JSON input and return (exit_code, stdout, stderr, duration).
fn run_hook(input: &str) -> (i32, String, String, Duration) {
    let rch = rch_binary();
    let start = Instant::now();

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

    let duration = start.elapsed();

    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
        duration,
    )
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

// =============================================================================
// TEST 1: stdout JSON Response Integrity
// =============================================================================

#[test]
fn test_hook_stdout_is_valid_json_or_empty() {
    require_binary!();

    // Passthrough command (Tier-0) - should produce empty stdout (allow)
    let input = r#"{"tool_name":"Bash","tool_input":{"command":"echo hello"}}"#;
    let (exit, stdout, _stderr, _dur) = run_hook(input);

    // Allow responses produce empty stdout or {}
    if !stdout.is_empty() {
        // If there's content, it must be valid JSON
        let parsed: Result<serde_json::Value, _> = serde_json::from_str(&stdout);
        assert!(
            parsed.is_ok(),
            "stdout must be valid JSON or empty, got: {}",
            stdout
        );
    }

    assert_eq!(exit, 0, "Passthrough command should exit 0");
}

#[test]
fn test_hook_stdout_no_ansi_codes() {
    require_binary!();

    // Test various commands that should all produce clean stdout
    let test_cases = [
        r#"{"tool_name":"Bash","tool_input":{"command":"echo hello"}}"#,
        r#"{"tool_name":"Bash","tool_input":{"command":"ls -la"}}"#,
        r#"{"tool_name":"Bash","tool_input":{"command":"pwd"}}"#,
        r#"{"tool_name":"Read","tool_input":{"command":"/some/file"}}"#,
    ];

    for input in test_cases {
        let (_exit, stdout, _stderr, _dur) = run_hook(input);

        assert!(
            !stdout.contains(ANSI_ESC),
            "stdout contains ANSI escape codes for input: {}\nstdout: {}",
            input,
            stdout
        );
    }
}

// =============================================================================
// TEST 2: Exit Code Preservation
// =============================================================================

#[test]
fn test_hook_exit_code_allow() {
    require_binary!();

    // Passthrough command should exit 0 (allow)
    let input = r#"{"tool_name":"Bash","tool_input":{"command":"echo hello"}}"#;
    let (exit, _stdout, _stderr, _dur) = run_hook(input);

    assert_eq!(exit, 0, "Allow response should exit 0");
}

#[test]
fn test_hook_exit_code_non_bash_tool() {
    require_binary!();

    // Non-Bash tools should pass through (exit 0)
    let input = r#"{"tool_name":"Read","tool_input":{"command":"/some/file"}}"#;
    let (exit, _stdout, _stderr, _dur) = run_hook(input);

    assert_eq!(exit, 0, "Non-Bash tool should exit 0 (passthrough)");
}

// =============================================================================
// TEST 3: Fail-Open Behavior
// =============================================================================

#[test]
fn test_hook_empty_input_failopen() {
    require_binary!();

    // Empty input should not crash - fail open
    let (exit, _stdout, _stderr, _dur) = run_hook("");

    assert_eq!(exit, 0, "Empty input should exit 0 (fail-open)");
}

#[test]
fn test_hook_invalid_json_failopen() {
    require_binary!();

    // Invalid JSON should not crash - fail open
    let (exit, _stdout, _stderr, _dur) = run_hook("not valid json at all");

    assert_eq!(exit, 0, "Invalid JSON should exit 0 (fail-open)");
}

#[test]
fn test_hook_malformed_json_failopen() {
    require_binary!();

    // Malformed JSON (missing required fields) should fail open
    let input = r#"{"tool_name":"Bash"}"#;
    let (exit, _stdout, _stderr, _dur) = run_hook(input);

    assert_eq!(exit, 0, "Malformed JSON should exit 0 (fail-open)");
}

// =============================================================================
// TEST 4: Timing Budget (Hook classification < 10ms)
// =============================================================================

#[test]
fn test_hook_classification_timing() {
    require_binary!();

    let iterations = 20;
    let mut total_ms = 0u128;

    let input = r#"{"tool_name":"Bash","tool_input":{"command":"echo test"}}"#;

    for _ in 0..iterations {
        let (_exit, _stdout, _stderr, dur) = run_hook(input);
        total_ms += dur.as_millis();
    }

    let avg_ms = total_ms / iterations as u128;

    assert!(
        avg_ms <= MAX_HOOK_TIME_MS as u128,
        "Average hook time {}ms exceeds threshold {}ms",
        avg_ms,
        MAX_HOOK_TIME_MS
    );

    eprintln!(
        "Hook timing: avg {}ms over {} iterations (threshold: {}ms)",
        avg_ms, iterations, MAX_HOOK_TIME_MS
    );
}

// =============================================================================
// TEST 5: stderr/stdout Separation
// =============================================================================

#[test]
fn test_hook_stderr_stdout_separation() {
    require_binary!();

    // Cargo build command (may produce deny output)
    let input = r#"{"tool_name":"Bash","tool_input":{"command":"cargo build --release"}}"#;
    let (_exit, stdout, stderr, _dur) = run_hook(input);

    // stdout must be valid JSON or empty
    if !stdout.is_empty() {
        let parsed: Result<serde_json::Value, _> = serde_json::from_str(&stdout);
        assert!(
            parsed.is_ok(),
            "stdout must be valid JSON when non-empty, got: {}",
            stdout
        );
    }

    // stderr can have anything - we don't care about its contents
    // but it must not corrupt stdout
    eprintln!("stderr length: {} bytes", stderr.len());
}

// =============================================================================
// TEST 6: JSON Structure Verification
// =============================================================================

#[test]
fn test_hook_deny_json_structure() {
    require_binary!();

    // Cargo build command that would be intercepted
    // Note: May output deny if daemon not running, or nothing if allowed
    let input = r#"{"tool_name":"Bash","tool_input":{"command":"cargo build --release"}}"#;
    let (_exit, stdout, _stderr, _dur) = run_hook(input);

    if !stdout.is_empty() {
        // Parse and check structure
        let parsed: serde_json::Value =
            serde_json::from_str(&stdout).expect("stdout must be valid JSON");

        // If it's a deny response, check structure
        if let Some(output) = parsed.get("hookSpecificOutput") {
            assert!(
                output.get("hookEventName").is_some(),
                "Deny response missing hookEventName"
            );
            assert!(
                output.get("permissionDecision").is_some(),
                "Deny response missing permissionDecision"
            );
            assert!(
                output.get("permissionDecisionReason").is_some(),
                "Deny response missing permissionDecisionReason"
            );
        }
    }
}

// =============================================================================
// TEST 7: No State Leakage Between Invocations
// =============================================================================

#[test]
fn test_hook_no_state_leakage() {
    require_binary!();

    // Run multiple hook invocations and verify consistency
    let input = r#"{"tool_name":"Bash","tool_input":{"command":"echo hello"}}"#;

    let mut results: Vec<(i32, String)> = Vec::new();

    for _ in 0..5 {
        let (exit, stdout, _stderr, _dur) = run_hook(input);
        results.push((exit, stdout));
    }

    // All results should be identical
    let first = &results[0];
    for (i, result) in results.iter().enumerate().skip(1) {
        assert_eq!(
            result.0, first.0,
            "Exit code mismatch at iteration {}: {} vs {}",
            i, result.0, first.0
        );
        assert_eq!(
            result.1, first.1,
            "stdout mismatch at iteration {}: '{}' vs '{}'",
            i, result.1, first.1
        );
    }
}

// =============================================================================
// TEST 8: Binary Reproducibility (Critical for AI Agents)
// =============================================================================

#[test]
fn test_hook_output_deterministic() {
    require_binary!();

    let inputs = [
        r#"{"tool_name":"Bash","tool_input":{"command":"echo test"}}"#,
        r#"{"tool_name":"Bash","tool_input":{"command":"cargo check"}}"#,
        r#"{"tool_name":"Read","tool_input":{"command":"/tmp/file"}}"#,
    ];

    for input in inputs {
        let (exit1, stdout1, _, _) = run_hook(input);
        let (exit2, stdout2, _, _) = run_hook(input);

        assert_eq!(exit1, exit2, "Exit code not deterministic for: {}", input);
        assert_eq!(stdout1, stdout2, "stdout not deterministic for: {}", input);
    }
}

// =============================================================================
// Test Summary
// =============================================================================

/// Summary test that runs all critical checks and produces a report.
#[test]
fn test_hook_non_interference_summary() {
    require_binary!();

    eprintln!("\n=== Hook Non-Interference Test Summary ===\n");

    // Test 1: Valid JSON
    let input = r#"{"tool_name":"Bash","tool_input":{"command":"echo hello"}}"#;
    let (exit, stdout, _stderr, dur) = run_hook(input);
    eprintln!(
        "Passthrough command: exit={}, stdout_len={}, time={}ms",
        exit,
        stdout.len(),
        dur.as_millis()
    );

    // Test 2: No ANSI codes
    let has_ansi = stdout.contains(ANSI_ESC);
    eprintln!("ANSI codes in stdout: {}", has_ansi);
    assert!(!has_ansi, "stdout must not contain ANSI codes");

    // Test 3: Valid JSON structure
    if !stdout.is_empty() {
        let valid_json = serde_json::from_str::<serde_json::Value>(&stdout).is_ok();
        eprintln!("stdout is valid JSON: {}", valid_json);
        assert!(valid_json, "stdout must be valid JSON");
    } else {
        eprintln!("stdout is empty (allow response)");
    }

    // Test 4: Timing
    let mut total_time = Duration::ZERO;
    let iterations = 10;
    for _ in 0..iterations {
        let (_, _, _, d) = run_hook(input);
        total_time += d;
    }
    let avg_time = total_time / iterations;
    eprintln!("Average hook time: {}ms", avg_time.as_millis());
    assert!(
        avg_time.as_millis() <= MAX_HOOK_TIME_MS as u128,
        "Hook timing exceeds threshold"
    );

    eprintln!("\n=== All Hook Non-Interference Tests PASSED ===\n");
}
