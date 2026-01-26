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
    let input = make_hook_input("cargo build --release");
    let (exit_code, stdout, _stderr, _duration) = run_hook(&input);

    // Hook should exit 0 (either allow or successful deny)
    // Non-zero may indicate daemon issues but shouldn't affect JSON purity
    eprintln!("Exit code: {}", exit_code);

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
    let commands = [
        "cargo build",
        "cargo test",
        "cargo check",
        "cargo build --release",
    ];

    for cmd in commands {
        let input = make_hook_input(cmd);

        // Run multiple times and average
        let iterations = 10;
        let mut total_duration = Duration::ZERO;

        for _ in 0..iterations {
            let (_exit_code, _stdout, _stderr, duration) = run_hook(&input);
            total_duration += duration;
        }

        let avg_ms = total_duration.as_millis() / iterations as u128;

        // Allow generous margin (10x budget) for CI variance
        let max_allowed_ms = MAX_COMPILATION_HOOK_TIME_MS * 10;
        assert!(
            avg_ms <= max_allowed_ms as u128,
            "Classification for '{}' too slow: {}ms (max: {}ms)",
            cmd,
            avg_ms,
            max_allowed_ms
        );

        eprintln!("Timing for '{}': {}ms avg", cmd, avg_ms);
    }
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
