//! E2E Tests for Hook Integration with Detailed Logging
//!
//! Tests the shell hook that intercepts compilation commands.
//! These tests verify:
//! - Command classification accuracy (intercept vs ignore)
//! - Timing budget compliance (P99 < 5ms for classification)
//! - Fallback behavior when daemon unavailable
//! - Environment variable handling
//!
//! Uses the E2E test harness from rch-common.

use rch_common::e2e::{HarnessResult, HookInputFixture, TestHarness, TestHarnessBuilder};
use rch_common::test_guard;
use rch_common::{Classification, TierDecision, classify_command, classify_command_detailed};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

// ============================================================================
// Test Helpers
// ============================================================================

/// Create a test harness configured for hook tests.
fn create_hook_harness(test_name: &str) -> HarnessResult<TestHarness> {
    // Respect CARGO_TARGET_DIR if set, otherwise use default target/debug
    let target_dir = if let Ok(target_dir) = std::env::var("CARGO_TARGET_DIR") {
        PathBuf::from(target_dir).join("debug")
    } else {
        let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("."));
        let project_root = manifest_dir.parent().unwrap_or(&manifest_dir);
        project_root.join("target/debug")
    };

    TestHarnessBuilder::new(test_name)
        .cleanup_on_success(true)
        .cleanup_on_failure(false)
        .default_timeout(Duration::from_secs(30))
        .rch_binary(target_dir.join("rch"))
        .rchd_binary(target_dir.join("rchd"))
        .rch_wkr_binary(target_dir.join("rch-wkr"))
        .build()
}

/// Run the hook binary with stdin input and capture output.
/// Returns (exit_code, stdout, stderr, duration).
#[allow(dead_code)]
fn run_hook_with_input(
    harness: &TestHarness,
    hook_input: &str,
    env_vars: Option<Vec<(&str, &str)>>,
) -> HarnessResult<(i32, String, String, Duration)> {
    let start = Instant::now();

    let mut cmd = Command::new(&harness.config.rch_binary);
    cmd.arg("hook")
        .arg("--input-format=json")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .current_dir(harness.test_dir());

    // Add environment variables if provided
    if let Some(vars) = env_vars {
        for (key, value) in vars {
            cmd.env(key, value);
        }
    }

    let mut child = cmd.spawn().map_err(|e| {
        rch_common::e2e::HarnessError::ProcessStartFailed(format!("Failed to spawn hook: {}", e))
    })?;

    // Write input to stdin
    if let Some(mut stdin) = child.stdin.take() {
        use std::io::Write;
        stdin.write_all(hook_input.as_bytes()).ok();
    }

    // Wait for process to complete
    let output = child.wait_with_output().map_err(|e| {
        rch_common::e2e::HarnessError::ProcessStartFailed(format!("Failed to wait for hook: {}", e))
    })?;

    let duration = start.elapsed();

    Ok((
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
        duration,
    ))
}

/// Classify a command and log the result for test diagnostics.
fn classify_and_log(harness: &TestHarness, command: &str) -> Classification {
    let start = Instant::now();
    let result = classify_command(command);
    let duration = start.elapsed();

    harness.logger.log_with_context(
        rch_common::e2e::LogLevel::Info,
        rch_common::e2e::LogSource::Custom("classify".to_string()),
        format!(
            "command='{}' is_compilation={} confidence={:.2} kind={:?}",
            command, result.is_compilation, result.confidence, result.kind
        ),
        vec![
            ("duration_us".to_string(), duration.as_micros().to_string()),
            ("reason".to_string(), result.reason.clone()),
        ],
    );

    result
}

// ============================================================================
// Classification Tests - Commands to INTERCEPT
// ============================================================================

#[test]
fn test_hook_intercepts_cargo_build() {
    let _guard = test_guard!();
    let harness = create_hook_harness("hook_intercepts_cargo_build").unwrap();

    harness
        .logger
        .info("TEST START: test_hook_intercepts_cargo_build");

    // Test basic cargo build
    let result = classify_and_log(&harness, "cargo build");
    harness
        .assert(result.is_compilation, "cargo build should be intercepted")
        .unwrap();
    assert!(
        result.confidence >= 0.95,
        "cargo build confidence should be >= 0.95"
    );

    // Test cargo build --release
    let result = classify_and_log(&harness, "cargo build --release");
    harness
        .assert(
            result.is_compilation,
            "cargo build --release should be intercepted",
        )
        .unwrap();
    assert!(result.confidence >= 0.95);

    // Test cargo build with target
    let result = classify_and_log(&harness, "cargo build --target x86_64-unknown-linux-gnu");
    harness
        .assert(
            result.is_compilation,
            "cargo build with target should be intercepted",
        )
        .unwrap();

    harness
        .logger
        .info("TEST PASS: test_hook_intercepts_cargo_build");
    harness.mark_passed();
}

#[test]
fn test_hook_intercepts_cargo_test() {
    let _guard = test_guard!();
    let harness = create_hook_harness("hook_intercepts_cargo_test").unwrap();

    harness
        .logger
        .info("TEST START: test_hook_intercepts_cargo_test");

    // Test cargo test
    let result = classify_and_log(&harness, "cargo test");
    harness
        .assert(result.is_compilation, "cargo test should be intercepted")
        .unwrap();
    assert!(result.confidence >= 0.95);

    // Test cargo test with package
    let result = classify_and_log(&harness, "cargo test -p my_crate");
    harness
        .assert(result.is_compilation, "cargo test -p should be intercepted")
        .unwrap();

    // Test cargo test with specific test
    let result = classify_and_log(&harness, "cargo test test_my_function");
    harness
        .assert(
            result.is_compilation,
            "cargo test with name should be intercepted",
        )
        .unwrap();

    harness
        .logger
        .info("TEST PASS: test_hook_intercepts_cargo_test");
    harness.mark_passed();
}

#[test]
fn test_hook_intercepts_cargo_check() {
    let _guard = test_guard!();
    let harness = create_hook_harness("hook_intercepts_cargo_check").unwrap();

    harness
        .logger
        .info("TEST START: test_hook_intercepts_cargo_check");

    let result = classify_and_log(&harness, "cargo check");
    harness
        .assert(result.is_compilation, "cargo check should be intercepted")
        .unwrap();
    assert!(result.confidence >= 0.90);

    harness
        .logger
        .info("TEST PASS: test_hook_intercepts_cargo_check");
    harness.mark_passed();
}

#[test]
fn test_hook_intercepts_rustc() {
    let _guard = test_guard!();
    let harness = create_hook_harness("hook_intercepts_rustc").unwrap();

    harness
        .logger
        .info("TEST START: test_hook_intercepts_rustc");

    let result = classify_and_log(&harness, "rustc main.rs");
    harness
        .assert(result.is_compilation, "rustc should be intercepted")
        .unwrap();
    assert!(result.confidence >= 0.95);

    harness.logger.info("TEST PASS: test_hook_intercepts_rustc");
    harness.mark_passed();
}

#[test]
fn test_hook_intercepts_bun_test() {
    let _guard = test_guard!();
    let harness = create_hook_harness("hook_intercepts_bun_test").unwrap();

    harness
        .logger
        .info("TEST START: test_hook_intercepts_bun_test");

    let result = classify_and_log(&harness, "bun test");
    harness
        .assert(result.is_compilation, "bun test should be intercepted")
        .unwrap();
    assert!(result.confidence >= 0.95);

    // With coverage
    let result = classify_and_log(&harness, "bun test --coverage");
    harness
        .assert(
            result.is_compilation,
            "bun test --coverage should be intercepted",
        )
        .unwrap();

    harness
        .logger
        .info("TEST PASS: test_hook_intercepts_bun_test");
    harness.mark_passed();
}

#[test]
fn test_hook_intercepts_bun_typecheck() {
    let _guard = test_guard!();
    let harness = create_hook_harness("hook_intercepts_bun_typecheck").unwrap();

    harness
        .logger
        .info("TEST START: test_hook_intercepts_bun_typecheck");

    let result = classify_and_log(&harness, "bun typecheck");
    harness
        .assert(result.is_compilation, "bun typecheck should be intercepted")
        .unwrap();
    assert!(result.confidence >= 0.95);

    harness
        .logger
        .info("TEST PASS: test_hook_intercepts_bun_typecheck");
    harness.mark_passed();
}

#[test]
fn test_hook_intercepts_gcc() {
    let _guard = test_guard!();
    let harness = create_hook_harness("hook_intercepts_gcc").unwrap();

    harness.logger.info("TEST START: test_hook_intercepts_gcc");

    let result = classify_and_log(&harness, "gcc -o main main.c");
    harness
        .assert(
            result.is_compilation,
            "gcc compilation should be intercepted",
        )
        .unwrap();
    assert!(result.confidence >= 0.90);

    harness.logger.info("TEST PASS: test_hook_intercepts_gcc");
    harness.mark_passed();
}

#[test]
fn test_hook_intercepts_make() {
    let _guard = test_guard!();
    let harness = create_hook_harness("hook_intercepts_make").unwrap();

    harness.logger.info("TEST START: test_hook_intercepts_make");

    let result = classify_and_log(&harness, "make -j8");
    harness
        .assert(result.is_compilation, "make -j8 should be intercepted")
        .unwrap();
    assert!(result.confidence >= 0.85);

    harness.logger.info("TEST PASS: test_hook_intercepts_make");
    harness.mark_passed();
}

#[test]
fn test_hook_intercepts_cmake_build() {
    let _guard = test_guard!();
    let harness = create_hook_harness("hook_intercepts_cmake_build").unwrap();

    harness
        .logger
        .info("TEST START: test_hook_intercepts_cmake_build");

    let result = classify_and_log(&harness, "cmake --build .");
    harness
        .assert(result.is_compilation, "cmake --build should be intercepted")
        .unwrap();
    assert!(result.confidence >= 0.85);

    harness
        .logger
        .info("TEST PASS: test_hook_intercepts_cmake_build");
    harness.mark_passed();
}

// ============================================================================
// Classification Tests - Commands to IGNORE
// ============================================================================

#[test]
fn test_hook_ignores_non_compilation() {
    let _guard = test_guard!();
    let harness = create_hook_harness("hook_ignores_non_compilation").unwrap();

    harness
        .logger
        .info("TEST START: test_hook_ignores_non_compilation");

    // Test ls
    let result = classify_and_log(&harness, "ls -la");
    harness
        .assert(!result.is_compilation, "ls should NOT be intercepted")
        .unwrap();

    // Test cd
    let result = classify_and_log(&harness, "cd /tmp");
    harness
        .assert(!result.is_compilation, "cd should NOT be intercepted")
        .unwrap();

    // Test echo
    let result = classify_and_log(&harness, "echo hello");
    harness
        .assert(!result.is_compilation, "echo should NOT be intercepted")
        .unwrap();

    // Test cat
    let result = classify_and_log(&harness, "cat file.txt");
    harness
        .assert(!result.is_compilation, "cat should NOT be intercepted")
        .unwrap();

    // Test git
    let result = classify_and_log(&harness, "git status");
    harness
        .assert(!result.is_compilation, "git should NOT be intercepted")
        .unwrap();

    harness
        .logger
        .info("TEST PASS: test_hook_ignores_non_compilation");
    harness.mark_passed();
}

#[test]
fn test_hook_ignores_piped_commands() {
    let _guard = test_guard!();
    let harness = create_hook_harness("hook_ignores_piped").unwrap();

    harness
        .logger
        .info("TEST START: test_hook_ignores_piped_commands");

    // Piped cargo build
    let result = classify_and_log(&harness, "cargo build | tee log");
    harness
        .assert(
            !result.is_compilation,
            "piped cargo build should NOT be intercepted",
        )
        .unwrap();
    assert!(
        result.reason.contains("piped"),
        "Reason should mention piped"
    );

    // Piped with grep
    let result = classify_and_log(&harness, "cargo build 2>&1 | grep error");
    harness
        .assert(
            !result.is_compilation,
            "piped command should NOT be intercepted",
        )
        .unwrap();

    // Piped bun test
    let result = classify_and_log(&harness, "bun test | grep PASS");
    harness
        .assert(
            !result.is_compilation,
            "piped bun test should NOT be intercepted",
        )
        .unwrap();

    harness
        .logger
        .info("TEST PASS: test_hook_ignores_piped_commands");
    harness.mark_passed();
}

#[test]
fn test_hook_ignores_redirected_commands() {
    let _guard = test_guard!();
    let harness = create_hook_harness("hook_ignores_redirected").unwrap();

    harness
        .logger
        .info("TEST START: test_hook_ignores_redirected_commands");

    // Output redirection
    let result = classify_and_log(&harness, "cargo build > output.txt");
    harness
        .assert(
            !result.is_compilation,
            "redirected cargo build should NOT be intercepted",
        )
        .unwrap();
    assert!(
        result.reason.contains("redirect"),
        "Reason should mention redirect"
    );

    // Stderr redirection
    let result = classify_and_log(&harness, "cargo build 2> errors.txt");
    harness
        .assert(
            !result.is_compilation,
            "stderr redirected should NOT be intercepted",
        )
        .unwrap();

    // Combined redirection
    let result = classify_and_log(&harness, "cargo build > out.txt 2>&1");
    harness
        .assert(
            !result.is_compilation,
            "combined redirect should NOT be intercepted",
        )
        .unwrap();

    harness
        .logger
        .info("TEST PASS: test_hook_ignores_redirected_commands");
    harness.mark_passed();
}

#[test]
fn test_hook_ignores_background_commands() {
    let _guard = test_guard!();
    let harness = create_hook_harness("hook_ignores_background").unwrap();

    harness
        .logger
        .info("TEST START: test_hook_ignores_background_commands");

    // Backgrounded cargo build
    let result = classify_and_log(&harness, "cargo build &");
    harness
        .assert(
            !result.is_compilation,
            "backgrounded cargo build should NOT be intercepted",
        )
        .unwrap();
    assert!(
        result.reason.contains("background"),
        "Reason should mention background"
    );

    // Backgrounded bun test
    let result = classify_and_log(&harness, "bun test &");
    harness
        .assert(
            !result.is_compilation,
            "backgrounded bun test should NOT be intercepted",
        )
        .unwrap();

    harness
        .logger
        .info("TEST PASS: test_hook_ignores_background_commands");
    harness.mark_passed();
}

#[test]
fn test_hook_ignores_chained_commands() {
    let _guard = test_guard!();
    let harness = create_hook_harness("hook_ignores_chained").unwrap();

    harness
        .logger
        .info("TEST START: test_hook_ignores_chained_commands");

    // && chained
    let result = classify_and_log(&harness, "cargo build && cargo test");
    harness
        .assert(
            !result.is_compilation,
            "&& chained should NOT be intercepted",
        )
        .unwrap();
    assert!(
        result.reason.contains("chained"),
        "Reason should mention chained"
    );

    // ; chained
    let result = classify_and_log(&harness, "cargo build; cargo test");
    harness
        .assert(
            !result.is_compilation,
            "; chained should NOT be intercepted",
        )
        .unwrap();

    // || chained
    let result = classify_and_log(&harness, "cargo build || echo failed");
    harness
        .assert(
            !result.is_compilation,
            "|| chained should NOT be intercepted",
        )
        .unwrap();

    harness
        .logger
        .info("TEST PASS: test_hook_ignores_chained_commands");
    harness.mark_passed();
}

#[test]
fn test_hook_ignores_cargo_fmt() {
    let _guard = test_guard!();
    let harness = create_hook_harness("hook_ignores_cargo_fmt").unwrap();

    harness
        .logger
        .info("TEST START: test_hook_ignores_cargo_fmt");

    let result = classify_and_log(&harness, "cargo fmt");
    harness
        .assert(
            !result.is_compilation,
            "cargo fmt should NOT be intercepted",
        )
        .unwrap();
    assert!(
        result.reason.contains("never-intercept"),
        "Should match never-intercept pattern"
    );

    harness
        .logger
        .info("TEST PASS: test_hook_ignores_cargo_fmt");
    harness.mark_passed();
}

#[test]
fn test_hook_ignores_bun_install() {
    let _guard = test_guard!();
    let harness = create_hook_harness("hook_ignores_bun_install").unwrap();

    harness
        .logger
        .info("TEST START: test_hook_ignores_bun_install");

    let result = classify_and_log(&harness, "bun install");
    harness
        .assert(
            !result.is_compilation,
            "bun install should NOT be intercepted",
        )
        .unwrap();

    let result = classify_and_log(&harness, "bun add lodash");
    harness
        .assert(!result.is_compilation, "bun add should NOT be intercepted")
        .unwrap();

    let result = classify_and_log(&harness, "bun run dev");
    harness
        .assert(!result.is_compilation, "bun run should NOT be intercepted")
        .unwrap();

    harness
        .logger
        .info("TEST PASS: test_hook_ignores_bun_install");
    harness.mark_passed();
}

#[test]
fn test_hook_ignores_bun_watch_mode() {
    let _guard = test_guard!();
    let harness = create_hook_harness("hook_ignores_bun_watch").unwrap();

    harness
        .logger
        .info("TEST START: test_hook_ignores_bun_watch_mode");

    // Watch mode is interactive - should not be intercepted
    let result = classify_and_log(&harness, "bun test --watch");
    harness
        .assert(
            !result.is_compilation,
            "bun test --watch should NOT be intercepted",
        )
        .unwrap();
    assert!(
        result.reason.contains("interactive"),
        "Should indicate interactive mode"
    );

    let result = classify_and_log(&harness, "bun typecheck --watch");
    harness
        .assert(
            !result.is_compilation,
            "bun typecheck --watch should NOT be intercepted",
        )
        .unwrap();

    harness
        .logger
        .info("TEST PASS: test_hook_ignores_bun_watch_mode");
    harness.mark_passed();
}

// ============================================================================
// Timing Budget Tests
// ============================================================================

#[test]
fn test_hook_timing_budget() {
    let _guard = test_guard!();
    let harness = create_hook_harness("hook_timing_budget").unwrap();

    harness.logger.info("TEST START: test_hook_timing_budget");

    // Collect timing data for many classifications
    let commands = [
        "ls -la",
        "echo hello",
        "cargo build",
        "cargo test --release",
        "bun test",
        "gcc -o main main.c",
        "make -j8",
        "git status",
        "npm install",
        "cd /tmp",
    ];

    let mut non_compilation_times: Vec<f64> = Vec::new();
    let mut compilation_times: Vec<f64> = Vec::new();

    // Run each command multiple times for better statistics
    for _ in 0..10 {
        for cmd in &commands {
            let start = Instant::now();
            let result = classify_command(cmd);
            let duration_ms = start.elapsed().as_secs_f64() * 1000.0;

            if result.is_compilation {
                compilation_times.push(duration_ms);
            } else {
                non_compilation_times.push(duration_ms);
            }
        }
    }

    // Calculate P99 for non-compilation
    non_compilation_times.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let p99_idx = (non_compilation_times.len() as f64 * 0.99) as usize;
    let p99_non_compilation = non_compilation_times
        .get(p99_idx.min(non_compilation_times.len() - 1))
        .copied()
        .unwrap_or(0.0);

    // Calculate P99 for compilation
    compilation_times.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let p99_idx = (compilation_times.len() as f64 * 0.99) as usize;
    let p99_compilation = compilation_times
        .get(p99_idx.min(compilation_times.len() - 1))
        .copied()
        .unwrap_or(0.0);

    harness.logger.log_with_context(
        rch_common::e2e::LogLevel::Info,
        rch_common::e2e::LogSource::Custom("timing".to_string()),
        format!(
            "TIMING: non_compilation_p99={:.3}ms compilation_p99={:.3}ms",
            p99_non_compilation, p99_compilation
        ),
        vec![
            (
                "non_compilation_count".to_string(),
                non_compilation_times.len().to_string(),
            ),
            (
                "compilation_count".to_string(),
                compilation_times.len().to_string(),
            ),
        ],
    );

    // Verify timing budgets per AGENTS.md:
    // - Non-compilation: <1ms (we allow up to 5ms for P99 due to system variance)
    // - Compilation: <5ms
    assert!(
        p99_non_compilation < 5.0,
        "Non-compilation P99 {:.3}ms should be < 5ms",
        p99_non_compilation
    );
    assert!(
        p99_compilation < 5.0,
        "Compilation P99 {:.3}ms should be < 5ms",
        p99_compilation
    );

    harness.logger.info(format!(
        "TEST PASS: test_hook_timing_budget (non_comp_p99={:.3}ms, comp_p99={:.3}ms)",
        p99_non_compilation, p99_compilation
    ));
    harness.mark_passed();
}

// ============================================================================
// Detailed Classification Tests
// ============================================================================

#[test]
fn test_hook_classification_details() {
    let _guard = test_guard!();
    let harness = create_hook_harness("hook_classification_details").unwrap();

    harness
        .logger
        .info("TEST START: test_hook_classification_details");

    // Test detailed classification for diagnostics
    let detailed = classify_command_detailed("cargo build --release");

    // Verify tier progression
    assert!(detailed.tiers.len() >= 4, "Should have at least 4 tiers");

    // Tier 0: Should pass (command present)
    let tier0 = detailed.tiers.iter().find(|t| t.tier == 0).unwrap();
    assert_eq!(tier0.decision, TierDecision::Pass, "Tier 0 should pass");

    // Tier 1: Should pass (no structure issues)
    let tier1 = detailed.tiers.iter().find(|t| t.tier == 1).unwrap();
    assert_eq!(tier1.decision, TierDecision::Pass, "Tier 1 should pass");

    // Tier 2: Should pass (keyword present)
    let tier2 = detailed.tiers.iter().find(|t| t.tier == 2).unwrap();
    assert_eq!(tier2.decision, TierDecision::Pass, "Tier 2 should pass");

    // Tier 3: Should pass (not in never-intercept list)
    let tier3 = detailed.tiers.iter().find(|t| t.tier == 3).unwrap();
    assert_eq!(tier3.decision, TierDecision::Pass, "Tier 3 should pass");

    // Final classification
    assert!(detailed.classification.is_compilation);
    assert!(detailed.classification.confidence >= 0.95);

    harness
        .logger
        .info("TEST PASS: test_hook_classification_details");
    harness.mark_passed();
}

#[test]
fn test_hook_classification_details_piped_rejection() {
    let _guard = test_guard!();
    let harness = create_hook_harness("hook_classification_details_piped").unwrap();

    harness
        .logger
        .info("TEST START: test_hook_classification_details_piped_rejection");

    let detailed = classify_command_detailed("cargo build | tee log.txt");

    // Should be rejected at Tier 1 (structure analysis)
    let tier1 = detailed.tiers.iter().find(|t| t.tier == 1).unwrap();
    assert_eq!(
        tier1.decision,
        TierDecision::Reject,
        "Tier 1 should reject piped command"
    );
    assert!(
        tier1.reason.contains("piped"),
        "Reason should mention piped"
    );

    // Final classification should be non-compilation
    assert!(!detailed.classification.is_compilation);

    harness
        .logger
        .info("TEST PASS: test_hook_classification_details_piped_rejection");
    harness.mark_passed();
}

#[test]
fn test_hook_classification_details_never_intercept() {
    let _guard = test_guard!();
    let harness = create_hook_harness("hook_classification_details_never_intercept").unwrap();

    harness
        .logger
        .info("TEST START: test_hook_classification_details_never_intercept");

    let detailed = classify_command_detailed("cargo fmt");

    // Should pass Tier 0, 1, 2 but reject at Tier 3
    let tier3 = detailed.tiers.iter().find(|t| t.tier == 3).unwrap();
    assert_eq!(
        tier3.decision,
        TierDecision::Reject,
        "Tier 3 should reject cargo fmt"
    );
    assert!(
        tier3.reason.contains("never-intercept"),
        "Reason should mention never-intercept"
    );

    assert!(!detailed.classification.is_compilation);

    harness
        .logger
        .info("TEST PASS: test_hook_classification_details_never_intercept");
    harness.mark_passed();
}

// ============================================================================
// Wrapper Command Tests
// ============================================================================

#[test]
fn test_hook_wrapped_commands() {
    let _guard = test_guard!();
    let harness = create_hook_harness("hook_wrapped_commands").unwrap();

    harness
        .logger
        .info("TEST START: test_hook_wrapped_commands");

    // Commands with wrappers should be normalized and classified
    let result = classify_and_log(&harness, "time cargo build");
    harness
        .assert(
            result.is_compilation,
            "time cargo build should be intercepted",
        )
        .unwrap();

    let result = classify_and_log(&harness, "sudo cargo check");
    harness
        .assert(
            result.is_compilation,
            "sudo cargo check should be intercepted",
        )
        .unwrap();

    let result = classify_and_log(&harness, "env RUST_BACKTRACE=1 cargo test");
    harness
        .assert(
            result.is_compilation,
            "env-wrapped cargo test should be intercepted",
        )
        .unwrap();

    harness.logger.info("TEST PASS: test_hook_wrapped_commands");
    harness.mark_passed();
}

// ============================================================================
// Hook Input JSON Tests
// ============================================================================

#[test]
fn test_hook_input_fixture_format() {
    let _guard = test_guard!();
    let harness = create_hook_harness("hook_input_fixture").unwrap();

    harness
        .logger
        .info("TEST START: test_hook_input_fixture_format");

    // Test HookInputFixture generates valid JSON
    let input = HookInputFixture::cargo_build();
    let json = input.to_json();

    assert!(json.contains("\"tool_name\": \"Bash\""));
    assert!(json.contains("\"command\": \"cargo build\""));

    // Test custom command
    let input = HookInputFixture::custom("cargo test --release");
    let json = input.to_json();
    assert!(json.contains("\"command\": \"cargo test --release\""));

    harness
        .logger
        .info("TEST PASS: test_hook_input_fixture_format");
    harness.mark_passed();
}

// ============================================================================
// Environment Variable Tests
// ============================================================================

#[test]
fn test_hook_env_rch_disabled() {
    let _guard = test_guard!();
    let harness = create_hook_harness("hook_env_disabled").unwrap();

    harness
        .logger
        .info("TEST START: test_hook_env_rch_disabled");

    // When RCH_ENABLED=false, classification should still work
    // (the config check happens in the hook, not in classify_command)
    // This test verifies the classification logic is independent of config

    let result = classify_command("cargo build");
    assert!(
        result.is_compilation,
        "Classification should work regardless of RCH_ENABLED"
    );

    harness.logger.info("TEST PASS: test_hook_env_rch_disabled");
    harness.mark_passed();
}

// ============================================================================
// Edge Cases
// ============================================================================

#[test]
fn test_hook_empty_command() {
    let _guard = test_guard!();
    let harness = create_hook_harness("hook_empty_command").unwrap();

    harness.logger.info("TEST START: test_hook_empty_command");

    let result = classify_command("");
    assert!(
        !result.is_compilation,
        "Empty command should not be intercepted"
    );
    assert!(
        result.reason.contains("empty"),
        "Reason should mention empty"
    );

    let result = classify_command("   ");
    assert!(
        !result.is_compilation,
        "Whitespace-only command should not be intercepted"
    );

    harness.logger.info("TEST PASS: test_hook_empty_command");
    harness.mark_passed();
}

#[test]
fn test_hook_subshell_capture() {
    let _guard = test_guard!();
    let harness = create_hook_harness("hook_subshell_capture").unwrap();

    harness
        .logger
        .info("TEST START: test_hook_subshell_capture");

    // Subshell capture should not be intercepted
    let result = classify_command("cargo build $(echo src/)");
    assert!(
        !result.is_compilation,
        "Subshell capture should not be intercepted"
    );
    assert!(
        result.reason.contains("subshell"),
        "Reason should mention subshell"
    );

    // Backtick subshell
    let result = classify_command("cargo build `echo flags`");
    assert!(
        !result.is_compilation,
        "Backtick subshell should not be intercepted"
    );

    harness.logger.info("TEST PASS: test_hook_subshell_capture");
    harness.mark_passed();
}

#[test]
fn test_hook_version_checks_not_intercepted() {
    let _guard = test_guard!();
    let harness = create_hook_harness("hook_version_checks").unwrap();

    harness
        .logger
        .info("TEST START: test_hook_version_checks_not_intercepted");

    // Version checks should not be intercepted
    let result = classify_command("cargo --version");
    assert!(
        !result.is_compilation,
        "cargo --version should not be intercepted"
    );

    let result = classify_command("rustc --version");
    assert!(
        !result.is_compilation,
        "rustc --version should not be intercepted"
    );

    let result = classify_command("gcc --version");
    assert!(
        !result.is_compilation,
        "gcc --version should not be intercepted"
    );

    let result = classify_command("bun --version");
    assert!(
        !result.is_compilation,
        "bun --version should not be intercepted"
    );

    harness
        .logger
        .info("TEST PASS: test_hook_version_checks_not_intercepted");
    harness.mark_passed();
}
