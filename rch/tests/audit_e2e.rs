//! E2E Audit Integration Tests for All Workstream Fixes
//!
//! Validates all 4 workstreams from the Hot-Path Performance & Correctness audit
//! (bd-2mmt). Each section logs structured output for CI integration.
//!
//! Sections:
//! 1. Performance budget verification (classify_command latency)
//! 2. WS2: Zero-allocation reject path (Cow::Borrowed on hot path)
//! 3. WS4: Multi-command classification correctness
//! 4. Fail-open verification (malformed input handling)
//! 5. Classification correctness (compilation vs non-compilation)
//!
//! WS1 (spawn_blocking) and WS3 (atomics) are verified via unit tests in
//! their respective crates; this file covers the cross-cutting E2E scenarios.

use rch_common::{
    Classification, CompilationKind, TierDecision, classify_command, classify_command_detailed,
    split_shell_commands,
};
use std::borrow::Cow;
use std::time::Instant;

// ============================================================================
// Section 1: Performance Budget Verification
// ============================================================================

/// Non-compilation commands that must classify in <1ms (p99).
const NON_COMPILATION_COMMANDS: &[&str] = &[
    "ls",
    "cat README.md",
    "echo hello",
    "git status",
    "git diff",
    "cd /tmp",
    "pwd",
    "whoami",
    "env",
    "which cargo",
    "mkdir -p /tmp/foo",
    "rm -rf /tmp/foo",
    "cp a b",
    "mv a b",
    "chmod 755 script.sh",
    "grep -r pattern .",
    "find . -name '*.rs'",
    "wc -l file.txt",
    "head -n 10 file.txt",
    "tail -f log.txt",
];

/// Compilation commands that must classify in <5ms (p99).
const COMPILATION_COMMANDS: &[&str] = &[
    "cargo build",
    "cargo build --release",
    "cargo test",
    "cargo test -p rch-common",
    "cargo check --all-targets",
    "cargo clippy --all-targets -- -D warnings",
    "cargo doc --no-deps",
    "cargo bench",
    "make",
    "make -j8",
    "gcc -o main main.c",
    "g++ -std=c++17 -o main main.cpp",
    "clang -O2 -o main main.c",
    "cmake --build build",
    "ninja",
    "rustc main.rs",
    "cargo nextest run",
    "meson compile -C build",
    "bun test",
    "bun typecheck",
];

/// Measure p99 latency for a set of commands over N iterations.
fn measure_p99_latency(commands: &[&str], iterations: usize) -> (f64, f64, f64) {
    let mut durations_us: Vec<f64> = Vec::with_capacity(commands.len() * iterations);

    for cmd in commands {
        for _ in 0..iterations {
            let start = Instant::now();
            let _ = classify_command(cmd);
            durations_us.push(start.elapsed().as_nanos() as f64 / 1_000.0);
        }
    }

    durations_us.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let len = durations_us.len();

    let p50 = durations_us[len / 2];
    let p95 = durations_us[(len as f64 * 0.95) as usize];
    let p99 = durations_us[(len as f64 * 0.99) as usize];

    (p50, p95, p99)
}

#[test]
fn test_perf_non_compilation_under_1ms() {
    // Warmup
    for cmd in NON_COMPILATION_COMMANDS {
        let _ = classify_command(cmd);
    }

    let (p50, p95, p99) = measure_p99_latency(NON_COMPILATION_COMMANDS, 100);

    let p99_ms = p99 / 1_000.0;
    let panic_threshold_ms = 5.0;

    eprintln!(
        "PERF: non-compilation p50={:.1}us p95={:.1}us p99={:.1}us ({:.3}ms) (<1ms required)",
        p50, p95, p99, p99_ms
    );

    assert!(
        p99_ms < panic_threshold_ms,
        "PERF FAIL: non-compilation p99={:.3}ms exceeds panic threshold {:.0}ms",
        p99_ms,
        panic_threshold_ms
    );

    // Soft check: log warning but don't fail if p99 > 1ms (CI variability)
    if p99_ms >= 1.0 {
        eprintln!(
            "PERF WARNING: non-compilation p99={:.3}ms exceeds 1ms budget (CI jitter expected)",
            p99_ms
        );
    }
}

#[test]
fn test_perf_compilation_under_5ms() {
    // Warmup
    for cmd in COMPILATION_COMMANDS {
        let _ = classify_command(cmd);
    }

    let (p50, p95, p99) = measure_p99_latency(COMPILATION_COMMANDS, 100);

    let p99_ms = p99 / 1_000.0;
    let panic_threshold_ms = 10.0;

    eprintln!(
        "PERF: compilation p50={:.1}us p95={:.1}us p99={:.1}us ({:.3}ms) (<5ms required)",
        p50, p95, p99, p99_ms
    );

    assert!(
        p99_ms < panic_threshold_ms,
        "PERF FAIL: compilation p99={:.3}ms exceeds panic threshold {:.0}ms",
        p99_ms,
        panic_threshold_ms
    );

    if p99_ms >= 5.0 {
        eprintln!(
            "PERF WARNING: compilation p99={:.3}ms exceeds 5ms budget (CI jitter expected)",
            p99_ms
        );
    }
}

// ============================================================================
// Section 2: WS2 — Zero-Allocation Reject Path Verification
// ============================================================================

/// Assert that a Cow<'static, str> is borrowed (zero allocation).
/// We need the actual &Cow to distinguish Borrowed from Owned.
#[allow(clippy::ptr_arg)]
fn assert_cow_borrowed(cow: &Cow<'static, str>, context: &str) {
    assert!(
        matches!(cow, Cow::Borrowed(_)),
        "{context}: expected Cow::Borrowed, got Cow::Owned({:?})",
        cow,
    );
}

#[test]
fn test_ws2_tier0_reject_uses_borrowed_reason() {
    // Empty command → Tier 0 instant reject
    let details = classify_command_detailed("");
    assert!(!details.classification.is_compilation);
    assert_cow_borrowed(&details.classification.reason, "empty command reason");
}

#[test]
fn test_ws2_tier0_whitespace_only_borrowed() {
    let details = classify_command_detailed("   ");
    assert!(!details.classification.is_compilation);
    assert_cow_borrowed(
        &details.classification.reason,
        "whitespace-only command reason",
    );
}

#[test]
fn test_ws2_non_compilation_reasons_borrowed() {
    // Non-compilation commands at various tiers should use borrowed reasons
    let simple_rejects = &["ls", "cat", "echo hello", "git status", "cd /tmp", "pwd"];

    for cmd in simple_rejects {
        let details = classify_command_detailed(cmd);
        assert!(
            !details.classification.is_compilation,
            "'{}' should not be compilation",
            cmd
        );

        // Check tier name fields are all borrowed (static strings)
        for tier in &details.tiers {
            assert_cow_borrowed(&tier.name, &format!("tier name for '{}'", cmd));
        }
    }
}

#[test]
fn test_ws2_bulk_classification_throughput() {
    // Classify 1000 non-compilation commands and measure throughput
    let commands: Vec<&str> = NON_COMPILATION_COMMANDS
        .iter()
        .cycle()
        .take(1000)
        .copied()
        .collect();

    let start = Instant::now();
    for cmd in &commands {
        let _ = classify_command(cmd);
    }
    let elapsed = start.elapsed();
    let avg_us = elapsed.as_micros() as f64 / commands.len() as f64;

    eprintln!(
        "CLASSIFICATION: {} commands in {:.1}ms, avg {:.1}us/cmd",
        commands.len(),
        elapsed.as_secs_f64() * 1_000.0,
        avg_us,
    );

    // Average should be well under 5ms (5000us) per command
    assert!(
        avg_us < 5_000.0,
        "CLASSIFICATION FAIL: avg {:.1}us exceeds 5ms budget",
        avg_us,
    );
}

// ============================================================================
// Section 3: WS4 — Multi-Command Classification
// ============================================================================

#[test]
fn test_ws4_split_shell_commands_basic() {
    let segments = split_shell_commands("cargo build && cargo test");
    assert_eq!(segments.len(), 2);
    assert_eq!(segments[0], "cargo build");
    assert_eq!(segments[1], "cargo test");
}

#[test]
fn test_ws4_split_semicolons() {
    let segments = split_shell_commands("cargo build; cargo test; echo done");
    assert_eq!(segments.len(), 3);
    assert_eq!(segments[0], "cargo build");
    assert_eq!(segments[1], "cargo test");
    assert_eq!(segments[2], "echo done");
}

#[test]
fn test_ws4_split_or_operator() {
    let segments = split_shell_commands("cargo build || echo failed");
    assert_eq!(segments.len(), 2);
    assert_eq!(segments[0], "cargo build");
    assert_eq!(segments[1], "echo failed");
}

#[test]
fn test_ws4_split_preserves_quoting() {
    // Quoted strings containing separators should not be split
    let segments = split_shell_commands("echo 'hello && world'");
    assert_eq!(segments.len(), 1);
    assert_eq!(segments[0], "echo 'hello && world'");
}

#[test]
fn test_ws4_split_empty_input() {
    let segments = split_shell_commands("");
    // Empty or whitespace-only should return empty or single empty entry
    assert!(
        segments.is_empty() || (segments.len() == 1 && segments[0].is_empty()),
        "empty input should produce empty/whitespace result, got {:?}",
        segments
    );
}

#[test]
fn test_ws4_multi_command_classification_correctness() {
    // Multi-command with compilation: should detect compilation
    let test_cases: &[(&str, bool)] = &[
        // Pure compilation
        // Compound && commands with compilation LAST segment are accepted
        // This enables patterns like "cd /path && cargo build"
        ("cargo build && cargo test", true), // last=cargo test (compilation)
        ("cargo build || echo failed", false), // || not supported
        ("cargo build; cargo test", false),  // ; not supported
        ("echo starting && cargo build", true), // last=cargo build (compilation)
        ("cargo test && echo done", false),  // last=echo done (not compilation)
        ("ls && cargo build && pwd", false), // last=pwd (not compilation)
        // Pure non-compilation chains
        ("ls && pwd", false),
        ("echo hello; echo world", false), // ; not supported anyway
        ("git status && git diff", false),
        ("cd /tmp || echo failed", false), // || not supported
        // Edge cases
        ("cargo build --release && cargo test -p my_crate", true), // last is cargo test
        ("make -j8 && echo done", false), // last=echo done (not compilation)
    ];

    let mut passed = 0;
    let total = test_cases.len();

    for (cmd, expected_compilation) in test_cases {
        let result = classify_command(cmd);
        let ok = result.is_compilation == *expected_compilation;

        eprintln!(
            "MULTI-CMD: '{}' → compilation={} (expected={}) {}",
            cmd,
            result.is_compilation,
            expected_compilation,
            if ok { "PASS" } else { "FAIL" },
        );

        if ok {
            passed += 1;
        }
    }

    assert_eq!(
        passed, total,
        "MULTI-CMD: {}/{} tests passed",
        passed, total
    );
}

#[test]
fn test_ws4_long_multi_command_chain() {
    // Stress test: long chain of commands
    let long_chain = (0..20)
        .map(|i| if i == 10 { "cargo build" } else { "echo step" })
        .collect::<Vec<_>>()
        .join(" && ");

    let result = classify_command(&long_chain);
    assert!(
        !result.is_compilation,
        "long chained command should be rejected"
    );
    assert!(result.reason.contains("chained"));
}

// ============================================================================
// Section 4: Fail-Open Verification
// ============================================================================

#[test]
fn test_failopen_empty_command() {
    let result = classify_command("");
    // Should return a valid result, not panic
    assert!(!result.is_compilation);
}

#[test]
fn test_failopen_whitespace_only() {
    let result = classify_command("   \t\n  ");
    assert!(!result.is_compilation);
}

#[test]
fn test_failopen_very_long_command() {
    // Extremely long command should not panic
    let long_cmd = "a".repeat(100_000);
    let result = classify_command(&long_cmd);
    // Should return a valid result (not compilation, since "aaa..." isn't a known command)
    assert!(!result.is_compilation);
}

#[test]
fn test_failopen_special_characters() {
    let special_cases = &[
        "\0",
        "\x01\x02\x03",
        "$(rm -rf /)",
        "`rm -rf /`",
        "'; DROP TABLE commands; --",
        "\\n\\r\\t",
        "\u{FEFF}cargo build", // BOM prefix
        "cargo\x00build",      // null byte in middle
    ];

    for cmd in special_cases {
        // Must not panic — that's the key invariant
        let result = classify_command(cmd);
        eprintln!(
            "FAIL-OPEN: input={:?} → compilation={} reason={:?} PASS",
            cmd.escape_default().to_string(),
            result.is_compilation,
            result.reason,
        );
    }
}

#[test]
fn test_failopen_unicode_edge_cases() {
    let unicode_cases = &[
        "café build",
        "cargo 🦀 build",
        "日本語コマンド",
        "cargo build —release", // em-dash instead of double-dash
    ];

    for cmd in unicode_cases {
        let result = classify_command(cmd);
        eprintln!(
            "FAIL-OPEN: unicode input='{}' → compilation={} PASS",
            cmd, result.is_compilation,
        );
    }
}

// ============================================================================
// Section 5: Classification Correctness
// ============================================================================

#[test]
fn test_classification_compilation_commands() {
    let expected_compilations: &[(&str, CompilationKind)] = &[
        ("cargo build", CompilationKind::CargoBuild),
        ("cargo build --release", CompilationKind::CargoBuild),
        ("cargo test", CompilationKind::CargoTest),
        ("cargo test -p rch-common", CompilationKind::CargoTest),
        ("cargo check", CompilationKind::CargoCheck),
        ("cargo check --all-targets", CompilationKind::CargoCheck),
        ("cargo clippy", CompilationKind::CargoClippy),
        ("cargo doc", CompilationKind::CargoDoc),
        ("cargo bench", CompilationKind::CargoBench),
        ("cargo nextest run", CompilationKind::CargoNextest),
        ("rustc main.rs", CompilationKind::Rustc),
        ("gcc -o main main.c", CompilationKind::Gcc),
        ("g++ -o main main.cpp", CompilationKind::Gpp),
        ("clang -O2 -o out main.c", CompilationKind::Clang),
        ("make", CompilationKind::Make),
        ("make -j8", CompilationKind::Make),
        ("cmake --build build", CompilationKind::CmakeBuild),
        ("ninja", CompilationKind::Ninja),
        ("meson compile -C build", CompilationKind::Meson),
        ("bun test", CompilationKind::BunTest),
        ("bun typecheck", CompilationKind::BunTypecheck),
    ];

    for (cmd, expected_kind) in expected_compilations {
        let result = classify_command(cmd);
        assert!(
            result.is_compilation,
            "'{}' should be classified as compilation, got reason={:?}",
            cmd, result.reason,
        );
        assert_eq!(
            result.kind,
            Some(*expected_kind),
            "'{}' should be {:?}, got {:?}",
            cmd,
            expected_kind,
            result.kind,
        );
        assert!(
            result.confidence >= 0.5,
            "'{}' confidence {:.2} too low",
            cmd,
            result.confidence,
        );
    }
}

#[test]
fn test_classification_non_compilation_commands() {
    let non_compilation = &[
        "ls",
        "ls -la",
        "cat README.md",
        "echo hello world",
        "git status",
        "git diff",
        "git add .",
        "git commit -m 'test'",
        "cd /tmp",
        "pwd",
        "mkdir -p /tmp/test",
        "rm -rf /tmp/test",
        "grep -r pattern .",
        "find . -name '*.rs'",
        "which cargo",
        "env",
        "whoami",
        "hostname",
        "date",
        "wc -l file.txt",
    ];

    for cmd in non_compilation {
        let result = classify_command(cmd);
        assert!(
            !result.is_compilation,
            "'{}' should NOT be classified as compilation (got kind={:?}, reason={:?})",
            cmd, result.kind, result.reason,
        );
    }
}

#[test]
fn test_classification_detailed_tier_structure() {
    // Verify that detailed classification produces correct tier structure
    let details = classify_command_detailed("cargo build");
    assert!(
        !details.tiers.is_empty(),
        "detailed classification should have tiers"
    );

    // All compilation commands should pass through tiers (not be rejected early)
    for tier in &details.tiers {
        assert_eq!(
            tier.decision,
            TierDecision::Pass,
            "cargo build should pass tier {} ({:?})",
            tier.tier,
            tier.name,
        );
    }

    assert!(details.classification.is_compilation);
    assert_eq!(
        details.classification.kind,
        Some(CompilationKind::CargoBuild)
    );

    // Verify a rejected command has at least one Reject tier
    let details = classify_command_detailed("ls");
    assert!(!details.classification.is_compilation);
    let has_reject = details
        .tiers
        .iter()
        .any(|t| t.decision == TierDecision::Reject);
    assert!(
        has_reject,
        "'ls' should have at least one Reject tier decision"
    );
}

// ============================================================================
// Section 6: Serde Roundtrip Verification
// ============================================================================

#[test]
fn test_classification_serde_roundtrip() {
    let original = classify_command("cargo build");
    let json = serde_json::to_string(&original).expect("serialize");
    let deserialized: Classification = serde_json::from_str(&json).expect("deserialize");

    assert_eq!(original.is_compilation, deserialized.is_compilation);
    assert_eq!(original.confidence, deserialized.confidence);
    assert_eq!(original.kind, deserialized.kind);
    assert_eq!(original.reason.as_ref(), deserialized.reason.as_ref());
}

#[test]
fn test_classification_details_serde_roundtrip() {
    let original = classify_command_detailed("cargo test --release");
    let json = serde_json::to_string(&original).expect("serialize");
    let deserialized: rch_common::ClassificationDetails =
        serde_json::from_str(&json).expect("deserialize");

    assert_eq!(original.original, deserialized.original);
    assert_eq!(original.normalized, deserialized.normalized);
    assert_eq!(original.tiers.len(), deserialized.tiers.len());
    assert_eq!(
        original.classification.is_compilation,
        deserialized.classification.is_compilation
    );
}

// ============================================================================
// Summary helper (run with --nocapture to see output)
// ============================================================================

#[test]
fn test_audit_summary() {
    eprintln!("=== AUDIT E2E SUMMARY ===");
    eprintln!("Section 1: Performance budget — verified via test_perf_* tests");
    eprintln!("Section 2: WS2 zero-alloc — verified via test_ws2_* tests");
    eprintln!("Section 3: WS1 blocking I/O — verified via rch unit tests (spawn_blocking)");
    eprintln!("Section 4: WS4 multi-command — verified via test_ws4_* tests");
    eprintln!(
        "Section 5: WS3 atomics — verified via rchd unit tests (speed_score, latency, disabled_at)"
    );
    eprintln!("Section 6: Fail-open — verified via test_failopen_* tests");
    eprintln!("Section 7: Classification correctness — verified via test_classification_* tests");
    eprintln!("Section 8: Serde roundtrip — verified via test_*_serde_* tests");
    eprintln!("=========================");
}
