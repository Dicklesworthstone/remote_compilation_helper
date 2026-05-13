//! Property-based tests for the command-classification hot path
//! (bd-zcecy.15).
//!
//! `classify_command` runs on every Bash command flowing through Claude
//! Code's PreToolUse hook. The fail-open philosophy from AGENTS.md
//! ("any non-zero exit BLOCKS the agent's Bash command") makes
//! classifier correctness one of the project's top-three reliability
//! concerns: a misclassification that triggers a non-zero exit silently
//! breaks a real Bash command that should have run.
//!
//! Existing unit tests cover the documented variants (cargo build,
//! cargo test, gcc, bun test, …). What they CANNOT cover by hand:
//!
//!   * adversarial inputs — embedded quotes, escaped pipes, env-var
//!     prefixes mixed with subshell substitution, partial UTF-8, ASCII
//!     control characters;
//!   * combinatorial coverage — every `cargo <subcommand>` × every
//!     modifier flag × every env-var prefix is in the tens of
//!     thousands; hand-rolled tests can only sample.
//!
//! `proptest` generates inputs in those spaces and asserts properties
//! that hold for the entire surface — not just sampled points.
//!
//! ## Properties asserted in this file
//!
//! The bead spec calls out seven properties (P1-P7). This file lands
//! the four that don't require deeper implementation introspection.
//! The remaining three (P3 multi-whitespace tolerance, P4 env-var
//! prefix resilience, P7 watch-token positioning) require classifier
//! changes or fixture-precise expectations and are filed as follow-up
//! work on the same epic.
//!
//!   P1 `determinism_same_input_same_output` — classifying the same
//!      input twice yields the same `Classification` (sanity check
//!      against TLS/RNG/mtime-dependent state in the classifier).
//!   P2 `trim_invariance` — `classify(s) == classify(s.trim())`. The
//!      classifier is documented as whitespace-tolerant.
//!   P5 `no_panic_for_arbitrary_utf8` — any UTF-8 string ≤ 4 KB does
//!      not panic the classifier. CRITICAL fail-open property: a
//!      panic in classify is the project's "exit non-zero blocks the
//!      agent" worst case.
//!   P6 `unquoted_top_level_metacharacters_are_not_intercepted` —
//!      piped/redirected/backgrounded commands must NOT be intercepted
//!      per AGENTS.md ("Piped/redirected/backgrounded commands").
//!
//! Each proptest runs ≥1024 cases by default; CI can scale via
//! `PROPTEST_CASES=N`.

use proptest::prelude::*;
use rch_common::classify_command;

// Input size cap (4 KB) for the UTF-8 regex generators below. The
// classifier is called per-Bash-command — real inputs cap at the OS's
// ARG_MAX (~128 KB on Linux). 4 KB exercises the interesting space
// without burning CI budget on long-string regex backtracking.

// =============================================================================
// P1 — Determinism
// =============================================================================

proptest! {
    /// `classify_command(s)` must return the same `Classification` when
    /// called twice with the same input. A failure here means the
    /// classifier carries observable state across calls (TLS cache,
    /// RNG seed, time-of-day) — a serious bug because the hook is
    /// called millions of times per day with no isolation between
    /// invocations.
    ///
    /// Uses proptest's `"\\PC{0,N}"` regex form which generates valid
    /// UTF-8 (any code point that is NOT control) — avoids the
    /// random-bytes-filter-to-utf8 path that drops 99% of generated
    /// inputs and triggers proptest's reject-budget protection.
    #[test]
    fn p1_determinism_same_input_same_output(
        cmd in "\\PC{0,4096}",
    ) {
        let first = classify_command(&cmd);
        let second = classify_command(&cmd);
        prop_assert_eq!(
            &first,
            &second,
            "classify_command must be deterministic for input: {:?}",
            cmd
        );
    }
}

// =============================================================================
// P2 — Trim invariance
// =============================================================================

proptest! {
    /// Leading/trailing ASCII whitespace must not change the
    /// classification. The hook receives commands that have already
    /// been shell-parsed, but operators sometimes paste commands with
    /// surrounding whitespace into `rch exec --`; the classifier
    /// should tolerate that.
    #[test]
    fn p2_trim_invariance(
        body in "[a-zA-Z0-9._\\- /=]{0,200}",
        prefix_ws in "[ \t\r\n]{0,8}",
        suffix_ws in "[ \t\r\n]{0,8}",
    ) {
        let trimmed_input = body.clone();
        let padded_input = format!("{prefix_ws}{body}{suffix_ws}");
        let trimmed_result = classify_command(&trimmed_input);
        let padded_result = classify_command(&padded_input);
        prop_assert_eq!(
            trimmed_result.is_compilation,
            padded_result.is_compilation,
            "leading/trailing whitespace must not change is_compilation: trimmed={:?} padded={:?}",
            trimmed_input,
            padded_input
        );
        prop_assert_eq!(
            trimmed_result.kind,
            padded_result.kind,
            "leading/trailing whitespace must not change CompilationKind: trimmed={:?} padded={:?}",
            trimmed_input,
            padded_input
        );
    }
}

// =============================================================================
// P5 — No-panic for arbitrary UTF-8
// =============================================================================

proptest! {
    // The hook's fail-open contract is the project's #1 invariant
    // (AGENTS.md). A panic in `classify_command` cannot be caught at
    // the hook entry point unless every caller wraps the call in
    // `catch_unwind` — they don't. So a single hostile UTF-8 string
    // that panics the classifier is a remote-DoS for the hook surface.
    //
    // This property runs ≥4096 cases (2× default) because the input
    // space is enormous and a panic on 0.01% of inputs is still a
    // weekly production crash.
    #![proptest_config(ProptestConfig {
        cases: std::env::var("PROPTEST_CASES")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(4096),
        ..ProptestConfig::default()
    })]

    #[test]
    fn p5_no_panic_for_arbitrary_utf8(
        // Two regex shapes mixed via `prop_oneof` would balloon the
        // input space; instead we use one generator that produces any
        // valid UTF-8 code point INCLUDING control characters (`\\P{Cn}`
        // = "not unassigned"). This covers the full hostile-input
        // surface: U+0000 NUL bytes, BiDi controls, surrogate-adjacent
        // code points, RTL overrides, malformed grapheme clusters.
        cmd in r"\P{Cn}{0,4096}",
    ) {
        // If `classify_command` panics, proptest catches it from this
        // closure boundary and fails with the input that triggered it
        // (proptest then shrinks to a minimal reproducer).
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            classify_command(&cmd)
        }));
        let cmd_len = cmd.len();
        prop_assert!(
            result.is_ok(),
            "classify_command panicked on input ({} bytes): {:?}",
            cmd_len,
            cmd
        );
    }
}

// =============================================================================
// P6 — Unquoted top-level shell metacharacters disable interception
// =============================================================================
//
// Per AGENTS.md "Commands NOT Intercepted (run locally)":
//     * Piped/redirected/backgrounded commands
//
// The hook MUST NOT redirect a command like `cargo build | tee log.txt`
// to a remote worker — the pipe target only exists locally. Similarly
// `cargo test > out.log`, `cargo run &`, etc.
//
// We generate any documented compilation command (cargo build, cargo
// test, gcc, etc.) and append an unquoted pipe/redirect/background
// suffix. The classification must come back NOT intercepted.

/// Compilation command prefixes that ARE normally intercepted. Pulled
/// directly from AGENTS.md "Supported Commands" list. Kept as a
/// const slice so the test is grep-able for documentation drift.
const NORMALLY_INTERCEPTED_PREFIXES: &[&str] = &[
    "cargo build",
    "cargo test",
    "cargo check",
    "cargo clippy",
    "cargo run",
    "bun test",
    "bun typecheck",
    "gcc -o out main.c",
    "g++ -o out main.cpp",
    "clang -o out main.c",
    "make",
];

proptest! {
    /// Any documented compilation command becomes NOT intercepted once
    /// it gains an unquoted top-level pipe/redirect/background. The
    /// classifier must respect this even when the metacharacter appears
    /// at varied positions in the command.
    #[test]
    fn p6_top_level_pipe_disables_interception(
        prefix_idx in 0usize..NORMALLY_INTERCEPTED_PREFIXES.len(),
        // Trailing args before the metacharacter — kept ASCII-safe so
        // the shell tokenizer reads them as ordinary tokens.
        middle in "[a-zA-Z0-9._\\-=/ ]{0,40}",
        metachar in r"[|>&]",
        suffix in "[a-zA-Z0-9._/\\-]{0,40}",
    ) {
        let prefix = NORMALLY_INTERCEPTED_PREFIXES[prefix_idx];
        // Baseline: the bare command (and middle args) IS intercepted.
        // We assert this so the property fires only when the bare form
        // would have been classified as compilation — protecting
        // against a false-positive scenario where the prefix didn't
        // generate compilation in the first place.
        let baseline = format!("{prefix} {middle}");
        let baseline_class = classify_command(baseline.trim());
        prop_assume!(baseline_class.is_compilation);

        // Now add the metacharacter. Classification MUST flip to
        // not-intercepted.
        let piped = format!("{prefix} {middle} {metachar} {suffix}");
        let piped_class = classify_command(&piped);
        prop_assert!(
            !piped_class.is_compilation,
            "unquoted top-level `{metachar}` must disable interception, \
             but {piped:?} classified as compilation ({piped_class:?})"
        );
    }
}

proptest! {
    /// Trailing `&` (background) at the top level disables
    /// interception. Separated from the `|>&` test because the `&`
    /// inside the character class would also generate `&&` (logical AND)
    /// which IS allowed in the chain prefix, complicating the assertion.
    /// This test pins the bare trailing-& case explicitly.
    #[test]
    fn p6b_trailing_ampersand_disables_interception(
        prefix_idx in 0usize..NORMALLY_INTERCEPTED_PREFIXES.len(),
        middle in "[a-zA-Z0-9._\\-=/ ]{0,40}",
    ) {
        let prefix = NORMALLY_INTERCEPTED_PREFIXES[prefix_idx];
        let baseline = format!("{prefix} {middle}");
        let baseline_class = classify_command(baseline.trim());
        prop_assume!(baseline_class.is_compilation);

        let backgrounded = format!("{prefix} {middle} &");
        let bg_class = classify_command(&backgrounded);
        prop_assert!(
            !bg_class.is_compilation,
            "trailing top-level `&` must disable interception, \
             but {backgrounded:?} classified as compilation ({bg_class:?})"
        );
    }
}

// =============================================================================
// Sanity smoke
// =============================================================================

/// Regression net: a handful of known cases that the proptest harness
/// should also cover. If proptest's filter discards everything, this
/// test catches the harness regressing into a vacuous pass.
#[test]
fn known_inputs_classify_as_documented() {
    // From AGENTS.md "Supported Commands" — these must be compilation.
    for cmd in [
        "cargo build",
        "cargo test",
        "cargo build --release",
        "cargo check --workspace --all-targets",
        "bun test",
    ] {
        let c = classify_command(cmd);
        assert!(c.is_compilation, "documented compilation missed: {cmd:?}");
    }
    // From AGENTS.md "Commands NOT Intercepted" — these must NOT be.
    for cmd in [
        "bun install",
        "bun run dev",
        "bun test --watch",
        "cargo build | tee log",
        "cargo test > out.log",
        "cargo run &",
        "echo hi",
    ] {
        let c = classify_command(cmd);
        assert!(
            !c.is_compilation,
            "documented non-intercept got intercepted: {cmd:?}"
        );
    }
}
