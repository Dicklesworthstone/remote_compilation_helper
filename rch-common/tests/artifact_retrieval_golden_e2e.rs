//! Artifact retrieval golden + source-integrity tests
//! (bd-session-history-remediation-ocv9i.9.3).
//!
//! Proves the artifact-retrieval surface (9.1 pattern rewriting + diagnostics,
//! 9.2 cost/glob advice, plus the source-integrity guard) across the bead's
//! required cases: anchored patterns, top-level root protections, broad
//! wildcard warnings, rewritten target dir, no-artifact-found, and a
//! malicious/stale remote layout that must not overwrite local source. Each
//! case asserts the diagnostics include the searched pattern, the found files,
//! and the reason no artifact matched.

use rch_common::artifact_cost::{GlobAdvice, RetrievalMode, assess_glob_expansion};
use rch_common::artifact_pattern::{
    ArtifactRetrievalDiagnostics, artifact_dest_is_safe, rewrite_artifact_pattern,
};
use rch_common::incident::IncidentReasonCode;

// --- anchored patterns + rewritten target dir --------------------------------

#[test]
fn anchored_pattern_rewrites_to_effective_target_dir() {
    // An anchored (absolute) pattern under the original target dir is rewritten
    // to the effective (worker-scoped) one.
    let r = rewrite_artifact_pattern(
        "/proj/target/debug/app",
        "/proj/target",
        "/proj/.rch-target-worker-css",
    );
    assert!(r.rewritten);
    assert_eq!(
        r.effective_pattern,
        "/proj/.rch-target-worker-css/debug/app"
    );
}

#[test]
fn relative_anchored_pattern_rewrites() {
    let r = rewrite_artifact_pattern("target/release/lib.rlib", "target", ".rch-target");
    assert!(r.rewritten);
    assert_eq!(r.effective_pattern, ".rch-target/release/lib.rlib");
}

// --- broad wildcard warnings -------------------------------------------------

#[test]
fn broad_wildcard_warns_and_recommends_manifest() {
    let advice = assess_glob_expansion("target/**/*", 20_000);
    assert!(matches!(advice, GlobAdvice::Warn { .. }));
    assert_eq!(advice.recommended_mode(), RetrievalMode::Manifest);
}

#[test]
fn anchored_explicit_pattern_never_warns() {
    // Anchored, non-recursive patterns are deliberate — never warned even with
    // many files.
    assert_eq!(
        assess_glob_expansion("target/debug/app", 100_000),
        GlobAdvice::Proceed
    );
}

// --- no artifact found: diagnostics carry pattern + reason -------------------

#[test]
fn no_artifact_found_diagnostics_carry_searched_pattern_and_reason() {
    let r = rewrite_artifact_pattern("target/debug/app", "target", ".rch-target");
    let diag = ArtifactRetrievalDiagnostics::new(&r, vec![]);
    assert!(diag.is_miss());
    assert_eq!(diag.miss_reason(), Some(IncidentReasonCode::ArtifactMiss));
    // Diagnostics name the searched (original + effective) pattern.
    assert_eq!(diag.original_pattern, "target/debug/app");
    assert_eq!(diag.effective_pattern, ".rch-target/debug/app");
    let text = diag.render();
    assert!(text.contains("original pattern: target/debug/app"));
    assert!(text.contains("effective pattern: .rch-target/debug/app"));
    assert!(text.contains("ARTIFACT MISS"));
}

#[test]
fn found_artifacts_listed_in_diagnostics() {
    let r = rewrite_artifact_pattern("target/debug/*.rlib", "target", ".rch-target");
    let diag = ArtifactRetrievalDiagnostics::new(
        &r,
        vec![
            ".rch-target/debug/liba.rlib".to_string(),
            ".rch-target/debug/libb.rlib".to_string(),
        ],
    );
    assert!(!diag.is_miss());
    assert_eq!(diag.matched_files.len(), 2);
    let text = diag.render();
    assert!(text.contains("matched files: 2"));
    assert!(text.contains(".rch-target/debug/liba.rlib"));
}

// --- top-level root protections + source-integrity ---------------------------

#[test]
fn top_level_root_protection_refuses_escapes() {
    // Absolute and `..` destinations escape the project root -> refused.
    assert!(!artifact_dest_is_safe("/etc/passwd"));
    assert!(!artifact_dest_is_safe("../../etc/passwd"));
    assert!(!artifact_dest_is_safe("target/../../../etc"));
    assert!(!artifact_dest_is_safe(""));
}

#[test]
fn malicious_remote_layout_cannot_overwrite_local_source() {
    // A stale/malicious remote sending an artifact named like local source must
    // be refused — only artifact output roots are writable destinations.
    assert!(!artifact_dest_is_safe("src/lib.rs"));
    assert!(!artifact_dest_is_safe("Cargo.toml"));
    assert!(!artifact_dest_is_safe(".git/config"));
    // Legitimate artifact destinations are allowed.
    assert!(artifact_dest_is_safe("target/debug/app"));
    assert!(artifact_dest_is_safe(".rch-target/debug/app"));
    assert!(artifact_dest_is_safe(
        ".rch-target-worker-css/release/lib.rlib"
    ));
}

#[test]
fn rewritten_target_dir_destinations_remain_safe() {
    // After a target-dir rewrite, the effective destinations are still under an
    // artifact root and therefore safe.
    let r = rewrite_artifact_pattern("target/debug/app", "target", ".rch-target-worker-css");
    assert!(artifact_dest_is_safe(
        r.effective_pattern.trim_start_matches('/')
    ));
}
