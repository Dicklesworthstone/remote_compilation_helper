//! Target-dir-aware artifact pattern rewriting
//! (bd-session-history-remediation-ocv9i.9.1).
//!
//! RCH rewrites `CARGO_TARGET_DIR` on the worker (to `.rch-target`, a pooled
//! root, or a worker-scoped dir) so concurrent builds don't collide. But the
//! artifact *patterns* an agent (or the classifier) specifies are written
//! against the *original* target dir — so retrieval looks in the wrong place
//! and reports a spurious "artifact miss". [`rewrite_artifact_pattern`] maps a
//! pattern from the original target dir to the effective one, and
//! [`ArtifactRetrievalDiagnostics`] records the original pattern, the effective
//! pattern, the target dir, and the matched files so the rewrite is auditable.

use serde::{Deserialize, Serialize};

use crate::incident::IncidentReasonCode;

/// The result of mapping one artifact pattern across a target-dir rewrite.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactPatternRewrite {
    /// The pattern as originally specified.
    pub original_pattern: String,
    /// The pattern after rewriting to the effective target dir.
    pub effective_pattern: String,
    /// The original `CARGO_TARGET_DIR` the pattern was written against.
    pub original_target_dir: String,
    /// The effective `CARGO_TARGET_DIR` the build actually used.
    pub effective_target_dir: String,
    /// Whether the pattern was actually rewritten (false when it did not
    /// reference the target dir, or the dirs are identical).
    pub rewritten: bool,
}

/// Rewrite `pattern` from `original_target_dir` to `effective_target_dir`.
///
/// A pattern is rewritten only when it begins with the original target dir on a
/// path-segment boundary (so `target` rewrites but `target_foo` does not). Both
/// absolute (`/proj/target/...`) and relative (`target/...`) forms are handled;
/// the caller passes matching forms. Patterns that do not reference the target
/// dir pass through unchanged.
#[must_use]
pub fn rewrite_artifact_pattern(
    pattern: &str,
    original_target_dir: &str,
    effective_target_dir: &str,
) -> ArtifactPatternRewrite {
    let unchanged = |rewritten: bool, effective: String| ArtifactPatternRewrite {
        original_pattern: pattern.to_string(),
        effective_pattern: effective,
        original_target_dir: original_target_dir.to_string(),
        effective_target_dir: effective_target_dir.to_string(),
        rewritten,
    };

    if original_target_dir.is_empty() || original_target_dir == effective_target_dir {
        return unchanged(false, pattern.to_string());
    }

    // Trim a single trailing slash so `target/` and `target` both match.
    let orig = original_target_dir
        .strip_suffix('/')
        .unwrap_or(original_target_dir);

    if let Some(rest) = pattern.strip_prefix(orig)
        && (rest.is_empty() || rest.starts_with('/'))
    {
        let eff = effective_target_dir
            .strip_suffix('/')
            .unwrap_or(effective_target_dir);
        return unchanged(true, format!("{eff}{rest}"));
    }

    unchanged(false, pattern.to_string())
}

/// Recognized artifact output roots (relative to the project). A retrieved
/// artifact must land under one of these — never over tracked source.
pub const ARTIFACT_OUTPUT_ROOTS: &[&str] = &["target", ".rch-target"];

/// Whether a retrieved artifact's RELATIVE destination is safe to write into the
/// local project. Protects against a malicious or stale remote layout
/// overwriting local source: the destination must not escape the project root
/// (no absolute path, no `..` traversal — the top-level root protection) and
/// must land under a recognized artifact output root (`target` or a
/// `.rch-target*` worker-scoped dir), never under `src/` or the project root
/// itself.
#[must_use]
pub fn artifact_dest_is_safe(rel_dest: &str) -> bool {
    if rel_dest.is_empty() || rel_dest.starts_with('/') {
        return false;
    }
    if std::path::Path::new(rel_dest)
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return false;
    }
    let first = rel_dest.split('/').next().unwrap_or("");
    // `.rch-target`, `.rch-target-worker-css`, … all start with ".rch-target".
    first == "target" || first.starts_with(".rch-target")
}

/// Auditable record of an artifact-retrieval attempt under a (possibly
/// rewritten) target dir. Printed by retrieval diagnostics and surfaced in the
/// JSON envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactRetrievalDiagnostics {
    /// Pattern as specified by the agent/classifier.
    pub original_pattern: String,
    /// Pattern actually used for retrieval (post-rewrite).
    pub effective_pattern: String,
    /// Effective remote target dir the build used.
    pub target_dir: String,
    /// Files matched by the effective pattern (relative paths).
    pub matched_files: Vec<String>,
}

impl ArtifactRetrievalDiagnostics {
    /// Build from a rewrite plus the files the effective pattern matched.
    #[must_use]
    pub fn new(rewrite: &ArtifactPatternRewrite, matched_files: Vec<String>) -> Self {
        Self {
            original_pattern: rewrite.original_pattern.clone(),
            effective_pattern: rewrite.effective_pattern.clone(),
            target_dir: rewrite.effective_target_dir.clone(),
            matched_files,
        }
    }

    /// True when no file matched — an artifact miss.
    #[must_use]
    pub fn is_miss(&self) -> bool {
        self.matched_files.is_empty()
    }

    /// Incident reason for a miss (for the incident ledger / status surfaces).
    #[must_use]
    pub fn miss_reason(&self) -> Option<IncidentReasonCode> {
        self.is_miss().then_some(IncidentReasonCode::ArtifactMiss)
    }

    /// Human-readable one-block diagnostic (the bead's required output: original
    /// pattern, effective pattern, target dir, matched files).
    #[must_use]
    pub fn render(&self) -> String {
        let mut s = format!(
            "artifact retrieval:\n  original pattern: {}\n  effective pattern: {}\n  target dir: {}\n  matched files: {}",
            self.original_pattern,
            self.effective_pattern,
            self.target_dir,
            self.matched_files.len(),
        );
        for f in &self.matched_files {
            s.push_str("\n    - ");
            s.push_str(f);
        }
        if self.is_miss() {
            s.push_str("\n  -> ARTIFACT MISS (no files matched under the rewritten target dir)");
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relative_target_pattern_is_rewritten() {
        let r = rewrite_artifact_pattern("target/debug/libfoo.rlib", "target", ".rch-target");
        assert!(r.rewritten);
        assert_eq!(r.effective_pattern, ".rch-target/debug/libfoo.rlib");
    }

    #[test]
    fn absolute_target_pattern_is_rewritten() {
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
    fn trailing_slashes_are_tolerated() {
        let r = rewrite_artifact_pattern("target/x", "target/", ".rch-target/");
        assert_eq!(r.effective_pattern, ".rch-target/x");
        // The bare target dir itself also rewrites.
        let bare = rewrite_artifact_pattern("target", "target", ".rch-target");
        assert_eq!(bare.effective_pattern, ".rch-target");
        assert!(bare.rewritten);
    }

    #[test]
    fn segment_boundary_prevents_false_prefix_match() {
        // "target_archive" must NOT be rewritten by an orig of "target".
        let r = rewrite_artifact_pattern("target_archive/x", "target", ".rch-target");
        assert!(!r.rewritten);
        assert_eq!(r.effective_pattern, "target_archive/x");
    }

    #[test]
    fn non_target_pattern_passes_through() {
        let r = rewrite_artifact_pattern("dist/bundle.js", "target", ".rch-target");
        assert!(!r.rewritten);
        assert_eq!(r.effective_pattern, "dist/bundle.js");
    }

    #[test]
    fn identical_dirs_are_a_noop() {
        let r = rewrite_artifact_pattern("target/debug/x", "target", "target");
        assert!(!r.rewritten);
        assert_eq!(r.effective_pattern, "target/debug/x");
    }

    #[test]
    fn empty_original_is_a_noop() {
        let r = rewrite_artifact_pattern("target/x", "", ".rch-target");
        assert!(!r.rewritten);
    }

    #[test]
    fn diagnostics_record_match_and_render() {
        let r = rewrite_artifact_pattern("target/debug/app", "target", ".rch-target");
        let d = ArtifactRetrievalDiagnostics::new(&r, vec![".rch-target/debug/app".to_string()]);
        assert!(!d.is_miss());
        assert_eq!(d.miss_reason(), None);
        assert_eq!(d.effective_pattern, ".rch-target/debug/app");
        assert_eq!(d.target_dir, ".rch-target");
        let text = d.render();
        assert!(text.contains("original pattern: target/debug/app"));
        assert!(text.contains("effective pattern: .rch-target/debug/app"));
        assert!(text.contains(".rch-target/debug/app"));
    }

    #[test]
    fn diagnostics_flag_artifact_miss() {
        // The classic failure: build succeeded only under the rewritten target
        // dir, but retrieval used the original pattern and matched nothing.
        let r = rewrite_artifact_pattern("target/debug/app", "target", ".rch-target");
        let d = ArtifactRetrievalDiagnostics::new(&r, vec![]);
        assert!(d.is_miss());
        assert_eq!(d.miss_reason(), Some(IncidentReasonCode::ArtifactMiss));
        assert!(d.render().contains("ARTIFACT MISS"));
    }

    #[test]
    fn diagnostics_serde_roundtrip() {
        let r = rewrite_artifact_pattern("target/x", "target", ".rch-target");
        let d = ArtifactRetrievalDiagnostics::new(&r, vec![".rch-target/x".to_string()]);
        let back: ArtifactRetrievalDiagnostics =
            serde_json::from_str(&serde_json::to_string(&d).unwrap()).unwrap();
        assert_eq!(d, back);
    }
}
