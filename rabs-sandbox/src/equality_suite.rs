//! Cross-worktree descriptor/output equality suite (bead D011; plan
//! §55/§57) — the M1 acceptance harness.
//!
//! D019 proved the COMMAND side converges (child rustc argv, `-C
//! metadata`, unit-hash filenames). This suite closes the loop on the
//! ARTIFACT side: two worktrees of the same source running the same
//! canonical command must produce equal `.rmeta` bytes, equal dep-info,
//! and equal binaries/rlibs — and any inequality is not a bare "false"
//! but a CLASSIFIED finding naming the artifact class and both sides,
//! feeding the same leak taxonomy the D012 scanner reports into.
//!
//! Dep-info gets a light normalization before comparison: byte order of
//! rules is directory-enumeration order, which is not semantic, so
//! lines are sorted. Paths inside are NOT rewritten — under the
//! canonical namespace they are already `/__rabs/...` on every host,
//! and rewriting would hide exactly the divergence this suite exists to
//! catch.

use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Artifact class, for classified findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactClass {
    /// `.rmeta` crate metadata.
    Rmeta,
    /// `.rlib` archives.
    Rlib,
    /// dep-info `.d` files (compared normalized).
    DepInfo,
    /// Executable / other binary output.
    Binary,
}

/// One collected artifact: class + content identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectedArtifact {
    /// Artifact class.
    pub class: ArtifactClass,
    /// SHA-256 of the (normalized, for dep-info) content.
    pub content_sha256: [u8; 32],
}

/// Everything one worktree run produced, keyed by file name.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RunArtifacts {
    /// File name → collected artifact.
    pub artifacts: BTreeMap<String, CollectedArtifact>,
}

/// One classified equality finding. Empty vector = M1-equal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EqualityFinding {
    /// The artifact NAME SETS differ (unit-hash divergence upstream).
    ArtifactSetMismatch {
        /// Names present only in run A.
        only_a: Vec<String>,
        /// Names present only in run B.
        only_b: Vec<String>,
    },
    /// Same name, different bytes — classified by artifact class.
    ContentMismatch {
        /// The affected file name.
        name: String,
        /// The artifact class (leak-taxonomy handle).
        class: ArtifactClass,
        /// Run A content digest.
        a_sha256: [u8; 32],
        /// Run B content digest.
        b_sha256: [u8; 32],
    },
    /// Same name, different class (a `.d` became a binary, …).
    ClassMismatch {
        /// The affected file name.
        name: String,
    },
}

/// Classify a file name into an artifact class (None = not collected:
/// incremental workdirs, fingerprint droppings, lockfiles).
#[must_use]
pub fn classify_artifact(name: &str) -> Option<ArtifactClass> {
    if name.ends_with(".rmeta") {
        Some(ArtifactClass::Rmeta)
    } else if name.ends_with(".rlib") {
        Some(ArtifactClass::Rlib)
    } else if name.ends_with(".d") {
        Some(ArtifactClass::DepInfo)
    } else if name.ends_with(".lock") || name.starts_with('.') {
        None
    } else {
        Some(ArtifactClass::Binary)
    }
}

/// Normalize dep-info content: sort lines (rule order tracks directory
/// enumeration, not semantics). Paths are left VERBATIM — canonical
/// namespaces make them equal; anything else must surface.
#[must_use]
pub fn normalize_dep_info(content: &[u8]) -> Vec<u8> {
    let text = String::from_utf8_lossy(content);
    let mut lines: Vec<&str> = text.lines().collect();
    lines.sort_unstable();
    let mut out = lines.join("\n").into_bytes();
    out.push(b'\n');
    out
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

/// Collect one run's artifacts from its `deps` directory on disk.
pub fn collect_run_artifacts(deps_dir: &std::path::Path) -> std::io::Result<RunArtifacts> {
    let mut run = RunArtifacts::default();
    for entry in std::fs::read_dir(deps_dir)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some(class) = classify_artifact(&name) else {
            continue;
        };
        let raw = std::fs::read(entry.path())?;
        let content = if class == ArtifactClass::DepInfo {
            normalize_dep_info(&raw)
        } else {
            raw
        };
        run.artifacts.insert(
            name,
            CollectedArtifact {
                class,
                content_sha256: sha256(&content),
            },
        );
    }
    Ok(run)
}

/// Compare two runs; every inequality is a classified finding.
#[must_use]
pub fn compare_runs(a: &RunArtifacts, b: &RunArtifacts) -> Vec<EqualityFinding> {
    let mut findings = Vec::new();
    let only_a: Vec<String> = a
        .artifacts
        .keys()
        .filter(|k| !b.artifacts.contains_key(*k))
        .cloned()
        .collect();
    let only_b: Vec<String> = b
        .artifacts
        .keys()
        .filter(|k| !a.artifacts.contains_key(*k))
        .cloned()
        .collect();
    if !only_a.is_empty() || !only_b.is_empty() {
        findings.push(EqualityFinding::ArtifactSetMismatch { only_a, only_b });
    }
    for (name, artifact_a) in &a.artifacts {
        let Some(artifact_b) = b.artifacts.get(name) else {
            continue;
        };
        if artifact_a.class != artifact_b.class {
            findings.push(EqualityFinding::ClassMismatch { name: name.clone() });
            continue;
        }
        if artifact_a.content_sha256 != artifact_b.content_sha256 {
            findings.push(EqualityFinding::ContentMismatch {
                name: name.clone(),
                class: artifact_a.class,
                a_sha256: artifact_a.content_sha256,
                b_sha256: artifact_b.content_sha256,
            });
        }
    }
    findings
}

/// Coverage guard: the comparison is meaningful only if every named
/// class was actually present — an accidentally-empty deps dir must
/// fail the SUITE, not pass it vacuously.
#[must_use]
pub fn classes_covered(run: &RunArtifacts, required: &[ArtifactClass]) -> bool {
    required
        .iter()
        .all(|class| run.artifacts.values().any(|a| a.class == *class))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn artifact(class: ArtifactClass, content: &[u8]) -> CollectedArtifact {
        CollectedArtifact {
            class,
            content_sha256: sha256(content),
        }
    }

    fn run(entries: &[(&str, ArtifactClass, &[u8])]) -> RunArtifacts {
        let mut r = RunArtifacts::default();
        for (name, class, content) in entries {
            r.artifacts
                .insert((*name).to_string(), artifact(*class, content));
        }
        r
    }

    #[test]
    fn equal_runs_produce_zero_findings() {
        let a = run(&[
            ("libfx-abc.rmeta", ArtifactClass::Rmeta, b"meta"),
            ("libfx-abc.rlib", ArtifactClass::Rlib, b"lib"),
            ("fx-abc.d", ArtifactClass::DepInfo, b"dep"),
            ("fx-abc", ArtifactClass::Binary, b"bin"),
        ]);
        assert_eq!(compare_runs(&a, &a.clone()), Vec::new());
        assert!(classes_covered(
            &a,
            &[
                ArtifactClass::Rmeta,
                ArtifactClass::Rlib,
                ArtifactClass::DepInfo,
                ArtifactClass::Binary
            ]
        ));
    }

    #[test]
    fn every_divergence_is_a_classified_finding() {
        let a = run(&[
            ("libfx-abc.rmeta", ArtifactClass::Rmeta, b"meta-A"),
            ("fx-abc", ArtifactClass::Binary, b"bin"),
        ]);
        // Different rmeta bytes → ContentMismatch classified Rmeta.
        let b = run(&[
            ("libfx-abc.rmeta", ArtifactClass::Rmeta, b"meta-B"),
            ("fx-abc", ArtifactClass::Binary, b"bin"),
        ]);
        assert!(matches!(
            compare_runs(&a, &b)[0],
            EqualityFinding::ContentMismatch {
                class: ArtifactClass::Rmeta,
                ..
            }
        ));
        // Different unit-hash name set → ArtifactSetMismatch.
        let c = run(&[
            ("libfx-fff.rmeta", ArtifactClass::Rmeta, b"meta-A"),
            ("fx-abc", ArtifactClass::Binary, b"bin"),
        ]);
        assert!(matches!(
            compare_runs(&a, &c)[0],
            EqualityFinding::ArtifactSetMismatch { .. }
        ));
    }

    #[test]
    fn dep_info_rule_order_is_not_semantic_but_paths_are() {
        let a = normalize_dep_info(b"out: /__rabs/workspace/a.rs\nout2: /__rabs/workspace/b.rs\n");
        let b = normalize_dep_info(b"out2: /__rabs/workspace/b.rs\nout: /__rabs/workspace/a.rs\n");
        assert_eq!(a, b, "rule order normalizes away");
        let c = normalize_dep_info(b"out: /host/worktree-1/a.rs\nout2: /__rabs/workspace/b.rs\n");
        assert_ne!(a, c, "a host path in dep-info must NOT normalize away");
    }

    #[test]
    fn droppings_are_not_collected_and_coverage_guard_catches_gaps() {
        assert_eq!(classify_artifact(".cargo-lock"), None);
        assert_eq!(classify_artifact("x.lock"), None);
        assert_eq!(classify_artifact("libfx.rmeta"), Some(ArtifactClass::Rmeta));
        let empty = RunArtifacts::default();
        assert!(!classes_covered(&empty, &[ArtifactClass::Rmeta]));
    }

    #[test]
    fn real_deps_dir_collection_hashes_and_classifies() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("libfx-abc.rmeta"), b"meta").unwrap();
        std::fs::write(dir.path().join("fx-abc.d"), b"z: b\na: c\n").unwrap();
        std::fs::write(dir.path().join("fx-abc"), b"binary").unwrap();
        std::fs::write(dir.path().join(".cargo-lock"), b"").unwrap();
        let collected = collect_run_artifacts(dir.path()).unwrap();
        assert_eq!(collected.artifacts.len(), 3, "the lock dropping is skipped");
        assert_eq!(
            collected.artifacts["fx-abc.d"].content_sha256,
            sha256(b"a: c\nz: b\n"),
            "dep-info hashed post-normalization"
        );
    }
}
