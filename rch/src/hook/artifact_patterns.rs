//! Remote artifact-pattern selection for the hook.
//!
//! This submodule owns the policy that decides *which* files travel back from a
//! worker after a remote build, extracted from `hook.rs` per bead
//! `remote_compilation_helper-zcecy.14`:
//!
//! - [`get_artifact_patterns`] maps a [`CompilationKind`] to the rsync
//!   include-pattern list for the default project-root sync-back (full `target/`
//!   outputs for builds, a narrow allowlist for test/diagnostic kinds).
//! - [`get_custom_target_artifact_patterns`] is the variant used when the build
//!   wrote into a custom `CARGO_TARGET_DIR` (the sync root IS the remote target
//!   dir): it rebases the same output globs onto the target-dir root and prefixes
//!   the [`CARGO_TARGET_CACHE_EXCLUDES`] rules so cargo's per-job cache trees
//!   (`incremental/`, `.fingerprint/`, `build/`, `*.d`) never transfer.
//! - [`kind_produces_transferable_artifacts`] classifies whether a kind produces a
//!   *required* local artifact, so the transfer pipeline can treat a failed
//!   artifact sync-back as a build failure (vs. a benign warning for streaming
//!   test/diagnostic kinds).
//!
//! It reaches its support layer from the parent via `use super::*`: the
//! `CompilationKind` enum and the `default_*_artifact_patterns` builders (which
//! live in `crate::transfer` and are imported into `hook`). The three classifier
//! fns are `pub(super)` — consumed by the sibling `transfer_orchestration`
//! (`execute_remote_compilation`) which imports them directly, and by the hook
//! test suite which imports them into `hook::tests`. `CARGO_TARGET_CACHE_EXCLUDES`
//! is used only within this module and stays private.

use super::*;

/// Get artifact patterns based on compilation kind.
///
/// Test and diagnostic commands use minimal patterns since their output is
/// streamed and the full target/ directory is not needed. This significantly
/// reduces artifact transfer time for commands that do not produce runnable
/// build artifacts.
pub(super) fn get_artifact_patterns(kind: Option<CompilationKind>) -> Vec<String> {
    match kind {
        Some(CompilationKind::BunTest) | Some(CompilationKind::BunTypecheck) => {
            default_bun_artifact_patterns()
        }
        // Test, bench, and diagnostic commands do not need full target/.
        Some(CompilationKind::CargoTest)
        | Some(CompilationKind::CargoNextest)
        | Some(CompilationKind::CargoBench)
        | Some(CompilationKind::CargoCheck)
        | Some(CompilationKind::CargoClippy) => default_rust_test_artifact_patterns(),
        Some(CompilationKind::Rustc)
        | Some(CompilationKind::CargoBuild)
        | Some(CompilationKind::CargoDoc) => default_rust_artifact_patterns(),
        Some(CompilationKind::Gcc)
        | Some(CompilationKind::Gpp)
        | Some(CompilationKind::Clang)
        | Some(CompilationKind::Clangpp)
        | Some(CompilationKind::Make)
        | Some(CompilationKind::CmakeBuild)
        | Some(CompilationKind::Ninja)
        | Some(CompilationKind::Meson) => default_c_cpp_artifact_patterns(),
        _ => default_rust_artifact_patterns(),
    }
}

/// Rsync filter entries that, prefixed onto an artifact pattern list, are emitted
/// as `--exclude` rules BEFORE the `--include` rules (rsync first-match-wins). They
/// strip cargo's per-job *cache* state out of a custom-`CARGO_TARGET_DIR` sync-back
/// so only build OUTPUTS travel — the multi-hundred-MB-to-GB `incremental/`,
/// `.fingerprint/`, `build/`, and `*.d` trees stay on the worker (they are
/// regenerated locally on demand and are useless without the matching remote
/// fingerprints anyway). The profile dirs are enumerated explicitly rather than
/// globbed so a source-tree `build/` (legitimate C/C++ artifact root) is never
/// caught — these only ever match the cargo `target/<profile>/` layout.
const CARGO_TARGET_CACHE_EXCLUDES: &[&str] = &[
    "- debug/incremental/",
    "- debug/.fingerprint/",
    "- debug/build/",
    "- release/incremental/",
    "- release/.fingerprint/",
    "- release/build/",
    "- */incremental/",
    "- */.fingerprint/",
    "- */build/",
    "- *.d",
];

pub(super) fn get_custom_target_artifact_patterns(kind: Option<CompilationKind>) -> Vec<String> {
    match kind {
        Some(CompilationKind::CargoTest)
        | Some(CompilationKind::CargoCheck)
        | Some(CompilationKind::CargoClippy) => Vec::new(),
        Some(CompilationKind::CargoNextest) | Some(CompilationKind::CargoBench) => {
            // Test/bench artifacts are already a narrow allowlist; just rebase them
            // onto the target-dir root (the sync root IS the remote target dir).
            get_artifact_patterns(kind)
                .into_iter()
                .map(|pattern| {
                    pattern
                        .strip_prefix("target/")
                        .unwrap_or(pattern.as_str())
                        .to_string()
                })
                .collect()
        }
        // CargoBuild / CargoDoc / Rustc (the `_` arm) previously synced the WHOLE
        // per-job remote target dir via `**`, dragging deps/, incremental/,
        // .fingerprint/, and build/ back on every build. Capture only the build
        // OUTPUTS — final binaries/libs under `<profile>/` and the crate's own
        // compiled artifacts in `<profile>/deps` (rlibs, the linked binary, etc.) —
        // plus doc output, while excluding the cache trees. Reuses the same
        // well-tested output globs as `get_artifact_patterns` (with the `target/`
        // prefix stripped because the sync root is already the target dir). The
        // exclude rules are emitted first so rsync never pulls cache bytes.
        _ => {
            let mut patterns: Vec<String> = CARGO_TARGET_CACHE_EXCLUDES
                .iter()
                .map(|s| (*s).to_string())
                .collect();
            patterns.extend(get_artifact_patterns(kind).into_iter().map(|pattern| {
                pattern
                    .strip_prefix("target/")
                    .unwrap_or(pattern.as_str())
                    .to_string()
            }));
            patterns
        }
    }
}

/// Whether a compilation kind produces build artifacts that must be transferred
/// back for the local build to be complete (binaries, libraries, docs, object
/// files). For these kinds, a failed artifact sync-back is a build failure
/// (issue #19 Fix 1), not a benign warning. Test/diagnostic kinds
/// (`cargo test`/`check`/`clippy`) stream their results over stdout/stderr and
/// produce no required local artifact, so a sync-back miss for them is tolerable.
///
/// Mirrors the artifact-producing set used by `get_custom_target_artifact_patterns`
/// / `get_artifact_patterns`: build/doc/rustc and the C/C++/build-system kinds.
pub(super) fn kind_produces_transferable_artifacts(kind: Option<CompilationKind>) -> bool {
    match kind {
        Some(CompilationKind::CargoBuild)
        | Some(CompilationKind::CargoDoc)
        | Some(CompilationKind::Rustc)
        | Some(CompilationKind::Gcc)
        | Some(CompilationKind::Gpp)
        | Some(CompilationKind::Clang)
        | Some(CompilationKind::Clangpp)
        | Some(CompilationKind::Make)
        | Some(CompilationKind::CmakeBuild)
        | Some(CompilationKind::Ninja)
        | Some(CompilationKind::Meson) => true,
        // Test/diagnostic kinds stream results; no required local artifact.
        Some(CompilationKind::CargoTest)
        | Some(CompilationKind::CargoNextest)
        | Some(CompilationKind::CargoBench)
        | Some(CompilationKind::CargoCheck)
        | Some(CompilationKind::CargoClippy)
        | Some(CompilationKind::BunTest)
        | Some(CompilationKind::BunTypecheck) => false,
        // Unclassified command: be conservative and treat a sync-back failure as
        // benign (we cannot prove a required artifact exists), matching the legacy
        // continue-on-warning behavior.
        None => false,
    }
}
