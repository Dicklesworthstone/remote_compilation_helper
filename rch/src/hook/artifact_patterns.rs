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
        // Zig cross-builds write to target/<triple>/<profile>/, so they need the
        // triple-aware globs — the plain rust patterns would miss the binary.
        Some(CompilationKind::CargoZigbuild) => default_zigbuild_artifact_patterns(),
        Some(CompilationKind::Gcc)
        | Some(CompilationKind::Gpp)
        | Some(CompilationKind::Clang)
        | Some(CompilationKind::Clangpp)
        | Some(CompilationKind::Make)
        | Some(CompilationKind::CmakeBuild)
        | Some(CompilationKind::Ninja)
        | Some(CompilationKind::Meson) => default_c_cpp_artifact_patterns(),
        // Nix outputs live in the worker's `/nix/store` behind a `result`
        // symlink that is meaningless on a nix-less local host, so nothing is
        // synced back — the exit status is the payload (streaming only).
        Some(CompilationKind::NixBuild) => Vec::new(),
        // Go and TypeScript kinds are stream-only by construction: the classifier
        // only accepts the non-emitting forms (`go build` without `-o`, `go test`,
        // `go vet`, `tsc --noEmit`), so there is no output file to bring home and
        // the exit status is the payload. Emitting forms are declined in
        // classify_go/classify_tsc and run locally. Falling through to the
        // `_ => default_rust_artifact_patterns()` catch-all would sync back
        // `target/**` — the wrong tree entirely.
        Some(CompilationKind::GoBuild)
        | Some(CompilationKind::GoTest)
        | Some(CompilationKind::GoVet)
        | Some(CompilationKind::Tsc) => Vec::new(),
        // Jobs (`rch exec --job`) are arbitrary commands; nothing may be synced
        // back automatically — exit status is the payload in this phase. The
        // `_` rust catch-all would drag a stale worker-side `target/**` home.
        Some(CompilationKind::Job) => Vec::new(),
        _ => default_rust_artifact_patterns(),
    }
}

/// Artifact patterns for the sync-back that lands in the LOCAL project root
/// (as opposed to a forwarded custom `CARGO_TARGET_DIR`).
///
/// When a custom-target sync is active (`custom_target_sync == true`) the build's
/// `target/` outputs are retrieved *exclusively* by the custom-target phase into
/// the forwarded `CARGO_TARGET_DIR` (via [`get_custom_target_artifact_patterns`]).
/// The project-root phase must therefore NOT carry any `target/`-prefixed
/// patterns: the remote build never writes into `<remote project>/target/` under
/// a forwarded target dir, so such a pull can only re-materialize *stale*
/// worker-side `target/` residue onto the local project-root filesystem — the
/// exact filesystem a custom `CARGO_TARGET_DIR` exists to protect (rch#30). It
/// also decouples the shared `artifacts_failed` flag from a doomed stale-residue
/// pull, removing the spurious `RCH-E309` that a failed project-root `target/`
/// retrieval would otherwise raise for a build whose real outputs all arrived via
/// the custom phase.
///
/// Non-`target/` project-root artifacts are preserved — tarpaulin/junit/cobertura
/// reports, C/C++ outputs (`build/`, `bin/`, `*.o`, …), and bun coverage all still
/// land at the project root regardless of `CARGO_TARGET_DIR`. When the filtered
/// list is empty (the common cargo build/doc/rustc case, whose patterns are all
/// `target/`-prefixed) the caller skips the project-root retrieval entirely.
pub(super) fn get_project_artifact_patterns(
    kind: Option<CompilationKind>,
    custom_target_sync: bool,
) -> Vec<String> {
    let patterns = get_artifact_patterns(kind);
    if custom_target_sync {
        patterns
            .into_iter()
            .filter(|pattern| !pattern.starts_with("target/"))
            .collect()
    } else {
        patterns
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
        | Some(CompilationKind::CargoClippy)
        // Nix builds and jobs never write into a cargo target dir and return
        // no artifacts.
        | Some(CompilationKind::NixBuild)
        | Some(CompilationKind::Job) => Vec::new(),
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
        // Zig cross-build in a custom CARGO_TARGET_DIR: outputs live at
        // `<triple>/<profile>/` (one level deeper than a normal build), so both the
        // output globs and the cache excludes must be triple-aware. The standard
        // `<profile>/incremental/` excludes wouldn't catch `<triple>/release/…`, so
        // add the nested forms before the (prefix-stripped) zigbuild output globs.
        Some(CompilationKind::CargoZigbuild) => {
            let mut patterns: Vec<String> = CARGO_TARGET_CACHE_EXCLUDES
                .iter()
                .map(|s| (*s).to_string())
                .collect();
            // Triple-nested cache trees: target/<triple>/<profile>/{incremental,.fingerprint,build}/
            patterns.extend(
                [
                    "- */release/incremental/",
                    "- */release/.fingerprint/",
                    "- */release/build/",
                    "- */debug/incremental/",
                    "- */debug/.fingerprint/",
                    "- */debug/build/",
                ]
                .iter()
                .map(|s| (*s).to_string()),
            );
            patterns.extend(get_artifact_patterns(kind).into_iter().map(|pattern| {
                pattern
                    .strip_prefix("target/")
                    .unwrap_or(pattern.as_str())
                    .to_string()
            }));
            patterns
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
            // Ordinary `cargo build --target <triple>` writes outputs one level
            // deeper (`<triple>/<profile>/`), exactly like zigbuild. The output
            // globs gained their triple-aware forms (hfdt-elh1t: a release leg
            // completed remotely but synced back zero binaries), so the cache
            // excludes must gain the triple-nested forms too or the new
            // `*/<profile>/**` includes would drag the remote cache trees home.
            patterns.extend(
                [
                    "- */release/incremental/",
                    "- */release/.fingerprint/",
                    "- */release/build/",
                    "- */debug/incremental/",
                    "- */debug/.fingerprint/",
                    "- */debug/build/",
                ]
                .iter()
                .map(|s| (*s).to_string()),
            );
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
        // Zig cross-build produces a real binary under target/<triple>/ that the
        // caller needs locally, so a failed sync-back is a build failure.
        | Some(CompilationKind::CargoZigbuild)
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
        | Some(CompilationKind::BunTypecheck)
        // Nix builds stream their result; outputs stay in the worker's /nix/store.
        | Some(CompilationKind::NixBuild)
        // Jobs are arbitrary admitted commands: no artifact contract exists in
        // this phase, so a sync-back miss can never fail a job.
        | Some(CompilationKind::Job)
        // Go/TS: only non-emitting forms are ever offloaded (see classify_go /
        // classify_tsc), so there is no required local artifact.
        | Some(CompilationKind::GoBuild)
        | Some(CompilationKind::GoTest)
        | Some(CompilationKind::GoVet)
        | Some(CompilationKind::Tsc) => false,
        // Unclassified command: be conservative and treat a sync-back failure as
        // benign (we cannot prove a required artifact exists), matching the legacy
        // continue-on-warning behavior.
        None => false,
    }
}
