//! Remote artifact-pattern selection for the hook.
//!
//! This submodule owns the policy that decides *which* files travel back from a
//! worker after a remote build, extracted from `hook.rs` per bead
//! `remote_compilation_helper-zcecy.14`:
//!
//! - [`get_artifact_patterns`] maps a [`CompilationKind`] (plus the command
//!   string, for its `--profile` selection) to the rsync include-pattern list
//!   for the default project-root sync-back (full `target/` outputs for
//!   builds, a narrow allowlist for test/diagnostic kinds).
//! - [`get_custom_target_artifact_patterns`] is the variant used when the build
//!   wrote into a custom `CARGO_TARGET_DIR` (the sync root IS the remote target
//!   dir): it rebases the same output globs onto the target-dir root and prefixes
//!   the [`CARGO_TARGET_CACHE_EXCLUDES`] rules so cargo's per-job cache trees
//!   (`incremental/`, `.fingerprint/`, `build/`, `*.d`) never transfer.
//! - [`kind_produces_transferable_artifacts`] classifies whether a kind produces a
//!   *required* local artifact, so the transfer pipeline can treat a failed
//!   artifact sync-back as a build failure (vs. a benign warning for streaming
//!   test/diagnostic kinds).
//! - [`sync_back_verified_zero_build_outputs`] is the bd-mpbav loud-failure
//!   gate: it classifies the per-file manifest of a SUCCESSFUL sync-back to
//!   detect the case where rsync matched only non-output files (loose target
//!   metadata, cache trees) and zero real build outputs — the signature of a
//!   silent stale-local-binary hazard (see also the RCH-E326 failure arm in
//!   `transfer_orchestration`).
//!
//! It reaches its support layer from the parent via `use super::*`: the
//! `CompilationKind` enum and the `default_*_artifact_patterns` builders (which
//! live in `crate::transfer` and are imported into `hook`), plus the cargo
//! profile analyzer [`cargo_custom_profile_output_dir`] from the sibling
//! `command_parsing` submodule. The classifier fns are `pub(super)` — consumed
//! by the sibling `transfer_orchestration` (`execute_remote_compilation`)
//! which imports them directly, and by the hook test suite which imports them
//! into `hook::tests`. `CARGO_TARGET_CACHE_EXCLUDES` is used only within this
//! module and stays private.

use super::command_parsing::cargo_custom_profile_output_dir;
use super::*;

/// Get artifact patterns based on compilation kind.
///
/// Test and diagnostic commands use minimal patterns since their output is
/// streamed and the full target/ directory is not needed. This significantly
/// reduces artifact transfer time for commands that do not produce runnable
/// build artifacts.
///
/// `command` (the exact command string being offloaded) selects cargo
/// profile-aware output globs: a custom `--profile <name>` writes to
/// `target/<name>/` — a directory none of the built-in `debug`/`release` globs
/// cover — so the matching `target/<name>/**` and `target/*/<name>/**` (the
/// second form covers `--target <triple>` builds, which write one level
/// deeper) are appended for the rust-artifact kinds (bd-mpbav). Built-in
/// profiles (`dev`/`test` → `debug`, `release`/`bench` → `release`) and a bare
/// `--release`/`-r` need no new globs, so nothing is appended for them.
pub(super) fn get_artifact_patterns(
    kind: Option<CompilationKind>,
    command: Option<&str>,
) -> Vec<String> {
    let mut patterns = match kind {
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
    };
    // Custom cargo profile outputs (bd-mpbav): `cargo build --profile P` with P
    // not built-in writes to target/P/, which the plain debug/release globs
    // miss entirely — the sync-back would return only loose target metadata
    // while the real binary stayed on the worker, leaving the local artifact
    // silently STALE. Append the profile's own globs for exactly the kinds
    // whose patterns are the cargo target/-rooted rust outputs.
    if rust_kind_targets_cargo_output_tree(kind)
        && let Some(profile_dir) = command.and_then(cargo_custom_profile_output_dir)
    {
        patterns.push(format!("target/{profile_dir}/**"));
        // `cargo build --target <triple> --profile P` writes one level deeper:
        // target/<triple>/P/ (mirrors the triple-aware forms the default and
        // zigbuild builders already carry for debug/release).
        patterns.push(format!("target/*/{profile_dir}/**"));
    }
    patterns
}

/// Whether this kind's artifact patterns are the cargo `target/`-rooted rust
/// output globs — i.e. the kinds for which a custom `--profile` changes the
/// output directory. This covers the explicit build/doc/rustc/zigbuild arms
/// AND the unclassified (`None`) rust catch-all; test/diagnostic kinds use the
/// narrow streaming allowlist (no full target/ sync, so no profile globs), and
/// non-rust kinds never write into a cargo target dir.
fn rust_kind_targets_cargo_output_tree(kind: Option<CompilationKind>) -> bool {
    matches!(
        kind,
        Some(
            CompilationKind::CargoBuild
                | CompilationKind::CargoDoc
                | CompilationKind::CargoZigbuild
                | CompilationKind::Rustc
        ) | None
    )
}
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
    command: Option<&str>,
    custom_target_sync: bool,
) -> Vec<String> {
    let patterns = get_artifact_patterns(kind, command);
    if custom_target_sync {
        patterns
            .into_iter()
            .filter(|pattern| !pattern.starts_with("target/"))
            .collect()
    } else {
        patterns
    }
}

/// The include globs of one phase's pattern list, shaped for the RCH-E326
/// failure message (bd-mpbav): `- ` exclude rules and the two loose
/// target-root metadata files are dropped so the message names only real
/// output locations the sync-back was expected to match.
pub(super) fn expected_output_glob_list(patterns: &[String]) -> Vec<String> {
    patterns
        .iter()
        .filter(|p| {
            !p.starts_with("- ")
                && !matches!(
                    p.as_str(),
                    ".rustc_info.json"
                        | "CACHEDIR.TAG"
                        | "target/.rustc_info.json"
                        | "target/CACHEDIR.TAG"
                )
        })
        .cloned()
        .collect()
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

/// Cache-exclude entries for one custom cargo profile output dir, rebased onto
/// the custom-target sync root (`<dir>` is the profile's output-directory name,
/// e.g. `release-perf`). Mirrors [`CARGO_TARGET_CACHE_EXCLUDES`]'s per-profile
/// entries, in both the plain (`<profile>/incremental/`) and the triple-nested
/// (`*/<profile>/incremental/`) forms, so a custom-profile include can never
/// drag its per-job cache trees home (bd-mpbav).
fn custom_profile_cache_excludes(profile_dir: &str) -> Vec<String> {
    [
        format!("- {profile_dir}/incremental/"),
        format!("- {profile_dir}/.fingerprint/"),
        format!("- {profile_dir}/build/"),
        format!("- */{profile_dir}/incremental/"),
        format!("- */{profile_dir}/.fingerprint/"),
        format!("- */{profile_dir}/build/"),
    ]
    .to_vec()
}

pub(super) fn get_custom_target_artifact_patterns(
    kind: Option<CompilationKind>,
    command: Option<&str>,
) -> Vec<String> {
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
            get_artifact_patterns(kind, command)
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
            // A custom profile under zigbuild writes to <triple>/<profile>/:
            // its cache trees need the same triple-aware excludes.
            if let Some(profile_dir) = command.and_then(cargo_custom_profile_output_dir) {
                patterns.extend(custom_profile_cache_excludes(&profile_dir));
            }
            patterns.extend(get_artifact_patterns(kind, command).into_iter().map(|pattern| {
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
            // Custom-profile builds (bd-mpbav) write to `<profile>/` (or
            // `<triple>/<profile>/`), so their cache trees need the same
            // treatment as debug/release above — emitted BEFORE the profile's
            // output includes.
            if let Some(profile_dir) = command.and_then(cargo_custom_profile_output_dir) {
                patterns.extend(custom_profile_cache_excludes(&profile_dir));
            }
            patterns.extend(get_artifact_patterns(kind, command).into_iter().map(|pattern| {
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

/// Whether a single file from a sync-back manifest represents a build OUTPUT
/// (a final binary, library, or doc file the local build needs), as opposed to
/// cargo's loose target-root metadata or per-job cache state.
///
/// The manifest paths are relative to the sync root: the remote project root
/// for the default-root phase (paths `target/…`) or the remote target dir
/// itself for a custom-`CARGO_TARGET_DIR` phase (`custom_target_sync = true`,
/// paths already below `target/`).
///
/// Policy (bd-mpbav), mirroring the include/exclude set the phases emit:
/// - The two loose target-root files the include list names explicitly —
///   `.rustc_info.json` and `CACHEDIR.TAG` — are metadata, not outputs: a
///   path with no directory component below the sync root is never an output.
///   (This is exactly the zero-output signature observed in the wild: "4
///   files, 660 bytes" of metadata while the real binary stayed on the worker.)
/// - Cargo per-job cache trees — any path through `incremental/`,
///   `.fingerprint/`, or `build/` — are not outputs (they mirror
///   [`CARGO_TARGET_CACHE_EXCLUDES`]; the default-root phase has no such
///   excludes, so they can appear in its manifest and must not masquerade as
///   outputs).
/// - Dependency `.d` files are not outputs (they mirror the `- *.d` exclude).
/// - Everything else under a subdirectory of the sync root is an output: a
///   successful `cargo build`/`doc`/`zigbuild` always materializes at least
///   one file under `<profile>/` (or `<triple>/<profile>/`, or `doc/`).
fn retrieved_path_is_build_output(path: &str, custom_target_sync: bool) -> bool {
    let rel = if custom_target_sync {
        path
    } else {
        path.strip_prefix("target/").unwrap_or(path)
    };
    let components: Vec<&str> = rel.split('/').filter(|c| !c.is_empty()).collect();
    // Root-level files (".rustc_info.json", "CACHEDIR.TAG") are metadata.
    if components.len() < 2 {
        return false;
    }
    // Cargo per-job cache trees never count as outputs.
    if components
        .iter()
        .any(|c| matches!(*c, "incremental" | ".fingerprint" | "build"))
    {
        return false;
    }
    // Dependency files mirror the `- *.d` exclude: cache, not output.
    !rel.ends_with(".d")
}

/// Whether a kind has an ENUMERABLE build-output contract: a successful
/// remote build of this kind provably materializes files at known locations
/// under the cargo target tree, so a sync-back that matched zero outputs is
/// provably a stale-local-artifact hazard, not a legitimate no-output run.
///
/// This is deliberately narrower than [`kind_produces_transferable_artifacts`]:
/// the zero-output LOUD FAILURE (RCH-E326) applies only where the contract is
/// enumerable. Direct `rustc` invocations write next to the source (or to
/// `-o`), not into `target/<profile>/`, and the C/C++/build-system kinds admit
/// compiler forms that legitimately produce no output file (e.g.
/// `gcc -fsyntax-only`, or a `make` target that only prints) — failing those
/// on a zero-output sync would break real builds. For those kinds a
/// zero-output sync-back keeps the legacy warn-only treatment.
pub(super) fn kind_has_enumerable_output_contract(kind: Option<CompilationKind>) -> bool {
    matches!(
        kind,
        Some(
            CompilationKind::CargoBuild
                | CompilationKind::CargoDoc
                | CompilationKind::CargoZigbuild
        )
    )
}

/// The bd-mpbav loud-failure gate: did a sync-back that SUCCEEDED (rsync exit
/// 0) nonetheless match ZERO build outputs for a kind whose output contract is
/// enumerable? Such a result means the artifacts the caller expects were never
/// in rsync's file list — typically because the output directory (e.g. a
/// custom cargo profile's `target/<profile>/`) is not covered by the include
/// patterns — so the LOCAL artifacts may be silently STALE even though the
/// remote build "succeeded". The caller must fail the build loudly
/// (RCH-E326) instead of surfacing the remote's exit 0.
///
/// Inputs:
/// - `manifest`: every REGULAR FILE rsync had in its matched file list — both
///   transferred items (`>f…`) and verified-up-to-date items (`.f`), parsed
///   from the retrieval's `--out-format='%i %n'` + `--info=name2` output.
///   Including up-to-date items is what keeps an already-current no-op
///   rebuild (nothing to transfer, everything current) from being misread as
///   a failure.
/// - `matched_regular_files`: the regular-file count from rsync's `--stats`
///   "Number of files: N (reg: R, dir: D)" line, when parseable.
///
/// Firing requires POSITIVE knowledge, mirroring the repo's fail-open
/// philosophy — each guard below declines to fire when the evidence is
/// incomplete rather than risking a false build failure:
/// - kind must have an enumerable output contract (see
///   [`kind_has_enumerable_output_contract`]);
/// - `matched_regular_files` must be known AND nonzero — an rsync that matched
///   literally nothing is reported as a warning only (the classifier admits
///   no-output invocations like `cargo build --help`), and an unparseable
///   count proves nothing;
/// - the manifest must ACCOUNT FOR every matched regular file
///   (`manifest.len() >= matched_regular_files`) — if the parser saw fewer
///   files than rsync matched (e.g. a worker rsync that does not itemize
///   up-to-date files), outputs may exist unlisted and the gate must not
///   fire;
/// - and no manifest path may classify as a build output (see
///   [`retrieved_path_is_build_output`]).
pub(super) fn sync_back_verified_zero_build_outputs(
    manifest: &[String],
    matched_regular_files: Option<u32>,
    kind: Option<CompilationKind>,
    custom_target_sync: bool,
) -> bool {
    if !kind_has_enumerable_output_contract(kind) {
        return false;
    }
    // Both counters must be known before zero-outputs can be PROVEN.
    let Some(matched) = matched_regular_files else {
        return false;
    };
    if matched == 0 {
        return false;
    }
    if manifest.len() < matched as usize {
        return false;
    }
    !manifest
        .iter()
        .any(|path| retrieved_path_is_build_output(path, custom_target_sync))
}
