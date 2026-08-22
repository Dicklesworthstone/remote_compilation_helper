//! C013 acceptance fixture (bead .21.13): pin the REAL fingerprint
//! semantics of Cargo's wrapper variables so the doctor check teaches
//! the truth.
//!
//! Empirically verified on current cargo (1.100-nightly, and the reason
//! this fixture exists — the folklore was wrong):
//!
//! - plain `RUSTC_WRAPPER` is NOT part of any fingerprint: enabling,
//!   swapping, or removing it never recompiles;
//! - `RUSTC_WORKSPACE_WRAPPER` IS fingerprinted by its VALUE: the first
//!   build under a given wrapper compiles exactly once, subsequent
//!   builds are cache hits, and removing the wrapper falls back to the
//!   previously valid artifacts WITHOUT recompiling.
//!
//! The wrappers used here are *passthrough* scripts (`exec "$@"`) whose
//! behavior is byte-for-byte identical to bare rustc. That isolates the
//! variable under test: between the runs compared, only the env var's
//! presence/value changes.
//!
//! Deterministic: isolated `CARGO_HOME`, offline mode, zero
//! dependencies, sequential builds in one tempdir.

#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

const CRATE_NAME: &str = "c013_fingerprint_fixture";

fn write_project(dir: &Path) {
    std::fs::create_dir_all(dir.join("src")).expect("src dir");
    std::fs::write(
        dir.join("Cargo.toml"),
        format!("[package]\nname = \"{CRATE_NAME}\"\nversion = \"0.1.0\"\nedition = \"2021\"\n"),
    )
    .expect("Cargo.toml");
    std::fs::write(dir.join("src/main.rs"), "fn main() {}\n").expect("main.rs");
}

/// A passthrough wrapper: cargo invokes `<wrapper> <rustc-path>
/// <args...>`, so `exec "$@"` is behaviorally identical to no wrapper.
fn write_passthrough_wrapper(path: &Path) {
    std::fs::write(path, "#!/bin/sh\nexec \"$@\"\n").expect("shim script");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).expect("chmod shim");
}

/// One `cargo build` with a single wrapper variable configured (or
/// removed). Returns whether Cargo reported compiling our crate.
fn build(dir: &Path, cargo_home: &Path, var: &str, wrapper: Option<&Path>) -> (bool, bool) {
    let mut cmd = Command::new(env!("CARGO"));
    cmd.arg("build")
        .arg("--offline")
        .arg("--manifest-path")
        .arg(dir.join("Cargo.toml"))
        .env("CARGO_HOME", cargo_home)
        .env_remove("CARGO_TARGET_DIR")
        .env_remove("RUSTC_WRAPPER")
        .env_remove("RUSTC_WORKSPACE_WRAPPER");
    if let Some(path) = wrapper {
        cmd.env(var, path);
    }
    let output = cmd.output().expect("spawn cargo");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    (
        output.status.success(),
        combined.contains(&format!("Compiling {CRATE_NAME}")),
    )
}

#[test]
fn workspace_wrapper_is_fingerprinted_and_plain_wrapper_is_not() {
    let project = tempfile::tempdir().expect("project dir");
    let cargo_home_tmp = tempfile::tempdir().expect("cargo home");
    let shims = tempfile::tempdir().expect("shim dir");
    write_project(project.path());

    let plain_a = shims.path().join("plain-a");
    let ws_a = shims.path().join("ws-a");
    write_passthrough_wrapper(&plain_a);
    write_passthrough_wrapper(&ws_a);

    // Baseline: initial build compiles; repeat is a cache hit.
    let (ok, compiled) = build(project.path(), cargo_home_tmp.path(), "RUSTC_WRAPPER", None);
    assert!(ok && compiled, "baseline build must compile the crate");
    let (ok, compiled) = build(
        project.path(),
        cargo_home_tmp.path(),
        "RUSTC_WORKSPACE_WRAPPER",
        None,
    );
    assert!(ok, "baseline repeat must succeed");
    assert!(!compiled, "baseline repeat must be fresh");

    // PLAIN RUSTC_WRAPPER: enabling it must NOT recompile.
    let (ok, compiled) = build(
        project.path(),
        cargo_home_tmp.path(),
        "RUSTC_WRAPPER",
        Some(&plain_a),
    );
    assert!(ok);
    assert!(
        !compiled,
        "plain RUSTC_WRAPPER is not fingerprinted: enabling it must \
         NOT force a rebuild"
    );

    // RUSTC_WORKSPACE_WRAPPER: first use of the value compiles ONCE.
    let (ok, compiled) = build(
        project.path(),
        cargo_home_tmp.path(),
        "RUSTC_WORKSPACE_WRAPPER",
        Some(&ws_a),
    );
    assert!(ok);
    assert!(
        compiled,
        "first enablement of RUSTC_WORKSPACE_WRAPPER must force a \
         one-time rebuild (its value is fingerprinted)"
    );

    // Same value again: back to incremental.
    let (ok, compiled) = build(
        project.path(),
        cargo_home_tmp.path(),
        "RUSTC_WORKSPACE_WRAPPER",
        Some(&ws_a),
    );
    assert!(ok);
    assert!(
        !compiled,
        "second build under the same workspace wrapper must be fresh"
    );

    // Removing it: falls back to previously valid artifacts — no compile.
    let (ok, compiled) = build(
        project.path(),
        cargo_home_tmp.path(),
        "RUSTC_WORKSPACE_WRAPPER",
        None,
    );
    assert!(ok);
    assert!(
        !compiled,
        "removing the workspace wrapper restores prior artifacts \
         without recompiling"
    );
}
