//! The minimal rabs-profile feature gate (bead A004; plan §42).
//!
//! RABS enables the smallest audited Asupersync surface rather than the
//! whole default set. This test pins the profile textually so any feature
//! creep is a deliberate, reviewed change:
//!
//! - `default-features = false` — the experimental `nightly-outcome-try`
//!   Try/residual impls stay off; RABS uses explicit Outcome helpers.
//! - Runtime `features = ["proc-macros"]` exactly.
//! - Browser/wasm, legacy-harness, messaging-fabric, and real-service-e2e
//!   features never appear in the runtime dependency.
//! - `test-internals` (which exposes private APIs like `Cx::new()`) may
//!   only ever appear under `[dev-dependencies]` for lab tests.
//!
//! The full dependency/feature inventory artifact for the critical
//! binaries (cargo-tree based) lands with the A012 budget gates, which
//! share its plumbing.

use std::fs;
use std::path::Path;

fn manifest() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
    fs::read_to_string(&path).expect("read rabs-asupersync/Cargo.toml")
}

/// The `[dependencies]` section only (not dev/build deps).
fn runtime_deps_section(manifest: &str) -> String {
    let mut out = String::new();
    let mut in_deps = false;
    for raw in manifest.lines() {
        let line = raw.trim();
        if line.starts_with('[') {
            in_deps = line == "[dependencies]";
            continue;
        }
        // Comments must not trip the gate: only effective lines count.
        if in_deps && !line.starts_with('#') {
            out.push_str(raw);
            out.push('\n');
        }
    }
    out
}

#[test]
fn asupersync_uses_the_minimal_profile() {
    let deps = runtime_deps_section(&manifest());
    let dep_line = deps
        .lines()
        .find(|l| l.trim_start().starts_with("asupersync ="))
        .expect("asupersync dependency present (pinned per ADR 007)");
    assert!(
        dep_line.contains("default-features = false"),
        "asupersync must disable default features (nightly-outcome-try is \
         experimental); line: {dep_line}"
    );
    assert!(
        dep_line.contains(r#"features = ["proc-macros"]"#),
        "runtime feature set must be exactly [\"proc-macros\"]; widening it \
         is a reviewed rabs-profile change (bead A004); line: {dep_line}"
    );
    assert!(
        dep_line.contains("rev = \"78b64636e99fea4ea2d868096576021dd3b8e519\""),
        "pin drift: the revision must match ADR 007's current pin; \
         line: {dep_line}"
    );
}

#[test]
fn every_runtime_consumer_uses_the_same_release_pin() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let mut edges = 0;
    for consumer in ["rabs-asupersync", "rabsd", "rabs-wkr"] {
        let source = fs::read_to_string(workspace.join(consumer).join("Cargo.toml"))
            .expect("read runtime consumer manifest");
        for line in source.lines().map(str::trim) {
            if !line.starts_with("asupersync =") {
                continue;
            }
            edges += 1;
            assert!(
                line.contains("version = \"=0.5.0\"")
                    && line.contains("rev = \"78b64636e99fea4ea2d868096576021dd3b8e519\"")
                    && line
                        .contains("git = \"https://github.com/Dicklesworthstone/asupersync.git\""),
                "{consumer} runtime pin differs from ADR 007: {line}"
            );
        }
    }
    assert_eq!(edges, 4, "three production edges and the rabsd dev edge");
}

#[test]
fn forbidden_features_never_enter_the_runtime_profile() {
    let deps = runtime_deps_section(&manifest());
    for forbidden in [
        "wasm-browser-preview",
        "wasm-runtime",
        "wasm-browser-dev",
        "wasm-browser-prod",
        "wasm-browser-deterministic",
        "wasm-browser-minimal",
        "browser-io",
        "browser-trace",
        "messaging-fabric",
        "legacy-internal-test-harnesses",
        "serialization-golden-harnesses",
        "real-service-e2e",
        "nightly-outcome-try",
        "test-internals",
    ] {
        assert!(
            !deps.contains(forbidden),
            "forbidden Asupersync feature `{forbidden}` appeared in the \
             runtime [dependencies] profile (plan sec 42: no browser/legacy/\
             experimental surfaces in critical binaries)"
        );
    }
}

#[test]
fn test_internals_only_ever_in_dev_dependencies() {
    // test-internals exposes private APIs (Cx::new()) and is lab-only.
    // It is currently unused; when the lab suites (G012) add it, this test
    // documents WHERE it is allowed to live.
    let m = manifest();
    let mut section = String::new();
    for raw in m.lines() {
        let line = raw.trim();
        if line.starts_with('[') {
            section = line.to_string();
            continue;
        }
        if !line.starts_with('#') && line.contains("test-internals") {
            assert_eq!(
                section, "[dev-dependencies]",
                "test-internals may only appear under [dev-dependencies], \
                 found under {section}"
            );
        }
    }
}
