//! Dependency-direction CI for the RABS domain crates (bead A002).
//!
//! Enforces, at `cargo test --workspace` time (and therefore in CI), the
//! crate-boundary law stated in each crate's lib.rs doc header:
//!
//! - **Domain crates** (`rabs-protocol`, `rabs-action`, `rabs-key`,
//!   `rabs-scheduler`, `rabs-cas`, `rabs-sandbox`) must never depend on
//!   Tokio, Asupersync, the `rabs-asupersync` adapter, daemon crates, or
//!   network-server stacks (risk R24: compatibility islands contaminating
//!   the native action path).
//! - The **pure** crates (`rabs-protocol`, `rabs-action`, `rabs-key`,
//!   `rabs-scheduler`) may depend only on an explicit allowlist
//!   (currently: `rabs-protocol`), keeping them runnable in the
//!   deterministic lab and plain unit tests with zero runtime.
//!
//! Implementation note: this reads `[dependencies]` sections of the crate
//! manifests textually rather than shelling out to `cargo metadata`, so the
//! check stays hermetic (no process effects, no network) and needs no extra
//! dependencies. `[dev-dependencies]` are exempt: test-only tooling does
//! not ship in the crates' dependency cones.

use std::fs;
use std::path::{Path, PathBuf};

/// Crates whose runtime dependency cone must stay free of runtime/adapter
/// contamination.
const DOMAIN_CRATES: &[&str] = &[
    "rabs-protocol",
    "rabs-action",
    "rabs-key",
    "rabs-scheduler",
    "rabs-cas",
    "rabs-sandbox",
];

/// Crates restricted to the pure allowlist below.
const PURE_CRATES: &[&str] = &["rabs-protocol", "rabs-action", "rabs-key", "rabs-scheduler"];

/// The only dependencies a pure crate may declare.
/// `sha2` is the reviewed pure digest crate for typed authoritative
/// digests (bead F034): no-default-features, pure computation, no I/O.
const PURE_ALLOWLIST: &[&str] = &["rabs-protocol", "sha2"];

/// Forbidden anywhere in a domain crate's `[dependencies]`.
const FORBIDDEN_IN_DOMAIN: &[&str] = &[
    "tokio",
    "asupersync",
    "rabs-asupersync",
    "asupersync-tokio-compat",
    "rabsd",
    "rabs-wkr",
    "rchd",
    "axum",
    "hyper",
    "tower",
    "tonic",
    "reqwest",
    "ureq",
];

fn workspace_root() -> PathBuf {
    // rabs-protocol/ -> workspace root
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("rabs-protocol has a parent directory")
        .to_path_buf()
}

/// Extract the dependency names declared in the `[dependencies]` section of
/// a manifest (not `[dev-dependencies]`, not `[build-dependencies]`).
fn runtime_dependency_names(manifest: &str) -> Vec<String> {
    let mut deps = Vec::new();
    let mut in_runtime_deps = false;
    for raw in manifest.lines() {
        let line = raw.trim();
        if line.starts_with('[') {
            in_runtime_deps = line == "[dependencies]";
            continue;
        }
        if !in_runtime_deps || line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(name) = line.split('=').next() {
            let name = name.trim().trim_matches('"');
            if !name.is_empty() {
                deps.push(name.to_string());
            }
        }
    }
    deps
}

fn load_deps(crate_name: &str) -> Vec<String> {
    let path = workspace_root().join(crate_name).join("Cargo.toml");
    let manifest =
        fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    runtime_dependency_names(&manifest)
}

#[test]
fn domain_crates_have_no_runtime_or_adapter_dependencies() {
    for krate in DOMAIN_CRATES {
        let deps = load_deps(krate);
        for dep in &deps {
            assert!(
                !FORBIDDEN_IN_DOMAIN.contains(&dep.as_str()),
                "dependency-direction violation: domain crate `{krate}` \
                 declares forbidden dependency `{dep}` (see the crate's \
                 lib.rs dependency rules; risk R24)"
            );
        }
    }
}

#[test]
fn pure_crates_use_only_the_allowlist() {
    for krate in PURE_CRATES {
        let deps = load_deps(krate);
        for dep in &deps {
            assert!(
                PURE_ALLOWLIST.contains(&dep.as_str()),
                "purity violation: `{krate}` declares `{dep}`, which is not \
                 in the pure-crate allowlist {PURE_ALLOWLIST:?}. If this \
                 dependency is genuinely required, it must be explicitly \
                 reviewed and added to the allowlist in \
                 rabs-protocol/tests/dependency_direction.rs in the same \
                 change (bead A002)"
            );
        }
    }
}

#[test]
fn all_guarded_crates_exist() {
    // Guards against the check silently passing because a crate was moved
    // or renamed out from under it.
    for krate in DOMAIN_CRATES {
        let path = workspace_root().join(krate).join("Cargo.toml");
        assert!(
            path.is_file(),
            "guarded crate `{krate}` missing at {}; update DOMAIN_CRATES if \
             the workspace layout changed deliberately",
            path.display()
        );
    }
}

#[test]
fn parser_sees_sections_correctly() {
    // Self-test of the manifest scanner: dev-dependencies and comments are
    // ignored; dependencies are captured.
    let sample = r#"
[package]
name = "x"

[dependencies]
rabs-protocol = { path = "../rabs-protocol" }
# tokio = "1"  (commented out — must not count)

[dev-dependencies]
tokio = { version = "1", features = ["full"] }
"#;
    let deps = runtime_dependency_names(sample);
    assert_eq!(deps, vec!["rabs-protocol".to_string()]);
}
