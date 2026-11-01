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
//! Implementation note: a test-only TOML parser reads ordinary and all
//! target-specific runtime dependencies, resolving renamed packages without
//! invoking Cargo or the network. `[dev-dependencies]` are exempt: test-only tooling does
//! not ship in the crates' dependency cones.

use std::collections::BTreeSet;
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

/// Extract actual package names from ordinary and target-specific runtime
/// declarations, including renamed and table-form dependencies.
fn runtime_dependency_names(manifest: &str, workspace: &toml::Value) -> Vec<String> {
    let manifest: toml::Value = toml::from_str(manifest).expect("valid Cargo manifest");
    let mut deps = BTreeSet::new();
    let mut tables = vec![&manifest];
    if let Some(targets) = manifest.get("target").and_then(toml::Value::as_table) {
        tables.extend(targets.values());
    }
    for table in tables {
        if let Some(declarations) = table.get("dependencies").and_then(toml::Value::as_table) {
            for (name, specification) in declarations {
                let specification = if specification
                    .get("workspace")
                    .and_then(toml::Value::as_bool)
                    == Some(true)
                {
                    workspace
                        .get("workspace")
                        .and_then(|workspace| workspace.get("dependencies"))
                        .and_then(|deps| deps.get(name))
                        .expect("inherited dependency must exist in the workspace")
                } else {
                    specification
                };
                deps.insert(
                    specification
                        .get("package")
                        .and_then(toml::Value::as_str)
                        .unwrap_or(name)
                        .to_owned(),
                );
            }
        }
    }
    deps.into_iter().collect()
}

fn load_deps(crate_name: &str) -> Vec<String> {
    let path = workspace_root().join(crate_name).join("Cargo.toml");
    let manifest =
        fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    let workspace: toml::Value = toml::from_str(
        &fs::read_to_string(workspace_root().join("Cargo.toml")).expect("read workspace manifest"),
    )
    .expect("valid workspace manifest");
    runtime_dependency_names(&manifest, &workspace)
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
    let deps = runtime_dependency_names(sample, &toml::Table::new().into());
    assert_eq!(deps, vec!["rabs-protocol".to_string()]);
}

#[test]
fn platform_and_renamed_runtime_dependencies_cannot_hide_from_direction_checks() {
    let sample = r#"
[dependencies]
pure-alias = { package = "rabs-protocol", version = "1" }
[target.'cfg(unix)'.dependencies]
hidden-runtime = { package = "tokio", version = "1", features = [
    "full",
] }
inherited-runtime = { workspace = true }
[target.'cfg(windows)'.dependencies.server]
package = "hyper"
version = "1"
[target.'cfg(unix)'.dev-dependencies]
reqwest = "1"
[build-dependencies]
ureq = "1"
"#;
    let workspace = toml::from_str(
        "[workspace.dependencies]\ninherited-runtime = { package = 'asupersync', version = '1' }",
    )
    .unwrap();
    let deps = runtime_dependency_names(sample, &workspace);
    assert_eq!(deps, ["asupersync", "hyper", "rabs-protocol", "tokio"]);
    assert_eq!(
        deps.iter()
            .filter(|dep| FORBIDDEN_IN_DOMAIN.contains(&dep.as_str()))
            .count(),
        3,
    );
}
