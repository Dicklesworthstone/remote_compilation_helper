//! Supply-chain / dependency budget gates for the RABS crates (bead A012).
//!
//! Every RABS crate carries an explicit **direct runtime dependency
//! budget**. Growth is cheap to type and expensive to own — each new
//! dependency widens the audit surface, the startup cost (fatal for tiny
//! wrappers, risk R100), and the supply-chain exposure — so exceeding a
//! budget must be a reviewed decision (bump the budget in the same change,
//! with justification), never an accident.
//!
//! Also enforced here: the license posture — every `rabs-*` crate stays
//! `publish = false` until the A016 license-metadata correction ships, so
//! no crate can be published with the workspace's currently misleading
//! plain-MIT metadata (risk R72).
//!
//! Scope note (honest boundary): these are DIRECT-dependency budgets from
//! parsed manifests, including all target-specific declarations. The union
//! counts a dependency name once across platforms, but distinct renamed
//! packages remain separate edges. Dev/build dependencies do not count.
//! The transitive-cone inventory (cargo-tree based,
//! per critical binary) needs CI plumbing and lands when the rabs CI job is
//! wired; until then the A002 direction gate + these budgets bound what a
//! direct edge can pull in.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

/// (crate, max direct runtime deps, current-baseline rationale)
const BUDGETS: &[(&str, usize, &str)] = &[
    ("rabs-protocol", 0, "schemas only; zero deps by design"),
    ("rabs-action", 1, "rabs-protocol only (pure state machines)"),
    (
        "rabs-key",
        2,
        "rabs-protocol + a reviewed pure digest crate (F034)",
    ),
    ("rabs-scheduler", 1, "rabs-protocol only (pure policy)"),
    (
        "rabs-cas",
        7,
        "protocol + rusqlite/fsqlite differential store pair + sha2 \
         (authoritative digests) + blake3 (H002 LOCAL fingerprints only, \
         workspace-reviewed, structurally excluded from TypedDigest) + \
         rabs-key (H039: publication admission reuses F035's one \
         bundle-root implementation; pure sibling, protocol-only deps) + \
         filetime (K004: preserve stock Cargo mtime semantics on \
         materialized outputs so downstream fingerprints match stock)",
    ),
    ("rabs-sandbox", 4, "protocol + reviewed namespace/fs crates"),
    (
        "rabs-wrap",
        3,
        "protocol + tempfile (wrapper-local staging scratch) + serde_json \
         (wrapper control-plane frames)",
    ),
    (
        "rabs-replay",
        2,
        "protocol + serde_json (B005 harness: reads the B002 NDJSON \
         corpus and emits the divergence corpus; process effects are \
         its purpose)",
    ),
    (
        "rabs-cli",
        5,
        "protocol build identity + serde/serde_json for bounded recovery records \
         + sha2 for exact saved-request identity + rustix for retained descriptors \
         and sealed native handoff; no daemon or async runtime dependency",
    ),
    ("rabs-asupersync", 3, "asupersync + protocol (+1 headroom)"),
    (
        "rabsd",
        13,
        "composes the domain crates (rabs-action/rabs-key/rabs-cas/\
         rabs-sandbox/rabs-scheduler) + the asupersync runtime adapter \
         (rabs-asupersync + asupersync) + configuration surfaces (serde, \
         serde_json, toml) + tempfile (daemon-owned staging scratch) + \
         sha2 (the coordinator's wire-level SHA-256 digests over delivery \
         archives, recovery, acks and prepared requests, which are protocol \
         values rather than rabs-key cache keys; used in 21 modules since \
         1c57edb3, bd-csbxg)",
    ),
    (
        "rabs-wkr",
        9,
        "composes execution-relevant domain crates + tempfile (anonymous, \
         session-owned diagnostic and transfer snapshots in source_transfer, \
         execution, session and request_journal; added by 860c872e without \
         the budget change)",
    ),
];

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

fn manifest_of(krate: &str) -> String {
    let path = workspace_root().join(krate).join("Cargo.toml");
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

fn runtime_dep_count(manifest: &str, workspace: &toml::Value) -> usize {
    let manifest: toml::Value = toml::from_str(manifest).expect("valid Cargo manifest");
    let mut edges = BTreeSet::new();
    let mut tables = vec![&manifest];
    if let Some(targets) = manifest.get("target").and_then(toml::Value::as_table) {
        tables.extend(targets.values());
    }
    for table in tables {
        if let Some(deps) = table.get("dependencies").and_then(toml::Value::as_table) {
            for (name, specification) in deps {
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
                let package = specification
                    .get("package")
                    .and_then(toml::Value::as_str)
                    .unwrap_or(name);
                edges.insert((name.clone(), package.to_owned()));
            }
        }
    }
    edges.len()
}

#[test]
fn direct_dependency_budgets_hold() {
    let workspace: toml::Value = toml::from_str(
        &fs::read_to_string(workspace_root().join("Cargo.toml")).expect("read workspace manifest"),
    )
    .expect("valid workspace manifest");
    let mut violations = Vec::new();
    for (krate, budget, rationale) in BUDGETS {
        let count = runtime_dep_count(&manifest_of(krate), &workspace);
        if count > *budget {
            violations.push(format!(
                "`{krate}`: {count} direct runtime deps > budget {budget} ({rationale})"
            ));
        }
    }
    assert!(
        violations.is_empty(),
        "dependency budgets exceeded (A012; changes require review):\n{}",
        violations.join("\n"),
    );
}

#[test]
fn budgets_include_platform_edges_without_counting_development_or_multiline_fields() {
    let sample = r#"
[dependencies]
shared = { version = "1", features = [
    "one",
    "two",
] }
[target.'cfg(unix)'.dependencies]
shared = { workspace = true }
[target.'cfg(windows)'.dependencies.hidden]
package = "platform-runtime"
version = "1"
[target.'cfg(unix)'.dependencies.hidden]
package = "other-runtime"
version = "1"
[dev-dependencies]
test-only = "1"
[build-dependencies]
build-only = "1"
[target.'cfg(unix)'.dev-dependencies]
platform-test-only = "1"
"#;
    let workspace = toml::from_str("[workspace.dependencies]\nshared = '1'").unwrap();
    assert_eq!(runtime_dep_count(sample, &workspace), 3);
}

#[test]
fn budgets_cover_every_rabs_crate_in_the_workspace() {
    // A new rabs-* crate must get a budget in the same change that adds it.
    let root_manifest =
        fs::read_to_string(workspace_root().join("Cargo.toml")).expect("read workspace Cargo.toml");
    for raw in root_manifest.lines() {
        let line = raw.trim().trim_matches(',').trim_matches('"');
        if (line.starts_with("rabs-") || line == "rabsd")
            && !raw.trim_start().starts_with('#')
            && !BUDGETS.iter().any(|(k, _, _)| *k == line)
        {
            panic!(
                "workspace member `{line}` has no dependency budget; add one \
                 to rabs-protocol/tests/dependency_budget.rs (bead A012)"
            );
        }
    }
}

/// The rabs crates the published `rch` links against. crates.io requires them
/// to be published too (they have been since 2.1.0); every other rabs crate
/// is experimental and stays unpublishable.
const PUBLISHED_RABS_LIBRARIES: &[&str] = &["rabs-protocol", "rabs-key", "rabs-cas"];

#[test]
fn only_rch_library_dependencies_among_rabs_crates_are_publishable() {
    // Risk R72 (plain-MIT metadata contradicting the rider LICENSE) was
    // closed by A016, and tests/license_metadata.rs now enforces it for every
    // crate, including that each publishable crate ships the LICENSE text.
    for (krate, _, _) in BUDGETS {
        let unpublishable = manifest_of(krate).contains("publish = false");
        if PUBLISHED_RABS_LIBRARIES.contains(krate) {
            assert!(
                !unpublishable,
                "`{krate}` is a dependency of the published rch and must stay publishable"
            );
        } else {
            assert!(
                unpublishable,
                "`{krate}` is experimental RABS and must declare publish = false"
            );
        }
    }
}
