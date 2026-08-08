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
//! textual manifest scans. The transitive-cone inventory (cargo-tree based,
//! per critical binary) needs CI plumbing and lands when the rabs CI job is
//! wired; until then the A002 direction gate + these budgets bound what a
//! direct edge can pull in.

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
        5,
        "protocol + rusqlite/fsqlite differential store pair + sha2 \
         (authoritative digests) + blake3 (H002 LOCAL fingerprints only, \
         workspace-reviewed, structurally excluded from TypedDigest)",
    ),
    ("rabs-sandbox", 4, "protocol + reviewed namespace/fs crates"),
    ("rabs-asupersync", 3, "asupersync + protocol (+1 headroom)"),
    ("rabsd", 10, "composes the domain crates + runtime adapter"),
    ("rabs-wkr", 8, "composes execution-relevant domain crates"),
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

fn runtime_dep_count(manifest: &str) -> usize {
    let mut n = 0;
    let mut in_deps = false;
    for raw in manifest.lines() {
        let line = raw.trim();
        if line.starts_with('[') {
            in_deps = line == "[dependencies]";
            continue;
        }
        if in_deps && !line.is_empty() && !line.starts_with('#') {
            n += 1;
        }
    }
    n
}

#[test]
fn direct_dependency_budgets_hold() {
    for (krate, budget, rationale) in BUDGETS {
        let count = runtime_dep_count(&manifest_of(krate));
        assert!(
            count <= *budget,
            "dependency budget exceeded for `{krate}`: {count} direct \
             runtime deps > budget {budget} ({rationale}). If the new \
             dependency is genuinely required, review it and raise the \
             budget in rabs-protocol/tests/dependency_budget.rs in the \
             SAME change, stating why (bead A012)"
        );
    }
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

#[test]
fn rabs_crates_stay_unpublishable_until_license_metadata_is_fixed() {
    // Risk R72: workspace package metadata advertises plain MIT while the
    // license file carries the rider. Until bead A016 corrects metadata,
    // no rabs crate may be publishable.
    for (krate, _, _) in BUDGETS {
        let manifest = manifest_of(krate);
        assert!(
            manifest.contains("publish = false"),
            "`{krate}` must declare publish = false until the A016 \
             license-metadata correction lands (risk R72)"
        );
    }
}
