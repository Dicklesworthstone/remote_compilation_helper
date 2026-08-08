//! License-metadata mismatch gate (beads A016/S017; risk R72).
//!
//! The repository's LICENSE carries an OpenAI/Anthropic rider; nothing
//! in the repo may advertise the project as ordinary OSI MIT. This gate
//! pins every metadata surface to the rider-bearing representation:
//!
//! - workspace Cargo metadata uses the `LicenseRef` form (syft-derived
//!   SBOMs inherit it from here);
//! - every member crate inherits `license.workspace = true` — no crate
//!   can drift back to plain `MIT`;
//! - the LICENSE file itself still names the rider and carries the
//!   rider section (an accidental replacement with stock MIT text
//!   fails this gate);
//! - the README names the rider and no longer links the plain-MIT
//!   badge/OSI page.
//!
//! Relicensing is an explicit owner decision: if these strings change
//! deliberately, this gate is updated in the same commit.

use std::fs;
use std::path::{Path, PathBuf};

const LICENSE_REF: &str = "LicenseRef-MIT-OpenAI-Anthropic-Rider";

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("rabs-protocol lives one level under the repo root")
        .to_path_buf()
}

#[test]
fn workspace_metadata_uses_the_rider_license_ref() {
    let manifest = fs::read_to_string(repo_root().join("Cargo.toml")).unwrap();
    assert!(
        manifest.contains(&format!("license = \"{LICENSE_REF}\"")),
        "workspace license must be the rider-bearing LicenseRef, never plain MIT"
    );
    assert!(
        !manifest.contains("license = \"MIT\""),
        "plain-MIT license metadata contradicts the LICENSE file (R72)"
    );
}

#[test]
fn every_member_crate_inherits_the_workspace_license() {
    let root = repo_root();
    let mut checked = 0;
    for entry in fs::read_dir(&root).unwrap() {
        let manifest = entry.unwrap().path().join("Cargo.toml");
        if !manifest.is_file() {
            continue;
        }
        let text = fs::read_to_string(&manifest).unwrap();
        for line in text.lines() {
            let line = line.trim_start();
            if line.starts_with("license") {
                assert!(
                    line.starts_with("license.workspace = true")
                        || line.starts_with("license = { workspace = true }"),
                    "{} must inherit the workspace license, found: {line}",
                    manifest.display()
                );
            }
        }
        checked += 1;
    }
    assert!(
        checked >= 5,
        "expected to scan the member crates, saw {checked}"
    );
}

#[test]
fn license_file_still_carries_the_rider() {
    let license = fs::read_to_string(repo_root().join("LICENSE")).unwrap();
    assert!(
        license
            .lines()
            .next()
            .is_some_and(|first| first.contains("MIT License (with OpenAI/Anthropic Rider)")),
        "LICENSE first line must name the rider"
    );
    assert!(
        license.contains("ADDITIONAL RIDER / RESTRICTION (OpenAI / Anthropic)"),
        "LICENSE must contain the rider section; stock MIT text is a metadata incident"
    );
}

#[test]
fn readme_never_claims_ordinary_osi_mit() {
    let readme = fs::read_to_string(repo_root().join("README.md")).unwrap();
    assert!(
        !readme.contains("opensource.org/licenses/MIT"),
        "README must not link the OSI MIT page for a rider-bearing license"
    );
    assert!(
        !readme.contains("badge/License-MIT-yellow"),
        "README must not carry the plain-MIT badge"
    );
    assert!(
        readme.contains("OpenAI/Anthropic"),
        "README's license claims must name the rider"
    );
    assert!(
        readme.contains(LICENSE_REF),
        "README should state the SPDX LicenseRef so release notices stay consistent"
    );
}
