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
fn every_publishable_crate_ships_the_license_text() {
    // A LicenseRef names a license by reference only. crates.io consumers see
    // the rider only if the package carries the text, and Cargo packages a
    // crate's own directory, never the workspace-root LICENSE.
    let root = repo_root();
    let license = fs::read_to_string(root.join("LICENSE")).unwrap();
    let mut publishable = 0;
    for entry in fs::read_dir(&root).unwrap() {
        let dir = entry.unwrap().path();
        let Ok(manifest) = fs::read_to_string(dir.join("Cargo.toml")) else {
            continue;
        };
        if dir == root || !manifest.contains("[package]") || manifest.contains("publish = false") {
            continue;
        }
        let shipped = fs::read_to_string(dir.join("LICENSE")).unwrap_or_default();
        assert_eq!(
            shipped,
            license,
            "{} is publishable but does not ship the rider LICENSE text",
            dir.display()
        );
        publishable += 1;
    }
    assert!(
        publishable >= 8,
        "expected the eight published crates, saw {publishable}"
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct MemberCrateLicenseSnapshot {
    name: String,
    manifest_text: String,
    shipped_license_text: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LicenseConformanceInputs {
    workspace_cargo_toml: String,
    member_crates: Vec<MemberCrateLicenseSnapshot>,
    root_license: String,
    readme: String,
    release_workflow: String,
    installer_script: String,
    dashboard_package_json: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum LicenseConformanceViolation {
    WorkspaceMissingRiderLicenseRef,
    WorkspaceClaimsPlainMit,
    MemberCrateDoesNotInheritWorkspaceLicense { crate_name: String },
    PublishableCrateMissingOrMismatchedLicense { crate_name: String },
    RootLicenseMissingRiderHeader,
    RootLicenseMissingRiderSection,
    ReadmeLinksOsiMit,
    ReadmeCarriesPlainMitBadge,
    ReadmeMissingRiderDisclosure,
    ReadmeMissingSpdxLicenseRef,
    ReleaseWorkflowMissingSpdxSbomGeneration,
    ReleaseWorkflowMissingCycloneDxSbomGeneration,
    ReleaseWorkflowOverridesSpdxWithPlainMit,
    InstallerClaimsPlainMit,
    DashboardClaimsPlainMit,
}

fn load_live_conformance_inputs() -> LicenseConformanceInputs {
    let root = repo_root();
    let workspace_cargo_toml = fs::read_to_string(root.join("Cargo.toml")).unwrap();
    let root_license = fs::read_to_string(root.join("LICENSE")).unwrap();
    let readme = fs::read_to_string(root.join("README.md")).unwrap();
    let release_workflow = fs::read_to_string(root.join(".github/workflows/release.yml")).unwrap();
    let installer_script = fs::read_to_string(root.join("install.sh")).unwrap();
    let dashboard_package_json = fs::read_to_string(root.join("dashboard/package.json")).unwrap();

    let mut member_crates = Vec::new();
    for entry in fs::read_dir(&root).unwrap() {
        let dir = entry.unwrap().path();
        if dir == root {
            continue;
        }
        let manifest_path = dir.join("Cargo.toml");
        if !manifest_path.is_file() {
            continue;
        }
        let manifest_text = fs::read_to_string(&manifest_path).unwrap();
        if !manifest_text.contains("[package]") {
            continue;
        }
        let name = dir
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown")
            .to_owned();
        let shipped_license_text = fs::read_to_string(dir.join("LICENSE")).ok();
        member_crates.push(MemberCrateLicenseSnapshot {
            name,
            manifest_text,
            shipped_license_text,
        });
    }
    member_crates.sort_by(|a, b| a.name.cmp(&b.name));

    LicenseConformanceInputs {
        workspace_cargo_toml,
        member_crates,
        root_license,
        readme,
        release_workflow,
        installer_script,
        dashboard_package_json,
    }
}

fn evaluate_license_conformance(
    inputs: &LicenseConformanceInputs,
) -> Result<(), Vec<LicenseConformanceViolation>> {
    let mut violations = Vec::new();

    if !inputs
        .workspace_cargo_toml
        .contains(&format!("license = \"{LICENSE_REF}\""))
    {
        violations.push(LicenseConformanceViolation::WorkspaceMissingRiderLicenseRef);
    }
    if inputs.workspace_cargo_toml.contains("license = \"MIT\"") {
        violations.push(LicenseConformanceViolation::WorkspaceClaimsPlainMit);
    }

    for member in &inputs.member_crates {
        let mut inherits_workspace_license = false;
        let mut invalid_override = false;
        for line in member.manifest_text.lines() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("license") {
                if trimmed.starts_with("license.workspace = true")
                    || trimmed.starts_with("license = { workspace = true }")
                {
                    inherits_workspace_license = true;
                } else {
                    invalid_override = true;
                }
            }
        }
        if invalid_override || !inherits_workspace_license {
            violations.push(
                LicenseConformanceViolation::MemberCrateDoesNotInheritWorkspaceLicense {
                    crate_name: member.name.clone(),
                },
            );
        }
        let is_publishable = !member.manifest_text.contains("publish = false");
        if is_publishable
            && member.shipped_license_text.as_deref() != Some(inputs.root_license.as_str())
        {
            violations.push(
                LicenseConformanceViolation::PublishableCrateMissingOrMismatchedLicense {
                    crate_name: member.name.clone(),
                },
            );
        }
    }

    if !inputs
        .root_license
        .lines()
        .next()
        .is_some_and(|first| first.contains("MIT License (with OpenAI/Anthropic Rider)"))
    {
        violations.push(LicenseConformanceViolation::RootLicenseMissingRiderHeader);
    }
    if !inputs
        .root_license
        .contains("ADDITIONAL RIDER / RESTRICTION (OpenAI / Anthropic)")
    {
        violations.push(LicenseConformanceViolation::RootLicenseMissingRiderSection);
    }

    if inputs.readme.contains("opensource.org/licenses/MIT") {
        violations.push(LicenseConformanceViolation::ReadmeLinksOsiMit);
    }
    if inputs.readme.contains("badge/License-MIT-yellow") {
        violations.push(LicenseConformanceViolation::ReadmeCarriesPlainMitBadge);
    }
    if !inputs.readme.contains("OpenAI/Anthropic") {
        violations.push(LicenseConformanceViolation::ReadmeMissingRiderDisclosure);
    }
    if !inputs.readme.contains(LICENSE_REF) {
        violations.push(LicenseConformanceViolation::ReadmeMissingSpdxLicenseRef);
    }

    if !inputs.release_workflow.contains("spdx-json") {
        violations.push(LicenseConformanceViolation::ReleaseWorkflowMissingSpdxSbomGeneration);
    }
    if !inputs.release_workflow.contains("cyclonedx-json") {
        violations.push(LicenseConformanceViolation::ReleaseWorkflowMissingCycloneDxSbomGeneration);
    }
    if inputs
        .release_workflow
        .contains("SPDX-License-Identifier: MIT")
    {
        violations.push(LicenseConformanceViolation::ReleaseWorkflowOverridesSpdxWithPlainMit);
    }

    if inputs
        .installer_script
        .contains("SPDX-License-Identifier: MIT")
        || inputs
            .installer_script
            .contains("Licensed under the MIT License")
    {
        violations.push(LicenseConformanceViolation::InstallerClaimsPlainMit);
    }

    if inputs
        .dashboard_package_json
        .contains("\"license\": \"MIT\"")
    {
        violations.push(LicenseConformanceViolation::DashboardClaimsPlainMit);
    }

    if violations.is_empty() {
        Ok(())
    } else {
        Err(violations)
    }
}

#[test]
fn s017_live_repo_passes_full_license_sbom_package_installer_website_conformance_gate() {
    let inputs = load_live_conformance_inputs();
    assert_eq!(evaluate_license_conformance(&inputs), Ok(()));
}

#[test]
fn s017_conformance_gate_turns_red_on_every_seeded_mismatch() {
    let baseline = load_live_conformance_inputs();

    // 1. Seeded Cargo workspace plain-MIT regression.
    let mut seeded_workspace = baseline.clone();
    seeded_workspace.workspace_cargo_toml = seeded_workspace
        .workspace_cargo_toml
        .replace(&format!("license = \"{LICENSE_REF}\""), "license = \"MIT\"");
    assert_eq!(
        evaluate_license_conformance(&seeded_workspace),
        Err(vec![
            LicenseConformanceViolation::WorkspaceMissingRiderLicenseRef,
            LicenseConformanceViolation::WorkspaceClaimsPlainMit,
        ])
    );

    // 2. Seeded member crate overriding workspace license.
    let mut seeded_member = baseline.clone();
    seeded_member.member_crates[0].manifest_text = seeded_member.member_crates[0]
        .manifest_text
        .replace("license.workspace = true", "license = \"MIT\"");
    let first_member_name = seeded_member.member_crates[0].name.clone();
    assert_eq!(
        evaluate_license_conformance(&seeded_member),
        Err(vec![
            LicenseConformanceViolation::MemberCrateDoesNotInheritWorkspaceLicense {
                crate_name: first_member_name,
            }
        ])
    );

    // 3. Seeded publishable crate shipping truncated/mismatched LICENSE text.
    let mut seeded_publishable = baseline.clone();
    let publishable_member = seeded_publishable
        .member_crates
        .iter_mut()
        .find(|m| !m.manifest_text.contains("publish = false"))
        .expect("at least one publishable member crate");
    let publishable_name = publishable_member.name.clone();
    publishable_member.shipped_license_text = Some("MIT License\nStock text only\n".to_owned());
    assert_eq!(
        evaluate_license_conformance(&seeded_publishable),
        Err(vec![
            LicenseConformanceViolation::PublishableCrateMissingOrMismatchedLicense {
                crate_name: publishable_name,
            }
        ])
    );

    // 4. Seeded root LICENSE stripped of rider section.
    let mut seeded_license = baseline.clone();
    seeded_license.root_license = "MIT License\n\nPermission is hereby granted...".to_owned();
    let license_err = evaluate_license_conformance(&seeded_license).unwrap_err();
    assert!(license_err.contains(&LicenseConformanceViolation::RootLicenseMissingRiderHeader));
    assert!(license_err.contains(&LicenseConformanceViolation::RootLicenseMissingRiderSection));

    // 5. Seeded README plain-MIT badge and missing SPDX LicenseRef.
    let mut seeded_readme = baseline.clone();
    seeded_readme.readme = seeded_readme
        .readme
        .replace(LICENSE_REF, "badge/License-MIT-yellow");
    assert_eq!(
        evaluate_license_conformance(&seeded_readme),
        Err(vec![
            LicenseConformanceViolation::ReadmeCarriesPlainMitBadge,
            LicenseConformanceViolation::ReadmeMissingSpdxLicenseRef,
        ])
    );

    // 6. Seeded SPDX/SBOM workflow regression.
    let mut seeded_sbom = baseline.clone();
    seeded_sbom.release_workflow = "# SPDX-License-Identifier: MIT\nname: Release\n".to_owned();
    assert_eq!(
        evaluate_license_conformance(&seeded_sbom),
        Err(vec![
            LicenseConformanceViolation::ReleaseWorkflowMissingSpdxSbomGeneration,
            LicenseConformanceViolation::ReleaseWorkflowMissingCycloneDxSbomGeneration,
            LicenseConformanceViolation::ReleaseWorkflowOverridesSpdxWithPlainMit,
        ])
    );

    // 7. Seeded installer notice and website/dashboard package metadata mismatch.
    let mut seeded_installer_and_web = baseline;
    seeded_installer_and_web
        .installer_script
        .push_str("\n# Licensed under the MIT License\n");
    seeded_installer_and_web.dashboard_package_json =
        "{\n  \"name\": \"rch-dashboard\",\n  \"license\": \"MIT\"\n}\n".to_owned();
    assert_eq!(
        evaluate_license_conformance(&seeded_installer_and_web),
        Err(vec![
            LicenseConformanceViolation::InstallerClaimsPlainMit,
            LicenseConformanceViolation::DashboardClaimsPlainMit,
        ])
    );
}
