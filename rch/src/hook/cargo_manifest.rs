//! Manifest-selected Cargo planning without changing the transfer/execution root.
//!
//! A repository may contain independent packages without a root Cargo.toml.
//! Keep package authorities separate from rsync roots: collapsing a package
//! into its enclosing transfer must not remove its manifest/source checks.

use super::super::cargo_target_dir::managed_clean_overlay_cargo_tokens;
use super::super::dependency_closure::{
    SyncClosureMode, SyncClosurePlanEntry, SyncRootOutcome, canonicalize_sync_root_for_plan,
    is_within_sync_topology,
};
use rch_common::path_topology::PathTopologyPolicy;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Resolve an explicit manifest relative to the invocation directory, not to
/// the eventual worker mirror. None preserves the existing implicit planner.
/// The shared literal parser handles quoting and executable wrapper prefixes;
/// Cargo's `--` terminates its options, including for nextest/test passthrough.
pub(super) fn selected_manifest_root(
    command: &str,
    invocation_root: &Path,
    policy: &PathTopologyPolicy,
) -> anyhow::Result<Option<PathBuf>> {
    let words = shell_words::split(command)?;
    if !words
        .iter()
        .any(|word| word == "--manifest-path" || word.starts_with("--manifest-path="))
    {
        return Ok(None);
    }
    let (words, cargo_index) = managed_clean_overlay_cargo_tokens(command)?;
    let mut selected = None;
    let mut changes_directory = words[..cargo_index]
        .iter()
        .any(|word| matches!(word.as_str(), "-C" | "--chdir") || word.starts_with("--chdir="));
    let mut args = words[cargo_index + 1..].iter();
    while let Some(arg) = args.next() {
        if arg == "--" {
            break;
        }
        let manifest = if arg == "--manifest-path" {
            Some(
                args.next()
                    .ok_or_else(|| anyhow::anyhow!("missing --manifest-path value"))?
                    .as_str(),
            )
        } else if let Some(value) = arg.strip_prefix("--manifest-path=") {
            Some(value)
        } else {
            // Never interpret another option's value as a manifest selector.
            // Changing cwd requires a separate, explicit replay mapping; refuse
            // that combination instead of discovering the wrong package graph.
            if arg.starts_with("-C") {
                changes_directory = true;
            }
            if matches!(
                arg.as_str(),
                "--config"
                    | "--target"
                    | "--target-dir"
                    | "--profile"
                    | "--package"
                    | "-p"
                    | "--exclude"
                    | "--features"
                    | "-F"
                    | "--bin"
                    | "--example"
                    | "--test"
                    | "--bench"
                    | "--color"
                    | "--message-format"
                    | "--jobs"
                    | "-j"
                    | "-Z"
                    | "-C"
                    | "--lockfile-path"
                    | "--artifact-dir"
                    | "--out-dir"
            ) {
                anyhow::ensure!(
                    args.next().is_some(),
                    "missing value for Cargo option {arg}"
                );
            }
            None
        };
        if let Some(manifest) = manifest {
            anyhow::ensure!(
                selected.is_none(),
                "multiple --manifest-path options are unsupported"
            );
            anyhow::ensure!(
                !manifest.is_empty() && manifest != "--" && !manifest.chars().any(char::is_control),
                "--manifest-path must name a nonempty Cargo.toml path without control characters"
            );
            selected = Some(manifest);
        }
    }
    let Some(selected) = selected else {
        return Ok(None);
    };
    anyhow::ensure!(
        !changes_directory,
        "--manifest-path with env --chdir/-C or cargo -C requires an explicit working-directory mapping"
    );
    let manifest = invocation_root.join(selected);
    anyhow::ensure!(
        manifest
            .file_name()
            .is_some_and(|name| name == "Cargo.toml")
            && manifest.is_file(),
        "selected Cargo manifest is not a file: {}",
        manifest.display()
    );
    let root = canonicalize_sync_root_for_plan(
        manifest
            .parent()
            .ok_or_else(|| anyhow::anyhow!("selected manifest has no package directory"))?,
        policy,
    );
    anyhow::ensure!(
        is_within_sync_topology(&root, policy),
        "selected Cargo manifest is outside the configured source topology: {}",
        manifest.display()
    );
    Ok(Some(root))
}

/// Project package-level verification onto the transfers that actually ran.
/// This changes only preflight inputs, never the transfer list, locks, build
/// cwd, or artifact basis. Every collapsed package inherits its covering
/// transfer's real outcome and relocated remote path (including proof roots).
pub(super) fn manifest_preflight_outcomes(
    transfers: &[(SyncClosurePlanEntry, SyncRootOutcome)],
    package_roots: &[PathBuf],
    policy: &PathTopologyPolicy,
) -> anyhow::Result<Vec<(SyncClosurePlanEntry, SyncRootOutcome)>> {
    anyhow::ensure!(
        !package_roots.is_empty(),
        "selected Cargo closure has no package roots"
    );
    let mut checks = BTreeMap::new();
    for (entry, outcome) in transfers {
        // Only a primary *transfer basis* may lack a manifest. All dependency
        // and workspace-metadata entries keep their existing requirements,
        // even when their local manifest has disappeared since planning.
        if !entry.is_primary
            || entry.mode == SyncClosureMode::WorkspaceMetadata
            || entry.local_root.join("Cargo.toml").is_file()
        {
            checks.insert(
                (entry.local_root.clone(), entry.mode),
                (entry.clone(), outcome.clone()),
            );
        }
    }
    for root in package_roots {
        let root = canonicalize_sync_root_for_plan(root, policy);
        let (cover, outcome) = transfers
            .iter()
            .filter(|(entry, _)| {
                entry.mode == SyncClosureMode::Full && root.starts_with(&entry.local_root)
            })
            .max_by_key(|(entry, _)| entry.local_root.components().count())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Cargo package {} is not covered by a full source transfer",
                    root.display()
                )
            })?;
        let relative = root.strip_prefix(&cover.local_root)?;
        let mut entry = cover.clone();
        entry.remote_root = Path::new(&cover.remote_root)
            .join(relative)
            .to_string_lossy()
            .into_owned();
        entry.local_root = root;
        checks.insert(
            (entry.local_root.clone(), entry.mode),
            (entry, outcome.clone()),
        );
    }
    Ok(checks.into_values().collect())
}

#[cfg(test)]
mod tests {
    use super::super::super::dependency_closure::{
        DependencyPreflightStatus, build_dependency_preflight_report, build_sync_closure_plan,
        synced_dependency_preflight_checks,
    };
    use super::super::super::{
        CompilationKind, HookReporter, OutputVisibility, WorkerConfig,
        build_dependency_runtime_plan,
    };
    use super::*;

    fn package(root: &Path, name: &str, extra: &str) {
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(
            root.join("Cargo.toml"),
            format!("[package]\nname = {name:?}\nversion = \"0.1.0\"\n{extra}"),
        )
        .unwrap();
        std::fs::write(root.join("src/lib.rs"), "pub fn fixture() {}\n").unwrap();
    }

    #[test]
    fn manifest_selection_preserves_literal_paths_and_cargo_option_boundaries() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().canonicalize().unwrap();
        let policy = PathTopologyPolicy::new(base.clone(), base.clone());
        let root = base.join("crate with ' quotes; $cash");
        package(&root, "selected", "");
        let path = root.join("Cargo.toml");
        let value = path.to_str().unwrap();
        for args in [
            vec!["cargo", "test", "--manifest-path", value],
            vec!["cargo", "+nightly", "test", "--manifest-path", value],
            vec![
                "env",
                "--",
                "KEY=value",
                "rustup",
                "run",
                "nightly",
                "cargo",
                "test",
                "--manifest-path",
                value,
            ],
            vec![
                "/usr/bin/time",
                "-f",
                "cargo",
                "cargo",
                "test",
                "--manifest-path",
                value,
            ],
        ] {
            assert_eq!(
                selected_manifest_root(&shell_words::join(args), &base, &policy).unwrap(),
                Some(root.clone())
            );
        }
        let relative = "crate with ' quotes; $cash/Cargo.toml";
        let equals = format!("--manifest-path={relative}");
        assert_eq!(
            selected_manifest_root(
                &shell_words::join(["cargo", "test", equals.as_str()]),
                &base,
                &policy,
            )
            .unwrap(),
            Some(root)
        );
        for command in [
            "cargo test -- --manifest-path nonexistent/Cargo.toml",
            "cargo nextest run -- --manifest-path=nonexistent/Cargo.toml",
            "env -- cargo test -- --manifest-path=nonexistent/Cargo.toml",
            "cargo test --config --manifest-path=not-a-selector",
            "cargo build",
        ] {
            assert_eq!(
                selected_manifest_root(command, &base, &policy).unwrap(),
                None,
                "{command}"
            );
        }
    }

    #[test]
    fn manifest_selection_refuses_missing_ambiguous_and_out_of_topology_inputs() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().canonicalize().unwrap();
        let root = base.join("repo");
        package(&root, "selected", "");
        package(&base.join("outside"), "outside", "");
        let policy = PathTopologyPolicy::new(root.clone(), root.clone());
        for command in [
            "cargo build --manifest-path",
            "cargo build --manifest-path=",
            "cargo build --manifest-path --",
            "cargo build --manifest-path missing/Cargo.toml",
            "cargo build --manifest-path ../outside/Cargo.toml",
            "cargo build --manifest-path Cargo.toml --manifest-path Cargo.toml",
            "env -C ignored cargo build --manifest-path Cargo.toml",
            "cargo -C ignored build --manifest-path Cargo.toml",
        ] {
            assert!(
                selected_manifest_root(command, &root, &policy).is_err(),
                "{command}"
            );
        }
    }

    #[test]
    fn selected_standalone_crates_plan_external_dependencies_and_verify_collapsed_packages() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().canonicalize().unwrap();
        let policy = PathTopologyPolicy::new(base.clone(), base.clone());
        let repo = base.join("repo");
        let a = repo.join("crates/a");
        let b = repo.join("crates/b");
        let dep = base.join("dep");
        package(
            &a,
            "selected_a",
            "[dependencies]\nexternal_dep = { path = \"../../../dep\" }\n",
        );
        package(&b, "selected_b", "");
        package(&dep, "external_dep", "");
        assert_eq!(a.join("../../../dep").canonicalize().unwrap(), dep);
        let reporter = HookReporter::new(OutputVisibility::None);
        for (name, selected, external) in [("a", &a, true), ("b", &b, false)] {
            let command =
                format!("cargo test --manifest-path crates/{name}/Cargo.toml --all-targets");
            let entry = selected_manifest_root(&command, &repo, &policy)
                .unwrap()
                .unwrap();
            assert_eq!(&entry, selected);
            let graph = build_dependency_runtime_plan(
                &entry,
                Some(CompilationKind::CargoTest),
                &reporter,
                &policy,
            );
            assert!(graph.fail_open_decision.is_none(), "{graph:?}");
            assert_eq!(graph.sync_roots.contains(&dep), external);
            let plan = build_sync_closure_plan(&graph.sync_roots, &repo, "fixture", &policy);
            assert_eq!(plan.iter().filter(|entry| entry.is_primary).count(), 1);
            assert!(
                plan.iter()
                    .any(|entry| entry.is_primary && entry.local_root == repo)
            );
            assert!(
                !plan.iter().any(|entry| &entry.local_root == selected),
                "nested package must stay collapsed into repository sync"
            );
            let transfers: Vec<_> = plan
                .into_iter()
                .map(|mut entry| {
                    entry.remote_root = base
                        .join("remote")
                        .join(entry.local_root.strip_prefix(&base).unwrap())
                        .to_string_lossy()
                        .into_owned();
                    (entry, SyncRootOutcome::Synced)
                })
                .collect();
            let outcomes =
                manifest_preflight_outcomes(&transfers, &graph.sync_roots, &policy).unwrap();
            let checks = synced_dependency_preflight_checks(&outcomes);
            let selected_remote = base.join("remote/repo/crates").join(name);
            assert!(checks.iter().any(|check| {
                Path::new(&check.required_path) == selected_remote.join("Cargo.toml")
            }));
            assert!(checks.iter().any(|check| {
                Path::new(&check.required_path) == selected_remote.join("src/lib.rs")
            }));
            assert!(!checks.iter().any(|check| {
                Path::new(&check.required_path) == base.join("remote/repo/Cargo.toml")
            }));
            let other = if name == "a" { "b" } else { "a" };
            assert!(!checks.iter().any(|check| {
                Path::new(&check.required_path)
                    .starts_with(base.join("remote/repo/crates").join(other))
            }));
            let present = checks
                .iter()
                .map(|check| check.required_path.clone())
                .collect();
            let worker = WorkerConfig::default();
            let healthy = build_dependency_preflight_report(
                &worker,
                &outcomes,
                &present,
                &Default::default(),
                None,
            );
            assert!(healthy.verified);
            for check in &checks {
                let missing = std::collections::BTreeSet::from([check.required_path.clone()]);
                let report =
                    build_dependency_preflight_report(&worker, &outcomes, &present, &missing, None);
                assert!(
                    !report.verified,
                    "missing {} must refuse",
                    check.required_path
                );
                assert!(report.evidence.iter().any(|item| {
                    item.required_path == check.required_path
                        && item.status == DependencyPreflightStatus::Missing
                }));
            }
        }
    }

    #[test]
    fn collapsed_package_inherits_failures_and_metadata_cannot_substitute_for_full_sync() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().canonicalize().unwrap();
        let policy = PathTopologyPolicy::new(base.clone(), base.clone());
        let root = base.join("repo");
        let nested = root.join("crate");
        package(&nested, "nested", "");
        let entry = SyncClosurePlanEntry {
            local_root: root,
            remote_root: "/relocated/proof/repo".into(),
            project_id: "fixture".into(),
            root_hash: "fixture".into(),
            is_primary: true,
            mode: SyncClosureMode::Full,
        };
        for (outcome, status) in [
            (
                SyncRootOutcome::Skipped {
                    reason: "not uploaded".into(),
                },
                DependencyPreflightStatus::Stale,
            ),
            (
                SyncRootOutcome::Failed {
                    error: "upload failed".into(),
                },
                DependencyPreflightStatus::Unknown,
            ),
        ] {
            let mapped = manifest_preflight_outcomes(
                &[(entry.clone(), outcome.clone())],
                std::slice::from_ref(&nested),
                &policy,
            )
            .unwrap();
            assert_eq!(mapped.len(), 1);
            assert_eq!(mapped[0].0.remote_root, "/relocated/proof/repo/crate");
            assert_eq!(mapped[0].1, outcome);
            let report = build_dependency_preflight_report(
                &WorkerConfig::default(),
                &mapped,
                &Default::default(),
                &Default::default(),
                None,
            );
            assert!(!report.verified);
            assert!(report.evidence.iter().all(|item| item.status == status));
        }
        let metadata = SyncClosurePlanEntry {
            mode: SyncClosureMode::WorkspaceMetadata,
            ..entry
        };
        assert!(
            manifest_preflight_outcomes(&[(metadata, SyncRootOutcome::Synced)], &[nested], &policy)
                .is_err()
        );
    }
}
