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
use rch_common::cargo_args::{is_manifest_selector_candidate, parse_manifest_selection};
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
        .any(|word| is_manifest_selector_candidate(word))
    {
        return Ok(None);
    }
    let (words, cargo_index) = managed_clean_overlay_cargo_tokens(command)?;
    let selection =
        parse_manifest_selection(&words[cargo_index + 1..]).map_err(anyhow::Error::msg)?;
    let changes_directory = selection.changes_directory
        || words[..cargo_index]
            .iter()
            .any(|word| matches!(word.as_str(), "-C" | "--chdir") || word.starts_with("--chdir="));
    let Some(selected) = selection.manifest else {
        return Ok(None);
    };
    anyhow::ensure!(
        !changes_directory,
        "Cargo manifest selection with env --chdir/-C or cargo -C requires an explicit working-directory mapping"
    );
    let manifest = invocation_root.join(selected.value);
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
    let plan: Vec<_> = transfers.iter().map(|(entry, _)| entry.clone()).collect();
    Ok(manifest_preflight_projection(&plan, package_roots, policy)?
        .into_iter()
        .map(|(index, entry)| (entry, transfers[index].1.clone()))
        .collect())
}

/// Use the same package authorities before upload and after transfer. The
/// index identifies the covering transfer, so local source selection never
/// invents a successful sync outcome or uses a nested package's own filters.
pub(super) fn manifest_preflight_projection(
    transfers: &[SyncClosurePlanEntry],
    package_roots: &[PathBuf],
    policy: &PathTopologyPolicy,
) -> anyhow::Result<Vec<(usize, SyncClosurePlanEntry)>> {
    anyhow::ensure!(
        !package_roots.is_empty(),
        "selected Cargo closure has no package roots"
    );
    let mut checks = BTreeMap::new();
    for (index, entry) in transfers.iter().enumerate() {
        // Only a primary *transfer basis* may lack a manifest. All dependency
        // and workspace-metadata entries keep their existing requirements,
        // even when their local manifest has disappeared since planning.
        if !entry.is_primary
            || entry.mode == SyncClosureMode::WorkspaceMetadata
            || entry.local_root.join("Cargo.toml").is_file()
        {
            checks.insert(
                (entry.local_root.clone(), entry.mode),
                (index, entry.clone()),
            );
        }
    }
    for root in package_roots {
        let root = canonicalize_sync_root_for_plan(root, policy);
        let (index, cover) = transfers
            .iter()
            .enumerate()
            .filter(|(_, entry)| {
                entry.mode == SyncClosureMode::Full && root.starts_with(&entry.local_root)
            })
            .max_by_key(|(_, entry)| entry.local_root.components().count())
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
        checks.insert((entry.local_root.clone(), entry.mode), (index, entry));
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
        let relative = "crate with ' quotes; $cash/Cargo.toml";
        for value in [path.to_str().unwrap(), relative] {
            for selector in [
                vec!["--manifest-path".to_owned(), value.to_owned()],
                vec![format!("--manifest-path={value}")],
                vec!["-m".to_owned(), value.to_owned()],
                vec![format!("-m{value}")],
                vec![format!("-m={value}")],
                vec!["-qm".to_owned(), value.to_owned()],
                vec![format!("-qvm{value}")],
                vec![format!("-qvm={value}")],
            ] {
                for prefix in [
                    vec!["cargo", "test"],
                    vec!["cargo", "+nightly", "test"],
                    vec![
                        "env",
                        "--",
                        "KEY=value",
                        "rustup",
                        "run",
                        "nightly",
                        "cargo",
                        "test",
                    ],
                    vec!["/usr/bin/time", "-f", "cargo", "cargo", "test"],
                ] {
                    let command = shell_words::join(
                        prefix
                            .into_iter()
                            .chain(selector.iter().map(String::as_str)),
                    );
                    assert_eq!(
                        selected_manifest_root(&command, &base, &policy).unwrap(),
                        Some(root.clone()),
                        "{command}"
                    );
                }
            }
        }
        for command in [
            "cargo test -- --manifest-path nonexistent/Cargo.toml",
            "cargo test -- -m nonexistent/Cargo.toml",
            "cargo nextest run -- --manifest-path=nonexistent/Cargo.toml",
            "env -- cargo test -- --manifest-path=nonexistent/Cargo.toml",
            "env -- cargo test -- -qmnonexistent/Cargo.toml",
            "cargo test --config --manifest-path=not-a-selector",
            "cargo test --features -mnot-a-selector",
            "cargo test -F -qmnot-a-selector",
            "cargo test -p -m=not-a-selector",
            "cargo test -Z -qmnot-a-selector",
            "cargo test -F-mnot-a-selector",
            "cargo test -qF -mnot-a-selector",
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
            "cargo build -m",
            "cargo build -m=",
            "cargo build -m --",
            "cargo build -qm",
            "cargo build -qvm=",
            "cargo build --manifest-path missing/Cargo.toml",
            "cargo build -mmissing/Cargo.toml",
            "cargo build --manifest-path ../outside/Cargo.toml",
            "cargo build -m=../outside/Cargo.toml",
            "cargo build --manifest-path Cargo.toml --manifest-path Cargo.toml",
            "cargo build -m Cargo.toml --manifest-path Cargo.toml",
            "cargo build --manifest-path Cargo.toml -qmCargo.toml",
            "cargo build -mCargo.toml -qvm=Cargo.toml",
            "env -C ignored cargo build --manifest-path Cargo.toml",
            "cargo -C ignored build --manifest-path Cargo.toml",
            "env -C ignored cargo build -m Cargo.toml",
            "cargo -qCignored build -m Cargo.toml",
            "cargo build -mCargo.toml -qC ignored",
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
        for (name, selected, external, selector) in
            [("a", &a, true, "-m "), ("b", &b, false, "-qvm=")]
        {
            let command = format!("cargo test {selector}crates/{name}/Cargo.toml --all-targets");
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

    #[cfg(unix)]
    #[tokio::test]
    async fn manifest_selection_preflight_uses_covering_repository_filters() {
        use super::super::super::dependency_closure::{
            DependencyPreflightFailure, verify_selected_dependency_inputs,
        };
        use crate::transfer::TransferPipeline;
        use rch_common::TransferConfig;

        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().canonicalize().unwrap();
        let repo = base.join("manifestless-repository");
        let member = repo.join("crates/selected");
        package(&member, "selected", "");
        std::fs::create_dir_all(member.join("tests")).unwrap();
        std::fs::write(member.join("tests/ignored.rs"), "#[test] fn fixture() {}\n").unwrap();
        std::fs::write(
            repo.join(".rchignore"),
            "/crates/selected/tests/ignored.rs\n",
        )
        .unwrap();
        // This nested policy is not the policy of the covering transfer.
        std::fs::write(member.join(".rchignore"), "# nothing excluded here\n").unwrap();
        let policy = PathTopologyPolicy::new(base.clone(), base);
        let plan = vec![SyncClosurePlanEntry {
            local_root: repo.clone(),
            remote_root: "/worker/owned/repository".into(),
            project_id: "selected".into(),
            root_hash: "fixture".into(),
            is_primary: true,
            mode: SyncClosureMode::Full,
        }];
        let projection = manifest_preflight_projection(&plan, &[member], &policy).unwrap();
        assert_eq!(projection.len(), 1);
        assert_eq!(projection[0].0, 0);
        assert_eq!(
            projection[0].1.remote_root,
            "/worker/owned/repository/crates/selected"
        );
        let pipeline = TransferPipeline::new(
            repo.clone(),
            "selected".into(),
            "fixture".into(),
            TransferConfig::default(),
        );
        let failure = verify_selected_dependency_inputs(
            &WorkerConfig::default(),
            &plan[0],
            &[&projection[0].1],
            &pipeline,
            None,
        )
        .await
        .expect_err("collapsed package checks must use the repository transfer policy")
        .downcast::<DependencyPreflightFailure>()
        .unwrap();
        let summary = failure.evidence_summary();
        assert!(
            summary.contains("crates/selected/tests/ignored.rs"),
            "{summary}"
        );
        assert!(
            summary.contains(repo.join(".rchignore").to_str().unwrap()),
            "{summary}"
        );
        assert!(!summary.contains("repository/Cargo.toml"), "{summary}");

        std::fs::write(
            repo.join(".rchignore"),
            "# source entrypoint is now selected\n",
        )
        .unwrap();
        verify_selected_dependency_inputs(
            &WorkerConfig::default(),
            &plan[0],
            &[&projection[0].1],
            &pipeline,
            None,
        )
        .await
        .expect("a manifestless transfer basis must not acquire a root Cargo.toml obligation");
    }
}
