//! Source ownership and invocation mapping for ordinary Node workspace members.

use crate::transfer::{
    TransferPipeline, escape_rsync_filter_literal_component, project_id_from_path,
};
use anyhow::{Context, Result, ensure};
use rch_common::path_topology::PathTopologyPolicy;
use rch_common::{CompilationKind, TransferConfig, normalize_project_path_with_policy};
use std::path::{Component, Path, PathBuf};

/// A frozen lock and an explicit workspace declaration may widen Node source
/// selection. Neither an unrelated package.json nor a parent repository can.
pub(super) fn source_root(
    invocation: &Path,
    kind: Option<CompilationKind>,
    topology: &PathTopologyPolicy,
) -> Result<PathBuf> {
    if !matches!(
        kind,
        Some(CompilationKind::Tsc | CompilationKind::BunTest | CompilationKind::BunTypecheck)
    ) {
        return Ok(invocation.to_owned());
    }
    let normalized = normalize_project_path_with_policy(invocation, topology)
        .context("Node invocation is outside the configured source topology")?;
    ensure!(
        normalized.canonical_path() == invocation,
        "Node invocation changed during source planning"
    );
    let mut boundary = normalized.canonical_root();
    // A .git directory or worktree pointer is an ancestry boundary. Do not
    // follow its contents or search an unrelated enclosing repository.
    for (depth, ancestor) in invocation
        .ancestors()
        .take_while(|ancestor| ancestor.starts_with(normalized.canonical_root()))
        .enumerate()
    {
        ensure!(
            depth <= rch_common::node_workspace_fs::MAX_ROOT_PARENTS,
            "Node source ancestry exceeds depth limit"
        );
        match std::fs::symlink_metadata(ancestor.join(".git")) {
            Ok(_) => {
                boundary = ancestor;
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).context("inspect Node repository boundary"),
        }
    }
    // The shared reader handles commands below a package directory, and keeps
    // standalone/no-lock invocations local to their original source root.
    let root = rch_common::node_workspace_fs::resolve_preparation_root(invocation, Some(boundary))?;
    let checked = normalize_project_path_with_policy(&root, topology)
        .context("declared Node workspace is outside the configured source topology")?;
    ensure!(
        checked.canonical_path() == root && invocation.starts_with(&root),
        "Node workspace changed during source planning"
    );
    Ok(root)
}

fn invocation_directory<'a>(source: &Path, invocation: &'a Path) -> Result<&'a Path> {
    let relative = invocation
        .strip_prefix(source)
        .context("invocation directory escapes the selected source root")?;
    ensure!(
        relative
            .components()
            .all(|part| matches!(part, Component::Normal(_))),
        "invocation directory is not a literal relative source path"
    );
    let text = relative
        .to_str()
        .context("invocation directory is not UTF-8")?;
    ensure!(
        !text.contains('\\') && !text.chars().any(char::is_control),
        "invocation directory contains an unsupported path character"
    );
    Ok(relative)
}

/// Preserve the member cwd under canonical, lane, isolated-proof and Windows
/// source mappings. The source root itself remains the ownership/disk boundary.
pub(super) fn remote_invocation_root(
    remote_source: &str,
    source: &Path,
    invocation: &Path,
) -> Result<String> {
    let relative = invocation_directory(source, invocation)?;
    if relative.as_os_str().is_empty() {
        Ok(remote_source.to_owned())
    } else {
        Ok(format!(
            "{}/{}",
            remote_source.trim_end_matches('/'),
            relative.display()
        ))
    }
}

/// Keep every exclusion that previously applied to the invocation after its
/// upload root expands. The workspace's own exclusions still apply as usual.
/// Read the production filter policy, including normalized config, runtime
/// scratch and member .rchignore rules, instead of reimplementing that policy.
pub(super) fn preserve_invocation_excludes(
    mut config: TransferConfig,
    source: &Path,
    invocation: &Path,
    project_hash: &str,
) -> Result<TransferConfig> {
    let relative = invocation_directory(source, invocation)?;
    if relative.as_os_str().is_empty() {
        return Ok(config);
    }
    let prefix = relative
        .iter()
        .map(|part| {
            part.to_str()
                .map(|part| escape_rsync_filter_literal_component(part).into_owned())
                .context("invocation filter path is not UTF-8")
        })
        .collect::<Result<Vec<_>>>()?
        .join("/");
    let original = TransferPipeline::new(
        invocation.to_owned(),
        project_id_from_path(invocation),
        project_hash.to_owned(),
        config.clone(),
    );
    let workspace = TransferPipeline::new(
        source.to_owned(),
        project_id_from_path(source),
        project_hash.to_owned(),
        config.clone(),
    );
    let workspace_excludes = workspace.source_content_filter_policy().1;
    for pattern in original.source_content_filter_policy().1 {
        if !pattern.starts_with('/') && workspace_excludes.contains(&pattern) {
            // Existing suffix/basename rules already cover the member. Keep
            // their original form so tracked-input exceptions for build/,
            // dist/ and Cargo target directories retain their precedence.
            continue;
        }
        // Adding ** enables rsync's wildcard parser. A backslash which used
        // to be literal can then acquire escape semantics; refuse that case
        // rather than silently weaken a caller's source exclusion.
        ensure!(
            !pattern.contains('\\'),
            "Node workspace source expansion cannot rebase a backslash exclusion: {pattern:?}"
        );
        let rebased = match pattern.strip_prefix('/') {
            Some(anchored) => format!("/{prefix}/{anchored}"),
            None => format!("/{prefix}/**/{pattern}"),
        };
        if !config.exclude_patterns.contains(&rebased) {
            config.exclude_patterns.push(rebased);
        }
    }
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn fixture() -> (PathBuf, PathBuf, PathTopologyPolicy) {
        let storage = tempfile::tempdir().unwrap().keep().canonicalize().unwrap();
        let root = storage.join("workspace");
        let member = root.join("packages/app[1]");
        std::fs::create_dir_all(member.join("nested/cache")).unwrap();
        std::fs::create_dir_all(root.join("packages/shared")).unwrap();
        std::fs::create_dir(root.join(".git")).unwrap();
        std::fs::write(
            root.join("package.json"),
            br#"{"workspaces":["packages/*"]}"#,
        )
        .unwrap();
        std::fs::write(root.join("package-lock.json"), br#"{"lockfileVersion":3}"#).unwrap();
        std::fs::write(member.join("package.json"), br#"{"name":"app"}"#).unwrap();
        std::fs::write(
            root.join("packages/shared/package.json"),
            br#"{"name":"shared"}"#,
        )
        .unwrap();
        std::fs::write(
            root.join("packages/shared/index.ts"),
            "export const shared = 1;\n",
        )
        .unwrap();
        let topology = PathTopologyPolicy::new(storage.clone(), storage.join("alias"));
        (root, member, topology)
    }

    #[test]
    fn ordinary_node_workspace_selects_declared_full_source_and_keeps_member_cwd() {
        let (root, member, topology) = fixture();
        for kind in [
            CompilationKind::Tsc,
            CompilationKind::BunTest,
            CompilationKind::BunTypecheck,
        ] {
            assert_eq!(source_root(&member, Some(kind), &topology).unwrap(), root);
            assert_eq!(
                source_root(&member.join("nested"), Some(kind), &topology).unwrap(),
                root
            );
        }
        assert_eq!(
            source_root(&member, Some(CompilationKind::CargoBuild), &topology).unwrap(),
            member
        );
        for remote in [
            "/worker/source",
            "/worker/offroot/abc/lane-2",
            "C:/rch/workspace/hash",
        ] {
            assert_eq!(
                remote_invocation_root(remote, &root, &member).unwrap(),
                format!("{remote}/packages/app[1]")
            );
        }
        assert!(remote_invocation_root("/worker/source", &member, &root).is_err());
        assert_eq!(
            remote_invocation_root("/worker/source", &root, &member.join("nested")).unwrap(),
            "/worker/source/packages/app[1]/nested"
        );

        std::fs::write(
            member.join("package-lock.json"),
            "independent frozen package",
        )
        .unwrap();
        assert_eq!(
            source_root(
                &member.join("nested"),
                Some(CompilationKind::Tsc),
                &topology
            )
            .unwrap(),
            member
        );
    }

    #[test]
    fn ordinary_node_workspace_preserves_git_topology_and_independent_project_boundaries() {
        let (root, member, topology) = fixture();
        std::fs::write(
            root.join("package.json"),
            br#"{"workspaces":["unrelated/*"]}"#,
        )
        .unwrap();
        assert_eq!(
            source_root(&member, Some(CompilationKind::Tsc), &topology).unwrap(),
            member
        );
        std::fs::write(
            root.join("package.json"),
            br#"{"workspaces":["packages/*"]}"#,
        )
        .unwrap();
        let restricted = PathTopologyPolicy::new(member.clone(), member.join("alias"));
        assert_eq!(
            source_root(&member, Some(CompilationKind::Tsc), &restricted).unwrap(),
            member
        );

        // A nearer independent frozen package stops the search even though
        // the outer workspace would otherwise declare this member.
        std::fs::write(
            root.join("packages/package.json"),
            br#"{"name":"independent"}"#,
        )
        .unwrap();
        std::fs::write(
            root.join("packages/yarn.lock"),
            "# frozen independent project\n",
        )
        .unwrap();
        assert_eq!(
            source_root(&member, Some(CompilationKind::BunTest), &topology).unwrap(),
            member
        );

        let (_root, member, topology) = fixture();
        // Linked worktrees have a .git file, not a directory. Its external
        // target is irrelevant: the marker itself limits ancestry discovery.
        std::fs::write(
            member.join(".git"),
            "gitdir: /unrelated/worktree/metadata\n",
        )
        .unwrap();
        assert_eq!(
            source_root(&member, Some(CompilationKind::Tsc), &topology).unwrap(),
            member
        );
        let standalone = topology.canonical_root().join("standalone");
        std::fs::create_dir(&standalone).unwrap();
        assert_eq!(
            source_root(&standalone, Some(CompilationKind::BunTest), &topology).unwrap(),
            standalone
        );
        let unlocked = topology.canonical_root().join("unlocked");
        let unlocked_cwd = unlocked.join("src");
        std::fs::create_dir_all(&unlocked_cwd).unwrap();
        std::fs::write(
            unlocked.join("package.json"),
            br#"{"name":"no-frozen-owner"}"#,
        )
        .unwrap();
        assert_eq!(
            source_root(&unlocked_cwd, Some(CompilationKind::Tsc), &topology).unwrap(),
            unlocked_cwd,
            "an ancestor package.json alone cannot widen selected source"
        );
    }

    #[tokio::test]
    async fn ordinary_node_workspace_rsync_preserves_member_exclusions_and_sibling_sources() {
        let (root, member, topology) = fixture();
        for name in [
            "index.ts",
            "private.txt",
            "config-private.txt",
            "nested/private.txt",
            "nested/key.pem",
            "nested/cache/state",
        ] {
            std::fs::write(member.join(name), name).unwrap();
        }
        std::fs::write(member.join(".rchignore"), "/private.txt\n*.pem\ncache/\n").unwrap();
        std::fs::write(root.join(".rchignore"), "/root-private.txt\n").unwrap();
        std::fs::write(root.join("root-private.txt"), "workspace exclusion").unwrap();
        let config = TransferConfig {
            exclude_patterns: vec!["/config-private.txt".into()],
            ..Default::default()
        };
        let original = TransferPipeline::new(
            member.clone(),
            "app".into(),
            "fixture".into(),
            config.clone(),
        );
        let original_files: BTreeSet<_> = original
            .enumerate_source_content_files()
            .await
            .unwrap()
            .into_iter()
            .collect();
        let selected = source_root(&member, Some(CompilationKind::Tsc), &topology).unwrap();
        let config = preserve_invocation_excludes(config, &selected, &member, "fixture").unwrap();
        let expanded =
            TransferPipeline::new(selected, "workspace".into(), "fixture".into(), config);
        let expanded_files: BTreeSet<_> = expanded
            .enumerate_source_content_files()
            .await
            .unwrap()
            .into_iter()
            .collect();
        let member_relative = member.strip_prefix(&root).unwrap();
        let expanded_member: BTreeSet<_> = expanded_files
            .iter()
            .filter_map(|path| path.strip_prefix(member_relative).ok().map(Path::to_owned))
            .collect();
        assert_eq!(
            expanded_member, original_files,
            "source-root promotion changed member exclusions"
        );
        assert!(expanded_files.contains(Path::new("package-lock.json")));
        assert!(expanded_files.contains(Path::new("packages/shared/index.ts")));
        assert!(!expanded_files.contains(Path::new("root-private.txt")));
        assert!(original_files.contains(Path::new("nested/private.txt")));
        assert!(!original_files.contains(Path::new("private.txt")));
        assert!(!original_files.contains(Path::new("config-private.txt")));
        assert!(!original_files.contains(Path::new("nested/key.pem")));
        assert!(!original_files.contains(Path::new("nested/cache/state")));
    }

    #[test]
    fn ordinary_node_workspace_refuses_ambiguous_exclusion_rebasing() {
        let (root, member, _) = fixture();
        let config = TransferConfig {
            exclude_patterns: vec![r"/private\file".into()],
            ..Default::default()
        };
        assert!(
            preserve_invocation_excludes(config, &root, &member, "fixture")
                .unwrap_err()
                .to_string()
                .contains("backslash exclusion")
        );
    }
}
