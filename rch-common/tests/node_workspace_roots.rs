//! Filesystem authority tests against the exported production resolver.

use rch_common::node_workspace_fs::{
    AncestorWorkspaceManager, MAX_ROOT_PARENTS, resolve_preparation_root, verify_install_root,
};
use std::path::Path;

fn project(workspaces: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("package.json"),
        format!(r#"{{"workspaces":{workspaces}}}"#),
    )
    .unwrap();
    dir
}

fn member(root: &Path, name: &str, contents: &str) {
    let dir = root.join(name);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("package.json"), contents).unwrap();
}

#[test]
fn member_preparation_uses_the_declared_locked_ancestor() {
    for lock in [
        "package-lock.json",
        "npm-shrinkwrap.json",
        "bun.lock",
        "bun.lockb",
        "yarn.lock",
    ] {
        let dir = project(r#"["packages/*"]"#);
        std::fs::write(dir.path().join(lock), b"locked").unwrap();
        member(dir.path(), "packages/app", r#"{"name":"app"}"#);
        let root = resolve_preparation_root(&dir.path().join("packages/app"), None).unwrap();
        assert_eq!(
            root.as_os_str(),
            dir.path().canonicalize().unwrap().as_os_str(),
            "{lock}"
        );
    }
}

#[test]
fn local_lock_preserves_independent_project_and_conflicts_refuse() {
    let dir = project(r#"["packages/*"]"#);
    std::fs::write(dir.path().join("bun.lock"), b"root").unwrap();
    member(dir.path(), "packages/app", r#"{"name":"app"}"#);
    let invocation = dir.path().join("packages/app");
    std::fs::write(invocation.join("package-lock.json"), b"member").unwrap();
    assert_eq!(
        resolve_preparation_root(&invocation, None).unwrap(),
        invocation.canonicalize().unwrap()
    );
    std::fs::write(invocation.join("pnpm-lock.yaml"), b"conflict").unwrap();
    assert!(
        resolve_preparation_root(&invocation, None)
            .unwrap_err()
            .to_string()
            .contains("conflicting")
    );
}

#[test]
fn undeclared_locked_ancestor_stops_upward_workspace_search() {
    let dir = project(r#"["packages/**"]"#);
    std::fs::write(dir.path().join("package-lock.json"), b"root").unwrap();
    member(dir.path(), "packages", r#"{"workspaces":["other/*"]}"#);
    std::fs::write(dir.path().join("packages/yarn.lock"), b"independent").unwrap();
    member(dir.path(), "packages/app", r#"{"name":"app"}"#);
    let invocation = dir.path().join("packages/app");
    assert_eq!(
        resolve_preparation_root(&invocation, None).unwrap(),
        invocation.canonicalize().unwrap()
    );
}

#[test]
fn pnpm_requires_explicit_membership_in_its_yaml() {
    let dir = project(r#"["packages/*"]"#);
    std::fs::write(dir.path().join("pnpm-lock.yaml"), b"root").unwrap();
    member(dir.path(), "packages/app", r#"{"name":"app"}"#);
    let invocation = dir.path().join("packages/app");
    assert_eq!(
        resolve_preparation_root(&invocation, None).unwrap(),
        invocation.canonicalize().unwrap()
    );
    std::fs::write(
        dir.path().join("pnpm-workspace.yaml"),
        b"packages: ['packages/*']\n",
    )
    .unwrap();
    assert_eq!(
        resolve_preparation_root(&invocation, None).unwrap(),
        dir.path().canonicalize().unwrap()
    );
    std::fs::write(
        dir.path().join("pnpm-workspace.yaml"),
        b"packages: ['packages/*', '!packages/app']\n",
    )
    .unwrap();
    assert_eq!(
        resolve_preparation_root(&invocation, None).unwrap(),
        invocation.canonicalize().unwrap()
    );
}

#[test]
fn ancestry_boundary_is_inclusive_and_never_reads_unowned_authority() {
    let dir = project(r#"["packages/*"]"#);
    std::fs::write(dir.path().join("package-lock.json"), b"locked").unwrap();
    member(dir.path(), "packages/app", r#"{"name":"app"}"#);
    let invocation = dir.path().join("packages/app");
    assert_eq!(
        resolve_preparation_root(&invocation, Some(dir.path())).unwrap(),
        dir.path().canonicalize().unwrap()
    );
    assert_eq!(
        resolve_preparation_root(&invocation, Some(&invocation)).unwrap(),
        invocation.canonicalize().unwrap()
    );
    assert!(resolve_preparation_root(dir.path(), Some(&invocation)).is_err());
    assert!(resolve_preparation_root(&invocation, Some(&dir.path().join("package.json"))).is_err());
    // Invalid authority outside the caller's boundary is neither parsed nor selected.
    std::fs::write(dir.path().join("package.json"), b"invalid JSON").unwrap();
    assert_eq!(
        resolve_preparation_root(&invocation, Some(&invocation)).unwrap(),
        invocation.canonicalize().unwrap()
    );
    assert!(resolve_preparation_root(&invocation, None).is_err());
}

#[test]
fn subdirectory_invocation_resolves_intermediate_package_then_frozen_workspace() {
    let dir = project(r#"["packages/*"]"#);
    std::fs::write(dir.path().join("package-lock.json"), b"root").unwrap();
    member(dir.path(), "packages/app", r#"{"name":"app"}"#);
    let invocation = dir.path().join("packages/app/src/nested");
    std::fs::create_dir_all(&invocation).unwrap();
    assert_eq!(
        resolve_preparation_root(&invocation, Some(dir.path())).unwrap(),
        dir.path().canonicalize().unwrap()
    );
    // A nearer frozen package is returned even though it is neither the
    // selected ancestry boundary nor the caller's actual directory.
    let package = dir.path().join("packages/app");
    std::fs::write(package.join("bun.lock"), b"independent").unwrap();
    assert_eq!(
        resolve_preparation_root(&invocation, Some(dir.path())).unwrap(),
        package.canonicalize().unwrap()
    );
}

#[test]
fn lock_free_parent_and_manifest_free_tree_never_widen_the_invocation() {
    let dir = project(r#"["packages/*"]"#);
    let invocation = dir.path().join("packages/app/src");
    std::fs::create_dir_all(&invocation).unwrap();
    assert_eq!(
        resolve_preparation_root(&invocation, Some(dir.path())).unwrap(),
        invocation.canonicalize().unwrap()
    );
    let empty = tempfile::tempdir().unwrap();
    assert_eq!(
        resolve_preparation_root(empty.path(), Some(empty.path())).unwrap(),
        empty.path().canonicalize().unwrap()
    );
}

#[test]
fn a_stray_lock_below_the_nearest_package_does_not_become_install_authority() {
    let dir = project(r#"[]"#);
    std::fs::write(dir.path().join("package-lock.json"), b"package lock").unwrap();
    let invocation = dir.path().join("src");
    std::fs::create_dir(&invocation).unwrap();
    std::fs::write(invocation.join("bun.lock"), b"not a package").unwrap();
    assert_eq!(
        resolve_preparation_root(&invocation, Some(dir.path())).unwrap(),
        dir.path().canonicalize().unwrap()
    );
}

#[test]
fn bun_and_classic_yarn_refuse_an_owning_ancestor_even_without_its_lock() {
    let dir = project(r#"["packages/*"]"#);
    member(dir.path(), "packages/app", r#"{"name":"app"}"#);
    let package = dir.path().join("packages/app");
    for manager in [
        AncestorWorkspaceManager::Bun,
        AncestorWorkspaceManager::YarnClassic,
    ] {
        let error = verify_install_root(&package, manager).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("outside the selected preparation root"),
            "{error:#}"
        );
    }
    // Only a read-only query occurred: neither root receives dependency outputs.
    assert!(!dir.path().join("node_modules").exists());
    assert!(!package.join("node_modules").exists());
}

#[test]
fn native_ancestor_query_stops_at_nearest_nonmatching_workspace_and_refuses_ambiguity() {
    let dir = project(r#"["packages/**"]"#);
    member(dir.path(), "packages", r#"{"workspaces":["other/*"]}"#);
    member(dir.path(), "packages/app", r#"{"name":"app"}"#);
    let package = dir.path().join("packages/app");
    for manager in [
        AncestorWorkspaceManager::Bun,
        AncestorWorkspaceManager::YarnClassic,
    ] {
        verify_install_root(&package, manager).unwrap();
    }
    std::fs::write(
        dir.path().join("packages/package.json"),
        br#"{"workspaces":["{app,other}"]}"#,
    )
    .unwrap();
    for manager in [
        AncestorWorkspaceManager::Bun,
        AncestorWorkspaceManager::YarnClassic,
    ] {
        assert!(verify_install_root(&package, manager).is_err());
    }
}

#[test]
fn discovery_depth_is_bounded_before_selecting_a_remote_root() {
    let dir = project(r#"["packages/**"]"#);
    std::fs::write(dir.path().join("package-lock.json"), b"root").unwrap();
    let relative = std::iter::repeat_n("child", MAX_ROOT_PARENTS + 1)
        .collect::<Vec<_>>()
        .join("/");
    member(dir.path(), &relative, r#"{"name":"deep"}"#);
    assert!(
        resolve_preparation_root(&dir.path().join(relative), Some(dir.path()))
            .unwrap_err()
            .to_string()
            .contains("depth limit")
    );
}

#[cfg(unix)]
#[test]
fn linked_or_special_workspace_authority_is_refused_without_blocking() {
    let dir = project(r#"["packages/*"]"#);
    member(dir.path(), "packages/app", r#"{"name":"app"}"#);
    std::os::unix::fs::symlink("package.json", dir.path().join("package-lock.json")).unwrap();
    assert!(resolve_preparation_root(&dir.path().join("packages/app"), None).is_err());

    let fifo = project(r#"["packages/*"]"#);
    std::fs::write(fifo.path().join("pnpm-lock.yaml"), b"root").unwrap();
    member(fifo.path(), "packages/app", r#"{"name":"app"}"#);
    rustix::fs::mkfifoat(
        rustix::fs::CWD,
        fifo.path().join("pnpm-workspace.yaml"),
        rustix::fs::Mode::RUSR,
    )
    .unwrap();
    assert!(resolve_preparation_root(&fifo.path().join("packages/app"), None).is_err());
}
