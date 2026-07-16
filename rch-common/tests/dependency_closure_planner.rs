#![cfg(unix)]

use rch_common::e2e::{MultiRepoFixtureConfig, reset_multi_repo_fixtures};
use rch_common::{
    DependencyClosurePlanState, DependencyRiskClass, DependencySyncReason, PathTopologyPolicy,
    build_dependency_closure_plan_with_policy,
};
use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(0);

struct TopologyFixture {
    root: PathBuf,
    canonical_root: PathBuf,
    alias_root: PathBuf,
}

impl TopologyFixture {
    fn new(prefix: &str) -> Self {
        let id = COUNTER.fetch_add(1, Ordering::SeqCst);
        let root = std::env::temp_dir().join(format!(
            "rch-dependency-planner-{}-{}-{}",
            prefix,
            std::process::id(),
            id
        ));
        let canonical_root = root.join("data/projects");
        let alias_root = root.join("dp");
        fs::create_dir_all(&canonical_root).expect("create canonical root");
        symlink(&canonical_root, &alias_root).expect("create alias symlink");

        Self {
            root,
            canonical_root,
            alias_root,
        }
    }

    fn policy(&self) -> PathTopologyPolicy {
        PathTopologyPolicy::new(self.canonical_root.clone(), self.alias_root.clone())
    }
}

impl Drop for TopologyFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn write_bin_crate(root: &Path, crate_name: &str, deps: &[(&str, &str)]) {
    fs::create_dir_all(root.join("src")).expect("create crate src");
    fs::write(root.join("Cargo.toml"), crate_manifest(crate_name, deps)).expect("write manifest");
    fs::write(
        root.join("src/main.rs"),
        format!("fn main() {{ println!(\"{}\"); }}\n", crate_name),
    )
    .expect("write main.rs");
}

fn write_lib_crate(root: &Path, crate_name: &str, deps: &[(&str, &str)]) {
    fs::create_dir_all(root.join("src")).expect("create crate src");
    fs::write(root.join("Cargo.toml"), crate_manifest(crate_name, deps)).expect("write manifest");
    fs::write(root.join("src/lib.rs"), "pub fn marker() {}\n").expect("write lib.rs");
}

fn crate_manifest(crate_name: &str, deps: &[(&str, &str)]) -> String {
    let mut dependencies = String::new();
    for (name, path) in deps {
        dependencies.push_str(&format!("{name} = {{ path = \"{path}\" }}\n"));
    }
    format!(
        "[package]\nname = \"{crate_name}\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\n[dependencies]\n{dependencies}"
    )
}

#[test]
fn planner_single_repo_generates_ready_plan() {
    let fixture = TopologyFixture::new("single");
    let app_root = fixture.canonical_root.join("single_repo/app");
    write_bin_crate(&app_root, "single_repo_app", &[]);

    let plan = build_dependency_closure_plan_with_policy(&app_root, &fixture.policy());

    assert_eq!(plan.state, DependencyClosurePlanState::Ready);
    assert!(!plan.fail_open);
    assert_eq!(plan.sync_order.len(), 1);
    assert_eq!(
        plan.sync_order[0].metadata.reason,
        DependencySyncReason::EntryPoint
    );
    assert_eq!(plan.sync_order[0].risk, DependencyRiskClass::Low);
    assert_eq!(plan.sync_order[0].order_index, 0);
}

#[test]
fn planner_multi_repo_produces_deterministic_dependency_first_order() {
    let fixture = TopologyFixture::new("multi");
    let config = MultiRepoFixtureConfig::new(
        fixture.canonical_root.clone(),
        fixture.alias_root.clone(),
        "planner_multi_repo",
    );
    let fixtures = reset_multi_repo_fixtures(&config).expect("generate fixture set");
    let scenario = fixtures
        .fixture("ready_relative_transitive")
        .expect("ready transitive fixture metadata");

    let plan =
        build_dependency_closure_plan_with_policy(&scenario.alias_entrypoint, &fixture.policy());

    assert_eq!(plan.state, DependencyClosurePlanState::Ready);
    assert!(!plan.fail_open);

    let expected_order = scenario
        .canonical_repo_paths
        .iter()
        .map(|path| path.canonicalize().expect("canonical fixture path"))
        .collect::<Vec<_>>();
    let observed_order = plan
        .sync_order
        .iter()
        .map(|action| action.package_root.clone())
        .collect::<Vec<_>>();
    assert_eq!(observed_order, expected_order);

    let reasons = plan
        .sync_order
        .iter()
        .map(|action| action.metadata.reason)
        .collect::<Vec<_>>();
    assert_eq!(
        reasons,
        vec![
            DependencySyncReason::TransitivePathDependency,
            DependencySyncReason::TransitivePathDependency,
            DependencySyncReason::EntryPoint,
        ]
    );
}

#[test]
fn planner_materializes_inactive_optional_cycle_as_full_sync_roots() {
    let fixture = TopologyFixture::new("optional-materialization");
    let scenario_root = fixture.canonical_root.join("optional_materialization");
    let app_root = scenario_root.join("app");
    let real_dep_root = scenario_root.join("real_dep");
    let optional_a_root = scenario_root.join("optional_a");
    let optional_b_root = scenario_root.join("optional_b");

    write_lib_crate(&real_dep_root, "real_dep", &[]);
    write_lib_crate(
        &optional_a_root,
        "optional_a",
        &[("optional_b", "../optional_b")],
    );
    write_lib_crate(
        &optional_b_root,
        "optional_b",
        &[("optional_a", "../optional_a")],
    );
    fs::create_dir_all(app_root.join("src")).expect("create app src");
    fs::write(
        app_root.join("Cargo.toml"),
        r#"[package]
name = "optional_materialization_app"
version = "0.1.0"
edition = "2024"

[dependencies]
real_dep = { path = "../real_dep" }
optional_a = { path = "../optional_a", optional = true }
"#,
    )
    .expect("write app manifest");
    fs::write(app_root.join("src/main.rs"), "fn main() {}\n").expect("write app main");

    let plan = build_dependency_closure_plan_with_policy(&app_root, &fixture.policy());

    assert!(
        plan.is_ready(),
        "the optional cycle must not enter the active topological-order calculation"
    );
    let expected_roots = [
        &app_root,
        &real_dep_root,
        &optional_a_root,
        &optional_b_root,
    ]
    .into_iter()
    .map(|root| root.canonicalize().expect("canonical fixture package"))
    .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        plan.sync_roots()
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>(),
        expected_roots,
        "all potentially activatable source roots must enter full synchronization"
    );
    for package_name in ["optional_a", "optional_b"] {
        let action = plan
            .sync_order
            .iter()
            .find(|action| action.package_name == package_name)
            .expect("materialization-only sync action");
        assert!(
            action
                .metadata
                .notes
                .iter()
                .any(|note| note == "materialization_only=true")
        );
    }
}

#[test]
fn planner_uses_workspace_root_for_inherited_optional_materialization() {
    let fixture = TopologyFixture::new("workspace-inherited-materialization");
    let scenario_root = fixture
        .canonical_root
        .join("workspace_inherited_materialization");
    let workspace_root = scenario_root.join("workspace");
    let app_root = workspace_root.join("crates/app");
    let optional_dep_root = scenario_root.join("optional_dep");

    write_lib_crate(&optional_dep_root, "workspace_optional_dep", &[]);
    fs::create_dir_all(app_root.join("src")).expect("create app src");
    fs::write(
        app_root.join("Cargo.toml"),
        r#"[package]
name = "workspace_inherited_app"
version = "0.1.0"
edition = "2024"

[dependencies]
workspace_optional_dep = { workspace = true, optional = true }
"#,
    )
    .expect("write app manifest");
    fs::write(app_root.join("src/lib.rs"), "pub fn app() {}\n").expect("write app lib");
    fs::create_dir_all(&workspace_root).expect("create workspace root");
    fs::write(
        workspace_root.join("Cargo.toml"),
        r#"[workspace]
members = ["crates/app"]
resolver = "3"

[workspace.dependencies]
workspace_optional_dep = { path = "../optional_dep" }
"#,
    )
    .expect("write workspace manifest");

    let plan = build_dependency_closure_plan_with_policy(&app_root, &fixture.policy());

    assert!(plan.is_ready());
    let app_root = app_root.canonicalize().expect("canonical app");
    let optional_dep_root = optional_dep_root
        .canonicalize()
        .expect("canonical optional dep");
    assert_eq!(
        plan.sync_roots()
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>(),
        std::collections::BTreeSet::from([app_root, optional_dep_root.clone()])
    );
    let optional_action = plan
        .sync_order
        .iter()
        .find(|action| action.package_root == optional_dep_root)
        .expect("workspace-inherited optional materialization action");
    assert!(
        optional_action
            .metadata
            .notes
            .iter()
            .any(|note| note == "materialization_only=true")
    );
}

#[test]
fn planner_marks_missing_inactive_path_as_materialization_failure() {
    let fixture = TopologyFixture::new("missing-optional-materialization");
    let app_root = fixture
        .canonical_root
        .join("missing_optional_materialization/app");
    fs::create_dir_all(app_root.join("src")).expect("create app src");
    fs::write(
        app_root.join("Cargo.toml"),
        r#"[package]
name = "missing_optional_materialization_app"
version = "0.1.0"
edition = "2024"

[dependencies]
missing_optional = { path = "../missing_optional", optional = true }
"#,
    )
    .expect("write app manifest");
    fs::write(app_root.join("src/lib.rs"), "pub fn app() {}\n").expect("write app lib");

    let plan = build_dependency_closure_plan_with_policy(&app_root, &fixture.policy());

    assert_eq!(plan.state, DependencyClosurePlanState::FailOpen);
    assert!(plan.fail_open);
    assert!(plan.sync_order.is_empty());
    assert!(
        plan.issues
            .iter()
            .any(|issue| issue.code == "materialization-closure-unavailable"),
        "missing inactive paths must be distinguished from ordinary active graph fallback"
    );
    assert!(
        plan.fail_open_reason
            .as_deref()
            .is_some_and(|reason| reason.contains("materialization closure produced"))
    );
}

#[test]
fn planner_broken_graphs_mark_fail_open_with_issues() {
    let fixture = TopologyFixture::new("broken");
    let config = MultiRepoFixtureConfig::new(
        fixture.canonical_root.clone(),
        fixture.alias_root.clone(),
        "planner_broken_graphs",
    );
    let fixtures = reset_multi_repo_fixtures(&config).expect("generate fixture set");

    for scenario_id in ["fail_invalid_manifest", "fail_outside_canonical_dep"] {
        let scenario = fixtures
            .fixture(scenario_id)
            .unwrap_or_else(|| panic!("missing fixture metadata for {scenario_id}"));

        let plan = build_dependency_closure_plan_with_policy(
            &scenario.canonical_entrypoint,
            &fixture.policy(),
        );
        assert_eq!(plan.state, DependencyClosurePlanState::FailOpen);
        assert!(plan.fail_open);
        assert!(
            !plan.issues.is_empty(),
            "expected fail-open issue metadata for {scenario_id}"
        );
        assert!(
            plan.fail_open_reason.is_some(),
            "expected fallback rationale for {scenario_id}"
        );
    }
}
