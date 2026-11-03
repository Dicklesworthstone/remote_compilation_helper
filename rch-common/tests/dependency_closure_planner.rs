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

// Keep registry/Git fixtures deterministic and offline without changing the
// environment of other tests. Cargo may decline locked metadata here; the real
// planner must then use its manifest fallback and still materialize local paths.
fn run_with_offline_cargo(test_name: &str) -> bool {
    const CHILD_ENV: &str = "RCH_PLANNER_OFFLINE_TEST";
    if std::env::var(CHILD_ENV).as_deref() == Ok(test_name) {
        return true;
    }
    let cargo_fixture = TopologyFixture::new("offline-cargo-home");
    let cargo_home = cargo_fixture.root.join("cargo-home");
    fs::create_dir_all(&cargo_home).unwrap();
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", test_name, "--nocapture"])
        .env(CHILD_ENV, test_name)
        .env("CARGO_HOME", &cargo_home)
        .env("CARGO_NET_OFFLINE", "true")
        .output()
        .expect("run isolated offline planner test");
    assert!(
        output.status.success()
            && String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed;"),
        "{test_name}:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    false
}

#[test]
fn planner_root_workspace_inheritance_preserves_successful_locked_metadata() {
    if !run_with_offline_cargo(
        "planner_root_workspace_inheritance_preserves_successful_locked_metadata",
    ) {
        return;
    }
    let fixture = TopologyFixture::new("root-workspace-locked-metadata");
    let app = fixture.canonical_root.join("app");
    let upstream = fixture.root.join("git-upstream");
    write_bin_crate(&app, "root_workspace_git", &[]);
    write_lib_crate(&upstream, "git_dep", &[]);
    for args in [
        vec!["init", "--quiet", "--initial-branch=main"],
        vec!["add", "Cargo.toml", "src/lib.rs"],
        vec![
            "-c",
            "user.name=RCH fixture",
            "-c",
            "user.email=rch-fixture@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "--quiet",
            "-m",
            "Local Git dependency fixture",
        ],
    ] {
        let output = std::process::Command::new("git")
            .args(&args)
            .current_dir(&upstream)
            .output()
            .expect("create local Git dependency");
        assert!(
            output.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let git_url = format!("file://{}", upstream.canonicalize().unwrap().display());
    fs::write(
        app.join("Cargo.toml"),
        format!(
            "[package]\nname = \"root_workspace_git\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\ngit_dep.workspace = true\n\n[workspace]\nmembers = [\".\"]\nresolver = \"2\"\n\n[workspace.dependencies]\ngit_dep = {{ git = {git_url:?} }}\n"
        ),
    )
    .unwrap();
    // Only a local file:// repository is fetched, into this test's isolated
    // Cargo home outside the source topology. No public registry is needed.
    let lock = std::process::Command::new("cargo")
        .args(["generate-lockfile", "--manifest-path"])
        .arg(app.join("Cargo.toml"))
        .env("CARGO_NET_OFFLINE", "false")
        .output()
        .expect("bootstrap locked local Git dependency");
    assert!(
        lock.status.success(),
        "{}",
        String::from_utf8_lossy(&lock.stderr)
    );
    let lock_path = app.join("Cargo.lock");
    let lock_bytes = fs::read(&lock_path).unwrap();
    let lock_modified = fs::metadata(&lock_path).unwrap().modified().unwrap();
    let metadata = std::process::Command::new("cargo")
        .args([
            "metadata",
            "--locked",
            "--offline",
            "--format-version",
            "1",
            "--manifest-path",
        ])
        .arg(app.join("Cargo.toml"))
        .output()
        .expect("real locked Cargo metadata");
    assert!(
        metadata.status.success(),
        "{}",
        String::from_utf8_lossy(&metadata.stderr)
    );
    let document: serde_json::Value = serde_json::from_slice(&metadata.stdout).unwrap();
    assert!(
        document["packages"]
            .as_array()
            .unwrap()
            .iter()
            .any(|package| {
                package["name"] == "git_dep"
                    && package["source"]
                        .as_str()
                        .is_some_and(|source| source.starts_with("git+file://"))
            })
    );
    let plan = build_dependency_closure_plan_with_policy(&app, &fixture.policy());
    assert!(plan.is_ready(), "{plan:#?}");
    assert_eq!(plan.sync_roots(), vec![app.canonicalize().unwrap()]);
    assert_eq!(fs::read(&lock_path).unwrap(), lock_bytes);
    assert_eq!(
        fs::metadata(&lock_path).unwrap().modified().unwrap(),
        lock_modified
    );
}

#[test]
fn planner_root_workspace_inherits_registry_git_and_optional_path_dependencies() {
    if !run_with_offline_cargo(
        "planner_root_workspace_inherits_registry_git_and_optional_path_dependencies",
    ) {
        return;
    }
    let fixture = TopologyFixture::new("root-workspace-inheritance");
    let app = fixture.canonical_root.join("app");
    let optional = fixture.canonical_root.join("optional");
    write_bin_crate(&app, "root_workspace_app", &[]);
    write_lib_crate(&optional, "optional_dep", &[]);
    let workspace = r#"
[workspace]
members = ["."]
resolver = "2"

[workspace.dependencies]
serde = { version = "1", features = ["derive"] }
tokio = { version = "1", features = ["full"] }
git_dep = { git = "https://example.invalid/rch-workspace-fixture.git" }
optional_dep = { path = "../optional" }
"#;

    for dependencies in [
        r#"serde = { version = "1", features = ["derive"] }
tokio = { version = "1", features = ["full"] }
git_dep = { git = "https://example.invalid/rch-workspace-fixture.git" }
optional_dep = { path = "../optional", optional = true }"#,
        r#"serde.workspace = true
tokio.workspace = true
git_dep.workspace = true
optional_dep = { workspace = true, optional = true }"#,
    ] {
        fs::write(
            app.join("Cargo.toml"),
            format!(
                "[package]\nname = \"root_workspace_app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\n{dependencies}\n{workspace}"
            ),
        )
        .unwrap();
        let plan = build_dependency_closure_plan_with_policy(&app, &fixture.policy());
        assert!(plan.is_ready(), "{dependencies}: {plan:#?}");
        assert_eq!(
            plan.sync_roots()
                .into_iter()
                .collect::<std::collections::BTreeSet<_>>(),
            std::collections::BTreeSet::from([
                app.canonicalize().unwrap(),
                optional.canonicalize().unwrap(),
            ]),
            "only local packages belong in the source-sync closure"
        );
        let optional_action = plan
            .sync_order
            .iter()
            .find(|action| action.package_name == "optional_dep")
            .expect("inactive inherited path must be materialized");
        assert!(
            optional_action
                .metadata
                .notes
                .iter()
                .any(|note| note == "materialization_only=true")
        );
        assert!(
            !app.join("Cargo.lock").exists(),
            "planning must not create a lockfile when locked metadata is unavailable"
        );
    }
}

#[test]
fn planner_root_workspace_still_refuses_missing_inherited_optional_paths() {
    if !run_with_offline_cargo(
        "planner_root_workspace_still_refuses_missing_inherited_optional_paths",
    ) {
        return;
    }
    let fixture = TopologyFixture::new("root-workspace-missing-inherited-path");
    let app = fixture.canonical_root.join("app");
    write_bin_crate(&app, "root_workspace_missing_path", &[]);
    fs::write(
        app.join("Cargo.toml"),
        r#"[package]
name = "root_workspace_missing_path"
version = "0.1.0"
edition = "2021"

[dependencies]
serde.workspace = true
missing_dep = { workspace = true, optional = true }

[workspace]
members = ["."]
resolver = "2"

[workspace.dependencies]
serde = "1"
missing_dep = { path = "../missing" }
"#,
    )
    .unwrap();

    let plan = build_dependency_closure_plan_with_policy(&app, &fixture.policy());
    assert_eq!(plan.state, DependencyClosurePlanState::FailOpen);
    assert!(plan.fail_open);
    assert!(plan.sync_order.is_empty());
    assert!(
        plan.issues
            .iter()
            .any(|issue| issue.code == "materialization-closure-unavailable"),
        "the missing local path must retain its materialization refusal: {plan:#?}"
    );
    let reason = plan.fail_open_reason.as_deref().unwrap();
    assert!(reason.contains("missing path dependency"), "{reason}");
    assert!(reason.contains("missing"), "{reason}");
}

#[test]
fn planner_keeps_excluded_fixture_bytes_inert_until_the_same_manifest_is_active() {
    let fixture = TopologyFixture::new("selected-fixture-members");
    let workspace = fixture.canonical_root.join("workspace");
    let app = workspace.join("app");
    let negative = workspace.join("fixtures/negative");
    write_lib_crate(&app, "app", &[]);
    write_lib_crate(&negative, "negative", &[]);
    let app_manifest = "[package]\nname='app'\nversion='0.1.0'\nedition='2021'\n";
    let root = "[workspace]\nmembers=['app','fixtures/*']\nexclude=['fixtures']\ndefault-members=['app','fixtures/negative']\nresolver='2'\n";
    let negative_manifest = "[package]\nname='negative'\nversion='0.1.0'\nedition='2021'\n[dependencies]\nforeign={path='/absolute/unpublished'}\n";
    fs::write(workspace.join("Cargo.toml"), root).unwrap();
    fs::write(app.join("Cargo.toml"), app_manifest).unwrap();
    fs::write(negative.join("Cargo.toml"), negative_manifest).unwrap();
    for entrypoint in [&workspace, &app] {
        let plan = build_dependency_closure_plan_with_policy(entrypoint, &fixture.policy());
        assert!(plan.is_ready(), "{plan:#?}");
        assert!(!plan.sync_roots().contains(&negative));
        assert_eq!(
            fs::read(negative.join("Cargo.toml")).unwrap(),
            negative_manifest.as_bytes()
        );
    }
    for section in [
        "dependencies",
        "dev-dependencies",
        "build-dependencies",
        "dev_dependencies",
        "build_dependencies",
        "target.'cfg(windows)'.dependencies",
        "target.'cfg(windows)'.dev-dependencies",
        "target.'cfg(windows)'.build-dependencies",
        "target.'cfg(windows)'.dev_dependencies",
        "target.'cfg(windows)'.build_dependencies",
    ] {
        fs::write(app.join("Cargo.toml"), format!("{app_manifest}\n[{section}]\nrenamed={{package='negative',path='../fixtures/negative'}}\n")).unwrap();
        let plan = build_dependency_closure_plan_with_policy(&app, &fixture.policy());
        assert_eq!(
            plan.state,
            DependencyClosurePlanState::FailOpen,
            "{section}: {plan:#?}"
        );
        assert!(
            format!("{plan:#?}").contains("/absolute/unpublished"),
            "{section}: {plan:#?}"
        );
        assert_eq!(
            fs::read(negative.join("Cargo.toml")).unwrap(),
            negative_manifest.as_bytes()
        );
    }
    fs::write(app.join("Cargo.toml"), app_manifest).unwrap();
    for active in [
        "[workspace]\nmembers=['app','fixtures/*','fixtures/negative']\nexclude=['fixtures']\nresolver='2'\n",
        "[workspace]\nmembers=['app','fixtures/*']\nexclude=['fixtures/n*']\nresolver='2'\n",
    ] {
        fs::write(workspace.join("Cargo.toml"), active).unwrap();
        let plan = build_dependency_closure_plan_with_policy(&workspace, &fixture.policy());
        assert_eq!(
            plan.state,
            DependencyClosurePlanState::FailOpen,
            "{plan:#?}"
        );
        assert_eq!(
            fs::read(negative.join("Cargo.toml")).unwrap(),
            negative_manifest.as_bytes()
        );
    }
    fs::write(workspace.join("Cargo.toml"), root).unwrap();
    let restored = build_dependency_closure_plan_with_policy(&workspace, &fixture.policy());
    assert!(restored.is_ready(), "{restored:#?}");
    assert_eq!(
        fs::read(negative.join("Cargo.toml")).unwrap(),
        negative_manifest.as_bytes()
    );
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
fn planner_checks_materialization_after_active_graph_failure() {
    let fixture = TopologyFixture::new("graph-failure-materialization");
    let app = fixture.canonical_root.join("app");
    write_lib_crate(&app, "app", &[]);
    for (dependencies, source_issue) in [
        (
            "[dependencies]\nmissing = { path = '../missing' }\n",
            "missing-path-dependency",
        ),
        (
            "[workspace.dependencies]\ninvalid = { path = 123 }\n",
            "manifest-parse-failure",
        ),
    ] {
        fs::write(
            app.join("Cargo.toml"),
            format!("[package]\nname = 'app'\nversion = '0.1.0'\nedition = '2021'\n{dependencies}"),
        )
        .unwrap();
        let plan = build_dependency_closure_plan_with_policy(&app, &fixture.policy());
        assert_eq!(plan.state, DependencyClosurePlanState::FailOpen);
        assert!(plan.fail_open);
        assert!(plan.sync_order.is_empty());
        for expected in ["materialization-closure-unavailable", source_issue] {
            assert!(
                plan.issues.iter().any(|issue| issue.code == expected),
                "{dependencies}: missing {expected}: {plan:#?}"
            );
        }
    }
}

#[test]
fn planner_preserves_graph_failure_when_materialization_is_complete() {
    let fixture = TopologyFixture::new("graph-failure-complete-materialization");
    let first = fixture.canonical_root.join("first");
    let second = fixture.canonical_root.join("second");
    write_lib_crate(&first, "first", &[("second", "../second")]);
    write_lib_crate(&second, "second", &[("first", "../first")]);

    let materialization =
        rch_common::cargo_path_deps::resolve_cargo_path_materialization_closure_with_policy(
            &first,
            &fixture.policy(),
        )
        .expect("cycles do not prevent source materialization");
    assert_eq!(materialization.packages.len(), 2);
    let plan = build_dependency_closure_plan_with_policy(&first, &fixture.policy());
    assert_eq!(plan.state, DependencyClosurePlanState::FailOpen);
    assert_eq!(plan.issues.len(), 1, "{plan:#?}");
    assert_eq!(plan.issues[0].code, "cyclic-path-dependency");
    assert!(plan.sync_order.is_empty());
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
