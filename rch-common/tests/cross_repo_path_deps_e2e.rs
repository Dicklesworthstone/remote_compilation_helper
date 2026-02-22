#![cfg(unix)]
//! E2E scenarios for real cross-repo Cargo path dependencies (bd-vvmd.2.8).
//!
//! These scenarios exercise the full planner pipeline against deterministic multi-repo
//! fixtures, validating:
//! - Direct and transitive path dependencies (ready plans)
//! - Symlinked `/dp` alias usage (alias entrypoint produces identical closure)
//! - Out-of-root rejection, missing dependency, and invalid manifest (fail-open paths)
//! - Deterministic sync order and explicit reason codes
//! - Reliability harness integration with per-phase logging

use rch_common::e2e::{
    MultiRepoFixtureConfig, MultiRepoFixtureSet, ReliabilityLifecycleCommand,
    ReliabilityScenarioSpec, TestHarnessBuilder, reset_multi_repo_fixtures,
};
use rch_common::{
    DependencyClosurePlan, DependencyClosurePlanState, DependencyRiskClass, DependencySyncReason,
    PathTopologyPolicy, build_dependency_closure_plan_with_policy,
    resolve_cargo_path_dependency_graph_with_policy,
};
use std::fs;
use std::os::unix::fs::symlink;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

// ---------------------------------------------------------------------------
// Shared topology fixture
// ---------------------------------------------------------------------------

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
            "rch-e2e-cross-repo-{}-{}-{}",
            prefix,
            std::process::id(),
            id,
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

    fn config(&self, namespace: &str) -> MultiRepoFixtureConfig {
        MultiRepoFixtureConfig::new(
            self.canonical_root.clone(),
            self.alias_root.clone(),
            namespace.to_string(),
        )
    }

    fn reset(&self, namespace: &str) -> MultiRepoFixtureSet {
        reset_multi_repo_fixtures(&self.config(namespace)).expect("reset multi-repo fixtures")
    }
}

impl Drop for TopologyFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

// ===========================================================================
// Success-path scenarios
// ===========================================================================

#[test]
fn e2e_ready_transitive_plan_has_dependency_first_sync_order() {
    let fixture = TopologyFixture::new("ready_transitive_order");
    let set = fixture.reset("e2e_transitive_order");
    let meta = set
        .fixture("ready_relative_transitive")
        .expect("ready_relative_transitive fixture");

    let plan =
        build_dependency_closure_plan_with_policy(&meta.canonical_entrypoint, &fixture.policy());

    assert_eq!(plan.state, DependencyClosurePlanState::Ready);
    assert!(!plan.fail_open);
    assert!(plan.issues.is_empty(), "ready plan should have no issues");
    assert_eq!(
        plan.sync_order.len(),
        3,
        "three repos: core_lib, util_lib, app_main"
    );

    // Dependency-first: core_lib (leaf) → util_lib (intermediate) → app_main (entrypoint)
    let names: Vec<&str> = plan
        .sync_order
        .iter()
        .map(|a| a.package_name.as_str())
        .collect();
    assert_eq!(
        names,
        &["fixture_core_lib", "fixture_util_lib", "fixture_app_main"],
    );

    // Verify order indices are monotonically increasing
    for (i, action) in plan.sync_order.iter().enumerate() {
        assert_eq!(action.order_index, i);
    }
}

#[test]
fn e2e_ready_transitive_plan_assigns_correct_sync_reasons() {
    let fixture = TopologyFixture::new("ready_transitive_reasons");
    let set = fixture.reset("e2e_transitive_reasons");
    let meta = set
        .fixture("ready_relative_transitive")
        .expect("ready_relative_transitive fixture");

    let plan =
        build_dependency_closure_plan_with_policy(&meta.canonical_entrypoint, &fixture.policy());

    let reasons: Vec<DependencySyncReason> =
        plan.sync_order.iter().map(|a| a.metadata.reason).collect();
    assert_eq!(
        reasons,
        &[
            DependencySyncReason::TransitivePathDependency,
            DependencySyncReason::TransitivePathDependency,
            DependencySyncReason::EntryPoint,
        ],
    );
}

#[test]
fn e2e_ready_transitive_plan_assigns_appropriate_risk() {
    let fixture = TopologyFixture::new("ready_transitive_risk");
    let set = fixture.reset("e2e_transitive_risk");
    let meta = set
        .fixture("ready_relative_transitive")
        .expect("ready_relative_transitive fixture");

    let plan =
        build_dependency_closure_plan_with_policy(&meta.canonical_entrypoint, &fixture.policy());

    // Transitive dependencies get Medium risk; entrypoint gets Low
    for action in &plan.sync_order {
        match action.metadata.reason {
            DependencySyncReason::EntryPoint => {
                assert_eq!(
                    action.risk,
                    DependencyRiskClass::Low,
                    "entrypoint {} should have Low risk",
                    action.package_name,
                );
            }
            DependencySyncReason::TransitivePathDependency => {
                assert_eq!(
                    action.risk,
                    DependencyRiskClass::Medium,
                    "transitive dep {} should have Medium risk",
                    action.package_name,
                );
            }
            _ => {}
        }
    }
}

#[test]
fn e2e_ready_transitive_canonical_roots_match_expected_repos() {
    let fixture = TopologyFixture::new("ready_transitive_roots");
    let set = fixture.reset("e2e_transitive_roots");
    let meta = set
        .fixture("ready_relative_transitive")
        .expect("ready_relative_transitive fixture");

    let plan =
        build_dependency_closure_plan_with_policy(&meta.canonical_entrypoint, &fixture.policy());

    let expected_roots: Vec<PathBuf> = meta
        .canonical_repo_paths
        .iter()
        .map(|p| p.canonicalize().expect("canonicalize fixture path"))
        .collect();
    assert_eq!(plan.canonical_roots.len(), expected_roots.len());
    for expected in &expected_roots {
        assert!(
            plan.canonical_roots.contains(expected),
            "canonical_roots should contain {}",
            expected.display()
        );
    }
}

#[test]
fn e2e_ready_transitive_graph_has_correct_edges() {
    let fixture = TopologyFixture::new("ready_transitive_edges");
    let set = fixture.reset("e2e_transitive_edges");
    let meta = set
        .fixture("ready_relative_transitive")
        .expect("ready_relative_transitive fixture");

    let graph = resolve_cargo_path_dependency_graph_with_policy(
        &meta.canonical_entrypoint,
        &fixture.policy(),
    )
    .expect("graph resolution should succeed");

    assert_eq!(graph.edges.len(), 2, "app→util and util→core");

    let dep_names: Vec<&str> = graph
        .edges
        .iter()
        .map(|e| e.dependency_name.as_str())
        .collect();
    assert!(
        dep_names.contains(&"fixture_util_lib"),
        "app_main depends on util_lib"
    );
    assert!(
        dep_names.contains(&"fixture_core_lib"),
        "util_lib depends on core_lib"
    );
}

#[test]
fn e2e_ready_transitive_plan_is_serializable_round_trip() {
    let fixture = TopologyFixture::new("ready_transitive_serde");
    let set = fixture.reset("e2e_transitive_serde");
    let meta = set
        .fixture("ready_relative_transitive")
        .expect("ready_relative_transitive fixture");

    let plan =
        build_dependency_closure_plan_with_policy(&meta.canonical_entrypoint, &fixture.policy());

    let json = serde_json::to_string_pretty(&plan).expect("serialize plan");
    let deserialized: DependencyClosurePlan =
        serde_json::from_str(&json).expect("deserialize plan");
    assert_eq!(plan, deserialized, "round-trip must be lossless");
}

// ===========================================================================
// Alias entrypoint scenarios
// ===========================================================================

#[test]
fn e2e_alias_absolute_plan_is_ready() {
    let fixture = TopologyFixture::new("alias_ready");
    let set = fixture.reset("e2e_alias_ready");
    let meta = set
        .fixture("ready_alias_absolute")
        .expect("ready_alias_absolute fixture");

    let plan =
        build_dependency_closure_plan_with_policy(&meta.canonical_entrypoint, &fixture.policy());

    assert_eq!(plan.state, DependencyClosurePlanState::Ready);
    assert!(!plan.fail_open);
    assert_eq!(plan.sync_order.len(), 2, "shared_lib and alias_app");
}

#[test]
fn e2e_alias_entrypoint_resolves_to_same_plan_as_canonical() {
    let fixture = TopologyFixture::new("alias_canonical_eq");
    let set = fixture.reset("e2e_alias_canonical_eq");
    let meta = set
        .fixture("ready_alias_absolute")
        .expect("ready_alias_absolute fixture");

    let canonical_plan =
        build_dependency_closure_plan_with_policy(&meta.canonical_entrypoint, &fixture.policy());
    let alias_plan =
        build_dependency_closure_plan_with_policy(&meta.alias_entrypoint, &fixture.policy());

    assert_eq!(
        canonical_plan.state, alias_plan.state,
        "plan state must match regardless of entrypoint form"
    );
    assert_eq!(
        canonical_plan.canonical_roots, alias_plan.canonical_roots,
        "canonical roots must be identical"
    );
    assert_eq!(
        canonical_plan.sync_order.len(),
        alias_plan.sync_order.len(),
        "sync order length must match"
    );

    for (i, (canon, alias)) in canonical_plan
        .sync_order
        .iter()
        .zip(alias_plan.sync_order.iter())
        .enumerate()
    {
        assert_eq!(
            canon.package_root, alias.package_root,
            "sync action {} package_root must match",
            i
        );
        assert_eq!(
            canon.package_name, alias.package_name,
            "sync action {} package_name must match",
            i
        );
        assert_eq!(
            canon.metadata.reason, alias.metadata.reason,
            "sync action {} reason must match",
            i
        );
    }
}

#[test]
fn e2e_alias_fixture_manifest_uses_alias_prefix() {
    let fixture = TopologyFixture::new("alias_prefix");
    let set = fixture.reset("e2e_alias_prefix");
    let meta = set
        .fixture("ready_alias_absolute")
        .expect("ready_alias_absolute fixture");

    let cargo_toml = fs::read_to_string(meta.canonical_entrypoint.join("Cargo.toml"))
        .expect("read alias app Cargo.toml");

    let alias_root_str = fixture.alias_root.to_string_lossy();
    assert!(
        cargo_toml.contains(alias_root_str.as_ref()),
        "manifest must use alias root prefix in path dependency"
    );
}

#[test]
fn e2e_transitive_alias_entrypoint_produces_same_roots() {
    let fixture = TopologyFixture::new("transitive_alias");
    let set = fixture.reset("e2e_transitive_alias");
    let meta = set
        .fixture("ready_relative_transitive")
        .expect("ready_relative_transitive fixture");

    let canonical_plan =
        build_dependency_closure_plan_with_policy(&meta.canonical_entrypoint, &fixture.policy());
    let alias_plan =
        build_dependency_closure_plan_with_policy(&meta.alias_entrypoint, &fixture.policy());

    assert_eq!(canonical_plan.state, DependencyClosurePlanState::Ready);
    assert_eq!(alias_plan.state, DependencyClosurePlanState::Ready);
    assert_eq!(
        canonical_plan.canonical_roots, alias_plan.canonical_roots,
        "alias entrypoint for transitive scenario must resolve to same roots"
    );
}

// ===========================================================================
// Failure-path scenarios
// ===========================================================================

#[test]
fn e2e_missing_path_dep_produces_fail_open_with_reason() {
    let fixture = TopologyFixture::new("missing_dep");
    let set = fixture.reset("e2e_missing_dep");
    let meta = set
        .fixture("fail_missing_path_dep")
        .expect("fail_missing_path_dep fixture");

    let plan =
        build_dependency_closure_plan_with_policy(&meta.canonical_entrypoint, &fixture.policy());

    assert_eq!(plan.state, DependencyClosurePlanState::FailOpen);
    assert!(plan.fail_open);
    assert!(
        plan.fail_open_reason.is_some(),
        "fail-open plan must have explicit reason"
    );
    assert!(
        !plan.issues.is_empty(),
        "fail-open plan must have at least one issue"
    );
}

#[test]
fn e2e_missing_path_dep_issues_contain_descriptive_code() {
    let fixture = TopologyFixture::new("missing_dep_code");
    let set = fixture.reset("e2e_missing_dep_code");
    let meta = set
        .fixture("fail_missing_path_dep")
        .expect("fail_missing_path_dep fixture");

    let plan =
        build_dependency_closure_plan_with_policy(&meta.canonical_entrypoint, &fixture.policy());

    let codes: Vec<&str> = plan.issues.iter().map(|i| i.code.as_str()).collect();
    let has_relevant_code = codes.iter().any(|c| {
        c.contains("missing")
            || c.contains("metadata")
            || c.contains("resolution")
            || c.contains("graph")
    });
    assert!(
        has_relevant_code,
        "issue codes {:?} should reference the missing dependency failure",
        codes,
    );
}

#[test]
fn e2e_outside_canonical_root_produces_fail_open() {
    let fixture = TopologyFixture::new("outside_root");
    let set = fixture.reset("e2e_outside_root");
    let meta = set
        .fixture("fail_outside_canonical_dep")
        .expect("fail_outside_canonical_dep fixture");

    let plan =
        build_dependency_closure_plan_with_policy(&meta.canonical_entrypoint, &fixture.policy());

    assert_eq!(plan.state, DependencyClosurePlanState::FailOpen);
    assert!(plan.fail_open);
    assert!(
        plan.fail_open_reason.is_some(),
        "outside-root plan must have explicit fallback rationale"
    );
}

#[test]
fn e2e_outside_canonical_root_has_fail_open_entry_manifest() {
    let fixture = TopologyFixture::new("outside_root_ep");
    let set = fixture.reset("e2e_outside_root_ep");
    let meta = set
        .fixture("fail_outside_canonical_dep")
        .expect("fail_outside_canonical_dep fixture");

    let plan =
        build_dependency_closure_plan_with_policy(&meta.canonical_entrypoint, &fixture.policy());

    // Fail-open plan preserves entry_manifest_path for fallback local execution context
    assert!(
        !plan.entry_manifest_path.as_os_str().is_empty(),
        "fail-open plan must preserve entry_manifest_path for local fallback"
    );
    assert!(
        plan.fail_open_reason.is_some(),
        "outside-root must have explicit fallback rationale"
    );
}

#[test]
fn e2e_invalid_manifest_produces_fail_open() {
    let fixture = TopologyFixture::new("invalid_manifest");
    let set = fixture.reset("e2e_invalid_manifest");
    let meta = set
        .fixture("fail_invalid_manifest")
        .expect("fail_invalid_manifest fixture");

    let plan =
        build_dependency_closure_plan_with_policy(&meta.canonical_entrypoint, &fixture.policy());

    assert_eq!(plan.state, DependencyClosurePlanState::FailOpen);
    assert!(plan.fail_open);
    assert!(
        plan.fail_open_reason.is_some(),
        "invalid manifest plan must have fallback rationale"
    );
    assert!(
        !plan.issues.is_empty(),
        "invalid manifest must produce at least one issue"
    );
}

#[test]
fn e2e_invalid_manifest_graph_resolution_returns_error() {
    let fixture = TopologyFixture::new("invalid_manifest_err");
    let set = fixture.reset("e2e_invalid_manifest_err");
    let meta = set
        .fixture("fail_invalid_manifest")
        .expect("fail_invalid_manifest fixture");

    let result = resolve_cargo_path_dependency_graph_with_policy(
        &meta.canonical_entrypoint,
        &fixture.policy(),
    );

    assert!(
        result.is_err(),
        "graph resolution should fail for invalid manifest"
    );
}

#[test]
fn e2e_all_failure_fixtures_produce_non_empty_issues() {
    let fixture = TopologyFixture::new("all_failures");
    let set = fixture.reset("e2e_all_failures");

    for scenario_id in [
        "fail_missing_path_dep",
        "fail_outside_canonical_dep",
        "fail_invalid_manifest",
    ] {
        let meta = set
            .fixture(scenario_id)
            .unwrap_or_else(|| panic!("fixture {scenario_id}"));

        let plan = build_dependency_closure_plan_with_policy(
            &meta.canonical_entrypoint,
            &fixture.policy(),
        );

        assert_eq!(
            plan.state,
            DependencyClosurePlanState::FailOpen,
            "{scenario_id} should be FailOpen"
        );
        assert!(!plan.issues.is_empty(), "{scenario_id} should have issues");
        assert!(
            plan.fail_open_reason.is_some(),
            "{scenario_id} should have fail_open_reason"
        );
    }
}

#[test]
fn e2e_failure_plans_have_elevated_risk_issues() {
    let fixture = TopologyFixture::new("failure_risk");
    let set = fixture.reset("e2e_failure_risk");

    for scenario_id in [
        "fail_missing_path_dep",
        "fail_outside_canonical_dep",
        "fail_invalid_manifest",
    ] {
        let meta = set
            .fixture(scenario_id)
            .unwrap_or_else(|| panic!("fixture {scenario_id}"));

        let plan = build_dependency_closure_plan_with_policy(
            &meta.canonical_entrypoint,
            &fixture.policy(),
        );

        let max_risk = plan
            .issues
            .iter()
            .map(|i| i.risk)
            .max()
            .expect("issues should not be empty");
        assert!(
            max_risk >= DependencyRiskClass::Medium,
            "{scenario_id}: failure issues should have at least Medium risk, got {:?}",
            max_risk
        );
    }
}

// ===========================================================================
// Determinism and idempotency
// ===========================================================================

#[test]
fn e2e_plan_is_deterministic_across_repeated_invocations() {
    let fixture = TopologyFixture::new("deterministic");
    let set = fixture.reset("e2e_deterministic");
    let meta = set
        .fixture("ready_relative_transitive")
        .expect("ready_relative_transitive fixture");

    let plan_a =
        build_dependency_closure_plan_with_policy(&meta.canonical_entrypoint, &fixture.policy());
    let plan_b =
        build_dependency_closure_plan_with_policy(&meta.canonical_entrypoint, &fixture.policy());

    assert_eq!(
        plan_a, plan_b,
        "repeated invocations must produce identical plans"
    );
}

#[test]
fn e2e_fixture_reset_produces_identical_plans() {
    let fixture = TopologyFixture::new("reset_deterministic");

    let set_a = fixture.reset("e2e_reset_det");
    let meta_a = set_a
        .fixture("ready_relative_transitive")
        .expect("fixture from first reset");
    let plan_a =
        build_dependency_closure_plan_with_policy(&meta_a.canonical_entrypoint, &fixture.policy());

    // Reset again (destroys and recreates the namespace)
    let set_b = fixture.reset("e2e_reset_det");
    let meta_b = set_b
        .fixture("ready_relative_transitive")
        .expect("fixture from second reset");
    let plan_b =
        build_dependency_closure_plan_with_policy(&meta_b.canonical_entrypoint, &fixture.policy());

    assert_eq!(
        plan_a.state, plan_b.state,
        "plan state must be deterministic across resets"
    );
    assert_eq!(
        plan_a.sync_order.len(),
        plan_b.sync_order.len(),
        "sync order length must be deterministic"
    );
    for (i, (a, b)) in plan_a
        .sync_order
        .iter()
        .zip(plan_b.sync_order.iter())
        .enumerate()
    {
        assert_eq!(
            a.package_name, b.package_name,
            "sync action {} package_name must be deterministic across resets",
            i
        );
        assert_eq!(
            a.metadata.reason, b.metadata.reason,
            "sync action {} reason must be deterministic across resets",
            i
        );
    }
}

// ===========================================================================
// Reliability harness integration
// ===========================================================================

#[test]
fn e2e_reliability_harness_ready_transitive_scenario() {
    let fixture = TopologyFixture::new("rel_transitive");
    let set = fixture.reset("e2e_rel_transitive");
    let meta = set
        .fixture("ready_relative_transitive")
        .expect("ready_relative_transitive fixture");

    let harness = TestHarnessBuilder::new("cross_repo_ready_transitive")
        .cleanup_on_success(true)
        .build()
        .expect("create test harness");

    // Build the closure plan and serialize it as a per-phase artifact
    let plan =
        build_dependency_closure_plan_with_policy(&meta.canonical_entrypoint, &fixture.policy());
    let plan_json = serde_json::to_string_pretty(&plan).expect("serialize plan");
    harness
        .create_file("closure_plan.json", &plan_json)
        .expect("write closure plan artifact");

    // Run a reliability scenario with cargo metadata as a pre-check
    let scenario = ReliabilityScenarioSpec::new("cross_repo_ready_transitive")
        .with_repo_set(
            meta.canonical_repo_paths
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>(),
        )
        .add_pre_check(ReliabilityLifecycleCommand::new(
            "verify-closure-plan",
            "test",
            [plan.state == DependencyClosurePlanState::Ready]
                .iter()
                .map(|b| b.to_string()),
        ))
        .add_execute_command(ReliabilityLifecycleCommand::new(
            "cargo-metadata-check",
            "cargo",
            [
                "metadata",
                "--format-version=1",
                "--no-deps",
                "--manifest-path",
                meta.canonical_entrypoint
                    .join("Cargo.toml")
                    .to_str()
                    .unwrap(),
            ],
        ))
        .add_post_check(ReliabilityLifecycleCommand::new(
            "verify-plan-artifact",
            "test",
            [
                "-f",
                harness
                    .test_dir()
                    .join("closure_plan.json")
                    .to_str()
                    .unwrap(),
            ],
        ));

    let report = harness
        .run_reliability_scenario(&scenario)
        .expect("reliability scenario should succeed");

    assert!(
        report.manifest_path.is_some(),
        "reliability report must include manifest"
    );
    assert!(
        report
            .command_records
            .iter()
            .any(|r| r.stage == "execute" && r.succeeded),
        "cargo metadata execute stage should succeed"
    );

    harness.mark_passed();
}

#[test]
fn e2e_reliability_harness_alias_scenario() {
    let fixture = TopologyFixture::new("rel_alias");
    let set = fixture.reset("e2e_rel_alias");
    let meta = set
        .fixture("ready_alias_absolute")
        .expect("ready_alias_absolute fixture");

    let harness = TestHarnessBuilder::new("cross_repo_ready_alias")
        .cleanup_on_success(true)
        .build()
        .expect("create test harness");

    let canonical_plan =
        build_dependency_closure_plan_with_policy(&meta.canonical_entrypoint, &fixture.policy());
    let alias_plan =
        build_dependency_closure_plan_with_policy(&meta.alias_entrypoint, &fixture.policy());

    // Serialize both plans for logging/artifact capture
    let canonical_json = serde_json::to_string_pretty(&canonical_plan).expect("serialize");
    let alias_json = serde_json::to_string_pretty(&alias_plan).expect("serialize");
    harness
        .create_file("canonical_plan.json", &canonical_json)
        .expect("write canonical plan");
    harness
        .create_file("alias_plan.json", &alias_json)
        .expect("write alias plan");

    let scenario = ReliabilityScenarioSpec::new("cross_repo_ready_alias")
        .with_repo_set(
            meta.canonical_repo_paths
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>(),
        )
        .add_execute_command(ReliabilityLifecycleCommand::new(
            "cargo-metadata-canonical",
            "cargo",
            [
                "metadata",
                "--format-version=1",
                "--no-deps",
                "--manifest-path",
                meta.canonical_entrypoint
                    .join("Cargo.toml")
                    .to_str()
                    .unwrap(),
            ],
        ))
        .add_post_check(ReliabilityLifecycleCommand::new(
            "verify-alias-canonical-equivalence",
            "test",
            [canonical_plan.canonical_roots == alias_plan.canonical_roots]
                .iter()
                .map(|b| b.to_string()),
        ));

    let report = harness
        .run_reliability_scenario(&scenario)
        .expect("alias reliability scenario should succeed");

    assert!(
        report
            .command_records
            .iter()
            .any(|r| r.command_name == "cargo-metadata-canonical" && r.succeeded),
        "cargo metadata should succeed via canonical entrypoint"
    );

    // Verify plans are equivalent
    harness
        .assert_eq(
            canonical_plan.state,
            alias_plan.state,
            "canonical and alias plans must have same state",
        )
        .expect("state equivalence");
    harness
        .assert_eq(
            canonical_plan.canonical_roots,
            alias_plan.canonical_roots,
            "canonical roots must match",
        )
        .expect("roots equivalence");

    harness.mark_passed();
}

#[test]
fn e2e_reliability_harness_fail_open_scenarios() {
    let fixture = TopologyFixture::new("rel_fail_open");
    let set = fixture.reset("e2e_rel_fail_open");

    let harness = TestHarnessBuilder::new("cross_repo_fail_open")
        .cleanup_on_success(true)
        .build()
        .expect("create test harness");

    let fail_scenarios = [
        "fail_missing_path_dep",
        "fail_outside_canonical_dep",
        "fail_invalid_manifest",
    ];

    for scenario_id in fail_scenarios {
        let meta = set
            .fixture(scenario_id)
            .unwrap_or_else(|| panic!("fixture {scenario_id}"));

        let plan = build_dependency_closure_plan_with_policy(
            &meta.canonical_entrypoint,
            &fixture.policy(),
        );

        // Serialize plan artifact for per-phase logging
        let plan_json = serde_json::to_string_pretty(&plan).expect("serialize");
        harness
            .create_file(&format!("{scenario_id}_plan.json"), &plan_json)
            .expect("write fail-open plan artifact");

        // Verify fail-open semantics
        harness
            .assert_eq(
                plan.state,
                DependencyClosurePlanState::FailOpen,
                &format!("{scenario_id}: expected FailOpen state"),
            )
            .expect("fail-open state");
        harness
            .assert(plan.fail_open, &format!("{scenario_id}: fail_open flag"))
            .expect("fail_open flag set");
        harness
            .assert(
                plan.fail_open_reason.is_some(),
                &format!("{scenario_id}: fail_open_reason present"),
            )
            .expect("fail_open_reason present");
        harness
            .assert(
                !plan.issues.is_empty(),
                &format!("{scenario_id}: issues non-empty"),
            )
            .expect("issues non-empty");
    }

    // Run a single reliability scenario across all failure cases
    let scenario = ReliabilityScenarioSpec::new("cross_repo_fail_open_combined")
        .add_triage_action("fail_open_validation")
        .add_execute_command(ReliabilityLifecycleCommand::new(
            "verify-fail-open-artifacts",
            "ls",
            fail_scenarios.iter().map(|s| format!("{}_plan.json", s)),
        ))
        .add_post_check(ReliabilityLifecycleCommand::new(
            "verify-all-plans-written",
            "test",
            [
                "-f",
                harness
                    .test_dir()
                    .join("fail_missing_path_dep_plan.json")
                    .to_str()
                    .unwrap(),
            ],
        ));

    let report = harness
        .run_reliability_scenario(&scenario)
        .expect("fail-open reliability scenario should succeed");

    assert!(report.manifest_path.is_some());

    harness.mark_passed();
}

// ===========================================================================
// Graph-level assertions
// ===========================================================================

#[test]
fn e2e_ready_transitive_graph_packages_are_all_local() {
    let fixture = TopologyFixture::new("graph_local");
    let set = fixture.reset("e2e_graph_local");
    let meta = set
        .fixture("ready_relative_transitive")
        .expect("ready_relative_transitive fixture");

    let graph = resolve_cargo_path_dependency_graph_with_policy(
        &meta.canonical_entrypoint,
        &fixture.policy(),
    )
    .expect("graph resolution should succeed");

    assert_eq!(graph.packages.len(), 3);
    for pkg in &graph.packages {
        assert!(
            pkg.package_root.starts_with(&fixture.canonical_root),
            "package {} should be under canonical root",
            pkg.package_name,
        );
    }
}

#[test]
fn e2e_alias_absolute_graph_resolves_canonical_packages() {
    let fixture = TopologyFixture::new("graph_alias");
    let set = fixture.reset("e2e_graph_alias");
    let meta = set
        .fixture("ready_alias_absolute")
        .expect("ready_alias_absolute fixture");

    let graph = resolve_cargo_path_dependency_graph_with_policy(
        &meta.canonical_entrypoint,
        &fixture.policy(),
    )
    .expect("graph resolution should succeed");

    assert_eq!(graph.packages.len(), 2);
    for pkg in &graph.packages {
        assert!(
            pkg.package_root.starts_with(&fixture.canonical_root),
            "package {} should resolve to canonical root even though manifest uses alias",
            pkg.package_name,
        );
    }
}

// ===========================================================================
// Cross-fixture sweep: all 5 scenarios
// ===========================================================================

#[test]
fn e2e_all_five_fixture_scenarios_produce_valid_plans() {
    let fixture = TopologyFixture::new("all_five");
    let set = fixture.reset("e2e_all_five");

    assert_eq!(set.fixtures.len(), 5, "fixture set should have 5 scenarios");

    for meta in &set.fixtures {
        let plan = build_dependency_closure_plan_with_policy(
            &meta.canonical_entrypoint,
            &fixture.policy(),
        );

        // Every plan must have a valid state
        assert!(
            matches!(
                plan.state,
                DependencyClosurePlanState::Ready | DependencyClosurePlanState::FailOpen
            ),
            "{}: plan state must be Ready or FailOpen",
            meta.id,
        );

        // Ready fixtures should produce ready plans
        if meta.expected_ready() {
            assert_eq!(
                plan.state,
                DependencyClosurePlanState::Ready,
                "{}: expected-ready fixture should produce Ready plan",
                meta.id,
            );
            assert!(!plan.fail_open);
            assert!(plan.issues.is_empty());
        } else {
            assert_eq!(
                plan.state,
                DependencyClosurePlanState::FailOpen,
                "{}: expected-failure fixture should produce FailOpen plan",
                meta.id,
            );
            assert!(plan.fail_open);
            assert!(plan.fail_open_reason.is_some());
        }

        // All plans must have an entry manifest path
        assert!(
            !plan.entry_manifest_path.as_os_str().is_empty(),
            "{}: entry_manifest_path must not be empty",
            meta.id,
        );
    }
}

#[test]
fn e2e_all_five_fixture_scenarios_manifest_exists_on_disk() {
    let fixture = TopologyFixture::new("all_manifests");
    let set = fixture.reset("e2e_all_manifests");

    assert!(
        set.manifest_path.exists(),
        "fixture manifest JSON must exist"
    );
    let manifest_json = fs::read_to_string(&set.manifest_path).expect("read fixture manifest");
    let parsed: serde_json::Value =
        serde_json::from_str(&manifest_json).expect("parse fixture manifest");

    let fixtures = parsed["fixtures"]
        .as_array()
        .expect("fixtures should be an array");
    assert_eq!(fixtures.len(), 5);
}
