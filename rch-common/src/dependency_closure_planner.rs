//! Dependency-closure planning on top of Cargo local path-dependency resolution.
//!
//! This planner converts resolver graph output into deterministic sync actions that
//! can be consumed by transfer and preflight stages. It also encodes explicit
//! fail-open fallback state when closure data is unsafe or unverifiable.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use crate::{
    CargoPathDependencyEdge, CargoPathDependencyError, CargoPathDependencyErrorKind,
    CargoPathDependencyGraph, CargoPathDependencyPackage, PathTopologyPolicy,
    resolve_cargo_path_dependency_graph_with_policy,
};

/// Planner-level lifecycle state for dependency closure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DependencyClosurePlanState {
    Ready,
    FailOpen,
}

/// Risk class attached to each sync action and planner issue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DependencyRiskClass {
    Low,
    Medium,
    High,
    Critical,
}

/// Why a specific root is included in the closure plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DependencySyncReason {
    EntryPoint,
    WorkspaceMember,
    TransitivePathDependency,
}

/// Structured reason metadata for one sync action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DependencySyncMetadata {
    pub reason: DependencySyncReason,
    pub workspace_member: bool,
    pub root_package: bool,
    pub inbound_dependency_names: Vec<String>,
    pub dependent_roots: Vec<PathBuf>,
    pub notes: Vec<String>,
}

/// Deterministic sync action for one canonical root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DependencySyncAction {
    pub order_index: usize,
    pub package_root: PathBuf,
    pub manifest_path: PathBuf,
    pub package_name: String,
    pub risk: DependencyRiskClass,
    pub metadata: DependencySyncMetadata,
}

/// Planner issue emitted for unsafe or unverifiable closure states.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DependencyPlanIssue {
    pub code: String,
    pub message: String,
    pub risk: DependencyRiskClass,
    pub diagnostics: Vec<String>,
}

/// Transfer/preflight-ready dependency closure plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DependencyClosurePlan {
    pub state: DependencyClosurePlanState,
    pub entry_manifest_path: PathBuf,
    pub workspace_root: Option<PathBuf>,
    pub canonical_roots: Vec<PathBuf>,
    pub sync_order: Vec<DependencySyncAction>,
    pub fail_open: bool,
    pub fail_open_reason: Option<String>,
    pub issues: Vec<DependencyPlanIssue>,
}

impl DependencyClosurePlan {
    /// True when closure is safe and deterministic for direct consumption.
    pub fn is_ready(&self) -> bool {
        self.state == DependencyClosurePlanState::Ready && !self.fail_open
    }

    /// Canonical root list in planner sync order.
    pub fn sync_roots(&self) -> Vec<PathBuf> {
        self.sync_order
            .iter()
            .map(|action| action.package_root.clone())
            .collect()
    }
}

/// Build a closure plan using default canonical topology policy.
pub fn build_dependency_closure_plan(entrypoint: &Path) -> DependencyClosurePlan {
    build_dependency_closure_plan_with_policy(entrypoint, &PathTopologyPolicy::default())
}

/// Build a closure plan using explicit topology policy.
///
/// This function is fail-open by design: resolver/planner failures are converted
/// into a `FailOpen` plan with structured issues and fallback rationale.
pub fn build_dependency_closure_plan_with_policy(
    entrypoint: &Path,
    policy: &PathTopologyPolicy,
) -> DependencyClosurePlan {
    match resolve_cargo_path_dependency_graph_with_policy(entrypoint, policy) {
        Ok(graph) => plan_dependency_closure_from_graph(&graph),
        Err(error) => fail_open_plan_from_resolver_error(entrypoint, &error),
    }
}

/// Convert a resolved graph into deterministic sync actions.
pub fn plan_dependency_closure_from_graph(
    graph: &CargoPathDependencyGraph,
) -> DependencyClosurePlan {
    let package_by_root: BTreeMap<PathBuf, CargoPathDependencyPackage> = graph
        .packages
        .iter()
        .cloned()
        .map(|package| (package.package_root.clone(), package))
        .collect();

    let order = match dependency_first_topological_order(&graph.packages, &graph.edges) {
        Some(order) => order,
        None => {
            return DependencyClosurePlan {
                state: DependencyClosurePlanState::FailOpen,
                entry_manifest_path: graph.entry_manifest_path.clone(),
                workspace_root: graph.workspace_root.clone(),
                canonical_roots: Vec::new(),
                sync_order: Vec::new(),
                fail_open: true,
                fail_open_reason: Some(
                    "planner could not derive deterministic order from dependency graph"
                        .to_string(),
                ),
                issues: vec![DependencyPlanIssue {
                    code: "planner_non_deterministic_order".to_string(),
                    message:
                        "dependency graph order is unverifiable; planner switched to fail-open"
                            .to_string(),
                    risk: DependencyRiskClass::Critical,
                    diagnostics: vec![
                        format!("packages={}", graph.packages.len()),
                        format!("edges={}", graph.edges.len()),
                    ],
                }],
            };
        }
    };

    let entry_root = graph
        .entry_manifest_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("/"));

    let root_packages = graph
        .root_packages
        .iter()
        .cloned()
        .collect::<BTreeSet<PathBuf>>();

    let mut inbound_dependency_names: BTreeMap<PathBuf, BTreeSet<String>> = BTreeMap::new();
    let mut dependent_roots: BTreeMap<PathBuf, BTreeSet<PathBuf>> = BTreeMap::new();
    for edge in &graph.edges {
        inbound_dependency_names
            .entry(edge.to.clone())
            .or_default()
            .insert(edge.dependency_name.clone());
        dependent_roots
            .entry(edge.to.clone())
            .or_default()
            .insert(edge.from.clone());
    }

    let mut sync_order = Vec::with_capacity(order.len());
    for (order_index, root) in order.iter().enumerate() {
        let package =
            package_by_root
                .get(root)
                .cloned()
                .unwrap_or_else(|| CargoPathDependencyPackage {
                    package_root: root.clone(),
                    manifest_path: root.join("Cargo.toml"),
                    package_name: root
                        .file_name()
                        .and_then(|segment| segment.to_str())
                        .unwrap_or("unknown")
                        .to_string(),
                    workspace_member: false,
                });

        let reason = if package.package_root == entry_root {
            DependencySyncReason::EntryPoint
        } else if package.workspace_member {
            DependencySyncReason::WorkspaceMember
        } else {
            DependencySyncReason::TransitivePathDependency
        };

        let inbound_names = inbound_dependency_names
            .get(&package.package_root)
            .map(|set| set.iter().cloned().collect::<Vec<_>>())
            .unwrap_or_default();
        let dependents = dependent_roots
            .get(&package.package_root)
            .map(|set| set.iter().cloned().collect::<Vec<_>>())
            .unwrap_or_default();

        let risk = classify_sync_risk(reason, dependents.len());
        let metadata = DependencySyncMetadata {
            reason,
            workspace_member: package.workspace_member,
            root_package: root_packages.contains(&package.package_root),
            inbound_dependency_names: inbound_names,
            dependent_roots: dependents.clone(),
            notes: vec![format!("dependent_root_count={}", dependents.len())],
        };

        sync_order.push(DependencySyncAction {
            order_index,
            package_root: package.package_root.clone(),
            manifest_path: package.manifest_path,
            package_name: package.package_name,
            risk,
            metadata,
        });
    }

    let canonical_roots = sync_order
        .iter()
        .map(|action| action.package_root.clone())
        .collect::<Vec<_>>();

    DependencyClosurePlan {
        state: DependencyClosurePlanState::Ready,
        entry_manifest_path: graph.entry_manifest_path.clone(),
        workspace_root: graph.workspace_root.clone(),
        canonical_roots,
        sync_order,
        fail_open: false,
        fail_open_reason: None,
        issues: Vec::new(),
    }
}

fn classify_sync_risk(
    reason: DependencySyncReason,
    dependent_root_count: usize,
) -> DependencyRiskClass {
    match reason {
        DependencySyncReason::EntryPoint | DependencySyncReason::WorkspaceMember => {
            DependencyRiskClass::Low
        }
        DependencySyncReason::TransitivePathDependency => {
            if dependent_root_count > 1 {
                DependencyRiskClass::High
            } else {
                DependencyRiskClass::Medium
            }
        }
    }
}

fn dependency_first_topological_order(
    packages: &[CargoPathDependencyPackage],
    edges: &[CargoPathDependencyEdge],
) -> Option<Vec<PathBuf>> {
    let mut nodes = packages
        .iter()
        .map(|package| package.package_root.clone())
        .collect::<BTreeSet<_>>();
    for edge in edges {
        nodes.insert(edge.from.clone());
        nodes.insert(edge.to.clone());
    }

    let mut indegree = nodes
        .iter()
        .cloned()
        .map(|node| (node, 0usize))
        .collect::<BTreeMap<_, _>>();
    let mut dependents_by_dependency: BTreeMap<PathBuf, BTreeSet<PathBuf>> = BTreeMap::new();

    for edge in edges {
        let from_indegree = indegree.get_mut(&edge.from)?;
        *from_indegree += 1;
        dependents_by_dependency
            .entry(edge.to.clone())
            .or_default()
            .insert(edge.from.clone());
    }

    let mut ready = indegree
        .iter()
        .filter_map(|(node, degree)| {
            if *degree == 0 {
                Some(node.clone())
            } else {
                None
            }
        })
        .collect::<BTreeSet<_>>();

    let mut order = Vec::with_capacity(indegree.len());
    while let Some(node) = ready.pop_first() {
        order.push(node.clone());
        if let Some(dependents) = dependents_by_dependency.get(&node) {
            for dependent in dependents {
                let degree = indegree.get_mut(dependent)?;
                if *degree == 0 {
                    return None;
                }
                *degree -= 1;
                if *degree == 0 {
                    ready.insert(dependent.clone());
                }
            }
        }
    }

    if order.len() == indegree.len() {
        Some(order)
    } else {
        None
    }
}

fn fail_open_plan_from_resolver_error(
    entrypoint: &Path,
    error: &CargoPathDependencyError,
) -> DependencyClosurePlan {
    let issue = issue_from_resolver_error(error);
    let entry_manifest_path = error
        .manifest_path()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| entrypoint.to_path_buf());

    DependencyClosurePlan {
        state: DependencyClosurePlanState::FailOpen,
        entry_manifest_path,
        workspace_root: None,
        canonical_roots: Vec::new(),
        sync_order: Vec::new(),
        fail_open: true,
        fail_open_reason: Some(format!(
            "resolver produced {}: {}",
            error.kind(),
            error.detail()
        )),
        issues: vec![issue],
    }
}

fn issue_from_resolver_error(error: &CargoPathDependencyError) -> DependencyPlanIssue {
    let (code, risk) = match error.kind() {
        CargoPathDependencyErrorKind::ManifestParseFailure => {
            ("manifest-parse-failure", DependencyRiskClass::Critical)
        }
        CargoPathDependencyErrorKind::MetadataParseFailure => {
            ("metadata-parse-failure", DependencyRiskClass::Critical)
        }
        CargoPathDependencyErrorKind::MetadataInvocationFailure => {
            ("metadata-invocation-failure", DependencyRiskClass::Critical)
        }
        CargoPathDependencyErrorKind::CyclicDependency => {
            ("cyclic-path-dependency", DependencyRiskClass::Critical)
        }
        CargoPathDependencyErrorKind::PathPolicyViolation => {
            ("path-policy-violation", DependencyRiskClass::High)
        }
        CargoPathDependencyErrorKind::MissingPathDependency => {
            ("missing-path-dependency", DependencyRiskClass::High)
        }
    };

    let mut diagnostics = error.diagnostics().to_vec();
    if let Some(dependency_name) = error.dependency_name() {
        diagnostics.push(format!("dependency_name={dependency_name}"));
    }
    if let Some(dependency_path) = error.dependency_path() {
        diagnostics.push(format!("dependency_path={}", dependency_path.display()));
    }
    if !error.cycle().is_empty() {
        diagnostics.push(format!("cycle={:?}", error.cycle()));
    }

    DependencyPlanIssue {
        code: code.to_string(),
        message: format!("{}: {}", error.kind(), error.detail()),
        risk,
        diagnostics,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn package(root: &str, name: &str, workspace_member: bool) -> CargoPathDependencyPackage {
        CargoPathDependencyPackage {
            package_root: PathBuf::from(root),
            manifest_path: PathBuf::from(root).join("Cargo.toml"),
            package_name: name.to_string(),
            workspace_member,
        }
    }

    fn edge(from: &str, to: &str, dependency_name: &str) -> CargoPathDependencyEdge {
        CargoPathDependencyEdge {
            from: PathBuf::from(from),
            to: PathBuf::from(to),
            dependency_name: dependency_name.to_string(),
        }
    }

    #[test]
    fn planner_produces_dependency_first_deterministic_sync_order() {
        let graph = CargoPathDependencyGraph {
            entry_manifest_path: PathBuf::from("/data/projects/app/Cargo.toml"),
            workspace_root: Some(PathBuf::from("/data/projects")),
            root_packages: vec![PathBuf::from("/data/projects/app")],
            packages: vec![
                package("/data/projects/app", "app", true),
                package("/data/projects/lib_a", "lib_a", false),
                package("/data/projects/lib_b", "lib_b", false),
            ],
            edges: vec![
                edge("/data/projects/app", "/data/projects/lib_a", "lib_a"),
                edge("/data/projects/lib_a", "/data/projects/lib_b", "lib_b"),
            ],
        };

        let plan = plan_dependency_closure_from_graph(&graph);
        assert!(plan.is_ready(), "acyclic graph should be planner-ready");
        assert_eq!(plan.sync_order.len(), 3);

        let ordered_roots = plan
            .sync_order
            .iter()
            .map(|action| action.package_root.as_path())
            .collect::<Vec<_>>();
        assert_eq!(
            ordered_roots,
            vec![
                Path::new("/data/projects/lib_b"),
                Path::new("/data/projects/lib_a"),
                Path::new("/data/projects/app"),
            ],
            "planner must sync dependencies before dependents"
        );
        assert_eq!(
            plan.sync_order[0].metadata.reason,
            DependencySyncReason::TransitivePathDependency
        );
        assert_eq!(
            plan.sync_order[2].metadata.reason,
            DependencySyncReason::EntryPoint
        );
    }

    #[test]
    fn planner_cycle_fails_open_with_stable_issue_code() {
        let graph = CargoPathDependencyGraph {
            entry_manifest_path: PathBuf::from("/data/projects/cycle_a/Cargo.toml"),
            workspace_root: None,
            root_packages: vec![PathBuf::from("/data/projects/cycle_a")],
            packages: vec![
                package("/data/projects/cycle_a", "cycle_a", false),
                package("/data/projects/cycle_b", "cycle_b", false),
            ],
            edges: vec![
                edge(
                    "/data/projects/cycle_a",
                    "/data/projects/cycle_b",
                    "cycle_b",
                ),
                edge(
                    "/data/projects/cycle_b",
                    "/data/projects/cycle_a",
                    "cycle_a",
                ),
            ],
        };

        let plan = plan_dependency_closure_from_graph(&graph);
        assert_eq!(plan.state, DependencyClosurePlanState::FailOpen);
        assert!(plan.fail_open);
        assert_eq!(plan.sync_order.len(), 0);
        assert_eq!(plan.issues.len(), 1);
        assert_eq!(plan.issues[0].code, "planner_non_deterministic_order");
        assert_eq!(plan.issues[0].risk, DependencyRiskClass::Critical);
    }

    #[test]
    fn resolver_error_mapping_reports_path_policy_violation_code() {
        let error = CargoPathDependencyError::new(
            CargoPathDependencyErrorKind::PathPolicyViolation,
            "dependency escaped canonical root",
        )
        .with_manifest_path("/data/projects/app/Cargo.toml")
        .with_dependency_name("bad_dep")
        .with_dependency_path("/tmp/outside");

        let issue = issue_from_resolver_error(&error);
        assert_eq!(issue.code, "path-policy-violation");
        assert_eq!(issue.risk, DependencyRiskClass::High);
        assert!(
            issue
                .diagnostics
                .iter()
                .any(|line| line.contains("dependency_path=/tmp/outside"))
        );
    }

    #[test]
    fn resolver_error_mapping_reports_manifest_parse_failure_code() {
        let error = CargoPathDependencyError::new(
            CargoPathDependencyErrorKind::ManifestParseFailure,
            "invalid Cargo.toml syntax",
        )
        .with_manifest_path("/data/projects/app/Cargo.toml");

        let plan = fail_open_plan_from_resolver_error(Path::new("/data/projects/app"), &error);
        assert_eq!(plan.state, DependencyClosurePlanState::FailOpen);
        assert_eq!(plan.issues.len(), 1);
        assert_eq!(plan.issues[0].code, "manifest-parse-failure");
        assert_eq!(plan.issues[0].risk, DependencyRiskClass::Critical);
        assert!(
            plan.fail_open_reason
                .as_deref()
                .is_some_and(|reason| reason.contains("manifest parse failure"))
        );
    }

    // =======================================================================
    // Empty and single-package closure tests
    // =======================================================================

    #[test]
    fn empty_graph_produces_empty_ready_plan() {
        let graph = CargoPathDependencyGraph {
            entry_manifest_path: PathBuf::from("/data/projects/empty/Cargo.toml"),
            workspace_root: None,
            root_packages: Vec::new(),
            packages: Vec::new(),
            edges: Vec::new(),
        };

        let plan = plan_dependency_closure_from_graph(&graph);
        assert!(plan.is_ready(), "empty graph should still be ready");
        assert_eq!(plan.sync_order.len(), 0);
        assert_eq!(plan.canonical_roots.len(), 0);
        assert!(plan.issues.is_empty());
        assert!(!plan.fail_open);
    }

    #[test]
    fn single_package_no_deps_produces_single_entry_point_action() {
        let graph = CargoPathDependencyGraph {
            entry_manifest_path: PathBuf::from("/data/projects/solo/Cargo.toml"),
            workspace_root: None,
            root_packages: vec![PathBuf::from("/data/projects/solo")],
            packages: vec![package("/data/projects/solo", "solo-crate", false)],
            edges: Vec::new(),
        };

        let plan = plan_dependency_closure_from_graph(&graph);
        assert!(plan.is_ready());
        assert_eq!(plan.sync_order.len(), 1);
        assert_eq!(plan.sync_order[0].order_index, 0);
        assert_eq!(plan.sync_order[0].package_name, "solo-crate");
        assert_eq!(
            plan.sync_order[0].metadata.reason,
            DependencySyncReason::EntryPoint
        );
        assert_eq!(plan.sync_order[0].risk, DependencyRiskClass::Low);
        assert!(
            plan.sync_order[0]
                .metadata
                .inbound_dependency_names
                .is_empty()
        );
        assert!(plan.sync_order[0].metadata.dependent_roots.is_empty());
    }

    // =======================================================================
    // Diamond dependency pattern (A→B, A→C, B→D, C→D)
    // =======================================================================

    #[test]
    fn diamond_dependency_preserves_deterministic_order() {
        let graph = CargoPathDependencyGraph {
            entry_manifest_path: PathBuf::from("/data/projects/app/Cargo.toml"),
            workspace_root: Some(PathBuf::from("/data/projects")),
            root_packages: vec![PathBuf::from("/data/projects/app")],
            packages: vec![
                package("/data/projects/app", "app", true),
                package("/data/projects/b", "lib_b", false),
                package("/data/projects/c", "lib_c", false),
                package("/data/projects/d", "lib_d", false),
            ],
            edges: vec![
                edge("/data/projects/app", "/data/projects/b", "lib_b"),
                edge("/data/projects/app", "/data/projects/c", "lib_c"),
                edge("/data/projects/b", "/data/projects/d", "lib_d"),
                edge("/data/projects/c", "/data/projects/d", "lib_d"),
            ],
        };

        let plan = plan_dependency_closure_from_graph(&graph);
        assert!(plan.is_ready(), "diamond graph should be planner-ready");
        assert_eq!(plan.sync_order.len(), 4);

        let ordered_roots: Vec<_> = plan
            .sync_order
            .iter()
            .map(|a| a.package_root.as_path())
            .collect();

        // D must come before B and C; B and C must come before app.
        let d_pos = ordered_roots
            .iter()
            .position(|r| *r == Path::new("/data/projects/d"))
            .unwrap();
        let b_pos = ordered_roots
            .iter()
            .position(|r| *r == Path::new("/data/projects/b"))
            .unwrap();
        let c_pos = ordered_roots
            .iter()
            .position(|r| *r == Path::new("/data/projects/c"))
            .unwrap();
        let app_pos = ordered_roots
            .iter()
            .position(|r| *r == Path::new("/data/projects/app"))
            .unwrap();
        assert!(d_pos < b_pos, "D must sync before B");
        assert!(d_pos < c_pos, "D must sync before C");
        assert!(b_pos < app_pos, "B must sync before app");
        assert!(c_pos < app_pos, "C must sync before app");

        // D has 2 dependent roots (B and C), so it should be High risk.
        let d_action = &plan.sync_order[d_pos];
        assert_eq!(d_action.risk, DependencyRiskClass::High);
        assert_eq!(d_action.metadata.dependent_roots.len(), 2);

        // B and C each have 1 dependent root (app), so Medium risk.
        let b_action = &plan.sync_order[b_pos];
        assert_eq!(b_action.risk, DependencyRiskClass::Medium);

        // app is entry point, so Low risk.
        let app_action = &plan.sync_order[app_pos];
        assert_eq!(app_action.risk, DependencyRiskClass::Low);
    }

    // =======================================================================
    // Risk classification boundary tests
    // =======================================================================

    #[test]
    fn classify_sync_risk_entry_point_is_always_low() {
        assert_eq!(
            classify_sync_risk(DependencySyncReason::EntryPoint, 0),
            DependencyRiskClass::Low
        );
        assert_eq!(
            classify_sync_risk(DependencySyncReason::EntryPoint, 10),
            DependencyRiskClass::Low
        );
    }

    #[test]
    fn classify_sync_risk_workspace_member_is_always_low() {
        assert_eq!(
            classify_sync_risk(DependencySyncReason::WorkspaceMember, 0),
            DependencyRiskClass::Low
        );
        assert_eq!(
            classify_sync_risk(DependencySyncReason::WorkspaceMember, 5),
            DependencyRiskClass::Low
        );
    }

    #[test]
    fn classify_sync_risk_transitive_with_zero_dependents_is_medium() {
        assert_eq!(
            classify_sync_risk(DependencySyncReason::TransitivePathDependency, 0),
            DependencyRiskClass::Medium
        );
    }

    #[test]
    fn classify_sync_risk_transitive_with_one_dependent_is_medium() {
        assert_eq!(
            classify_sync_risk(DependencySyncReason::TransitivePathDependency, 1),
            DependencyRiskClass::Medium
        );
    }

    #[test]
    fn classify_sync_risk_transitive_with_two_dependents_is_high() {
        assert_eq!(
            classify_sync_risk(DependencySyncReason::TransitivePathDependency, 2),
            DependencyRiskClass::High
        );
    }

    #[test]
    fn classify_sync_risk_transitive_with_many_dependents_is_high() {
        assert_eq!(
            classify_sync_risk(DependencySyncReason::TransitivePathDependency, 100),
            DependencyRiskClass::High
        );
    }

    // =======================================================================
    // Wide fan-out graph test
    // =======================================================================

    #[test]
    fn wide_fanout_graph_syncs_all_leaves_before_root() {
        let leaf_count = 20;
        let mut packages = vec![package("/data/projects/hub", "hub", true)];
        let mut edges = Vec::new();
        for i in 0..leaf_count {
            let root = format!("/data/projects/leaf_{i}");
            let name = format!("leaf_{i}");
            packages.push(package(&root, &name, false));
            edges.push(edge("/data/projects/hub", &root, &name));
        }

        let graph = CargoPathDependencyGraph {
            entry_manifest_path: PathBuf::from("/data/projects/hub/Cargo.toml"),
            workspace_root: Some(PathBuf::from("/data/projects")),
            root_packages: vec![PathBuf::from("/data/projects/hub")],
            packages,
            edges,
        };

        let plan = plan_dependency_closure_from_graph(&graph);
        assert!(plan.is_ready());
        assert_eq!(plan.sync_order.len(), leaf_count + 1);

        // Hub must be last.
        let hub_action = plan.sync_order.last().unwrap();
        assert_eq!(hub_action.package_root, PathBuf::from("/data/projects/hub"));
        assert_eq!(hub_action.metadata.reason, DependencySyncReason::EntryPoint);

        // All leaves must come before hub.
        for action in &plan.sync_order[..leaf_count] {
            assert_eq!(
                action.metadata.reason,
                DependencySyncReason::TransitivePathDependency
            );
            assert_eq!(action.metadata.dependent_roots.len(), 1);
            assert_eq!(action.risk, DependencyRiskClass::Medium);
        }
    }

    // =======================================================================
    // Deep chain graph test
    // =======================================================================

    #[test]
    fn deep_chain_graph_preserves_order() {
        let depth = 10;
        let mut packages = Vec::new();
        let mut edges = Vec::new();
        for i in 0..depth {
            let root = format!("/data/projects/chain_{i}");
            let name = format!("chain_{i}");
            packages.push(package(&root, &name, i == depth - 1));
            if i > 0 {
                let parent = format!("/data/projects/chain_{}", i);
                let child = format!("/data/projects/chain_{}", i - 1);
                edges.push(edge(&parent, &child, &format!("chain_{}", i - 1)));
            }
        }

        let graph = CargoPathDependencyGraph {
            entry_manifest_path: PathBuf::from(format!(
                "/data/projects/chain_{}/Cargo.toml",
                depth - 1
            )),
            workspace_root: Some(PathBuf::from("/data/projects")),
            root_packages: vec![PathBuf::from(format!("/data/projects/chain_{}", depth - 1))],
            packages,
            edges,
        };

        let plan = plan_dependency_closure_from_graph(&graph);
        assert!(plan.is_ready());
        assert_eq!(plan.sync_order.len(), depth);

        // chain_0 should be first (leaf), chain_{depth-1} should be last (entry point).
        assert_eq!(
            plan.sync_order[0].package_root,
            PathBuf::from("/data/projects/chain_0")
        );
        assert_eq!(
            plan.sync_order.last().unwrap().package_root,
            PathBuf::from(format!("/data/projects/chain_{}", depth - 1))
        );
    }

    // =======================================================================
    // All error kind mappings
    // =======================================================================

    #[test]
    fn resolver_error_mapping_metadata_parse_failure() {
        let error = CargoPathDependencyError::new(
            CargoPathDependencyErrorKind::MetadataParseFailure,
            "cannot parse metadata JSON",
        );
        let issue = issue_from_resolver_error(&error);
        assert_eq!(issue.code, "metadata-parse-failure");
        assert_eq!(issue.risk, DependencyRiskClass::Critical);
    }

    #[test]
    fn resolver_error_mapping_metadata_invocation_failure() {
        let error = CargoPathDependencyError::new(
            CargoPathDependencyErrorKind::MetadataInvocationFailure,
            "cargo metadata timed out after 30s",
        );
        let issue = issue_from_resolver_error(&error);
        assert_eq!(issue.code, "metadata-invocation-failure");
        assert_eq!(issue.risk, DependencyRiskClass::Critical);
    }

    #[test]
    fn resolver_error_mapping_missing_path_dependency() {
        let error = CargoPathDependencyError::new(
            CargoPathDependencyErrorKind::MissingPathDependency,
            "path dep does not exist on disk",
        )
        .with_dependency_name("phantom_dep")
        .with_dependency_path("/data/projects/nonexistent");

        let issue = issue_from_resolver_error(&error);
        assert_eq!(issue.code, "missing-path-dependency");
        assert_eq!(issue.risk, DependencyRiskClass::High);
        assert!(
            issue
                .diagnostics
                .iter()
                .any(|d| d.contains("dependency_name=phantom_dep")),
            "diagnostics should include dependency name"
        );
        assert!(
            issue
                .diagnostics
                .iter()
                .any(|d| d.contains("dependency_path=/data/projects/nonexistent")),
            "diagnostics should include dependency path"
        );
    }

    #[test]
    fn resolver_error_mapping_cyclic_dependency() {
        let error = CargoPathDependencyError::new(
            CargoPathDependencyErrorKind::CyclicDependency,
            "circular path dependency detected",
        );

        let issue = issue_from_resolver_error(&error);
        assert_eq!(issue.code, "cyclic-path-dependency");
        assert_eq!(issue.risk, DependencyRiskClass::Critical);
        assert!(
            issue.message.contains("cyclic path dependency"),
            "message should contain error kind, got: {}",
            issue.message
        );
    }

    // =======================================================================
    // fail_open_plan_from_resolver_error tests
    // =======================================================================

    #[test]
    fn fail_open_plan_preserves_manifest_path_from_error() {
        let error = CargoPathDependencyError::new(
            CargoPathDependencyErrorKind::MetadataInvocationFailure,
            "timeout",
        )
        .with_manifest_path("/data/projects/app/Cargo.toml");

        let plan =
            fail_open_plan_from_resolver_error(Path::new("/data/projects/app/Cargo.toml"), &error);
        assert_eq!(
            plan.entry_manifest_path,
            PathBuf::from("/data/projects/app/Cargo.toml")
        );
        assert_eq!(plan.state, DependencyClosurePlanState::FailOpen);
        assert!(plan.fail_open);
        assert!(plan.sync_order.is_empty());
        assert!(plan.canonical_roots.is_empty());
        assert!(plan.workspace_root.is_none());
    }

    #[test]
    fn fail_open_plan_uses_entrypoint_when_error_has_no_manifest_path() {
        let error = CargoPathDependencyError::new(
            CargoPathDependencyErrorKind::MissingPathDependency,
            "dep not found",
        );

        let plan = fail_open_plan_from_resolver_error(Path::new("/data/projects/fallback"), &error);
        assert_eq!(
            plan.entry_manifest_path,
            PathBuf::from("/data/projects/fallback")
        );
    }

    // =======================================================================
    // DependencyClosurePlan API tests
    // =======================================================================

    #[test]
    fn is_ready_returns_false_for_fail_open() {
        let plan = DependencyClosurePlan {
            state: DependencyClosurePlanState::FailOpen,
            entry_manifest_path: PathBuf::from("/tmp/Cargo.toml"),
            workspace_root: None,
            canonical_roots: Vec::new(),
            sync_order: Vec::new(),
            fail_open: true,
            fail_open_reason: Some("test".to_string()),
            issues: Vec::new(),
        };
        assert!(!plan.is_ready());
    }

    #[test]
    fn sync_roots_returns_roots_in_sync_order() {
        let plan = DependencyClosurePlan {
            state: DependencyClosurePlanState::Ready,
            entry_manifest_path: PathBuf::from("/data/projects/app/Cargo.toml"),
            workspace_root: None,
            canonical_roots: vec![
                PathBuf::from("/data/projects/dep"),
                PathBuf::from("/data/projects/app"),
            ],
            sync_order: vec![
                DependencySyncAction {
                    order_index: 0,
                    package_root: PathBuf::from("/data/projects/dep"),
                    manifest_path: PathBuf::from("/data/projects/dep/Cargo.toml"),
                    package_name: "dep".to_string(),
                    risk: DependencyRiskClass::Medium,
                    metadata: DependencySyncMetadata {
                        reason: DependencySyncReason::TransitivePathDependency,
                        workspace_member: false,
                        root_package: false,
                        inbound_dependency_names: vec!["dep".to_string()],
                        dependent_roots: vec![PathBuf::from("/data/projects/app")],
                        notes: vec!["dependent_root_count=1".to_string()],
                    },
                },
                DependencySyncAction {
                    order_index: 1,
                    package_root: PathBuf::from("/data/projects/app"),
                    manifest_path: PathBuf::from("/data/projects/app/Cargo.toml"),
                    package_name: "app".to_string(),
                    risk: DependencyRiskClass::Low,
                    metadata: DependencySyncMetadata {
                        reason: DependencySyncReason::EntryPoint,
                        workspace_member: false,
                        root_package: true,
                        inbound_dependency_names: Vec::new(),
                        dependent_roots: Vec::new(),
                        notes: vec!["dependent_root_count=0".to_string()],
                    },
                },
            ],
            fail_open: false,
            fail_open_reason: None,
            issues: Vec::new(),
        };

        let roots = plan.sync_roots();
        assert_eq!(
            roots,
            vec![
                PathBuf::from("/data/projects/dep"),
                PathBuf::from("/data/projects/app"),
            ]
        );
    }

    // =======================================================================
    // Workspace member classification tests
    // =======================================================================

    #[test]
    fn workspace_member_gets_workspace_member_reason() {
        let graph = CargoPathDependencyGraph {
            entry_manifest_path: PathBuf::from("/data/projects/app/Cargo.toml"),
            workspace_root: Some(PathBuf::from("/data/projects")),
            root_packages: vec![PathBuf::from("/data/projects/app")],
            packages: vec![
                package("/data/projects/app", "app", true),
                package("/data/projects/member", "member", true),
            ],
            edges: vec![edge(
                "/data/projects/app",
                "/data/projects/member",
                "member",
            )],
        };

        let plan = plan_dependency_closure_from_graph(&graph);
        assert!(plan.is_ready());

        let member_action = plan
            .sync_order
            .iter()
            .find(|a| a.package_name == "member")
            .unwrap();
        assert_eq!(
            member_action.metadata.reason,
            DependencySyncReason::WorkspaceMember
        );
        assert!(member_action.metadata.workspace_member);
        assert_eq!(member_action.risk, DependencyRiskClass::Low);
    }

    // =======================================================================
    // Inbound dependency name deduplication
    // =======================================================================

    #[test]
    fn inbound_dependency_names_are_deduplicated() {
        let graph = CargoPathDependencyGraph {
            entry_manifest_path: PathBuf::from("/data/projects/app/Cargo.toml"),
            workspace_root: None,
            root_packages: vec![PathBuf::from("/data/projects/app")],
            packages: vec![
                package("/data/projects/app", "app", false),
                package("/data/projects/dep", "dep", false),
                package("/data/projects/other", "other", false),
            ],
            edges: vec![
                edge("/data/projects/app", "/data/projects/dep", "dep"),
                edge("/data/projects/other", "/data/projects/dep", "dep"),
            ],
        };

        let plan = plan_dependency_closure_from_graph(&graph);
        let dep_action = plan
            .sync_order
            .iter()
            .find(|a| a.package_name == "dep")
            .unwrap();
        // Same dependency name from two sources — should appear only once (BTreeSet dedup).
        assert_eq!(dep_action.metadata.inbound_dependency_names, vec!["dep"]);
    }

    // =======================================================================
    // Topological order determinism
    // =======================================================================

    #[test]
    fn topological_sort_is_deterministic_across_calls() {
        let graph = CargoPathDependencyGraph {
            entry_manifest_path: PathBuf::from("/data/projects/app/Cargo.toml"),
            workspace_root: None,
            root_packages: vec![PathBuf::from("/data/projects/app")],
            packages: vec![
                package("/data/projects/app", "app", false),
                package("/data/projects/a", "a", false),
                package("/data/projects/b", "b", false),
                package("/data/projects/c", "c", false),
            ],
            edges: vec![
                edge("/data/projects/app", "/data/projects/a", "a"),
                edge("/data/projects/app", "/data/projects/b", "b"),
                edge("/data/projects/app", "/data/projects/c", "c"),
            ],
        };

        let plan1 = plan_dependency_closure_from_graph(&graph);
        let plan2 = plan_dependency_closure_from_graph(&graph);

        let roots1: Vec<_> = plan1.sync_order.iter().map(|a| &a.package_root).collect();
        let roots2: Vec<_> = plan2.sync_order.iter().map(|a| &a.package_root).collect();
        assert_eq!(roots1, roots2, "topological order must be deterministic");
    }

    // =======================================================================
    // Notes field validation
    // =======================================================================

    #[test]
    fn notes_include_dependent_root_count() {
        let graph = CargoPathDependencyGraph {
            entry_manifest_path: PathBuf::from("/data/projects/app/Cargo.toml"),
            workspace_root: None,
            root_packages: vec![PathBuf::from("/data/projects/app")],
            packages: vec![
                package("/data/projects/app", "app", false),
                package("/data/projects/dep", "dep", false),
            ],
            edges: vec![edge("/data/projects/app", "/data/projects/dep", "dep")],
        };

        let plan = plan_dependency_closure_from_graph(&graph);
        let dep_action = plan
            .sync_order
            .iter()
            .find(|a| a.package_name == "dep")
            .unwrap();
        assert!(
            dep_action
                .metadata
                .notes
                .iter()
                .any(|n| n == "dependent_root_count=1"),
            "notes should include dependent_root_count"
        );

        let app_action = plan
            .sync_order
            .iter()
            .find(|a| a.package_name == "app")
            .unwrap();
        assert!(
            app_action
                .metadata
                .notes
                .iter()
                .any(|n| n == "dependent_root_count=0"),
            "entry point should have 0 dependent roots"
        );
    }

    // =======================================================================
    // Serialization round-trip
    // =======================================================================

    #[test]
    fn plan_serialization_round_trip() {
        let graph = CargoPathDependencyGraph {
            entry_manifest_path: PathBuf::from("/data/projects/app/Cargo.toml"),
            workspace_root: Some(PathBuf::from("/data/projects")),
            root_packages: vec![PathBuf::from("/data/projects/app")],
            packages: vec![
                package("/data/projects/app", "app", true),
                package("/data/projects/dep", "dep", false),
            ],
            edges: vec![edge("/data/projects/app", "/data/projects/dep", "dep")],
        };

        let plan = plan_dependency_closure_from_graph(&graph);
        let json = serde_json::to_string(&plan).expect("plan should serialize");
        let deserialized: DependencyClosurePlan =
            serde_json::from_str(&json).expect("plan should deserialize");
        assert_eq!(plan, deserialized);
    }

    #[test]
    fn fail_open_plan_serialization_round_trip() {
        let error = CargoPathDependencyError::new(
            CargoPathDependencyErrorKind::CyclicDependency,
            "cycle detected",
        );

        let plan = fail_open_plan_from_resolver_error(Path::new("/data/projects/app"), &error);
        let json = serde_json::to_string(&plan).expect("fail-open plan should serialize");
        let deserialized: DependencyClosurePlan =
            serde_json::from_str(&json).expect("fail-open plan should deserialize");
        assert_eq!(plan, deserialized);
    }

    // =======================================================================
    // root_package flag validation
    // =======================================================================

    #[test]
    fn root_package_flag_set_correctly() {
        let graph = CargoPathDependencyGraph {
            entry_manifest_path: PathBuf::from("/data/projects/app/Cargo.toml"),
            workspace_root: None,
            root_packages: vec![PathBuf::from("/data/projects/app")],
            packages: vec![
                package("/data/projects/app", "app", false),
                package("/data/projects/dep", "dep", false),
            ],
            edges: vec![edge("/data/projects/app", "/data/projects/dep", "dep")],
        };

        let plan = plan_dependency_closure_from_graph(&graph);
        let app_action = plan
            .sync_order
            .iter()
            .find(|a| a.package_name == "app")
            .unwrap();
        assert!(
            app_action.metadata.root_package,
            "app should be marked as root_package"
        );

        let dep_action = plan
            .sync_order
            .iter()
            .find(|a| a.package_name == "dep")
            .unwrap();
        assert!(
            !dep_action.metadata.root_package,
            "dep should not be marked as root_package"
        );
    }

    // =======================================================================
    // Order indices are sequential
    // =======================================================================

    #[test]
    fn order_indices_are_sequential_from_zero() {
        let graph = CargoPathDependencyGraph {
            entry_manifest_path: PathBuf::from("/data/projects/app/Cargo.toml"),
            workspace_root: None,
            root_packages: vec![PathBuf::from("/data/projects/app")],
            packages: vec![
                package("/data/projects/app", "app", false),
                package("/data/projects/a", "a", false),
                package("/data/projects/b", "b", false),
            ],
            edges: vec![
                edge("/data/projects/app", "/data/projects/a", "a"),
                edge("/data/projects/a", "/data/projects/b", "b"),
            ],
        };

        let plan = plan_dependency_closure_from_graph(&graph);
        for (i, action) in plan.sync_order.iter().enumerate() {
            assert_eq!(action.order_index, i, "order_index should be sequential");
        }
    }
}
