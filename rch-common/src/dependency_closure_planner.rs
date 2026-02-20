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
}
