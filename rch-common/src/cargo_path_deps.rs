//! Cargo local path-dependency graph resolver.
//!
//! The resolver builds a deterministic graph of local `path` dependencies using
//! a two-phase strategy:
//! 1. `cargo metadata` (primary source of truth when available)
//! 2. Recursive manifest parsing fallback (for malformed metadata and metadata failures)
//!
//! Every discovered path is normalized through [`PathTopologyPolicy`] to enforce
//! canonical-root safety and stable path identity.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::{PathNormalizationErrorKind, PathTopologyPolicy, normalize_project_path_with_policy};

/// Deterministic graph of local Cargo path dependencies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CargoPathDependencyGraph {
    /// Canonical path to the entry manifest used for resolution.
    pub entry_manifest_path: PathBuf,
    /// Canonical workspace root when entrypoint is a workspace manifest.
    pub workspace_root: Option<PathBuf>,
    /// Canonical root packages used as traversal roots (sorted).
    pub root_packages: Vec<PathBuf>,
    /// Reachable local packages in deterministic order.
    pub packages: Vec<CargoPathDependencyPackage>,
    /// Reachable path-dependency edges in deterministic order.
    pub edges: Vec<CargoPathDependencyEdge>,
}

/// One package node in the resolved path-dependency graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CargoPathDependencyPackage {
    /// Canonical package root directory.
    pub package_root: PathBuf,
    /// Canonical package manifest path.
    pub manifest_path: PathBuf,
    /// Package name (best effort, deterministic fallback if missing).
    pub package_name: String,
    /// Whether this package is a workspace member/root.
    pub workspace_member: bool,
}

/// One directed path-dependency edge.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct CargoPathDependencyEdge {
    /// Canonical source package root.
    pub from: PathBuf,
    /// Canonical dependency package root.
    pub to: PathBuf,
    /// Dependency key from manifest (`[dependencies] <name> = { path = ... }`).
    pub dependency_name: String,
}

/// Taxonomy for local path-dependency resolution failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CargoPathDependencyErrorKind {
    ManifestParseFailure,
    MissingPathDependency,
    CyclicDependency,
    PathPolicyViolation,
    MetadataParseFailure,
    MetadataInvocationFailure,
}

impl fmt::Display for CargoPathDependencyErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ManifestParseFailure => write!(f, "manifest parse failure"),
            Self::MissingPathDependency => write!(f, "missing path dependency"),
            Self::CyclicDependency => write!(f, "cyclic path dependency"),
            Self::PathPolicyViolation => write!(f, "path policy violation"),
            Self::MetadataParseFailure => write!(f, "metadata parse failure"),
            Self::MetadataInvocationFailure => write!(f, "metadata invocation failure"),
        }
    }
}

/// Structured error with explicit diagnostics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CargoPathDependencyError {
    kind: CargoPathDependencyErrorKind,
    detail: String,
    manifest_path: Option<Box<PathBuf>>,
    dependency_name: Option<Box<str>>,
    dependency_path: Option<Box<PathBuf>>,
    cycle: Vec<PathBuf>,
    diagnostics: Vec<String>,
}

impl CargoPathDependencyError {
    pub(crate) fn new(kind: CargoPathDependencyErrorKind, detail: impl Into<String>) -> Self {
        Self {
            kind,
            detail: detail.into(),
            manifest_path: None,
            dependency_name: None,
            dependency_path: None,
            cycle: Vec::new(),
            diagnostics: Vec::new(),
        }
    }

    pub(crate) fn with_manifest_path(mut self, manifest_path: impl Into<PathBuf>) -> Self {
        self.manifest_path = Some(Box::new(manifest_path.into()));
        self
    }

    pub(crate) fn with_dependency_name(mut self, dependency_name: impl Into<String>) -> Self {
        self.dependency_name = Some(dependency_name.into().into_boxed_str());
        self
    }

    pub(crate) fn with_dependency_path(mut self, dependency_path: impl Into<PathBuf>) -> Self {
        self.dependency_path = Some(Box::new(dependency_path.into()));
        self
    }

    fn with_cycle(mut self, cycle: Vec<PathBuf>) -> Self {
        self.cycle = cycle;
        self
    }

    fn with_diagnostic(mut self, diagnostic: impl Into<String>) -> Self {
        self.diagnostics.push(diagnostic.into());
        self
    }

    fn with_diagnostics<I>(mut self, diagnostics: I) -> Self
    where
        I: IntoIterator,
        I::Item: Into<String>,
    {
        self.diagnostics
            .extend(diagnostics.into_iter().map(Into::into));
        self
    }

    fn push_diagnostic(&mut self, diagnostic: impl Into<String>) {
        self.diagnostics.push(diagnostic.into());
    }

    /// Error category.
    pub fn kind(&self) -> &CargoPathDependencyErrorKind {
        &self.kind
    }

    /// Human-readable detail.
    pub fn detail(&self) -> &str {
        &self.detail
    }

    /// Manifest path associated with the error when available.
    pub fn manifest_path(&self) -> Option<&Path> {
        self.manifest_path.as_deref().map(PathBuf::as_path)
    }

    /// Dependency key associated with the error when available.
    pub fn dependency_name(&self) -> Option<&str> {
        self.dependency_name.as_deref()
    }

    /// Dependency path associated with the error when available.
    pub fn dependency_path(&self) -> Option<&Path> {
        self.dependency_path.as_deref().map(PathBuf::as_path)
    }

    /// Cycle path for cyclic failures (ordered, includes repeated terminal node).
    pub fn cycle(&self) -> &[PathBuf] {
        &self.cycle
    }

    /// Structured diagnostic lines.
    pub fn diagnostics(&self) -> &[String] {
        &self.diagnostics
    }
}

impl fmt::Display for CargoPathDependencyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.kind, self.detail)?;
        if let Some(manifest_path) = &self.manifest_path {
            write!(f, " (manifest: {})", manifest_path.display())?;
        }
        if let Some(dependency_name) = &self.dependency_name {
            write!(f, " (dependency: {dependency_name})")?;
        }
        if let Some(dependency_path) = &self.dependency_path {
            write!(f, " (path: {})", dependency_path.display())?;
        }
        Ok(())
    }
}

impl std::error::Error for CargoPathDependencyError {}

/// Resolve local Cargo path dependencies for `entrypoint` using the default topology policy.
pub fn resolve_cargo_path_dependency_graph(
    entrypoint: &Path,
) -> Result<CargoPathDependencyGraph, CargoPathDependencyError> {
    resolve_cargo_path_dependency_graph_with_policy(entrypoint, &PathTopologyPolicy::default())
}

/// Resolve local Cargo path dependencies for `entrypoint` with explicit topology policy.
pub fn resolve_cargo_path_dependency_graph_with_policy(
    entrypoint: &Path,
    policy: &PathTopologyPolicy,
) -> Result<CargoPathDependencyGraph, CargoPathDependencyError> {
    resolve_cargo_path_dependency_graph_with_policy_and_provider(
        entrypoint,
        policy,
        invoke_cargo_metadata,
    )
}

fn resolve_cargo_path_dependency_graph_with_policy_and_provider<F>(
    entrypoint: &Path,
    policy: &PathTopologyPolicy,
    metadata_provider: F,
) -> Result<CargoPathDependencyGraph, CargoPathDependencyError>
where
    F: Fn(&Path) -> Result<String, CargoPathDependencyError>,
{
    let entry_manifest = resolve_entry_manifest(entrypoint, policy)?;

    match resolve_from_metadata(&entry_manifest, policy, &metadata_provider) {
        Ok(graph) => Ok(graph),
        Err(metadata_error) => match resolve_from_manifest_fallback(&entry_manifest, policy) {
            Ok(graph) => Ok(graph),
            Err(mut error) => {
                error.push_diagnostic(format!("metadata phase failure: {metadata_error}"));
                if !metadata_error.diagnostics().is_empty() {
                    error.push_diagnostic("metadata diagnostics follow".to_string());
                    error
                        .diagnostics
                        .extend(metadata_error.diagnostics().iter().cloned());
                }
                Err(error)
            }
        },
    }
}

fn resolve_entry_manifest(
    entrypoint: &Path,
    policy: &PathTopologyPolicy,
) -> Result<PathBuf, CargoPathDependencyError> {
    let maybe_manifest = entrypoint
        .file_name()
        .is_some_and(|name| name == "Cargo.toml");
    let root_candidate = if maybe_manifest {
        entrypoint.parent().ok_or_else(|| {
            CargoPathDependencyError::new(
                CargoPathDependencyErrorKind::ManifestParseFailure,
                format!("invalid manifest path: {}", entrypoint.display()),
            )
        })?
    } else {
        entrypoint
    };

    let normalized_root = normalize_path_for_policy(
        root_candidate,
        policy,
        None,
        None,
        "resolve entrypoint root",
    )?;
    let manifest_path = normalized_root.join("Cargo.toml");
    if !manifest_path.is_file() {
        return Err(CargoPathDependencyError::new(
            CargoPathDependencyErrorKind::ManifestParseFailure,
            format!("manifest does not exist: {}", manifest_path.display()),
        )
        .with_manifest_path(manifest_path));
    }

    Ok(manifest_path)
}

fn invoke_cargo_metadata(manifest_path: &Path) -> Result<String, CargoPathDependencyError> {
    let output = Command::new("cargo")
        .arg("metadata")
        .arg("--format-version")
        .arg("1")
        .arg("--manifest-path")
        .arg(manifest_path)
        .output()
        .map_err(|error| {
            CargoPathDependencyError::new(
                CargoPathDependencyErrorKind::MetadataInvocationFailure,
                format!("failed to execute cargo metadata: {error}"),
            )
            .with_manifest_path(manifest_path)
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        let detail = if stderr.trim().is_empty() {
            format!("cargo metadata exited with status {}", output.status)
        } else {
            stderr.trim().to_string()
        };
        return Err(CargoPathDependencyError::new(
            CargoPathDependencyErrorKind::MetadataInvocationFailure,
            detail,
        )
        .with_manifest_path(manifest_path));
    }

    String::from_utf8(output.stdout).map_err(|error| {
        CargoPathDependencyError::new(
            CargoPathDependencyErrorKind::MetadataParseFailure,
            format!("metadata stdout is not valid UTF-8: {error}"),
        )
        .with_manifest_path(manifest_path)
    })
}

#[derive(Debug, Default)]
struct PartialGraph {
    workspace_root: Option<PathBuf>,
    roots: BTreeSet<PathBuf>,
    packages: BTreeMap<PathBuf, PackageRecord>,
    adjacency: BTreeMap<PathBuf, BTreeSet<EdgeTail>>,
}

impl PartialGraph {
    fn add_root(&mut self, root: PathBuf) {
        self.roots.insert(root);
    }

    fn add_package(
        &mut self,
        package_root: PathBuf,
        manifest_path: PathBuf,
        package_name: String,
        workspace_member: bool,
    ) {
        self.packages
            .entry(package_root.clone())
            .and_modify(|existing| {
                if existing.package_name == default_package_name(&package_root)
                    && package_name != existing.package_name
                {
                    existing.package_name = package_name.clone();
                }
                existing.workspace_member |= workspace_member;
                existing.manifest_path = manifest_path.clone();
            })
            .or_insert(PackageRecord {
                manifest_path,
                package_name,
                workspace_member,
            });
        self.adjacency.entry(package_root).or_default();
    }

    fn add_edge(&mut self, from: PathBuf, to: PathBuf, dependency_name: String) {
        self.adjacency.entry(from).or_default().insert(EdgeTail {
            to,
            dependency_name,
        });
    }
}

#[derive(Debug, Clone)]
struct PackageRecord {
    manifest_path: PathBuf,
    package_name: String,
    workspace_member: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct EdgeTail {
    to: PathBuf,
    dependency_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct EdgeRecord {
    from: PathBuf,
    to: PathBuf,
    dependency_name: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VisitState {
    Visiting,
    Visited,
}

fn finalize_graph(
    entry_manifest_path: PathBuf,
    partial: PartialGraph,
) -> Result<CargoPathDependencyGraph, CargoPathDependencyError> {
    let mut states: BTreeMap<PathBuf, VisitState> = BTreeMap::new();
    let mut stack: Vec<PathBuf> = Vec::new();
    let mut reachable_nodes: BTreeSet<PathBuf> = BTreeSet::new();
    let mut reachable_edges: BTreeSet<EdgeRecord> = BTreeSet::new();

    for root in &partial.roots {
        traverse_for_reachable(
            root,
            &partial.adjacency,
            &mut states,
            &mut stack,
            &mut reachable_nodes,
            &mut reachable_edges,
        )?;
    }

    let packages = reachable_nodes
        .iter()
        .map(|root| {
            if let Some(package) = partial.packages.get(root) {
                CargoPathDependencyPackage {
                    package_root: root.clone(),
                    manifest_path: package.manifest_path.clone(),
                    package_name: package.package_name.clone(),
                    workspace_member: package.workspace_member,
                }
            } else {
                CargoPathDependencyPackage {
                    package_root: root.clone(),
                    manifest_path: root.join("Cargo.toml"),
                    package_name: default_package_name(root),
                    workspace_member: partial.roots.contains(root),
                }
            }
        })
        .collect::<Vec<_>>();

    let edges = reachable_edges
        .into_iter()
        .map(|edge| CargoPathDependencyEdge {
            from: edge.from,
            to: edge.to,
            dependency_name: edge.dependency_name,
        })
        .collect::<Vec<_>>();

    Ok(CargoPathDependencyGraph {
        entry_manifest_path,
        workspace_root: partial.workspace_root,
        root_packages: partial.roots.into_iter().collect(),
        packages,
        edges,
    })
}

fn traverse_for_reachable(
    node: &Path,
    adjacency: &BTreeMap<PathBuf, BTreeSet<EdgeTail>>,
    states: &mut BTreeMap<PathBuf, VisitState>,
    stack: &mut Vec<PathBuf>,
    reachable_nodes: &mut BTreeSet<PathBuf>,
    reachable_edges: &mut BTreeSet<EdgeRecord>,
) -> Result<(), CargoPathDependencyError> {
    match states.get(node).copied() {
        Some(VisitState::Visited) => return Ok(()),
        Some(VisitState::Visiting) => {
            let cycle = cycle_from_stack(stack, node);
            return Err(CargoPathDependencyError::new(
                CargoPathDependencyErrorKind::CyclicDependency,
                "cycle detected while traversing dependency graph",
            )
            .with_cycle(cycle));
        }
        None => {}
    }

    states.insert(node.to_path_buf(), VisitState::Visiting);
    stack.push(node.to_path_buf());
    reachable_nodes.insert(node.to_path_buf());

    if let Some(edges) = adjacency.get(node) {
        for edge in edges {
            reachable_edges.insert(EdgeRecord {
                from: node.to_path_buf(),
                to: edge.to.clone(),
                dependency_name: edge.dependency_name.clone(),
            });
            if states.get(&edge.to) == Some(&VisitState::Visiting) {
                let cycle = cycle_from_stack(stack, &edge.to);
                return Err(CargoPathDependencyError::new(
                    CargoPathDependencyErrorKind::CyclicDependency,
                    format!(
                        "cycle detected between {} and {}",
                        node.display(),
                        edge.to.display()
                    ),
                )
                .with_cycle(cycle));
            }
            traverse_for_reachable(
                &edge.to,
                adjacency,
                states,
                stack,
                reachable_nodes,
                reachable_edges,
            )?;
        }
    }

    stack.pop();
    states.insert(node.to_path_buf(), VisitState::Visited);
    Ok(())
}

fn cycle_from_stack(stack: &[PathBuf], terminal: &Path) -> Vec<PathBuf> {
    if let Some(position) = stack.iter().position(|entry| entry == terminal) {
        let mut cycle = stack[position..].to_vec();
        cycle.push(terminal.to_path_buf());
        cycle
    } else {
        vec![terminal.to_path_buf()]
    }
}

fn default_package_name(root: &Path) -> String {
    root.file_name()
        .and_then(|segment| segment.to_str())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| root.display().to_string())
}

fn validate_absolute_dependency_scope(
    dependency_candidate: &Path,
    policy: &PathTopologyPolicy,
    manifest_path: &Path,
    dependency_name: &str,
    context: &str,
) -> Result<(), CargoPathDependencyError> {
    if !dependency_candidate.is_absolute() {
        return Ok(());
    }
    if dependency_candidate.starts_with(policy.canonical_root())
        || dependency_candidate.starts_with(policy.alias_root())
    {
        return Ok(());
    }

    Err(CargoPathDependencyError::new(
        CargoPathDependencyErrorKind::PathPolicyViolation,
        format!("{context}: {}", dependency_candidate.display()),
    )
    .with_manifest_path(manifest_path)
    .with_dependency_name(dependency_name.to_string())
    .with_dependency_path(dependency_candidate.to_path_buf())
    .with_diagnostic(format!(
        "allowed canonical root: {}",
        policy.canonical_root().display()
    ))
    .with_diagnostic(format!(
        "allowed alias root: {}",
        policy.alias_root().display()
    )))
}

fn normalize_path_for_policy(
    path: &Path,
    policy: &PathTopologyPolicy,
    manifest_path: Option<&Path>,
    dependency_name: Option<&str>,
    context: &str,
) -> Result<PathBuf, CargoPathDependencyError> {
    normalize_project_path_with_policy(path, policy)
        .map(|normalized| normalized.canonical_path().to_path_buf())
        .map_err(|error| {
            let mapped_kind = if error.kind() == &PathNormalizationErrorKind::InputResolveFailed {
                CargoPathDependencyErrorKind::MissingPathDependency
            } else {
                CargoPathDependencyErrorKind::PathPolicyViolation
            };
            let mut mapped = CargoPathDependencyError::new(
                mapped_kind,
                format!("{context}: {} ({})", error.kind(), error.detail()),
            )
            .with_diagnostic(format!("normalization_error_kind={}", error.kind()))
            .with_diagnostic(format!("normalization_detail={}", error.detail()))
            .with_diagnostics(error.decision_trace().iter().map(ToString::to_string));

            if let Some(manifest_path) = manifest_path {
                mapped = mapped.with_manifest_path(manifest_path);
            }
            if let Some(dependency_name) = dependency_name {
                mapped = mapped.with_dependency_name(dependency_name.to_string());
            }
            mapped.with_dependency_path(path)
        })
}

#[derive(Debug, Deserialize)]
struct MetadataDocument {
    #[serde(default)]
    packages: Vec<MetadataPackage>,
    #[serde(default)]
    workspace_members: Vec<String>,
    workspace_root: Option<String>,
    resolve: Option<MetadataResolve>,
}

#[derive(Debug, Deserialize)]
struct MetadataResolve {
    root: Option<String>,
}

#[derive(Debug, Deserialize)]
struct MetadataPackage {
    id: String,
    name: String,
    manifest_path: String,
    #[serde(default)]
    dependencies: Vec<MetadataDependency>,
}

#[derive(Debug, Deserialize)]
struct MetadataDependency {
    name: String,
    path: Option<String>,
}

#[derive(Debug)]
struct MetadataPackageRecord {
    package_root: PathBuf,
    manifest_path: PathBuf,
    dependencies: Vec<MetadataDependency>,
}

fn resolve_from_metadata<F>(
    entry_manifest_path: &Path,
    policy: &PathTopologyPolicy,
    metadata_provider: &F,
) -> Result<CargoPathDependencyGraph, CargoPathDependencyError>
where
    F: Fn(&Path) -> Result<String, CargoPathDependencyError>,
{
    let raw_metadata = metadata_provider(entry_manifest_path)?;
    let metadata = serde_json::from_str::<MetadataDocument>(&raw_metadata).map_err(|error| {
        CargoPathDependencyError::new(
            CargoPathDependencyErrorKind::MetadataParseFailure,
            format!("failed to parse cargo metadata JSON: {error}"),
        )
        .with_manifest_path(entry_manifest_path)
    })?;

    let mut partial = PartialGraph::default();
    let workspace_member_ids = metadata
        .workspace_members
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut id_to_root: BTreeMap<String, PathBuf> = BTreeMap::new();
    let mut package_records: Vec<MetadataPackageRecord> = Vec::new();

    for package in metadata.packages {
        let manifest_path = PathBuf::from(&package.manifest_path);
        let manifest_dir = manifest_path.parent().ok_or_else(|| {
            CargoPathDependencyError::new(
                CargoPathDependencyErrorKind::MetadataParseFailure,
                format!(
                    "metadata package has invalid manifest path: {}",
                    manifest_path.display()
                ),
            )
            .with_manifest_path(entry_manifest_path)
        })?;
        let package_root = normalize_path_for_policy(
            manifest_dir,
            policy,
            Some(entry_manifest_path),
            None,
            "normalize metadata package root",
        )?;
        let canonical_manifest_path = package_root.join("Cargo.toml");
        let workspace_member = workspace_member_ids.contains(&package.id);

        partial.add_package(
            package_root.clone(),
            canonical_manifest_path.clone(),
            package.name.clone(),
            workspace_member,
        );

        id_to_root.insert(package.id.clone(), package_root.clone());
        package_records.push(MetadataPackageRecord {
            package_root,
            manifest_path: canonical_manifest_path,
            dependencies: package.dependencies,
        });
    }

    for package in &package_records {
        for dependency in &package.dependencies {
            let Some(raw_path) = dependency.path.as_deref() else {
                continue;
            };

            let dependency_candidate =
                resolve_dependency_candidate(&package.package_root, raw_path);
            validate_absolute_dependency_scope(
                &dependency_candidate,
                policy,
                &package.manifest_path,
                &dependency.name,
                "metadata dependency path policy violation",
            )?;
            if !dependency_candidate.exists() {
                return Err(CargoPathDependencyError::new(
                    CargoPathDependencyErrorKind::MissingPathDependency,
                    format!(
                        "metadata dependency path does not exist: {}",
                        dependency_candidate.display()
                    ),
                )
                .with_manifest_path(package.manifest_path.clone())
                .with_dependency_name(dependency.name.clone())
                .with_dependency_path(dependency_candidate));
            }

            let dependency_root = normalize_path_for_policy(
                &dependency_candidate,
                policy,
                Some(&package.manifest_path),
                Some(&dependency.name),
                "normalize metadata dependency path",
            )?;
            let dependency_manifest = dependency_root.join("Cargo.toml");
            if !dependency_manifest.is_file() {
                return Err(CargoPathDependencyError::new(
                    CargoPathDependencyErrorKind::MissingPathDependency,
                    format!(
                        "dependency manifest is missing: {}",
                        dependency_manifest.display()
                    ),
                )
                .with_manifest_path(package.manifest_path.clone())
                .with_dependency_name(dependency.name.clone())
                .with_dependency_path(dependency_manifest));
            }

            partial.add_package(
                dependency_root.clone(),
                dependency_manifest,
                dependency.name.clone(),
                false,
            );
            partial.add_edge(
                package.package_root.clone(),
                dependency_root,
                dependency.name.clone(),
            );
        }
    }

    if let Some(workspace_root) = metadata.workspace_root {
        let workspace_root = normalize_path_for_policy(
            Path::new(&workspace_root),
            policy,
            Some(entry_manifest_path),
            None,
            "normalize metadata workspace root",
        )?;
        partial.workspace_root = Some(workspace_root);
    }

    if !workspace_member_ids.is_empty() {
        for workspace_id in &workspace_member_ids {
            let root = id_to_root.get(workspace_id).ok_or_else(|| {
                CargoPathDependencyError::new(
                    CargoPathDependencyErrorKind::MetadataParseFailure,
                    format!("workspace member id missing from package list: {workspace_id}"),
                )
                .with_manifest_path(entry_manifest_path)
            })?;
            partial.add_root(root.clone());
            if let Some(package) = partial.packages.get_mut(root) {
                package.workspace_member = true;
            }
        }
    } else if let Some(resolve_root) = metadata.resolve.and_then(|resolve| resolve.root) {
        let root = id_to_root.get(&resolve_root).ok_or_else(|| {
            CargoPathDependencyError::new(
                CargoPathDependencyErrorKind::MetadataParseFailure,
                format!("resolve root id missing from package list: {resolve_root}"),
            )
            .with_manifest_path(entry_manifest_path)
        })?;
        partial.add_root(root.clone());
    } else {
        let entry_root = entry_manifest_path.parent().ok_or_else(|| {
            CargoPathDependencyError::new(
                CargoPathDependencyErrorKind::MetadataParseFailure,
                format!(
                    "entry manifest has no parent: {}",
                    entry_manifest_path.display()
                ),
            )
            .with_manifest_path(entry_manifest_path)
        })?;
        partial.add_root(entry_root.to_path_buf());
    }

    for root in partial.roots.clone() {
        partial
            .packages
            .entry(root.clone())
            .or_insert(PackageRecord {
                manifest_path: root.join("Cargo.toml"),
                package_name: default_package_name(&root),
                workspace_member: true,
            });
    }

    finalize_graph(entry_manifest_path.to_path_buf(), partial)
}

#[derive(Debug, Clone)]
struct ManifestDocument {
    package_name: Option<String>,
    has_workspace: bool,
    workspace_members: Vec<String>,
    path_dependencies: Vec<ManifestDependency>,
}

#[derive(Debug, Clone)]
struct ManifestDependency {
    dependency_name: String,
    dependency_path: String,
}

fn resolve_from_manifest_fallback(
    entry_manifest_path: &Path,
    policy: &PathTopologyPolicy,
) -> Result<CargoPathDependencyGraph, CargoPathDependencyError> {
    let entry_manifest = read_manifest_document(entry_manifest_path)?;
    let entry_root = entry_manifest_path.parent().ok_or_else(|| {
        CargoPathDependencyError::new(
            CargoPathDependencyErrorKind::ManifestParseFailure,
            format!(
                "entry manifest has no parent: {}",
                entry_manifest_path.display()
            ),
        )
        .with_manifest_path(entry_manifest_path)
    })?;
    let entry_root = normalize_path_for_policy(
        entry_root,
        policy,
        Some(entry_manifest_path),
        None,
        "normalize fallback entry root",
    )?;

    let mut partial = PartialGraph::default();
    if entry_manifest.has_workspace {
        partial.workspace_root = Some(entry_root.clone());
    }

    let workspace_member_manifests = expand_workspace_members(
        &entry_root,
        &entry_manifest.workspace_members,
        entry_manifest_path,
    )?;
    let workspace_member_set = workspace_member_manifests
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let include_entry_manifest =
        entry_manifest.package_name.is_some() || workspace_member_set.is_empty();

    let mut manifest_cache: BTreeMap<PathBuf, ManifestDocument> = BTreeMap::new();
    let mut states: BTreeMap<PathBuf, VisitState> = BTreeMap::new();
    let mut stack: Vec<PathBuf> = Vec::new();

    for manifest_path in &workspace_member_set {
        visit_manifest_recursive(
            manifest_path,
            policy,
            &workspace_member_set,
            true,
            &mut partial,
            &mut manifest_cache,
            &mut states,
            &mut stack,
        )?;
    }
    if include_entry_manifest {
        visit_manifest_recursive(
            entry_manifest_path,
            policy,
            &workspace_member_set,
            true,
            &mut partial,
            &mut manifest_cache,
            &mut states,
            &mut stack,
        )?;
    }

    finalize_graph(entry_manifest_path.to_path_buf(), partial)
}

#[allow(clippy::too_many_arguments)]
fn visit_manifest_recursive(
    manifest_path: &Path,
    policy: &PathTopologyPolicy,
    workspace_member_manifests: &BTreeSet<PathBuf>,
    mark_workspace_member: bool,
    partial: &mut PartialGraph,
    manifest_cache: &mut BTreeMap<PathBuf, ManifestDocument>,
    states: &mut BTreeMap<PathBuf, VisitState>,
    stack: &mut Vec<PathBuf>,
) -> Result<PathBuf, CargoPathDependencyError> {
    let manifest_root = manifest_path.parent().ok_or_else(|| {
        CargoPathDependencyError::new(
            CargoPathDependencyErrorKind::ManifestParseFailure,
            format!("manifest has no parent: {}", manifest_path.display()),
        )
        .with_manifest_path(manifest_path)
    })?;
    let package_root = normalize_path_for_policy(
        manifest_root,
        policy,
        Some(manifest_path),
        None,
        "normalize manifest package root",
    )?;
    let canonical_manifest = package_root.join("Cargo.toml");
    if !canonical_manifest.is_file() {
        return Err(CargoPathDependencyError::new(
            CargoPathDependencyErrorKind::ManifestParseFailure,
            format!("manifest file missing: {}", canonical_manifest.display()),
        )
        .with_manifest_path(canonical_manifest));
    }

    if states.get(&package_root) == Some(&VisitState::Visiting) {
        let cycle = cycle_from_stack(stack, &package_root);
        return Err(CargoPathDependencyError::new(
            CargoPathDependencyErrorKind::CyclicDependency,
            format!(
                "cyclic path dependency detected at {}",
                package_root.display()
            ),
        )
        .with_cycle(cycle));
    }
    if states.get(&package_root) == Some(&VisitState::Visited) {
        if mark_workspace_member {
            partial.add_root(package_root.clone());
            if let Some(package) = partial.packages.get_mut(&package_root) {
                package.workspace_member = true;
            }
        }
        return Ok(package_root);
    }

    states.insert(package_root.clone(), VisitState::Visiting);
    stack.push(package_root.clone());

    let manifest = if let Some(cached) = manifest_cache.get(&canonical_manifest) {
        cached.clone()
    } else {
        let parsed = read_manifest_document(&canonical_manifest)?;
        manifest_cache.insert(canonical_manifest.clone(), parsed.clone());
        parsed
    };

    let workspace_member =
        mark_workspace_member || workspace_member_manifests.contains(&canonical_manifest);
    partial.add_package(
        package_root.clone(),
        canonical_manifest.clone(),
        manifest
            .package_name
            .clone()
            .unwrap_or_else(|| default_package_name(&package_root)),
        workspace_member,
    );
    if workspace_member {
        partial.add_root(package_root.clone());
    }

    for dependency in &manifest.path_dependencies {
        let dependency_candidate =
            resolve_dependency_candidate(&package_root, &dependency.dependency_path);
        validate_absolute_dependency_scope(
            &dependency_candidate,
            policy,
            &canonical_manifest,
            &dependency.dependency_name,
            "manifest dependency path policy violation",
        )?;
        if !dependency_candidate.exists() {
            return Err(CargoPathDependencyError::new(
                CargoPathDependencyErrorKind::MissingPathDependency,
                format!(
                    "dependency path does not exist: {}",
                    dependency_candidate.display()
                ),
            )
            .with_manifest_path(canonical_manifest.clone())
            .with_dependency_name(dependency.dependency_name.clone())
            .with_dependency_path(dependency_candidate));
        }

        let dependency_root = normalize_path_for_policy(
            &dependency_candidate,
            policy,
            Some(&canonical_manifest),
            Some(&dependency.dependency_name),
            "normalize manifest dependency path",
        )?;
        let dependency_manifest = dependency_root.join("Cargo.toml");
        if !dependency_manifest.is_file() {
            return Err(CargoPathDependencyError::new(
                CargoPathDependencyErrorKind::MissingPathDependency,
                format!(
                    "dependency manifest missing: {}",
                    dependency_manifest.display()
                ),
            )
            .with_manifest_path(canonical_manifest.clone())
            .with_dependency_name(dependency.dependency_name.clone())
            .with_dependency_path(dependency_manifest));
        }

        partial.add_edge(
            package_root.clone(),
            dependency_root.clone(),
            dependency.dependency_name.clone(),
        );
        visit_manifest_recursive(
            &dependency_manifest,
            policy,
            workspace_member_manifests,
            false,
            partial,
            manifest_cache,
            states,
            stack,
        )?;
    }

    stack.pop();
    states.insert(package_root, VisitState::Visited);
    Ok(canonical_manifest
        .parent()
        .unwrap_or_else(|| Path::new("/"))
        .to_path_buf())
}

fn resolve_dependency_candidate(base_root: &Path, raw_dependency_path: &str) -> PathBuf {
    let raw = PathBuf::from(raw_dependency_path);
    let resolved = if raw.is_absolute() {
        raw
    } else {
        base_root.join(raw)
    };
    if resolved
        .file_name()
        .is_some_and(|file_name| file_name == "Cargo.toml")
    {
        resolved.parent().map(Path::to_path_buf).unwrap_or(resolved)
    } else {
        resolved
    }
}

fn read_manifest_document(
    manifest_path: &Path,
) -> Result<ManifestDocument, CargoPathDependencyError> {
    let contents = std::fs::read_to_string(manifest_path).map_err(|error| {
        CargoPathDependencyError::new(
            CargoPathDependencyErrorKind::ManifestParseFailure,
            format!(
                "failed to read manifest {}: {error}",
                manifest_path.display()
            ),
        )
        .with_manifest_path(manifest_path)
    })?;
    let table = toml::from_str::<toml::Table>(&contents).map_err(|error| {
        CargoPathDependencyError::new(
            CargoPathDependencyErrorKind::ManifestParseFailure,
            format!(
                "failed to parse manifest {}: {error}",
                manifest_path.display()
            ),
        )
        .with_manifest_path(manifest_path)
    })?;

    let package_name = table
        .get("package")
        .and_then(toml::Value::as_table)
        .and_then(|package| package.get("name"))
        .and_then(toml::Value::as_str)
        .map(ToOwned::to_owned);
    let has_workspace = table.contains_key("workspace");
    let workspace_members = table
        .get("workspace")
        .and_then(toml::Value::as_table)
        .and_then(|workspace| workspace.get("members"))
        .and_then(toml::Value::as_array)
        .map(|members| {
            members
                .iter()
                .filter_map(toml::Value::as_str)
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let mut path_dependencies = Vec::new();
    collect_dependency_paths(table.get("dependencies"), &mut path_dependencies);
    collect_dependency_paths(table.get("dev-dependencies"), &mut path_dependencies);
    collect_dependency_paths(table.get("build-dependencies"), &mut path_dependencies);

    if let Some(targets) = table.get("target").and_then(toml::Value::as_table) {
        for target_config in targets.values() {
            if let Some(target_table) = target_config.as_table() {
                collect_dependency_paths(target_table.get("dependencies"), &mut path_dependencies);
                collect_dependency_paths(
                    target_table.get("dev-dependencies"),
                    &mut path_dependencies,
                );
                collect_dependency_paths(
                    target_table.get("build-dependencies"),
                    &mut path_dependencies,
                );
            }
        }
    }

    Ok(ManifestDocument {
        package_name,
        has_workspace,
        workspace_members,
        path_dependencies,
    })
}

fn collect_dependency_paths(
    maybe_table_value: Option<&toml::Value>,
    collector: &mut Vec<ManifestDependency>,
) {
    let Some(table) = maybe_table_value.and_then(toml::Value::as_table) else {
        return;
    };
    for (dependency_name, dependency_value) in table {
        let Some(dependency_table) = dependency_value.as_table() else {
            continue;
        };
        let Some(path) = dependency_table.get("path").and_then(toml::Value::as_str) else {
            continue;
        };
        collector.push(ManifestDependency {
            dependency_name: dependency_name.clone(),
            dependency_path: path.to_string(),
        });
    }
}

fn expand_workspace_members(
    workspace_root: &Path,
    members: &[String],
    manifest_path: &Path,
) -> Result<Vec<PathBuf>, CargoPathDependencyError> {
    let mut manifests = BTreeSet::new();
    for member in members {
        let expanded_paths = expand_member_pattern(workspace_root, member).map_err(|error| {
            CargoPathDependencyError::new(
                CargoPathDependencyErrorKind::ManifestParseFailure,
                format!("failed to expand workspace member '{member}': {error}"),
            )
            .with_manifest_path(manifest_path)
        })?;
        for candidate in expanded_paths {
            let manifest_candidate = if candidate
                .file_name()
                .is_some_and(|file_name| file_name == "Cargo.toml")
            {
                candidate
            } else {
                candidate.join("Cargo.toml")
            };
            if !manifest_candidate.is_file() {
                return Err(CargoPathDependencyError::new(
                    CargoPathDependencyErrorKind::MissingPathDependency,
                    format!(
                        "workspace member manifest missing: {}",
                        manifest_candidate.display()
                    ),
                )
                .with_manifest_path(manifest_path)
                .with_dependency_name(member.clone())
                .with_dependency_path(manifest_candidate));
            }
            manifests.insert(manifest_candidate);
        }
    }
    Ok(manifests.into_iter().collect())
}

fn expand_member_pattern(base: &Path, pattern: &str) -> Result<Vec<PathBuf>, std::io::Error> {
    if !contains_glob(pattern) {
        return Ok(vec![base.join(pattern)]);
    }

    let mut candidates = vec![base.to_path_buf()];
    let normalized_pattern = pattern.replace('\\', "/");
    for segment in normalized_pattern.split('/') {
        if segment.is_empty() || segment == "." {
            continue;
        }
        if segment == ".." {
            candidates = candidates
                .into_iter()
                .map(|candidate| {
                    candidate
                        .parent()
                        .unwrap_or_else(|| Path::new("/"))
                        .to_path_buf()
                })
                .collect();
            continue;
        }

        let wildcard_segment = contains_wildcard(segment);
        let mut next_candidates = Vec::new();
        for candidate in &candidates {
            if wildcard_segment {
                if !candidate.is_dir() {
                    continue;
                }
                for entry in std::fs::read_dir(candidate)? {
                    let entry = entry?;
                    let file_name = entry.file_name();
                    let Some(file_name) = file_name.to_str() else {
                        continue;
                    };
                    if wildcard_match(segment, file_name) {
                        next_candidates.push(entry.path());
                    }
                }
            } else {
                next_candidates.push(candidate.join(segment));
            }
        }
        candidates = next_candidates;
    }

    Ok(candidates)
}

fn contains_glob(pattern: &str) -> bool {
    pattern.chars().any(|ch| matches!(ch, '*' | '?' | '['))
}

fn contains_wildcard(segment: &str) -> bool {
    segment.contains('*') || segment.contains('?')
}

fn wildcard_match(pattern: &str, value: &str) -> bool {
    wildcard_match_bytes(pattern.as_bytes(), value.as_bytes())
}

fn wildcard_match_bytes(pattern: &[u8], value: &[u8]) -> bool {
    if pattern.is_empty() {
        return value.is_empty();
    }
    if pattern[0] == b'*' {
        for index in 0..=value.len() {
            if wildcard_match_bytes(&pattern[1..], &value[index..]) {
                return true;
            }
        }
        return false;
    }
    if value.is_empty() {
        return false;
    }
    if pattern[0] == b'?' || pattern[0] == value[0] {
        return wildcard_match_bytes(&pattern[1..], &value[1..]);
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::e2e::{MultiRepoFixtureConfig, reset_multi_repo_fixtures};
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[cfg(unix)]
    use std::os::unix::fs::symlink;

    static FIXTURE_COUNTER: AtomicU64 = AtomicU64::new(0);

    #[cfg(unix)]
    struct TopologyFixture {
        root: PathBuf,
        canonical_root: PathBuf,
        alias_root: PathBuf,
    }

    #[cfg(unix)]
    impl TopologyFixture {
        fn new(prefix: &str) -> Self {
            let id = FIXTURE_COUNTER.fetch_add(1, Ordering::SeqCst);
            let root = std::env::temp_dir().join(format!(
                "rch-cargo-path-deps-{}-{}-{}",
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

    #[cfg(unix)]
    impl Drop for TopologyFixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[cfg(unix)]
    fn write_lib_crate(root: &Path, crate_name: &str, deps: &[(&str, &str)]) {
        fs::create_dir_all(root.join("src")).expect("create crate src");
        fs::write(root.join("Cargo.toml"), crate_manifest(crate_name, deps))
            .expect("write manifest");
        fs::write(
            root.join("src/lib.rs"),
            format!(
                "pub fn {}() -> &'static str {{ \"{}\" }}\n",
                crate_name, crate_name
            ),
        )
        .expect("write lib.rs");
    }

    #[cfg(unix)]
    fn write_bin_crate(root: &Path, crate_name: &str, deps: &[(&str, &str)]) {
        fs::create_dir_all(root.join("src")).expect("create crate src");
        fs::write(root.join("Cargo.toml"), crate_manifest(crate_name, deps))
            .expect("write manifest");
        fs::write(
            root.join("src/main.rs"),
            format!("fn main() {{ println!(\"{}\"); }}\n", crate_name),
        )
        .expect("write main.rs");
    }

    #[cfg(unix)]
    fn crate_manifest(crate_name: &str, deps: &[(&str, &str)]) -> String {
        let mut dependencies = String::new();
        for (name, path) in deps {
            dependencies.push_str(&format!("{name} = {{ path = \"{path}\" }}\n"));
        }
        format!(
            "[package]\nname = \"{crate_name}\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\n[dependencies]\n{dependencies}"
        )
    }

    #[cfg(unix)]
    #[test]
    fn resolves_workspace_transitive_path_dependencies() {
        let fixture = TopologyFixture::new("workspace");
        let scenario_root = fixture.canonical_root.join("workspace_transitive");
        let workspace_root = scenario_root.join("workspace");
        let shared_root = scenario_root.join("shared/shared_lib");
        let util_root = workspace_root.join("crates/util");
        let app_root = workspace_root.join("crates/app");

        write_lib_crate(&shared_root, "workspace_shared", &[]);
        write_lib_crate(
            &util_root,
            "workspace_util",
            &[("workspace_shared", "../../../shared/shared_lib")],
        );
        write_bin_crate(&app_root, "workspace_app", &[("workspace_util", "../util")]);
        fs::create_dir_all(&workspace_root).expect("create workspace root");
        fs::write(
            workspace_root.join("Cargo.toml"),
            "[workspace]\nmembers = [\"crates/app\", \"crates/util\"]\nresolver = \"3\"\n",
        )
        .expect("write workspace manifest");

        let graph =
            resolve_cargo_path_dependency_graph_with_policy(&workspace_root, &fixture.policy())
                .expect("resolve workspace graph");

        let app_root = app_root.canonicalize().expect("canonical app root");
        let util_root = util_root.canonicalize().expect("canonical util root");
        let shared_root = shared_root.canonicalize().expect("canonical shared root");
        assert_eq!(
            graph.root_packages,
            vec![app_root.clone(), util_root.clone()]
        );
        let package_roots = graph
            .packages
            .iter()
            .map(|package| package.package_root.clone())
            .collect::<Vec<_>>();
        assert!(
            package_roots
                .windows(2)
                .all(|window| window[0] <= window[1]),
            "packages should be deterministically sorted"
        );
        assert_eq!(
            package_roots.into_iter().collect::<BTreeSet<_>>(),
            BTreeSet::from([app_root.clone(), shared_root.clone(), util_root.clone()])
        );
        assert_eq!(
            graph.edges,
            vec![
                CargoPathDependencyEdge {
                    from: app_root,
                    to: util_root.clone(),
                    dependency_name: "workspace_util".to_string(),
                },
                CargoPathDependencyEdge {
                    from: util_root,
                    to: shared_root,
                    dependency_name: "workspace_shared".to_string(),
                },
            ]
        );
    }

    #[cfg(unix)]
    #[test]
    fn resolves_virtual_workspace_members_from_alias_path() {
        let fixture = TopologyFixture::new("virtual-workspace");
        let scenario_root = fixture.canonical_root.join("virtual_workspace");
        let workspace_root = scenario_root.join("ws");
        let member_a = workspace_root.join("members/a");
        let member_b = workspace_root.join("members/b");

        write_lib_crate(&member_b, "virtual_b", &[]);
        write_lib_crate(&member_a, "virtual_a", &[("virtual_b", "../b")]);
        fs::create_dir_all(&workspace_root).expect("create workspace root");
        fs::write(
            workspace_root.join("Cargo.toml"),
            "[workspace]\nmembers = [\"members/a\", \"members/b\"]\nresolver = \"3\"\n",
        )
        .expect("write workspace manifest");

        let relative = workspace_root
            .strip_prefix(&fixture.canonical_root)
            .expect("workspace under canonical root");
        let alias_workspace = fixture.alias_root.join(relative);

        let graph =
            resolve_cargo_path_dependency_graph_with_policy(&alias_workspace, &fixture.policy())
                .expect("resolve virtual workspace graph");

        let member_a = member_a.canonicalize().expect("canonical member a");
        let member_b = member_b.canonicalize().expect("canonical member b");
        assert_eq!(
            graph.workspace_root,
            Some(
                workspace_root
                    .canonicalize()
                    .expect("canonical workspace root")
            )
        );
        assert_eq!(
            graph.root_packages,
            vec![member_a.clone(), member_b.clone()]
        );
        assert_eq!(
            graph.edges,
            vec![CargoPathDependencyEdge {
                from: member_a,
                to: member_b,
                dependency_name: "virtual_b".to_string(),
            }]
        );
    }

    #[cfg(unix)]
    #[test]
    fn resolves_nested_manifest_transitive_closure() {
        let fixture = TopologyFixture::new("nested");
        let scenario_root = fixture.canonical_root.join("nested_manifests");
        let app_root = scenario_root.join("app");
        let util_root = scenario_root.join("libs/util");
        let core_root = scenario_root.join("libs/core");

        write_lib_crate(&core_root, "nested_core", &[]);
        write_lib_crate(&util_root, "nested_util", &[("nested_core", "../core")]);
        write_bin_crate(&app_root, "nested_app", &[("nested_util", "../libs/util")]);

        let graph = resolve_cargo_path_dependency_graph_with_policy(
            &app_root.join("Cargo.toml"),
            &fixture.policy(),
        )
        .expect("resolve nested manifest graph");

        let app_root = app_root.canonicalize().expect("canonical app");
        let util_root = util_root.canonicalize().expect("canonical util");
        let core_root = core_root.canonicalize().expect("canonical core");
        assert_eq!(graph.root_packages, vec![app_root.clone()]);
        assert_eq!(
            graph.edges,
            vec![
                CargoPathDependencyEdge {
                    from: app_root,
                    to: util_root.clone(),
                    dependency_name: "nested_util".to_string(),
                },
                CargoPathDependencyEdge {
                    from: util_root,
                    to: core_root,
                    dependency_name: "nested_core".to_string(),
                },
            ]
        );
    }

    #[cfg(unix)]
    #[test]
    fn malformed_metadata_uses_manifest_fallback() {
        let fixture = TopologyFixture::new("malformed-metadata");
        let scenario_root = fixture.canonical_root.join("metadata_fallback");
        let app_root = scenario_root.join("app");
        let dep_root = scenario_root.join("dep");

        write_lib_crate(&dep_root, "fallback_dep", &[]);
        write_bin_crate(&app_root, "fallback_app", &[("fallback_dep", "../dep")]);

        let graph = resolve_cargo_path_dependency_graph_with_policy_and_provider(
            &app_root,
            &fixture.policy(),
            |_| Ok("{not-json".to_string()),
        )
        .expect("resolver should recover using fallback");

        let app_root = app_root.canonicalize().expect("canonical app");
        let dep_root = dep_root.canonicalize().expect("canonical dep");
        assert_eq!(graph.root_packages, vec![app_root.clone()]);
        assert_eq!(
            graph.edges,
            vec![CargoPathDependencyEdge {
                from: app_root,
                to: dep_root,
                dependency_name: "fallback_dep".to_string(),
            }]
        );
    }

    #[cfg(unix)]
    #[test]
    fn malformed_manifest_reports_manifest_parse_failure() {
        let fixture = TopologyFixture::new("manifest-error");
        let config = MultiRepoFixtureConfig::new(
            fixture.canonical_root.clone(),
            fixture.alias_root.clone(),
            "resolver_manifest_error",
        );
        let fixtures = reset_multi_repo_fixtures(&config).expect("generate fixture set");
        let invalid = fixtures
            .fixture("fail_invalid_manifest")
            .expect("invalid fixture metadata");

        let error = resolve_cargo_path_dependency_graph_with_policy(
            &invalid.canonical_entrypoint,
            &fixture.policy(),
        )
        .expect_err("invalid manifest must fail");
        assert_eq!(
            error.kind(),
            &CargoPathDependencyErrorKind::ManifestParseFailure
        );
    }

    #[cfg(unix)]
    #[test]
    fn missing_path_reports_missing_dependency_kind() {
        let fixture = TopologyFixture::new("missing-path");
        let config = MultiRepoFixtureConfig::new(
            fixture.canonical_root.clone(),
            fixture.alias_root.clone(),
            "resolver_missing_path",
        );
        let fixtures = reset_multi_repo_fixtures(&config).expect("generate fixture set");
        let missing = fixtures
            .fixture("fail_missing_path_dep")
            .expect("missing fixture metadata");

        let error = resolve_cargo_path_dependency_graph_with_policy(
            &missing.canonical_entrypoint,
            &fixture.policy(),
        )
        .expect_err("missing dependency must fail");
        assert_eq!(
            error.kind(),
            &CargoPathDependencyErrorKind::MissingPathDependency
        );
    }

    #[cfg(unix)]
    #[test]
    fn outside_root_reports_path_policy_violation() {
        let fixture = TopologyFixture::new("outside-root");
        let config = MultiRepoFixtureConfig::new(
            fixture.canonical_root.clone(),
            fixture.alias_root.clone(),
            "resolver_outside_root",
        );
        let fixtures = reset_multi_repo_fixtures(&config).expect("generate fixture set");
        let outside = fixtures
            .fixture("fail_outside_canonical_dep")
            .expect("outside fixture metadata");

        let error = resolve_cargo_path_dependency_graph_with_policy(
            &outside.canonical_entrypoint,
            &fixture.policy(),
        )
        .expect_err("outside root dependency must fail");
        assert_eq!(
            error.kind(),
            &CargoPathDependencyErrorKind::PathPolicyViolation
        );
    }

    #[cfg(unix)]
    #[test]
    fn cyclic_path_dependencies_report_cycle_kind() {
        let fixture = TopologyFixture::new("cycle");
        let scenario_root = fixture.canonical_root.join("cycle");
        let crate_a = scenario_root.join("a");
        let crate_b = scenario_root.join("b");

        write_lib_crate(&crate_a, "cycle_a", &[("cycle_b", "../b")]);
        write_lib_crate(&crate_b, "cycle_b", &[("cycle_a", "../a")]);

        let error = resolve_cargo_path_dependency_graph_with_policy(&crate_a, &fixture.policy())
            .expect_err("cyclic path dependencies must fail");
        assert_eq!(
            error.kind(),
            &CargoPathDependencyErrorKind::CyclicDependency
        );
        assert!(
            error.cycle().len() >= 3,
            "cycle path should include repeated terminal node"
        );
    }
}
