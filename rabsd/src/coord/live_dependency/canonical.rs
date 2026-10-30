//! Retained backing paths for the coordinator-owned canonical Cargo driver.
//!
//! Compiler arguments, dep-info and action keys keep their namespace-visible
//! names. Only filesystem observation and private output installation use this
//! capability. It is constructed by the driver, never decoded from a wrapper
//! frame, and owns the operation directory until every request has drained.

use rabs_key::live_dependency::{
    DependencyActionPlan, DependencyDirectoryFact, DependencySourceKind, ExternFact,
    LiveRustcRequest, PlannedExtern,
};
use rabs_sandbox::cargo_check::{CompilationSelection, CompilationUnit};
use std::collections::BTreeSet;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

const ROOTS: [&str; 5] = [
    "/__rabs/workspace",
    "/__rabs/cargo-home",
    "/__rabs/toolchain",
    "/__rabs/out/cargo",
    "/__rabs/home",
];

type DirectoryMappings = Vec<(Vec<u8>, Vec<u8>)>;

#[derive(Debug)]
struct Mount {
    visible: PathBuf,
    backing: PathBuf,
    device: u64,
    inode: u64,
}

/// Filesystem capability retained by one canonical Cargo operation.
///
/// There is deliberately no public constructor or deserializer. An absolute
/// path supplied by a wrapper cannot select a coordinator filesystem root.
#[derive(Debug)]
pub struct CanonicalPaths {
    _owner: Arc<tempfile::TempDir>,
    mounts: Vec<Mount>,
    closed_dependency_execution_required: bool,
    workspace_units: Vec<CompilationUnit>,
    workspace_tests_selected: bool,
    workspace_benches_selected: bool,
    workspace_bulk_harnesses_selected: bool,
}

/// One generated tree's filesystem backing and Cargo-visible record spelling.
/// Only a retained driver mapping can construct this binding. In particular,
/// a wrapper cannot supply a replacement name for Cargo's `root-output` file.
#[derive(Debug)]
pub(crate) struct CanonicalGeneratedRoot {
    physical: PathBuf,
    logical: PathBuf,
}

impl CanonicalGeneratedRoot {
    pub(crate) fn physical(&self) -> &Path {
        &self.physical
    }

    pub(crate) fn logical(&self) -> &Path {
        &self.logical
    }
}

fn ordinary_absolute(path: &Path) -> bool {
    path.to_str().is_some_and(|text| {
        text.starts_with('/')
            && text.len() > 1
            && !text.contains(['\\', '\0'])
            && text
                .split('/')
                .skip(1)
                .all(|part| !matches!(part, "" | "." | ".."))
    })
}

fn path_text(path: PathBuf) -> Result<String, String> {
    path.into_os_string()
        .into_string()
        .map_err(|_| "canonical backing path is not UTF-8".to_owned())
}

fn generated_layout(logical: &DependencyActionPlan) -> Result<Option<&Path>, String> {
    let mut presented = logical
        .execution_env
        .iter()
        .filter(|(name, _)| name == "OUT_DIR")
        .map(|(_, value)| value.as_str());
    if presented.next() != logical.generated_root.as_deref() || presented.next().is_some() {
        return Err("canonical generated root differs from its compiler environment".into());
    }
    let Some(root) = &logical.generated_root else {
        return Ok(None);
    };
    let generated = Path::new(root);
    let target = Path::new("/__rabs/out/cargo");
    if !logical.canonical_cargo
        || !ordinary_absolute(generated)
        || generated == target
        || !generated.starts_with(target)
        || generated.file_name().and_then(|name| name.to_str()) != Some("out")
        || [&logical.source_root, &logical.out_dir]
            .into_iter()
            .chain(&logical.dependency_dirs)
            .any(|other| {
                let other = Path::new(other);
                generated.starts_with(other) || other.starts_with(generated)
            })
    {
        return Err(
            "canonical generated inputs must bind a distinct Cargo OUT_DIR under the retained target mount"
                .into(),
        );
    }
    Ok(Some(generated))
}

impl CanonicalPaths {
    pub(crate) fn new(
        owner: Arc<tempfile::TempDir>,
        mappings: Vec<(PathBuf, PathBuf)>,
    ) -> Result<Arc<Self>, String> {
        let owned = owner.path();
        if !ordinary_absolute(owned) {
            return Err("canonical operation root is not an ordinary absolute path".into());
        }
        let root = std::fs::symlink_metadata(owned).map_err(|error| error.to_string())?;
        if !root.is_dir()
            || root.uid() != rustix::process::geteuid().as_raw()
            || root.mode() & 0o077 != 0
        {
            return Err("canonical operation root must be an owned private directory".into());
        }
        let mut visible = BTreeSet::new();
        let mut mounts: Vec<Mount> = Vec::new();
        for (logical, backing) in mappings {
            if !ROOTS.iter().any(|root| logical == Path::new(root))
                || !visible.insert(logical.clone())
                || !ordinary_absolute(&backing)
                || backing == owned
                || !backing.starts_with(owned)
                || mounts.iter().any(|mount| {
                    backing.starts_with(&mount.backing) || mount.backing.starts_with(&backing)
                })
            {
                return Err("canonical mount mapping is outside or aliases its owned roots".into());
            }
            for ancestor in backing
                .ancestors()
                .take_while(|path| path.starts_with(owned))
            {
                let metadata =
                    std::fs::symlink_metadata(ancestor).map_err(|error| error.to_string())?;
                if !metadata.is_dir()
                    || metadata.uid() != root.uid()
                    || metadata.mode() & 0o022 != 0
                {
                    return Err(
                        "canonical backing ancestor is not an owned ordinary directory".into(),
                    );
                }
            }
            let metadata =
                std::fs::symlink_metadata(&backing).map_err(|error| error.to_string())?;
            mounts.push(Mount {
                visible: logical,
                backing,
                device: metadata.dev(),
                inode: metadata.ino(),
            });
        }
        if visible.len() != ROOTS.len() {
            return Err("canonical driver did not retain every declared mount".into());
        }
        Ok(Arc::new(Self {
            _owner: owner,
            mounts,
            closed_dependency_execution_required: false,
            workspace_units: Vec::new(),
            workspace_tests_selected: false,
            workspace_benches_selected: false,
            workspace_bulk_harnesses_selected: false,
        }))
    }

    /// Bind actual Cargo-selected path-package units before the endpoint
    /// becomes visible to project code. A wrapper frame cannot extend this set.
    pub(crate) fn with_workspace_units(
        mut self: Arc<Self>,
        units: &[CompilationUnit],
        selection: Option<&CompilationSelection>,
    ) -> Result<Arc<Self>, String> {
        let selected = units
            .iter()
            .filter(|unit| workspace_manifest(unit).is_some())
            .cloned()
            .collect::<Vec<_>>();
        for unit in &selected {
            let source = Path::new(unit.source_path());
            if !source.starts_with("/__rabs/workspace")
                || !std::fs::symlink_metadata(self.physical(source)?)
                    .map_err(|error| error.to_string())?
                    .is_file()
            {
                return Err(
                    "selected workspace compiler source is not a retained ordinary file".into(),
                );
            }
        }
        let paths = Arc::get_mut(&mut self)
            .ok_or("workspace unit membership must be bound before sharing its capability")?;
        paths.workspace_units = selected;
        paths.workspace_tests_selected =
            selection.is_some_and(|selection| selection.tests && !selection.all_targets);
        paths.workspace_benches_selected = selection.is_some_and(|selection| {
            selection.benches
                && !selection.all_targets
                && !selection.lib
                && !selection.bins
                && !selection.examples
                && selection.bin.is_empty()
                && selection.example.is_empty()
        });
        paths.workspace_bulk_harnesses_selected = selection
            .is_some_and(|selection| selection.tests || selection.benches || selection.all_targets);
        Ok(self)
    }

    pub(crate) fn workspace_request(&self, request: LiveRustcRequest<'_>) -> bool {
        let manifest = request
            .env
            .iter()
            .find(|(name, _)| name == "CARGO_MANIFEST_DIR")
            .map(|(_, value)| value.as_str());
        self.workspace_units
            .iter()
            .any(|unit| workspace_manifest(unit) == manifest && manifest.is_some())
    }

    /// Membership is distinct from the pure planner's path/argument validation.
    /// Match a selected ordinary compiler family, including target and features,
    /// before permitting fresh remote execution; this grants no cache authority.
    pub(crate) fn require_workspace_execution(
        &self,
        plan: &DependencyActionPlan,
    ) -> Result<(), String> {
        use rabs_key::live_dependency::remote::{
            RemoteDependencyOutputClass, remote_dependency_output_class,
        };
        if !plan.canonical_cargo
            || plan.source_kind != DependencySourceKind::WorkspaceExecutionOnly
            || plan.source_root != "/__rabs/workspace"
        {
            return Err(
                "workspace execution requires the canonical driver's retained source scope".into(),
            );
        }
        let source = rabs_key::live_dependency::workspace_source_path(plan)
            .map_err(|error| error.to_string())?;
        let mut crate_types = plan.invocation.crate_types.clone();
        crate_types.sort();
        let features = plan
            .invocation
            .features
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        let mode =
            remote_dependency_output_class(&plan.invocation).map_err(|error| error.to_string())?;
        rabs_key::output_derivation::check_workspace_output_options(&plan.invocation)
            .map_err(|error| error.to_string())?;
        let test_harness = plan
            .invocation
            .passthrough
            .iter()
            .any(|arg| arg == "--test");
        let selected = self.workspace_units.iter().any(|unit| {
            // Cargo's unit graph serializes both Check { test: false } and
            // Check { test: true } as "check". Its target.test field states
            // eligibility, not which compiler invocation will run. For broad
            // selectors that also include ordinary targets, retain distinct
            // check-root multiplicity instead of blessing every root as a
            // harness. Pure test/bench selectors and explicit test/bench target
            // kinds establish selected families themselves. This is fresh
            // execution of the exact invocation, never cache authority.
            let harness_selected = unit.is_root()
                && (unit
                    .target_kinds()
                    .iter()
                    .any(|kind| matches!(kind.as_str(), "test" | "bench"))
                    || (self.workspace_bulk_harnesses_selected && unit.has_multiple_check_roots())
                    || (self.workspace_tests_selected && unit.testable())
                    || self.workspace_benches_selected);
            let output_shape = if test_harness {
                mode == RemoteDependencyOutputClass::Metadata
                    && harness_selected
                    && (crate_types.is_empty() || unit.crate_types() == crate_types)
            } else if crate_types.is_empty() {
                // Cargo's harness=false integration tests and benchmarks use
                // --cfg test with an implicit binary type, without --test.
                // Only their selected roots establish this custom harness
                // family; ordinary roots and prerequisites cannot borrow it.
                mode == RemoteDependencyOutputClass::Metadata
                    && plan.invocation.cfgs.iter().any(|cfg| cfg == "test")
                    && unit.is_root()
                    && unit.crate_types() == ["bin"]
                    && unit.target_kinds().len() == 1
                    && matches!(unit.target_kinds()[0].as_str(), "test" | "bench")
            } else {
                unit.crate_types() == crate_types
            };
            workspace_manifest(unit) == Some(plan.package_root.as_str())
                && unit.source_path() == source
                && Some(unit.crate_name()) == plan.invocation.crate_name.as_deref()
                && output_shape
                && unit.platform().unwrap_or(&plan.host_triple) == plan.target_triple
                && unit
                    .features()
                    .iter()
                    .map(String::as_str)
                    .collect::<BTreeSet<_>>()
                    == features
                && match mode {
                    RemoteDependencyOutputClass::Metadata => unit.mode() == "check",
                    _ => unit.mode() == "build",
                }
        });
        if !selected {
            return Err(
                "workspace compiler request does not match a retained Cargo-selected unit".into(),
            );
        }
        let path = self.physical(Path::new(&source))?;
        if !std::fs::symlink_metadata(path)
            .map_err(|error| error.to_string())?
            .is_file()
        {
            return Err("selected workspace source is no longer an ordinary file".into());
        }
        Ok(())
    }

    /// Bind the selected Cargo graph's execution policy before sharing this
    /// capability with the rustc endpoint. Build scripts and procedural macros
    /// can access that endpoint, so wrapper-supplied local completion claims
    /// cannot establish compiler evidence for any unit in their operation.
    /// Independent closed worker executions retain their existing authority.
    pub(crate) fn require_closed_dependency_execution(
        mut self: Arc<Self>,
    ) -> Result<Arc<Self>, String> {
        let paths = Arc::get_mut(&mut self).ok_or(
            "canonical execution policy must be bound before sharing its mount capability",
        )?;
        paths.closed_dependency_execution_required = true;
        Ok(self)
    }

    /// Local capture and local-key replay are both refused for an operation
    /// whose graph may execute project code. The flag is never a wire field.
    pub(crate) fn require_local_capture(&self) -> Result<(), String> {
        if self.closed_dependency_execution_required {
            Err("canonical-project-executors-require-isolated-dependency-execution".into())
        } else {
            Ok(())
        }
    }

    fn verify_mount(mount: &Mount) -> Result<(), String> {
        let metadata =
            std::fs::symlink_metadata(&mount.backing).map_err(|error| error.to_string())?;
        if !metadata.is_dir() || (metadata.dev(), metadata.ino()) != (mount.device, mount.inode) {
            return Err("canonical backing root was replaced".into());
        }
        Ok(())
    }

    /// Resolve a visible name through this operation's retained mount table.
    /// Unknown namespaces, traversal, replaced roots and symlinks are refused.
    pub(crate) fn physical(&self, path: &Path) -> Result<PathBuf, String> {
        if !ordinary_absolute(path) {
            return Err("canonical request path is not normalized and absolute".into());
        }
        let (mount, relative) = self
            .mounts
            .iter()
            .find_map(|mount| path.strip_prefix(&mount.visible).ok().map(|r| (mount, r)))
            .ok_or("canonical request names an undeclared mount")?;
        Self::verify_mount(mount)?;
        let mut physical = mount.backing.clone();
        for component in relative.components() {
            physical.push(component.as_os_str());
            match std::fs::symlink_metadata(&physical) {
                Ok(metadata) if metadata.file_type().is_symlink() => {
                    return Err("canonical backing path contains a symlink".into());
                }
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.to_string()),
            }
        }
        Self::verify_mount(mount)?;
        Ok(physical)
    }

    /// Recover the visible name of a path observed through a retained mount.
    pub(crate) fn logical(&self, path: &Path) -> Result<PathBuf, String> {
        if !ordinary_absolute(path) {
            return Err("observed canonical backing path is not normalized".into());
        }
        let (mount, relative) = self
            .mounts
            .iter()
            .find_map(|mount| path.strip_prefix(&mount.backing).ok().map(|r| (mount, r)))
            .ok_or("observed input is outside the retained canonical mounts")?;
        Self::verify_mount(mount)?;
        Ok(mount.visible.join(relative))
    }

    /// An I/O-only projection. Never pass this copy to an action-key builder or
    /// use it to reconstruct compiler argv, environment, dep-info or transcripts.
    pub(crate) fn project_plan(
        &self,
        logical: &DependencyActionPlan,
    ) -> Result<DependencyActionPlan, String> {
        generated_layout(logical)?;
        let translate = |value: &str| path_text(self.physical(Path::new(value))?);
        let mut physical = logical.clone();
        physical.compiler = translate(&logical.compiler)?;
        physical.cwd = translate(&logical.cwd)?;
        physical.out_dir = translate(&logical.out_dir)?;
        physical.package_root = translate(&logical.package_root)?;
        physical.source_root = translate(&logical.source_root)?;
        // Cargo's root-output record and compiler environment retain the
        // visible spelling. Only this I/O field selects the hidden backing.
        physical.generated_root = logical
            .generated_root
            .as_deref()
            .map(translate)
            .transpose()?;
        physical.native_roots = logical
            .native_roots
            .iter()
            .map(|path| translate(path))
            .collect::<Result<_, _>>()?;
        physical.dependency_dirs = logical
            .dependency_dirs
            .iter()
            .map(|path| translate(path))
            .collect::<Result<_, _>>()?;
        for external in &mut physical.externs {
            if let PlannedExtern::File { path, .. } = external {
                *path = translate(path)?;
            }
        }
        Ok(physical)
    }

    /// Bind Cargo's exact logical OUT_DIR to the tree observed for this plan.
    /// The I/O projection deliberately leaves compiler argv/environment alone:
    /// Cargo's completed `root-output` record contains the logical name even
    /// though the coordinator reads that record through a hidden backing.
    pub(crate) fn generated_root(
        &self,
        logical: &DependencyActionPlan,
        physical: &DependencyActionPlan,
    ) -> Result<Option<CanonicalGeneratedRoot>, String> {
        if !logical.canonical_cargo
            || !physical.canonical_cargo
            || logical.source_kind != physical.source_kind
            || self.physical(Path::new(&logical.source_root))? != Path::new(&physical.source_root)
            || logical.execution_env != physical.execution_env
        {
            return Err("generated observation differs from its canonical source mapping".into());
        }
        let Some(logical_root) = generated_layout(logical)? else {
            return if physical.generated_root.is_none() {
                Ok(None)
            } else {
                Err("canonical generated root has an unbound physical backing".into())
            };
        };
        let backing = self.physical(logical_root)?;
        if physical.generated_root.as_deref().map(Path::new) != Some(backing.as_path()) {
            return Err("canonical generated root differs from its retained backing".into());
        }
        Ok(Some(CanonicalGeneratedRoot {
            physical: backing,
            logical: logical_root.to_path_buf(),
        }))
    }

    /// Bind propagated native search inputs to this driver's private target.
    /// The planner selects only complete Cargo OUT_DIR roots. Their completed
    /// root-output/stdout records are checked by the same observer used for
    /// the current package's generated inputs, never trusted from the wrapper.
    pub(crate) fn native_roots(
        &self,
        logical: &DependencyActionPlan,
        physical: &DependencyActionPlan,
    ) -> Result<Vec<CanonicalGeneratedRoot>, String> {
        if !logical.canonical_cargo
            || !physical.canonical_cargo
            || logical.source_kind != physical.source_kind
            || logical.execution_env != physical.execution_env
            || self.physical(Path::new(&logical.source_root))? != Path::new(&physical.source_root)
            || logical.native_roots.len() != physical.native_roots.len()
            || logical.native_roots.len()
                > rabs_key::live_dependency::remote::MAX_CANONICAL_NATIVE_ROOTS
            || logical
                .native_roots
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
        {
            return Err("native input observation differs from its canonical mapping".into());
        }
        let mut bindings = Vec::with_capacity(logical.native_roots.len());
        for (root, backing) in logical.native_roots.iter().zip(&physical.native_roots) {
            let path = Path::new(root);
            if !ordinary_absolute(path)
                || !path.starts_with("/__rabs/out/cargo")
                || path.file_name().and_then(|name| name.to_str()) != Some("out")
                || [&logical.source_root, &logical.out_dir]
                    .into_iter()
                    .chain(&logical.dependency_dirs)
                    .chain(logical.generated_root.iter())
                    .chain(logical.native_roots.iter().filter(|other| *other != root))
                    .any(|other| path.starts_with(other) || Path::new(other).starts_with(path))
            {
                return Err("native inputs must bind distinct Cargo OUT_DIR trees".into());
            }
            let expected = self.physical(path)?;
            if expected != Path::new(backing) {
                return Err("native input root differs from its retained backing".into());
            }
            bindings.push(CanonicalGeneratedRoot {
                physical: expected,
                logical: path.to_path_buf(),
            });
        }
        Ok(bindings)
    }

    pub(crate) fn dependency_facts(
        &self,
        physical: &[DependencyDirectoryFact],
    ) -> Result<Vec<DependencyDirectoryFact>, String> {
        physical
            .iter()
            .map(|directory| {
                Ok(DependencyDirectoryFact {
                    path: path_text(self.logical(Path::new(&directory.path))?)?,
                    artifacts: directory
                        .artifacts
                        .iter()
                        .map(|artifact| {
                            Ok(ExternFact {
                                path: path_text(self.logical(Path::new(&artifact.path))?)?,
                                content_digest: artifact.content_digest.clone(),
                            })
                        })
                        .collect::<Result<_, String>>()?,
                })
            })
            .collect()
    }

    /// Probe the retained native compiler with loader paths from the same
    /// captured toolchain. These host probe values never replace the compiler's
    /// canonical execution environment or enter its action descriptor.
    pub(crate) fn probe_environment(
        &self,
        environment: &[(String, String)],
    ) -> Result<Vec<(String, String)>, String> {
        environment
            .iter()
            .map(|(name, value)| {
                let value = if matches!(
                    name.as_str(),
                    "LD_LIBRARY_PATH" | "DYLD_LIBRARY_PATH" | "DYLD_FALLBACK_LIBRARY_PATH"
                ) {
                    value
                        .split(':')
                        .map(|path| {
                            if path.starts_with("/__rabs/") {
                                path_text(self.physical(Path::new(path))?)
                            } else {
                                Ok(path.to_owned())
                            }
                        })
                        .collect::<Result<Vec<_>, String>>()?
                        .join(":")
                } else {
                    value.clone()
                };
                Ok((name.clone(), value))
            })
            .collect()
    }

    /// I/O-only dep-info validation mappings. The compiler's canonical bytes
    /// remain unchanged when installed for the retained Cargo namespace.
    pub(crate) fn output_mappings(&self) -> Result<DirectoryMappings, String> {
        self.mounts
            .iter()
            .map(|mount| {
                Self::verify_mount(mount)?;
                Ok((
                    mount.visible.as_os_str().as_bytes().to_vec(),
                    mount.backing.as_os_str().as_bytes().to_vec(),
                ))
            })
            .collect()
    }

    pub(crate) fn backing_roots(&self) -> Vec<String> {
        self.mounts
            .iter()
            .map(|mount| mount.backing.to_string_lossy().into_owned())
            .collect()
    }
}

fn workspace_manifest(unit: &CompilationUnit) -> Option<&str> {
    let manifest = unit
        .package_id()
        .strip_prefix("path+file://")?
        .split_once('#')?
        .0;
    (manifest == "/__rabs/workspace" || manifest.starts_with("/__rabs/workspace/"))
        .then_some(manifest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::DirBuilderExt;

    fn fixture() -> (Arc<tempfile::TempDir>, Arc<CanonicalPaths>) {
        let owner = Arc::new(crate::test_util::private_tempdir());
        let mappings = ROOTS
            .iter()
            .enumerate()
            .map(|(index, root)| {
                let backing = owner.path().join(index.to_string());
                std::fs::DirBuilder::new()
                    .mode(0o700)
                    .create(&backing)
                    .unwrap();
                (PathBuf::from(root), backing)
            })
            .collect();
        let paths = CanonicalPaths::new(Arc::clone(&owner), mappings).unwrap();
        (owner, paths)
    }

    #[test]
    fn canonical_paths_use_component_boundaries_and_keep_the_owner_alive() {
        let (owner, paths) = fixture();
        let root = owner.path().to_path_buf();
        let visible = Path::new("/__rabs/out/cargo/debug/deps/liba.rmeta");
        let backing = paths.physical(visible).unwrap();
        assert_eq!(backing, root.join("3/debug/deps/liba.rmeta"));
        assert_eq!(paths.logical(&backing).unwrap(), visible);
        drop(owner);
        assert!(root.is_dir());
        for path in [
            "/__rabs/out/cargo-other/file",
            "/__rabs/out/cargo/../state",
            "/__rabs/out/cargo/./file",
            "/__rabs/out/cargo//file",
            "/etc/passwd",
        ] {
            assert!(paths.physical(Path::new(path)).is_err(), "{path}");
        }
    }

    fn workspace_graph(package_id: &str) -> rabs_sandbox::cargo_check::CompilationUnitGraph {
        use rabs_sandbox::cargo_check::{CompilationCommand, validate_compilation_unit_graph};
        let graph = serde_json::json!({"version":1,"roots":[0],"units":[{
            "pkg_id":package_id,
            "target":{"kind":["lib"],"crate_types":["lib"],"name":"project-lib",
                "src_path":"/__rabs/workspace/app/src/lib.rs","edition":"2024"},
            "profile":{"name":"dev"},"platform":null,"mode":"check",
            "features":["base"],"dependencies":[]
        }]});
        validate_compilation_unit_graph(&graph, CompilationCommand::Check).unwrap()
    }

    fn workspace_plan() -> DependencyActionPlan {
        workspace_metadata_plan(Some("lib"), false)
    }

    fn workspace_metadata_plan(
        crate_type: Option<&str>,
        test_harness: bool,
    ) -> DependencyActionPlan {
        workspace_metadata_plan_with_test_cfg(crate_type, test_harness, false)
    }

    fn workspace_metadata_plan_with_test_cfg(
        crate_type: Option<&str>,
        test_harness: bool,
        test_cfg: bool,
    ) -> DependencyActionPlan {
        let mut argv = [
            "/__rabs/toolchain/bin/rustc",
            "--crate-name",
            "project_lib",
            "--edition=2024",
            "app/src/lib.rs",
            "--emit=dep-info,metadata",
            "-Cmetadata=abc",
            "-Cextra-filename=-abc",
            "--out-dir",
            "/__rabs/out/cargo/debug/deps",
            "--error-format=json",
            "--json=diagnostic-rendered-ansi,artifacts",
            "--cfg",
            "feature=\"base\"",
        ]
        .map(str::to_owned)
        .to_vec();
        if let Some(crate_type) = crate_type {
            argv.extend(["--crate-type".into(), crate_type.into()]);
        }
        if test_harness {
            argv.push("--test".into());
        }
        if test_cfg {
            argv.extend(["--cfg".into(), "test".into()]);
        }
        let env = [
            ("CARGO_MANIFEST_DIR", "/__rabs/workspace/app"),
            ("CARGO_PKG_NAME", "project"),
            ("CARGO_PRIMARY_PACKAGE", "1"),
            ("CARGO_HOME", "/__rabs/cargo-home"),
            ("HOME", "/__rabs/home"),
        ]
        .map(|(name, value)| (name.to_owned(), value.to_owned()));
        rabs_key::live_dependency::plan_canonical_workspace_execution(
            LiveRustcRequest {
                argv: &argv,
                cwd: "/__rabs/workspace",
                env: &env,
            },
            "x86_64-unknown-linux-gnu",
        )
        .unwrap()
    }

    fn workspace_target_graph(
        kind: &str,
        crate_type: &str,
        testable: bool,
        is_root: bool,
        multiple_check_roots: bool,
    ) -> rabs_sandbox::cargo_check::CompilationUnitGraph {
        use rabs_sandbox::cargo_check::{CompilationCommand, validate_compilation_unit_graph};
        let unit = serde_json::json!({
            "pkg_id":"path+file:///__rabs/workspace/app#project@0.1.0",
            "target":{"kind":[kind],"crate_types":[crate_type],"name":"project-lib",
                "src_path":"/__rabs/workspace/app/src/lib.rs","edition":"2024","test":testable},
            "profile":{"name":"dev"},"platform":null,"mode":"check",
            "features":["base"],"dependencies":[]
        });
        let mut graph = serde_json::json!({"version":1,"roots":[0],"units":[unit.clone()]});
        if is_root && multiple_check_roots {
            graph["units"].as_array_mut().unwrap().push(unit.clone());
            graph["roots"] = serde_json::json!([0, 1]);
        }
        if !is_root {
            let mut consumer = unit;
            consumer["target"]["kind"] = serde_json::json!(["bin"]);
            consumer["target"]["crate_types"] = serde_json::json!(["bin"]);
            consumer["target"]["name"] = serde_json::json!("consumer");
            consumer["target"]["src_path"] = serde_json::json!("/__rabs/workspace/app/src/main.rs");
            consumer["dependencies"] =
                serde_json::json!([{"index":0,"extern_crate_name":"project_lib"}]);
            graph["units"].as_array_mut().unwrap().push(consumer);
            graph["roots"] = serde_json::json!([1]);
        }
        validate_compilation_unit_graph(&graph, CompilationCommand::Check).unwrap()
    }

    fn workspace_target_paths(
        kind: &str,
        crate_type: &str,
        testable: bool,
        is_root: bool,
        selection: Option<&CompilationSelection>,
    ) -> Arc<CanonicalPaths> {
        workspace_target_paths_with_check_roots(
            kind, crate_type, testable, is_root, selection, false,
        )
    }

    fn workspace_target_paths_with_check_roots(
        kind: &str,
        crate_type: &str,
        testable: bool,
        is_root: bool,
        selection: Option<&CompilationSelection>,
        multiple_check_roots: bool,
    ) -> Arc<CanonicalPaths> {
        let (owner, paths) = fixture();
        std::fs::create_dir_all(owner.path().join("0/app/src")).unwrap();
        std::fs::write(
            owner.path().join("0/app/src/lib.rs"),
            b"pub fn value() {}\n",
        )
        .unwrap();
        std::fs::write(owner.path().join("0/app/src/main.rs"), b"fn main() {}\n").unwrap();
        let graph =
            workspace_target_graph(kind, crate_type, testable, is_root, multiple_check_roots);
        paths
            .with_workspace_units(graph.workspace_units(), selection)
            .unwrap()
    }

    #[test]
    fn selected_binary_example_test_and_bench_checks_preserve_metadata_output_shape() {
        for kind in ["bin", "example", "test", "bench"] {
            let paths = workspace_target_paths(kind, "bin", true, true, None);
            let plan = workspace_metadata_plan(Some("bin"), false);
            assert!(paths.require_workspace_execution(&plan).is_ok(), "{kind}");
            assert!(
                paths
                    .require_workspace_execution(&workspace_plan())
                    .is_err(),
                "{kind}"
            );
            let mut wrong_source = plan.clone();
            wrong_source.invocation.source = Some(rabs_key::invocation::SourceInput::Path(
                "app/src/main.rs".into(),
            ));
            assert!(
                paths.require_workspace_execution(&wrong_source).is_err(),
                "{kind}"
            );
            let harness = workspace_metadata_plan(None, true);
            assert_eq!(
                paths.require_workspace_execution(&harness).is_ok(),
                matches!(kind, "test" | "bench"),
                "only selected integration/bench roots independently establish a harness family: {kind}"
            );
        }
    }

    #[test]
    fn library_and_binary_harnesses_require_trusted_selection_and_root_membership() {
        let tests = CompilationSelection {
            tests: true,
            ..CompilationSelection::default()
        };
        let all_targets = CompilationSelection {
            all_targets: true,
            ..CompilationSelection::default()
        };
        let lib_only = CompilationSelection {
            lib: true,
            ..CompilationSelection::default()
        };
        for (kind, crate_type) in [("lib", "lib"), ("bin", "bin"), ("example", "bin")] {
            let harness = workspace_metadata_plan(None, true);
            for selection in [None, Some(&lib_only)] {
                let paths = workspace_target_paths(kind, crate_type, true, true, selection);
                assert!(
                    paths.require_workspace_execution(&harness).is_err(),
                    "{kind}"
                );
            }
            for selection in [&tests, &all_targets] {
                let paths = workspace_target_paths_with_check_roots(
                    kind,
                    crate_type,
                    true,
                    true,
                    Some(selection),
                    selection.all_targets,
                );
                assert!(
                    paths.require_workspace_execution(&harness).is_ok(),
                    "{kind}"
                );
                let prerequisite =
                    workspace_target_paths(kind, crate_type, true, false, Some(selection));
                assert!(
                    prerequisite.require_workspace_execution(&harness).is_err(),
                    "{kind}"
                );
            }
            let disabled = workspace_target_paths(kind, crate_type, false, true, Some(&tests));
            assert!(
                disabled.require_workspace_execution(&harness).is_err(),
                "{kind}"
            );
        }
    }

    #[test]
    fn broad_selectors_cannot_turn_an_ordinary_only_root_into_a_harness() {
        let selections = [
            serde_json::json!({"all_targets":true}),
            serde_json::json!({"all_targets":true,"tests":true,"benches":true}),
            serde_json::json!({"benches":true,"lib":true}),
            serde_json::json!({"benches":true,"bins":true}),
            serde_json::json!({"benches":true,"examples":true}),
            serde_json::json!({"benches":true,"bin":["project-lib"]}),
            serde_json::json!({"benches":true,"example":["project-lib"]}),
        ];
        for value in selections {
            let selection: CompilationSelection = serde_json::from_value(value).unwrap();
            for (kind, crate_type) in [("lib", "lib"), ("bin", "bin"), ("example", "bin")] {
                for testable in [false, true] {
                    let harness = workspace_metadata_plan(None, true);
                    let ordinary =
                        workspace_target_paths(kind, crate_type, testable, true, Some(&selection));
                    assert!(
                        ordinary.require_workspace_execution(&harness).is_err(),
                        "single {kind} root, testable={testable}, {selection:?}"
                    );
                    assert!(
                        ordinary
                            .require_workspace_execution(&workspace_metadata_plan(
                                Some(crate_type),
                                false,
                            ))
                            .is_ok()
                    );
                    let both = workspace_target_paths_with_check_roots(
                        kind,
                        crate_type,
                        testable,
                        true,
                        Some(&selection),
                        true,
                    );
                    assert!(
                        both.require_workspace_execution(&harness).is_ok(),
                        "two selected {kind} metadata roots, {selection:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn pure_bench_selection_uses_selected_roots_without_inventing_target_bench_flags() {
        let benches = CompilationSelection {
            benches: true,
            ..CompilationSelection::default()
        };
        let harness = workspace_metadata_plan(None, true);
        for (kind, crate_type) in [("lib", "lib"), ("bin", "bin"), ("example", "bin")] {
            let selected = workspace_target_paths(kind, crate_type, false, true, Some(&benches));
            assert!(selected.require_workspace_execution(&harness).is_ok());
            let dependency = workspace_target_paths(kind, crate_type, false, false, Some(&benches));
            assert!(dependency.require_workspace_execution(&harness).is_err());
            let unselected =
                workspace_target_paths_with_check_roots(kind, crate_type, false, true, None, true);
            assert!(unselected.require_workspace_execution(&harness).is_err());
        }
    }

    #[test]
    fn custom_harness_checks_require_selected_test_or_bench_roots_and_exact_metadata_options() {
        let all_targets = CompilationSelection {
            all_targets: true,
            ..CompilationSelection::default()
        };
        let custom = workspace_metadata_plan_with_test_cfg(None, false, true);
        assert!(custom.invocation.crate_types.is_empty());
        assert!(
            !custom
                .invocation
                .passthrough
                .iter()
                .any(|arg| arg == "--test")
        );
        assert_eq!(custom.invocation.cfgs, ["test"]);
        for kind in ["test", "bench"] {
            for testable in [false, true] {
                for selection in [None, Some(&all_targets)] {
                    let selected = workspace_target_paths(kind, "bin", testable, true, selection);
                    assert!(
                        selected.require_workspace_execution(&custom).is_ok(),
                        "{kind}"
                    );
                    let prerequisite =
                        workspace_target_paths(kind, "bin", testable, false, selection);
                    assert!(
                        prerequisite.require_workspace_execution(&custom).is_err(),
                        "{kind}"
                    );
                    for mutation in 0..4 {
                        let mut invalid = custom.clone();
                        match mutation {
                            0 => invalid.invocation.cfgs.clear(),
                            1 => invalid.invocation.emit.push("link".into()),
                            2 => invalid
                                .invocation
                                .passthrough
                                .push("--future-output-option".into()),
                            _ => invalid.invocation.features.clear(),
                        }
                        assert!(
                            selected.require_workspace_execution(&invalid).is_err(),
                            "{kind}, mutation {mutation}"
                        );
                    }
                }
            }
        }
        for (kind, crate_type) in [("lib", "lib"), ("bin", "bin"), ("example", "bin")] {
            let ordinary = workspace_target_paths_with_check_roots(
                kind,
                crate_type,
                true,
                true,
                Some(&all_targets),
                true,
            );
            assert!(
                ordinary.require_workspace_execution(&custom).is_err(),
                "ordinary {kind} roots cannot authorize an implicit custom harness"
            );
        }
    }

    #[test]
    fn only_retained_cargo_selected_library_units_can_execute_as_workspace_requests() {
        let (owner, paths) = fixture();
        std::fs::create_dir_all(owner.path().join("0/app/src")).unwrap();
        std::fs::write(
            owner.path().join("0/app/src/lib.rs"),
            b"pub fn value() {}\n",
        )
        .unwrap();
        let graph = workspace_graph("path+file:///__rabs/workspace/app#project@0.1.0");
        let paths = paths
            .with_workspace_units(graph.workspace_units(), None)
            .unwrap();
        let plan = workspace_plan();
        assert!(paths.require_workspace_execution(&plan).is_ok());
        assert_eq!(plan.cwd, "/__rabs/workspace");
        assert_eq!(plan.package_root, "/__rabs/workspace/app");
        for mutation in 0..6 {
            let mut other = plan.clone();
            match mutation {
                0 => other.invocation.crate_name = Some("unselected".into()),
                1 => other.invocation.features.clear(),
                2 => other.target_triple = "aarch64-unknown-linux-gnu".into(),
                3 => other.package_root = "/__rabs/workspace/other".into(),
                4 => other.invocation.crate_types = vec!["rlib".into()],
                _ => {
                    other.invocation.source = Some(rabs_key::invocation::SourceInput::Path(
                        "other/src/lib.rs".into(),
                    ))
                }
            }
            assert!(
                paths.require_workspace_execution(&other).is_err(),
                "mutation {mutation}"
            );
        }
        let retained = Arc::clone(&paths);
        assert!(
            paths
                .with_workspace_units(graph.workspace_units(), None)
                .is_err()
        );
        assert!(retained.require_workspace_execution(&plan).is_ok());
    }

    #[test]
    fn vendored_registry_bytes_cannot_borrow_path_package_execution_membership() {
        let (_owner, paths) = fixture();
        let graph =
            workspace_graph("registry+https://github.com/rust-lang/crates.io-index#project@0.1.0");
        let paths = paths
            .with_workspace_units(graph.workspace_units(), None)
            .unwrap();
        assert!(
            paths
                .require_workspace_execution(&workspace_plan())
                .is_err()
        );
        let argv = Vec::new();
        let env = vec![("CARGO_MANIFEST_DIR".into(), "/__rabs/workspace/app".into())];
        assert!(!paths.workspace_request(LiveRustcRequest {
            argv: &argv,
            cwd: "/__rabs/workspace",
            env: &env,
        }));
    }

    #[test]
    fn project_executor_policy_is_bound_before_sharing_and_never_grants_local_capture() {
        let (_owner, paths) = fixture();
        assert!(paths.require_local_capture().is_ok());
        let paths = paths.require_closed_dependency_execution().unwrap();
        assert_eq!(
            paths.require_local_capture().unwrap_err(),
            "canonical-project-executors-require-isolated-dependency-execution"
        );
        let retained = Arc::clone(&paths);
        assert!(paths.require_closed_dependency_execution().is_err());
        assert!(retained.require_local_capture().is_err());
        // Observation and output installation still use the same bounded,
        // retained mounts after worker authority has been required.
        assert!(
            retained
                .physical(Path::new("/__rabs/out/cargo/debug/deps"))
                .is_ok()
        );
    }

    #[test]
    fn coordinator_rejects_a_local_key_even_if_an_executor_request_bypasses_the_edge() {
        use super::super::{LiveDecision, LiveDependencyLane, LiveDependencyRequest};
        use crate::coord::live::CoordLive;
        use crate::edge::live_facts::{FactsMiss, LiveFacts};
        use rabs_key::live_dependency::{
            LiveRustcRequest, canonical_cargo_dependency_key,
            plan_canonical_cargo_dependency_action,
        };
        use rabs_protocol::input_evidence::{
            ActionInputManifest, INPUT_EVIDENCE_SCHEMA_VERSION, InputFileType, PositiveInput,
        };
        use rabs_protocol::raw_bytes::RawBytes;
        use rabs_protocol::result_identity::ObjectId;
        use std::os::unix::fs::PermissionsExt;
        use std::time::{Duration, Instant};

        let (owner, paths) = fixture();
        let package = "/__rabs/cargo-home/registry/src/fixture-index/leaf-1.0.0";
        let output = "/__rabs/out/cargo/debug/deps";
        let physical_package = paths.physical(Path::new(package)).unwrap();
        let physical_output = paths.physical(Path::new(output)).unwrap();
        let toolchain = owner.path().join("2");
        for directory in [
            &physical_package,
            &physical_output,
            &toolchain.join("bin"),
            &toolchain.join("lib/rustlib/x86_64-unknown-linux-gnu/lib"),
        ] {
            std::fs::create_dir_all(directory).unwrap();
        }
        std::fs::write(
            physical_package.join("lib.rs"),
            b"pub const VALUE:u32=42;\n",
        )
        .unwrap();
        std::fs::write(toolchain.join("lib/libdriver.so"), b"runtime fixture").unwrap();
        std::fs::write(
            toolchain.join("lib/rustlib/x86_64-unknown-linux-gnu/lib/libcore.rlib"),
            b"sysroot fixture",
        )
        .unwrap();
        let compiler = toolchain.join("bin/rustc");
        // Identity probes only: this test exercises actual coordinator gates,
        // not compiler execution or canonical namespace enforcement.
        std::fs::write(
            &compiler,
            concat!(
                "#!/bin/sh\ncase \"$*\" in\n",
                "'-vV') printf 'rustc fixture\\nhost: x86_64-unknown-linux-gnu\\n';;\n",
                "'--print sysroot') printf '%s\\n' \"${0%/bin/rustc}\";;\n",
                "*) exit 64;;\nesac\n",
            ),
        )
        .unwrap();
        std::fs::set_permissions(&compiler, std::fs::Permissions::from_mode(0o700)).unwrap();
        let argv = vec![
            "/__rabs/toolchain/bin/rustc".into(),
            "--crate-name=leaf".into(),
            "--crate-type=lib".into(),
            "--emit=dep-info,metadata".into(),
            "--cap-lints=allow".into(),
            "--error-format=json".into(),
            format!("--out-dir={output}"),
            format!("{package}/lib.rs"),
        ];
        let env = vec![
            ("CARGO_HOME".into(), "/__rabs/cargo-home".into()),
            ("HOME".into(), "/__rabs/home".into()),
            ("CARGO_MANIFEST_DIR".into(), package.into()),
            ("CARGO_PKG_NAME".into(), "leaf".into()),
        ];
        let plan = plan_canonical_cargo_dependency_action(
            LiveRustcRequest {
                argv: &argv,
                cwd: package,
                env: &env,
            },
            "x86_64-unknown-linux-gnu",
            None,
        )
        .unwrap();
        let physical = paths.project_plan(&plan).unwrap();
        let facts = LiveFacts::new();
        let package = facts
            .package(&physical_package, plan.source_kind, None)
            .unwrap();
        let dependencies = facts.dependencies(&physical).unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        let toolchain_facts = loop {
            match facts.toolchain(&compiler, &[]) {
                Ok(facts) => break facts,
                Err(FactsMiss::Pending) => {
                    assert!(
                        Instant::now() < deadline,
                        "fixture facts did not become ready"
                    );
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("fixture compiler facts: {error}"),
            }
        };
        let toolchain_guard = facts.toolchain_guard(&compiler, &toolchain_facts).unwrap();
        let inputs = ActionInputManifest {
            schema_version: INPUT_EVIDENCE_SCHEMA_VERSION,
            inputs: package
                .files
                .iter()
                .map(|(relative, object, executable)| PositiveInput {
                    virtual_path: RawBytes::new(plan.input_virtual_path(relative).into_bytes()),
                    object: ObjectId(object.clone()),
                    file_type: InputFileType::Regular,
                    executable: *executable,
                    symlink_resolution: Vec::new(),
                })
                .collect(),
            ..ActionInputManifest::default()
        };
        let key = canonical_cargo_dependency_key(
            &plan,
            &toolchain_facts,
            &[],
            &paths.dependency_facts(&dependencies.directories).unwrap(),
            None,
            &inputs,
        )
        .unwrap();
        let mut request = LiveDependencyRequest {
            key,
            plan,
            inputs,
            package,
            dependencies,
            toolchain: toolchain_guard,
            externs: Vec::new(),
            canonical_paths: Some(paths),
        };
        assert!(
            request.verify_read_closure().is_ok(),
            "metadata contract is locally admissible without project code"
        );
        let ordinary_plan = request.plan.clone();
        // Exercise the actual request output-contract boundary with real
        // workspace plans. The rest of this request remains the dependency
        // fixture; this does not establish workspace execution authority.
        for workspace in [
            workspace_metadata_plan(Some("bin"), false),
            workspace_metadata_plan(None, true),
            workspace_metadata_plan_with_test_cfg(None, false, true),
        ] {
            request.plan = workspace.clone();
            assert!(request.verify_output_contract().is_ok());
            assert_eq!(
                request.verify_read_closure().unwrap_err(),
                "workspace execution requires a fresh isolated remote compiler"
            );
            request.plan.outputs.declarations.pop();
            assert!(request.verify_output_contract().is_err());
            request.plan = workspace.clone();
            request.plan.invocation.emit.push("link".into());
            assert!(request.verify_output_contract().is_err());
            for source_kind in [
                DependencySourceKind::RegistryPackage,
                DependencySourceKind::GitCheckout,
                DependencySourceKind::DirectoryPackage,
            ] {
                request.plan = workspace.clone();
                request.plan.source_kind = source_kind;
                assert!(request.verify_output_contract().is_err());
            }
        }
        request.plan = ordinary_plan.clone();
        let generated = "/__rabs/out/cargo/debug/build/leaf/out";
        request.plan.generated_root = Some(generated.into());
        request
            .plan
            .execution_env
            .push(("OUT_DIR".into(), generated.into()));
        assert_eq!(
            request.verify_read_closure().unwrap_err(),
            "canonical-generated-inputs-require-isolated-dependency-execution"
        );
        assert!(request.verify_enforced_read_closure(None).is_err());
        request.plan = ordinary_plan;
        let paths = request
            .canonical_paths
            .take()
            .unwrap()
            .require_closed_dependency_execution()
            .unwrap();
        request.canonical_paths = Some(paths);
        let reason = "canonical-project-executors-require-isolated-dependency-execution";
        assert_eq!(request.verify_read_closure().unwrap_err(), reason);
        assert_eq!(
            request.verify_enforced_read_closure(None).unwrap_err(),
            reason
        );
        let lane = LiveDependencyLane::new(Arc::new(CoordLive::new()));
        let LiveDecision::PassThrough(rejected) = lane.decide(request) else {
            panic!("a constructed local key must not produce a local hit or attempt");
        };
        assert_eq!(rejected, reason);
        assert_eq!(std::fs::read_dir(physical_output).unwrap().count(), 0);
    }

    #[test]
    fn canonical_paths_refuse_symlinks_and_replaced_mount_roots() {
        use std::os::unix::fs::symlink;
        let (owner, paths) = fixture();
        symlink(owner.path().join("1"), owner.path().join("0/alias")).unwrap();
        assert!(
            paths
                .physical(Path::new("/__rabs/workspace/alias/Cargo.toml"))
                .is_err()
        );
        std::fs::rename(owner.path().join("0"), owner.path().join("old-source")).unwrap();
        std::fs::create_dir(owner.path().join("0")).unwrap();
        assert!(
            paths
                .physical(Path::new("/__rabs/workspace/lib.rs"))
                .is_err()
        );
    }

    #[test]
    fn canonical_mounts_cannot_select_ambient_or_overlapping_backing_paths() {
        let (owner, _) = fixture();
        let mut mappings: Vec<_> = ROOTS
            .iter()
            .enumerate()
            .map(|(index, root)| (PathBuf::from(root), owner.path().join(index.to_string())))
            .collect();
        mappings[1].1 = owner.path().join("0/child");
        std::fs::create_dir(&mappings[1].1).unwrap();
        assert!(CanonicalPaths::new(Arc::clone(&owner), mappings.clone()).is_err());
        mappings[1].1 = std::env::temp_dir();
        assert!(CanonicalPaths::new(owner, mappings).is_err());
    }

    struct GeneratedFixture {
        _owner: Arc<tempfile::TempDir>,
        paths: Arc<CanonicalPaths>,
        plan: DependencyActionPlan,
        physical: DependencyActionPlan,
        binding: CanonicalGeneratedRoot,
        record: PathBuf,
        stdout: PathBuf,
    }

    impl GeneratedFixture {
        fn new(populated: bool, separate_run: bool) -> Self {
            use rabs_key::live_dependency::{
                LiveRustcRequest, plan_canonical_remote_dependency_action,
            };

            let (owner, paths) = fixture();
            let package = "/__rabs/cargo-home/registry/src/fixture-index/generated-1.0.0";
            let output = "/__rabs/out/cargo/debug/deps";
            let generated = "/__rabs/out/cargo/debug/build/generated-unit/out";
            let source = paths.physical(Path::new(package)).unwrap();
            let generated_backing = paths.physical(Path::new(generated)).unwrap();
            for directory in [
                source.clone(),
                paths.physical(Path::new(output)).unwrap(),
                generated_backing.clone(),
            ] {
                std::fs::create_dir_all(directory).unwrap();
            }
            std::fs::write(
                source.join("lib.rs"),
                b"include!(concat!(env!(\"OUT_DIR\"), \"/value.rs\"));\n",
            )
            .unwrap();
            if populated {
                std::fs::write(
                    generated_backing.join("value.rs"),
                    b"pub const VALUE: u32 = 17;\n",
                )
                .unwrap();
            }
            let unit = generated_backing.parent().unwrap();
            let run = if separate_run {
                let run = unit.join("run");
                std::fs::create_dir(&run).unwrap();
                run
            } else {
                unit.to_path_buf()
            };
            let record = run.join("root-output");
            let stdout = run.join(if separate_run { "stdout" } else { "output" });
            std::fs::write(&record, generated.as_bytes()).unwrap();
            std::fs::write(&stdout, b"cargo::rustc-env=BUILD_LABEL=pinned\n").unwrap();
            let argv = vec![
                "/__rabs/toolchain/bin/rustc".into(),
                "--crate-name=generated".into(),
                "--crate-type=lib".into(),
                "--emit=dep-info,metadata".into(),
                "--cap-lints=allow".into(),
                "--error-format=json".into(),
                format!("--out-dir={output}"),
                format!("{package}/lib.rs"),
            ];
            let env = vec![
                ("CARGO_HOME".into(), "/__rabs/cargo-home".into()),
                ("HOME".into(), "/__rabs/home".into()),
                ("CARGO_MANIFEST_DIR".into(), package.into()),
                ("CARGO_PKG_NAME".into(), "generated".into()),
                ("OUT_DIR".into(), generated.into()),
                ("BUILD_LABEL".into(), "pinned".into()),
            ];
            let plan = plan_canonical_remote_dependency_action(
                LiveRustcRequest {
                    argv: &argv,
                    cwd: package,
                    env: &env,
                },
                "x86_64-unknown-linux-gnu",
                None,
            )
            .unwrap();
            let physical = paths.project_plan(&plan).unwrap();
            let binding = paths.generated_root(&plan, &physical).unwrap().unwrap();
            Self {
                _owner: owner,
                paths,
                plan,
                physical,
                binding,
                record,
                stdout,
            }
        }

        fn capture(
            &self,
            facts: &Arc<crate::edge::live_facts::LiveFacts>,
        ) -> Result<Arc<crate::edge::live_facts::PackageFacts>, crate::edge::live_facts::FactsMiss>
        {
            facts.package_canonical(&self.physical, Some(&self.binding), &[])
        }
    }

    #[test]
    fn propagated_native_capture_binds_complete_trees_records_and_memo_generations() {
        use crate::edge::live_facts::{LiveFacts, native_snapshot_root};
        use rabs_protocol::input_evidence::ActionInputManifest;
        let mut fixture = GeneratedFixture::new(false, false);
        let logical = "/__rabs/out/cargo/debug/build/provider/out";
        let backing = fixture.paths.physical(Path::new(logical)).unwrap();
        std::fs::create_dir_all(backing.join("native")).unwrap();
        std::fs::create_dir_all(backing.join("empty/inner")).unwrap();
        std::fs::write(
            backing.join("native/libprovider.a"),
            b"retained native archive",
        )
        .unwrap();
        let unit = backing.parent().unwrap();
        std::fs::write(unit.join("root-output"), logical).unwrap();
        std::fs::write(
            unit.join("output"),
            format!("cargo::rustc-link-search=native={logical}/native\n"),
        )
        .unwrap();
        // Downstream Cargo units inherit this search even without their own
        // build script, OUT_DIR or rustc-link-lib argument.
        fixture.plan.generated_root = None;
        fixture
            .plan
            .execution_env
            .retain(|(name, _)| name != "OUT_DIR");
        fixture.plan.keyed_env = fixture.plan.execution_env.clone();
        fixture.plan.native_roots = vec![logical.into()];
        fixture
            .plan
            .invocation
            .lib_search
            .push(format!("native={logical}/native"));
        fixture.physical = fixture.paths.project_plan(&fixture.plan).unwrap();
        let native = fixture
            .paths
            .native_roots(&fixture.plan, &fixture.physical)
            .unwrap();
        let facts = LiveFacts::new();
        let capture = || {
            facts
                .package_canonical(&fixture.physical, None, &native)
                .unwrap()
        };
        let first = capture();
        assert!(
            Arc::ptr_eq(&first, &capture()),
            "unchanged complete observation reuses one sealed image"
        );
        assert_eq!(first.native.len(), 1);
        assert_eq!(
            first
                .snapshot
                .file_bytes(&native_snapshot_root(0), "native/libprovider.a"),
            Some(b"retained native archive".as_slice())
        );
        first.verify_generated_disjoint(&fixture.physical).unwrap();
        let mut inputs = ActionInputManifest::default();
        first
            .append_native_inputs(&fixture.plan, &mut inputs)
            .unwrap();
        assert_eq!(
            rabs_key::live_dependency::native_input_directories(&fixture.plan, &inputs, 0).unwrap(),
            vec!["empty", "empty/inner", "native"]
        );
        let record_path = fixture.plan.native_record_virtual_path(0).into_bytes();
        let record = inputs
            .inputs
            .iter()
            .find(|input| input.virtual_path.as_bytes() == record_path)
            .unwrap()
            .object
            .clone();
        std::fs::write(
            unit.join("output"),
            format!("cargo::rustc-link-search=native={logical}/native\ncargo::metadata=changed\n"),
        )
        .unwrap();
        assert!(
            first
                .verify_unchanged(Path::new(&fixture.physical.source_root))
                .is_err()
        );
        let changed_record = capture();
        assert!(!Arc::ptr_eq(&first, &changed_record));
        let mut changed_inputs = ActionInputManifest::default();
        changed_record
            .append_native_inputs(&fixture.plan, &mut changed_inputs)
            .unwrap();
        assert_ne!(
            record,
            changed_inputs
                .inputs
                .iter()
                .find(|input| input.virtual_path.as_bytes() == record_path)
                .unwrap()
                .object
        );
        std::fs::create_dir(backing.join("another-empty")).unwrap();
        assert!(
            changed_record
                .verify_unchanged(Path::new(&fixture.physical.source_root))
                .is_err()
        );
        let changed_tree = capture();
        assert!(!Arc::ptr_eq(&changed_record, &changed_tree));
        std::fs::write(
            backing.join("native/libprovider.a"),
            b"changed archive bytes",
        )
        .unwrap();
        assert!(
            changed_tree
                .verify_unchanged(Path::new(&fixture.physical.source_root))
                .is_err()
        );
        assert_ne!(changed_tree.native[0].files, capture().native[0].files);
        std::fs::write(unit.join("root-output"), "/another/producers/out").unwrap();
        assert!(
            facts
                .package_canonical(&fixture.physical, None, &native)
                .is_err()
        );
    }

    #[test]
    fn native_mapping_and_capture_refuse_unbound_or_output_aliasing_roots() {
        use crate::edge::live_facts::LiveFacts;
        let mut fixture = GeneratedFixture::new(false, false);
        let logical = "/__rabs/out/cargo/debug/build/provider/out";
        let backing = fixture.paths.physical(Path::new(logical)).unwrap();
        std::fs::create_dir_all(&backing).unwrap();
        std::fs::write(backing.join("libprovider.a"), b"native bytes").unwrap();
        std::fs::write(backing.parent().unwrap().join("root-output"), logical).unwrap();
        std::fs::write(
            backing.parent().unwrap().join("output"),
            b"cargo::rustc-link-lib=static=provider\n",
        )
        .unwrap();
        fixture.plan.native_roots = vec![logical.into()];
        fixture
            .plan
            .invocation
            .lib_search
            .push(format!("native={logical}"));
        fixture.physical = fixture.paths.project_plan(&fixture.plan).unwrap();
        let native = fixture
            .paths
            .native_roots(&fixture.plan, &fixture.physical)
            .unwrap();
        let facts = LiveFacts::new();
        assert!(
            facts
                .package_canonical(&fixture.physical, Some(&fixture.binding), &[])
                .is_err()
        );
        let captured = facts
            .package_canonical(&fixture.physical, Some(&fixture.binding), &native)
            .unwrap();
        captured
            .verify_generated_disjoint(&fixture.physical)
            .unwrap();
        let output =
            Path::new(&fixture.physical.out_dir).join(fixture.plan.output_names().first().unwrap());
        std::fs::hard_link(backing.join("libprovider.a"), output).unwrap();
        assert!(
            captured
                .verify_generated_disjoint(&fixture.physical)
                .is_err()
        );
        let mut forged = fixture.physical.clone();
        forged.native_roots[0] = fixture.physical.source_root.clone();
        assert!(fixture.paths.native_roots(&fixture.plan, &forged).is_err());
        let mut overlapping = fixture.plan.clone();
        overlapping.native_roots[0] = fixture.plan.generated_root.clone().unwrap();
        let physical = fixture.paths.project_plan(&overlapping).unwrap();
        assert!(fixture.paths.native_roots(&overlapping, &physical).is_err());
    }

    #[test]
    fn canonical_generated_capture_keeps_cargo_records_and_visible_paths_exact() {
        use crate::edge::live_facts::{GENERATED_ROOT, LiveFacts};

        for populated in [false, true] {
            for separate_run in [false, true] {
                let fixture = GeneratedFixture::new(populated, separate_run);
                let facts = LiveFacts::new();
                let captured = fixture.capture(&facts).unwrap();
                assert_eq!(
                    captured.generated_files.len(),
                    if populated { 1 } else { 0 }
                );
                assert_eq!(
                    captured.snapshot.file_bytes(GENERATED_ROOT, "value.rs"),
                    populated.then_some(b"pub const VALUE: u32 = 17;\n".as_slice())
                );
                assert_eq!(
                    captured.build_script_output.as_deref(),
                    Some(b"cargo::rustc-env=BUILD_LABEL=pinned\n".as_slice())
                );
                assert_eq!(fixture.physical.execution_env, fixture.plan.execution_env);
                assert_eq!(fixture.physical.keyed_env, fixture.plan.keyed_env);
                assert_eq!(
                    fixture.physical.invocation.canonical_bytes(),
                    fixture.plan.invocation.canonical_bytes()
                );
                assert_eq!(
                    std::fs::read(&fixture.record).unwrap(),
                    fixture.binding.logical().to_str().unwrap().as_bytes()
                );
                assert!(Arc::ptr_eq(&captured, &fixture.capture(&facts).unwrap()));
                captured
                    .verify_unchanged(Path::new(&fixture.physical.source_root))
                    .unwrap();
                captured
                    .verify_generated_disjoint(&fixture.physical)
                    .unwrap();
                // A physical-path observer cannot borrow the canonical memo.
                assert!(
                    facts
                        .package(
                            Path::new(&fixture.physical.source_root),
                            fixture.plan.source_kind,
                            Some(fixture.binding.physical()),
                        )
                        .is_err()
                );
                std::fs::write(
                    &fixture.record,
                    fixture.binding.physical().to_str().unwrap().as_bytes(),
                )
                .unwrap();
                assert!(
                    captured
                        .verify_unchanged(Path::new(&fixture.physical.source_root))
                        .is_err()
                );
                assert!(fixture.capture(&facts).is_err());
                facts
                    .package(
                        Path::new(&fixture.physical.source_root),
                        fixture.plan.source_kind,
                        Some(fixture.binding.physical()),
                    )
                    .unwrap();
            }
        }
    }

    #[test]
    fn canonical_generated_inputs_revalidate_bytes_members_records_and_aliases() {
        use crate::edge::live_facts::LiveFacts;

        for mutation in [
            "file",
            "member",
            "stdout",
            "record",
            "root-symlink",
            "file-symlink",
        ] {
            let fixture = GeneratedFixture::new(true, false);
            let facts = LiveFacts::new();
            let captured = fixture.capture(&facts).unwrap();
            let root = fixture.binding.physical();
            match mutation {
                "file" => std::fs::write(root.join("value.rs"), b"pub const VALUE: u32 = 23;\n"),
                "member" => std::fs::write(root.join("introduced.rs"), b"new member"),
                "stdout" => {
                    std::fs::write(&fixture.stdout, b"cargo::rustc-env=BUILD_LABEL=other\n")
                }
                "record" => std::fs::write(&fixture.record, b"/__rabs/out/cargo/other/out"),
                "root-symlink" => {
                    let moved = root.with_file_name("moved-out");
                    std::fs::rename(root, &moved).unwrap();
                    std::os::unix::fs::symlink(moved, root)
                }
                "file-symlink" => std::os::unix::fs::symlink("value.rs", root.join("alias.rs")),
                _ => unreachable!(),
            }
            .unwrap();
            assert!(
                captured
                    .verify_unchanged(Path::new(&fixture.physical.source_root))
                    .is_err(),
                "{mutation}"
            );
        }
        let fixture = GeneratedFixture::new(true, false);
        let captured = fixture.capture(&LiveFacts::new()).unwrap();
        std::fs::hard_link(
            fixture.binding.physical().join("value.rs"),
            Path::new(&fixture.physical.out_dir).join(&fixture.plan.output_names()[0]),
        )
        .unwrap();
        assert!(
            captured
                .verify_generated_disjoint(&fixture.physical)
                .is_err()
        );
    }

    #[test]
    fn generated_capture_binds_visible_cargo_records_to_retained_physical_inputs() {
        use crate::edge::live_facts::LiveFacts;

        let fixture = GeneratedFixture::new(true, true);
        let facts = LiveFacts::new();
        let source = Path::new(&fixture.physical.source_root);
        let first = fixture.capture(&facts).unwrap();
        std::fs::write(
            fixture.binding.physical().join("value.rs"),
            b"pub const VALUE:u32=23;\n",
        )
        .unwrap();
        assert!(first.verify_unchanged(source).is_err());
        let changed = fixture.capture(&facts).unwrap();
        assert_ne!(first.generated_files, changed.generated_files);
        std::fs::write(&fixture.stdout, b"cargo::rustc-env=BUILD_LABEL=changed\n").unwrap();
        assert!(changed.verify_unchanged(source).is_err());
        let changed_record = fixture.capture(&facts).unwrap();
        assert_ne!(
            first.build_script_output,
            changed_record.build_script_output
        );
        std::fs::write(&fixture.record, b"/__rabs/out/cargo/debug/build/other/out").unwrap();
        assert!(changed_record.verify_unchanged(source).is_err());
        assert!(fixture.capture(&facts).is_err());
    }

    #[test]
    fn generated_projection_refuses_ambient_aliasing_and_mismatched_out_dir_names() {
        let fixture = GeneratedFixture::new(false, true);
        let paths = &fixture.paths;
        let plan = &fixture.plan;
        for invalid in [
            "/tmp/ambient/out",
            "/__rabs/workspace/vendor/generated/out",
            "/__rabs/out/cargo",
            "/__rabs/out/cargo/debug",
            "/__rabs/out/cargo/debug/deps/out",
            "/__rabs/out/cargo/debug/build/generated/out/../other/out",
        ] {
            let mut invalid_plan = plan.clone();
            invalid_plan.generated_root = Some(invalid.into());
            for (name, value) in &mut invalid_plan.execution_env {
                if name == "OUT_DIR" {
                    *value = invalid.into();
                }
            }
            assert!(paths.project_plan(&invalid_plan).is_err(), "{invalid}");
            assert!(
                paths
                    .generated_root(&invalid_plan, &fixture.physical)
                    .is_err(),
                "{invalid}"
            );
        }
        let mut mismatched = plan.clone();
        mismatched.generated_root = Some("/__rabs/out/cargo/debug/build/other/out".into());
        assert!(paths.project_plan(&mismatched).is_err());
        let mut alias_spelling = plan.clone();
        alias_spelling
            .execution_env
            .iter_mut()
            .find(|(name, _)| name == "OUT_DIR")
            .unwrap()
            .1
            .push('/');
        assert!(paths.project_plan(&alias_spelling).is_err());
        let mut duplicate = plan.clone();
        duplicate
            .execution_env
            .push(("OUT_DIR".into(), plan.generated_root.clone().unwrap()));
        assert!(paths.project_plan(&duplicate).is_err());

        let generated = fixture.binding.physical();
        std::fs::rename(generated, generated.with_file_name("moved-out")).unwrap();
        std::os::unix::fs::symlink(&fixture.physical.source_root, generated).unwrap();
        assert!(paths.project_plan(plan).is_err());
        assert!(paths.generated_root(plan, &fixture.physical).is_err());
    }

    #[test]
    fn generated_binding_cannot_select_another_plan_or_backing() {
        let fixture = GeneratedFixture::new(false, false);
        let mut wrong_backing = fixture.physical.clone();
        wrong_backing.generated_root = Some(fixture.physical.source_root.clone());
        assert!(
            fixture
                .paths
                .generated_root(&fixture.plan, &wrong_backing)
                .is_err()
        );
        let mut wrong_source = fixture.physical.clone();
        wrong_source.source_root = fixture.physical.out_dir.clone();
        assert!(
            fixture
                .paths
                .generated_root(&fixture.plan, &wrong_source)
                .is_err()
        );
        let mut wrong_env = fixture.physical.clone();
        wrong_env
            .execution_env
            .retain(|(name, _)| name != "OUT_DIR");
        assert!(
            fixture
                .paths
                .generated_root(&fixture.plan, &wrong_env)
                .is_err()
        );
        let mut duplicate = fixture.plan.clone();
        duplicate
            .execution_env
            .push(("OUT_DIR".into(), "elsewhere".into()));
        assert!(fixture.paths.project_plan(&duplicate).is_err());
        assert!(
            fixture
                .paths
                .generated_root(&duplicate, &fixture.physical)
                .is_err()
        );
        assert!(
            crate::edge::live_facts::LiveFacts::new()
                .package_canonical(&wrong_backing, Some(&fixture.binding), &[])
                .is_err()
        );
    }
}
