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
use rabs_sandbox::cargo_check::CompilationLibraryUnit;
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
    workspace_units: Vec<CompilationLibraryUnit>,
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
        }))
    }

    /// Bind actual Cargo-selected path-package library units before the endpoint
    /// becomes visible to project code. A wrapper frame cannot extend this set.
    pub(crate) fn with_workspace_units(
        mut self: Arc<Self>,
        units: &[CompilationLibraryUnit],
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
        Arc::get_mut(&mut self)
            .ok_or("workspace unit membership must be bound before sharing its capability")?
            .workspace_units = selected;
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
    /// Match a selected ordinary library family, including target and features,
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
        let selected = self.workspace_units.iter().any(|unit| {
            workspace_manifest(unit) == Some(plan.package_root.as_str())
                && unit.source_path() == source
                && Some(unit.crate_name()) == plan.invocation.crate_name.as_deref()
                && unit.crate_types() == crate_types
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
                "workspace compiler request does not match a retained Cargo-selected library unit"
                    .into(),
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
    pub(crate) fn output_mappings(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>, String> {
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

fn workspace_manifest(unit: &CompilationLibraryUnit) -> Option<&str> {
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
        let argv = [
            "/__rabs/toolchain/bin/rustc",
            "--crate-name",
            "project_lib",
            "--edition=2024",
            "app/src/lib.rs",
            "--crate-type",
            "lib",
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
        .map(str::to_owned);
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
        let paths = paths.with_workspace_units(graph.library_units()).unwrap();
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
        assert!(paths.with_workspace_units(graph.library_units()).is_err());
        assert!(retained.require_workspace_execution(&plan).is_ok());
    }

    #[test]
    fn vendored_registry_bytes_cannot_borrow_path_package_execution_membership() {
        let (_owner, paths) = fixture();
        let graph =
            workspace_graph("registry+https://github.com/rust-lang/crates.io-index#project@0.1.0");
        let paths = paths.with_workspace_units(graph.library_units()).unwrap();
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
            facts.package_canonical(&self.physical, Some(&self.binding))
        }
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
                .package_canonical(&wrong_backing, Some(&fixture.binding))
                .is_err()
        );
    }
}
