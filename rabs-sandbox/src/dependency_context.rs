//! Path-preserving execution for a closed, immutable dependency compilation.
//!
//! A Cargo wrapper has already exposed the subscriber's paths to rustc. This
//! separate, negotiated context keeps those paths unchanged while binding only
//! retained input bytes and private output. It does not widen the canonical
//! Cargo namespace or grant action-cache publication authority. The selected
//! ELF runtime is copied into a retained private tree before launch and must
//! exactly match the measured runtime cohort. Metadata execution retains private
//! /proc and /dev. Archive code generation uses a distinct negotiated mode with
//! no procfs or general device tree, so assembler file reads cannot consume
//! unkeyed process state or entropy. Neither mode admits arbitrary plugins.

use crate::canonical_namespace::{
    Bind, CanonicalNamespaceSpec, HostIsolationSupport, IsolationError, NamespaceBoundary,
    NamespaceLaunch, push_binds, push_common_prelude, push_env, push_host_usr,
};
use crate::generated_source::validate_generated_directories;
use crate::layout;
use crate::runtime_cohort::RetainedRuntime;
use std::collections::BTreeSet;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// Both peers must explicitly select this capability before dependency execution.
pub const DEPENDENCY_CONTEXT_VERSION: &str = "dependency-exec-v8";
/// Separately negotiated canonical Cargo dependency execution. This is not a
/// pathname-based extension of the original-path context: both peers must
/// select this version and its output mode before canonical aliases can enter
/// a compiler view. Version 4 binds every generated subdirectory, including
/// empty directories, alongside the sealed files at canonical Cargo OUT_DIR.
pub const CANONICAL_DEPENDENCY_CONTEXT_VERSION: &str = "canonical-dependency-exec-v4";
/// Fresh execution of a Cargo-selected workspace compilation. This separately
/// negotiated context carries the complete retained workspace directory tree;
/// it grants no dependency-cache or workspace-result publication authority.
/// Version 3 also admits static archive bundling into a workspace rlib from
/// that unit's complete, independently retained OUT_DIR. Metadata checks retain
/// their existing binary, example and standard/custom harness contract.
pub const CANONICAL_WORKSPACE_CONTEXT_VERSION: &str = "canonical-workspace-exec-v3";
/// Separately advertised extension for metadata checks with static native inputs
/// from the current canonical Cargo OUT_DIR. The existing context versions and
/// measured metadata namespace remain unchanged; a coordinator must observe this
/// capability before dispatching native metadata to an older worker. Archive
/// execution does not require it and keeps its existing policy identity.
pub const CANONICAL_NATIVE_METADATA_CAPABILITY: &str = "canonical-generated-static-metadata-v1";
/// Additional complete Cargo build-output trees consumed through propagated
/// native search paths. Peers must negotiate this before transferring inputs;
/// it does not widen ordinary dependency execution or cache authority.
pub const CANONICAL_NATIVE_ROOTS_CAPABILITY: &str = "canonical-generated-native-roots-v1";
/// Full environments remain bounded by the existing command transport allowance.
pub const MAX_DEPENDENCY_ENV_ENTRIES: usize = 1024;
/// Maximum dependency search roots accepted in this bounded execution mode.
pub const MAX_DEPENDENCY_DIRS: usize = 64;
/// Maximum independently retained native build-output roots per compilation.
pub const MAX_NATIVE_ROOTS: usize = 32;

/// The output class selects the filesystem contract independently of argv.
/// The worker must also check that the actual invocation belongs to this class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DependencyExecutionMode {
    /// Metadata and dep-info only, with the established private proc/device view.
    Metadata,
    /// Pure Rust archive code generation, without procfs or entropy devices.
    Rlib,
}

impl DependencyExecutionMode {
    /// Exact negotiated wire spelling; unknown modes must never use a default.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Metadata => "metadata",
            Self::Rlib => "rlib",
        }
    }
}

/// Measured permission to construct one dependency execution mode's base view.
///
/// Canonical and metadata execution need a private proc mount. Archive execution
/// deliberately omits procfs and general devices, and can work on hosts whose
/// enclosing container forbids mounting procfs. Its separate no-op probe must
/// succeed before that mode is advertised or executed. Neither result is input
/// closure, runtime identity, or cache-publication authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependencyIsolationSupport {
    mode: DependencyExecutionMode,
    bubblewrap: Option<String>,
    base_namespace: bool,
    null_device: bool,
}

impl DependencyIsolationSupport {
    /// Execute a no-op in the required base namespace. Metadata retains the
    /// existing canonical capability requirement; archives measure their own
    /// null-only device view without borrowing that canonical result.
    #[must_use]
    pub fn probe(mode: DependencyExecutionMode) -> Self {
        Self::probe_with_bubblewrap(mode, Path::new("bwrap"))
    }

    fn probe_with_bubblewrap(mode: DependencyExecutionMode, executable: &Path) -> Self {
        if mode == DependencyExecutionMode::Metadata {
            let canonical = HostIsolationSupport::probe_with_bubblewrap(executable);
            return Self {
                mode,
                bubblewrap: canonical.bubblewrap,
                base_namespace: canonical.unprivileged_userns,
                null_device: false,
            };
        }
        if !cfg!(target_os = "linux") {
            return Self {
                mode,
                bubblewrap: None,
                base_namespace: false,
                null_device: false,
            };
        }
        let bubblewrap = std::process::Command::new(executable)
            .arg("--version")
            .output()
            .ok()
            .filter(|output| output.status.success())
            .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned());
        let null_device = linux_null_device(Path::new("/dev/null"));
        let base_namespace = bubblewrap.is_some() && null_device && {
            let mut argv = dependency_base_argv(mode, &[]);
            // These host bytes only let the trusted no-op run while measuring
            // mount/namespace availability. They never enter a compiler view:
            // production requires a separately retained, keyed runtime below.
            push_host_usr(&mut argv);
            push_dependency_temporary_mounts(&mut argv);
            argv.extend(["--chdir", layout::TMP, "--", "/usr/bin/true"].map(OsString::from));
            let mut command = std::process::Command::new(executable);
            command.args(&argv[1..]).env_clear();
            if let Some(path) = std::env::var_os("PATH") {
                command.env("PATH", path);
            }
            command
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .is_ok_and(|status| status.success())
        };
        let null_device = null_device && linux_null_device(Path::new("/dev/null"));
        Self {
            mode,
            bubblewrap,
            base_namespace,
            null_device,
        }
    }

    /// The single execution mode whose base namespace was measured.
    #[must_use]
    pub const fn mode(&self) -> DependencyExecutionMode {
        self.mode
    }

    /// Whether the no-op completed successfully inside this mode's base view.
    #[must_use]
    pub fn is_supported(&self) -> bool {
        self.bubblewrap.is_some()
            && self.base_namespace
            && (self.mode == DependencyExecutionMode::Metadata || self.null_device)
    }

    /// Missing capabilities for this exact mode, never for another namespace.
    #[must_use]
    pub fn missing(&self) -> Vec<&'static str> {
        let mut missing = Vec::new();
        if self.bubblewrap.is_none() {
            missing.push("bubblewrap");
        }
        if !self.base_namespace {
            missing.push(match self.mode {
                DependencyExecutionMode::Metadata => "dependency-metadata-base-namespace",
                DependencyExecutionMode::Rlib => "dependency-rlib-base-namespace",
            });
        }
        if self.mode == DependencyExecutionMode::Rlib && !self.null_device {
            missing.push("linux-null-device");
        }
        missing
    }

    fn require_mode(&self, mode: DependencyExecutionMode) -> Result<(), IsolationError> {
        self.require_mode_with_null_device(mode, Path::new("/dev/null"))
    }

    fn require_mode_with_null_device(
        &self,
        mode: DependencyExecutionMode,
        null_device: &Path,
    ) -> Result<(), IsolationError> {
        if self.mode != mode {
            return Err(IsolationError::InvalidSpec {
                reason: "dependency isolation was measured for another execution mode".into(),
            });
        }
        let mut missing = self.missing();
        // The source of --dev-bind may have changed since capability probing.
        // Never mount arbitrary regular bytes or another device at /dev/null.
        if mode == DependencyExecutionMode::Rlib
            && !linux_null_device(null_device)
            && !missing.contains(&"linux-null-device")
        {
            missing.push("linux-null-device");
        }
        if missing.is_empty() {
            Ok(())
        } else {
            Err(IsolationError::UnsupportedHost {
                missing: missing.into_iter().map(str::to_owned).collect(),
            })
        }
    }
}

fn linux_null_device(path: &Path) -> bool {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::{FileTypeExt, MetadataExt};
        std::fs::symlink_metadata(path).is_ok_and(|metadata| {
            metadata.file_type().is_char_device()
                && rustix::fs::major(metadata.rdev()) == 1
                && rustix::fs::minor(metadata.rdev()) == 3
        })
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = path;
        false
    }
}

fn dependency_base_argv(mode: DependencyExecutionMode, env: &[(String, String)]) -> Vec<OsString> {
    let mut argv = vec!["bwrap".into()];
    push_common_prelude(&mut argv);
    argv.extend(["--unshare-net", "--hostname", "rabs"].map(OsString::from));
    push_env(&mut argv, env);
    match mode {
        DependencyExecutionMode::Metadata => {
            argv.extend(["--proc", "/proc", "--dev", "/dev"].map(OsString::from));
        }
        DependencyExecutionMode::Rlib => {
            // LLVM's integrated assembler can read files absent from rustc's
            // dep-info. Process state and entropy do not belong to this view.
            // The null sink is deterministic and needed by ordinary I/O.
            argv.extend(
                ["--dir", "/dev", "--dev-bind", "/dev/null", "/dev/null"].map(OsString::from),
            );
        }
    }
    argv
}

fn push_dependency_temporary_mounts(argv: &mut Vec<OsString>) {
    argv.extend(["--tmpfs", "/tmp", "--tmpfs", layout::TMP].map(OsString::from));
}

/// One retained candidate directory, mapped by its first-use dependency index.
/// The prefix names only a subtree of the sealed source-transfer bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependencyArtifactRoot {
    pub path: String,
    pub prefix: String,
}

/// A complete foreign Cargo build-script output tree. The prefix selects only
/// its sealed bundle bytes; visible paths never authorize host filesystem reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependencyNativeRoot {
    pub path: String,
    pub prefix: String,
    pub directories: Vec<String>,
}

/// Validated original paths and complete environment for one rustc action.
/// Physical source, toolchain, output and jobserver backings never appear here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependencyExecContext {
    canonical_cargo: bool,
    workspace_execution_only: bool,
    execution_mode: DependencyExecutionMode,
    source_root: String,
    source_directories: Vec<String>,
    generated_root: Option<String>,
    generated_directories: Vec<String>,
    native_roots: Vec<DependencyNativeRoot>,
    cwd: String,
    toolchain_root: String,
    compiler: String,
    out_dir: String,
    dependency_dirs: Vec<String>,
    loader_dirs: Vec<String>,
    artifact_roots: Vec<DependencyArtifactRoot>,
    env: Vec<(String, String)>,
    runtime_cohort_sha256: [u8; 32],
}

/// A context cannot be represented by the closed dependency namespace.
/// Errors never include environment values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependencyContextError(&'static str);

impl std::fmt::Display for DependencyContextError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.0)
    }
}
impl std::error::Error for DependencyContextError {}

fn invalid(message: &'static str) -> DependencyContextError {
    DependencyContextError(message)
}

fn normalized_absolute(value: &str) -> bool {
    value.starts_with('/')
        && !value.contains('\0')
        && value.len() <= 4096
        && value[1..]
            .split('/')
            .all(|component| !component.is_empty() && component != "." && component != "..")
}

fn overlaps(left: &Path, right: &Path) -> bool {
    left.starts_with(right) || right.starts_with(left)
}

fn valid_alias(value: &str) -> bool {
    normalized_absolute(value)
        && ![
            "/__rabs", "/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc", "/proc", "/dev", "/sys",
            "/run",
        ]
        .iter()
        .any(|reserved| overlaps(Path::new(value), Path::new(reserved)))
}

fn canonical_descendant(value: &str, root: &str) -> bool {
    normalized_absolute(value) && value != root && Path::new(value).starts_with(root)
}

fn canonical_alias(value: &str) -> bool {
    value == layout::TOOLCHAIN
        || value == "/__rabs/out/cargo"
        || [layout::WORKSPACE, layout::CARGO_HOME, "/__rabs/out/cargo"]
            .iter()
            .any(|root| canonical_descendant(value, root))
}

impl DependencyExecContext {
    /// Validate exact path spellings, disjoint mount roots and a full
    /// environment. Environment names/values are preserved byte-for-byte as
    /// UTF-8; only descriptor coordination is replaced later by the worker.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        source_root: String,
        cwd: String,
        toolchain_root: String,
        compiler: String,
        out_dir: String,
        dependency_dirs: Vec<String>,
        env: Vec<(String, String)>,
        runtime_cohort_sha256: [u8; 32],
    ) -> Result<Self, DependencyContextError> {
        Self::new_with_loader_dirs(
            source_root,
            cwd,
            toolchain_root,
            compiler,
            out_dir,
            dependency_dirs,
            Vec::new(),
            env,
            runtime_cohort_sha256,
        )
    }

    /// Include explicitly observed empty loader directories. Cargo commonly
    /// searches both target/debug/deps and its target/debug parent. Only owned
    /// child mountpoints appear under an empty loader parent; no original
    /// target-tree backing is exposed to the compiler.
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_loader_dirs(
        source_root: String,
        cwd: String,
        toolchain_root: String,
        compiler: String,
        out_dir: String,
        dependency_dirs: Vec<String>,
        loader_dirs: Vec<String>,
        env: Vec<(String, String)>,
        runtime_cohort_sha256: [u8; 32],
    ) -> Result<Self, DependencyContextError> {
        Self::new_with_artifacts(
            source_root,
            cwd,
            toolchain_root,
            compiler,
            out_dir,
            dependency_dirs,
            loader_dirs,
            Vec::new(),
            env,
            runtime_cohort_sha256,
        )
    }

    /// Include exact retained Rust metadata/archive candidate directories.
    /// Directory order is invocation first-use order, so each retained prefix
    /// has the same identity as the keyed inventory and the source upload.
    /// A search root may equal the writable output root. Its retained files
    /// require individually owned read-only mounts over private placeholders;
    /// the worker supplies that sealed inventory before compiling the namespace.
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_artifacts(
        source_root: String,
        cwd: String,
        toolchain_root: String,
        compiler: String,
        out_dir: String,
        dependency_dirs: Vec<String>,
        loader_dirs: Vec<String>,
        artifact_roots: Vec<DependencyArtifactRoot>,
        env: Vec<(String, String)>,
        runtime_cohort_sha256: [u8; 32],
    ) -> Result<Self, DependencyContextError> {
        Self::new_with_generated_artifacts(
            source_root,
            cwd,
            toolchain_root,
            compiler,
            out_dir,
            dependency_dirs,
            loader_dirs,
            artifact_roots,
            None,
            env,
            runtime_cohort_sha256,
        )
    }

    /// Add one complete captured build-script output tree at its original
    /// OUT_DIR spelling. This imports generated compiler inputs only; the
    /// worker never runs or replays the build script. An empty tree still
    /// requires a separate private read-only backing.
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_generated_artifacts(
        source_root: String,
        cwd: String,
        toolchain_root: String,
        compiler: String,
        out_dir: String,
        dependency_dirs: Vec<String>,
        loader_dirs: Vec<String>,
        artifact_roots: Vec<DependencyArtifactRoot>,
        generated_root: Option<String>,
        env: Vec<(String, String)>,
        runtime_cohort_sha256: [u8; 32],
    ) -> Result<Self, DependencyContextError> {
        Self::new_in_profile(
            false,
            false,
            source_root,
            cwd,
            toolchain_root,
            compiler,
            out_dir,
            dependency_dirs,
            loader_dirs,
            artifact_roots,
            generated_root,
            env,
            runtime_cohort_sha256,
        )
    }

    /// Retain a canonical Cargo dependency's exact visible names while giving
    /// its compiler only the selected package, toolchain and candidate bytes.
    /// The complete outer Cargo workspace, Cargo home and control socket are
    /// never mounted. The driver owns path admission; this constructor grants
    /// neither caller-filesystem access nor cache/publication authority.
    ///
    /// Archive emission selects the existing Rlib namespace, which excludes
    /// procfs and entropy devices so assembler inputs must come from retained
    /// keyed bytes. Arbitrary canonical mount aliases remain unsupported.
    /// Neither mode authorizes local codegen capture.
    #[allow(clippy::too_many_arguments)]
    pub fn new_canonical_cargo(
        mode: DependencyExecutionMode,
        source_root: String,
        cwd: String,
        out_dir: String,
        dependency_dirs: Vec<String>,
        loader_dirs: Vec<String>,
        artifact_roots: Vec<DependencyArtifactRoot>,
        env: Vec<(String, String)>,
        runtime_cohort_sha256: [u8; 32],
    ) -> Result<Self, DependencyContextError> {
        Self::new_canonical_cargo_with_generated(
            mode,
            source_root,
            cwd,
            out_dir,
            dependency_dirs,
            loader_dirs,
            artifact_roots,
            None,
            env,
            runtime_cohort_sha256,
        )
    }

    /// Add one complete retained build-script input tree at the exact OUT_DIR
    /// beneath the canonical Cargo target. The tree is disjoint from writable
    /// compiler outputs and may be empty; its bytes are supplied by the sealed
    /// source owner. The worker neither executes nor caches the build script.
    #[allow(clippy::too_many_arguments)]
    pub fn new_canonical_cargo_with_generated(
        mode: DependencyExecutionMode,
        source_root: String,
        cwd: String,
        out_dir: String,
        dependency_dirs: Vec<String>,
        loader_dirs: Vec<String>,
        artifact_roots: Vec<DependencyArtifactRoot>,
        generated_root: Option<String>,
        env: Vec<(String, String)>,
        runtime_cohort_sha256: [u8; 32],
    ) -> Result<Self, DependencyContextError> {
        Self::new_in_profile(
            true,
            false,
            source_root,
            cwd,
            layout::TOOLCHAIN.to_owned(),
            format!("{}/bin/rustc", layout::TOOLCHAIN),
            out_dir,
            dependency_dirs,
            loader_dirs,
            artifact_roots,
            generated_root,
            env,
            runtime_cohort_sha256,
        )
        .map(|context| context.with_execution_mode(mode))
    }

    /// Execute one selected canonical workspace compilation against the complete
    /// retained workspace, exact dependency candidates and optional generated
    /// input tree. The caller must hold the driver's selected-unit capability;
    /// neither this path validator nor a peer's request establishes membership.
    /// CARGO_PRIMARY_PACKAGE and lint settings remain the compiler's own inputs.
    ///
    /// Source and generated inventories contain every relative subdirectory,
    /// including empty ones, in sorted order with the roots excluded. Workers
    /// independently pair them with the transferred files before constructing
    /// private read-only backings. No source mount exposes the outer Cargo
    /// target, Cargo home, control socket or uncaptured host workspace.
    #[allow(clippy::too_many_arguments)]
    pub fn new_canonical_workspace_execution(
        mode: DependencyExecutionMode,
        cwd: String,
        out_dir: String,
        dependency_dirs: Vec<String>,
        loader_dirs: Vec<String>,
        artifact_roots: Vec<DependencyArtifactRoot>,
        generated_root: Option<String>,
        source_directories: Vec<String>,
        generated_directories: Vec<String>,
        env: Vec<(String, String)>,
        runtime_cohort_sha256: [u8; 32],
    ) -> Result<Self, DependencyContextError> {
        validate_generated_directories(&source_directories)
            .map_err(|_| invalid("workspace source directory inventory is invalid"))?;
        let mut context = Self::new_in_profile(
            true,
            true,
            layout::WORKSPACE.to_owned(),
            cwd,
            layout::TOOLCHAIN.to_owned(),
            format!("{}/bin/rustc", layout::TOOLCHAIN),
            out_dir,
            dependency_dirs,
            loader_dirs,
            artifact_roots,
            generated_root,
            env,
            runtime_cohort_sha256,
        )?;
        // The process cwd and Cargo's package directory must actually exist in
        // the complete source image, not merely lie beneath its lexical root.
        let manifest = context
            .env
            .iter()
            .find(|(name, _)| name == "CARGO_MANIFEST_DIR")
            .map(|(_, value)| value.as_str())
            .expect("validated workspace manifest directory");
        for path in [context.cwd.as_str(), manifest] {
            if path != layout::WORKSPACE
                && path
                    .strip_prefix(&format!("{}/", layout::WORKSPACE))
                    .is_none_or(|relative| {
                        source_directories
                            .binary_search_by(|candidate| candidate.as_str().cmp(relative))
                            .is_err()
                    })
            {
                return Err(invalid(
                    "workspace cwd or package directory is absent from its source inventory",
                ));
            }
        }
        context.source_directories = source_directories;
        context
            .with_generated_directories(generated_directories)
            .map(|context| context.with_execution_mode(mode))
    }

    #[allow(clippy::too_many_arguments)]
    fn new_in_profile(
        canonical_cargo: bool,
        workspace_execution_only: bool,
        source_root: String,
        cwd: String,
        toolchain_root: String,
        compiler: String,
        out_dir: String,
        dependency_dirs: Vec<String>,
        mut loader_dirs: Vec<String>,
        mut artifact_roots: Vec<DependencyArtifactRoot>,
        generated_root: Option<String>,
        mut env: Vec<(String, String)>,
        runtime_cohort_sha256: [u8; 32],
    ) -> Result<Self, DependencyContextError> {
        if canonical_cargo {
            let environment = |name: &str| {
                env.iter()
                    .find(|(key, _)| key == name)
                    .map(|(_, value)| value.as_str())
            };
            let source_allowed = if workspace_execution_only {
                source_root == layout::WORKSPACE
            } else {
                [layout::WORKSPACE, layout::CARGO_HOME]
                    .iter()
                    .any(|root| canonical_descendant(&source_root, root))
            };
            let manifest_allowed = if workspace_execution_only {
                environment("CARGO_MANIFEST_DIR").is_some_and(|directory| {
                    directory == layout::WORKSPACE
                        || canonical_descendant(directory, layout::WORKSPACE)
                })
            } else {
                environment("CARGO_MANIFEST_DIR") == Some(cwd.as_str())
            };
            if !source_allowed
                || toolchain_root != layout::TOOLCHAIN
                || generated_root
                    .as_ref()
                    .is_some_and(|root| !canonical_descendant(root, "/__rabs/out/cargo"))
                || !canonical_descendant(&out_dir, "/__rabs/out/cargo")
                || dependency_dirs
                    .iter()
                    .any(|root| !canonical_descendant(root, "/__rabs/out/cargo"))
                || loader_dirs.iter().any(|root| {
                    root != "/__rabs/out/cargo" && !canonical_descendant(root, "/__rabs/out/cargo")
                })
                || environment("HOME") != Some(layout::HOME)
                || environment("CARGO_HOME") != Some(layout::CARGO_HOME)
                || !manifest_allowed
            {
                return Err(invalid(
                    "canonical dependency context has an invalid Cargo layout",
                ));
            }
        }
        let valid_alias = |value: &str| {
            if canonical_cargo {
                canonical_alias(value) || (workspace_execution_only && value == layout::WORKSPACE)
            } else {
                valid_alias(value)
            }
        };
        let roots: Vec<_> = [&source_root, &toolchain_root, &out_dir]
            .into_iter()
            .chain(generated_root.iter())
            .collect();
        if roots.iter().any(|root| !valid_alias(root))
            || !normalized_absolute(&cwd)
            || !Path::new(&cwd).starts_with(&source_root)
            || compiler != format!("{toolchain_root}/bin/rustc")
        {
            return Err(invalid("dependency context has invalid original paths"));
        }
        for (index, root) in roots.iter().enumerate() {
            if roots[index + 1..]
                .iter()
                .any(|other| overlaps(Path::new(root), Path::new(other)))
            {
                return Err(invalid(
                    "dependency source, generated, toolchain and output roots overlap",
                ));
            }
        }
        if dependency_dirs.len() > MAX_DEPENDENCY_DIRS {
            return Err(invalid("too many dependency search directories"));
        }
        if dependency_dirs.iter().collect::<BTreeSet<_>>().len() != dependency_dirs.len() {
            return Err(invalid("duplicate dependency search directory"));
        }
        for (index, directory) in dependency_dirs.iter().enumerate() {
            if !valid_alias(directory)
                || (directory != &out_dir
                    && roots
                        .iter()
                        .any(|root| overlaps(Path::new(directory), Path::new(root))))
                || dependency_dirs[index + 1..]
                    .iter()
                    .any(|other| overlaps(Path::new(directory), Path::new(other)))
            {
                return Err(invalid("dependency search directory shadows another mount"));
            }
        }
        if artifact_roots.len() > MAX_DEPENDENCY_DIRS {
            return Err(invalid("too many retained dependency artifact roots"));
        }
        artifact_roots.sort_by(|left, right| left.path.cmp(&right.path));
        if artifact_roots
            .windows(2)
            .any(|pair| pair[0].path == pair[1].path)
        {
            return Err(invalid("duplicate retained dependency artifact root"));
        }
        for artifact in &artifact_roots {
            let Some(index) = dependency_dirs
                .iter()
                .position(|path| path == &artifact.path)
            else {
                return Err(invalid(
                    "artifact root is not a declared dependency directory",
                ));
            };
            if artifact.prefix != format!("dependencies/{index:04}") {
                return Err(invalid("artifact root has a wrong first-use prefix"));
            }
        }
        if loader_dirs.len() > MAX_DEPENDENCY_DIRS {
            return Err(invalid("too many dependency loader directories"));
        }
        loader_dirs.sort();
        if loader_dirs.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(invalid("duplicate dependency loader directory"));
        }
        for directory in &loader_dirs {
            if !valid_alias(directory)
                || overlaps(Path::new(directory), Path::new(&source_root))
                || overlaps(Path::new(directory), Path::new(&toolchain_root))
                || generated_root
                    .as_ref()
                    .is_some_and(|root| Path::new(directory).starts_with(root))
                || (directory != &out_dir && Path::new(directory).starts_with(&out_dir))
                || dependency_dirs.iter().any(|dependency| {
                    directory != dependency && Path::new(directory).starts_with(dependency)
                })
            {
                return Err(invalid(
                    "dependency loader directory shadows a protected mount",
                ));
            }
        }
        if env.len() > MAX_DEPENDENCY_ENV_ENTRIES {
            return Err(invalid("dependency environment exceeds entry limit"));
        }
        let mut total = 0usize;
        let mut names = BTreeSet::new();
        for (name, value) in &env {
            if name.is_empty() || name.contains(['=', '\0']) || !names.insert(name) {
                return Err(invalid("invalid or duplicate dependency environment name"));
            }
            total = total
                .saturating_add(name.len())
                .saturating_add(value.len())
                .saturating_add(2);
            if value.contains('\0')
                || value.len() > crate::process_context::MAX_COMMAND_ENV_VALUE_BYTES
                || total > crate::process_context::MAX_COMMAND_ENV_BYTES
            {
                return Err(invalid(
                    "dependency environment exceeds byte limit or contains NUL",
                ));
            }
            if (name.starts_with("LD_") && name != "LD_LIBRARY_PATH") || name == "GLIBC_TUNABLES" {
                return Err(invalid(
                    "dependency environment has an unmodeled loader control",
                ));
            }
        }
        if env
            .iter()
            .find(|(name, _)| name == "OUT_DIR")
            .map(|(_, value)| value.as_str())
            != generated_root.as_deref()
        {
            return Err(invalid(
                "dependency OUT_DIR differs from its captured generated root",
            ));
        }
        env.sort_by(|left, right| left.0.cmp(&right.0));
        let context = Self {
            canonical_cargo,
            workspace_execution_only,
            execution_mode: DependencyExecutionMode::Metadata,
            source_root,
            source_directories: Vec::new(),
            generated_root,
            generated_directories: Vec::new(),
            native_roots: Vec::new(),
            cwd,
            toolchain_root,
            compiler,
            out_dir,
            dependency_dirs,
            loader_dirs,
            artifact_roots,
            env,
            runtime_cohort_sha256,
        };
        // Validate even when runtime observation is deferred until acquisition.
        context.loader_search_paths(Path::new(&context.toolchain_root))?;
        Ok(context)
    }

    /// Exact wire version selected for this validated path profile.
    pub const fn version(&self) -> &'static str {
        if self.workspace_execution_only {
            CANONICAL_WORKSPACE_CONTEXT_VERSION
        } else if self.canonical_cargo {
            CANONICAL_DEPENDENCY_CONTEXT_VERSION
        } else {
            DEPENDENCY_CONTEXT_VERSION
        }
    }

    /// Whether names came from a canonical Cargo planning namespace.
    pub const fn canonical_cargo(&self) -> bool {
        self.canonical_cargo
    }

    /// Whether this context permits only request-owned workspace execution.
    /// It must never be interpreted as dependency cache or publication proof.
    pub const fn workspace_execution_only(&self) -> bool {
        self.workspace_execution_only
    }

    /// Select the independently negotiated output class after path validation.
    /// Rlib narrows the namespace; it never grants execution or cache authority.
    #[must_use]
    pub fn with_execution_mode(mut self, mode: DependencyExecutionMode) -> Self {
        self.execution_mode = mode;
        self
    }

    /// Filesystem contract required for this invocation's output class.
    pub const fn execution_mode(&self) -> DependencyExecutionMode {
        self.execution_mode
    }

    /// Original immutable package/snapshot root.
    pub fn source_root(&self) -> &str {
        &self.source_root
    }
    /// Complete sorted workspace source subdirectories, root excluded. This
    /// inventory is explicit only in the workspace execution-only profile.
    pub fn source_directories(&self) -> &[String] {
        &self.source_directories
    }
    /// Original captured build-script output tree, when present.
    pub fn generated_root(&self) -> Option<&str> {
        self.generated_root.as_deref()
    }
    /// Complete sorted generated subdirectories relative to OUT_DIR. The root
    /// itself is implicit; the worker checks this inventory against the paired
    /// sealed generated files before constructing its private read-only tree.
    pub fn generated_directories(&self) -> &[String] {
        &self.generated_directories
    }

    /// Bind the complete captured generated-directory inventory to this
    /// execution. No directories may exist without a generated input root.
    /// File collisions and file-parent coverage require the separately retained
    /// source manifest and are checked before execution, never assumed here.
    ///
    /// # Errors
    /// A missing root, unsafe path, unsorted or duplicate name, missing parent,
    /// or directory inventory exceeding the negotiated bound.
    pub fn with_generated_directories(
        mut self,
        directories: Vec<String>,
    ) -> Result<Self, DependencyContextError> {
        if self.generated_root.is_none() && !directories.is_empty() {
            return Err(invalid(
                "dependency generated directories require a generated root",
            ));
        }
        validate_generated_directories(&directories)
            .map_err(|_| invalid("dependency generated directory inventory is invalid"))?;
        self.generated_directories = directories;
        Ok(self)
    }

    /// Retain additional complete native search trees from canonical Cargo's
    /// completed dependency build scripts. Their files and run records are
    /// acquired by the coordinator; this validates only the mount contract.
    /// Sorted paths define stable bundle prefixes without host path aliases.
    pub fn with_native_roots(
        mut self,
        roots: Vec<DependencyNativeRoot>,
    ) -> Result<Self, DependencyContextError> {
        if roots.len() > MAX_NATIVE_ROOTS
            || (!roots.is_empty() && !self.canonical_cargo)
            || roots.windows(2).any(|pair| pair[0].path >= pair[1].path)
        {
            return Err(invalid(
                "native input roots require a bounded canonical sorted set",
            ));
        }
        for (index, root) in roots.iter().enumerate() {
            if !canonical_descendant(&root.path, "/__rabs/out/cargo")
                || !root.path.ends_with("/out")
                || root.prefix != format!("native/{index:04}")
            {
                return Err(invalid(
                    "native input root has an invalid canonical path or prefix",
                ));
            }
            validate_generated_directories(&root.directories)
                .map_err(|_| invalid("native input directory inventory is invalid"))?;
            let visible = Path::new(&root.path);
            if [&self.source_root, &self.toolchain_root, &self.out_dir]
                .into_iter()
                .chain(self.generated_root.iter())
                .chain(self.dependency_dirs.iter())
                .any(|other| overlaps(visible, Path::new(other)))
                || roots[index + 1..]
                    .iter()
                    .any(|other| overlaps(visible, Path::new(&other.path)))
                || self
                    .loader_dirs
                    .iter()
                    .any(|directory| Path::new(directory).starts_with(visible))
            {
                return Err(invalid("native input root shadows another mount"));
            }
        }
        self.native_roots = roots;
        Ok(self)
    }

    /// Ordered additional retained build-output trees, each with exact topology.
    pub fn native_roots(&self) -> &[DependencyNativeRoot] {
        &self.native_roots
    }
    /// Original compiler working directory.
    pub fn cwd(&self) -> &str {
        &self.cwd
    }
    /// Original complete toolchain root.
    pub fn toolchain_root(&self) -> &str {
        &self.toolchain_root
    }
    /// Original rustc executable path, rooted in the transferred toolchain.
    pub fn compiler(&self) -> &str {
        &self.compiler
    }
    /// Original output directory, backed by this execution's private owner.
    pub fn out_dir(&self) -> &str {
        &self.out_dir
    }
    /// Dependency search directories in invocation first-use order.
    pub fn dependency_dirs(&self) -> &[String] {
        &self.dependency_dirs
    }
    /// Explicitly observed empty loader roots, including supported parents.
    pub fn loader_dirs(&self) -> &[String] {
        &self.loader_dirs
    }
    /// Exact retained candidate roots, paired with their sealed bundle prefixes.
    pub fn artifact_roots(&self) -> &[DependencyArtifactRoot] {
        &self.artifact_roots
    }
    /// Full exact environment before worker-local descriptor coordination.
    pub fn env(&self) -> &[(String, String)] {
        &self.env
    }
    /// Measured host runtime cohort required by the keyed execution profile.
    pub fn runtime_cohort_sha256(&self) -> &[u8; 32] {
        &self.runtime_cohort_sha256
    }

    /// Map loader search paths to retained physical toolchain bytes. Empty
    /// output/search roots cannot supply libraries. No caller path is opened.
    pub fn loader_search_paths(
        &self,
        toolchain_backing: &Path,
    ) -> Result<Vec<PathBuf>, DependencyContextError> {
        let Some((_, value)) = self.env.iter().find(|(name, _)| name == "LD_LIBRARY_PATH") else {
            return Ok(Vec::new());
        };
        // Preserve Cargo's whole-empty binding verbatim while representing its
        // zero search entries. Empty components in a nonempty colon list have
        // different loader semantics and remain invalid absolute paths below.
        if value.is_empty() {
            return Ok(Vec::new());
        }
        let mut paths = Vec::new();
        for directory in value.split(':') {
            if !normalized_absolute(directory) {
                return Err(invalid(
                    "dependency loader search path is not an absolute normalized path",
                ));
            }
            if let Ok(relative) = Path::new(directory).strip_prefix(&self.toolchain_root) {
                paths.push(toolchain_backing.join(relative));
            } else if directory != self.out_dir
                && !self
                    .dependency_dirs
                    .iter()
                    .chain(&self.loader_dirs)
                    .any(|path| path == directory)
            {
                return Err(invalid(
                    "dependency loader search path lies outside owned inputs",
                ));
            }
        }
        Ok(paths)
    }

    fn empty_aliases(&self) -> Vec<&str> {
        self.dependency_dirs
            .iter()
            .chain(&self.loader_dirs)
            .map(String::as_str)
            .filter(|path| {
                *path != self.out_dir.as_str()
                    && !self.artifact_roots.iter().any(|root| root.path == *path)
            })
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    fn empty_backing(root: &Path, index: usize) -> PathBuf {
        root.join(format!("search-{index:04}"))
    }

    /// Populate a fresh worker-owned staging directory with empty search trees.
    /// Every alias has separate private backing. An ancestor receives only the
    /// declared descendant mountpoint directories, created before its read-only
    /// bind; bubblewrap need not modify an already read-only target parent.
    ///
    /// # Errors
    /// The root is not a fresh absolute directory, or directory creation fails.
    pub fn prepare_empty_backings(&self, root: &Path) -> std::io::Result<()> {
        if !root.is_absolute()
            || root.starts_with("/__rabs")
            || std::fs::read_dir(root)?.next().is_some()
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "empty dependency backing must be a fresh private absolute directory",
            ));
        }
        let aliases = self.empty_aliases();
        for (index, alias) in aliases.iter().enumerate() {
            let backing = Self::empty_backing(root, index);
            std::fs::create_dir(&backing)?;
            for child in aliases
                .iter()
                .copied()
                .chain(std::iter::once(self.out_dir.as_str()))
                .chain(self.artifact_roots.iter().map(|root| root.path.as_str()))
                .chain(self.generated_root())
                .chain(self.native_roots.iter().map(|root| root.path.as_str()))
            {
                if let Ok(relative) = Path::new(child).strip_prefix(*alias)
                    && !relative.as_os_str().is_empty()
                {
                    std::fs::create_dir_all(backing.join(relative))?;
                }
            }
        }
        Ok(())
    }

    /// Construct only the explicitly owned mounts. Callers must first populate
    /// the fresh empty backing with prepare_empty_backings, then retain and
    /// verify all owners through process/drain completion. This type supplies
    /// visible aliases, never physical acquisition authority.
    pub fn namespace(
        &self,
        source_backing: &Path,
        toolchain_backing: &Path,
        output_backing: &Path,
        empty_backing: &Path,
        home_backing: &Path,
    ) -> Result<CanonicalNamespaceSpec, DependencyContextError> {
        let backings = [
            source_backing,
            toolchain_backing,
            output_backing,
            empty_backing,
            home_backing,
        ];
        if backings
            .iter()
            .any(|path| !path.is_absolute() || path.starts_with("/__rabs"))
        {
            return Err(invalid(
                "dependency mount backing is not private absolute storage",
            ));
        }
        let mut spec = CanonicalNamespaceSpec::new();
        spec.cwd = PathBuf::from(&self.cwd);
        spec.env = self.env.clone();
        spec.ro_binds = vec![
            Bind::new(source_backing, &self.source_root),
            Bind::new(toolchain_backing, &self.toolchain_root),
        ];
        if !self.artifact_roots.is_empty()
            || self.generated_root.is_some()
            || !self.native_roots.is_empty()
        {
            if source_backing.file_name() != Some(std::ffi::OsStr::new("package")) {
                return Err(invalid("dependency source is not a sealed package bundle"));
            }
            let bundle = source_backing
                .parent()
                .ok_or_else(|| invalid("dependency bundle parent is missing"))?;
            if let Some(generated) = self.generated_root() {
                // SourceOwner replaces this with its exclusive empty backing
                // when the sealed manifest contains an empty generated tree.
                spec.ro_binds
                    .push(Bind::new(bundle.join("generated"), generated));
            }
            spec.ro_binds.extend(
                self.artifact_roots
                    .iter()
                    .filter(|root| root.path != self.out_dir)
                    .map(|root| Bind::new(bundle.join(&root.prefix), &root.path)),
            );
            spec.ro_binds.extend(
                self.native_roots
                    .iter()
                    .map(|root| Bind::new(bundle.join(&root.prefix), &root.path)),
            );
        }
        spec.ro_binds.extend(
            self.empty_aliases()
                .into_iter()
                .enumerate()
                .map(|(index, path)| Bind::new(Self::empty_backing(empty_backing, index), path)),
        );
        spec.rw_binds = vec![
            Bind::new(output_backing, &self.out_dir),
            Bind::new(home_backing, layout::HOME),
        ];
        Ok(spec)
    }
}

/// Compile the separately validated original-path namespace. Ordinary
/// build_canonical_argv remains restricted to canonical /__rabs roots.
/// The runtime owner must outlive the child, its process cleanup, and output
/// capture. Its private retained bytes replace the broad host runtime mounts.
pub fn build_dependency_argv(
    context: &DependencyExecContext,
    spec: &CanonicalNamespaceSpec,
    runtime: &RetainedRuntime,
    support: &DependencyIsolationSupport,
    program: &str,
    args: &[String],
) -> Result<NamespaceLaunch, IsolationError> {
    if context.workspace_execution_only() {
        return Err(IsolationError::InvalidSpec {
            reason: "workspace execution requires its retained source-owner package anchor".into(),
        });
    }
    build_dependency_argv_with_package_anchor(context, spec, runtime, support, program, args, None)
}

/// Compile a workspace execution namespace after the source owner has rebuilt
/// its complete directory topology in separate private storage. The source
/// mount now names that rebuilt tree, while read-only dependency candidates
/// remain anchored in the original sealed transfer bundle.
///
/// `retained_package` must come from the live source owner's verified
/// dependency_root, never from a wire field or a guessed spec path. The caller
/// must retain that owner and independently protect every exact source and
/// artifact mount through completion. This only separates those two owned
/// backings; it grants no authority to read arbitrary coordinator paths.
#[allow(clippy::too_many_arguments)]
pub fn build_workspace_dependency_argv(
    context: &DependencyExecContext,
    spec: &CanonicalNamespaceSpec,
    runtime: &RetainedRuntime,
    support: &DependencyIsolationSupport,
    program: &str,
    args: &[String],
    retained_package: &Path,
) -> Result<NamespaceLaunch, IsolationError> {
    if !context.workspace_execution_only()
        || !retained_package.is_absolute()
        || retained_package.starts_with("/__rabs")
        || retained_package.file_name() != Some(std::ffi::OsStr::new("package"))
        || !std::fs::symlink_metadata(retained_package).is_ok_and(|metadata| metadata.is_dir())
        || !std::fs::canonicalize(retained_package)
            .is_ok_and(|canonical| canonical == retained_package)
    {
        return Err(IsolationError::InvalidSpec {
            reason: "workspace execution lacks its ordinary retained package anchor".into(),
        });
    }
    build_dependency_argv_with_package_anchor(
        context,
        spec,
        runtime,
        support,
        program,
        args,
        Some(retained_package),
    )
}

#[allow(clippy::too_many_arguments)]
fn build_dependency_argv_with_package_anchor(
    context: &DependencyExecContext,
    spec: &CanonicalNamespaceSpec,
    runtime: &RetainedRuntime,
    support: &DependencyIsolationSupport,
    program: &str,
    args: &[String],
    retained_package: Option<&Path>,
) -> Result<NamespaceLaunch, IsolationError> {
    support.require_mode(context.execution_mode())?;
    let refuse = || IsolationError::InvalidSpec {
        reason: "dependency namespace differs from its validated context".to_owned(),
    };
    let mut expected_ro: BTreeSet<_> = [
        context.source_root.as_str(),
        context.toolchain_root.as_str(),
    ]
    .into_iter()
    .chain(context.generated_root())
    .chain(context.native_roots.iter().map(|root| root.path.as_str()))
    .chain(context.empty_aliases())
    .chain(
        context
            .artifact_roots
            .iter()
            .filter(|root| root.path != context.out_dir)
            .map(|root| root.path.as_str()),
    )
    .map(PathBuf::from)
    .collect();
    let mut output_inputs = Vec::new();
    if let Some(root) = context
        .artifact_roots
        .iter()
        .find(|root| root.path == context.out_dir)
    {
        let source = spec
            .ro_binds
            .iter()
            .find(|bind| bind.visible == Path::new(context.source_root()))
            .ok_or_else(refuse)?;
        if source.backing.file_name() != Some(std::ffi::OsStr::new("package")) {
            return Err(refuse());
        }
        let retained = retained_package
            .unwrap_or(&source.backing)
            .parent()
            .ok_or_else(refuse)?
            .join(&root.prefix);
        for bind in &spec.ro_binds {
            if !bind.visible.starts_with(&context.out_dir) {
                continue;
            }
            let name = bind
                .visible
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(refuse)?;
            if bind.visible.parent() != Some(Path::new(&context.out_dir))
                || !name.starts_with("lib")
                || !(name.ends_with(".rmeta") || name.ends_with(".rlib"))
                || name.chars().any(char::is_control)
                || name.contains(['\\', ':'])
                || bind.backing != retained.join(name)
            {
                return Err(refuse());
            }
            expected_ro.insert(bind.visible.clone());
            output_inputs.push(bind.clone());
        }
        // The context declares a populated root. Only SourceOwner may derive
        // this exact set from its sealed manifest and create its placeholders;
        // this builder separately constrains shape, backing and mount ordering.
        if output_inputs.is_empty()
            || output_inputs.len() > crate::source_transfer::MAX_SOURCE_FILES
        {
            return Err(refuse());
        }
    }
    let expected_rw =
        BTreeSet::from([PathBuf::from(&context.out_dir), PathBuf::from(layout::HOME)]);
    let actual_ro: BTreeSet<_> = spec
        .ro_binds
        .iter()
        .map(|bind| bind.visible.clone())
        .collect();
    let actual_rw: BTreeSet<_> = spec
        .rw_binds
        .iter()
        .map(|bind| bind.visible.clone())
        .collect();
    let semantic_env = |env: &[(String, String)]| -> Vec<(String, String)> {
        env.iter()
            .filter(|(name, _)| {
                !matches!(name.as_str(), "MAKEFLAGS" | "MFLAGS" | "CARGO_MAKEFLAGS")
            })
            .cloned()
            .collect()
    };
    if program != context.compiler
        || spec.cwd != Path::new(&context.cwd)
        || spec.allows_network()
        || spec.hostname != "rabs"
        || actual_ro != expected_ro
        || actual_rw != expected_rw
        || actual_ro.len() != spec.ro_binds.len()
        || actual_rw.len() != spec.rw_binds.len()
        || semantic_env(&spec.env) != semantic_env(&context.env)
        || spec
            .ro_binds
            .iter()
            .chain(&spec.rw_binds)
            .any(|bind| !bind.backing.is_absolute() || bind.backing.starts_with("/__rabs"))
        || args.iter().any(|arg| arg.contains('\0'))
    {
        return Err(refuse());
    }
    if runtime.cohort().bytes != context.runtime_cohort_sha256 {
        return Err(IsolationError::InvalidSpec {
            reason: "retained dependency runtime differs from the negotiated cohort".to_owned(),
        });
    }
    let mut argv = dependency_base_argv(context.execution_mode(), &spec.env);
    let writable_backings: Vec<_> = spec
        .rw_binds
        .iter()
        .map(|bind| bind.backing.clone())
        .collect();
    runtime
        .append_mounts(&mut argv, &writable_backings)
        .map_err(|error| IsolationError::InvalidSpec {
            reason: format!("retained dependency runtime cannot be mounted: {error}"),
        })?;
    push_dependency_temporary_mounts(&mut argv);
    let mut ro: Vec<_> = spec
        .ro_binds
        .iter()
        .filter(|bind| !bind.visible.starts_with(&context.out_dir))
        .cloned()
        .collect();
    let mut rw = spec.rw_binds.clone();
    ro.sort_by(|left, right| left.visible.cmp(&right.visible));
    rw.sort_by(|left, right| left.visible.cmp(&right.visible));
    push_binds(&mut argv, &ro, &rw);
    output_inputs.sort_by(|left, right| left.visible.cmp(&right.visible));
    push_binds(&mut argv, &output_inputs, &[]);
    argv.extend(["--chdir", context.cwd.as_str(), "--", program].map(OsString::from));
    argv.extend(args.iter().map(OsString::from));
    Ok(NamespaceLaunch {
        argv,
        boundary: NamespaceBoundary {
            user_ns: true,
            pid_ns: true,
            ipc_ns: true,
            uts_hostname: Some("rabs".to_owned()),
            net_isolated: true,
            mounts_closed_view: true,
            clearenv: true,
            host_usr_ro: false,
            tmpfs_tmp: true,
            proc_private: context.execution_mode() == DependencyExecutionMode::Metadata,
            die_with_parent: true,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const CANONICAL_SOURCE: &str = "/__rabs/cargo-home/registry/src/index/leaf-1.0.0";
    const CANONICAL_OUTPUT: &str = "/__rabs/out/cargo/debug/deps";

    fn workspace_context(
        mode: DependencyExecutionMode,
        source_directories: Vec<String>,
        generated_root: Option<&str>,
        generated_directories: Vec<String>,
        artifacts: Vec<DependencyArtifactRoot>,
    ) -> Result<DependencyExecContext, DependencyContextError> {
        let mut env = vec![
            ("HOME".into(), layout::HOME.into()),
            ("CARGO_HOME".into(), layout::CARGO_HOME.into()),
            (
                "CARGO_MANIFEST_DIR".into(),
                "/__rabs/workspace/member".into(),
            ),
            ("CARGO_PKG_NAME".into(), "member".into()),
            ("CARGO_PRIMARY_PACKAGE".into(), "1".into()),
            ("ARBITRARY_COMPILE_INPUT".into(), "exact value".into()),
            (
                "LD_LIBRARY_PATH".into(),
                format!("{CANONICAL_OUTPUT}:/__rabs/toolchain/lib"),
            ),
        ];
        if let Some(root) = generated_root {
            env.push(("OUT_DIR".into(), root.into()));
        }
        DependencyExecContext::new_canonical_workspace_execution(
            mode,
            layout::WORKSPACE.into(),
            CANONICAL_OUTPUT.into(),
            vec![CANONICAL_OUTPUT.into()],
            Vec::new(),
            artifacts,
            generated_root.map(str::to_owned),
            source_directories,
            generated_directories,
            env,
            [0; 32],
        )
    }

    fn workspace_directories() -> Vec<String> {
        vec!["empty".into(), "member".into(), "member/src".into()]
    }

    fn native_root(path: &str, index: usize) -> DependencyNativeRoot {
        DependencyNativeRoot {
            path: path.into(),
            prefix: format!("native/{index:04}"),
            directories: vec!["empty".into(), "nested".into()],
        }
    }

    #[test]
    fn canonical_native_roots_keep_disjoint_complete_mounts_without_out_dir() {
        let roots = vec![
            native_root("/__rabs/out/cargo/debug/build/a-hash/out", 0),
            native_root("/__rabs/out/cargo/debug/build/b-hash/out", 1),
        ];
        let context = canonical_context()
            .with_native_roots(roots.clone())
            .unwrap();
        assert_eq!(context.native_roots(), roots);
        assert!(context.generated_root().is_none());
        let spec = context
            .namespace(
                Path::new("/private/bundle/package"),
                Path::new("/private/toolchain"),
                Path::new("/private/output"),
                Path::new("/private/empty"),
                Path::new("/private/home"),
            )
            .unwrap();
        for root in &roots {
            assert!(spec.ro_binds.contains(&Bind::new(
                Path::new("/private/bundle").join(&root.prefix),
                &root.path
            )));
            assert!(
                !spec
                    .rw_binds
                    .iter()
                    .any(|bind| bind.visible == Path::new(&root.path))
            );
        }
        for path in [
            "/host/native/out",
            "/__rabs/out/cargo/debug/build/a/../out",
            "/__rabs/out/cargo/debug/build/a",
            CANONICAL_OUTPUT,
        ] {
            assert!(
                canonical_context()
                    .with_native_roots(vec![native_root(path, 0)])
                    .is_err(),
                "{path}"
            );
        }
        let mut reversed = roots.clone();
        reversed.reverse();
        assert!(canonical_context().with_native_roots(reversed).is_err());
        let mut bad_prefix = roots.clone();
        bad_prefix[1].prefix = "native/0000".into();
        assert!(canonical_context().with_native_roots(bad_prefix).is_err());
        let mut parentless = roots.clone();
        parentless[0].directories = vec!["missing/parent".into()];
        assert!(canonical_context().with_native_roots(parentless).is_err());
        let overlap = vec![
            roots[0].clone(),
            native_root(&format!("{}/nested/out", roots[0].path), 1),
        ];
        assert!(canonical_context().with_native_roots(overlap).is_err());
        let own = workspace_context(
            DependencyExecutionMode::Rlib,
            workspace_directories(),
            Some(&roots[0].path),
            Vec::new(),
            Vec::new(),
        )
        .unwrap();
        assert!(own.with_native_roots(roots).is_err());
    }

    #[test]
    fn workspace_context_negotiates_complete_source_and_preserves_primary_member_environment() {
        for mode in [
            DependencyExecutionMode::Metadata,
            DependencyExecutionMode::Rlib,
        ] {
            let context =
                workspace_context(mode, workspace_directories(), None, Vec::new(), Vec::new())
                    .unwrap();
            assert!(context.canonical_cargo());
            assert!(context.workspace_execution_only());
            assert_eq!(context.version(), CANONICAL_WORKSPACE_CONTEXT_VERSION);
            assert_eq!(context.execution_mode(), mode);
            assert_eq!(context.source_root(), layout::WORKSPACE);
            assert_eq!(context.cwd(), layout::WORKSPACE);
            assert_eq!(context.source_directories(), workspace_directories());
            assert!(
                context
                    .env()
                    .contains(&("CARGO_PRIMARY_PACKAGE".into(), "1".into()))
            );
            assert!(
                context
                    .env()
                    .contains(&("ARBITRARY_COMPILE_INPUT".into(), "exact value".into()))
            );
            assert!(context.env().contains(&(
                "CARGO_MANIFEST_DIR".into(),
                "/__rabs/workspace/member".into()
            )));
            assert!(
                DependencyExecContext::new_canonical_cargo(
                    mode,
                    context.source_root.clone(),
                    context.cwd.clone(),
                    context.out_dir.clone(),
                    context.dependency_dirs.clone(),
                    context.loader_dirs.clone(),
                    Vec::new(),
                    context.env.clone(),
                    [0; 32],
                )
                .is_err(),
                "the old dependency version cannot mount the complete workspace"
            );
        }
        let dependency = canonical_context();
        assert!(!dependency.workspace_execution_only());
        assert!(dependency.source_directories().is_empty());
    }

    #[test]
    fn workspace_context_rejects_incomplete_source_topology_and_unowned_cargo_directories() {
        for directories in [
            Vec::new(),
            vec!["member/src".into()],
            vec!["member".into(), "member".into()],
            vec!["member/src".into(), "member".into()],
            vec!["/member".into()],
            vec!["member".into(), "member/../escape".into()],
            vec!["member".into(), "member//src".into()],
            vec!["member".into(), "member/./src".into()],
        ] {
            assert!(
                workspace_context(
                    DependencyExecutionMode::Metadata,
                    directories,
                    None,
                    Vec::new(),
                    Vec::new()
                )
                .is_err()
            );
        }
        let valid = workspace_context(
            DependencyExecutionMode::Metadata,
            workspace_directories(),
            None,
            Vec::new(),
            Vec::new(),
        )
        .unwrap();
        for (cwd, manifest) in [
            ("/__rabs/workspace/absent", "/__rabs/workspace/member"),
            ("/__rabs/workspace", "/__rabs/workspace/absent"),
            ("/__rabs/workspace", "/__rabs/cargo-home/registry/package"),
            ("/__rabs/workspace/../home", "/__rabs/workspace/member"),
            ("/outside/workspace", "/__rabs/workspace/member"),
        ] {
            let mut env = valid.env.clone();
            env.iter_mut()
                .find(|(name, _)| name == "CARGO_MANIFEST_DIR")
                .unwrap()
                .1 = manifest.into();
            assert!(
                DependencyExecContext::new_canonical_workspace_execution(
                    DependencyExecutionMode::Metadata,
                    cwd.into(),
                    valid.out_dir.clone(),
                    valid.dependency_dirs.clone(),
                    Vec::new(),
                    Vec::new(),
                    None,
                    workspace_directories(),
                    Vec::new(),
                    env,
                    [0; 32],
                )
                .is_err(),
                "cwd={cwd}, manifest={manifest}"
            );
        }
    }

    #[test]
    fn workspace_context_retains_empty_generated_roots_and_refuses_parentless_generated_dirs() {
        const ROOT: &str = "/__rabs/out/cargo/debug/build/member-123/out";
        let empty = workspace_context(
            DependencyExecutionMode::Rlib,
            workspace_directories(),
            Some(ROOT),
            Vec::new(),
            Vec::new(),
        )
        .unwrap();
        assert_eq!(empty.generated_root(), Some(ROOT));
        assert!(empty.generated_directories().is_empty());
        let full = workspace_context(
            DependencyExecutionMode::Rlib,
            workspace_directories(),
            Some(ROOT),
            vec!["nested".into(), "nested/empty".into()],
            Vec::new(),
        )
        .unwrap();
        assert_eq!(full.generated_directories(), &["nested", "nested/empty"]);
        assert_ne!(empty, full);
        for (root, directories) in [
            (None, vec!["nested".into()]),
            (Some(ROOT), vec!["nested/empty".into()]),
            (Some(ROOT), vec!["nested".into(), "nested".into()]),
            (Some(CANONICAL_OUTPUT), Vec::new()),
            (Some("/__rabs/workspace/generated"), Vec::new()),
        ] {
            assert!(
                workspace_context(
                    DependencyExecutionMode::Metadata,
                    workspace_directories(),
                    root,
                    directories,
                    Vec::new()
                )
                .is_err()
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn workspace_namespace_keeps_dependency_files_anchored_to_the_original_sealed_owner() {
        let owner = tempfile::tempdir().unwrap();
        let original = owner.path().join("original/package");
        let rebuilt = owner.path().join("rebuilt/package");
        std::fs::create_dir_all(&original).unwrap();
        std::fs::create_dir_all(rebuilt.join("member/src")).unwrap();
        std::fs::create_dir(rebuilt.join("empty")).unwrap();
        let artifact = original
            .parent()
            .unwrap()
            .join("dependencies/0000/libleaf.rmeta");
        std::fs::create_dir_all(artifact.parent().unwrap()).unwrap();
        std::fs::write(&artifact, b"retained exact dependency").unwrap();
        let mut context = workspace_context(
            DependencyExecutionMode::Metadata,
            workspace_directories(),
            None,
            Vec::new(),
            vec![DependencyArtifactRoot {
                path: CANONICAL_OUTPUT.into(),
                prefix: "dependencies/0000".into(),
            }],
        )
        .unwrap();
        let mut spec = context
            .namespace(
                &original,
                Path::new("/private/toolchain"),
                Path::new("/private/output"),
                Path::new("/private/empty"),
                Path::new("/private/home"),
            )
            .unwrap();
        let runtime = RuntimeFixture::prepare(&mut context, &mut spec);
        spec.ro_binds
            .iter_mut()
            .find(|bind| bind.visible == Path::new(layout::WORKSPACE))
            .unwrap()
            .backing = rebuilt.clone();
        let visible = Path::new(CANONICAL_OUTPUT).join("libleaf.rmeta");
        spec.ro_binds.push(Bind::new(&artifact, &visible));
        let support = fixture_support(context.execution_mode());
        assert!(
            build_dependency_argv(
                &context,
                &spec,
                &runtime.runtime,
                &support,
                context.compiler(),
                &[]
            )
            .is_err(),
            "workspace cannot borrow implicit dependency anchoring"
        );
        let launch = build_workspace_dependency_argv(
            &context,
            &spec,
            &runtime.runtime,
            &support,
            context.compiler(),
            &[],
            &original,
        )
        .unwrap();
        assert!(launch.argv.windows(3).any(|args| args[0] == "--ro-bind"
            && args[1] == artifact.as_os_str()
            && args[2] == visible.as_os_str()));
        assert!(launch.argv.windows(3).any(|args| args[0] == "--ro-bind"
            && args[1] == rebuilt.as_os_str()
            && args[2] == layout::WORKSPACE));
        let mut substituted = spec.clone();
        substituted
            .ro_binds
            .iter_mut()
            .find(|bind| bind.visible == visible)
            .unwrap()
            .backing = rebuilt
            .parent()
            .unwrap()
            .join("dependencies/0000/libleaf.rmeta");
        assert!(
            build_workspace_dependency_argv(
                &context,
                &substituted,
                &runtime.runtime,
                &support,
                context.compiler(),
                &[],
                &original
            )
            .is_err()
        );
        assert!(
            build_workspace_dependency_argv(
                &context,
                &spec,
                &runtime.runtime,
                &support,
                context.compiler(),
                &[],
                &rebuilt
            )
            .is_err(),
            "a real but different anchor cannot reassign artifact custody"
        );
        let alias = owner.path().join("alias");
        std::os::unix::fs::symlink(original.parent().unwrap(), &alias).unwrap();
        assert!(
            build_workspace_dependency_argv(
                &context,
                &spec,
                &runtime.runtime,
                &support,
                context.compiler(),
                &[],
                &alias.join("package")
            )
            .is_err()
        );
        assert!(
            build_workspace_dependency_argv(
                &canonical_context(),
                &spec,
                &runtime.runtime,
                &support,
                context.compiler(),
                &[],
                &original
            )
            .is_err()
        );
    }

    fn canonical_context() -> DependencyExecContext {
        DependencyExecContext::new_canonical_cargo(
            DependencyExecutionMode::Metadata,
            CANONICAL_SOURCE.into(),
            CANONICAL_SOURCE.into(),
            CANONICAL_OUTPUT.into(),
            vec![CANONICAL_OUTPUT.into()],
            vec!["/__rabs/out/cargo/debug".into()],
            Vec::new(),
            vec![
                ("HOME".into(), layout::HOME.into()),
                ("CARGO_HOME".into(), layout::CARGO_HOME.into()),
                ("CARGO_MANIFEST_DIR".into(), CANONICAL_SOURCE.into()),
                (
                    "LD_LIBRARY_PATH".into(),
                    format!("{CANONICAL_OUTPUT}:/__rabs/out/cargo/debug:/__rabs/toolchain/lib"),
                ),
            ],
            [0; 32],
        )
        .unwrap()
    }

    #[test]
    fn canonical_dependency_context_is_explicit_and_mounts_only_one_package() {
        let context = canonical_context();
        assert!(context.canonical_cargo());
        assert_eq!(context.version(), CANONICAL_DEPENDENCY_CONTEXT_VERSION);
        assert_eq!(context.execution_mode(), DependencyExecutionMode::Metadata);
        assert!(context.generated_root().is_none());
        assert!(
            DependencyExecContext::new_with_artifacts(
                context.source_root.clone(),
                context.cwd.clone(),
                context.toolchain_root.clone(),
                context.compiler.clone(),
                context.out_dir.clone(),
                context.dependency_dirs.clone(),
                context.loader_dirs.clone(),
                context.artifact_roots.clone(),
                context.env.clone(),
                context.runtime_cohort_sha256,
            )
            .is_err(),
            "ordinary dependency-exec-v8 cannot reinterpret canonical paths"
        );
        let spec = context
            .namespace(
                Path::new("/private/bundle/package"),
                Path::new("/private/toolchain"),
                Path::new("/private/output"),
                Path::new("/private/empty"),
                Path::new("/private/home"),
            )
            .unwrap();
        let ro: BTreeSet<_> = spec
            .ro_binds
            .iter()
            .map(|bind| bind.visible.as_path())
            .collect();
        assert_eq!(
            ro,
            BTreeSet::from([
                Path::new(CANONICAL_SOURCE),
                Path::new(layout::TOOLCHAIN),
                Path::new("/__rabs/out/cargo/debug"),
            ])
        );
        assert_eq!(
            spec.rw_binds,
            [
                Bind::new("/private/output", CANONICAL_OUTPUT),
                Bind::new("/private/home", layout::HOME),
            ]
        );
        assert_eq!(
            context
                .loader_search_paths(Path::new("/private/toolchain"))
                .unwrap(),
            [PathBuf::from("/private/toolchain/lib")]
        );
    }

    fn canonical_generated_context(
        root: &str,
        mode: DependencyExecutionMode,
    ) -> Result<DependencyExecContext, DependencyContextError> {
        let base = canonical_context();
        let mut env = base.env;
        env.push(("OUT_DIR".into(), root.into()));
        DependencyExecContext::new_canonical_cargo_with_generated(
            mode,
            base.source_root,
            base.cwd,
            base.out_dir,
            base.dependency_dirs,
            base.loader_dirs,
            base.artifact_roots,
            Some(root.into()),
            env,
            base.runtime_cohort_sha256,
        )
    }

    #[test]
    fn canonical_generated_inputs_require_a_disjoint_cargo_target_and_exact_environment() {
        let generated = "/__rabs/out/cargo/debug/build/leaf-123/out";
        let validate = |context: DependencyExecContext| {
            DependencyExecContext::new_canonical_cargo_with_generated(
                context.execution_mode,
                context.source_root,
                context.cwd,
                context.out_dir,
                context.dependency_dirs,
                context.loader_dirs,
                context.artifact_roots,
                context.generated_root,
                context.env,
                context.runtime_cohort_sha256,
            )
        };
        for mode in [
            DependencyExecutionMode::Metadata,
            DependencyExecutionMode::Rlib,
        ] {
            let context = canonical_generated_context(generated, mode).unwrap();
            assert_eq!(context.version(), "canonical-dependency-exec-v4");
            assert_eq!(context.generated_root(), Some(generated));
            assert_eq!(context.execution_mode(), mode);
            assert!(
                context
                    .env()
                    .contains(&("OUT_DIR".into(), generated.into()))
            );
            assert_eq!(validate(context.clone()).unwrap(), context);
            for dependency in [
                generated,
                "/__rabs/out/cargo/debug/build",
                "/__rabs/out/cargo/debug/build/leaf-123/out/deps",
            ] {
                let mut changed = context.clone();
                changed.dependency_dirs.push(dependency.into());
                assert!(validate(changed).is_err(), "dependency root {dependency}");
            }
            for loader in [generated, "/__rabs/out/cargo/debug/build/leaf-123/out/lib"] {
                let mut changed = context.clone();
                changed.loader_dirs.push(loader.into());
                assert!(validate(changed).is_err(), "loader root {loader}");
            }
            for value in ["", "/__rabs/out/cargo/other-generated"] {
                let mut changed = context.clone();
                changed
                    .env
                    .iter_mut()
                    .find(|(name, _)| name == "OUT_DIR")
                    .unwrap()
                    .1 = value.into();
                assert!(validate(changed).is_err());
            }
            let mut missing_root = context.clone();
            missing_root.generated_root = None;
            assert!(validate(missing_root).is_err());
            let mut env = context.env.clone();
            env.retain(|(name, _)| name != "OUT_DIR");
            assert!(
                DependencyExecContext::new_canonical_cargo_with_generated(
                    mode,
                    context.source_root,
                    context.cwd,
                    context.out_dir,
                    context.dependency_dirs,
                    context.loader_dirs,
                    context.artifact_roots,
                    Some(generated.into()),
                    env,
                    context.runtime_cohort_sha256,
                )
                .is_err()
            );
        }
        for root in [
            "/__rabs",
            "/__rabs/out/cargo",
            "/__rabs/out/cargo/debug",
            CANONICAL_OUTPUT,
            "/__rabs/out/cargo/debug/deps/generated",
            "/__rabs/out/cargo/debug/build/../out",
            "/__rabs/out/cargo/debug//out",
            "/__rabs/out/cargo-other/build/leaf/out",
            CANONICAL_SOURCE,
            "/__rabs/workspace/generated",
            "/__rabs/cargo-home/generated",
            "/__rabs/toolchain/generated",
            "/__rabs/home/control",
            "/tmp/generated",
            "relative/generated",
        ] {
            for mode in [
                DependencyExecutionMode::Metadata,
                DependencyExecutionMode::Rlib,
            ] {
                assert!(
                    canonical_generated_context(root, mode).is_err(),
                    "generated root escaped its closed canonical input contract: {root}"
                );
            }
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn canonical_generated_namespace_keeps_inputs_read_only_under_the_loader_parent() {
        let generated = "/__rabs/out/cargo/debug/build/leaf-123/out";
        for mode in [
            DependencyExecutionMode::Metadata,
            DependencyExecutionMode::Rlib,
        ] {
            let mut context = canonical_generated_context(generated, mode).unwrap();
            let empty = tempfile::tempdir().unwrap();
            context.prepare_empty_backings(empty.path()).unwrap();
            let mut spec = context
                .namespace(
                    Path::new("/private/bundle/package"),
                    Path::new("/private/toolchain"),
                    Path::new("/private/output"),
                    empty.path(),
                    Path::new("/private/home"),
                )
                .unwrap();
            let runtime = RuntimeFixture::prepare(&mut context, &mut spec);
            let parent = spec
                .ro_binds
                .iter()
                .find(|bind| bind.visible == Path::new("/__rabs/out/cargo/debug"))
                .unwrap();
            assert!(parent.backing.starts_with(empty.path()));
            let generated_mountpoint = parent.backing.join("build/leaf-123/out");
            assert!(generated_mountpoint.is_dir());
            assert_eq!(std::fs::read_dir(&generated_mountpoint).unwrap().count(), 0);
            assert!(
                spec.ro_binds
                    .contains(&Bind::new("/private/bundle/generated", generated))
            );
            let support = fixture_support(mode);
            let launch = build_dependency_argv(
                &context,
                &spec,
                &runtime.runtime,
                &support,
                context.compiler(),
                &[],
            )
            .unwrap();
            let argv = launch
                .argv
                .iter()
                .map(|arg| arg.to_str().unwrap())
                .collect::<Vec<_>>();
            let parent_at = argv
                .windows(3)
                .position(|row| {
                    row == [
                        "--ro-bind",
                        parent.backing.to_str().unwrap(),
                        "/__rabs/out/cargo/debug",
                    ]
                })
                .unwrap();
            let generated_at = argv
                .windows(3)
                .position(|row| row == ["--ro-bind", "/private/bundle/generated", generated])
                .unwrap();
            assert!(parent_at < generated_at);
            assert_eq!(
                argv.contains(&"--proc"),
                mode == DependencyExecutionMode::Metadata
            );
            assert_eq!(
                argv.contains(&"--dev"),
                mode == DependencyExecutionMode::Metadata
            );
            assert!(
                spec.rw_binds
                    .iter()
                    .all(|bind| !overlaps(&bind.visible, Path::new(generated)))
            );
            let mut missing = spec.clone();
            missing
                .ro_binds
                .retain(|bind| bind.visible != Path::new(generated));
            assert!(
                build_dependency_argv(
                    &context,
                    &missing,
                    &runtime.runtime,
                    &support,
                    context.compiler(),
                    &[],
                )
                .is_err()
            );
            let mut writable_only = spec.clone();
            let generated_at = writable_only
                .ro_binds
                .iter()
                .position(|bind| bind.visible == Path::new(generated))
                .unwrap();
            writable_only
                .rw_binds
                .push(writable_only.ro_binds.remove(generated_at));
            assert!(
                build_dependency_argv(
                    &context,
                    &writable_only,
                    &runtime.runtime,
                    &support,
                    context.compiler(),
                    &[],
                )
                .is_err()
            );
            let mut writable = spec;
            writable
                .rw_binds
                .push(Bind::new("/private/bundle/generated", generated));
            assert!(
                build_dependency_argv(
                    &context,
                    &writable,
                    &runtime.runtime,
                    &support,
                    context.compiler(),
                    &[],
                )
                .is_err()
            );
        }
    }

    #[test]
    fn canonical_dependency_layout_cannot_expose_outer_driver_or_host_roots() {
        let original = canonical_context();
        let validate = |context: DependencyExecContext| {
            DependencyExecContext::new_canonical_cargo(
                context.execution_mode,
                context.source_root,
                context.cwd,
                context.out_dir,
                context.dependency_dirs,
                context.loader_dirs,
                context.artifact_roots,
                context.env,
                context.runtime_cohort_sha256,
            )
        };
        for root in [
            "/__rabs",
            layout::WORKSPACE,
            layout::CARGO_HOME,
            "/__rabs/home/control",
            "/__rabs/cargo-home-other/package",
            "/tmp/package",
            "/__rabs/workspace/vendor/../other",
        ] {
            let mut context = original.clone();
            context.source_root = root.into();
            context.cwd = root.into();
            context
                .env
                .iter_mut()
                .find(|(name, _)| name == "CARGO_MANIFEST_DIR")
                .unwrap()
                .1 = root.into();
            assert!(validate(context).is_err(), "source root {root}");
        }
        for root in [
            "/__rabs/out",
            "/__rabs/out/cargo",
            "/__rabs/out/cargo-other/deps",
            "/tmp/deps",
        ] {
            let mut context = original.clone();
            context.out_dir = root.into();
            context.dependency_dirs = vec![root.into()];
            assert!(validate(context).is_err(), "output root {root}");
        }
        for root in [
            layout::WORKSPACE,
            layout::CARGO_HOME,
            "/__rabs/home/control",
            "/__rabs/out",
            "/usr/lib",
        ] {
            let mut context = original.clone();
            context.loader_dirs.push(root.into());
            assert!(validate(context).is_err(), "loader root {root}");
        }
        for (name, value) in [
            ("HOME", "/home/user"),
            ("CARGO_HOME", "/home/user/.cargo"),
            ("OUT_DIR", "/__rabs/out/cargo/debug/generated"),
        ] {
            let mut context = original.clone();
            context.env.retain(|(key, _)| key != name);
            context.env.push((name.into(), value.into()));
            assert!(validate(context).is_err(), "environment {name}");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn canonical_dependency_namespace_preserves_paths_and_refuses_extra_mounts_and_wrong_mode() {
        let mut context = canonical_context();
        let mut spec = context
            .namespace(
                Path::new("/private/bundle/package"),
                Path::new("/private/toolchain"),
                Path::new("/private/output"),
                Path::new("/private/empty"),
                Path::new("/private/home"),
            )
            .unwrap();
        let runtime = RuntimeFixture::prepare(&mut context, &mut spec);
        let support = fixture_support(DependencyExecutionMode::Metadata);
        let args = vec![
            format!("{CANONICAL_SOURCE}/src/lib.rs"),
            "--emit=dep-info,metadata".into(),
        ];
        let launch = build_dependency_argv(
            &context,
            &spec,
            &runtime.runtime,
            &support,
            context.compiler(),
            &args,
        )
        .unwrap();
        assert!(launch.boundary.mounts_closed_view);
        assert!(!launch.boundary.host_usr_ro);
        let argv = launch
            .argv
            .iter()
            .map(|value| value.to_str().unwrap())
            .collect::<Vec<_>>();
        assert!(argv.ends_with(&[context.compiler(), args[0].as_str(), args[1].as_str()]));
        for visible in [
            layout::WORKSPACE,
            layout::CARGO_HOME,
            "/__rabs/home/control",
        ] {
            let mut extra = spec.clone();
            extra
                .ro_binds
                .push(Bind::new("/private/outer-driver", visible));
            assert!(
                build_dependency_argv(
                    &context,
                    &extra,
                    &runtime.runtime,
                    &support,
                    context.compiler(),
                    &args
                )
                .is_err()
            );
        }
        let archive = context.with_execution_mode(DependencyExecutionMode::Rlib);
        assert!(matches!(
            build_dependency_argv(&archive, &spec, &runtime.runtime, &support, archive.compiler(), &args),
            Err(IsolationError::InvalidSpec { reason }) if reason.contains("another execution mode")
        ));
    }

    // Pure namespace-construction fixtures, never kernel capability evidence.
    fn fixture_support(mode: DependencyExecutionMode) -> DependencyIsolationSupport {
        DependencyIsolationSupport {
            mode,
            bubblewrap: Some("test".into()),
            base_namespace: true,
            null_device: mode == DependencyExecutionMode::Rlib,
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn archive_null_device_cannot_be_replaced_by_regular_bytes_or_another_device() {
        let owner = tempfile::tempdir().unwrap();
        let regular = owner.path().join("null");
        std::fs::write(&regular, b"unkeyed bytes must never enter the archive view").unwrap();
        let link = owner.path().join("null-link");
        std::os::unix::fs::symlink("/dev/null", &link).unwrap();
        let support = fixture_support(DependencyExecutionMode::Rlib);
        for path in [
            regular,
            link,
            owner.path().join("missing"),
            PathBuf::from("/dev/zero"),
        ] {
            assert!(!linux_null_device(&path), "{}", path.display());
            assert!(matches!(
                support.require_mode_with_null_device(DependencyExecutionMode::Rlib, &path),
                Err(IsolationError::UnsupportedHost { missing })
                    if missing == ["linux-null-device"]
            ));
        }
        // Metadata never gains a new device rule or consumes an archive proof.
        let metadata = fixture_support(DependencyExecutionMode::Metadata);
        assert!(
            metadata
                .require_mode_with_null_device(
                    DependencyExecutionMode::Metadata,
                    &owner.path().join("missing")
                )
                .is_ok()
        );
    }

    #[cfg(target_os = "linux")]
    fn probe_fixture(body: &str) -> (tempfile::TempDir, PathBuf) {
        use std::os::unix::fs::PermissionsExt;

        let owner = tempfile::tempdir().unwrap();
        let executable = owner.path().join("bwrap");
        std::fs::write(
            &executable,
            format!(
                "#!/bin/sh\n\
                 if [ \"$#\" -eq 1 ] && [ \"$1\" = --version ]; then\n\
                 printf 'bubblewrap fixture\\n'; exit 0\n\
                 fi\n\
                 printf '%s\\000' \"$@\" > \"$0.argv\"\n\
                 {body}\n"
            ),
        )
        .unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
        (owner, executable)
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn archive_probe_executes_the_complete_production_base() {
        // The fixture checks the exact command and exit handling; only the
        // real ignored rustc test below supplies kernel execution evidence.
        let (owner, executable) = probe_fixture("exit 0");
        let support = DependencyIsolationSupport::probe_with_bubblewrap(
            DependencyExecutionMode::Rlib,
            &executable,
        );
        assert!(support.is_supported());
        assert!(support.missing().is_empty());
        assert_eq!(support.mode(), DependencyExecutionMode::Rlib);
        let recorded = std::fs::read_to_string(owner.path().join("bwrap.argv")).unwrap();
        let argv = recorded.split_terminator('\0').collect::<Vec<_>>();
        let production = dependency_base_argv(DependencyExecutionMode::Rlib, &[]);
        let expected = production[1..]
            .iter()
            .map(|argument| argument.to_str().unwrap())
            .collect::<Vec<_>>();
        assert!(argv.starts_with(&expected));
        for flag in [
            "--unshare-user",
            "--unshare-pid",
            "--unshare-ipc",
            "--unshare-uts",
            "--unshare-net",
            "--clearenv",
            "--die-with-parent",
        ] {
            assert!(argv.contains(&flag), "missing production axis {flag}");
        }
        for pair in [
            ["--hostname", "rabs"],
            ["--dir", "/dev"],
            ["--tmpfs", "/tmp"],
            ["--tmpfs", layout::TMP],
            ["--chdir", layout::TMP],
            ["--", "/usr/bin/true"],
        ] {
            assert!(argv.windows(2).any(|window| window == pair), "{pair:?}");
        }
        assert!(
            argv.windows(3)
                .any(|window| window == ["--dev-bind", "/dev/null", "/dev/null"])
        );
        assert!(!argv.contains(&"--proc") && !argv.contains(&"--dev"));
        assert!(
            !argv
                .windows(3)
                .any(|window| window == ["--ro-bind", "/", "/"])
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn archive_support_does_not_fabricate_proc_or_canonical_support() {
        let (_owner, executable) = probe_fixture(
            "for arg do\n\
             if [ \"$arg\" = --proc ]; then exit 1; fi\n\
             done\n\
             exit 0",
        );
        let canonical = HostIsolationSupport::probe_with_bubblewrap(&executable);
        assert!(!canonical.unprivileged_userns);
        assert_eq!(
            canonical.missing_for_canonical(),
            ["unprivileged-user-namespaces"]
        );
        let metadata = DependencyIsolationSupport::probe_with_bubblewrap(
            DependencyExecutionMode::Metadata,
            &executable,
        );
        assert!(!metadata.is_supported());
        assert_eq!(metadata.missing(), ["dependency-metadata-base-namespace"]);
        let archive = DependencyIsolationSupport::probe_with_bubblewrap(
            DependencyExecutionMode::Rlib,
            &executable,
        );
        assert!(archive.is_supported());
        assert!(archive.require_mode(DependencyExecutionMode::Rlib).is_ok());
        assert!(matches!(
            archive.require_mode(DependencyExecutionMode::Metadata),
            Err(IsolationError::InvalidSpec { .. })
        ));
        assert!(matches!(
            metadata.require_mode(DependencyExecutionMode::Metadata),
            Err(IsolationError::UnsupportedHost { .. })
        ));
        assert!(matches!(
            crate::canonical_namespace::build_canonical_argv(
                &CanonicalNamespaceSpec::new(),
                &canonical,
                "cargo",
                &[],
            ),
            Err(IsolationError::UnsupportedHost { .. })
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn archive_probe_requires_successful_execution_of_every_base_axis() {
        for refused in [
            "--unshare-user",
            "--unshare-pid",
            "--unshare-ipc",
            "--unshare-uts",
            "--unshare-net",
            "--clearenv",
            "--tmpfs",
            "--dev-bind",
            "/usr/bin/true",
        ] {
            let (_owner, executable) = probe_fixture(&format!(
                "for arg do\nif [ \"$arg\" = '{refused}' ]; then exit 1; fi\ndone\nexit 0"
            ));
            let support = DependencyIsolationSupport::probe_with_bubblewrap(
                DependencyExecutionMode::Rlib,
                &executable,
            );
            assert!(!support.is_supported(), "{refused}");
            assert_eq!(support.missing(), ["dependency-rlib-base-namespace"]);
            assert!(matches!(
                support.require_mode(DependencyExecutionMode::Rlib),
                Err(IsolationError::UnsupportedHost { .. })
            ));
        }
        let owner = tempfile::tempdir().unwrap();
        let missing = DependencyIsolationSupport::probe_with_bubblewrap(
            DependencyExecutionMode::Rlib,
            &owner.path().join("missing-bwrap"),
        );
        assert!(!missing.is_supported());
        assert_eq!(
            missing.missing(),
            ["bubblewrap", "dependency-rlib-base-namespace"]
        );
    }

    #[cfg(target_os = "linux")]
    struct RuntimeFixture {
        runtime: RetainedRuntime,
        root: tempfile::TempDir,
    }

    #[cfg(target_os = "linux")]
    impl RuntimeFixture {
        fn prepare(context: &mut DependencyExecContext, spec: &mut CanonicalNamespaceSpec) -> Self {
            Self::prepare_with_program(context, spec, Path::new("/usr/bin/true"))
        }

        fn prepare_with_program(
            context: &mut DependencyExecContext,
            spec: &mut CanonicalNamespaceSpec,
            executable: &Path,
        ) -> Self {
            let root = tempfile::tempdir().unwrap();
            let toolchain = root.path().join("toolchain");
            std::fs::create_dir_all(toolchain.join("bin")).unwrap();
            std::fs::create_dir(toolchain.join("lib")).unwrap();
            let compiler = toolchain.join("bin/rustc");
            std::fs::copy(executable, &compiler).unwrap();
            spec.ro_binds
                .iter_mut()
                .find(|bind| bind.visible == Path::new(context.toolchain_root()))
                .unwrap()
                .backing = toolchain.clone();
            for (index, bind) in spec.rw_binds.iter_mut().enumerate() {
                bind.backing = root.path().join(format!("writable-{index}"));
                std::fs::create_dir(&bind.backing).unwrap();
            }
            let runtime = crate::runtime_cohort::retain_runtime_cohort(
                &compiler,
                &toolchain,
                &[],
                root.path(),
                root.path(),
                || false,
            )
            .unwrap();
            context.runtime_cohort_sha256 = runtime.cohort().bytes;
            Self { runtime, root }
        }
    }

    fn context(env: Vec<(String, String)>) -> DependencyExecContext {
        DependencyExecContext::new(
            "/home/user/registry/package".into(),
            "/home/user/registry/package/src".into(),
            "/home/user/toolchains/pinned".into(),
            "/home/user/toolchains/pinned/bin/rustc".into(),
            "/work/build/deps".into(),
            vec!["/work/build/deps".into(), "/work/build/empty".into()],
            env,
            [7; 32],
        )
        .unwrap()
    }

    fn generated_context(
        generated: Option<&str>,
        env: Vec<(String, String)>,
        loaders: Vec<String>,
    ) -> Result<DependencyExecContext, DependencyContextError> {
        let base = context(Vec::new());
        DependencyExecContext::new_with_generated_artifacts(
            base.source_root,
            base.cwd,
            base.toolchain_root,
            base.compiler,
            base.out_dir,
            base.dependency_dirs,
            loaders,
            Vec::new(),
            generated.map(str::to_owned),
            env,
            [7; 32],
        )
    }

    #[test]
    fn generated_directory_context_binds_complete_tree_in_both_path_profiles() {
        let root = "/work/build/generated/unit/out";
        let original = generated_context(
            Some(root),
            vec![("OUT_DIR".to_owned(), root.to_owned())],
            Vec::new(),
        )
        .unwrap();
        let canonical = canonical_generated_context(
            "/__rabs/out/cargo/debug/build/leaf-123/out",
            DependencyExecutionMode::Rlib,
        )
        .unwrap();
        assert_eq!(original.version(), "dependency-exec-v8");
        assert_eq!(canonical.version(), "canonical-dependency-exec-v4");
        for context in [original, canonical] {
            assert!(context.generated_directories().is_empty());
            let populated = context
                .clone()
                .with_generated_directories(vec!["empty".into(), "empty/child".into()])
                .unwrap();
            assert_eq!(populated.generated_directories(), &["empty", "empty/child"]);
            assert_ne!(populated, context);
            assert_eq!(populated.generated_root(), context.generated_root());
            assert_eq!(populated.env(), context.env());
            for directories in [
                vec!["empty/child".into()],
                vec!["empty".into(), "empty".into()],
                vec!["empty".into(), "empty/../other".into()],
                vec!["z".into(), "a".into()],
                vec!["/absolute".into()],
            ] {
                assert!(
                    context
                        .clone()
                        .with_generated_directories(directories)
                        .is_err()
                );
            }
        }
        for context in [context(Vec::new()), canonical_context()] {
            assert!(context.generated_root().is_none());
            assert!(
                context
                    .clone()
                    .with_generated_directories(Vec::new())
                    .is_ok()
            );
            assert!(
                context
                    .with_generated_directories(vec!["empty".into()])
                    .is_err()
            );
        }
    }

    #[test]
    fn generated_root_and_out_dir_environment_form_one_exact_contract() {
        let root = "/work/build/generated/unit/out";
        let env = vec![("OUT_DIR".to_owned(), root.to_owned())];
        let good = generated_context(Some(root), env.clone(), Vec::new()).unwrap();
        assert_eq!(good.generated_root(), Some(root));
        assert_eq!(good.env(), env);
        assert!(
            generated_context(None, Vec::new(), Vec::new())
                .unwrap()
                .generated_root()
                .is_none()
        );
        for (generated, env) in [
            (Some(root), Vec::new()),
            (None, env.clone()),
            (Some(root), vec![("OUT_DIR".to_owned(), String::new())]),
            (
                Some(root),
                vec![("OUT_DIR".to_owned(), "/elsewhere/out".to_owned())],
            ),
        ] {
            assert!(generated_context(generated, env, Vec::new()).is_err());
        }
        for generated in [
            "/home/user/registry/package",
            "/home/user/registry/package/generated",
            "/home/user/toolchains/pinned/lib",
            "/work/build/deps",
            "/work/build/deps/generated",
            "/work/build/empty",
            "/work/build",
            "/usr/generated",
            "/proc/generated",
            "/__rabs/generated",
            "/work/../generated",
            "relative/generated",
        ] {
            assert!(
                generated_context(
                    Some(generated),
                    vec![("OUT_DIR".to_owned(), generated.to_owned())],
                    Vec::new()
                )
                .is_err(),
                "{generated}"
            );
        }
        for loader in [root, "/work/build/generated/unit/out/lib"] {
            assert!(generated_context(Some(root), env.clone(), vec![loader.to_owned()]).is_err());
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn generated_tree_is_read_only_below_its_prepared_loader_parent() {
        let root = "/work/build/generated/unit/out";
        let mut context = generated_context(
            Some(root),
            vec![
                ("OUT_DIR".to_owned(), root.to_owned()),
                ("LD_LIBRARY_PATH".to_owned(), "/work/build".to_owned()),
            ],
            vec!["/work/build".to_owned()],
        )
        .unwrap();
        let empty = tempfile::tempdir().unwrap();
        context.prepare_empty_backings(empty.path()).unwrap();
        let mut spec = context
            .namespace(
                Path::new("/private/bundle/package"),
                Path::new("/private/toolchain"),
                Path::new("/private/output"),
                empty.path(),
                Path::new("/private/home"),
            )
            .unwrap();
        let runtime = RuntimeFixture::prepare(&mut context, &mut spec);
        let parent = spec
            .ro_binds
            .iter()
            .find(|bind| bind.visible == Path::new("/work/build"))
            .unwrap();
        let generated = spec
            .ro_binds
            .iter()
            .find(|bind| bind.visible == Path::new(root))
            .unwrap();
        assert_eq!(generated.backing, Path::new("/private/bundle/generated"));
        assert_eq!(
            std::fs::read_dir(parent.backing.join("generated/unit/out"))
                .unwrap()
                .count(),
            0
        );
        assert!(
            spec.rw_binds
                .iter()
                .all(|bind| !overlaps(&bind.visible, Path::new(root)))
        );
        let support = fixture_support(context.execution_mode());
        let launch = build_dependency_argv(
            &context,
            &spec,
            &runtime.runtime,
            &support,
            context.compiler(),
            &[],
        )
        .unwrap();
        let argv: Vec<_> = launch
            .argv
            .iter()
            .map(|value| value.to_str().unwrap())
            .collect();
        let parent_at = argv
            .windows(3)
            .position(|row| row == ["--ro-bind", parent.backing.to_str().unwrap(), "/work/build"])
            .unwrap();
        let generated_at = argv
            .windows(3)
            .position(|row| row == ["--ro-bind", "/private/bundle/generated", root])
            .unwrap();
        assert!(parent_at < generated_at);
        let mut missing = spec.clone();
        missing
            .ro_binds
            .retain(|bind| bind.visible != Path::new(root));
        assert!(
            build_dependency_argv(
                &context,
                &missing,
                &runtime.runtime,
                &support,
                context.compiler(),
                &[]
            )
            .is_err()
        );
        let mut extra = spec;
        extra
            .ro_binds
            .push(Bind::new("/private/foreign", format!("{root}/injected")));
        assert!(
            build_dependency_argv(
                &context,
                &extra,
                &runtime.runtime,
                &support,
                context.compiler(),
                &[]
            )
            .is_err()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn original_paths_environment_and_empty_search_mounts_survive() {
        let mut context = context(vec![(
            "DEPENDENCY_FLAVOR".into(),
            "hello /home/user/registry/package".into(),
        )]);
        let mut spec = context
            .namespace(
                Path::new("/private/source"),
                Path::new("/private/toolchain"),
                Path::new("/private/output"),
                Path::new("/private/empty"),
                Path::new("/private/home"),
            )
            .unwrap();
        let runtime = RuntimeFixture::prepare(&mut context, &mut spec);
        let support = fixture_support(context.execution_mode());
        let args = vec!["src/lib.rs".into(), "--emit=dep-info,metadata".into()];
        let launch = build_dependency_argv(
            &context,
            &spec,
            &runtime.runtime,
            &support,
            context.compiler(),
            &args,
        )
        .unwrap();
        let args: Vec<_> = launch
            .argv
            .iter()
            .map(|value| value.to_str().unwrap())
            .collect();
        assert!(
            args.windows(3)
                .any(|values| values == ["--ro-bind", "/private/source", context.source_root()])
        );
        assert!(args.windows(3).any(|values| values
            == [
                "--ro-bind",
                "/private/empty/search-0000",
                "/work/build/empty"
            ]));
        assert!(args.windows(3).any(|values| values
            == [
                "--bind",
                runtime.root.path().join("writable-0").to_str().unwrap(),
                context.out_dir()
            ]));
        assert!(args.windows(3).any(|values| values
            == [
                "--setenv",
                "DEPENDENCY_FLAVOR",
                "hello /home/user/registry/package"
            ]));
        assert!(args.ends_with(&[context.compiler(), "src/lib.rs", "--emit=dep-info,metadata"]));
        let canonical_support = HostIsolationSupport {
            bubblewrap: Some("test".into()),
            unprivileged_userns: true,
            overlayfs: false,
            cgroup_v2: false,
            landlock: false,
        };
        assert!(
            crate::canonical_namespace::build_canonical_argv(
                &spec,
                &canonical_support,
                context.compiler(),
                &[]
            )
            .is_err()
        );
        assert!(launch.boundary.net_isolated);
        assert!(!launch.boundary.host_usr_ro);
        let retained_usr = args
            .windows(3)
            .find(|values| values[0] == "--ro-bind" && values[2] == "/usr")
            .unwrap();
        assert!(Path::new(retained_usr[1]).starts_with(runtime.root.path()));
        assert!(
            !args
                .windows(3)
                .any(|values| values[0].starts_with("--ro-bind")
                    && matches!(values[1], "/usr" | "/etc/ld.so.cache"))
        );
        assert!(!args.contains(&"/etc/alternatives"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn archive_mode_removes_process_and_entropy_files_without_exposing_host_devices() {
        assert_archive_mode_namespace(
            context(Vec::new()).with_execution_mode(DependencyExecutionMode::Rlib),
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn canonical_archive_mode_removes_process_and_entropy_files_and_outer_driver_mounts() {
        let metadata = canonical_context();
        let archive = DependencyExecContext::new_canonical_cargo(
            DependencyExecutionMode::Rlib,
            metadata.source_root,
            metadata.cwd,
            metadata.out_dir,
            metadata.dependency_dirs,
            metadata.loader_dirs,
            metadata.artifact_roots,
            metadata.env,
            metadata.runtime_cohort_sha256,
        )
        .unwrap();
        assert_eq!(archive.version(), "canonical-dependency-exec-v4");
        assert_archive_mode_namespace(archive);
    }

    #[cfg(target_os = "linux")]
    fn assert_archive_mode_namespace(mut context: DependencyExecContext) {
        let mut spec = context
            .namespace(
                Path::new("/private/source"),
                Path::new("/private/toolchain"),
                Path::new("/private/output"),
                Path::new("/private/empty"),
                Path::new("/private/home"),
            )
            .unwrap();
        let fixture = RuntimeFixture::prepare(&mut context, &mut spec);
        let support = fixture_support(context.execution_mode());
        let launch = build_dependency_argv(
            &context,
            &spec,
            &fixture.runtime,
            &support,
            context.compiler(),
            &[],
        )
        .unwrap();
        let argv: Vec<_> = launch
            .argv
            .iter()
            .map(|arg| arg.to_str().unwrap())
            .collect();
        assert_eq!(context.execution_mode().as_str(), "rlib");
        assert!(!launch.boundary.proc_private);
        assert!(launch.boundary.mounts_closed_view && launch.boundary.net_isolated);
        assert!(!argv.contains(&"--proc") && !argv.contains(&"--dev"));
        assert!(!argv.iter().any(|arg| arg.starts_with("/proc")));
        assert!(
            argv.windows(3)
                .any(|row| row == ["--dev-bind", "/dev/null", "/dev/null"])
        );
        assert!(
            !argv.windows(3).any(
                |row| matches!(row[0], "--bind" | "--ro-bind" | "--dev-bind") && row[1] == "/dev"
            )
        );
        if context.canonical_cargo() {
            for visible in [
                layout::WORKSPACE,
                layout::CARGO_HOME,
                "/__rabs/home/control",
            ] {
                assert!(!argv.windows(3).any(|row| {
                    matches!(row[0], "--bind" | "--ro-bind" | "--dev-bind") && row[2] == visible
                }));
                let mut extra = spec.clone();
                extra
                    .ro_binds
                    .push(Bind::new("/private/outer-driver", visible));
                assert!(
                    build_dependency_argv(
                        &context,
                        &extra,
                        &fixture.runtime,
                        &support,
                        context.compiler(),
                        &[],
                    )
                    .is_err()
                );
            }
        }

        // The separately negotiated metadata mode preserves its established
        // execution semantics; the archive policy must not quietly replace it.
        let metadata = context.with_execution_mode(DependencyExecutionMode::Metadata);
        assert!(matches!(
            build_dependency_argv(
                &metadata,
                &spec,
                &fixture.runtime,
                &support,
                metadata.compiler(),
                &[],
            ),
            Err(IsolationError::InvalidSpec { .. })
        ));
        let support = fixture_support(DependencyExecutionMode::Metadata);
        let launch = build_dependency_argv(
            &metadata,
            &spec,
            &fixture.runtime,
            &support,
            metadata.compiler(),
            &[],
        )
        .unwrap();
        assert!(launch.boundary.proc_private);
        assert!(
            launch
                .argv
                .windows(2)
                .any(|row| row[0] == "--proc" && row[1] == "/proc")
        );
        assert!(
            launch
                .argv
                .windows(2)
                .any(|row| row[0] == "--dev" && row[1] == "/dev")
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn retained_runtime_requires_the_exact_cohort_and_disjoint_writable_backings() {
        let mut context = context(Vec::new());
        let mut spec = context
            .namespace(
                Path::new("/private/source"),
                Path::new("/private/toolchain"),
                Path::new("/private/output"),
                Path::new("/private/empty"),
                Path::new("/private/home"),
            )
            .unwrap();
        let fixture = RuntimeFixture::prepare(&mut context, &mut spec);
        let support = fixture_support(context.execution_mode());
        let launch = build_dependency_argv(
            &context,
            &spec,
            &fixture.runtime,
            &support,
            context.compiler(),
            &[],
        )
        .unwrap();
        let retained_usr = launch
            .argv
            .windows(3)
            .find(|values| values[0] == "--ro-bind" && values[2] == "/usr")
            .map(|values| PathBuf::from(&values[1]))
            .unwrap();
        let mut mismatched = context.clone();
        mismatched.runtime_cohort_sha256[31] ^= 1;
        assert!(
            build_dependency_argv(
                &mismatched,
                &spec,
                &fixture.runtime,
                &support,
                mismatched.compiler(),
                &[]
            )
            .unwrap_err()
            .to_string()
            .contains("differs from the negotiated cohort")
        );
        let alias = fixture.root.path().join("runtime-alias");
        std::os::unix::fs::symlink(&retained_usr, &alias).unwrap();
        for backing in [
            retained_usr.clone(),
            retained_usr.parent().unwrap().to_path_buf(),
            fixture.root.path().to_path_buf(),
            alias,
        ] {
            let mut invalid = spec.clone();
            invalid.rw_binds[0].backing = backing;
            assert!(
                build_dependency_argv(
                    &context,
                    &invalid,
                    &fixture.runtime,
                    &support,
                    context.compiler(),
                    &[]
                )
                .unwrap_err()
                .to_string()
                .contains("retained dependency runtime cannot be mounted")
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires a Linux host permitting the full bubblewrap namespace"]
    fn selected_elf_runtime_executes_with_private_outputs_and_without_broad_host_usr() {
        let support = DependencyIsolationSupport::probe(DependencyExecutionMode::Metadata);
        assert!(
            support.is_supported(),
            "full namespace unavailable: {:?}",
            support.missing()
        );
        let mut context = context(Vec::new());
        let empty = tempfile::tempdir().unwrap();
        context.prepare_empty_backings(empty.path()).unwrap();
        let mut spec = context
            .namespace(
                Path::new("/private/source"),
                Path::new("/private/toolchain"),
                Path::new("/private/output"),
                empty.path(),
                Path::new("/private/home"),
            )
            .unwrap();
        let fixture =
            RuntimeFixture::prepare_with_program(&mut context, &mut spec, Path::new("/bin/sh"));
        let source = fixture.root.path().join("source");
        std::fs::create_dir_all(source.join("src")).unwrap();
        spec.ro_binds
            .iter_mut()
            .find(|bind| bind.visible == Path::new(context.source_root()))
            .unwrap()
            .backing = source;
        // Shell builtins inspect the view; no second host executable is added
        // to the retained runtime. Successful launch itself loads its real ELF
        // interpreter and selected libc through the captured topology.
        let script = concat!(
            "set -eu; ",
            "test ! -e /usr/bin/env; ",
            "test ! -e /usr/share; ",
            "test ! -e /etc/alternatives; ",
            "test ! -e /etc/ld.so.preload; ",
            "test -d /proc/self; test -e /dev/null; ",
            "if (printf forbidden > /usr/rabs-write-probe) 2>/dev/null; ",
            "then exit 41; fi; ",
            "printf retained-runtime-ok > /work/build/deps/proof"
        );
        let launch = build_dependency_argv(
            &context,
            &spec,
            &fixture.runtime,
            &support,
            context.compiler(),
            &["-c".to_owned(), script.to_owned()],
        )
        .unwrap();
        let output = crate::canonical_namespace::command_for(&launch)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "selected ELF namespace failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            std::fs::read(fixture.root.path().join("writable-0/proof")).unwrap(),
            b"retained-runtime-ok"
        );
        fixture.runtime.verify(|| false).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires bubblewrap and RABS_TEST_TOOLCHAIN_ROOT naming an installed rustc toolchain"]
    fn real_rustc_emits_metadata_with_only_the_selected_retained_elf_runtime() {
        let toolchain = PathBuf::from(
            std::env::var_os("RABS_TEST_TOOLCHAIN_ROOT")
                .expect("set RABS_TEST_TOOLCHAIN_ROOT to the installed toolchain root"),
        );
        assert!(toolchain.is_absolute());
        let owner = tempfile::tempdir().unwrap();
        let source = owner.path().join("source");
        let output = owner.path().join("output");
        for directory in [&source, &output] {
            std::fs::create_dir(directory).unwrap();
        }
        std::fs::write(
            source.join("lib.rs"),
            b"pub fn retained_runtime_value() -> String { format!(\"{}\", 42) }\n",
        )
        .unwrap();
        let runtime = crate::runtime_cohort::retain_runtime_cohort(
            &toolchain.join("bin/rustc"),
            &toolchain,
            &[toolchain.join("lib")],
            output.as_path(),
            owner.path(),
            || false,
        )
        .unwrap();
        // This checks real compiler/backend ELF loading and metadata output in
        // a sparse filesystem. It deliberately does not assert the full worker
        // PID/proc/network boundary, authenticated delivery, or cache serving.
        let mut argv: Vec<OsString> = [
            "bwrap",
            "--die-with-parent",
            "--unshare-user",
            "--clearenv",
            "--dev",
            "/dev",
            "--tmpfs",
            "/tmp",
        ]
        .map(OsString::from)
        .to_vec();
        runtime
            .append_mounts(&mut argv, std::slice::from_ref(&output))
            .unwrap();
        for (option, backing, visible) in [
            ("--ro-bind", source.as_path(), "/source/package"),
            ("--ro-bind", toolchain.as_path(), "/toolchains/pinned"),
            ("--bind", output.as_path(), "/target/output"),
        ] {
            argv.extend([
                OsString::from(option),
                backing.as_os_str().to_owned(),
                OsString::from(visible),
            ]);
        }
        argv.extend(
            [
                "--setenv",
                "LD_LIBRARY_PATH",
                "/toolchains/pinned/lib",
                "--chdir",
                "/source/package",
                "--",
                "/toolchains/pinned/bin/rustc",
                "lib.rs",
                "--crate-name=retained_runtime_smoke",
                "--crate-type=lib",
                "--emit=metadata,dep-info",
                "--out-dir=/target/output",
            ]
            .map(OsString::from),
        );
        let result = std::process::Command::new(&argv[0])
            .args(&argv[1..])
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "real rustc selected ELF runtime failed: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(
            std::fs::metadata(output.join("libretained_runtime_smoke.rmeta"))
                .unwrap()
                .len()
                > 0
        );
        let dep_info = std::fs::read_to_string(output.join("retained_runtime_smoke.d")).unwrap();
        assert!(dep_info.contains("lib.rs"));
        runtime.verify(|| false).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires bubblewrap and RABS_TEST_TOOLCHAIN_ROOT naming an installed rustc toolchain"]
    fn real_rustc_archive_view_closes_assembler_inputs_missing_from_dep_info() {
        assert_real_archive_view_closes_assembler_inputs(false);
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires the full Metadata bubblewrap namespace with private procfs and RABS_TEST_TOOLCHAIN_ROOT naming an installed rustc toolchain"]
    fn real_workspace_binary_example_and_test_metadata_preserve_exact_empty_outputs() {
        let toolchain = PathBuf::from(
            std::env::var_os("RABS_TEST_TOOLCHAIN_ROOT")
                .expect("set RABS_TEST_TOOLCHAIN_ROOT to the installed toolchain root"),
        );
        assert!(toolchain.is_absolute());
        let support = DependencyIsolationSupport::probe(DependencyExecutionMode::Metadata);
        assert!(support.is_supported(), "{support:?}");
        let owner = tempfile::tempdir().unwrap();
        let source = owner.path().join("bundle/package");
        let output = owner.path().join("outputs");
        let home = owner.path().join("home");
        let empty = owner.path().join("empty");
        let source_directories = [
            "empty",
            "member",
            "member/examples",
            "member/src",
            "member/tests",
        ]
        .map(str::to_owned)
        .to_vec();
        for relative in &source_directories {
            std::fs::create_dir_all(source.join(relative)).unwrap();
        }
        for directory in [&output, &home, &empty] {
            std::fs::create_dir(directory).unwrap();
        }
        std::fs::write(source.join("shared.txt"), "retained workspace input\n").unwrap();
        for relative in [
            "member/src/main.rs",
            "member/examples/demo.rs",
            "member/tests/check.rs",
        ] {
            std::fs::write(
                source.join(relative),
                "const _: &str = env!(\"CARGO_PRIMARY_PACKAGE\");\nconst _: &str = include_str!(\"../../shared.txt\");\n#[cfg(not(test))]\nfn main() {}\n#[test]\nfn metadata_only() { panic!(\"metadata checking must not execute tests\"); }\n",
            )
            .unwrap();
        }
        std::fs::write(
            source.join("member/tests/custom.rs"),
            "const _: &str = env!(\"CARGO_PRIMARY_PACKAGE\");\nconst _: &str = include_str!(\"../../shared.txt\");\nfn main() { panic!(\"metadata checking must not execute custom harnesses\"); }\n",
        )
        .unwrap();
        let runtime = crate::runtime_cohort::retain_runtime_cohort(
            &toolchain.join("bin/rustc"),
            &toolchain,
            &[toolchain.join("lib")],
            &output,
            owner.path(),
            || false,
        )
        .unwrap();
        for (name, relative, crate_type, test, custom_harness) in [
            (
                "workspace_bin",
                "member/src/main.rs",
                Some("bin"),
                false,
                false,
            ),
            (
                "workspace_example",
                "member/examples/demo.rs",
                Some("bin"),
                false,
                false,
            ),
            (
                "workspace_integration",
                "member/tests/check.rs",
                None,
                true,
                false,
            ),
            (
                "workspace_unit",
                "member/src/main.rs",
                Some("lib"),
                true,
                false,
            ),
            (
                "workspace_custom",
                "member/tests/custom.rs",
                None,
                false,
                true,
            ),
        ] {
            let destination = output.join(name);
            std::fs::create_dir(&destination).unwrap();
            let mut context = workspace_context(
                DependencyExecutionMode::Metadata,
                source_directories.clone(),
                None,
                Vec::new(),
                Vec::new(),
            )
            .unwrap();
            context.runtime_cohort_sha256 = runtime.cohort().bytes;
            context.prepare_empty_backings(&empty).unwrap();
            let spec = context
                .namespace(&source, &toolchain, &destination, &empty, &home)
                .unwrap();
            let mut args = vec![
                relative.into(),
                format!("--crate-name={name}"),
                "--edition=2024".into(),
                "--emit=dep-info,metadata".into(),
                "--error-format=json".into(),
                "-Cextra-filename=-retained".into(),
                format!("--out-dir={}", context.out_dir()),
            ];
            if let Some(kind) = crate_type {
                args.push(format!("--crate-type={kind}"));
            }
            if test {
                args.push("--test".into());
            }
            if custom_harness {
                args.push("--cfg=test".into());
            }
            let launch = build_workspace_dependency_argv(
                &context,
                &spec,
                &runtime,
                &support,
                context.compiler(),
                &args,
                &source,
            )
            .unwrap();
            assert!(launch.boundary.proc_private);
            assert!(launch.boundary.net_isolated && launch.boundary.mounts_closed_view);
            let result = crate::canonical_namespace::command_for(&launch)
                .output()
                .unwrap();
            assert!(
                result.status.success(),
                "{name}: {}",
                String::from_utf8_lossy(&result.stderr)
            );
            let metadata = format!("lib{name}-retained.rmeta");
            let dep_info = format!("{name}-retained.d");
            let names: BTreeSet<_> = std::fs::read_dir(&destination)
                .unwrap()
                .map(|entry| entry.unwrap().file_name().into_string().unwrap())
                .collect();
            assert_eq!(names, BTreeSet::from([metadata.clone(), dep_info.clone()]));
            assert_eq!(
                std::fs::metadata(destination.join(metadata)).unwrap().len(),
                0
            );
            let dep_info = std::fs::read_to_string(destination.join(dep_info)).unwrap();
            assert!(dep_info.contains(relative) && dep_info.contains("shared.txt"));
            assert!(
                !destination.join(name).exists(),
                "checking must not link a binary"
            );
            runtime.verify(|| false).unwrap();
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires bubblewrap and RABS_TEST_TOOLCHAIN_ROOT naming an installed rustc toolchain"]
    fn real_canonical_rustc_archive_view_closes_assembler_inputs_missing_from_dep_info() {
        assert_real_archive_view_closes_assembler_inputs(true);
    }

    #[cfg(target_os = "linux")]
    fn assert_real_archive_view_closes_assembler_inputs(canonical: bool) {
        let toolchain = PathBuf::from(
            std::env::var_os("RABS_TEST_TOOLCHAIN_ROOT")
                .expect("set RABS_TEST_TOOLCHAIN_ROOT to the installed toolchain root"),
        );
        assert!(toolchain.is_absolute());
        let support = DependencyIsolationSupport::probe(DependencyExecutionMode::Rlib);
        assert!(support.is_supported(), "{support:?}");
        let owner = tempfile::tempdir().unwrap();
        let source = owner.path().join("source");
        let output = owner.path().join("output");
        let home = owner.path().join("home");
        let empty = owner.path().join("empty");
        for directory in [&source, &output, &home, &empty] {
            std::fs::create_dir(directory).unwrap();
        }
        let marker = b"rabs-complete-keyed-assembler-input";
        std::fs::write(source.join("payload.bin"), marker).unwrap();
        let host_only = owner.path().join("host-only.bin");
        std::fs::write(&host_only, b"unkeyed-host-input").unwrap();
        let runtime = crate::runtime_cohort::retain_runtime_cohort(
            &toolchain.join("bin/rustc"),
            &toolchain,
            &[toolchain.join("lib")],
            &output,
            owner.path(),
            || false,
        )
        .unwrap();
        let context = if canonical {
            DependencyExecContext::new_canonical_cargo(
                DependencyExecutionMode::Rlib,
                CANONICAL_SOURCE.into(),
                CANONICAL_SOURCE.into(),
                CANONICAL_OUTPUT.into(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                vec![
                    ("HOME".into(), layout::HOME.into()),
                    ("CARGO_HOME".into(), layout::CARGO_HOME.into()),
                    ("CARGO_MANIFEST_DIR".into(), CANONICAL_SOURCE.into()),
                    ("LD_LIBRARY_PATH".into(), "/__rabs/toolchain/lib".into()),
                ],
                runtime.cohort().bytes,
            )
            .unwrap()
        } else {
            DependencyExecContext::new(
                "/source/package".into(),
                "/source/package".into(),
                "/toolchains/pinned".into(),
                "/toolchains/pinned/bin/rustc".into(),
                "/target/output".into(),
                Vec::new(),
                vec![("LD_LIBRARY_PATH".into(), "/toolchains/pinned/lib".into())],
                runtime.cohort().bytes,
            )
            .unwrap()
            .with_execution_mode(DependencyExecutionMode::Rlib)
        };
        context.prepare_empty_backings(&empty).unwrap();
        let spec = context
            .namespace(&source, &toolchain, &output, &empty, &home)
            .unwrap();
        let compile = |path: &str, name: &str| {
            // LLVM's assembler reads .incbin itself. Rustc's dep-info does not
            // list this file, so success must depend on the enforced view.
            std::fs::write(
                source.join("lib.rs"),
                format!(
                    "core::arch::global_asm!(r#\".pushsection .rodata.rabs,\\\"a\\\"\n.incbin \\\"{path}\\\"\n.popsection\"#);\npub fn value() -> u64 {{ 42 }}\n"
                ).replace("\\\"", "\""),
            )
            .unwrap();
            let args = vec![
                "lib.rs".into(),
                format!("--crate-name={name}"),
                "--edition=2024".into(),
                "--crate-type=rlib".into(),
                "--emit=dep-info,metadata,link".into(),
                format!("--out-dir={}", context.out_dir()),
                "-Cembed-bitcode=no".into(),
            ];
            let launch = build_dependency_argv(
                &context,
                &spec,
                &runtime,
                &support,
                context.compiler(),
                &args,
            )
            .unwrap();
            crate::canonical_namespace::command_for(&launch)
                .output()
                .unwrap()
        };
        let result = compile(
            &format!("{}/payload.bin", context.source_root()),
            "closed_archive",
        );
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let archive = std::fs::read(output.join("libclosed_archive.rlib")).unwrap();
        assert!(archive.starts_with(b"!<arch>\n"));
        assert!(archive.windows(marker.len()).any(|window| window == marker));
        assert!(
            !std::fs::read_to_string(output.join("closed_archive.d"))
                .unwrap()
                .contains("payload.bin")
        );
        assert!(
            std::fs::metadata(output.join("libclosed_archive.rmeta"))
                .unwrap()
                .len()
                > 0
        );
        for (index, denied) in [
            host_only.to_str().unwrap(),
            "/proc/version",
            "/proc/sys/kernel/random/uuid",
            "/dev/urandom",
        ]
        .into_iter()
        .enumerate()
        {
            let name = format!("unclosed_archive_{index}");
            let result = compile(denied, &name);
            assert!(
                !result.status.success(),
                "unkeyed assembler read succeeded: {denied}"
            );
            assert!(String::from_utf8_lossy(&result.stderr).contains("error"));
            assert!(!output.join(format!("lib{name}.rlib")).exists());
        }
        runtime.verify(|| false).unwrap();
    }

    /// Use the actual production archive view, including the retained sparse
    /// runtime, without requiring the broader Cargo namespace's private procfs.
    /// Native objects must come from the captured tree; a thin archive cannot
    /// read an original host object merely because that object still exists.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires bubblewrap, cc, GNU ar, and RABS_TEST_TOOLCHAIN_ROOT naming an installed rustc toolchain"]
    fn real_canonical_archive_bundles_retained_native_inputs_and_denies_thin_escape() {
        assert_real_native_archive_view(false);
    }

    /// Exercise a downstream package with no OUT_DIR, whose native search paths
    /// name two separately retained dependency build-script trees.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires bubblewrap, cc, GNU ar, and RABS_TEST_TOOLCHAIN_ROOT naming an installed rustc toolchain"]
    fn real_canonical_archive_bundles_propagated_native_roots_and_denies_thin_escape() {
        assert_real_native_archive_view(true);
    }

    #[cfg(target_os = "linux")]
    fn assert_real_native_archive_view(foreign: bool) {
        use std::process::Command;

        let toolchain = PathBuf::from(
            std::env::var_os("RABS_TEST_TOOLCHAIN_ROOT")
                .expect("set RABS_TEST_TOOLCHAIN_ROOT to the installed toolchain root"),
        );
        assert!(toolchain.is_absolute());
        let support = DependencyIsolationSupport::probe(DependencyExecutionMode::Rlib);
        assert!(support.is_supported(), "{support:?}");
        for workspace in [false, true] {
            let owner = tempfile::tempdir().unwrap();
            let source = owner.path().join("bundle/package");
            let generated = owner.path().join(if foreign {
                "bundle/native/0000/native"
            } else {
                "bundle/generated/native"
            });
            let thin_generated = if foreign {
                owner.path().join("bundle/native/0001/native")
            } else {
                generated.clone()
            };
            let original = owner.path().join("original");
            let output = owner.path().join("output");
            let home = owner.path().join("home");
            let empty = owner.path().join("empty");
            for directory in [&source, &generated, &original, &output, &home, &empty] {
                std::fs::create_dir_all(directory).unwrap();
            }
            std::fs::create_dir_all(&thin_generated).unwrap();
            let checked = |command: &mut Command| {
                let result = command.output().unwrap();
                assert!(
                    result.status.success(),
                    "{command:?}: {}",
                    String::from_utf8_lossy(&result.stderr)
                );
                result
            };
            std::fs::write(
                original.join("answer.c"),
                "unsigned int rabs_native_answer(void) { return 37; }\n",
            )
            .unwrap();
            checked(
                Command::new("cc")
                    .args(["-c", "-fPIC", "-o"])
                    .arg(original.join("answer.o"))
                    .arg(original.join("answer.c")),
            );
            checked(
                Command::new("ar")
                    .arg("crsD")
                    .arg(original.join("libretained.a"))
                    .arg(original.join("answer.o")),
            );
            checked(
                Command::new("ar")
                    .arg("crsTD")
                    .arg(original.join("libthin.a"))
                    .arg(original.join("answer.o")),
            );
            assert!(
                std::fs::read(original.join("libthin.a"))
                    .unwrap()
                    .starts_with(b"!<thin>\n"),
                "the escape case must be an actual thin archive"
            );
            for (name, destination) in [
                ("libretained.a", &generated),
                ("libthin.a", &thin_generated),
            ] {
                std::fs::copy(original.join(name), destination.join(name)).unwrap();
            }
            // Corrupt only the original archive after the private snapshot exists.
            // The original object deliberately remains readable on the host for
            // the thin-archive escape oracle below.
            std::fs::write(original.join("libretained.a"), b"not an archive").unwrap();
            std::fs::write(
            source.join("lib.rs"),
            "unsafe extern \"C\" { fn rabs_native_answer() -> u32; }\npub fn answer() -> u32 { unsafe { rabs_native_answer() } }\n",
        )
        .unwrap();
            let control = owner.path().join("host-control");
            std::fs::create_dir(&control).unwrap();
            // Prove this compiler actually accepts the same thin archive when
            // its original object is visible. A generic unsupported-archive error
            // must never stand in for successful namespace confinement.
            checked(
                Command::new(toolchain.join("bin/rustc"))
                    .arg(source.join("lib.rs"))
                    .args([
                        "--crate-name=thin_control",
                        "--edition=2024",
                        "--crate-type=rlib",
                        "--emit=dep-info,metadata,link",
                        "-lstatic=thin",
                    ])
                    .arg("--out-dir")
                    .arg(&control)
                    .arg(format!("-Lnative={}", original.display())),
            );
            assert!(control.join("libthin_control.rlib").is_file());
            let runtime = crate::runtime_cohort::retain_runtime_cohort(
                &toolchain.join("bin/rustc"),
                &toolchain,
                &[toolchain.join("lib")],
                &output,
                owner.path(),
                || false,
            )
            .unwrap();
            let generated_root = "/__rabs/out/cargo/debug/build/native-hash/out";
            let foreign_second_root = "/__rabs/out/cargo/debug/build/native-z-hash/out";
            let own_root = (!foreign).then(|| generated_root.to_owned());
            let own_directories = if foreign {
                Vec::new()
            } else {
                vec!["native".into()]
            };
            let package_root = if workspace {
                layout::WORKSPACE
            } else {
                CANONICAL_SOURCE
            };
            let mut env = vec![
                ("HOME".into(), layout::HOME.into()),
                ("CARGO_HOME".into(), layout::CARGO_HOME.into()),
                ("CARGO_MANIFEST_DIR".into(), package_root.into()),
                ("CARGO_PKG_NAME".into(), "native_fixture".into()),
                ("LD_LIBRARY_PATH".into(), "/__rabs/toolchain/lib".into()),
            ];
            if let Some(root) = &own_root {
                env.push(("OUT_DIR".into(), root.clone()));
            }
            let context = if workspace {
                env.push(("CARGO_PRIMARY_PACKAGE".into(), "1".into()));
                DependencyExecContext::new_canonical_workspace_execution(
                    DependencyExecutionMode::Rlib,
                    layout::WORKSPACE.into(),
                    CANONICAL_OUTPUT.into(),
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                    own_root,
                    Vec::new(),
                    own_directories,
                    env,
                    runtime.cohort().bytes,
                )
                .unwrap()
            } else {
                DependencyExecContext::new_canonical_cargo_with_generated(
                    DependencyExecutionMode::Rlib,
                    CANONICAL_SOURCE.into(),
                    CANONICAL_SOURCE.into(),
                    CANONICAL_OUTPUT.into(),
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                    own_root,
                    env,
                    runtime.cohort().bytes,
                )
                .unwrap()
                .with_generated_directories(own_directories)
                .unwrap()
            };
            let context = if foreign {
                assert!(context.generated_root().is_none());
                context
                    .with_native_roots(vec![
                        DependencyNativeRoot {
                            path: generated_root.into(),
                            prefix: "native/0000".into(),
                            directories: vec!["native".into()],
                        },
                        DependencyNativeRoot {
                            path: foreign_second_root.into(),
                            prefix: "native/0001".into(),
                            directories: vec!["native".into()],
                        },
                    ])
                    .unwrap()
            } else {
                context
            };
            assert_eq!(context.workspace_execution_only(), workspace);
            context.prepare_empty_backings(&empty).unwrap();
            let spec = context
                .namespace(&source, &toolchain, &output, &empty, &home)
                .unwrap();
            let compile = |library: &str, name: &str| {
                let mut args = vec![
                    "lib.rs".into(),
                    format!("--crate-name={name}"),
                    "--edition=2024".into(),
                    "--crate-type=rlib".into(),
                    "--emit=dep-info,metadata,link".into(),
                    format!("--out-dir={}", context.out_dir()),
                    format!("-Lnative={generated_root}/native"),
                    format!("-lstatic={library}"),
                ];
                if foreign {
                    args.push(format!("-Lnative={foreign_second_root}/native"));
                }
                let launch = if workspace {
                    build_workspace_dependency_argv(
                        &context,
                        &spec,
                        &runtime,
                        &support,
                        context.compiler(),
                        &args,
                        &source,
                    )
                } else {
                    build_dependency_argv(
                        &context,
                        &spec,
                        &runtime,
                        &support,
                        context.compiler(),
                        &args,
                    )
                }
                .unwrap();
                crate::canonical_namespace::command_for(&launch)
                    .output()
                    .unwrap()
            };
            let built = compile("retained", "native_bridge");
            assert!(
                built.status.success(),
                "{}",
                String::from_utf8_lossy(&built.stderr)
            );
            assert!(
                !std::fs::read_to_string(output.join("native_bridge.d"))
                    .unwrap()
                    .contains("libretained.a"),
                "the archive is a real compiler input absent from dep-info"
            );
            let main = owner.path().join("main.rs");
            std::fs::write(
            &main,
            "fn main() { assert_eq!(native_bridge::answer(), 37); println!(\"{}\", native_bridge::answer()); }\n",
        )
        .unwrap();
            let binary = owner.path().join("linked-native");
            checked(
                Command::new(toolchain.join("bin/rustc"))
                    .arg(&main)
                    .arg("--edition=2024")
                    .arg("--extern")
                    .arg(format!(
                        "native_bridge={}",
                        output.join("libnative_bridge.rlib").display()
                    ))
                    .arg("-o")
                    .arg(&binary),
            );
            assert_eq!(checked(&mut Command::new(&binary)).stdout, b"37\n");
            let denied = compile("thin", "native_escape");
            assert!(
                !denied.status.success(),
                "thin archive unexpectedly read the unmounted original host object"
            );
            assert!(String::from_utf8_lossy(&denied.stderr).contains("error"));
            assert!(!output.join("libnative_escape.rlib").exists());
            runtime.verify(|| false).unwrap();
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn retained_candidate_roots_bind_first_use_prefixes_without_reordering_inputs() {
        let directories = vec!["/target/z-first".to_owned(), "/target/a-second".to_owned()];
        let roots = vec![
            DependencyArtifactRoot {
                path: directories[0].clone(),
                prefix: "dependencies/0000".to_owned(),
            },
            DependencyArtifactRoot {
                path: directories[1].clone(),
                prefix: "dependencies/0001".to_owned(),
            },
        ];
        let make = |artifact_roots| {
            DependencyExecContext::new_with_artifacts(
                "/source/package".to_owned(),
                "/source/package".to_owned(),
                "/toolchains/pinned".to_owned(),
                "/toolchains/pinned/bin/rustc".to_owned(),
                "/target/output".to_owned(),
                directories.clone(),
                vec!["/target".to_owned()],
                artifact_roots,
                Vec::new(),
                [7; 32],
            )
        };
        let mut context = make(roots.clone()).unwrap();
        assert_eq!(context.dependency_dirs(), directories.as_slice());
        assert_eq!(context.artifact_roots()[0], roots[1]);
        assert_eq!(context.artifact_roots()[1], roots[0]);
        let empty = tempfile::tempdir().unwrap();
        context.prepare_empty_backings(empty.path()).unwrap();
        for child in ["z-first", "a-second", "output"] {
            assert!(empty.path().join("search-0000").join(child).is_dir());
        }
        let mut spec = context
            .namespace(
                Path::new("/private/bundle/package"),
                Path::new("/private/toolchain"),
                Path::new("/private/output"),
                empty.path(),
                Path::new("/private/home"),
            )
            .unwrap();
        let runtime = RuntimeFixture::prepare(&mut context, &mut spec);
        for root in &roots {
            assert!(spec.ro_binds.iter().any(|bind| {
                bind.visible == Path::new(&root.path)
                    && bind.backing == Path::new("/private/bundle").join(&root.prefix)
            }));
            assert!(
                !spec
                    .rw_binds
                    .iter()
                    .any(|bind| { overlaps(&bind.visible, Path::new(&root.path)) })
            );
        }
        let support = fixture_support(context.execution_mode());
        build_dependency_argv(
            &context,
            &spec,
            &runtime.runtime,
            &support,
            context.compiler(),
            &[],
        )
        .unwrap();
        for invalid in [
            vec![DependencyArtifactRoot {
                path: directories[0].clone(),
                prefix: "dependencies/0001".to_owned(),
            }],
            vec![DependencyArtifactRoot {
                path: "/target/unowned".to_owned(),
                prefix: "dependencies/0000".to_owned(),
            }],
            vec![DependencyArtifactRoot {
                path: directories[0].clone(),
                prefix: "dependencies/../package".to_owned(),
            }],
            vec![roots[0].clone(), roots[0].clone()],
        ] {
            assert!(make(invalid).is_err());
        }
        let shared = DependencyExecContext::new_with_artifacts(
            "/source/package".to_owned(),
            "/source/package".to_owned(),
            "/toolchains/pinned".to_owned(),
            "/toolchains/pinned/bin/rustc".to_owned(),
            "/target/output".to_owned(),
            vec!["/target/output".to_owned()],
            Vec::new(),
            vec![DependencyArtifactRoot {
                path: "/target/output".to_owned(),
                prefix: "dependencies/0000".to_owned(),
            }],
            Vec::new(),
            [7; 32],
        )
        .unwrap();
        assert_eq!(shared.artifact_roots()[0].path, shared.out_dir());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn shared_output_file_binds_follow_the_writable_root_and_refuse_other_shapes() {
        let base = context(Vec::new());
        let mut context = DependencyExecContext::new_with_artifacts(
            base.source_root,
            base.cwd,
            base.toolchain_root,
            base.compiler,
            base.out_dir.clone(),
            base.dependency_dirs,
            vec!["/work/build".to_owned()],
            vec![DependencyArtifactRoot {
                path: base.out_dir,
                prefix: "dependencies/0000".to_owned(),
            }],
            Vec::new(),
            [7; 32],
        )
        .unwrap();
        let mut spec = context
            .namespace(
                Path::new("/private/bundle/package"),
                Path::new("/private/toolchain"),
                Path::new("/private/output"),
                Path::new("/private/empty"),
                Path::new("/private/home"),
            )
            .unwrap();
        let runtime = RuntimeFixture::prepare(&mut context, &mut spec);
        assert!(
            spec.ro_binds
                .iter()
                .all(|bind| { bind.visible != Path::new(context.out_dir()) })
        );
        let support = fixture_support(context.execution_mode());
        assert!(
            build_dependency_argv(
                &context,
                &spec,
                &runtime.runtime,
                &support,
                context.compiler(),
                &[]
            )
            .is_err()
        );
        for name in ["libz.rmeta", "liba.rlib"] {
            spec.ro_binds.push(Bind::new(
                Path::new("/private/bundle/dependencies/0000").join(name),
                Path::new(context.out_dir()).join(name),
            ));
        }
        let launch = build_dependency_argv(
            &context,
            &spec,
            &runtime.runtime,
            &support,
            context.compiler(),
            &[],
        )
        .unwrap();
        let argv: Vec<_> = launch
            .argv
            .iter()
            .map(|arg| arg.to_str().unwrap())
            .collect();
        let parent = argv
            .windows(3)
            .position(|args| args[0] == "--ro-bind" && args[2] == "/work/build")
            .unwrap();
        let writable = argv
            .windows(3)
            .position(|args| args[0] == "--bind" && args[2] == context.out_dir())
            .unwrap();
        let archive = argv
            .windows(3)
            .position(|args| args[0] == "--ro-bind" && args[2] == "/work/build/deps/liba.rlib")
            .unwrap();
        let metadata = argv
            .windows(3)
            .position(|args| args[0] == "--ro-bind" && args[2] == "/work/build/deps/libz.rmeta")
            .unwrap();
        assert!(parent < writable && writable < archive && archive < metadata);
        assert!(launch.boundary.proc_private && launch.boundary.net_isolated);

        for bind in [
            Bind::new("/private/bundle/dependencies/0000", context.out_dir()),
            Bind::new(
                "/private/bundle/dependencies/0000/libleaf.rmeta",
                "/work/build/deps/nested/libleaf.rmeta",
            ),
            Bind::new(
                "/private/bundle/dependencies/0000/libmacro.so",
                "/work/build/deps/libmacro.so",
            ),
            Bind::new(
                "/private/bundle/dependencies/0000/leaf.rmeta",
                "/work/build/deps/leaf.rmeta",
            ),
            Bind::new(
                "/private/bundle/dependencies/0001/libother.rmeta",
                "/work/build/deps/libother.rmeta",
            ),
            Bind::new(
                "/private/bundle/dependencies/0000/liba.rlib",
                "/work/build/deps/liba.rlib",
            ),
        ] {
            let mut invalid = spec.clone();
            invalid.ro_binds.push(bind);
            assert!(
                build_dependency_argv(
                    &context,
                    &invalid,
                    &runtime.runtime,
                    &support,
                    context.compiler(),
                    &[]
                )
                .is_err()
            );
        }
        let mut invalid = spec;
        invalid
            .rw_binds
            .push(Bind::new("/private/alias", "/work/build/deps/liba.rlib"));
        assert!(
            build_dependency_argv(
                &context,
                &invalid,
                &runtime.runtime,
                &support,
                context.compiler(),
                &[]
            )
            .is_err()
        );
    }

    #[test]
    fn aliases_cannot_shadow_inputs_runtime_or_each_other() {
        let good = context(Vec::new());
        for out in [
            "/",
            "/usr/output",
            "/etc/output",
            "/__rabs/output",
            good.source_root(),
            "/home/user",
        ] {
            assert!(
                DependencyExecContext::new(
                    good.source_root.clone(),
                    good.cwd.clone(),
                    good.toolchain_root.clone(),
                    good.compiler.clone(),
                    out.into(),
                    Vec::new(),
                    Vec::new(),
                    [7; 32]
                )
                .is_err(),
                "{out}"
            );
        }
        for directory in [
            "/home/user/registry",
            "/work/build/deps/nested",
            "/proc/secret",
            "/work/build/../escape",
        ] {
            assert!(
                DependencyExecContext::new(
                    good.source_root.clone(),
                    good.cwd.clone(),
                    good.toolchain_root.clone(),
                    good.compiler.clone(),
                    good.out_dir.clone(),
                    vec![directory.into()],
                    Vec::new(),
                    [7; 32]
                )
                .is_err(),
                "{directory}"
            );
        }
    }

    #[test]
    fn loader_paths_only_resolve_into_retained_toolchain_or_empty_roots() {
        let context = context(vec![(
            "LD_LIBRARY_PATH".into(),
            "/work/build/deps:/home/user/toolchains/pinned/lib:/work/build/empty".into(),
        )]);
        assert_eq!(
            context
                .loader_search_paths(Path::new("/retained/tc"))
                .unwrap(),
            vec![PathBuf::from("/retained/tc/lib")]
        );
        for (name, value) in [
            ("LD_PRELOAD", "libbad.so"),
            ("GLIBC_TUNABLES", "x"),
            ("LD_LIBRARY_PATH", ":/usr/lib"),
            ("LD_LIBRARY_PATH", "/tmp/unowned"),
        ] {
            assert!(
                DependencyExecContext::new(
                    context.source_root.clone(),
                    context.cwd.clone(),
                    context.toolchain_root.clone(),
                    context.compiler.clone(),
                    context.out_dir.clone(),
                    context.dependency_dirs.clone(),
                    vec![(name.into(), value.into())],
                    [7; 32]
                )
                .is_err()
            );
        }
    }

    #[test]
    fn empty_loader_list_is_preserved_in_every_execution_profile() {
        for base in [
            context(Vec::new()),
            canonical_context(),
            workspace_context(
                DependencyExecutionMode::Metadata,
                workspace_directories(),
                None,
                Vec::new(),
                Vec::new(),
            )
            .unwrap(),
        ] {
            let rebuild = |env| {
                if base.workspace_execution_only() {
                    DependencyExecContext::new_canonical_workspace_execution(
                        base.execution_mode,
                        base.cwd.clone(),
                        base.out_dir.clone(),
                        base.dependency_dirs.clone(),
                        base.loader_dirs.clone(),
                        base.artifact_roots.clone(),
                        base.generated_root.clone(),
                        base.source_directories.clone(),
                        base.generated_directories.clone(),
                        env,
                        base.runtime_cohort_sha256,
                    )
                } else if base.canonical_cargo() {
                    DependencyExecContext::new_canonical_cargo(
                        base.execution_mode,
                        base.source_root.clone(),
                        base.cwd.clone(),
                        base.out_dir.clone(),
                        base.dependency_dirs.clone(),
                        base.loader_dirs.clone(),
                        base.artifact_roots.clone(),
                        env,
                        base.runtime_cohort_sha256,
                    )
                } else {
                    DependencyExecContext::new_with_artifacts(
                        base.source_root.clone(),
                        base.cwd.clone(),
                        base.toolchain_root.clone(),
                        base.compiler.clone(),
                        base.out_dir.clone(),
                        base.dependency_dirs.clone(),
                        base.loader_dirs.clone(),
                        base.artifact_roots.clone(),
                        env,
                        base.runtime_cohort_sha256,
                    )
                }
            };
            let mut absent_env = base.env.clone();
            absent_env.retain(|(name, _)| name != "LD_LIBRARY_PATH");
            let absent = rebuild(absent_env.clone()).unwrap();
            assert!(
                absent
                    .loader_search_paths(Path::new("/retained/toolchain"))
                    .unwrap()
                    .is_empty()
            );
            let mut empty_env = absent_env;
            empty_env.push(("LD_LIBRARY_PATH".into(), String::new()));
            let empty = rebuild(empty_env.clone()).unwrap();
            assert_eq!(empty.version(), base.version());
            assert!(
                empty
                    .env()
                    .contains(&("LD_LIBRARY_PATH".into(), String::new()))
            );
            assert_ne!(empty.env(), absent.env());
            assert!(
                empty
                    .loader_search_paths(Path::new("/retained/toolchain"))
                    .unwrap()
                    .is_empty()
            );
            for value in [
                ":".to_owned(),
                format!(":{}/lib", base.toolchain_root),
                format!("{}/lib:", base.toolchain_root),
                format!(
                    "{}/lib::{}/lib/rustlib",
                    base.toolchain_root, base.toolchain_root
                ),
            ] {
                let mut invalid = empty_env.clone();
                invalid
                    .iter_mut()
                    .find(|(name, _)| name == "LD_LIBRARY_PATH")
                    .unwrap()
                    .1 = value.clone();
                assert!(
                    rebuild(invalid).is_err(),
                    "{} must refuse {value:?}",
                    base.version()
                );
            }
            empty_env.push(("LD_PRELOAD".into(), String::new()));
            assert!(
                rebuild(empty_env).is_err(),
                "an empty search list cannot bypass loader-control checks"
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn cargo_loader_parent_has_private_child_mountpoints_before_read_only_bind() {
        let base = context(Vec::new());
        let env = vec![(
            "LD_LIBRARY_PATH".into(),
            "/work/build/deps:/work/build:/work/build/empty:/home/user/toolchains/pinned/lib"
                .into(),
        )];
        assert!(
            DependencyExecContext::new(
                base.source_root.clone(),
                base.cwd.clone(),
                base.toolchain_root.clone(),
                base.compiler.clone(),
                base.out_dir.clone(),
                base.dependency_dirs.clone(),
                env.clone(),
                [7; 32],
            )
            .is_err(),
            "the parent must be explicitly declared"
        );
        let mut context = DependencyExecContext::new_with_loader_dirs(
            base.source_root,
            base.cwd,
            base.toolchain_root,
            base.compiler,
            base.out_dir,
            base.dependency_dirs,
            vec!["/work/build".into(), "/work/build/deps".into()],
            env,
            [7; 32],
        )
        .unwrap();
        assert_eq!(
            context
                .loader_search_paths(Path::new("/retained/toolchain"))
                .unwrap(),
            vec![PathBuf::from("/retained/toolchain/lib")]
        );
        let empty = tempfile::tempdir().unwrap();
        context.prepare_empty_backings(empty.path()).unwrap();
        let mut spec = context
            .namespace(
                Path::new("/private/source"),
                Path::new("/private/toolchain"),
                Path::new("/private/output"),
                empty.path(),
                Path::new("/private/home"),
            )
            .unwrap();
        let runtime = RuntimeFixture::prepare(&mut context, &mut spec);
        let parent = spec
            .ro_binds
            .iter()
            .find(|bind| bind.visible == Path::new("/work/build"))
            .unwrap();
        let children: BTreeSet<_> = std::fs::read_dir(&parent.backing)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(
            children,
            BTreeSet::from([OsString::from("deps"), OsString::from("empty")])
        );
        for child in ["deps", "empty"] {
            assert_eq!(
                std::fs::read_dir(parent.backing.join(child))
                    .unwrap()
                    .count(),
                0
            );
        }
        let search = spec
            .ro_binds
            .iter()
            .find(|bind| bind.visible == Path::new("/work/build/empty"))
            .unwrap();
        assert_ne!(
            search.backing,
            parent.backing.join("empty"),
            "each alias has its own owner subtree"
        );
        assert_eq!(std::fs::read_dir(&search.backing).unwrap().count(), 0);
        let support = fixture_support(context.execution_mode());
        let launch = build_dependency_argv(
            &context,
            &spec,
            &runtime.runtime,
            &support,
            context.compiler(),
            &[],
        )
        .unwrap();
        let argv: Vec<_> = launch
            .argv
            .iter()
            .map(|value| value.to_str().unwrap())
            .collect();
        let parent_at = argv
            .windows(3)
            .position(|args| args[0] == "--ro-bind" && args[2] == "/work/build")
            .unwrap();
        let output_at = argv
            .windows(3)
            .position(|args| args[0] == "--bind" && args[2] == "/work/build/deps")
            .unwrap();
        assert!(
            parent_at < output_at,
            "the writable child is mounted after its read-only parent"
        );
        assert!(
            context.prepare_empty_backings(empty.path()).is_err(),
            "an old backing cannot be reused"
        );
    }

    #[test]
    fn loader_roots_cannot_replace_inputs_or_nest_below_writable_output() {
        let base = context(Vec::new());
        for directory in [
            "/home/user/registry",
            "/home/user/toolchains/pinned/lib",
            "/usr/lib",
            "/work/build/deps/runtime",
            "/work/build/empty/runtime",
            "/work/../unowned",
        ] {
            assert!(
                DependencyExecContext::new_with_loader_dirs(
                    base.source_root.clone(),
                    base.cwd.clone(),
                    base.toolchain_root.clone(),
                    base.compiler.clone(),
                    base.out_dir.clone(),
                    base.dependency_dirs.clone(),
                    vec![directory.into()],
                    Vec::new(),
                    [7; 32],
                )
                .is_err(),
                "{directory}"
            );
        }
        assert!(
            DependencyExecContext::new_with_loader_dirs(
                base.source_root,
                base.cwd,
                base.toolchain_root,
                base.compiler,
                base.out_dir,
                base.dependency_dirs,
                vec!["/work/build".into(), "/work/build".into()],
                Vec::new(),
                [7; 32],
            )
            .is_err()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn post_validation_environment_or_mount_injection_is_refused() {
        let mut context = context(vec![("NUM_JOBS".into(), "2".into())]);
        let mut spec = context
            .namespace(
                Path::new("/private/source"),
                Path::new("/private/toolchain"),
                Path::new("/private/output"),
                Path::new("/private/empty"),
                Path::new("/private/home"),
            )
            .unwrap();
        let runtime = RuntimeFixture::prepare(&mut context, &mut spec);
        let support = fixture_support(context.execution_mode());
        let mut changed = spec.clone();
        changed.env[0].1 = "8".into();
        assert!(
            build_dependency_argv(
                &context,
                &changed,
                &runtime.runtime,
                &support,
                context.compiler(),
                &[]
            )
            .is_err()
        );
        let mut changed = spec;
        changed
            .rw_binds
            .push(Bind::new("/private/other", context.source_root()));
        assert!(
            build_dependency_argv(
                &context,
                &changed,
                &runtime.runtime,
                &support,
                context.compiler(),
                &[]
            )
            .is_err()
        );
    }
}
