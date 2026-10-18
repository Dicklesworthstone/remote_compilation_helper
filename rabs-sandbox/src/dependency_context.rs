//! Path-preserving execution for a closed, immutable dependency compilation.
//!
//! A Cargo wrapper has already exposed the subscriber's paths to rustc. This
//! separate, negotiated context keeps those paths unchanged while binding only
//! retained input bytes and private output. It does not widen the canonical
//! Cargo namespace or grant action-cache publication authority. The host /usr
//! runtime remains explicit and must match the measured runtime cohort before
//! the worker launches this mode.

use crate::canonical_namespace::{
    Bind, CanonicalNamespaceSpec, HostIsolationSupport, IsolationError, NamespaceBoundary,
    NamespaceLaunch, push_binds, push_common_prelude, push_env, push_host_usr, require_support,
};
use crate::layout;
use std::collections::BTreeSet;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// Both peers must explicitly select this capability before dependency execution.
pub const DEPENDENCY_CONTEXT_VERSION: &str = "dependency-exec-v2";
/// Full environments remain bounded by the existing command transport allowance.
pub const MAX_DEPENDENCY_ENV_ENTRIES: usize = 1024;
/// Maximum empty dependency search roots accepted in this initial leaf mode.
pub const MAX_DEPENDENCY_DIRS: usize = 64;

/// Validated original paths and complete environment for one leaf rustc action.
/// Physical source, toolchain, output and jobserver backings never appear here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependencyExecContext {
    source_root: String,
    cwd: String,
    toolchain_root: String,
    compiler: String,
    out_dir: String,
    dependency_dirs: Vec<String>,
    loader_dirs: Vec<String>,
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
        mut dependency_dirs: Vec<String>,
        mut loader_dirs: Vec<String>,
        mut env: Vec<(String, String)>,
        runtime_cohort_sha256: [u8; 32],
    ) -> Result<Self, DependencyContextError> {
        let roots = [&source_root, &toolchain_root, &out_dir];
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
                    "dependency source, toolchain and output roots overlap",
                ));
            }
        }
        if dependency_dirs.len() > MAX_DEPENDENCY_DIRS {
            return Err(invalid("too many dependency search directories"));
        }
        dependency_dirs.sort();
        if dependency_dirs.windows(2).any(|pair| pair[0] == pair[1]) {
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
        env.sort_by(|left, right| left.0.cmp(&right.0));
        let context = Self {
            source_root,
            cwd,
            toolchain_root,
            compiler,
            out_dir,
            dependency_dirs,
            loader_dirs,
            env,
            runtime_cohort_sha256,
        };
        // Validate even when runtime observation is deferred until acquisition.
        context.loader_search_paths(Path::new(&context.toolchain_root))?;
        Ok(context)
    }

    /// Original immutable package/snapshot root.
    pub fn source_root(&self) -> &str {
        &self.source_root
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
    /// Empty dependency search directories, including an optional output alias.
    pub fn dependency_dirs(&self) -> &[String] {
        &self.dependency_dirs
    }
    /// Explicitly observed empty loader roots, including supported parents.
    pub fn loader_dirs(&self) -> &[String] {
        &self.loader_dirs
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
            .filter(|path| *path != self.out_dir.as_str())
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
pub fn build_dependency_argv(
    context: &DependencyExecContext,
    spec: &CanonicalNamespaceSpec,
    support: &HostIsolationSupport,
    program: &str,
    args: &[String],
) -> Result<NamespaceLaunch, IsolationError> {
    require_support(support)?;
    let refuse = || IsolationError::InvalidSpec {
        reason: "dependency namespace differs from its validated context".to_owned(),
    };
    let expected_ro: BTreeSet<_> = [
        context.source_root.as_str(),
        context.toolchain_root.as_str(),
    ]
    .into_iter()
    .chain(context.empty_aliases())
    .map(PathBuf::from)
    .collect();
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
    let mut argv = vec!["bwrap".into()];
    push_common_prelude(&mut argv);
    argv.extend(["--unshare-net", "--hostname", "rabs"].map(OsString::from));
    push_env(&mut argv, &spec.env);
    argv.extend(["--proc", "/proc", "--dev", "/dev"].map(OsString::from));
    push_host_usr(&mut argv);
    argv.extend(["--tmpfs", "/tmp", "--tmpfs", layout::TMP].map(OsString::from));
    let mut ro = spec.ro_binds.clone();
    let mut rw = spec.rw_binds.clone();
    ro.sort_by(|left, right| left.visible.cmp(&right.visible));
    rw.sort_by(|left, right| left.visible.cmp(&right.visible));
    push_binds(&mut argv, &ro, &rw);
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
            host_usr_ro: true,
            tmpfs_tmp: true,
            proc_private: true,
            die_with_parent: true,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn original_paths_environment_and_empty_search_mounts_survive() {
        let context = context(vec![(
            "DEPENDENCY_FLAVOR".into(),
            "hello /home/user/registry/package".into(),
        )]);
        let spec = context
            .namespace(
                Path::new("/private/source"),
                Path::new("/private/toolchain"),
                Path::new("/private/output"),
                Path::new("/private/empty"),
                Path::new("/private/home"),
            )
            .unwrap();
        let support = HostIsolationSupport {
            bubblewrap: Some("test".into()),
            unprivileged_userns: true,
            overlayfs: false,
            cgroup_v2: false,
            landlock: false,
        };
        let args = vec!["src/lib.rs".into(), "--emit=dep-info,metadata".into()];
        let launch =
            build_dependency_argv(&context, &spec, &support, context.compiler(), &args).unwrap();
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
        assert!(
            args.windows(3)
                .any(|values| values == ["--bind", "/private/output", context.out_dir()])
        );
        assert!(args.windows(3).any(|values| values
            == [
                "--setenv",
                "DEPENDENCY_FLAVOR",
                "hello /home/user/registry/package"
            ]));
        assert!(args.ends_with(&[context.compiler(), "src/lib.rs", "--emit=dep-info,metadata"]));
        assert!(
            crate::canonical_namespace::build_canonical_argv(
                &spec,
                &support,
                context.compiler(),
                &[]
            )
            .is_err()
        );
        assert!(launch.boundary.net_isolated);
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
        let context = DependencyExecContext::new_with_loader_dirs(
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
        let spec = context
            .namespace(
                Path::new("/private/source"),
                Path::new("/private/toolchain"),
                Path::new("/private/output"),
                empty.path(),
                Path::new("/private/home"),
            )
            .unwrap();
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
        let support = HostIsolationSupport {
            bubblewrap: Some("test".into()),
            unprivileged_userns: true,
            overlayfs: false,
            cgroup_v2: false,
            landlock: false,
        };
        let launch =
            build_dependency_argv(&context, &spec, &support, context.compiler(), &[]).unwrap();
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

    #[test]
    fn post_validation_environment_or_mount_injection_is_refused() {
        let context = context(vec![("NUM_JOBS".into(), "2".into())]);
        let spec = context
            .namespace(
                Path::new("/private/source"),
                Path::new("/private/toolchain"),
                Path::new("/private/output"),
                Path::new("/private/empty"),
                Path::new("/private/home"),
            )
            .unwrap();
        let support = HostIsolationSupport {
            bubblewrap: Some("test".into()),
            unprivileged_userns: true,
            overlayfs: false,
            cgroup_v2: false,
            landlock: false,
        };
        let mut changed = spec.clone();
        changed.env[0].1 = "8".into();
        assert!(
            build_dependency_argv(&context, &changed, &support, context.compiler(), &[]).is_err()
        );
        let mut changed = spec;
        changed
            .rw_binds
            .push(Bind::new("/private/other", context.source_root()));
        assert!(
            build_dependency_argv(&context, &changed, &support, context.compiler(), &[]).is_err()
        );
    }
}
