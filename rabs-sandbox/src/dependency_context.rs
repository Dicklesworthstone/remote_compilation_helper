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
pub const DEPENDENCY_CONTEXT_VERSION: &str = "dependency-exec-v1";
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
            "/__rabs", "/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc", "/proc",
            "/dev", "/sys", "/run",
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
        mut dependency_dirs: Vec<String>,
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
                return Err(invalid("dependency source, toolchain and output roots overlap"));
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
                    && roots.iter().any(|root| overlaps(Path::new(directory), Path::new(root))))
                || dependency_dirs[index + 1..]
                    .iter()
                    .any(|other| overlaps(Path::new(directory), Path::new(other)))
            {
                return Err(invalid("dependency search directory shadows another mount"));
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
            total = total.saturating_add(name.len()).saturating_add(value.len()).saturating_add(2);
            if value.contains('\0')
                || value.len() > crate::process_context::MAX_COMMAND_ENV_VALUE_BYTES
                || total > crate::process_context::MAX_COMMAND_ENV_BYTES
            {
                return Err(invalid("dependency environment exceeds byte limit or contains NUL"));
            }
            if (name.starts_with("LD_") && name != "LD_LIBRARY_PATH") || name == "GLIBC_TUNABLES" {
                return Err(invalid("dependency environment has an unmodeled loader control"));
            }
        }
        env.sort_by(|left, right| left.0.cmp(&right.0));
        let context = Self {
            source_root, cwd, toolchain_root, compiler, out_dir, dependency_dirs, env,
            runtime_cohort_sha256,
        };
        // Validate even when runtime observation is deferred until acquisition.
        context.loader_search_paths(Path::new(&context.toolchain_root))?;
        Ok(context)
    }

    /// Original immutable package/snapshot root.
    pub fn source_root(&self) -> &str { &self.source_root }
    /// Original compiler working directory.
    pub fn cwd(&self) -> &str { &self.cwd }
    /// Original complete toolchain root.
    pub fn toolchain_root(&self) -> &str { &self.toolchain_root }
    /// Original rustc executable path, rooted in the transferred toolchain.
    pub fn compiler(&self) -> &str { &self.compiler }
    /// Original output directory, backed by this execution's private owner.
    pub fn out_dir(&self) -> &str { &self.out_dir }
    /// Empty dependency search directories, including an optional output alias.
    pub fn dependency_dirs(&self) -> &[String] { &self.dependency_dirs }
    /// Full exact environment before worker-local descriptor coordination.
    pub fn env(&self) -> &[(String, String)] { &self.env }
    /// Measured host runtime cohort required by the keyed execution profile.
    pub fn runtime_cohort_sha256(&self) -> &[u8; 32] { &self.runtime_cohort_sha256 }

    /// Map loader search paths to retained physical toolchain bytes. Empty
    /// output/search roots cannot supply libraries. No caller path is opened.
    pub fn loader_search_paths(&self, toolchain_backing: &Path) -> Result<Vec<PathBuf>, DependencyContextError> {
        let Some((_, value)) = self.env.iter().find(|(name, _)| name == "LD_LIBRARY_PATH") else {
            return Ok(Vec::new());
        };
        let mut paths = Vec::new();
        for directory in value.split(':') {
            if !normalized_absolute(directory) {
                return Err(invalid("dependency loader search path is not an absolute normalized path"));
            }
            if let Ok(relative) = Path::new(directory).strip_prefix(&self.toolchain_root) {
                paths.push(toolchain_backing.join(relative));
            } else if directory != self.out_dir && !self.dependency_dirs.iter().any(|path| path == directory) {
                return Err(invalid("dependency loader search path lies outside owned inputs"));
            }
        }
        Ok(paths)
    }

    /// Construct only the explicitly owned mounts. Callers must retain and
    /// verify these owners through process/drain completion; this type supplies
    /// visible aliases, never physical acquisition authority.
    pub fn namespace(
        &self,
        source_backing: &Path,
        toolchain_backing: &Path,
        output_backing: &Path,
        empty_backing: &Path,
        home_backing: &Path,
    ) -> Result<CanonicalNamespaceSpec, DependencyContextError> {
        let backings = [source_backing, toolchain_backing, output_backing, empty_backing, home_backing];
        if backings.iter().any(|path| !path.is_absolute() || path.starts_with("/__rabs")) {
            return Err(invalid("dependency mount backing is not private absolute storage"));
        }
        let mut spec = CanonicalNamespaceSpec::new();
        spec.cwd = PathBuf::from(&self.cwd);
        spec.env = self.env.clone();
        spec.ro_binds = vec![
            Bind::new(source_backing, &self.source_root),
            Bind::new(toolchain_backing, &self.toolchain_root),
        ];
        spec.ro_binds.extend(self.dependency_dirs.iter()
            .filter(|path| *path != &self.out_dir)
            .map(|path| Bind::new(empty_backing, path)));
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
    let refuse = || IsolationError::InvalidSpec { reason: "dependency namespace differs from its validated context".to_owned() };
    let expected_ro: BTreeSet<_> = [&context.source_root, &context.toolchain_root]
        .into_iter().chain(context.dependency_dirs.iter().filter(|path| *path != &context.out_dir))
        .map(|path| PathBuf::from(path)).collect();
    let expected_rw = BTreeSet::from([PathBuf::from(&context.out_dir), PathBuf::from(layout::HOME)]);
    let actual_ro: BTreeSet<_> = spec.ro_binds.iter().map(|bind| bind.visible.clone()).collect();
    let actual_rw: BTreeSet<_> = spec.rw_binds.iter().map(|bind| bind.visible.clone()).collect();
    let semantic_env = |env: &[(String, String)]| -> Vec<(String, String)> {
        env.iter().filter(|(name, _)| !matches!(name.as_str(), "MAKEFLAGS" | "MFLAGS" | "CARGO_MAKEFLAGS"))
            .cloned().collect()
    };
    if program != context.compiler || spec.cwd != Path::new(&context.cwd)
        || spec.allows_network() || spec.hostname != "rabs"
        || actual_ro != expected_ro || actual_rw != expected_rw
        || actual_ro.len() != spec.ro_binds.len() || actual_rw.len() != spec.rw_binds.len()
        || semantic_env(&spec.env) != semantic_env(&context.env)
        || spec.ro_binds.iter().chain(&spec.rw_binds)
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
            user_ns: true, pid_ns: true, ipc_ns: true, uts_hostname: Some("rabs".to_owned()),
            net_isolated: true, mounts_closed_view: true, clearenv: true, host_usr_ro: true,
            tmpfs_tmp: true, proc_private: true, die_with_parent: true,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context(env: Vec<(String, String)>) -> DependencyExecContext {
        DependencyExecContext::new("/home/user/registry/package".into(), "/home/user/registry/package/src".into(),
            "/home/user/toolchains/pinned".into(), "/home/user/toolchains/pinned/bin/rustc".into(),
            "/work/build/deps".into(), vec!["/work/build/deps".into(), "/work/build/empty".into()], env, [7;32]).unwrap()
    }

    #[test]
    fn original_paths_environment_and_empty_search_mounts_survive() {
        let context = context(vec![("DEPENDENCY_FLAVOR".into(), "hello /home/user/registry/package".into())]);
        let spec = context.namespace(Path::new("/private/source"), Path::new("/private/toolchain"),
            Path::new("/private/output"), Path::new("/private/empty"), Path::new("/private/home")).unwrap();
        let support = HostIsolationSupport { bubblewrap:Some("test".into()), unprivileged_userns:true,
            overlayfs:false, cgroup_v2:false, landlock:false };
        let args = vec!["src/lib.rs".into(), "--emit=dep-info,metadata".into()];
        let launch = build_dependency_argv(&context, &spec, &support, context.compiler(), &args).unwrap();
        let args: Vec<_> = launch.argv.iter().map(|value| value.to_str().unwrap()).collect();
        assert!(args.windows(3).any(|values| values == ["--ro-bind", "/private/source", context.source_root()]));
        assert!(args.windows(3).any(|values| values == ["--ro-bind", "/private/empty", "/work/build/empty"]));
        assert!(args.windows(3).any(|values| values == ["--bind", "/private/output", context.out_dir()]));
        assert!(args.windows(3).any(|values| values == ["--setenv", "DEPENDENCY_FLAVOR", "hello /home/user/registry/package"]));
        assert!(args.ends_with(&[context.compiler(), "src/lib.rs", "--emit=dep-info,metadata"]));
        assert!(crate::canonical_namespace::build_canonical_argv(&spec, &support, context.compiler(), &[]).is_err());
        assert!(launch.boundary.net_isolated);
    }

    #[test]
    fn aliases_cannot_shadow_inputs_runtime_or_each_other() {
        let good = context(Vec::new());
        for out in ["/", "/usr/output", "/etc/output", "/__rabs/output", good.source_root(), "/home/user"] {
            assert!(DependencyExecContext::new(good.source_root.clone(), good.cwd.clone(), good.toolchain_root.clone(),
                good.compiler.clone(), out.into(), Vec::new(), Vec::new(), [7;32]).is_err(), "{out}");
        }
        for directory in ["/home/user/registry", "/work/build/deps/nested", "/proc/secret", "/work/build/../escape"] {
            assert!(DependencyExecContext::new(good.source_root.clone(), good.cwd.clone(), good.toolchain_root.clone(),
                good.compiler.clone(), good.out_dir.clone(), vec![directory.into()], Vec::new(), [7;32]).is_err(), "{directory}");
        }
    }

    #[test]
    fn loader_paths_only_resolve_into_retained_toolchain_or_empty_roots() {
        let context = context(vec![("LD_LIBRARY_PATH".into(), "/work/build/deps:/home/user/toolchains/pinned/lib:/work/build/empty".into())]);
        assert_eq!(context.loader_search_paths(Path::new("/retained/tc")).unwrap(), vec![PathBuf::from("/retained/tc/lib")]);
        for (name, value) in [("LD_PRELOAD", "libbad.so"), ("GLIBC_TUNABLES", "x"), ("LD_LIBRARY_PATH", ":/usr/lib"), ("LD_LIBRARY_PATH", "/tmp/unowned")] {
            assert!(DependencyExecContext::new(context.source_root.clone(), context.cwd.clone(), context.toolchain_root.clone(),
                context.compiler.clone(), context.out_dir.clone(), context.dependency_dirs.clone(),
                vec![(name.into(), value.into())], [7;32]).is_err());
        }
    }

    #[test]
    fn post_validation_environment_or_mount_injection_is_refused() {
        let context = context(vec![("NUM_JOBS".into(), "2".into())]);
        let spec = context.namespace(Path::new("/private/source"), Path::new("/private/toolchain"),
            Path::new("/private/output"), Path::new("/private/empty"), Path::new("/private/home")).unwrap();
        let support = HostIsolationSupport { bubblewrap:Some("test".into()), unprivileged_userns:true,
            overlayfs:false, cgroup_v2:false, landlock:false };
        let mut changed = spec.clone();
        changed.env[0].1 = "8".into();
        assert!(build_dependency_argv(&context, &changed, &support, context.compiler(), &[]).is_err());
        let mut changed = spec;
        changed.rw_binds.push(Bind::new("/private/other", context.source_root()));
        assert!(build_dependency_argv(&context, &changed, &support, context.compiler(), &[]).is_err());
    }
}
