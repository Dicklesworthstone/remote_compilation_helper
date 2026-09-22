//! Canonical process-context capture (bead D026; risk R78; plan §28).
//!
//! A compiler's output is a function of more than argv and files:
//! umask decides created-file modes, rlimits can change codegen
//! behavior under pressure, CPU count leaks into build-script feature
//! probes, argv0/cwd leak into diagnostics and `file!()`-adjacent
//! surfaces, and an inherited descriptor is a covert input channel.
//! R78's rule: every such channel is either **pinned to a canonical
//! value** by the launch (umask, cwd, argv0) or **captured as an
//! explicit semantic input** that participates in action identity
//! (CPU view, rlimits) — never silently inherited.
//!
//! Inherited FDs are default-closed before spawn. The one approved
//! exception class — a local jobserver pipe — is capability-scoped and
//! excluded from semantic identity ONLY when proven output-neutral;
//! an unproven jobserver stays inside the identity so two runs with
//! different unproven descriptors can never alias.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Explicit worker command context. Advertised before a coordinator may send
/// `command_context`; an older worker must never silently ignore its semantics.
pub const COMMAND_CONTEXT_VERSION: &str = "env-cwd-v1";
/// Maximum explicitly supplied environment entries, excluding the pinned base.
pub const MAX_COMMAND_ENV_ENTRIES: usize = 256;
/// Aggregate encoded `name=value\0` bytes, excluding the pinned base.
pub const MAX_COMMAND_ENV_BYTES: usize = 128 * 1024;
/// Bound one value independently of the aggregate environment allowance.
pub const MAX_COMMAND_ENV_VALUE_BYTES: usize = 64 * 1024;

// These names belong to the mount plan or the worker's jobserver. Refuse them
// instead of accepting an environment that execution would silently replace.
const WORKER_OWNED_ENV: &[&str] = &[
    "PATH", "HOME", "CARGO_HOME", "TMPDIR", "RUSTUP_HOME", "RUSTUP_TOOLCHAIN",
    "LANG", "LC_ALL", "TZ", "MAKEFLAGS", "CARGO_MAKEFLAGS", "MFLAGS", "NUM_JOBS",
];

/// Validated, explicit execution context for a canonical worker command.
///
/// This is neither host environment capture nor action-cache authorization.
/// Callers preserve it in the original request identity. Values are passed
/// verbatim to the existing clear-environment namespace launcher; they are not
/// interpreted as shell text. Only workspace-relative canonical directories
/// are supported in this protocol version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandContext {
    cwd: PathBuf,
    env: Vec<(String, String)>,
}

/// A command context cannot be represented without changing its meaning.
/// Error messages deliberately contain no environment values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandContextError {
    /// The directory is not an unambiguous canonical workspace path.
    InvalidWorkingDirectory,
    /// Environment names must use bounded POSIX identifier spelling.
    InvalidEnvironmentName(String),
    /// Canonical mounts and worker-local coordination own this name.
    WorkerOwnedEnvironment(String),
    /// Two entries name the same variable; last-wins is not an input contract.
    DuplicateEnvironmentName(String),
    /// Count, individual value, NUL exclusion, or total byte limit failed.
    EnvironmentLimit,
    /// An existing namespace entry would be overwritten by this context.
    EnvironmentConflict(String),
}

impl std::fmt::Display for CommandContextError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidWorkingDirectory => write!(f, "command cwd must be a canonical workspace path"),
            Self::InvalidEnvironmentName(name) => write!(f, "invalid command environment name {name:?}"),
            Self::WorkerOwnedEnvironment(name) => write!(f, "command cannot replace worker-owned environment {name:?}"),
            Self::DuplicateEnvironmentName(name) => write!(f, "duplicate command environment name {name:?}"),
            Self::EnvironmentLimit => write!(f, "command environment exceeds its limits or contains NUL"),
            Self::EnvironmentConflict(name) => write!(f, "command environment conflicts with namespace entry {name:?}"),
        }
    }
}

impl std::error::Error for CommandContextError {}

impl Default for CommandContext {
    fn default() -> Self {
        Self { cwd: PathBuf::from(crate::layout::WORKSPACE), env: Vec::new() }
    }
}

impl CommandContext {
    /// Validate without normalizing paths, dropping values, or inheriting any
    /// host variables. An explicitly empty value is distinct from an omission.
    ///
    /// # Errors
    /// [`CommandContextError`] names the violated input boundary.
    pub fn new(cwd: &str, env: Vec<(String, String)>) -> Result<Self, CommandContextError> {
        let suffix = cwd.strip_prefix(crate::layout::WORKSPACE)
            .ok_or(CommandContextError::InvalidWorkingDirectory)?;
        if cwd.len() > 4096 || cwd.chars().any(char::is_control)
            || cwd.contains(['\\', ':'])
            || (!suffix.is_empty() && (!suffix.starts_with('/')
                || suffix[1..].split('/').any(|part| part.is_empty() || matches!(part, "." | ".."))))
        {
            return Err(CommandContextError::InvalidWorkingDirectory);
        }
        if env.len() > MAX_COMMAND_ENV_ENTRIES {
            return Err(CommandContextError::EnvironmentLimit);
        }
        let mut entries = BTreeMap::new();
        let mut bytes = 0_usize;
        for (name, value) in env {
            let mut characters = name.bytes();
            if name.len() > 256
                || !characters.next().is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
                || !characters.all(|b| b.is_ascii_alphanumeric() || b == b'_')
            {
                return Err(CommandContextError::InvalidEnvironmentName(name));
            }
            if WORKER_OWNED_ENV.contains(&name.as_str()) {
                return Err(CommandContextError::WorkerOwnedEnvironment(name));
            }
            if value.len() > MAX_COMMAND_ENV_VALUE_BYTES || value.contains('\0') {
                return Err(CommandContextError::EnvironmentLimit);
            }
            // Each individual length is bounded above before addition.
            bytes = bytes.checked_add(name.len() + value.len() + 2)
                .filter(|bytes| *bytes <= MAX_COMMAND_ENV_BYTES)
                .ok_or(CommandContextError::EnvironmentLimit)?;
            match entries.entry(name) {
                std::collections::btree_map::Entry::Vacant(entry) => { entry.insert(value); }
                std::collections::btree_map::Entry::Occupied(entry) => {
                    return Err(CommandContextError::DuplicateEnvironmentName(entry.key().clone()));
                }
            }
        }
        Ok(Self { cwd: PathBuf::from(cwd), env: entries.into_iter().collect() })
    }

    /// The canonical directory to pass to the namespace's `--chdir`.
    #[must_use]
    pub fn cwd(&self) -> &Path { &self.cwd }

    /// Exact values, sorted by environment name.
    #[must_use]
    pub fn environment(&self) -> &[(String, String)] { &self.env }

    /// Apply after mount-plan construction and before worker jobserver setup.
    /// The existing launcher clears the host environment and sets these values
    /// INSIDE the namespace, not in the host bubblewrap process environment.
    ///
    /// # Errors
    /// An unexpected base-environment collision refuses before changing `spec`.
    /// This also fences newly added pinned keys until the validator is updated.
    pub fn apply_to(
        &self,
        spec: &mut crate::canonical_namespace::CanonicalNamespaceSpec,
    ) -> Result<(), CommandContextError> {
        for (name, _) in &self.env {
            if spec.env.iter().any(|(existing, _)| existing == name) {
                return Err(CommandContextError::EnvironmentConflict(name.clone()));
            }
        }
        let mut env = spec.env.clone();
        env.extend(self.env.iter().cloned());
        env.sort_by(|a, b| a.0.cmp(&b.0));
        spec.env = env;
        spec.cwd = self.cwd.clone();
        Ok(())
    }
}

/// The CPU view a launch presents — an explicit semantic input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuView {
    /// Pinned logical CPU count presented to the action.
    Pinned(u32),
    /// Host count captured and recorded as a semantic input.
    CapturedHost(u32),
}

/// One rlimit the launch pins (soft value).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RlimitSpec {
    /// Resource name (`NOFILE`, `NPROC`, `STACK`, …).
    pub resource: String,
    /// Pinned soft limit.
    pub soft: u64,
}

/// The canonical process context for one action launch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalProcessContext {
    /// Pinned umask (canonical `0o022`).
    pub umask: u32,
    /// Pinned working directory (the canonical workspace).
    pub cwd: String,
    /// Pinned argv0 (the canonical binary path, never a host alias).
    pub argv0: String,
    /// Pinned rlimits, sorted by resource.
    pub rlimits: Vec<RlimitSpec>,
    /// The CPU view (pinned or captured-as-input).
    pub cpu_view: CpuView,
}

impl CanonicalProcessContext {
    /// The canonical default: umask 022, cwd at the workspace, argv0
    /// canonical, a pinned NOFILE floor, and an explicitly captured
    /// host CPU count.
    #[must_use]
    pub fn canonical_default(argv0: &str, host_cpus: u32) -> Self {
        Self {
            umask: 0o022,
            cwd: crate::layout::WORKSPACE.to_string(),
            argv0: argv0.to_string(),
            rlimits: vec![RlimitSpec {
                resource: "NOFILE".to_string(),
                soft: 4096,
            }],
            cpu_view: CpuView::CapturedHost(host_cpus),
        }
    }
}

/// Classification of one inherited descriptor at spawn time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FdClass {
    /// stdin/stdout/stderr — approved, semantics owned by the harness.
    Stdio,
    /// A local jobserver pipe, capability-scoped.
    Jobserver {
        /// Whether output-neutrality has been PROVEN for this lane.
        proven_output_neutral: bool,
    },
    /// Anything else the process happened to inherit.
    Unapproved,
}

/// What the spawner does with one inherited descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FdDisposition {
    /// Kept open (approved).
    Keep,
    /// Closed before spawn (default for everything unapproved).
    CloseBeforeSpawn,
}

/// Decide every inherited descriptor's fate: unapproved ⇒ closed.
#[must_use]
pub fn fd_plan(inherited: &[(i32, FdClass)]) -> Vec<(i32, FdDisposition)> {
    inherited
        .iter()
        .map(|(fd, class)| {
            let disposition = match class {
                FdClass::Stdio | FdClass::Jobserver { .. } => FdDisposition::Keep,
                FdClass::Unapproved => FdDisposition::CloseBeforeSpawn,
            };
            (*fd, disposition)
        })
        .collect()
}

/// The semantic-identity inputs this context contributes to the action
/// key. Everything pinned or captured participates; an approved
/// jobserver is EXCLUDED only when proven output-neutral — an unproven
/// one is recorded so it can never silently alias two runs.
#[must_use]
pub fn semantic_identity_inputs(
    context: &CanonicalProcessContext,
    descriptors: &[(i32, FdClass)],
) -> BTreeMap<String, String> {
    let mut inputs = BTreeMap::new();
    inputs.insert("umask".to_string(), format!("{:03o}", context.umask));
    inputs.insert("cwd".to_string(), context.cwd.clone());
    inputs.insert("argv0".to_string(), context.argv0.clone());
    for limit in &context.rlimits {
        inputs.insert(format!("rlimit.{}", limit.resource), limit.soft.to_string());
    }
    match context.cpu_view {
        CpuView::Pinned(count) => {
            inputs.insert("cpu.pinned".to_string(), count.to_string());
        }
        CpuView::CapturedHost(count) => {
            inputs.insert("cpu.captured".to_string(), count.to_string());
        }
    }
    for (fd, class) in descriptors {
        match class {
            FdClass::Jobserver {
                proven_output_neutral: true,
            }
            | FdClass::Stdio => {} // excluded: proven neutral / harness-owned
            FdClass::Jobserver {
                proven_output_neutral: false,
            } => {
                inputs.insert(format!("fd.{fd}"), "jobserver-unproven".to_string());
            }
            FdClass::Unapproved => {
                // Closed before spawn — but its PRESENCE is recorded so
                // a spawn plan that failed to close cannot alias.
                inputs.insert(format!("fd.{fd}"), "unapproved-closed".to_string());
            }
        }
    }
    inputs
}

/// Capture the REAL host process context on Linux (`/proc` surfaces).
/// Umask comes from `/proc/self/status` (readable without mutation);
/// unavailable fields are typed `None`, never guessed.
#[cfg(target_os = "linux")]
#[must_use]
pub fn capture_host_umask() -> Option<u32> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    status
        .lines()
        .find_map(|line| line.strip_prefix("Umask:"))
        .and_then(|value| u32::from_str_radix(value.trim(), 8).ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn namespace() -> crate::canonical_namespace::CanonicalNamespaceSpec {
        crate::canonical_mounts::CanonicalMountPlan::new("/tc", "/ws", "/ch", "/home")
            .to_spec().unwrap()
    }

    #[test]
    fn explicit_context_preserves_values_and_reaches_namespace_argv() {
        let context = CommandContext::new("/__rabs/workspace/packages/🦀", vec![
            ("Z_EMPTY".into(), String::new()),
            ("BUILD_LABEL".into(), "value with spaces, \"quotes\", $HOME and\n雪".into()),
        ]).unwrap();
        let mut spec = namespace();
        let base = spec.env.clone();
        context.apply_to(&mut spec).unwrap();
        assert_eq!(spec.cwd, context.cwd());
        assert!(base.iter().all(|entry| spec.env.contains(entry)));
        assert!(spec.env.windows(2).all(|pair| pair[0].0 < pair[1].0));
        let support = crate::canonical_namespace::HostIsolationSupport {
            bubblewrap: Some("fixture".into()), unprivileged_userns: true,
            overlayfs: false, cgroup_v2: false, landlock: false,
        };
        let launch = crate::canonical_namespace::build_canonical_argv(
            &spec, &support, "/__rabs/toolchain/bin/rustc", &["lib.rs".into()],
        ).unwrap();
        assert!(launch.argv.iter().any(|arg| arg == "--clearenv"));
        assert!(launch.argv.windows(2).any(|args| args[0] == "--chdir" && args[1] == context.cwd().as_os_str()));
        for (name, value) in context.environment() {
            assert!(launch.argv.windows(3).any(|args| args[0] == "--setenv"
                && args[1] == name.as_str() && args[2] == value.as_str()));
        }
    }

    #[test]
    fn command_cwd_rejects_aliases_and_host_paths_without_normalizing() {
        for cwd in ["", "relative", "/etc", "/__rabs/workspace-other", "/__rabs/home",
            "/__rabs/workspace/", "/__rabs/workspace//member", "/__rabs/workspace/.",
            "/__rabs/workspace/a/../b", "/__rabs/workspace/a\\b", "/__rabs/workspace/a:b",
            "/__rabs/workspace/a\0b", "/__rabs/workspace/a\nb"] {
            assert_eq!(CommandContext::new(cwd, vec![]), Err(CommandContextError::InvalidWorkingDirectory), "{cwd:?}");
        }
        let default = CommandContext::default();
        assert_eq!(default.cwd(), Path::new(crate::layout::WORKSPACE));
        assert!(default.environment().is_empty());
        assert_eq!(CommandContext::new(crate::layout::WORKSPACE, vec![]).unwrap(), default);
        assert!(CommandContext::new(&format!("/__rabs/workspace/{}", "x".repeat(4096)), vec![]).is_err());
    }

    #[test]
    fn every_pinned_mount_and_jobserver_variable_is_refused() {
        // Catch drift when CanonicalMountPlan gains another pinned variable.
        for name in namespace().env.into_iter().map(|(name, _)| name)
            .chain(WORKER_OWNED_ENV.iter().map(|name| (*name).to_owned()))
        {
            assert_eq!(CommandContext::new(crate::layout::WORKSPACE,
                vec![(name.clone(), "not-worker-authority".into())]),
                Err(CommandContextError::WorkerOwnedEnvironment(name)));
        }
    }

    #[test]
    fn command_environment_refuses_invalid_names_duplicates_and_nul_without_values_in_errors() {
        for name in ["", "A=B", "1FIRST", "two words", "雪", "A\0B", "A-B", "A\nB"] {
            let error = CommandContext::new(crate::layout::WORKSPACE,
                vec![(name.into(), "private-value".into())]).unwrap_err();
            assert!(matches!(error, CommandContextError::InvalidEnvironmentName(_)));
            assert!(!error.to_string().contains("private-value"));
        }
        assert!(matches!(CommandContext::new(crate::layout::WORKSPACE,
            vec![("N".repeat(257), "v".into())]), Err(CommandContextError::InvalidEnvironmentName(_))));
        assert_eq!(CommandContext::new(crate::layout::WORKSPACE,
            vec![("VALID".into(), "secret\0value".into())]), Err(CommandContextError::EnvironmentLimit));
        assert_eq!(CommandContext::new(crate::layout::WORKSPACE,
            vec![("KEY".into(), "a".into()), ("KEY".into(), "a".into())]),
            Err(CommandContextError::DuplicateEnvironmentName("KEY".into())));
    }

    #[test]
    fn command_environment_bounds_are_inclusive_and_account_for_delimiters() {
        let entries: Vec<_> = (0..MAX_COMMAND_ENV_ENTRIES)
            .map(|n| (format!("KEY_{n}"), String::new())).collect();
        assert!(CommandContext::new(crate::layout::WORKSPACE, entries.clone()).is_ok());
        let mut too_many = entries;
        too_many.push(("ONE_TOO_MANY".into(), String::new()));
        assert_eq!(CommandContext::new(crate::layout::WORKSPACE, too_many), Err(CommandContextError::EnvironmentLimit));
        assert!(CommandContext::new(crate::layout::WORKSPACE,
            vec![("A".into(), "v".repeat(MAX_COMMAND_ENV_VALUE_BYTES))]).is_ok());
        assert_eq!(CommandContext::new(crate::layout::WORKSPACE,
            vec![("A".into(), "v".repeat(MAX_COMMAND_ENV_VALUE_BYTES + 1))]), Err(CommandContextError::EnvironmentLimit));
        let first = "v".repeat(MAX_COMMAND_ENV_VALUE_BYTES);
        let second = "v".repeat(MAX_COMMAND_ENV_BYTES - MAX_COMMAND_ENV_VALUE_BYTES - 6);
        assert!(CommandContext::new(crate::layout::WORKSPACE,
            vec![("A".into(), first.clone()), ("B".into(), second.clone())]).is_ok());
        assert_eq!(CommandContext::new(crate::layout::WORKSPACE,
            vec![("A".into(), first), ("B".into(), format!("{second}v"))]), Err(CommandContextError::EnvironmentLimit));
    }

    #[test]
    fn context_conflicts_leave_the_entire_namespace_unchanged() {
        let context = CommandContext::new("/__rabs/workspace/member",
            vec![("A_NEW".into(), "value".into()), ("Z_EXISTING".into(), "other".into())]).unwrap();
        let mut spec = namespace();
        spec.env.push(("Z_EXISTING".into(), "original".into()));
        let original = spec.clone();
        assert_eq!(context.apply_to(&mut spec), Err(CommandContextError::EnvironmentConflict("Z_EXISTING".into())));
        assert_eq!(spec, original);
    }

    fn context() -> CanonicalProcessContext {
        CanonicalProcessContext::canonical_default("/__rabs/toolchain/bin/rustc", 8)
    }

    #[test]
    fn canonical_default_pins_the_canonical_world() {
        let ctx = context();
        assert_eq!(ctx.umask, 0o022);
        assert_eq!(ctx.cwd, "/__rabs/workspace");
        assert_eq!(ctx.argv0, "/__rabs/toolchain/bin/rustc");
        assert_eq!(ctx.cpu_view, CpuView::CapturedHost(8));
    }

    #[test]
    fn t024_differential_fixtures_split_identity_on_every_context_channel() {
        // THE T024 acceptance shape: same base context, one channel
        // perturbed at a time — each perturbation MUST change the
        // semantic identity.
        let base = semantic_identity_inputs(&context(), &[]);
        let mut umask_differs = context();
        umask_differs.umask = 0o077;
        let mut cpu_differs = context();
        cpu_differs.cpu_view = CpuView::CapturedHost(64);
        let mut rlimit_differs = context();
        rlimit_differs.rlimits[0].soft = 1024;
        let mut cwd_differs = context();
        cwd_differs.cwd = "/__rabs/repos/dep-a".to_string();
        let mut argv0_differs = context();
        argv0_differs.argv0 = "/usr/bin/rustc".to_string();
        for (label, perturbed) in [
            ("umask", umask_differs),
            ("cpu", cpu_differs),
            ("rlimit", rlimit_differs),
            ("cwd", cwd_differs),
            ("argv0", argv0_differs),
        ] {
            assert_ne!(
                base,
                semantic_identity_inputs(&perturbed, &[]),
                "{label} perturbation must change semantic identity"
            );
        }
        // And pinned-vs-captured CPU is itself a semantic distinction.
        let mut pinned = context();
        pinned.cpu_view = CpuView::Pinned(8);
        assert_ne!(base, semantic_identity_inputs(&pinned, &[]));
    }

    #[test]
    fn unapproved_fds_close_before_spawn_and_are_recorded() {
        let inherited = vec![
            (0, FdClass::Stdio),
            (
                7,
                FdClass::Jobserver {
                    proven_output_neutral: true,
                },
            ),
            (9, FdClass::Unapproved),
        ];
        let plan = fd_plan(&inherited);
        assert_eq!(plan[0], (0, FdDisposition::Keep));
        assert_eq!(plan[1], (7, FdDisposition::Keep));
        assert_eq!(plan[2], (9, FdDisposition::CloseBeforeSpawn));
        // The unapproved fd's presence is still recorded in identity.
        let identity = semantic_identity_inputs(&context(), &inherited);
        assert_eq!(identity["fd.9"], "unapproved-closed");
    }

    #[test]
    fn jobserver_exclusion_requires_proof_of_output_neutrality() {
        let proven = vec![(
            7,
            FdClass::Jobserver {
                proven_output_neutral: true,
            },
        )];
        let unproven = vec![(
            7,
            FdClass::Jobserver {
                proven_output_neutral: false,
            },
        )];
        let base = semantic_identity_inputs(&context(), &[]);
        // Proven-neutral jobserver: EXCLUDED — identity unchanged.
        assert_eq!(base, semantic_identity_inputs(&context(), &proven));
        // Unproven: INCLUDED — identity differs.
        let with_unproven = semantic_identity_inputs(&context(), &unproven);
        assert_ne!(base, with_unproven);
        assert_eq!(with_unproven["fd.7"], "jobserver-unproven");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn real_umask_capture_reads_proc_without_mutation() {
        let umask = capture_host_umask().expect("/proc/self/status has Umask on Linux");
        assert!(umask <= 0o777);
    }
}
