//! Linux canonical Cargo-driver namespace + nested per-action closed-view
//! materializer (bead D003; invariants I1/I19/I20; plan §55).
//!
//! WHY (I19): Cargo creates path-sensitive unit identities BEFORE any
//! wrapper runs, so only launching the Cargo *process itself* inside the
//! canonical namespace erases path divergence between hosts/worktrees. This
//! module constructs that namespace — the fixed `/__rabs/…` visible world
//! from [`crate::layout`] backed by hidden attempt-specific physical
//! directories — and, from the same machinery, materializes the finer
//! per-action CLOSED input views (only declared inputs visible; an
//! undeclared path is *absent*, not merely read-only).
//!
//! ## Mechanism: measured host support, external tooling, no unsafe
//!
//! This crate forbids `unsafe`, and privileged helpers are a last resort
//! (A011 ledger). The preferred stack from the bead — user/mount/pid/uts/
//! network namespaces via unprivileged userns — is therefore driven through
//! **bubblewrap** as a subprocess: [`HostIsolationSupport::probe`] measures
//! what the host actually provides, [`build_canonical_argv`] deterministically
//! compiles a namespace spec into a `bwrap` argv, and a host that cannot
//! satisfy the request yields a typed [`IsolationError::UnsupportedHost`]
//! refusal — never a silently weaker sandbox.
//!
//! ## Boundary honesty
//!
//! The constructed argv IS the enforcement claim, and
//! [`NamespaceBoundary`] records exactly which properties it enforces so
//! `StrictHermeticLinux` can prove its documented boundary
//! ([`NamespaceBoundary::satisfies_strict_hermetic_linux`]) instead of
//! asserting it. One deliberately documented softness in this first
//! increment: the host `/usr` tree is visible READ-ONLY inside the
//! namespace (`host_usr_ro`) — dynamic linking and `/bin/sh` for build
//! scripts need it until D005 lands fully pinned toolchain/sysroot mounts.
//! It is part of the recorded boundary, not hidden behind one.

use crate::layout;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// Measured isolation capabilities of the current host.
///
/// Probing runs cheap read-only checks plus one `bwrap --unshare-user`
/// smoke execution; the result is evidence, so callers persist it next to
/// whatever the namespace produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostIsolationSupport {
    /// `bwrap` exists on PATH and `--version` succeeds.
    pub bubblewrap: Option<String>,
    /// A no-op command inside `bwrap --unshare-user --unshare-pid` works —
    /// the load-bearing check: unprivileged user namespaces usable end to
    /// end, not merely advertised by a sysctl.
    pub unprivileged_userns: bool,
    /// `overlay` appears in `/proc/filesystems` (future D004/D005 lowers).
    pub overlayfs: bool,
    /// cgroup v2 controllers available at `/sys/fs/cgroup`.
    pub cgroup_v2: bool,
    /// `landlock` listed in the active LSM stack.
    pub landlock: bool,
}

impl HostIsolationSupport {
    /// Probe the current host. On non-Linux everything is absent.
    #[must_use]
    pub fn probe() -> Self {
        if !cfg!(target_os = "linux") {
            return Self {
                bubblewrap: None,
                unprivileged_userns: false,
                overlayfs: false,
                cgroup_v2: false,
                landlock: false,
            };
        }

        let bubblewrap = std::process::Command::new("bwrap")
            .arg("--version")
            .output()
            .ok()
            .filter(|out| out.status.success())
            .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_string());

        let unprivileged_userns = bubblewrap.is_some()
            && std::process::Command::new("bwrap")
                .args([
                    "--unshare-user",
                    "--unshare-pid",
                    "--ro-bind",
                    "/",
                    "/",
                    "true",
                ])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .map(|status| status.success())
                .unwrap_or(false);

        let overlayfs = std::fs::read_to_string("/proc/filesystems")
            .map(|s| s.lines().any(|l| l.trim_end().ends_with("overlay")))
            .unwrap_or(false);
        let cgroup_v2 = Path::new("/sys/fs/cgroup/cgroup.controllers").exists();
        let landlock = std::fs::read_to_string("/sys/kernel/security/lsm")
            .map(|s| s.split(',').any(|l| l.trim() == "landlock"))
            .unwrap_or(false);

        Self {
            bubblewrap,
            unprivileged_userns,
            overlayfs,
            cgroup_v2,
            landlock,
        }
    }

    /// The capabilities the canonical namespace REQUIRES; anything missing
    /// is a typed refusal, never a degraded sandbox.
    #[must_use]
    pub fn missing_for_canonical(&self) -> Vec<&'static str> {
        let mut missing = Vec::new();
        if self.bubblewrap.is_none() {
            missing.push("bubblewrap");
        }
        if !self.unprivileged_userns {
            missing.push("unprivileged-user-namespaces");
        }
        missing
    }
}

/// One bind mount from a hidden physical backing path onto a fixed visible
/// path inside the namespace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bind {
    /// Hidden physical backing directory (absolute; MAY carry attempt IDs —
    /// the namespace hides it).
    pub backing: PathBuf,
    /// Fixed visible path (must live under a [`layout`] root).
    pub visible: PathBuf,
}

impl Bind {
    /// Convenience constructor.
    pub fn new(backing: impl Into<PathBuf>, visible: impl Into<PathBuf>) -> Self {
        Self {
            backing: backing.into(),
            visible: visible.into(),
        }
    }
}

/// Specification of the canonical Cargo-driver namespace for one command
/// (or compatible command group).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalNamespaceSpec {
    /// Read-only binds (source snapshot, toolchain, registry, git, repos).
    pub ro_binds: Vec<Bind>,
    /// Read-write binds (workspace, out/build/incremental units, cargo-home,
    /// home).
    pub rw_binds: Vec<Bind>,
    /// The complete presented environment, name-sorted `K=V` pairs — the
    /// child receives EXACTLY this (I21), enforced via `--clearenv`.
    pub env: Vec<(String, String)>,
    /// Deterministic UTS hostname.
    pub hostname: String,
    /// Whether the network namespace is shared with the host. `false`
    /// (default-deny) is required for `StrictHermeticLinux`.
    pub(crate) allow_network: bool,
    /// Working directory inside the namespace.
    pub cwd: PathBuf,
}

impl CanonicalNamespaceSpec {
    /// A spec with the canonical defaults: deterministic hostname, closed
    /// network, cwd at the fixed workspace root.
    #[must_use]
    pub fn new() -> Self {
        Self {
            ro_binds: Vec::new(),
            rw_binds: Vec::new(),
            env: Vec::new(),
            hostname: "rabs".to_string(),
            allow_network: false,
            cwd: PathBuf::from(layout::WORKSPACE),
        }
    }

    /// Whether this spec would share the host network. Public callers may
    /// inspect this fact but cannot widen it; E025's brokered fetch keeps it
    /// false.
    #[must_use]
    pub const fn allows_network(&self) -> bool {
        self.allow_network
    }
}

impl Default for CanonicalNamespaceSpec {
    fn default() -> Self {
        Self::new()
    }
}

/// A nested per-action CLOSED input view: only the declared inputs and
/// output destinations exist; everything else — including paths that ARE
/// visible in the enclosing canonical namespace — is absent. Materialized
/// with the same builder as the canonical namespace (one mechanism, no
/// drift); the closure property comes from binding nothing that was not
/// declared.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionViewSpec {
    /// Declared input paths, read-only.
    pub input_binds: Vec<Bind>,
    /// Declared output destinations, read-write.
    pub output_binds: Vec<Bind>,
    /// Complete presented environment for the action.
    pub env: Vec<(String, String)>,
    /// Working directory inside the view.
    pub cwd: PathBuf,
}

/// Typed refusals from the builder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IsolationError {
    /// The measured host cannot construct the requested namespace.
    UnsupportedHost {
        /// The specific missing capabilities.
        missing: Vec<String>,
    },
    /// A bind or field in the spec is invalid.
    InvalidSpec {
        /// What was wrong.
        reason: String,
    },
}

impl std::fmt::Display for IsolationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedHost { missing } => {
                write!(f, "host cannot construct namespace; missing: {missing:?}")
            }
            Self::InvalidSpec { reason } => write!(f, "invalid namespace spec: {reason}"),
        }
    }
}

impl std::error::Error for IsolationError {}

/// The enforcement claims of one constructed namespace argv — recorded
/// evidence, derived from what was actually emitted, never asserted
/// independently of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamespaceBoundary {
    /// Fresh user namespace.
    pub user_ns: bool,
    /// Fresh pid namespace (child sees itself near pid 1; host pids absent).
    pub pid_ns: bool,
    /// Fresh IPC namespace.
    pub ipc_ns: bool,
    /// Fresh UTS namespace with the deterministic hostname.
    pub uts_hostname: Option<String>,
    /// Network default-deny (fresh, empty net namespace).
    pub net_isolated: bool,
    /// Mount view is closed: only the emitted binds plus `/proc`, `/dev`,
    /// tmpfs `/__rabs/tmp`, and (when `host_usr_ro`) the host `/usr` exist.
    pub mounts_closed_view: bool,
    /// Environment fully cleared then explicitly set (I21).
    pub clearenv: bool,
    /// DOCUMENTED SOFTNESS: host `/usr` visible read-only (dynamic linker,
    /// `/bin/sh`) until D005 pins toolchain/sysroot mounts.
    pub host_usr_ro: bool,
    /// `/__rabs/tmp` is a private tmpfs.
    pub tmpfs_tmp: bool,
    /// Private procfs mounted at `/proc`.
    pub proc_private: bool,
    /// Child dies with the supervising parent (no orphan escape).
    pub die_with_parent: bool,
}

impl NamespaceBoundary {
    /// Whether this boundary satisfies the documented
    /// `IsolationProfile::StrictHermeticLinux` contract of this increment:
    /// every namespace axis fresh, network closed, env explicit, closed
    /// mount view — with `host_usr_ro` as the one named, recorded
    /// exception.
    #[must_use]
    pub fn satisfies_strict_hermetic_linux(&self) -> bool {
        self.user_ns
            && self.pid_ns
            && self.ipc_ns
            && self.uts_hostname.is_some()
            && self.net_isolated
            && self.mounts_closed_view
            && self.clearenv
            && self.tmpfs_tmp
            && self.proc_private
            && self.die_with_parent
    }
}

/// A constructed namespace launch: the argv to execute and the boundary it
/// enforces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamespaceLaunch {
    /// Full argv (`argv[0]` is `bwrap`).
    pub argv: Vec<OsString>,
    /// The recorded enforcement claims of exactly this argv.
    pub boundary: NamespaceBoundary,
}

fn validate_visible(visible: &Path) -> Result<(), IsolationError> {
    let ok = layout::VISIBLE_ROOTS
        .iter()
        .any(|root| visible.starts_with(root));
    if !ok {
        return Err(IsolationError::InvalidSpec {
            reason: format!(
                "visible path {} is outside every canonical root",
                visible.display()
            ),
        });
    }
    Ok(())
}

fn validate_backing(backing: &Path) -> Result<(), IsolationError> {
    if !backing.is_absolute() {
        return Err(IsolationError::InvalidSpec {
            reason: format!("backing path {} is not absolute", backing.display()),
        });
    }
    if backing.starts_with("/__rabs") {
        return Err(IsolationError::InvalidSpec {
            reason: format!(
                "backing path {} lives inside the visible namespace — the two \
                 path worlds must never mix",
                backing.display()
            ),
        });
    }
    Ok(())
}

fn sorted_binds(binds: &[Bind]) -> Result<Vec<Bind>, IsolationError> {
    let mut out = binds.to_vec();
    for bind in &out {
        validate_visible(&bind.visible)?;
        validate_backing(&bind.backing)?;
    }
    out.sort_by(|a, b| a.visible.cmp(&b.visible));
    Ok(out)
}

fn push_common_prelude(argv: &mut Vec<OsString>) {
    argv.push("--die-with-parent".into());
    argv.push("--unshare-user".into());
    argv.push("--unshare-pid".into());
    argv.push("--unshare-ipc".into());
    argv.push("--unshare-uts".into());
}

fn push_host_usr(argv: &mut Vec<OsString>) {
    // Merged-usr host base, read-only: the dynamic linker, libc, and
    // /bin/sh for build scripts. Recorded as `host_usr_ro` in the boundary.
    argv.push("--ro-bind".into());
    argv.push("/usr".into());
    argv.push("/usr".into());
    for link in ["bin", "sbin", "lib", "lib64"] {
        argv.push("--symlink".into());
        argv.push(format!("usr/{link}").into());
        argv.push(format!("/{link}").into());
    }
    // The dynamic linker consults the cache when present; harmless if absent.
    argv.push("--ro-bind-try".into());
    argv.push("/etc/ld.so.cache".into());
    argv.push("/etc/ld.so.cache".into());
    // Debian/Ubuntu route `cc`/`c++` through absolute symlinks into
    // /etc/alternatives; without it rustc reports "linker `cc` not found"
    // (observed live on hz2). Part of the same recorded host_usr_ro
    // softness, gone when D005 pins a full toolchain root.
    argv.push("--ro-bind-try".into());
    argv.push("/etc/alternatives".into());
    argv.push("/etc/alternatives".into());
}

fn push_env(argv: &mut Vec<OsString>, env: &[(String, String)]) {
    argv.push("--clearenv".into());
    let mut pairs = env.to_vec();
    pairs.sort_by(|a, b| a.0.cmp(&b.0));
    for (name, value) in pairs {
        argv.push("--setenv".into());
        argv.push(name.into());
        argv.push(value.into());
    }
}

fn push_binds(argv: &mut Vec<OsString>, ro: &[Bind], rw: &[Bind]) {
    for bind in ro {
        argv.push("--ro-bind".into());
        argv.push(bind.backing.clone().into_os_string());
        argv.push(bind.visible.clone().into_os_string());
    }
    for bind in rw {
        argv.push("--bind".into());
        argv.push(bind.backing.clone().into_os_string());
        argv.push(bind.visible.clone().into_os_string());
    }
}

fn require_support(support: &HostIsolationSupport) -> Result<(), IsolationError> {
    let missing = support.missing_for_canonical();
    if missing.is_empty() {
        Ok(())
    } else {
        Err(IsolationError::UnsupportedHost {
            missing: missing.into_iter().map(str::to_string).collect(),
        })
    }
}

/// Compile the canonical Cargo-driver namespace into a deterministic
/// `bwrap` argv. Pure: no processes are spawned, so the builder (and its
/// tests) run on every platform; execution requires a host whose
/// [`HostIsolationSupport`] passed [`require`](HostIsolationSupport::missing_for_canonical).
pub fn build_canonical_argv(
    spec: &CanonicalNamespaceSpec,
    support: &HostIsolationSupport,
    program: &str,
    args: &[String],
) -> Result<NamespaceLaunch, IsolationError> {
    require_support(support)?;
    if spec.hostname.is_empty() || !spec.hostname.is_ascii() {
        return Err(IsolationError::InvalidSpec {
            reason: "hostname must be non-empty ASCII".to_string(),
        });
    }
    let ro = sorted_binds(&spec.ro_binds)?;
    let rw = sorted_binds(&spec.rw_binds)?;

    let mut argv: Vec<OsString> = vec!["bwrap".into()];
    push_common_prelude(&mut argv);
    if !spec.allow_network {
        argv.push("--unshare-net".into());
    }
    argv.push("--hostname".into());
    argv.push(spec.hostname.clone().into());
    push_env(&mut argv, &spec.env);
    argv.push("--proc".into());
    argv.push("/proc".into());
    argv.push("--dev".into());
    argv.push("/dev".into());
    push_host_usr(&mut argv);
    argv.push("--tmpfs".into());
    argv.push(layout::TMP.into());
    push_binds(&mut argv, &ro, &rw);
    argv.push("--chdir".into());
    argv.push(spec.cwd.clone().into_os_string());
    argv.push("--".into());
    argv.push(program.into());
    for arg in args {
        argv.push(arg.into());
    }

    let boundary = NamespaceBoundary {
        user_ns: true,
        pid_ns: true,
        ipc_ns: true,
        uts_hostname: Some(spec.hostname.clone()),
        net_isolated: !spec.allow_network,
        mounts_closed_view: true,
        clearenv: true,
        host_usr_ro: true,
        tmpfs_tmp: true,
        proc_private: true,
        die_with_parent: true,
    };
    Ok(NamespaceLaunch { argv, boundary })
}

/// Materialize a nested per-action CLOSED input view. Same builder, same
/// namespace axes, network always closed; the closure property is
/// structural — nothing undeclared is bound, so an undeclared path does
/// not exist inside the view even when it exists in the enclosing
/// canonical namespace.
pub fn build_action_view_argv(
    spec: &ActionViewSpec,
    support: &HostIsolationSupport,
    program: &str,
    args: &[String],
) -> Result<NamespaceLaunch, IsolationError> {
    let canonical = CanonicalNamespaceSpec {
        ro_binds: spec.input_binds.clone(),
        rw_binds: spec.output_binds.clone(),
        env: spec.env.clone(),
        hostname: "rabs".to_string(),
        allow_network: false,
        cwd: spec.cwd.clone(),
    };
    build_canonical_argv(&canonical, support, program, args)
}

/// Convert a launch into an executable [`std::process::Command`].
#[must_use]
pub fn command_for(launch: &NamespaceLaunch) -> std::process::Command {
    let mut cmd = std::process::Command::new(&launch.argv[0]);
    cmd.args(&launch.argv[1..]);
    // The child environment is governed entirely by --clearenv/--setenv in
    // the argv; clearing here as well keeps bwrap's own env minimal.
    cmd.env_clear();
    if let Some(path) = std::env::var_os("PATH") {
        cmd.env("PATH", path);
    }
    cmd
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full_support() -> HostIsolationSupport {
        HostIsolationSupport {
            bubblewrap: Some("bubblewrap 0.11.1".to_string()),
            unprivileged_userns: true,
            overlayfs: true,
            cgroup_v2: true,
            landlock: true,
        }
    }

    fn strs(argv: &[OsString]) -> Vec<String> {
        argv.iter()
            .map(|s| s.to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn canonical_argv_is_deterministic_and_network_closed() {
        let mut spec = CanonicalNamespaceSpec::new();
        spec.rw_binds.push(Bind::new(
            "/data/rabs/backing/attempt-42/ws",
            layout::WORKSPACE,
        ));
        spec.ro_binds
            .push(Bind::new("/data/rabs/toolchains/t1", layout::TOOLCHAIN));
        spec.env
            .push(("PATH".into(), "/__rabs/toolchain/bin".into()));

        let a = build_canonical_argv(&spec, &full_support(), "cargo", &["build".into()]).unwrap();
        let b = build_canonical_argv(&spec, &full_support(), "cargo", &["build".into()]).unwrap();
        assert_eq!(a.argv, b.argv, "same spec must compile identically");

        let s = strs(&a.argv);
        assert!(s.contains(&"--unshare-net".to_string()), "default deny");
        assert!(s.contains(&"--clearenv".to_string()));
        assert!(s.contains(&"--die-with-parent".to_string()));
        assert_eq!(s[0], "bwrap");
        assert!(a.boundary.satisfies_strict_hermetic_linux());
    }

    #[test]
    fn allow_network_drops_unshare_net_and_fails_strict_profile() {
        let mut spec = CanonicalNamespaceSpec::new();
        spec.allow_network = true;
        spec.rw_binds.push(Bind::new("/tmp/x", layout::WORKSPACE));
        let launch =
            build_canonical_argv(&spec, &full_support(), "cargo", &["metadata".into()]).unwrap();
        let s = strs(&launch.argv);
        assert!(!s.contains(&"--unshare-net".to_string()));
        assert!(!launch.boundary.satisfies_strict_hermetic_linux());
    }

    #[test]
    fn refuses_unsupported_host_with_named_capabilities() {
        let support = HostIsolationSupport {
            bubblewrap: None,
            unprivileged_userns: false,
            overlayfs: false,
            cgroup_v2: false,
            landlock: false,
        };
        let spec = CanonicalNamespaceSpec::new();
        let err = build_canonical_argv(&spec, &support, "cargo", &[]).unwrap_err();
        match err {
            IsolationError::UnsupportedHost { missing } => {
                assert!(missing.contains(&"bubblewrap".to_string()));
                assert!(missing.contains(&"unprivileged-user-namespaces".to_string()));
            }
            other => panic!("expected UnsupportedHost, got {other:?}"),
        }
    }

    #[test]
    fn refuses_visible_paths_outside_canonical_roots() {
        let mut spec = CanonicalNamespaceSpec::new();
        spec.rw_binds.push(Bind::new("/tmp/x", "/etc"));
        let err = build_canonical_argv(&spec, &full_support(), "cargo", &[]).unwrap_err();
        assert!(matches!(err, IsolationError::InvalidSpec { .. }));
    }

    #[test]
    fn refuses_backing_paths_inside_the_visible_world() {
        let mut spec = CanonicalNamespaceSpec::new();
        spec.rw_binds
            .push(Bind::new("/__rabs/workspace", layout::WORKSPACE));
        let err = build_canonical_argv(&spec, &full_support(), "cargo", &[]).unwrap_err();
        assert!(matches!(err, IsolationError::InvalidSpec { .. }));
    }

    #[test]
    fn binds_are_ordered_by_visible_path_regardless_of_spec_order() {
        let mut spec = CanonicalNamespaceSpec::new();
        spec.ro_binds
            .push(Bind::new("/b/toolchain", layout::TOOLCHAIN));
        spec.ro_binds.push(Bind::new("/b/git", layout::GIT));
        let one = build_canonical_argv(&spec, &full_support(), "true", &[]).unwrap();
        spec.ro_binds.reverse();
        let two = build_canonical_argv(&spec, &full_support(), "true", &[]).unwrap();
        assert_eq!(one.argv, two.argv);
    }

    #[test]
    fn env_pairs_are_sorted_into_the_argv() {
        let mut spec = CanonicalNamespaceSpec::new();
        spec.env.push(("ZED".into(), "1".into()));
        spec.env.push(("ALPHA".into(), "2".into()));
        let launch = build_canonical_argv(&spec, &full_support(), "true", &[]).unwrap();
        let s = strs(&launch.argv);
        let alpha = s.iter().position(|x| x == "ALPHA").unwrap();
        let zed = s.iter().position(|x| x == "ZED").unwrap();
        assert!(alpha < zed);
    }

    #[test]
    fn action_view_is_closed_and_strict() {
        let view = ActionViewSpec {
            input_binds: vec![Bind::new("/b/src", layout::WORKSPACE)],
            output_binds: vec![Bind::new("/b/out", format!("{}/unit1", layout::OUT))],
            env: vec![("PATH".into(), "/usr/bin".into())],
            cwd: PathBuf::from(layout::WORKSPACE),
        };
        let launch = build_action_view_argv(&view, &full_support(), "rustc", &[]).unwrap();
        let s = strs(&launch.argv);
        assert!(s.contains(&"--unshare-net".to_string()));
        assert!(launch.boundary.satisfies_strict_hermetic_linux());
        // Nothing beyond the declared binds + the documented base is bound.
        let bind_count = s
            .iter()
            .filter(|x| *x == "--ro-bind" || *x == "--bind")
            .count();
        // 1 input + 1 output + host /usr = 3 (ld.so.cache uses ro-bind-try).
        assert_eq!(bind_count, 3);
    }

    #[test]
    fn probe_on_non_linux_reports_unsupported_not_panic() {
        if cfg!(target_os = "linux") {
            return;
        }
        let support = HostIsolationSupport::probe();
        assert!(support.bubblewrap.is_none());
        assert!(!support.unprivileged_userns);
        assert!(!support.missing_for_canonical().is_empty());
    }
}
