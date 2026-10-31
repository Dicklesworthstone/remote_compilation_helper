//! Local canonical Cargo execution connected to the coordinator's rustc cache.
//!
//! This explicit profile runs selected Cargo check, build, test, run, bench or Clippy offline and locked against
//! captured inputs and a captured toolchain. Cargo itself runs at canonical
//! paths, so unit hashes and rustc arguments are stable across checkouts. A
//! fresh operation-scoped socket admits only rustc requests; the persistent
//! CAS and the ordinary daemon socket are never visible to the build.
//!
//! The selected Cargo unit graph identifies active build scripts and procedural
//! macros. Their presence, or a test/run/bench/Clippy command, disables local compiler-result authority for the whole
//! operation; eligible dependency caching requires isolated workers. Pure check/build graphs
//! retain the existing evidence-gated metadata lane; archive codegen requires an
//! isolated worker. Selected workspace compilations can execute freshly on workers;
//! unsupported rustc invocations compile normally in the namespace. Workspace
//! results never gain action-cache publication or replay authority.

pub mod service;
mod target_state;

use super::live::{CoordLive, cluster_id};
use super::live_dependency::LiveDependencyLane;
use super::live_dependency::canonical::CanonicalPaths;
use super::live_dependency::remote::{RemoteDependencies, SharedRemoteExecutions};
use super::source_delivery::control::{PreparationControl, PreparationRootGuard};
use crate::edge::live_facts::{FileSig, read_stable};
use crate::edge::server::{
    CanonicalActivity, EdgeServerConfig, canonical_edge_work, canonical_edge_work_shared,
};
use asupersync::signal::ShutdownController;
use rabs_asupersync::daemon_runtime::{
    DaemonError, DaemonRunOptions, ShutdownReceipt, SubsystemWork, run_daemon_controlled,
};
use rabs_asupersync::obligations::ObligationSet;
use rabs_asupersync::process_groups::ManagedProcessGroup;
use rabs_asupersync::region_tree::Attribution;
use rabs_asupersync::root_permits::{RootPermit, RootPermitBroker};
use rabs_asupersync::stream_drain::{DrainLimits, DrainedOutput, LiveOutputFiles};
use rabs_protocol::release_authorization::ReleaseAuthorizationMode;
use rabs_sandbox::canonical_mounts::{CanonicalMountPlan, UnitMount};
use rabs_sandbox::canonical_namespace::{
    CanonicalNamespaceSpec, HostIsolationSupport, build_canonical_argv, command_for,
};
use rabs_sandbox::cargo_check::{
    CompilationCommand, CompilationSelection, run_build_selection, validate_compilation_unit_graph,
};
use rabs_sandbox::cargo_home::CargoHomeProjection;
use rabs_sandbox::cargo_target::state::{PrivateTreeSnapshot, SourceTimestamps};
use rabs_sandbox::process_context::CommandContext;
use rabs_sandbox::source_transfer::{MAX_SOURCE_BYTES, SourceManifest};
use rabs_sandbox::toolchain_cache::{CAPACITY as TOOLCHAIN_CAPACITY, ToolchainPool};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, IsTerminal, Write};
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use target_state::{TargetCacheConfig, TargetState};

const PROFILE_VERSION: &str = "canonical-compile-local-v1";
const CARGO: &str = "/__rabs/toolchain/bin/cargo";
const CARGO_CLIPPY: &str = "/__rabs/toolchain/bin/cargo-clippy";
const CLIPPY_DRIVER: &str = "/__rabs/toolchain/bin/clippy-driver";
const RUSTC: &str = "/__rabs/toolchain/bin/rustc";
const RUSTDOC: &str = "/__rabs/toolchain/bin/rustdoc";
const TARGET: &str = "/__rabs/out/cargo";
const WRAPPER: &str = "/__rabs/home/control/rabs-wrap";
const SOCKET: &str = "/__rabs/home/control/rustc.sock";
const MAX_GRAPH_BYTES: u64 = 16 * 1024 * 1024;

/// All host locations are selected by the operator, not by Cargo or a wrapper
/// request. State and operation parents must be owned, private directories.
/// `vendor` is relative to `source_root`; `cargo_home_source` is absolute.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Profile {
    version: String,
    source_root: PathBuf,
    toolchain_root: PathBuf,
    state_root: PathBuf,
    operation_root: PathBuf,
    wrapper: PathBuf,
    /// A persistent coordinator can own several independent canonical builds.
    /// This socket stays outside the compiler namespace.
    service_socket: Option<PathBuf>,
    #[serde(default)]
    command: CompilationCommand,
    #[serde(default = "default_manifest")]
    manifest: String,
    vendor: Option<String>,
    cargo_home_source: Option<PathBuf>,
    /// An absent check selection retains the library-only default. An explicit
    /// empty selection and builds use Cargo's ordinary default members/targets.
    selection: Option<CompilationSelection>,
    #[serde(default = "default_jobs")]
    jobs: u32,
    #[serde(default = "default_timeout")]
    timeout_seconds: u64,
    /// Literal application inputs for Cargo and its descendants. No values are
    /// inherited from the client or service process, and tool/control variables
    /// remain owned by the canonical driver.
    #[serde(default, deserialize_with = "project_environment")]
    env: BTreeMap<String, String>,
    /// Private Cargo freshness across invocations. The operator must advance
    /// the epoch when host tools/libraries visible through /usr change.
    target_cache: Option<TargetCacheConfig>,
}

fn project_environment<'de, D>(deserializer: D) -> Result<BTreeMap<String, String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct EnvironmentVisitor;
    impl<'de> serde::de::Visitor<'de> for EnvironmentVisitor {
        type Value = BTreeMap<String, String>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("an object of unique literal environment bindings")
        }

        fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
        where
            M: serde::de::MapAccess<'de>,
        {
            let mut environment = BTreeMap::new();
            while let Some((name, value)) = map.next_entry::<String, String>()? {
                if environment.insert(name, value).is_some() {
                    return Err(serde::de::Error::custom(
                        "duplicate canonical environment name",
                    ));
                }
            }
            Ok(environment)
        }
    }

    deserializer.deserialize_map(EnvironmentVisitor)
}

fn default_manifest() -> String {
    "Cargo.toml".to_owned()
}
fn default_jobs() -> u32 {
    1
}
fn default_timeout() -> u64 {
    1800
}
fn invalid(reason: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, reason.into())
}
fn require(condition: bool, reason: &str) -> io::Result<()> {
    if condition {
        Ok(())
    } else {
        Err(invalid(reason))
    }
}

fn plain_absolute(path: &Path) -> bool {
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

fn relative_member(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 1024
        && !path.contains(['\\', ':'])
        && !path.chars().any(char::is_control)
        && path.split('/').all(|part| !matches!(part, "" | "." | ".."))
}

fn ordinary_directory(path: &Path) -> io::Result<()> {
    require(
        plain_absolute(path),
        "profile roots must be ordinary absolute paths",
    )?;
    for ancestor in path.ancestors().take_while(|path| path.parent().is_some()) {
        require(
            fs::symlink_metadata(ancestor)?.is_dir(),
            "profile root ancestry must contain only ordinary directories",
        )?;
    }
    Ok(())
}

fn private_directory(path: &Path) -> io::Result<()> {
    ordinary_directory(path)?;
    let metadata = fs::symlink_metadata(path)?;
    require(
        metadata.uid() == rustix::process::geteuid().as_raw() && metadata.mode() & 0o077 == 0,
        "state and operation roots must be owned private directories (0700)",
    )
}

fn create_private(path: &Path) -> io::Result<()> {
    fs::DirBuilder::new().mode(0o700).create(path)
}

fn overlap(first: &Path, second: &Path) -> bool {
    first.starts_with(second) || second.starts_with(first)
}

/// A canonical profile has its own authority/CAS namespace. The advisory file
/// lock is held from admission through the last process/session join, so a
/// second invocation cannot advance the first invocation's coordinator term.
#[derive(Debug)]
struct StateOwner {
    root: PathBuf,
    root_identity: (u64, u64),
    lock: File,
}
impl StateOwner {
    fn acquire(parent: &Path) -> io::Result<Self> {
        let root = parent.join("canonical-compile-v1");
        match create_private(&root) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => private_directory(&root)?,
            Err(error) => return Err(error),
        }
        let lock_path = root.join("owner.lock");
        let flags = rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(i32::try_from(flags.bits()).map_err(io::Error::other)?)
            .open(&lock_path)?;
        let metadata = file.metadata()?;
        require(
            metadata.is_file()
                && metadata.uid() == rustix::process::geteuid().as_raw()
                && metadata.mode() & 0o077 == 0
                && FileSig::of(&metadata) == FileSig::of(&fs::symlink_metadata(&lock_path)?),
            "canonical state lock must be an owned private ordinary file",
        )?;
        file.try_lock().map_err(|error| {
            io::Error::new(
                io::ErrorKind::WouldBlock,
                format!("canonical state is busy or cannot be locked: {error}"),
            )
        })?;
        let root_metadata = fs::symlink_metadata(&root)?;
        Ok(Self {
            root,
            root_identity: (root_metadata.dev(), root_metadata.ino()),
            lock: file,
        })
    }

    fn verify(&self) -> io::Result<()> {
        private_directory(&self.root)?;
        let root = fs::symlink_metadata(&self.root)?;
        let named_lock = fs::symlink_metadata(self.root.join("owner.lock"))?;
        require(
            (root.dev(), root.ino()) == self.root_identity
                && named_lock.is_file()
                && named_lock.uid() == rustix::process::geteuid().as_raw()
                && named_lock.mode() & 0o077 == 0
                && FileSig::of(&named_lock) == FileSig::of(&self.lock.metadata()?),
            "canonical state owner generation changed",
        )
    }
}

/// One persistent authority for all builds admitted by a canonical service.
/// Operation edges share this coordinator and worker pool, while their paths,
/// cancellation, output files and completion barriers remain independent.
pub(super) struct SharedRuntime {
    state: Arc<StateOwner>,
    parent: PathBuf,
    coord: Arc<CoordLive>,
    lane: LiveDependencyLane,
    remote: Option<Arc<RemoteDependencies>>,
    remote_executions: Option<Arc<SharedRemoteExecutions>>,
    roots: Arc<RootPermitBroker>,
    jobs_per_root: u32,
    target_cache_lock: Arc<Mutex<()>>,
    toolchains: ToolchainPool,
    build_identity: String,
    release_mode: ReleaseAuthorizationMode,
    stopped: Arc<AtomicBool>,
    server: Mutex<Option<ServerOwner>>,
}

impl SharedRuntime {
    pub(super) fn start(
        state_root: &Path,
        release_mode: ReleaseAuthorizationMode,
        build_identity: String,
        max_roots: usize,
        jobs_per_root: u32,
    ) -> io::Result<Arc<Self>> {
        Self::start_with_remote(
            state_root,
            release_mode,
            build_identity,
            max_roots,
            jobs_per_root,
            RemoteDependencies::from_canonical_environment,
        )
    }

    fn start_with_remote(
        state_root: &Path,
        release_mode: ReleaseAuthorizationMode,
        build_identity: String,
        max_roots: usize,
        jobs_per_root: u32,
        remote: impl FnOnce(&Path) -> io::Result<Option<Arc<RemoteDependencies>>>,
    ) -> io::Result<Arc<Self>> {
        require(
            (1..=4096).contains(&max_roots) && (1..=4096).contains(&jobs_per_root),
            "canonical service root and per-root job limits must be between 1 and 4096",
        )?;
        private_directory(state_root)?;
        let state = Arc::new(StateOwner::acquire(state_root)?);
        // The state owner stays locked through pool shutdown. Every returned
        // lease separately owns its private captured tree through the last
        // planning, execution or worker upload that uses it.
        let toolchains = ToolchainPool::new(
            &state.root,
            TOOLCHAIN_CAPACITY,
            rabs_cas::materialization::try_verified_reflink,
        )?;
        let cas = Arc::new(
            crate::janitor::store::mount_and_reconcile(&state.root.join("cas"))
                .map_err(io::Error::other)?,
        );
        let coord = Arc::new(
            CoordLive::with_cas(cas)
                .with_release_authorization(build_identity.clone(), release_mode),
        );
        let remote = remote(&state.root.join("shadow"))?;
        let remote_executions = remote
            .as_ref()
            .map(|pool| SharedRemoteExecutions::new(pool.worker_count()));
        let stopped = Arc::new(AtomicBool::new(false));
        let controller = Arc::new(ShutdownController::new());
        let options = DaemonRunOptions {
            coord_work: Some(stop_on_exit(
                coordinator_work(Arc::clone(&coord)),
                Arc::clone(&stopped),
                Arc::clone(&controller),
            )),
            ..DaemonRunOptions::default()
        };
        let worker_controller = Arc::clone(&controller);
        let worker = std::thread::Builder::new()
            .name("rabs-canonical-service-coord".into())
            .spawn(move || run_daemon_controlled(options, worker_controller))?;
        let server = ServerOwner {
            controller,
            worker: Some(worker),
            normal_shutdown: None,
        };
        let started = Instant::now();
        loop {
            if stopped.load(Ordering::Acquire)
                || server
                    .worker
                    .as_ref()
                    .is_none_or(|worker| worker.is_finished())
            {
                return Err(io::Error::other(
                    "canonical service coordinator stopped during startup",
                ));
            }
            if coord.available() && coord.authority().is_some() {
                break;
            }
            if started.elapsed() >= Duration::from_secs(30) {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "canonical service coordinator startup timed out",
                ));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        Ok(Arc::new(Self {
            state,
            parent: state_root.to_path_buf(),
            lane: LiveDependencyLane::new(Arc::clone(&coord)),
            coord,
            remote,
            remote_executions,
            roots: RootPermitBroker::new(max_roots),
            jobs_per_root,
            target_cache_lock: Arc::new(Mutex::new(())),
            toolchains,
            build_identity,
            release_mode,
            stopped,
            server: Mutex::new(Some(server)),
        }))
    }

    pub(super) fn healthy(&self) -> bool {
        !self.stopped.load(Ordering::Acquire)
            && self.state.verify().is_ok()
            && self.coord.available()
            && self.coord.authority().is_some()
            && self.server.lock().is_ok_and(|server| {
                server.as_ref().is_some_and(|owner| {
                    owner
                        .worker
                        .as_ref()
                        .is_some_and(|worker| !worker.is_finished())
                })
            })
    }

    /// The service first seals admission, cancels/joins operations and only
    /// then releases this authority. Dropping the last Arc is the RAII backstop.
    pub(super) fn shutdown(&self) -> io::Result<()> {
        require(
            self.roots.active() == 0,
            "canonical service still owns active Cargo roots",
        )?;
        self.stopped.store(true, Ordering::Release);
        // Connections own subscriber interest, not the compiler. Finish every
        // service-owned transport before releasing coordinator authority or the
        // input/toolchain roots retained by that execution.
        let executions = self
            .remote_executions
            .as_ref()
            .map_or(Ok(()), |owner| owner.shutdown());
        let toolchains = self.toolchains.shutdown();
        let server = self
            .server
            .lock()
            .map_err(|_| io::Error::other("canonical service owner lock poisoned"))?
            .take();
        if let Some(server) = server {
            require(
                server.finish()?.clean(),
                "canonical service coordinator did not drain cleanly",
            )?;
        }
        executions.map_err(io::Error::other)?;
        toolchains?;
        Ok(())
    }

    fn acquire_root(&self, stopped: &AtomicBool, budget: Duration) -> io::Result<RootAdmission> {
        let deadline = Instant::now()
            .checked_add(budget)
            .ok_or_else(|| invalid("canonical root admission deadline overflow"))?;
        let mut obligations = ObligationSet::default();
        loop {
            if stopped.load(Ordering::Acquire) || !self.healthy() {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "canonical Cargo root admission cancelled",
                ));
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "canonical Cargo root admission timed out",
                ));
            }
            if let Ok(permit) = self
                .roots
                .acquire_timeout(&mut obligations, remaining.min(Duration::from_millis(50)))
            {
                let admitted = RootAdmission {
                    permit: Some(permit),
                    obligations,
                    _state: Arc::clone(&self.state),
                };
                if stopped.load(Ordering::Acquire) || !self.healthy() {
                    return Err(io::Error::new(
                        io::ErrorKind::Interrupted,
                        "canonical Cargo root admission cancelled",
                    ));
                }
                return Ok(admitted);
            }
        }
    }
}

impl Drop for SharedRuntime {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::Release);
        if let Some(executions) = &self.remote_executions {
            let _ = executions.shutdown();
        }
        let _ = self.toolchains.shutdown();
        // Explicit join precedes field destruction, particularly StateOwner's
        // process lock. The last Arc cannot disappear while an operation runs.
        let server = match self.server.get_mut() {
            Ok(server) => server.take(),
            Err(poisoned) => poisoned.into_inner().take(),
        };
        if let Some(server) = server {
            let _ = server.finish();
        }
    }
}

#[derive(Debug)]
struct RootAdmission {
    permit: Option<RootPermit>,
    obligations: ObligationSet,
    // Failed cleanup retains the charge and this lock together. A new service
    // cannot acquire the same authority while an unresolved root still exists.
    _state: Arc<StateOwner>,
}

impl Drop for RootAdmission {
    fn drop(&mut self) {
        if let Some(permit) = self.permit.take() {
            let result = permit.release_into(&mut self.obligations);
            debug_assert!(
                result.is_ok(),
                "owned Cargo root obligation must resolve once"
            );
        }
    }
}

/// Compiler output and driver events belong to one caller. The service path
/// never inherits the daemon's stdio, and its files have one aggregate bound.
enum OperationOutput {
    Inherit,
    Captured {
        stdout: File,
        stderr: File,
        maximum: u64,
        used: u64,
        cargo_maximum: u64,
    },
}

impl OperationOutput {
    fn captured(stdout: File, stderr: File, maximum: u64) -> io::Result<Self> {
        let first = stdout.metadata()?;
        let second = stderr.metadata()?;
        require(
            maximum > 0
                && [&first, &second].iter().all(|metadata| {
                    metadata.is_file()
                        && metadata.uid() == rustix::process::geteuid().as_raw()
                        && metadata.mode() & 0o077 == 0
                        && metadata.nlink() == 1
                        && metadata.len() == 0
                })
                && (first.dev(), first.ino()) != (second.dev(), second.ino()),
            "canonical operation output needs separate empty private ordinary files and a byte bound",
        )?;
        let total = maximum
            .checked_add(MAX_GRAPH_BYTES)
            .and_then(|value| value.checked_add(64 * 1024))
            .ok_or_else(|| invalid("canonical output budget overflow"))?;
        Ok(Self::Captured {
            stdout,
            stderr,
            maximum: total,
            used: 0,
            cargo_maximum: maximum,
        })
    }

    fn reserve(&mut self, bytes: u64) -> io::Result<()> {
        if let Self::Captured { maximum, used, .. } = self {
            let next = used
                .checked_add(bytes)
                .filter(|next| *next <= *maximum)
                .ok_or_else(|| {
                    io::Error::other("canonical operation output exceeded its byte bound")
                })?;
            *used = next;
        }
        Ok(())
    }

    fn line(&mut self, line: &str) -> io::Result<()> {
        self.reserve((line.len() as u64).saturating_add(1))?;
        match self {
            Self::Inherit => writeln!(io::stderr().lock(), "{line}"),
            Self::Captured { stderr, .. } => writeln!(stderr, "{line}"),
        }
    }

    fn event(&mut self, value: Value) -> io::Result<()> {
        self.line(&value.to_string())
    }

    fn warning(&mut self, stage: &str, error: &io::Error) -> io::Result<()> {
        self.event(json!({"kind":"canonical-target-state-unavailable",
            "stage":stage, "reason":error.to_string(), "action_cache_authority":false}))
    }

    fn replay(&mut self, output: &DrainedOutput) -> io::Result<()> {
        let bytes = output
            .stdout
            .total_bytes()
            .checked_add(output.stderr.total_bytes())
            .ok_or_else(|| invalid("canonical diagnostic length overflow"))?;
        self.reserve(bytes)?;
        match self {
            Self::Inherit => replay(output),
            Self::Captured { stdout, stderr, .. } => {
                io::copy(&mut output.stdout.reader()?, stdout)?;
                io::copy(&mut output.stderr.reader()?, stderr)?;
                stdout.flush()?;
                stderr.flush()
            }
        }
    }

    fn cargo_output(&self, directory: PathBuf, inherit_stdin: bool) -> io::Result<CargoOutput> {
        Ok(match self {
            Self::Inherit => CargoOutput::Inherit { inherit_stdin },
            Self::Captured {
                stdout,
                stderr,
                maximum,
                used,
                cargo_maximum,
            } => CargoOutput::Stream {
                directory,
                maximum: (*cargo_maximum).min(maximum.saturating_sub(*used)),
                files: LiveOutputFiles::new(stdout.try_clone()?, stderr.try_clone()?)?,
            },
        })
    }
}

impl Profile {
    fn validate(&self) -> io::Result<()> {
        require(
            self.version == PROFILE_VERSION,
            "unsupported canonical compilation profile version",
        )?;
        require(
            (1..=4096).contains(&self.jobs),
            "jobs must be between 1 and 4096",
        )?;
        require(
            (1..=7200).contains(&self.timeout_seconds),
            "timeout_seconds must be between 1 and 7200",
        )?;
        if let Some(cache) = &self.target_cache {
            cache.validate()?;
        }
        self.compilation_args()?;
        self.command_environment()?;
        require(
            relative_member(&self.manifest),
            "manifest must be an ordinary relative path",
        )?;
        require(
            Path::new(&self.manifest)
                .file_name()
                .is_some_and(|name| name == "Cargo.toml"),
            "manifest must name Cargo.toml",
        )?;
        require(
            !(self.vendor.is_some() && self.cargo_home_source.is_some()),
            "choose vendor or cargo_home_source, not both",
        )?;
        if let Some(vendor) = &self.vendor {
            require(
                relative_member(vendor),
                "vendor must be an ordinary relative path",
            )?;
        }
        ordinary_directory(&self.source_root)?;
        ordinary_directory(&self.toolchain_root)?;
        private_directory(&self.state_root)?;
        private_directory(&self.operation_root)?;
        let mut roots = vec![
            &self.source_root,
            &self.toolchain_root,
            &self.state_root,
            &self.operation_root,
        ];
        if let Some(home) = &self.cargo_home_source {
            ordinary_directory(home)?;
            roots.push(home);
        }
        for (index, root) in roots.iter().enumerate() {
            for other in &roots[index + 1..] {
                require(
                    !overlap(root, other),
                    "profile input and state roots must not overlap",
                )?;
            }
        }
        if let Some(socket) = &self.service_socket {
            require(
                plain_absolute(socket)
                    && !socket.starts_with(&self.source_root)
                    && !socket.starts_with(&self.toolchain_root)
                    && !socket.starts_with(&self.operation_root)
                    && self
                        .cargo_home_source
                        .as_ref()
                        .is_none_or(|root| !socket.starts_with(root)),
                "service_socket must be an ordinary absolute path outside captured inputs and operation roots",
            )?;
        }
        require(
            plain_absolute(&self.wrapper),
            "wrapper must be an absolute executable file",
        )?;
        ordinary_directory(
            self.wrapper
                .parent()
                .ok_or_else(|| invalid("wrapper parent"))?,
        )?;
        let metadata = fs::symlink_metadata(&self.wrapper)?;
        require(
            metadata.is_file() && metadata.mode() & 0o111 != 0,
            "wrapper must be an ordinary executable file",
        )?;
        require(
            !self.wrapper.starts_with(&self.source_root)
                && !self.wrapper.starts_with(&self.state_root)
                && !self.wrapper.starts_with(&self.operation_root),
            "wrapper must be outside captured source and mutable operation/state roots",
        )
    }

    fn manifest_path(&self) -> String {
        format!("/__rabs/workspace/{}", self.manifest)
    }

    fn cwd(&self) -> PathBuf {
        let mut cwd = PathBuf::from("/__rabs/workspace");
        if let Some(parent) = Path::new(&self.manifest).parent()
            && !parent.as_os_str().is_empty()
        {
            cwd.push(parent);
        }
        cwd
    }

    fn program(&self) -> &'static str {
        if self.command == CompilationCommand::Clippy {
            CARGO_CLIPPY
        } else {
            CARGO
        }
    }

    fn compilation_prefix(&self) -> io::Result<Vec<String>> {
        self.selected_prefix(self.command, self.selection.as_ref())
    }

    fn selected_prefix(
        &self,
        command: CompilationCommand,
        selection: Option<&CompilationSelection>,
    ) -> io::Result<Vec<String>> {
        let mut args = match selection {
            Some(selection) => selection.cargo_arguments(command)?,
            None if command == CompilationCommand::Check => {
                vec!["check".into(), "--lib".into()]
            }
            None => vec![command.as_str().into()],
        };
        args.extend([
            "--offline".into(),
            "--locked".into(),
            "--manifest-path".into(),
            self.manifest_path(),
            "--message-format=json".into(),
            "--jobs".into(),
            self.jobs.to_string(),
        ]);
        Ok(args)
    }

    fn compilation_args(&self) -> io::Result<Vec<String>> {
        let mut args = self.compilation_prefix()?;
        if let Some(selection) = &self.selection {
            args.extend(selection.runtime_arguments(self.command)?);
        }
        Ok(args)
    }

    fn graph_args(&self, run_selection: Option<&CompilationSelection>) -> io::Result<Vec<String>> {
        let mut args = if self.command == CompilationCommand::Run {
            self.selected_prefix(
                CompilationCommand::Build,
                Some(run_selection.ok_or_else(|| {
                    invalid("Cargo run graph requires a resolved runnable target")
                })?),
            )?
        } else {
            self.compilation_prefix()?
        };
        // These are Cargo arguments. Harness arguments after `--` must never
        // swallow the nonexecuting graph switch or alter the planning command.
        args.extend([
            "--unit-graph".into(),
            "-Z".into(),
            "unstable-options".into(),
        ]);
        if self.command == CompilationCommand::Clippy
            && let Some(selection) = &self.selection
        {
            args.extend(selection.runtime_arguments(self.command)?);
        }
        Ok(args)
    }

    fn no_run(&self) -> bool {
        matches!(
            self.command,
            CompilationCommand::Test | CompilationCommand::Bench
        ) && self
            .selection
            .as_ref()
            .is_some_and(|selection| selection.no_run)
    }

    fn inherits_stdin(&self) -> bool {
        self.command == CompilationCommand::Run
            || (self.command == CompilationCommand::Bench && !self.no_run())
    }

    fn validate_stdin(&self, terminal: bool) -> io::Result<()> {
        // Managed children have their own process group. Reading the caller's
        // controlling terminal could stop that group with SIGTTIN; supporting
        // interactive job control needs a separate, owned terminal/session.
        require(
            !self.inherits_stdin() || !terminal,
            "canonical run/bench requires nonterminal stdin: redirect input from a pipe, file, or /dev/null, or run a delivered build outside this noninteractive profile",
        )
    }

    /// Use the same exact environment for retained request identity, canonical
    /// Cargo planning and execution. CommandContext owns identifier, value and
    /// aggregate bounds, including the additional driver-owned entries.
    fn command_environment(&self) -> io::Result<Vec<(String, String)>> {
        require(
            !self.env.keys().any(|name| {
                matches!(
                    name.as_str(),
                    "CARGO" | "RUSTC" | "RUSTDOC" | "RUSTFLAGS" | "RUSTDOCFLAGS" | "GLIBC_TUNABLES"
                ) || [
                    "CARGO_", "RUSTUP_", "RUSTC_", "RUSTDOC_", "CLIPPY_", "RABS_", "RCH_", "LD_",
                    "DYLD_",
                ]
                .iter()
                .any(|prefix| name.starts_with(prefix))
            }),
            "canonical env cannot replace worker, compiler or preparation controls",
        )?;
        let mut environment = vec![
            ("CARGO_INCREMENTAL".into(), "0".into()),
            ("CARGO_TARGET_DIR".into(), TARGET.into()),
            ("RUSTC".into(), RUSTC.into()),
        ];
        if self.command == CompilationCommand::Test {
            environment.push(("RUSTDOC".into(), RUSTDOC.into()));
        }
        if self.command == CompilationCommand::Clippy {
            environment.push(("CARGO".into(), CARGO.into()));
        }
        environment.extend(
            self.env
                .iter()
                .map(|(name, value)| (name.clone(), value.clone())),
        );
        let cwd = self.cwd();
        let context = CommandContext::new(
            cwd.to_str()
                .ok_or_else(|| invalid("canonical manifest path must be UTF-8"))?,
            environment,
        )
        .map_err(|error| invalid(error.to_string()))?;
        Ok(context.environment().to_vec())
    }

    fn source_specification(&self) -> io::Result<Value> {
        let mut source = json!({"manifest":self.manifest});
        if let Some(vendor) = &self.vendor {
            source["vendor"] = json!(vendor);
        }
        if let Some(home) = &self.cargo_home_source {
            source["cargo_home_source"] = json!(home);
        }
        let environment: BTreeMap<_, _> = self.command_environment()?.into_iter().collect();
        Ok(json!({
            "kind":"canonical-exec", "request_id":1, "program":self.program(),
            "args":self.compilation_args()?, "toolchain_source":self.toolchain_root,
            "cargo_source":source,
            "command_context":{"version":"env-cwd-v1", "cwd":self.cwd(),
                "env":environment}
        }))
    }
}

/// Resolve only the graph query's run target. Every probe runs the captured
/// Cargo inside the same immutable namespace before a wrapper endpoint exists.
/// The actual run command and its program arguments remain unchanged.
#[allow(clippy::too_many_arguments)]
fn resolve_run_selection(
    profile: &Profile,
    spec: &CanonicalNamespaceSpec,
    support: &HostIsolationSupport,
    owner: &Path,
    timeout: Duration,
    stopped: &AtomicBool,
    shared: Option<&SharedRuntime>,
    destination: &mut OperationOutput,
) -> io::Result<CompilationSelection> {
    let selection = profile.selection.clone().unwrap_or_default();
    if !selection.bin.is_empty() || !selection.example.is_empty() {
        return run_build_selection(&selection, &Value::Null, None);
    }
    let metadata_args = vec![
        "metadata".into(),
        "--no-deps".into(),
        "--format-version=1".into(),
        "--offline".into(),
        "--locked".into(),
        "--manifest-path".into(),
        profile.manifest_path(),
    ];
    let metadata = execute_controlled(
        spec,
        support,
        CARGO,
        &metadata_args,
        CargoOutput::Capture {
            directory: owner.join("run-metadata-drain"),
            maximum: MAX_GRAPH_BYTES,
        },
        timeout,
        stopped,
        shared,
        destination,
    )?;
    if !metadata.status.success() {
        destination.replay(&metadata)?;
        return Err(invalid(
            "captured Cargo metadata could not resolve the run target",
        ));
    }
    let metadata: Value = serde_json::from_reader(metadata.stdout.reader()?)?;
    let package_id = if let Some(package) = selection.packages.first() {
        let args = vec![
            "pkgid".into(),
            "--offline".into(),
            "--locked".into(),
            "--manifest-path".into(),
            profile.manifest_path(),
            "--package".into(),
            package.clone(),
        ];
        let output = execute_controlled(
            spec,
            support,
            CARGO,
            &args,
            CargoOutput::Capture {
                directory: owner.join("run-package-drain"),
                maximum: MAX_GRAPH_BYTES,
            },
            timeout,
            stopped,
            shared,
            destination,
        )?;
        if !output.status.success() {
            destination.replay(&output)?;
            return Err(invalid(
                "captured Cargo pkgid could not resolve the selected run package",
            ));
        }
        Some(
            io::read_to_string(output.stdout.reader()?)?
                .trim_end_matches(['\n', '\r'])
                .to_owned(),
        )
    } else {
        None
    };
    run_build_selection(&selection, &metadata, package_id.as_deref())
}

/// Run the explicit local profile with the SAME release policy and build
/// identity as the normal daemon. This entry point intentionally has no
/// implicit advisory-policy overload.
///
/// Planning output is captured under a byte bound. The actual compilation inherits
/// stdout/stderr, so diagnostics and Cargo JSON reach the caller immediately
/// with their original bytes and native pipe/terminal behavior. The exit code
/// is Cargo's real result; a timeout, cancellation or incomplete process-group
/// cleanup is an error even when a signal handler managed to exit zero.
pub fn run_profile_with_release(
    path: &Path,
    release_mode: ReleaseAuthorizationMode,
    build_identity: String,
) -> io::Result<i32> {
    let (_, bytes) = read_stable(path, 64 * 1024)?;
    let profile: Profile =
        serde_json::from_slice(&bytes).map_err(|error| invalid(error.to_string()))?;
    // Refuse unsupported terminal input before validating source roots,
    // acquiring state, probing namespaces, or capturing any source bytes.
    profile.validate_stdin(std::io::stdin().is_terminal())?;
    if profile.service_socket.is_some() && profile.inherits_stdin() {
        return Err(invalid(
            "canonical service does not accept commands with inherited stdin",
        ));
    }
    profile.validate()?;
    if profile.service_socket.is_some() {
        return service::run_client_profile(path, release_mode, build_identity);
    }
    run_operation(
        profile,
        release_mode,
        build_identity,
        None,
        Arc::new(AtomicBool::new(false)),
        OperationOutput::Inherit,
    )
}

pub(super) fn run_shared_profile(
    bytes: &[u8],
    runtime: Arc<SharedRuntime>,
    stopped: Arc<AtomicBool>,
    stdout: File,
    stderr: File,
    maximum: u64,
) -> io::Result<i32> {
    require(
        bytes.len() <= 64 * 1024,
        "canonical profile exceeds its byte bound",
    )?;
    let profile: Profile =
        serde_json::from_slice(bytes).map_err(|error| invalid(error.to_string()))?;
    require(
        !profile.inherits_stdin(),
        "canonical service does not accept commands with inherited stdin",
    )?;
    require(
        profile.service_socket.is_some()
            && profile.state_root == runtime.parent
            && profile.jobs <= runtime.jobs_per_root,
        "canonical profile must name this service state and stay within its per-root job grant",
    )?;
    profile.validate()?;
    require(
        runtime.healthy(),
        "canonical service coordinator is unavailable",
    )?;
    let output = OperationOutput::captured(stdout, stderr, maximum)?;
    run_operation(
        profile,
        runtime.release_mode,
        runtime.build_identity.clone(),
        Some(runtime),
        stopped,
        output,
    )
}

fn run_operation(
    profile: Profile,
    release_mode: ReleaseAuthorizationMode,
    build_identity: String,
    shared: Option<Arc<SharedRuntime>>,
    stopped: Arc<AtomicBool>,
    mut output: OperationOutput,
) -> io::Result<i32> {
    let timeout = Duration::from_secs(profile.timeout_seconds);
    let cancelled = || {
        stopped.load(Ordering::Acquire) || shared.as_ref().is_some_and(|runtime| !runtime.healthy())
    };
    let acquire_root = |budget| {
        shared
            .as_ref()
            .expect("shared preparation admission is installed only for a service")
            .acquire_root(&stopped, budget)
            .map(PreparationRootGuard::new)
    };
    let preparation =
        PreparationControl::new(&cancelled, shared.as_ref().map(|_| &acquire_root as &_));
    preparation.checkpoint()?;
    let standalone_state = shared
        .is_none()
        .then(|| StateOwner::acquire(&profile.state_root))
        .transpose()?;
    let state_root = match &shared {
        Some(runtime) => runtime.state.root.clone(),
        None => standalone_state
            .as_ref()
            .expect("standalone state owner")
            .root
            .clone(),
    };
    preparation.checkpoint()?;
    let support = HostIsolationSupport::probe();
    require(
        support.missing_for_canonical().is_empty(),
        &format!(
            "canonical local compilation requires measured namespace support: {:?}",
            support.missing_for_canonical()
        ),
    )?;
    // A service owns this warmup independently of its waiting clients. The
    // original source generation is checked at acquisition; this operation
    // then executes the exact retained image even if that source later changes.
    let retained_toolchain = shared
        .as_ref()
        .map(|runtime| {
            runtime
                .toolchains
                .acquire(&profile.toolchain_root, timeout, cancelled)
        })
        .transpose()?;
    let owner = Arc::new(
        tempfile::Builder::new()
            .prefix("rabs-compile-")
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir_in(&profile.operation_root)?,
    );
    let bundle = owner.path().join("bundle");
    let (_report, source) = super::source_delivery::prepare_local_bundle_controlled(
        &profile.source_root,
        &profile.source_specification()?,
        &bundle,
        retained_toolchain.clone(),
        &preparation,
    )?;
    let (_, request_bytes) = read_stable(
        &bundle.join("request.json"),
        super::worker_delivery::MAX_FRAME_BYTES as u64,
    )?;
    let request: Value = serde_json::from_slice(&request_bytes)?;
    let source_root = source
        .sealed_root()
        .ok_or_else(|| invalid("source was not sealed"))?;
    let cargo_projection = request
        .get("cargo_home")
        .map(|home| {
            let version = home["version"]
                .as_str()
                .ok_or_else(|| invalid("Cargo home version missing"))?;
            let prefix = home["prefix"]
                .as_str()
                .ok_or_else(|| invalid("Cargo home prefix missing"))?;
            CargoHomeProjection::for_version(version, prefix, source.manifest())
        })
        .transpose()?;
    let cargo_home = cargo_projection
        .as_ref()
        .map(|projection| projection.prepare(&source, &owner.path().join("inputs"), cancelled))
        .transpose()?;
    let captured_workspace = cargo_home
        .as_ref()
        .and_then(|home| home.projected_workspace())
        .unwrap_or(source_root)
        .to_path_buf();
    let workspace_manifest = cargo_projection
        .as_ref()
        .and_then(CargoHomeProjection::workspace_manifest)
        .unwrap_or(source.manifest());
    // Timestamp restoration may only touch an independently owned runtime
    // view. Keep the original sealed source/projection and its witnesses exact.
    let mut target_reuse_enabled = profile.target_cache.is_some();
    let workspace = if target_reuse_enabled {
        let copy = || -> io::Result<PathBuf> {
            let runtime = owner.path().join("runtime-workspace");
            create_private(&runtime)?;
            let snapshot =
                PrivateTreeSnapshot::capture(&captured_workspace, MAX_SOURCE_BYTES, &cancelled)?;
            snapshot.restore_into_with_cloner(
                &captured_workspace,
                &runtime,
                &cancelled,
                rabs_cas::materialization::try_verified_reflink,
            )?;
            Ok(runtime)
        };
        match copy() {
            Ok(runtime) => runtime,
            Err(error) => {
                preparation.checkpoint()?;
                // A failed optional copy is never mounted. Verify the original
                // exact inputs again, then execute cold without retiming them.
                SourceTimestamps::capture(&captured_workspace, workspace_manifest, &cancelled)?;
                output.warning("workspace-copy", &error)?;
                target_reuse_enabled = false;
                captured_workspace
            }
        }
    } else {
        captured_workspace
    };
    let home_root = owner.path().join("home");
    let mut target_root = owner.path().join("target");
    create_private(&home_root)?;
    create_private(&target_root)?;
    let cargo_root = if let Some(home) = &cargo_home {
        home.root().to_path_buf()
    } else {
        let path = owner.path().join("cargo-home");
        create_private(&path)?;
        path
    };
    let toolchain = retained_toolchain.as_ref().map_or_else(
        || bundle.join("toolchain"),
        |retained| retained.root().to_path_buf(),
    );
    let mut plan = CanonicalMountPlan::new(&toolchain, &workspace, &cargo_root, &home_root);
    plan.out_units.push(UnitMount {
        unit: "cargo".into(),
        backing: target_root.clone(),
    });
    plan.extra_env.extend(profile.command_environment()?);
    let mut spec = plan.to_spec().map_err(|error| invalid(error.to_string()))?;
    spec.cwd = profile.cwd();
    // Source and HOME are immutable inside the build. In particular, mounting
    // the control directory below a writable HOME would let a later parent
    // bind obscure its protection in the namespace builder's mount ordering.
    make_read_only(&mut spec, "/__rabs/workspace")?;
    make_read_only(&mut spec, "/__rabs/home")?;
    let paths = CanonicalPaths::new_with_retained_toolchain(
        owner.clone(),
        vec![
            ("/__rabs/workspace".into(), workspace.clone()),
            ("/__rabs/cargo-home".into(), cargo_root.clone()),
            ("/__rabs/toolchain".into(), toolchain.clone()),
            (TARGET.into(), target_root.clone()),
            ("/__rabs/home".into(), home_root.clone()),
        ],
        retained_toolchain.clone(),
    )
    .map_err(io::Error::other)?;
    if profile.command == CompilationCommand::Clippy {
        for program in [CARGO_CLIPPY, CLIPPY_DRIVER] {
            let physical = paths
                .physical(Path::new(program))
                .map_err(io::Error::other)?;
            let metadata = fs::symlink_metadata(physical)?;
            require(
                metadata.is_file() && metadata.mode() & 0o111 != 0,
                "Clippy requires captured ordinary executable bin/cargo-clippy and bin/clippy-driver",
            )?;
        }
    }
    preparation.checkpoint()?;
    if let Some(retained) = &retained_toolchain {
        retained.image().verify_retained_generation(cancelled)?;
    }
    let compilation_args = profile.compilation_args()?;
    // Ask the captured Cargo for the exact units this command would compile.
    // Metadata's package list includes inactive optional/dev targets and cannot
    // establish which build scripts or proc macros a selected check executes.
    // The unit-graph query does not compile/run units, and the cache endpoint
    // does not exist yet. Unsupported Cargo versions fail closed here.
    let run_selection = if profile.command == CompilationCommand::Run {
        Some(resolve_run_selection(
            &profile,
            &spec,
            &support,
            owner.path(),
            timeout,
            &stopped,
            shared.as_deref(),
            &mut output,
        )?)
    } else {
        None
    };
    let graph_args = profile.graph_args(run_selection.as_ref())?;
    let planned = execute_controlled(
        &spec,
        &support,
        profile.program(),
        &graph_args,
        CargoOutput::Capture {
            directory: owner.path().join("unit-graph-drain"),
            maximum: MAX_GRAPH_BYTES,
        },
        timeout,
        &stopped,
        shared.as_deref(),
        &mut output,
    )?;
    if !planned.status.success() {
        output.replay(&planned)?;
        return Err(invalid(
            "captured Cargo unit planning failed (nightly Cargo with --unit-graph is required); no rustc cache endpoint was started",
        ));
    }
    let graph: Value = serde_json::from_reader(planned.stdout.reader()?)?;
    let graph = validate_compilation_unit_graph(&graph, profile.command)?;
    if graph.contains_doctests() && !profile.no_run() {
        let rustdoc = paths
            .physical(Path::new(RUSTDOC))
            .map_err(io::Error::other)?;
        let metadata = fs::symlink_metadata(rustdoc)?;
        require(
            metadata.is_file() && metadata.mode() & 0o111 != 0,
            "selected doctests require the captured ordinary executable bin/rustdoc",
        )?;
    }
    for path in graph.source_paths() {
        let path = Path::new(path);
        require(
            path.starts_with("/__rabs/workspace") || path.starts_with("/__rabs/cargo-home"),
            "selected Cargo target source is outside the captured source roots",
        )?;
        let physical = paths.physical(path).map_err(io::Error::other)?;
        require(
            fs::symlink_metadata(physical)?.is_file(),
            "selected Cargo target source must be a captured ordinary file",
        )?;
    }

    // Only after graph admission can this exact wrapper and scoped endpoint
    // enter the namespace. Neither is selected by a source/config/env hint.
    let control = home_root.join("control");
    create_private(&control)?;
    capture_wrapper(&profile.wrapper, &control.join("rabs-wrap"))?;
    // Planning ran without an endpoint. Bind the retained wrapper and complete
    // execution environment before selecting private state for this command.
    spec.env.extend([
        ("RUSTC_WRAPPER".into(), WRAPPER.into()),
        ("RABS_SOCKET_PATH".into(), SOCKET.into()),
        (
            "RABS_BREAKER_FILE".into(),
            "/__rabs/cargo-home/.rabs-breaker".into(),
        ),
    ]);
    let mut private_target_state = if profile.target_cache.is_some() {
        "cold"
    } else {
        "disabled"
    };
    let mut target_state = None;
    if target_reuse_enabled && let Some(config) = &profile.target_cache {
        let mut prepare = || -> io::Result<(TargetState, Option<PathBuf>)> {
            let _cache_guard = shared
                .as_ref()
                .map(|runtime| {
                    runtime
                        .target_cache_lock
                        .lock()
                        .map_err(|_| io::Error::other("canonical target cache lock poisoned"))
                })
                .transpose()?;
            let (_, wrapper) = read_stable(&control.join("rabs-wrap"), 128 * 1024 * 1024)?;
            let key = TargetReuseContext {
                request: &request,
                workspace: workspace_manifest,
                full_source: source.manifest().digest(),
                projection: cargo_projection.as_ref(),
                spec: &spec,
                support: &support,
                program: profile.program(),
                args: &compilation_args,
                build_identity: &build_identity,
                wrapper: Sha256::digest(&wrapper).into(),
                closed_dependency_execution: graph.requires_closed_dependency_execution(),
            }
            .key(config)?;
            let mut cache =
                TargetState::open(&state_root, config, key, &workspace, workspace_manifest)?;
            let candidate = owner.path().join("restored-target");
            let restored = match create_private(&candidate).and_then(|()| cache.restore(&candidate))
            {
                Ok(restored) => restored.then_some(candidate),
                Err(error) => {
                    // A failed optional restore still permits a successful
                    // cold Cargo execution to replace the seed in this run.
                    // The failed candidate never enters the namespace.
                    output.warning("restore", &error)?;
                    None
                }
            };
            Ok((cache, restored))
        };
        match prepare() {
            Ok((cache, restored)) => {
                target_state = Some(cache);
                if let Some(restored) = restored {
                    let output = spec
                        .rw_binds
                        .iter_mut()
                        .find(|bind| bind.visible == Path::new(TARGET))
                        .ok_or_else(|| invalid("canonical target mount missing"))?;
                    output.backing.clone_from(&restored);
                    target_root = restored;
                    private_target_state = "restored";
                }
            }
            Err(error) => output.warning("restore", &error)?,
        }
    }
    // A failed restore remains in unmounted private staging. The live endpoint
    // receives only the completely selected target's retained inode capability.
    let paths = CanonicalPaths::new_with_retained_toolchain(
        owner.clone(),
        vec![
            ("/__rabs/workspace".into(), workspace),
            ("/__rabs/cargo-home".into(), cargo_root),
            ("/__rabs/toolchain".into(), toolchain),
            (TARGET.into(), target_root.clone()),
            ("/__rabs/home".into(), home_root.clone()),
        ],
        retained_toolchain.clone(),
    )
    .map_err(io::Error::other)?;
    let paths = paths
        .with_workspace_units(graph.workspace_units(), profile.selection.as_ref())
        .map_err(io::Error::other)?;
    let paths = if graph.requires_closed_dependency_execution() {
        paths
            .require_closed_dependency_execution()
            .map_err(io::Error::other)?
    } else {
        paths
    };
    let socket = control.join("rustc.sock");
    // sockaddr_un includes its terminating NUL. Refuse before boot, rather
    // than silently selecting a shorter socket outside this operation owner.
    require(
        socket.as_os_str().as_encoded_bytes().len() < 108,
        "operation_root is too long for the owned Unix socket (choose a shorter path)",
    )?;
    let coord = match &shared {
        Some(runtime) => {
            require(
                runtime.healthy(),
                "canonical service coordinator stopped during preparation",
            )?;
            Arc::clone(&runtime.coord)
        }
        None => {
            let mounted = Arc::new(
                crate::janitor::store::mount_and_reconcile(&state_root.join("cas"))
                    .map_err(io::Error::other)?,
            );
            Arc::new(
                CoordLive::with_cas(mounted)
                    .with_release_authorization(build_identity, release_mode),
            )
        }
    };
    let controller = Arc::new(ShutdownController::new());
    if shared.is_none() {
        controller.listen_for_signals();
    }
    let activity = CanonicalActivity::new();
    let config = EdgeServerConfig {
        socket_path: socket.clone(),
        state_dir: if shared.is_some() {
            owner.path().join("shadow")
        } else {
            state_root.join("shadow")
        },
        coord: coord.edge_subscriber(),
        prepared_operations: None,
        live_dependency: Some(shared.as_ref().map_or_else(
            || LiveDependencyLane::new(Arc::clone(&coord)),
            |runtime| runtime.lane.clone(),
        )),
    };
    let edge = match &shared {
        Some(runtime) => canonical_edge_work_shared(
            config,
            Arc::clone(&paths),
            Arc::clone(&activity),
            runtime.remote.clone(),
            runtime.remote_executions.clone(),
        ),
        None => canonical_edge_work(config, Arc::clone(&paths), Arc::clone(&activity)),
    };
    // The service's cancel flag also governs response delivery. Finishing a
    // successfully drained scoped edge must not cancel that caller, while an
    // edge that exits before the owner requests shutdown must stop its Cargo.
    let normal_shutdown = shared.as_ref().map(|_| Arc::new(AtomicBool::new(false)));
    let edge = match &normal_shutdown {
        Some(expected) => stop_on_unexpected_exit(
            edge,
            Arc::clone(&stopped),
            Arc::clone(&controller),
            Arc::clone(expected),
        ),
        None => stop_on_exit(edge, Arc::clone(&stopped), Arc::clone(&controller)),
    };
    let options = DaemonRunOptions {
        edge_work: Some(edge),
        coord_work: shared.is_none().then(|| {
            stop_on_exit(
                coordinator_work(coord.clone()),
                stopped.clone(),
                controller.clone(),
            )
        }),
        ..DaemonRunOptions::default()
    };
    let worker_controller = controller.clone();
    let worker = std::thread::Builder::new()
        .name("rabs-canonical-coord".into())
        .spawn(move || run_daemon_controlled(options, worker_controller))?;
    let server = ServerOwner {
        controller,
        worker: Some(worker),
        normal_shutdown,
    };
    wait_ready(&server, &socket, &coord, &stopped)?;
    output.event(
        json!({"kind":"canonical-compilation-started", "version":PROFILE_VERSION,
        "command":profile.command.as_str(), "namespace":"canonical",
        "cache_scope":"external-dependency-metadata-and-worker-rlib",
        "private_target_state":private_target_state,
        "test_execution":profile.command == CompilationCommand::Test && !profile.no_run(),
        "test_result_cache":false,
        "run_execution":profile.command == CompilationCommand::Run,
        "benchmark_execution":profile.command == CompilationCommand::Bench && !profile.no_run(),
        "program_result_cache":false, "benchmark_result_cache":false,
        "lint_execution":profile.command == CompilationCommand::Clippy,
        "lint_result_cache":false,
        "workspace_cache":false, "source_sha256":request["source_manifest"]["manifest_sha256"],
        "selected_units":graph.units, "selected_packages":graph.packages,
        "selected_roots":graph.roots, "shared_coordinator":shared.is_some()}),
    )?;
    let cargo_output = output.cargo_output(
        owner.path().join("compilation-drain"),
        profile.inherits_stdin(),
    )?;
    let streamed = matches!(&cargo_output, CargoOutput::Stream { .. });
    let result = execute_controlled(
        &spec,
        &support,
        profile.program(),
        &compilation_args,
        cargo_output,
        timeout,
        &stopped,
        shared.as_deref(),
        &mut output,
    );
    // A successful wrapper exits after capture ACK; publication can still be
    // queued on that same session. Seal admission only after Cargo's process
    // group is gone, then keep coordinator authority alive through the last
    // session/publication before requesting subsystem shutdown.
    let publication_drain = if result.is_ok() {
        activity.seal_and_wait(Duration::from_secs(60), || {
            stopped.load(Ordering::Acquire)
                || shared.as_ref().is_some_and(|runtime| !runtime.healthy())
        })
    } else {
        Ok(())
    };
    let shutdown = server.finish();
    let compiled = result?;
    publication_drain.map_err(io::Error::other)?;
    let receipt = shutdown?;
    require(
        receipt.clean(),
        "canonical coordinator did not drain cleanly",
    )?;
    // The operator-owned image is mounted read-only in the build, but a host
    // mutation must still invalidate this operation before target publication
    // or delivery. Do not substitute the now-current mutable toolchain source.
    preparation.checkpoint()?;
    if let Some(retained) = &retained_toolchain {
        retained.image().verify_retained_generation(cancelled)?;
    }
    if !streamed {
        output.replay(&compiled)?;
    }
    output.line(&receipt.to_json_line())?;
    if (compiled.status.success()
        || (matches!(
            profile.command,
            CompilationCommand::Test | CompilationCommand::Run | CompilationCommand::Bench
        ) && compiled.status.code().is_some()))
        && let Some(cache) = &target_state
    {
        // Retain state only after compiler, session, publication and coordinator
        // drain. Delivered files remain independent of this saved generation.
        // A normal program/harness failure can retain compiled artifacts too.
        // Cargo and the requested bodies execute again; no outcome is saved.
        let capture = || -> io::Result<()> {
            let _cache_guard = shared
                .as_ref()
                .map(|runtime| {
                    runtime
                        .target_cache_lock
                        .lock()
                        .map_err(|_| io::Error::other("canonical target cache lock poisoned"))
                })
                .transpose()?;
            cache.capture(&target_root)
        };
        if let Err(error) = capture() {
            output.warning("capture", &error)?;
        }
    }
    // Optional target capture can outlive the client connection. Preserve its
    // valid cache generation, but do not retain a deliverable whose owner is
    // already known to have cancelled or lost coordinator authority.
    if let Some(runtime) = &shared
        && (stopped.load(Ordering::Acquire) || !runtime.healthy())
    {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "canonical operation cancelled before output delivery",
        ));
    }
    if compiled.status.success()
        && (profile.command == CompilationCommand::Build || profile.no_run())
    {
        // No Cargo process, wrapper session or materializer remains. Verify
        // the retained target mapping once more before moving its completed
        // tree to a fresh private output owner. Captured source, toolchain,
        // credentials and control sockets stay with the temporary operation.
        require(
            paths
                .physical(Path::new(TARGET))
                .map_err(io::Error::other)?
                == target_root,
            "completed target differs from its retained canonical mount",
        )?;
        let delivered = retain_build_target(&profile.operation_root, &target_root)?;
        output.event(
            json!({"kind":"canonical-build-completed", "version":PROFILE_VERSION,
                "command":profile.command.as_str(), "tests_executed":false,
                "canonical_target":TARGET, "target_directory":delivered}),
        )?;
    }
    use std::os::unix::process::ExitStatusExt;
    Ok(compiled
        .status
        .code()
        .unwrap_or_else(|| 128 + compiled.status.signal().unwrap_or(1)))
}

/// Only private Cargo freshness uses this compatibility family. Every command
/// still runs with its original arguments; no action-cache authority follows.
struct TargetReuseContext<'a> {
    request: &'a Value,
    workspace: &'a SourceManifest,
    full_source: [u8; 32],
    projection: Option<&'a CargoHomeProjection>,
    spec: &'a CanonicalNamespaceSpec,
    support: &'a HostIsolationSupport,
    program: &'a str,
    args: &'a [String],
    build_identity: &'a str,
    wrapper: [u8; 32],
    closed_dependency_execution: bool,
}

impl TargetReuseContext<'_> {
    fn key(&self, config: &TargetCacheConfig) -> io::Result<[u8; 32]> {
        use rabs_sandbox::cargo_artifacts::CargoArtifactMode;
        use rabs_sandbox::cargo_target::{compatible_arguments, source_edit_identity};
        config.validate()?;
        require(
            !self.spec.allows_network(),
            "private target requires a closed network",
        )?;
        let toolchain = super::worker_delivery::toolchain_identity(self.request)?
            .ok_or_else(|| invalid("private target requires a captured toolchain"))?;
        let no_run = self
            .args
            .iter()
            .take_while(|arg| arg.as_str() != "--")
            .any(|arg| arg == "--no-run");
        let mode = match self.args.first().map(String::as_str) {
            Some("test") if !no_run => CargoArtifactMode::TestExecution,
            Some("bench") if !no_run => CargoArtifactMode::BenchExecution,
            Some("run") => CargoArtifactMode::RunExecution,
            _ => CargoArtifactMode::Compilation,
        };
        let args = compatible_arguments(self.program, self.args, mode)
            .unwrap_or_else(|| self.args.to_vec());
        // Build scripts, procedural macros and LLVM's assembler can read
        // captured data without reporting it to Cargo or rustc dep-info.
        // Retiming a file cannot dirty a unit that never declared that file:
        // even a pure Rust build can embed an untracked global_asm! .incbin.
        // Source-edit families therefore require a compiler-only check. All
        // codegen, Clippy and project-executor graphs keep their complete source
        // key. Clippy can read manifests/configuration outside rustc dep-info.
        let metadata_only = self.args.first().is_some_and(|command| command == "check");
        let source = if metadata_only && !self.closed_dependency_execution {
            source_edit_identity(self.workspace, self.full_source, self.projection)
                .unwrap_or(self.full_source)
        } else {
            self.full_source
        };
        let mut ro: Vec<_> = self
            .spec
            .ro_binds
            .iter()
            .map(|bind| &bind.visible)
            .collect();
        let mut rw: Vec<_> = self
            .spec
            .rw_binds
            .iter()
            .map(|bind| &bind.visible)
            .collect();
        ro.sort();
        rw.sort();
        let identity = json!({
            "version":"canonical-private-cargo-target-v1",
            "runtime_epoch":config.runtime_epoch,
            "driver":self.build_identity, "wrapper":self.wrapper,
            "source_family":source,
            "projection":self.projection.map(|home| (home.version(), home.prefix())),
            "toolchain":{"sha256":toolchain.sha256,
                "files":toolchain.files,"bytes":toolchain.bytes},
            "program":self.program, "args":args, "cwd":self.spec.cwd,
            "env":self.spec.env, "hostname":self.spec.hostname,
            "ro":ro, "rw":rw, "output":TARGET,
            "bubblewrap":self.support.bubblewrap,
            "userns":self.support.unprivileged_userns,
            "runtime":if self.closed_dependency_execution {
                "fresh-home+captured-or-empty-cargo-home+isolated-dependency-cache-v1"
            } else {
                "fresh-home+captured-or-empty-cargo-home+no-project-executors-v1"
            }
        });
        Ok(Sha256::digest(serde_json::to_vec(&identity)?).into())
    }
}

/// Move, rather than recopy, a fully drained target to a newly allocated private
/// owner on the same filesystem. There is no caller-selected overwrite target
/// and no retained copy of source or toolchain inputs. Successful builds and
/// Test/bench --no-run calls use this; other paths keep temporary target ownership.
fn retain_build_target(parent: &Path, target: &Path) -> io::Result<PathBuf> {
    private_directory(parent)?;
    require(
        fs::symlink_metadata(target)?.is_dir(),
        "completed Cargo target must be an ordinary directory",
    )?;
    let destination = tempfile::Builder::new()
        .prefix("rabs-build-")
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir_in(parent)?;
    let delivered = destination.path().join("target");
    fs::rename(target, &delivered)?;
    // Ownership transfers immediately after the move: a later reporting/fsync
    // error must not recursively discard a successful build's artifacts.
    let retained = destination.keep();
    File::open(&retained)?.sync_all()?;
    File::open(parent)?.sync_all()?;
    Ok(delivered)
}

fn make_read_only(spec: &mut CanonicalNamespaceSpec, visible: &str) -> io::Result<()> {
    let index = spec
        .rw_binds
        .iter()
        .position(|bind| bind.visible == Path::new(visible))
        .ok_or_else(|| invalid("canonical writable mount missing"))?;
    spec.ro_binds.push(spec.rw_binds.remove(index));
    Ok(())
}

fn capture_wrapper(source: &Path, destination: &Path) -> io::Result<()> {
    let (signature, bytes) = read_stable(source, 128 * 1024 * 1024)?;
    let metadata = fs::symlink_metadata(source)?;
    require(
        FileSig::of(&metadata) == signature && metadata.mode() & 0o111 != 0,
        "wrapper changed while it was captured",
    )?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o500)
        .open(destination)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    fs::set_permissions(destination, fs::Permissions::from_mode(0o500))?;
    Ok(())
}

enum CargoOutput {
    Capture {
        directory: PathBuf,
        maximum: u64,
    },
    Stream {
        directory: PathBuf,
        maximum: u64,
        files: LiveOutputFiles,
    },
    Inherit {
        inherit_stdin: bool,
    },
}

#[allow(clippy::too_many_arguments)]
fn execute_controlled(
    spec: &CanonicalNamespaceSpec,
    support: &HostIsolationSupport,
    program: &str,
    args: &[String],
    output: CargoOutput,
    timeout: Duration,
    stopped: &AtomicBool,
    shared: Option<&SharedRuntime>,
    destination: &mut OperationOutput,
) -> io::Result<DrainedOutput> {
    let launch = build_canonical_argv(spec, support, program, args)
        .map_err(|error| invalid(error.to_string()))?;
    let mut command = command_for(&launch);
    let (limits, maximum, live_files) = match output {
        CargoOutput::Capture { directory, maximum } => {
            command
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            (DrainLimits::new(directory), maximum, None)
        }
        CargoOutput::Stream {
            directory,
            maximum,
            files,
        } => {
            command
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            (DrainLimits::new(directory), maximum, Some(files))
        }
        CargoOutput::Inherit { inherit_stdin } => {
            // Only the explicit noninteractive run/bench executor consumes
            // caller input. Planning probes and earlier compilation/test
            // commands keep their original EOF behavior.
            command.stdin(if inherit_stdin {
                Stdio::inherit()
            } else {
                Stdio::null()
            });
            // No forwarding thread or retained copy stands between Cargo and
            // its consumer. A slow pipe reader backpressures the child, while
            // the supervisor can still cancel the entire group. With no piped
            // child streams the ordinary drain starts no lanes and creates no
            // spill directory. A zero budget also prevents accidental capture.
            command.stdout(Stdio::inherit()).stderr(Stdio::inherit());
            (
                DrainLimits {
                    resident_bound: 0,
                    spill_dir: PathBuf::new(),
                },
                0,
                None,
            )
        }
    };
    // Capture and transfer have finished before this scarce root permit is
    // acquired. Cargo creates its own valid jobserver from the admitted --jobs
    // value; this broker separately accounts for its implicit root token.
    let root = shared
        .map(|runtime| runtime.acquire_root(stopped, timeout))
        .transpose()?;
    if stopped.load(Ordering::Acquire) || shared.is_some_and(|runtime| !runtime.healthy()) {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "canonical Cargo cancelled before spawn",
        ));
    }
    let process = ManagedProcessGroup::spawn_command(command, Attribution::default())?;
    let group = process.pgid();
    let start = Instant::now();
    let mut cancelled = false;
    let mut timed_out = false;
    let streamed = live_files.is_some();
    let stop_requested = || {
        cancelled |=
            stopped.load(Ordering::Acquire) || shared.is_some_and(|runtime| !runtime.healthy());
        timed_out |= start.elapsed() >= timeout;
        cancelled || timed_out
    };
    let drained = match live_files {
        Some(files) => {
            process.wait_with_bounded_drain_files(&limits, maximum, files, stop_requested)
        }
        None => process.wait_with_bounded_drain_budget(&limits, maximum, stop_requested),
    };
    let unresolved = match &drained {
        Ok(output) => output.residual_group_members != 0,
        Err(_) => !rabs_asupersync::process_groups::members_from_proc(group).is_empty(),
    };
    if unresolved {
        if let Some(runtime) = shared {
            runtime.stopped.store(true, Ordering::Release);
        }
        // Failed cleanup is neither a free root nor a clean cancellation. The
        // admission also retains the state lock until the service process exits.
        std::mem::forget(root);
        return Err(io::Error::other(
            "canonical Cargo process group did not drain",
        ));
    }
    let output = drained?;
    if streamed {
        // The exact prefixes already reached the service's private files.
        // Charge them once, without appending the final capture again. The
        // drain's quota was capped to this destination's remaining allowance.
        let bytes = output
            .stdout
            .total_bytes()
            .checked_add(output.stderr.total_bytes())
            .ok_or_else(|| invalid("canonical diagnostic length overflow"))?;
        destination.reserve(bytes)?;
    }
    cancelled |=
        stopped.load(Ordering::Acquire) || shared.is_some_and(|runtime| !runtime.healthy());
    timed_out |= start.elapsed() >= timeout;
    if cancelled || timed_out {
        if !streamed {
            destination.replay(&output)?;
        }
        return Err(io::Error::new(
            if timed_out {
                io::ErrorKind::TimedOut
            } else {
                io::ErrorKind::Interrupted
            },
            if timed_out {
                "canonical Cargo command timed out"
            } else {
                "canonical Cargo command was cancelled"
            },
        ));
    }
    Ok(output)
}

fn replay(output: &DrainedOutput) -> io::Result<()> {
    io::copy(&mut output.stdout.reader()?, &mut io::stdout().lock())?;
    io::copy(&mut output.stderr.reader()?, &mut io::stderr().lock())?;
    Ok(())
}

fn coordinator_work(coord: Arc<CoordLive>) -> SubsystemWork {
    Box::new(move |cx, mut shutdown| {
        Box::pin(async move {
            coord.mark_up();
            if let Err(reason) = coord.acquire_boot_authority(&cluster_id()) {
                coord.mark_down();
                return Err(reason);
            }
            cx.trace("canonical Cargo coordinator owns dependency-cache authority");
            shutdown.wait().await;
            coord.mark_down();
            Ok(())
        })
    })
}

fn stop_on_exit(
    work: SubsystemWork,
    stopped: Arc<AtomicBool>,
    controller: Arc<ShutdownController>,
) -> SubsystemWork {
    Box::new(move |cx, shutdown| {
        Box::pin(async move {
            let result = work(cx, shutdown).await;
            stopped.store(true, Ordering::Release);
            controller.shutdown();
            result
        })
    })
}

fn stop_on_unexpected_exit(
    work: SubsystemWork,
    stopped: Arc<AtomicBool>,
    controller: Arc<ShutdownController>,
    normal_shutdown: Arc<AtomicBool>,
) -> SubsystemWork {
    Box::new(move |cx, shutdown| {
        Box::pin(async move {
            // Dropping or unwinding the work future must stop its caller too;
            // otherwise a failed edge could leave Cargo waiting for its socket.
            let _exit = ScopedExit {
                stopped,
                controller,
                normal_shutdown,
            };
            work(cx, shutdown).await
        })
    })
}

struct ScopedExit {
    stopped: Arc<AtomicBool>,
    controller: Arc<ShutdownController>,
    normal_shutdown: Arc<AtomicBool>,
}

impl Drop for ScopedExit {
    fn drop(&mut self) {
        if !self.normal_shutdown.load(Ordering::Acquire) {
            self.stopped.store(true, Ordering::Release);
        }
        self.controller.shutdown();
    }
}

struct ServerOwner {
    controller: Arc<ShutdownController>,
    worker: Option<JoinHandle<Result<ShutdownReceipt, DaemonError>>>,
    normal_shutdown: Option<Arc<AtomicBool>>,
}
impl ServerOwner {
    fn request_shutdown(&self) {
        if let Some(expected) = &self.normal_shutdown {
            expected.store(true, Ordering::Release);
        }
        self.controller.shutdown();
    }

    fn finish(mut self) -> io::Result<ShutdownReceipt> {
        self.request_shutdown();
        self.worker
            .take()
            .ok_or_else(|| io::Error::other("canonical coordinator already joined"))?
            .join()
            .map_err(|_| io::Error::other("canonical coordinator panicked"))?
            .map_err(io::Error::other)
    }
}
impl Drop for ServerOwner {
    fn drop(&mut self) {
        self.request_shutdown();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn wait_ready(
    server: &ServerOwner,
    socket: &Path,
    coord: &CoordLive,
    stopped: &AtomicBool,
) -> io::Result<()> {
    let start = Instant::now();
    loop {
        if stopped.load(Ordering::Acquire)
            || server
                .worker
                .as_ref()
                .is_none_or(|worker| worker.is_finished())
        {
            return Err(io::Error::other(
                "canonical coordinator stopped during startup",
            ));
        }
        if coord.available()
            && coord.authority().is_some()
            && fs::symlink_metadata(socket).is_ok_and(|metadata| metadata.file_type().is_socket())
        {
            return Ok(());
        }
        if start.elapsed() >= Duration::from_secs(30) {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "canonical coordinator startup timed out",
            ));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn readonly_home_and_source_leave_only_cargo_state_and_outputs_writable() {
        let mut plan = CanonicalMountPlan::new(
            "/private/toolchain",
            "/private/source",
            "/private/cargo",
            "/private/home",
        );
        plan.out_units.push(UnitMount {
            unit: "cargo".into(),
            backing: "/private/target".into(),
        });
        let mut spec = plan.to_spec().unwrap();
        make_read_only(&mut spec, "/__rabs/workspace").unwrap();
        make_read_only(&mut spec, "/__rabs/home").unwrap();
        let writable: BTreeSet<_> = spec
            .rw_binds
            .iter()
            .map(|bind| bind.visible.clone())
            .collect();
        assert_eq!(
            writable,
            BTreeSet::from([PathBuf::from("/__rabs/cargo-home"), PathBuf::from(TARGET)])
        );
        assert!(
            spec.ro_binds
                .iter()
                .any(|bind| bind.visible == Path::new("/__rabs/home"))
        );
    }

    #[test]
    fn profile_rejects_ambient_authority_fields_and_path_traversal() {
        let value = json!({"version":PROFILE_VERSION, "source_root":"/source", "toolchain_root":"/toolchain",
            "state_root":"/state", "operation_root":"/operations", "wrapper":"/bin/rabs-wrap", "env":{"LD_PRELOAD":"/bad"}});
        let profile: Profile = serde_json::from_value(value).unwrap();
        assert!(
            profile
                .validate()
                .unwrap_err()
                .to_string()
                .contains("cannot replace worker, compiler or preparation controls")
        );
        for path in [
            "",
            "../Cargo.toml",
            "/Cargo.toml",
            "a//Cargo.toml",
            "a/./Cargo.toml",
        ] {
            assert!(!relative_member(path));
        }
        assert!(relative_member("app/Cargo.toml"));
        for path in [
            "/tmp/../state",
            "/tmp//state",
            "/tmp/./state",
            "relative",
            "/",
        ] {
            assert!(!plain_absolute(Path::new(path)));
        }
    }

    fn application_environment_profile() -> Profile {
        serde_json::from_value(json!({
            "version":PROFILE_VERSION, "source_root":"/source", "toolchain_root":"/toolchain",
            "state_root":"/state", "operation_root":"/operations", "wrapper":"/bin/rabs-wrap"
        }))
        .unwrap()
    }

    #[test]
    fn explicit_application_inputs_are_literal_and_identical_in_request_and_namespace() {
        let inputs = BTreeMap::from([
            ("APP_VERSION".into(), "v1 '雪' $(touch never)".into()),
            ("GIT_COMMIT".into(), "abcdef123456".into()),
            ("EMPTY".into(), String::new()),
            ("MULTILINE".into(), "first\nsecond\t".into()),
            ("SOURCE_DATE_EPOCH".into(), "1700000000".into()),
        ]);
        for command in [
            CompilationCommand::Check,
            CompilationCommand::Build,
            CompilationCommand::Test,
            CompilationCommand::Clippy,
            CompilationCommand::Run,
            CompilationCommand::Bench,
        ] {
            let mut profile = application_environment_profile();
            profile.command = command;
            profile.env = inputs.clone();
            let specification = profile.source_specification().unwrap();
            let mut expected = inputs.clone();
            expected.extend([
                ("CARGO_INCREMENTAL".into(), "0".into()),
                ("CARGO_TARGET_DIR".into(), TARGET.into()),
                ("RUSTC".into(), RUSTC.into()),
            ]);
            if command == CompilationCommand::Test {
                expected.insert("RUSTDOC".into(), RUSTDOC.into());
            }
            if command == CompilationCommand::Clippy {
                expected.insert("CARGO".into(), CARGO.into());
            }
            assert_eq!(specification["command_context"]["env"], json!(expected));
            let mut mounts = CanonicalMountPlan::new(
                "/private/toolchain",
                "/private/source",
                "/private/cargo",
                "/private/home",
            );
            mounts.extra_env = profile.command_environment().unwrap();
            let actual: BTreeMap<_, _> = mounts.to_spec().unwrap().env.into_iter().collect();
            for (name, value) in expected {
                assert_eq!(actual[&name], value, "{command:?}: {name}");
            }
            assert_eq!(actual["HOME"], "/__rabs/home");
            assert!(!actual.contains_key("RABS_SOCKET_PATH"));
        }
    }

    #[test]
    fn project_environment_refuses_controls_before_root_access_without_echoing_values() {
        for name in [
            "PATH",
            "HOME",
            "CARGO_HOME",
            "TMPDIR",
            "RUSTUP_HOME",
            "RUSTUP_TOOLCHAIN",
            "LANG",
            "LC_ALL",
            "TZ",
            "MAKEFLAGS",
            "CARGO_MAKEFLAGS",
            "MFLAGS",
            "NUM_JOBS",
            "CARGO",
            "RUSTC",
            "RUSTDOC",
            "RUSTFLAGS",
            "RUSTDOCFLAGS",
            "GLIBC_TUNABLES",
            "CARGO_INCREMENTAL",
            "CARGO_ENCODED_RUSTFLAGS",
            "CARGO_BUILD_RUSTC_WRAPPER",
            "CARGO_TARGET_DIR",
            "CARGO_PROFILE_DEV_OPT_LEVEL",
            "CARGO_NET_OFFLINE",
            "RUSTC_WRAPPER",
            "RUSTC_WORKSPACE_WRAPPER",
            "RUSTC_BOOTSTRAP",
            "RUSTDOC_LOG",
            "CLIPPY_ARGS",
            "CLIPPY_CONF_DIR",
            "RABS_SOCKET_PATH",
            "RABS_COORD_TLS_KEY",
            "RCH_REQUIRE_REMOTE",
            "LD_PRELOAD",
            "LD_LIBRARY_PATH",
            "DYLD_LIBRARY_PATH",
        ] {
            let mut profile = application_environment_profile();
            profile
                .env
                .insert(name.into(), "never-echo-this-value".into());
            let error = profile.validate().unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput, "{name}: {error}");
            assert!(
                error.to_string().contains("cannot replace"),
                "{name}: {error}"
            );
            assert!(!error.to_string().contains("never-echo-this-value"));
        }
        for name in ["", "1BAD", "BAD-NAME", "A=B", "雪", "A\n"] {
            let mut profile = application_environment_profile();
            profile
                .env
                .insert(name.into(), "never-echo-this-value".into());
            let error = profile.validate().unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
            assert!(error.to_string().contains("environment name"));
            assert!(!error.to_string().contains("never-echo-this-value"));
        }
    }

    #[test]
    fn project_environment_bounds_include_driver_controls_and_preserve_empty_values() {
        let mut profile = application_environment_profile();
        profile.env = (0..253)
            .map(|index| (format!("APP_{index}"), String::new()))
            .collect();
        assert_eq!(profile.command_environment().unwrap().len(), 256);
        profile.command = CompilationCommand::Test;
        assert!(profile.command_environment().is_err());
        profile.env.remove("APP_252");
        assert_eq!(profile.command_environment().unwrap().len(), 256);
        profile.env.clear();
        profile.env.insert("A".repeat(256), String::new());
        assert!(profile.command_environment().is_ok());
        profile.env.insert("B".repeat(257), String::new());
        assert!(profile.command_environment().is_err());
        profile.env = BTreeMap::from([("VALUE".into(), "x".repeat(64 * 1024))]);
        assert!(profile.command_environment().is_ok());
        profile.env.insert("OTHER".into(), "x".repeat(64 * 1024));
        assert!(profile.command_environment().is_err());
        profile.env = BTreeMap::from([("VALUE".into(), "x".repeat(64 * 1024 + 1))]);
        assert!(profile.command_environment().is_err());
        profile.env.insert("VALUE".into(), "before\0after".into());
        assert!(profile.command_environment().is_err());
    }

    #[test]
    fn native_profile_rejects_duplicate_project_environment_bindings() {
        let original = r#"{"version":"canonical-compile-local-v1","source_root":"/source","toolchain_root":"/toolchain","state_root":"/state","operation_root":"/operations","wrapper":"/bin/rabs-wrap","env":{"INPUT":"first","INPUT":"second"}}"#;
        let error = serde_json::from_str::<Profile>(original).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("duplicate canonical environment name")
        );
        assert!(!error.to_string().contains("first"));
        assert!(!error.to_string().contains("second"));
    }

    #[test]
    fn root_and_member_manifests_produce_valid_exact_command_contexts() {
        let mut profile: Profile = serde_json::from_value(json!({
            "version":PROFILE_VERSION, "source_root":"/source", "toolchain_root":"/toolchain",
            "state_root":"/state", "operation_root":"/operations", "wrapper":"/bin/rabs-wrap"
        }))
        .unwrap();
        for (manifest, expected) in [
            ("Cargo.toml", "/__rabs/workspace"),
            ("app/Cargo.toml", "/__rabs/workspace/app"),
        ] {
            profile.manifest = manifest.into();
            let specification = profile.source_specification().unwrap();
            assert_eq!(specification["command_context"]["cwd"], expected);
            let context = &specification["command_context"];
            let environment = context["env"]
                .as_object()
                .unwrap()
                .iter()
                .map(|(name, value)| (name.clone(), value.as_str().unwrap().to_owned()))
                .collect();
            assert!(
                rabs_sandbox::process_context::CommandContext::new(
                    context["cwd"].as_str().unwrap(),
                    environment,
                )
                .is_ok()
            );
        }
    }

    #[test]
    fn selected_compilations_keep_driver_owned_control_arguments_and_check_library_default() {
        let mut profile: Profile = serde_json::from_value(json!({
            "version":PROFILE_VERSION, "source_root":"/source", "toolchain_root":"/toolchain",
            "state_root":"/state", "operation_root":"/operations", "wrapper":"/bin/rabs-wrap"
        }))
        .unwrap();
        assert_eq!(
            &profile.compilation_args().unwrap()[..2],
            ["check", "--lib"]
        );
        profile.selection = Some(CompilationSelection::default());
        assert!(
            !profile
                .compilation_args()
                .unwrap()
                .iter()
                .any(|arg| arg == "--lib")
        );
        profile.selection = Some(
            serde_json::from_value(json!({
                "workspace":true, "packages":["app"], "features":["app/fast"],
                "no_default_features":true, "tests":true
            }))
            .unwrap(),
        );
        profile.manifest = "workspace/Cargo.toml".into();
        profile.jobs = 4;
        let specification = profile.source_specification().unwrap();
        assert_eq!(
            specification["args"],
            json!([
                "check",
                "--workspace",
                "--no-default-features",
                "--tests",
                "--package",
                "app",
                "--features",
                "app/fast",
                "--offline",
                "--locked",
                "--manifest-path",
                "/__rabs/workspace/workspace/Cargo.toml",
                "--message-format=json",
                "--jobs",
                "4"
            ])
        );
        assert_eq!(specification["command_context"]["env"]["RUSTC"], RUSTC);
        assert_eq!(
            specification["command_context"]["env"]["CARGO_TARGET_DIR"],
            TARGET
        );
        profile
            .selection
            .as_mut()
            .unwrap()
            .features
            .push("--config=bad".into());
        assert!(profile.source_specification().is_err());
    }

    #[test]
    fn build_command_uses_cargo_defaults_and_preserves_the_exact_graph_selection() {
        let mut profile: Profile = serde_json::from_value(json!({
            "version":PROFILE_VERSION, "command":"build",
            "source_root":"/source", "toolchain_root":"/toolchain",
            "state_root":"/state", "operation_root":"/operations", "wrapper":"/bin/rabs-wrap"
        }))
        .unwrap();
        assert_eq!(profile.command, CompilationCommand::Build);
        assert_eq!(
            &profile.compilation_args().unwrap()[..2],
            ["build", "--offline"]
        );
        profile.selection = Some(
            serde_json::from_value(json!({
                "packages":["app"], "bin":["server"], "profile":"release"
            }))
            .unwrap(),
        );
        let request = profile.source_specification().unwrap();
        assert_eq!(
            request["args"],
            json!([
                "build",
                "--package",
                "app",
                "--bin",
                "server",
                "--profile",
                "release",
                "--offline",
                "--locked",
                "--manifest-path",
                "/__rabs/workspace/Cargo.toml",
                "--message-format=json",
                "--jobs",
                "1"
            ])
        );
        for command in ["rustc", "doc"] {
            assert!(serde_json::from_value::<Profile>(json!({
                "version":PROFILE_VERSION, "command":command,
                "source_root":"/source", "toolchain_root":"/toolchain",
                "state_root":"/state", "operation_root":"/operations", "wrapper":"/bin/rabs-wrap"
            })).is_err());
        }
    }

    #[test]
    fn clippy_uses_captured_driver_and_identical_lints_after_the_planning_controls() {
        let profile: Profile = serde_json::from_value(json!({
            "version":PROFILE_VERSION, "command":"clippy",
            "source_root":"/source", "toolchain_root":"/toolchain",
            "state_root":"/state", "operation_root":"/operations", "wrapper":"/bin/rabs-wrap",
            "jobs":3, "selection":{"workspace":true, "all_targets":true, "no_deps":true,
                "lint_args":["-D", "warnings", "-Aclippy::needless_return"]}
        }))
        .unwrap();
        let args = profile.compilation_args().unwrap();
        let separator = args.iter().position(|arg| arg == "--").unwrap();
        assert_eq!(
            &args[..4],
            ["clippy", "--workspace", "--all-targets", "--no-deps"]
        );
        assert_eq!(
            &args[separator + 1..],
            ["-D", "warnings", "-Aclippy::needless_return"]
        );
        let graph = profile.graph_args(None).unwrap();
        assert_eq!(&graph[..separator], &args[..separator]);
        assert_eq!(
            &graph[separator..separator + 3],
            ["--unit-graph", "-Z", "unstable-options"]
        );
        assert_eq!(&graph[separator + 3..], &args[separator..]);
        let request = profile.source_specification().unwrap();
        assert_eq!(request["program"], CARGO_CLIPPY);
        assert_eq!(request["args"], json!(args));
        assert_eq!(request["command_context"]["env"]["CARGO"], CARGO);
        assert_eq!(request["command_context"]["env"]["RUSTC"], RUSTC);
        assert!(request["command_context"]["env"].get("RUSTDOC").is_none());
        assert!(!profile.no_run());
    }

    #[test]
    fn test_command_keeps_runtime_arguments_out_of_planning_and_after_driver_controls() {
        let profile: Profile = serde_json::from_value(json!({
            "version":PROFILE_VERSION, "command":"test",
            "source_root":"/source", "toolchain_root":"/toolchain",
            "state_root":"/state", "operation_root":"/operations", "wrapper":"/bin/rabs-wrap",
            "jobs":3, "selection":{"packages":["app"], "test":["integration"],
                "no_fail_fast":true, "test_filter":"selected test",
                "test_args":["--exact", "--nocapture", "--config", "literal harness value", ""]}
        }))
        .unwrap();
        let args = profile.compilation_args().unwrap();
        let separator = args.iter().position(|arg| arg == "--").unwrap();
        assert_eq!(
            &args[..separator],
            [
                "test",
                "--no-fail-fast",
                "--package",
                "app",
                "--test",
                "integration",
                "selected test",
                "--offline",
                "--locked",
                "--manifest-path",
                "/__rabs/workspace/Cargo.toml",
                "--message-format=json",
                "--jobs",
                "3"
            ]
        );
        assert_eq!(
            &args[separator + 1..],
            [
                "--exact",
                "--nocapture",
                "--config",
                "literal harness value",
                ""
            ]
        );
        let graph = profile.graph_args(None).unwrap();
        assert_eq!(&graph[..separator], &args[..separator]);
        assert_eq!(
            &graph[separator..],
            ["--unit-graph", "-Z", "unstable-options"]
        );
        assert!(!graph.iter().any(|arg| arg == "--" || arg == "--config"));
        let request = profile.source_specification().unwrap();
        assert_eq!(request["args"], json!(args));
        assert_eq!(request["command_context"]["env"]["RUSTDOC"], RUSTDOC);
        assert!(!profile.no_run());
    }

    #[test]
    fn test_no_run_comes_from_explicit_selection_and_does_not_change_the_default_command() {
        let mut profile: Profile = serde_json::from_value(json!({
            "version":PROFILE_VERSION, "command":"test",
            "source_root":"/source", "toolchain_root":"/toolchain",
            "state_root":"/state", "operation_root":"/operations", "wrapper":"/bin/rabs-wrap",
            "selection":{"no_run":true}
        }))
        .unwrap();
        assert!(profile.no_run());
        assert!(
            profile
                .compilation_args()
                .unwrap()
                .iter()
                .any(|arg| arg == "--no-run")
        );
        assert!(
            profile
                .graph_args(None)
                .unwrap()
                .iter()
                .any(|arg| arg == "--no-run")
        );
        profile.selection = None;
        assert!(!profile.no_run());
        assert_eq!(
            &profile.compilation_args().unwrap()[..2],
            ["test", "--offline"]
        );
        profile.command = CompilationCommand::Check;
        assert_eq!(
            &profile.compilation_args().unwrap()[..2],
            ["check", "--lib"]
        );
        assert!(
            profile.source_specification().unwrap()["command_context"]["env"]
                .get("RUSTDOC")
                .is_none()
        );
        profile.selection = Some(CompilationSelection {
            doc: true,
            ..CompilationSelection::default()
        });
        assert!(profile.compilation_args().is_err());
    }

    #[test]
    fn only_current_run_and_bench_execution_inherit_nonterminal_stdin() {
        for (command, no_run, inherits_stdin) in [
            (CompilationCommand::Run, false, true),
            (CompilationCommand::Bench, false, true),
            (CompilationCommand::Bench, true, false),
            (CompilationCommand::Test, false, false),
            (CompilationCommand::Test, true, false),
            (CompilationCommand::Check, false, false),
            (CompilationCommand::Build, false, false),
            (CompilationCommand::Clippy, false, false),
        ] {
            let profile: Profile = serde_json::from_value(json!({
                "version":PROFILE_VERSION, "command":command.as_str(),
                "source_root":"/source", "toolchain_root":"/toolchain",
                "state_root":"/state", "operation_root":"/operations", "wrapper":"/bin/rabs-wrap",
                "selection":{"no_run":no_run}
            }))
            .unwrap();
            assert_eq!(profile.inherits_stdin(), inherits_stdin, "{command:?}");
            assert!(profile.validate_stdin(false).is_ok(), "{command:?}");
            assert_eq!(
                profile.validate_stdin(true).is_err(),
                inherits_stdin,
                "{command:?}, no_run={no_run}"
            );
        }
    }

    #[test]
    fn run_plans_exact_build_target_and_preserves_its_actual_program_tail() {
        let profile: Profile = serde_json::from_value(json!({
            "version":PROFILE_VERSION, "command":"run", "source_root":"/source",
            "toolchain_root":"/toolchain", "state_root":"/state", "operation_root":"/operations",
            "wrapper":"/bin/rabs-wrap", "selection":{"example":["demo"], "profile":"dev",
                "run_args":["--unit-graph", "--no-run", "", "line\nvalue"]}
        }))
        .unwrap();
        let selected =
            run_build_selection(profile.selection.as_ref().unwrap(), &Value::Null, None).unwrap();
        let graph = profile.graph_args(Some(&selected)).unwrap();
        assert_eq!(
            &graph[..5],
            ["build", "--example", "demo", "--profile", "dev"]
        );
        assert!(!graph.iter().any(|arg| arg == "--" || arg == "--no-run"));
        assert_eq!(graph.iter().filter(|arg| *arg == "--unit-graph").count(), 1);
        assert!(
            profile.graph_args(None).is_err(),
            "run must never plan an unselected build graph"
        );
        let args = profile.compilation_args().unwrap();
        assert_eq!(args[0], "run");
        let tail = args.iter().position(|arg| arg == "--").unwrap();
        assert_eq!(
            &args[tail + 1..],
            ["--unit-graph", "--no-run", "", "line\nvalue"]
        );
        assert!(
            !profile.no_run(),
            "a literal program argument cannot change Cargo's execution mode"
        );
        assert!(profile.inherits_stdin());
        assert!(profile.validate_stdin(true).is_err());
        assert_eq!(profile.source_specification().unwrap()["args"], json!(args));
    }

    #[test]
    fn bench_planning_omits_runtime_tail_and_no_run_retains_compilation_delivery() {
        let mut profile: Profile = serde_json::from_value(json!({
            "version":PROFILE_VERSION, "command":"bench", "source_root":"/source",
            "toolchain_root":"/toolchain", "state_root":"/state", "operation_root":"/operations",
            "wrapper":"/bin/rabs-wrap", "selection":{"bench":["timing"], "test_filter":"selected",
                "test_args":["--exact", "--no-run", ""]}
        }))
        .unwrap();
        let args = profile.compilation_args().unwrap();
        let tail = args.iter().position(|arg| arg == "--").unwrap();
        let graph = profile.graph_args(None).unwrap();
        assert_eq!(&graph[..tail], &args[..tail]);
        assert_eq!(&graph[tail..], ["--unit-graph", "-Z", "unstable-options"]);
        assert!(!profile.no_run());
        assert!(profile.inherits_stdin());
        assert!(profile.validate_stdin(true).is_err());
        assert!(!args.iter().any(|arg| arg == "--release"));
        profile.selection = Some(CompilationSelection {
            bench: vec!["timing".into()],
            no_run: true,
            ..CompilationSelection::default()
        });
        assert!(profile.no_run());
        assert!(!profile.inherits_stdin());
        assert!(profile.validate_stdin(true).is_ok());
        assert!(
            profile
                .graph_args(None)
                .unwrap()
                .iter()
                .any(|arg| arg == "--no-run")
        );
        assert!(
            profile.source_specification().unwrap()["command_context"]["env"]
                .get("RUSTDOC")
                .is_none()
        );
    }

    #[test]
    fn completed_build_retains_only_outputs_without_copying_or_overwriting() {
        let owner = crate::test_util::private_tempdir();
        let operation = tempfile::tempdir_in(owner.path()).unwrap();
        let target = operation.path().join("target");
        create_private(&target).unwrap();
        create_private(&target.join("debug")).unwrap();
        fs::write(target.join("debug/libapp.rlib"), b"complete archive").unwrap();
        fs::write(target.join("debug/app"), b"completed executable").unwrap();
        fs::set_permissions(target.join("debug/app"), fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(
            operation.path().join("captured-input"),
            b"not a deliverable",
        )
        .unwrap();
        let before = fs::metadata(target.join("debug/libapp.rlib")).unwrap();
        let delivered = retain_build_target(owner.path(), &target).unwrap();
        let after = fs::metadata(delivered.join("debug/libapp.rlib")).unwrap();
        assert_eq!((before.dev(), before.ino()), (after.dev(), after.ino()));
        assert!(!target.exists());
        assert!(operation.path().join("captured-input").is_file());
        drop(operation);
        assert_eq!(
            fs::read(delivered.join("debug/libapp.rlib")).unwrap(),
            b"complete archive"
        );
        assert_eq!(
            fs::metadata(delivered.join("debug/app")).unwrap().mode() & 0o111,
            0o111
        );
        assert_eq!(
            fs::read_dir(delivered.parent().unwrap()).unwrap().count(),
            1
        );
        assert_eq!(
            fs::metadata(delivered.parent().unwrap()).unwrap().mode() & 0o077,
            0
        );

        let next_operation = tempfile::tempdir_in(owner.path()).unwrap();
        let next_target = next_operation.path().join("target");
        create_private(&next_target).unwrap();
        fs::write(next_target.join("different"), b"next build").unwrap();
        let next = retain_build_target(owner.path(), &next_target).unwrap();
        assert_ne!(next, delivered);
        assert_eq!(
            fs::read(delivered.join("debug/libapp.rlib")).unwrap(),
            b"complete archive"
        );
        assert_eq!(fs::read(next.join("different")).unwrap(), b"next build");
    }

    #[test]
    fn live_profile_state_cannot_be_taken_over_and_does_not_alias_daemon_cas() {
        let owner = tempfile::tempdir().unwrap();
        let first = StateOwner::acquire(owner.path()).unwrap();
        assert_eq!(first.root, owner.path().join("canonical-compile-v1"));
        assert!(!owner.path().join("cas").exists());
        let refusal = match StateOwner::acquire(owner.path()) {
            Ok(_) => panic!("a live profile state owner was superseded"),
            Err(error) => error,
        };
        assert_eq!(refusal.kind(), io::ErrorKind::WouldBlock);
        drop(first);
        assert!(StateOwner::acquire(owner.path()).is_ok());
    }

    #[test]
    fn persistent_state_refuses_replaced_lock_and_root_generations() {
        let parent = crate::test_util::private_tempdir();
        let state = StateOwner::acquire(parent.path()).unwrap();
        state.verify().unwrap();
        fs::rename(
            state.root.join("owner.lock"),
            state.root.join("retained-owner.lock"),
        )
        .unwrap();
        let replacement = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(state.root.join("owner.lock"))
            .unwrap();
        assert!(state.verify().is_err());
        drop(replacement);
        fs::rename(&state.root, parent.path().join("retained-state")).unwrap();
        create_private(&state.root).unwrap();
        let _replacement = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(state.root.join("owner.lock"))
            .unwrap();
        assert!(state.verify().is_err());
    }

    fn shared_runtime(state: &Path, roots: usize) -> Arc<SharedRuntime> {
        // Actual coordinator, CAS, authority and scheduler; no external worker
        // is configured by this filesystem/runtime test.
        SharedRuntime::start_with_remote(
            state,
            ReleaseAuthorizationMode::Advisory,
            "canonical-shared-tests".into(),
            roots,
            4,
            |_| Ok(None),
        )
        .unwrap()
    }

    #[test]
    fn shared_root_admission_is_bounded_cancellable_and_preserves_authority() {
        let owner = crate::test_util::private_tempdir();
        let runtime = shared_runtime(owner.path(), 2);
        let authority = runtime.coord.authority().unwrap();
        let running = AtomicBool::new(false);
        let first = runtime
            .acquire_root(&running, Duration::from_secs(1))
            .unwrap();
        let second = runtime
            .acquire_root(&running, Duration::from_secs(1))
            .unwrap();
        assert_eq!(runtime.roots.active(), 2);
        assert_eq!(
            runtime
                .acquire_root(&running, Duration::from_millis(10))
                .unwrap_err()
                .kind(),
            io::ErrorKind::TimedOut
        );
        assert!(runtime.shutdown().is_err());
        assert!(runtime.healthy());

        let cancelled = Arc::new(AtomicBool::new(false));
        let waiter = {
            let runtime = Arc::clone(&runtime);
            let cancelled = Arc::clone(&cancelled);
            std::thread::spawn(move || runtime.acquire_root(&cancelled, Duration::from_secs(5)))
        };
        cancelled.store(true, Ordering::Release);
        assert_eq!(
            waiter.join().unwrap().unwrap_err().kind(),
            io::ErrorKind::Interrupted
        );
        assert_eq!(runtime.roots.active(), 2);
        assert_eq!(runtime.coord.authority().unwrap(), authority);
        assert!(runtime.healthy());
        drop(first);
        let next = runtime
            .acquire_root(&running, Duration::from_secs(1))
            .unwrap();
        assert_eq!(runtime.roots.active(), 2);
        drop(second);
        drop(next);
        assert_eq!(runtime.roots.active(), 0);
        runtime.shutdown().unwrap();
        assert!(!runtime.healthy());
        drop(runtime);

        let restarted = shared_runtime(owner.path(), 1);
        assert!(restarted.coord.authority().unwrap().term > authority.term);
        assert_ne!(
            restarted.coord.authority().unwrap().incarnation_id,
            authority.incarnation_id
        );
        restarted.shutdown().unwrap();
    }

    #[test]
    fn shared_profile_refuses_foreign_state_extra_jobs_and_inherited_stdin_before_capture() {
        let owner = crate::test_util::private_tempdir();
        let runtime = shared_runtime(owner.path(), 1);
        let authority = runtime.coord.authority().unwrap();
        let operations = owner.path().join("must-not-be-created");
        let base = json!({"version":PROFILE_VERSION,
            "source_root":"/missing-source", "toolchain_root":"/missing-toolchain",
            "state_root":owner.path(), "operation_root":operations,
            "wrapper":"/missing-wrapper", "service_socket":"/service.sock", "jobs":4});
        for (index, (field, value, reason)) in [
            (
                "state_root",
                json!("/different-service-state"),
                "this service state",
            ),
            ("jobs", json!(5), "per-root job grant"),
            ("service_socket", Value::Null, "this service state"),
            ("command", json!("run"), "inherited stdin"),
            ("command", json!("bench"), "inherited stdin"),
        ]
        .into_iter()
        .enumerate()
        {
            let mut profile = base.clone();
            profile[field] = value;
            let file = |stream: &str| {
                OpenOptions::new()
                    .write(true)
                    .read(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(owner.path().join(format!("{index}-{stream}")))
                    .unwrap()
            };
            let error = run_shared_profile(
                &serde_json::to_vec(&profile).unwrap(),
                Arc::clone(&runtime),
                Arc::new(AtomicBool::new(false)),
                file("stdout"),
                file("stderr"),
                1024,
            )
            .unwrap_err();
            assert!(error.to_string().contains(reason), "{error}");
            assert!(!operations.exists());
            assert_eq!(runtime.roots.active(), 0);
            assert_eq!(runtime.coord.authority().unwrap(), authority);
            assert!(runtime.healthy());
        }
        runtime.shutdown().unwrap();
    }

    #[test]
    fn shared_edges_keep_one_term_and_one_cancellation_does_not_stop_the_other() {
        use std::io::{BufRead, BufReader};
        let state = crate::test_util::private_tempdir();
        let runtime = shared_runtime(state.path(), 2);
        let authority = runtime.coord.authority().unwrap();
        let attach = || {
            let owner = Arc::new(crate::test_util::private_tempdir());
            let mut mappings = Vec::new();
            for (visible, name) in [
                ("/__rabs/workspace", "source"),
                ("/__rabs/toolchain", "toolchain"),
                ("/__rabs/cargo-home", "cargo"),
                (TARGET, "target"),
                ("/__rabs/home", "home"),
            ] {
                let physical = owner.path().join(name);
                create_private(&physical).unwrap();
                mappings.push((PathBuf::from(visible), physical));
            }
            let paths = CanonicalPaths::new(Arc::clone(&owner), mappings).unwrap();
            let socket = owner.path().join("rustc.sock");
            let stopped = Arc::new(AtomicBool::new(false));
            let activity = CanonicalActivity::new();
            let controller = Arc::new(ShutdownController::new());
            let normal_shutdown = Arc::new(AtomicBool::new(false));
            let edge = canonical_edge_work_shared(
                EdgeServerConfig {
                    socket_path: socket.clone(),
                    state_dir: owner.path().join("shadow"),
                    coord: runtime.coord.edge_subscriber(),
                    prepared_operations: None,
                    live_dependency: Some(runtime.lane.clone()),
                },
                paths,
                Arc::clone(&activity),
                None,
                None,
            );
            let options = DaemonRunOptions {
                edge_work: Some(stop_on_unexpected_exit(
                    edge,
                    Arc::clone(&stopped),
                    Arc::clone(&controller),
                    Arc::clone(&normal_shutdown),
                )),
                ..DaemonRunOptions::default()
            };
            let worker_controller = Arc::clone(&controller);
            let worker =
                std::thread::spawn(move || run_daemon_controlled(options, worker_controller));
            let server = ServerOwner {
                controller,
                worker: Some(worker),
                normal_shutdown: Some(normal_shutdown),
            };
            wait_ready(&server, &socket, &runtime.coord, &stopped).unwrap();
            let stream = std::os::unix::net::UnixStream::connect(&socket).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            (owner, server, stopped, activity, BufReader::new(stream))
        };
        let exchange = |stream: &mut BufReader<std::os::unix::net::UnixStream>, request: Value| {
            writeln!(stream.get_mut(), "{request}").unwrap();
            let mut line = String::new();
            stream.read_line(&mut line).unwrap();
            serde_json::from_str::<Value>(&line).unwrap()
        };
        let hello = json!({"kind":"hello",
            "transport":{"minimum_compatible":1,"current":1},
            "application":{"minimum_compatible":1,"current":1}});
        let (_first_owner, first, first_stopped, first_activity, mut first_peer) = attach();
        let (_second_owner, second, second_stopped, second_activity, mut second_peer) = attach();
        assert_eq!(exchange(&mut first_peer, hello.clone())["kind"], "hello-ok");
        assert_eq!(exchange(&mut second_peer, hello)["kind"], "hello-ok");
        assert_eq!(first_activity.active_sessions(), 1);
        assert_eq!(second_activity.active_sessions(), 1);
        assert_eq!(runtime.coord.authority().unwrap(), authority);

        first_stopped.store(true, Ordering::Release);
        assert!(first.finish().unwrap().clean());
        assert!(first_stopped.load(Ordering::Acquire));
        assert!(!second_stopped.load(Ordering::Acquire));
        assert_eq!(first_activity.active_sessions(), 0);
        assert_eq!(second_activity.active_sessions(), 1);
        assert_eq!(
            exchange(&mut second_peer, json!({"kind":"status"}))["reason"],
            "canonical-build-socket"
        );
        assert!(runtime.healthy());
        assert_eq!(runtime.coord.authority().unwrap(), authority);
        assert!(second.finish().unwrap().clean());
        assert!(!second_stopped.load(Ordering::Acquire));
        assert_eq!(second_activity.active_sessions(), 0);
        assert!(runtime.healthy());
        runtime.shutdown().unwrap();
    }

    #[test]
    fn unexpected_scoped_edge_completion_cancels_its_caller() {
        let stopped = Arc::new(AtomicBool::new(false));
        let controller = Arc::new(ShutdownController::new());
        let normal_shutdown = Arc::new(AtomicBool::new(false));
        let edge: SubsystemWork = Box::new(|_, _| Box::pin(async { Ok(()) }));
        let options = DaemonRunOptions {
            edge_work: Some(stop_on_unexpected_exit(
                edge,
                Arc::clone(&stopped),
                Arc::clone(&controller),
                Arc::clone(&normal_shutdown),
            )),
            ..DaemonRunOptions::default()
        };
        let worker_controller = Arc::clone(&controller);
        let worker = std::thread::spawn(move || run_daemon_controlled(options, worker_controller));
        let server = ServerOwner {
            controller,
            worker: Some(worker),
            normal_shutdown: Some(normal_shutdown),
        };
        let deadline = Instant::now() + Duration::from_secs(5);
        while !stopped.load(Ordering::Acquire) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(stopped.load(Ordering::Acquire));
        assert!(server.finish().unwrap().clean());
    }

    #[test]
    fn shared_output_files_are_private_distinct_and_have_an_aggregate_bound() {
        let owner = crate::test_util::private_tempdir();
        let make = |name: &str| {
            OpenOptions::new()
                .write(true)
                .read(true)
                .create_new(true)
                .mode(0o600)
                .open(owner.path().join(name))
                .unwrap()
        };
        let stdout = make("stdout");
        assert!(
            OperationOutput::captured(stdout.try_clone().unwrap(), stdout.try_clone().unwrap(), 1)
                .is_err()
        );
        let stderr = make("stderr");
        let mut first = OperationOutput::captured(stdout, stderr, 1).unwrap();
        first.event(json!({"operation":"first"})).unwrap();
        let mut second =
            OperationOutput::captured(make("stdout-second"), make("stderr-second"), 1).unwrap();
        second.event(json!({"operation":"second"})).unwrap();
        assert_eq!(
            fs::read_to_string(owner.path().join("stderr")).unwrap(),
            "{\"operation\":\"first\"}\n"
        );
        assert_eq!(
            fs::read_to_string(owner.path().join("stderr-second")).unwrap(),
            "{\"operation\":\"second\"}\n"
        );
        let before = fs::metadata(owner.path().join("stderr")).unwrap().len();
        assert!(
            first
                .line(&"x".repeat(MAX_GRAPH_BYTES as usize + 64 * 1024 + 1))
                .is_err()
        );
        assert_eq!(
            fs::metadata(owner.path().join("stderr")).unwrap().len(),
            before
        );
        assert_eq!(fs::metadata(owner.path().join("stdout")).unwrap().len(), 0);
    }

    #[test]
    fn scoped_socket_refuses_generic_daemon_authority_and_drains_its_open_session() {
        use std::io::{BufRead, BufReader};
        let owner = Arc::new(crate::test_util::private_tempdir());
        let mut mappings = Vec::new();
        for (visible, name) in [
            ("/__rabs/workspace", "source"),
            ("/__rabs/toolchain", "toolchain"),
            ("/__rabs/cargo-home", "cargo"),
            (TARGET, "target"),
            ("/__rabs/home", "home"),
        ] {
            let physical = owner.path().join(name);
            create_private(&physical).unwrap();
            mappings.push((PathBuf::from(visible), physical));
        }
        let paths = CanonicalPaths::new(owner.clone(), mappings).unwrap();
        let cas = Arc::new(
            crate::janitor::store::mount_and_reconcile(&owner.path().join("cas")).unwrap(),
        );
        let coord = Arc::new(CoordLive::with_cas(cas));
        let socket = owner.path().join("home/rustc.sock");
        let stopped = Arc::new(AtomicBool::new(false));
        let controller = Arc::new(ShutdownController::new());
        let activity = CanonicalActivity::new();
        let edge = canonical_edge_work(
            EdgeServerConfig {
                socket_path: socket.clone(),
                state_dir: owner.path().join("shadow"),
                coord: coord.edge_subscriber(),
                prepared_operations: None,
                live_dependency: Some(LiveDependencyLane::new(coord.clone())),
            },
            paths,
            Arc::clone(&activity),
        );
        let options = DaemonRunOptions {
            edge_work: Some(stop_on_exit(edge, stopped.clone(), controller.clone())),
            coord_work: Some(stop_on_exit(
                coordinator_work(coord.clone()),
                stopped.clone(),
                controller.clone(),
            )),
            ..DaemonRunOptions::default()
        };
        let worker_controller = controller.clone();
        let worker = std::thread::spawn(move || run_daemon_controlled(options, worker_controller));
        let server = ServerOwner {
            controller,
            worker: Some(worker),
            normal_shutdown: None,
        };
        wait_ready(&server, &socket, &coord, &stopped).unwrap();
        let stream = std::os::unix::net::UnixStream::connect(&socket).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut stream = BufReader::new(stream);
        let exchange = |stream: &mut BufReader<std::os::unix::net::UnixStream>, request: Value| {
            writeln!(stream.get_mut(), "{request}").unwrap();
            let mut reply = String::new();
            stream.read_line(&mut reply).unwrap();
            serde_json::from_str::<Value>(&reply).unwrap()
        };
        let hello = exchange(
            &mut stream,
            json!({"kind":"hello",
            "transport":{"minimum_compatible":1,"current":1},
            "application":{"minimum_compatible":1,"current":1}}),
        );
        assert_eq!(hello["kind"], "hello-ok");
        assert_eq!(activity.active_sessions(), 1);
        for kind in [
            "status",
            "serve",
            "consult",
            "prepared-submit",
            "prepared-cancel",
        ] {
            let reply = exchange(&mut stream, json!({"kind":kind}));
            assert_eq!(reply["kind"], "refusal", "{reply}");
            assert_eq!(reply["reason"], "canonical-build-socket", "{reply}");
        }
        // Leave the peer open deliberately. The embedded daemon must cancel
        // and join its own session before releasing socket/path ownership.
        assert!(server.finish().unwrap().clean());
        assert!(!socket.exists());
        assert!(stopped.load(Ordering::Acquire));
        assert!(!coord.available());
        assert_eq!(activity.active_sessions(), 0);
    }

    fn reuse_source(source: &[u8], manifest: &[u8], cache: Option<&[u8]>) -> SourceManifest {
        use rabs_sandbox::source_transfer::SourceFile;
        let mut files = vec![("Cargo.toml", manifest), ("src/lib.rs", source)];
        if let Some(cache) = cache {
            files.push((
                "captured-cargo/registry/src/index-123/dependency-1.0.0/src/lib.rs",
                cache,
            ));
        }
        SourceManifest::new(
            files
                .into_iter()
                .map(|(path, bytes)| SourceFile {
                    path: path.into(),
                    len: bytes.len() as u64,
                    sha256: Sha256::digest(bytes).into(),
                    executable: false,
                })
                .collect(),
        )
        .unwrap()
    }

    /// Pure key inputs only; this capability fixture never executes a namespace
    /// and makes no assertion about this test host's measured isolation support.
    struct ReuseKeyFixture {
        request: Value,
        source: SourceManifest,
        projection: Option<CargoHomeProjection>,
        spec: CanonicalNamespaceSpec,
        support: HostIsolationSupport,
        program: &'static str,
        args: Vec<String>,
        config: TargetCacheConfig,
        wrapper: [u8; 32],
        driver: String,
        closed_dependency_execution: bool,
    }

    impl ReuseKeyFixture {
        fn new() -> Self {
            let mut plan = CanonicalMountPlan::new(
                "/physical/toolchain",
                "/physical/workspace",
                "/physical/cargo",
                "/physical/home",
            );
            plan.out_units.push(UnitMount {
                unit: "cargo".into(),
                backing: "/physical/target".into(),
            });
            let mut spec = plan.to_spec().unwrap();
            make_read_only(&mut spec, "/__rabs/workspace").unwrap();
            make_read_only(&mut spec, "/__rabs/home").unwrap();
            Self {
                request: json!({"toolchain_identity":{
                    "version":rabs_sandbox::toolchain_dataset::TOOLCHAIN_DATASET_VERSION,
                    "sha256":"ab".repeat(32),"files":7,"bytes":1024}}),
                source: reuse_source(b"pub const VALUE:u8=1;", b"manifest", None),
                projection: None,
                spec,
                support: HostIsolationSupport {
                    bubblewrap: Some("pure-key-fixture".into()),
                    unprivileged_userns: true,
                    overlayfs: false,
                    cgroup_v2: false,
                    landlock: false,
                },
                program: CARGO,
                args: [
                    "check",
                    "--offline",
                    "--locked",
                    "--manifest-path",
                    "/__rabs/workspace/Cargo.toml",
                    "--message-format=json",
                    "--jobs",
                    "2",
                ]
                .map(str::to_owned)
                .into(),
                config: TargetCacheConfig {
                    runtime_epoch: "host-1".into(),
                    max_bytes: 1024 * 1024,
                    max_families: 8,
                },
                wrapper: [5; 32],
                driver: "driver-1".into(),
                closed_dependency_execution: false,
            }
        }

        fn key(&self) -> [u8; 32] {
            TargetReuseContext {
                request: &self.request,
                workspace: self
                    .projection
                    .as_ref()
                    .and_then(CargoHomeProjection::workspace_manifest)
                    .unwrap_or(&self.source),
                full_source: self.source.digest(),
                projection: self.projection.as_ref(),
                spec: &self.spec,
                support: &self.support,
                program: self.program,
                args: &self.args,
                build_identity: &self.driver,
                wrapper: self.wrapper,
                closed_dependency_execution: self.closed_dependency_execution,
            }
            .key(&self.config)
            .unwrap()
        }

        fn with_captured_cache(source: &[u8], cache: &[u8]) -> Self {
            use rabs_sandbox::cargo_home::ISOLATED_CARGO_HOME_SOURCE_VERSION;
            let mut fixture = Self::new();
            fixture.source = reuse_source(source, b"manifest", Some(cache));
            fixture.projection = Some(
                CargoHomeProjection::for_version(
                    ISOLATED_CARGO_HOME_SOURCE_VERSION,
                    "captured-cargo",
                    &fixture.source,
                )
                .unwrap(),
            );
            fixture
        }
    }

    #[test]
    fn private_target_key_reuses_only_metadata_check_selections_and_source_edits() {
        let fixture = ReuseKeyFixture::new();
        let original = fixture.key();
        let mut changed = ReuseKeyFixture::new();
        changed
            .args
            .extend(["--features".into(), "extra".into(), "--lib".into()]);
        changed.source = reuse_source(b"pub const VALUE:u8=2;", b"manifest", None);
        assert_eq!(changed.key(), original);

        changed.source = reuse_source(b"pub const VALUE:u8=2;", b"changed manifest", None);
        assert_ne!(changed.key(), original);
        for arguments in [
            ["--target", "aarch64-unknown-linux-gnu"],
            ["--profile", "release"],
        ] {
            let mut changed = ReuseKeyFixture::new();
            changed.args.extend(arguments.map(str::to_owned));
            assert_ne!(changed.key(), original, "{arguments:?}");
        }
        let mut changed = ReuseKeyFixture::new();
        *changed.args.last_mut().unwrap() = "4".into();
        assert_ne!(changed.key(), original, "job grant is an exact input");
    }

    #[test]
    fn private_target_codegen_binds_data_that_assembler_dep_info_does_not_track() {
        use rabs_sandbox::source_transfer::SourceFile;

        let with_payload = |bytes: &[u8]| {
            let mut files = ReuseKeyFixture::new().source.files().to_vec();
            files.push(SourceFile {
                path: "assembly-payload.bin".into(),
                len: bytes.len() as u64,
                sha256: Sha256::digest(bytes).into(),
                executable: false,
            });
            SourceManifest::new(files).unwrap()
        };
        let mut build = ReuseKeyFixture::new();
        build.args[0] = "build".into();
        build.source = with_payload(b"first embedded payload");
        let original = build.key();
        build
            .args
            .extend(["--lib".into(), "--features".into(), "fast".into()]);
        assert_eq!(
            build.key(),
            original,
            "identical source still shares Cargo selections"
        );
        build.source = with_payload(b"other embedded payload");
        assert_ne!(
            build.key(),
            original,
            "untracked assembler data must invalidate codegen"
        );

        // A build must not import a check's normalized source-edit seed and
        // thereby inherit codegen outputs from an earlier build in that family.
        let mut check = ReuseKeyFixture::new();
        check.source = with_payload(b"first embedded payload");
        assert_ne!(
            check.key(),
            original,
            "check and codegen source policies are separate"
        );
    }

    #[test]
    fn private_target_tests_reuse_compiled_state_across_no_run_and_runtime_arguments() {
        let mut tests = ReuseKeyFixture::new();
        tests.args[0] = "test".into();
        tests.closed_dependency_execution = true;
        tests.spec.env.push(("RUSTDOC".into(), RUSTDOC.into()));
        tests.args.push("--no-run".into());
        let compiled = tests.key();

        tests.args.pop();
        assert_eq!(
            tests.key(),
            compiled,
            "running tests may reuse their compiled state"
        );
        tests.args.extend([
            "selected test".into(),
            "--".into(),
            "--exact".into(),
            "--no-run".into(),
        ]);
        assert_eq!(
            tests.key(),
            compiled,
            "a literal harness --no-run is not Cargo's mode"
        );
        *tests.args.last_mut().unwrap() = "--nocapture".into();
        assert_eq!(
            tests.key(),
            compiled,
            "test runtime choices do not change compilation"
        );

        tests.source = reuse_source(b"changed test source", b"manifest", None);
        assert_ne!(
            tests.key(),
            compiled,
            "test execution requires exact captured source"
        );
        tests.source = ReuseKeyFixture::new().source;
        tests.args.insert(1, "--doc".into());
        assert_ne!(
            tests.key(),
            compiled,
            "doc selection retains its separate target family"
        );
    }

    #[test]
    fn private_clippy_targets_bind_driver_full_source_selections_and_ordered_lints() {
        let clippy = || {
            let mut fixture = ReuseKeyFixture::new();
            fixture.program = CARGO_CLIPPY;
            fixture.args[0] = "clippy".into();
            fixture.closed_dependency_execution = true;
            fixture.spec.env.push(("CARGO".into(), CARGO.into()));
            fixture
        };
        let original = clippy().key();
        assert_ne!(
            original,
            ReuseKeyFixture::new().key(),
            "a check cannot make lint execution fresh"
        );
        let mut changed = clippy();
        changed.source = reuse_source(b"pub const VALUE:u8=2;", b"manifest", None);
        assert_ne!(
            changed.key(),
            original,
            "Clippy may read source not listed in compiler dep-info"
        );
        for option in ["--no-deps", "--all-targets", "--workspace"] {
            let mut changed = clippy();
            changed.args.push(option.into());
            assert_ne!(
                changed.key(),
                original,
                "Clippy selection must retain lint coverage: {option}"
            );
        }
        let mut changed = clippy();
        changed.program = CARGO;
        assert_ne!(
            changed.key(),
            original,
            "the actual captured driver is part of the family"
        );
        let mut changed = clippy();
        changed
            .args
            .extend(["--", "-D", "warnings", "-A", "dead_code"].map(str::to_owned));
        let deny_then_allow = changed.key();
        assert_ne!(deny_then_allow, original);
        let tail = changed.args.len() - 4;
        changed.args[tail..]
            .clone_from_slice(&["-A", "dead_code", "-D", "warnings"].map(str::to_owned));
        assert_ne!(
            changed.key(),
            deny_then_allow,
            "later lint levels can override earlier ones"
        );
    }

    #[test]
    fn private_run_and_bench_targets_reuse_compilation_but_bind_source_and_profile() {
        for command in ["run", "bench"] {
            let mut fixture = ReuseKeyFixture::new();
            fixture.closed_dependency_execution = true;
            fixture.args[0] = command.into();
            let original = fixture.key();
            fixture
                .args
                .extend(["--".into(), "--no-run".into(), "".into(), "雪".into()]);
            assert_eq!(
                fixture.key(),
                original,
                "{command} runtime arguments cannot skip a body or fragment its compile state"
            );
            fixture
                .args
                .truncate(fixture.args.iter().position(|arg| arg == "--").unwrap());
            if command == "bench" {
                fixture.args.push("--no-run".into());
                assert_eq!(
                    fixture.key(),
                    original,
                    "bench no-run and execution may share compiled artifacts"
                );
                fixture.args.pop();
            }
            fixture.args.extend([
                "--profile".into(),
                if command == "bench" { "dev" } else { "release" }.into(),
            ]);
            assert_ne!(
                fixture.key(),
                original,
                "{command} compilation profile changed"
            );
            fixture.args.truncate(fixture.args.len() - 2);
            fixture.source =
                reuse_source(b"changed program or benchmark source", b"manifest", None);
            assert_ne!(
                fixture.key(),
                original,
                "{command} must retain its complete source family"
            );
        }
    }

    #[test]
    fn private_target_key_excludes_physical_roots_but_binds_runtime_and_execution_inputs() {
        let original = ReuseKeyFixture::new().key();
        let mut relocated = ReuseKeyFixture::new();
        for (index, bind) in relocated
            .spec
            .ro_binds
            .iter_mut()
            .chain(&mut relocated.spec.rw_binds)
            .enumerate()
        {
            bind.backing = PathBuf::from(format!("/relocated/backing-{index}"));
        }
        relocated.spec.ro_binds.reverse();
        relocated.spec.rw_binds.reverse();
        relocated.config.max_bytes *= 2;
        assert_eq!(relocated.key(), original);

        let mut changed = ReuseKeyFixture::new();
        changed.config.runtime_epoch = "host-2".into();
        assert_ne!(changed.key(), original);
        let mut changed = ReuseKeyFixture::new();
        changed.wrapper = [6; 32];
        assert_ne!(changed.key(), original);
        let mut changed = ReuseKeyFixture::new();
        changed.driver = "driver-2".into();
        assert_ne!(changed.key(), original);
        let mut changed = ReuseKeyFixture::new();
        changed.request["toolchain_identity"]["sha256"] = json!("cd".repeat(32));
        assert_ne!(changed.key(), original);
        let mut changed = ReuseKeyFixture::new();
        changed
            .spec
            .env
            .push(("RUSTFLAGS".into(), "-C opt-level=2".into()));
        assert_ne!(changed.key(), original);
        let mut changed = ReuseKeyFixture::new();
        changed.spec.cwd = "/__rabs/workspace/member".into();
        assert_ne!(changed.key(), original);
    }

    #[test]
    fn private_target_families_separate_absent_empty_and_changed_application_inputs() {
        let mut identities = BTreeSet::new();
        for value in [None, Some(""), Some("first"), Some("second")] {
            let mut profile = application_environment_profile();
            if let Some(value) = value {
                profile.env.insert("APP_VERSION".into(), value.into());
            }
            let mut fixture = ReuseKeyFixture::new();
            fixture
                .spec
                .env
                .extend(profile.command_environment().unwrap());
            assert!(identities.insert(fixture.key()));
        }
        let identity = |encoded: &str| {
            let mut profile = application_environment_profile();
            profile.env = serde_json::from_str(encoded).unwrap();
            let mut fixture = ReuseKeyFixture::new();
            fixture
                .spec
                .env
                .extend(profile.command_environment().unwrap());
            fixture.key()
        };
        assert_eq!(
            identity(r#"{"Z_LAST":"z","A_FIRST":"a"}"#),
            identity(r#"{"A_FIRST":"a","Z_LAST":"z"}"#),
            "profile object order is not an application input"
        );
    }

    #[test]
    fn private_target_key_keeps_captured_dependency_cache_bytes_exact_across_local_edits() {
        let first =
            ReuseKeyFixture::with_captured_cache(b"old workspace source", b"dependency bytes");
        let edited =
            ReuseKeyFixture::with_captured_cache(b"edited workspace source", b"dependency bytes");
        assert_eq!(first.key(), edited.key());
        let changed_cache = ReuseKeyFixture::with_captured_cache(
            b"edited workspace source",
            b"changed dependency bytes",
        );
        assert_ne!(first.key(), changed_cache.key());
    }

    #[test]
    fn private_target_key_separates_project_executor_policy_from_local_capture_authority() {
        let pure = ReuseKeyFixture::new();
        let mut executors = ReuseKeyFixture::new();
        executors.closed_dependency_execution = true;
        assert_ne!(pure.key(), executors.key());
        executors.closed_dependency_execution = false;
        assert_eq!(pure.key(), executors.key());
    }

    #[test]
    fn private_target_executor_graph_binds_untracked_source_bytes_and_membership() {
        use rabs_sandbox::source_transfer::SourceFile;

        let source_with_data = |bytes: Option<&[u8]>| {
            let mut files = ReuseKeyFixture::new().source.files().to_vec();
            if let Some(bytes) = bytes {
                files.push(SourceFile {
                    path: "macro-input.txt".into(),
                    len: bytes.len() as u64,
                    sha256: Sha256::digest(bytes).into(),
                    executable: false,
                });
            }
            SourceManifest::new(files).unwrap()
        };
        let mut fixture = ReuseKeyFixture::new();
        fixture.closed_dependency_execution = true;
        fixture.source = source_with_data(Some(b"first expansion"));
        let original = fixture.key();

        for bind in fixture
            .spec
            .ro_binds
            .iter_mut()
            .chain(&mut fixture.spec.rw_binds)
        {
            bind.backing = PathBuf::from("/other-checkout/independent-backing");
        }
        assert_eq!(fixture.key(), original, "identical relocated inputs reuse");
        fixture.source = source_with_data(Some(b"other expansion"));
        assert_ne!(
            fixture.key(),
            original,
            "untracked data bytes dirty executors"
        );
        fixture.source = source_with_data(None);
        assert_ne!(
            fixture.key(),
            original,
            "missing untracked data dirties executors"
        );

        let mut cached = ReuseKeyFixture::with_captured_cache(b"workspace", b"dependency");
        cached.closed_dependency_execution = true;
        let before = cached.key();
        let mut edited = ReuseKeyFixture::with_captured_cache(b"edited workspace", b"dependency");
        edited.closed_dependency_execution = true;
        assert_ne!(edited.key(), before, "projected source remains exact too");
    }
}
