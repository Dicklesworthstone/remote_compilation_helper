//! Local canonical Cargo execution connected to the coordinator's rustc cache.
//!
//! This explicit profile runs selected Cargo check, build, test, nextest, run, bench or Clippy offline and locked against
//! captured inputs and a captured toolchain. Cargo itself runs at canonical
//! paths, so unit hashes and rustc arguments are stable across checkouts. A
//! fresh operation-scoped socket admits only rustc requests; the persistent
//! CAS and the ordinary daemon socket are never visible to the build.
//!
//! The selected Cargo unit graph identifies active build scripts and procedural
//! macros. Their presence, or a test/nextest/run/bench/Clippy command, disables local compiler-result authority for the whole
//! operation; eligible dependency caching requires isolated workers. Pure check/build graphs
//! retain the existing evidence-gated metadata lane; archive codegen requires an
//! isolated worker. Selected workspace compilations can execute freshly on workers;
//! unsupported rustc invocations compile normally in the namespace. Workspace
//! results never gain action-cache publication or replay authority.

mod remote_artifacts;
pub(super) mod remote_operation;
pub mod remote_service;
pub(crate) mod remote_toolchains;
pub mod service;
mod target_state;
pub(crate) use target_state::RestoredTargetProvenance;

use super::live::{CoordLive, cluster_id};
use super::live_dependency::LiveDependencyLane;
use super::live_dependency::canonical::{CanonicalPaths, CommittedOutputExportError};
use super::live_dependency::remote::{RemoteDependencies, SharedRemoteExecutions};
use super::source_delivery::control::{
    PreparationControl, PreparationRootGuard, UnconfirmedCleanup,
};
use crate::controlled_output::ControlledOutput;
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
use rabs_protocol::subscriber_interest::{ChildTermination, RelayAction, relay_child_termination};
use rabs_sandbox::canonical_mounts::{CanonicalMountPlan, UnitMount};
use rabs_sandbox::canonical_namespace::{
    CanonicalNamespaceSpec, HostIsolationSupport, build_canonical_argv, command_for,
};
use rabs_sandbox::cargo_check::{
    CompilationCommand, CompilationSelection, CompilationStdin, run_build_selection,
    validate_compilation_unit_graph,
};
use rabs_sandbox::cargo_home::CargoHomeProjection;
use rabs_sandbox::cargo_target::state::{PrivateTreeSnapshot, SourceTimestamps};
use rabs_sandbox::process_context::CommandContext;
use rabs_sandbox::source_transfer::{
    MAX_SOURCE_BYTES, MAX_SOURCE_CHUNK, SourceCheckpointError, SourceFile, SourceManifest,
    SourceReceiver,
};
use rabs_sandbox::toolchain_cache::{CAPACITY as TOOLCHAIN_CAPACITY, ToolchainPool};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, IsTerminal, Write};
use std::os::fd::AsFd;
use std::os::unix::fs::{
    DirBuilderExt, FileExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt,
};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, TryLockError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use target_state::{TargetCacheConfig, TargetState};

const PROFILE_VERSION: &str = "canonical-compile-local-v1";
const CARGO: &str = "/__rabs/toolchain/bin/cargo";
const CARGO_CLIPPY: &str = "/__rabs/toolchain/bin/cargo-clippy";
const CARGO_NEXTEST: &str = "/__rabs/toolchain/bin/cargo-nextest";
const CLIPPY_DRIVER: &str = "/__rabs/toolchain/bin/clippy-driver";
const RUSTC: &str = "/__rabs/toolchain/bin/rustc";
const RUSTDOC: &str = "/__rabs/toolchain/bin/rustdoc";
const TARGET: &str = "/__rabs/out/cargo";
const WRAPPER: &str = "/__rabs/home/control/rabs-wrap";
const SOCKET: &str = "/__rabs/home/control/rustc.sock";
const MAX_GRAPH_BYTES: u64 = 16 * 1024 * 1024;

/// Report a final canonical CLI error without re-entering a blocked caller
/// sink after the operation has already drained. The caller keeps its error
/// exit code whether or not stderr accepts this best-effort diagnostic.
pub fn report_cli_error(message: std::fmt::Arguments<'_>) {
    let stopped = AtomicBool::new(false);
    if let Ok(mut stderr) = ControlledOutput::new(
        &io::stderr(),
        &stopped,
        Instant::now() + Duration::from_millis(100),
    ) {
        let _ = writeln!(stderr, "{message}");
    }
}

/// Relay only after the command's operation owner, output writers and signal
/// bridge have drained. An ordinary high exit must never become a signal.
pub fn exit_like(termination: ChildTermination) -> ! {
    match relay_child_termination(termination, true) {
        RelayAction::ExitWith(code) | RelayAction::ExitWithConventionalCode(code) => {
            std::process::exit(code)
        }
        RelayAction::RestoreDefaultAndResignal { signal_number } => {
            // The same native relay is used by rabs-wrap. Rust ignores PIPE,
            // and the caller may leave a signal blocked or handled. Restore
            // its default and unblock it before raising on this process.
            let _ = signal_hook::low_level::emulate_default_handler(signal_number);
            let _ = signal_hook::low_level::raise(signal_number);
            // Unknown platform signals may have no supported native relay.
            // This is a last-resort failure, never an inferred classification.
            std::process::exit(128 + signal_number)
        }
    }
}

fn native_termination(status: std::process::ExitStatus) -> io::Result<ChildTermination> {
    use std::os::unix::process::ExitStatusExt;
    let termination = match (status.code(), status.signal()) {
        (Some(code), None) => ChildTermination::Exited(code),
        (None, Some(signal_number)) => ChildTermination::Signaled { signal_number },
        _ => {
            return Err(invalid(
                "canonical launcher did not return a terminal native status",
            ));
        }
    };
    rabs_protocol::canonical_service::encode_termination(termination).map_err(io::Error::other)?;
    Ok(termination)
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, Eq, PartialEq)]
enum SourceSelection {
    #[default]
    #[serde(skip)]
    Complete,
    #[serde(rename = "cargo-unit-graph-v1")]
    UnitGraph,
}

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
    /// Omission preserves command defaults. Explicit `closed` supplies EOF and
    /// permits noninteractive run/bench execution through a shared service.
    stdin: Option<CompilationStdin>,
    /// Source-root-relative input for run, test or bench execution. The exact member
    /// is copied from the sealed source into private, read-only descriptor
    /// custody before Cargo starts. Mutually exclusive with `stdin`.
    stdin_file: Option<String>,
    #[serde(default = "default_manifest")]
    manifest: String,
    vendor: Option<String>,
    cargo_home_source: Option<PathBuf>,
    /// Resolve external inputs from this command's actual Cargo unit graph.
    /// An omitted field retains complete locked-graph preparation.
    #[serde(default)]
    source_selection: SourceSelection,
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

/// Cache restoration and capture can copy gigabytes. A cancelled root must
/// leave the queue promptly even while another root owns that I/O, and must
/// recheck its interest after acquiring the lock before touching cache state.
fn acquire_target_cache_lock<'a>(
    lock: &'a Mutex<()>,
    stopped: &impl Fn() -> bool,
) -> io::Result<MutexGuard<'a, ()>> {
    loop {
        if stopped() {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "canonical target cache admission cancelled",
            ));
        }
        match lock.try_lock() {
            Ok(guard) => {
                if stopped() {
                    return Err(io::Error::new(
                        io::ErrorKind::Interrupted,
                        "canonical target cache admission cancelled",
                    ));
                }
                return Ok(guard);
            }
            Err(TryLockError::WouldBlock) => std::thread::sleep(Duration::from_millis(10)),
            Err(TryLockError::Poisoned(_)) => {
                return Err(io::Error::other("canonical target cache lock poisoned"));
            }
        }
    }
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
        let remote = self.remote.as_ref().map_or(Ok(()), |pool| pool.shutdown());
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
        remote?;
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
        if let Some(remote) = &self.remote {
            let _ = remote.shutdown();
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
enum OperationOutput<'a> {
    Inherit {
        stdout: ControlledOutput<'a>,
        stderr: ControlledOutput<'a>,
    },
    Captured {
        stdout: File,
        stderr: File,
        maximum: u64,
        used: u64,
        cargo_maximum: u64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProfileStdin<'a> {
    Closed,
    Inherit,
    Captured(&'a str),
}

impl<'a> OperationOutput<'a> {
    fn inherited(
        stdout: &impl AsFd,
        stderr: &impl AsFd,
        stopped: &'a AtomicBool,
        deadline: Instant,
    ) -> io::Result<Self> {
        // Capture the caller's descriptors before any source preparation or
        // execution. Only driver diagnostics use these bounded writers; Cargo
        // still inherits its original streams under process-group supervision.
        Ok(Self::Inherit {
            stdout: ControlledOutput::new(stdout, stopped, deadline)?,
            stderr: ControlledOutput::new(stderr, stopped, deadline)?,
        })
    }

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
            Self::Inherit { stderr, .. } => writeln!(stderr, "{line}"),
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
            Self::Inherit { stdout, stderr } => {
                io::copy(&mut output.stdout.reader()?, stdout)?;
                io::copy(&mut output.stderr.reader()?, stderr)?;
                stdout.flush()?;
                stderr.flush()
            }
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
            Self::Inherit { .. } => CargoOutput::Inherit { inherit_stdin },
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
    /// Keep compiler parallelism distinct from the declared test-runner demand.
    /// Retained profile validation stays compatible; only fresh admission uses
    /// this requirement before capture or root reservation.
    fn execution_slots(&self) -> io::Result<u32> {
        if self.command == CompilationCommand::Nextest {
            rabs_sandbox::cargo_artifacts::nextest::execution_slots(
                &self.selection.clone().unwrap_or_default(),
                self.jobs,
            )
        } else {
            Ok(self.jobs)
        }
    }

    fn client_deadline(&self) -> io::Result<Instant> {
        // Admission may wait for one operation budget, followed by bounded
        // Cargo planning and execution. Capture and final drain keep the same
        // finite allowance as the local service protocol.
        let budget =
            Duration::from_secs(self.timeout_seconds.saturating_mul(4).saturating_add(600));
        Instant::now()
            .checked_add(budget)
            .ok_or_else(|| invalid("canonical client deadline overflow"))
    }

    fn validate_logical(&self) -> io::Result<()> {
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
        self.stdin_policy()?;
        self.command_environment()?;
        self.source_selection_version()?;
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
        Ok(())
    }

    fn validate(&self) -> io::Result<()> {
        self.validate_logical()?;
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
        } else if self.command == CompilationCommand::Nextest {
            CARGO_NEXTEST
        } else {
            CARGO
        }
    }

    fn graph_program(&self) -> &'static str {
        if self.command == CompilationCommand::Nextest {
            CARGO
        } else {
            self.program()
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
            None => CompilationSelection::default().cargo_arguments(command)?,
        };
        args.extend([
            "--offline".into(),
            "--locked".into(),
            "--manifest-path".into(),
            self.manifest_path(),
        ]);
        if command == CompilationCommand::Nextest {
            // Nextest's --jobs controls tests, not Cargo compilation, and its
            // --message-format describes test reports, not Cargo artifacts.
            // Preserve the captured runner configuration unless the selection
            // explicitly supplies test_threads.
            args.extend(["--build-jobs".into(), self.jobs.to_string()]);
        } else {
            args.extend([
                "--message-format=json".into(),
                "--jobs".into(),
                self.jobs.to_string(),
            ]);
        }
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
        } else if self.command == CompilationCommand::Nextest {
            let selection = self
                .selection
                .clone()
                .unwrap_or_default()
                .nextest_build_selection()?;
            self.selected_prefix(CompilationCommand::Test, Some(&selection))?
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
            CompilationCommand::Test | CompilationCommand::Bench | CompilationCommand::Nextest
        ) && self
            .selection
            .as_ref()
            .is_some_and(|selection| selection.no_run)
    }

    fn stdin_policy(&self) -> io::Result<ProfileStdin<'_>> {
        if let Some(path) = &self.stdin_file {
            require(self.stdin.is_none(), "choose stdin or stdin_file, not both")?;
            require(
                self.command == CompilationCommand::Run
                    || (matches!(
                        self.command,
                        CompilationCommand::Test
                            | CompilationCommand::Bench
                            | CompilationCommand::Nextest
                    ) && !self.no_run()),
                "captured stdin_file is supported only for run, test, nextest or bench execution",
            )?;
            require(
                relative_member(path),
                "stdin_file must be an ordinary source-root-relative file",
            )?;
            return Ok(ProfileStdin::Captured(path));
        }
        Ok(
            match self.command.stdin_policy(self.no_run(), self.stdin)? {
                CompilationStdin::Closed => ProfileStdin::Closed,
                CompilationStdin::Inherit => ProfileStdin::Inherit,
            },
        )
    }

    fn inherits_stdin(&self) -> io::Result<bool> {
        Ok(matches!(self.stdin_policy()?, ProfileStdin::Inherit))
    }

    fn validate_stdin(&self, terminal: bool) -> io::Result<()> {
        // Managed children have their own process group. Reading the caller's
        // controlling terminal could stop that group with SIGTTIN; supporting
        // interactive job control needs a separate, owned terminal/session.
        require(
            !self.inherits_stdin()? || !terminal,
            "canonical run/test/bench requires nonterminal stdin when input is inherited: redirect from a pipe, file, or /dev/null, select stdin: closed for EOF or stdin_file for captured input, or run a delivered build outside this noninteractive profile",
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
        if matches!(
            self.command,
            CompilationCommand::Test | CompilationCommand::Doc
        ) {
            environment.push(("RUSTDOC".into(), RUSTDOC.into()));
        }
        if matches!(
            self.command,
            CompilationCommand::Clippy | CompilationCommand::Nextest
        ) {
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
        if let Some(version) = self.source_selection_version()? {
            source["selection"] = json!(version);
        }
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

    fn source_selection_version(&self) -> io::Result<Option<&'static str>> {
        if self.source_selection == SourceSelection::Complete {
            return Ok(None);
        }
        Ok(Some("cargo-unit-graph-v1"))
    }
}

#[cfg(test)]
pub(super) fn source_specification_for_test(profile: Value) -> io::Result<Value> {
    let profile: Profile = serde_json::from_value(profile)
        .map_err(|error| invalid(format!("invalid native test profile: {error}")))?;
    profile.source_specification()
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
    destination: &mut OperationOutput<'_>,
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
        None,
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
            None,
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

/// Synchronous capture and planning need cancellation before the operation's
/// coordinator exists. Keep the same stop flag through capture, execution and
/// delivery, and join the signal bridge before releasing the command owner.
pub(super) struct OperationCancellation {
    pub(super) stopped: Arc<AtomicBool>,
    done: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
    native_signals: Option<signal_hook::iterator::Handle>,
    first_signal: Arc<AtomicI32>,
}

impl OperationCancellation {
    pub(super) fn start() -> io::Result<Self> {
        let shutdown = Arc::new(ShutdownController::new());
        shutdown.listen_for_signals();
        let stopped = Arc::new(AtomicBool::new(false));
        let done = Arc::new(AtomicBool::new(false));
        let child_stop = Arc::clone(&stopped);
        let child_done = Arc::clone(&done);
        let thread = std::thread::Builder::new()
            .name("rabs-canonical-signals".into())
            .spawn(move || {
                while !child_done.load(Ordering::Acquire) {
                    if shutdown.is_shutting_down() {
                        child_stop.store(true, Ordering::Release);
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
            })?;
        Ok(Self {
            stopped,
            done,
            thread: Some(thread),
            native_signals: None,
            first_signal: Arc::new(AtomicI32::new(0)),
        })
    }

    /// The native CLI owns INT/TERM/HUP until cleanup finishes. The persistent
    /// daemon's shutdown/reload listeners deliberately remain unchanged.
    fn start_native() -> io::Result<Self> {
        use signal_hook::consts::{SIGHUP, SIGINT, SIGTERM};
        let mut signals = signal_hook::iterator::Signals::new([SIGINT, SIGTERM, SIGHUP])?;
        let handle = signals.handle();
        let stopped = Arc::new(AtomicBool::new(false));
        let first_signal = Arc::new(AtomicI32::new(0));
        let child_stop = Arc::clone(&stopped);
        let child_signal = Arc::clone(&first_signal);
        let thread = std::thread::Builder::new()
            .name("rabs-canonical-native-signals".into())
            .spawn(move || {
                let observe = |signal| {
                    // Standard signals may coalesce, and the iterator does
                    // not order a pending batch by arrival time. Retain the
                    // first cancellation observed by this bridge; later
                    // observations cannot replace it while the operation drains.
                    if child_signal
                        .compare_exchange(0, signal, Ordering::AcqRel, Ordering::Acquire)
                        .is_ok()
                    {
                        child_stop.store(true, Ordering::Release);
                    }
                };
                for signal in signals.forever() {
                    observe(signal);
                }
                // Closing the iterator wakes its thread. A signal may already
                // be queued even if this bridge has not yet been scheduled;
                // retain it before releasing the handler and selecting a fate.
                for signal in signals.pending() {
                    observe(signal);
                }
            })?;
        Ok(Self {
            stopped,
            done: Arc::new(AtomicBool::new(false)),
            thread: Some(thread),
            native_signals: Some(handle),
            first_signal,
        })
    }

    fn join_bridge(&mut self) {
        self.done.store(true, Ordering::Release);
        if let Some(handle) = &self.native_signals {
            handle.close();
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }

    /// Call only after all operation owners have returned. A service client
    /// additionally requires the server's drained EOF before relaying a signal.
    fn finish(
        mut self,
        result: io::Result<ChildTermination>,
        cleanup_confirmed: bool,
    ) -> io::Result<ChildTermination> {
        self.join_bridge();
        let cleanup_confirmed = cleanup_confirmed
            && (result.is_ok()
                || result
                    .as_ref()
                    .is_err_and(|error| error.kind() == io::ErrorKind::Interrupted))
            && !result.as_ref().is_err_and(|error| {
                error
                    .get_ref()
                    .is_some_and(|inner| inner.is::<UnconfirmedCleanup>())
            });
        match self.first_signal.load(Ordering::Acquire) {
            signal_number if signal_number != 0 && cleanup_confirmed => {
                Ok(ChildTermination::Signaled { signal_number })
            }
            _ => result,
        }
    }
}

impl Drop for OperationCancellation {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::Release);
        self.join_bridge();
    }
}

/// Run the explicit local profile with the SAME release policy and build
/// identity as the normal daemon. This entry point intentionally has no
/// implicit advisory-policy overload.
///
/// Planning output is captured under a byte bound. The actual compilation inherits
/// stdout/stderr, so diagnostics and Cargo JSON reach the caller immediately
/// with their original bytes and native pipe/terminal behavior. Preserve the
/// supervised launcher's exact native termination and the first client
/// cancellation observed by its signal bridge after cleanup. Bubblewrap may already encode an inner
/// Cargo signal as an ordinary high exit; that ambiguity is never guessed away.
/// A timeout or incomplete process-group cleanup remains an error even when a
/// signal handler managed to exit zero.
pub fn run_profile_with_release(
    path: &Path,
    release_mode: ReleaseAuthorizationMode,
    build_identity: String,
) -> io::Result<ChildTermination> {
    let cancellation = OperationCancellation::start_native()?;
    let mut cleanup_confirmed = true;
    let result = (|| {
        let (_, bytes) = read_stable(path, 64 * 1024)?;
        let profile: Profile =
            serde_json::from_slice(&bytes).map_err(|error| invalid(error.to_string()))?;
        // Refuse unsupported terminal input before validating source roots,
        // acquiring state, probing namespaces, or capturing any source bytes.
        profile.validate_stdin(std::io::stdin().is_terminal())?;
        if profile.service_socket.is_some() && profile.inherits_stdin()? {
            return Err(invalid(
                "canonical service does not accept commands with inherited stdin; select stdin: closed for EOF or stdin_file for captured input",
            ));
        }
        profile.execution_slots()?;
        profile.validate()?;
        if profile.service_socket.is_some() {
            return service::run_client_profile(
                path,
                release_mode,
                build_identity,
                &cancellation.stopped,
                &mut cleanup_confirmed,
            );
        }
        let output = OperationOutput::inherited(
            &io::stdout(),
            &io::stderr(),
            &cancellation.stopped,
            profile.client_deadline()?,
        )?;
        run_operation(
            profile,
            release_mode,
            build_identity,
            None,
            Arc::clone(&cancellation.stopped),
            output,
            None,
        )
        .map(|outcome| outcome.termination)
    })();
    cancellation.finish(result, cleanup_confirmed)
}

pub(super) fn run_shared_profile(
    bytes: &[u8],
    runtime: Arc<SharedRuntime>,
    stopped: Arc<AtomicBool>,
    stdout: File,
    stderr: File,
    maximum: u64,
) -> io::Result<ChildTermination> {
    require(
        bytes.len() <= 64 * 1024,
        "canonical profile exceeds its byte bound",
    )?;
    let profile: Profile =
        serde_json::from_slice(bytes).map_err(|error| invalid(error.to_string()))?;
    require(
        !profile.inherits_stdin()?,
        "canonical service does not accept commands with inherited stdin; select stdin: closed for EOF or stdin_file for captured input",
    )?;
    require(
        profile.service_socket.is_some()
            && profile.state_root == runtime.parent
            && profile.execution_slots()? <= runtime.jobs_per_root,
        "canonical profile must name this service state and fit its build and test execution slots",
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
        None,
    )
    .map(|outcome| outcome.termination)
}

/// Exact live provenance survives private target retention. Remote delivery
/// keeps this owner until its final acknowledgment; local callers drop it
/// after the ordinary synchronous completion barrier.
struct OperationProvenance {
    // Close the sealed source descriptor before dropping its directory owner
    // through CanonicalPaths. Shared dependency producers retain their own Arc.
    _source: SourceReceiver,
    paths: Arc<CanonicalPaths>,
    coord: Arc<CoordLive>,
}

struct OperationOutcome {
    exit_code: i32,
    /// Exact status of the supervised namespace launcher. A numeric status
    /// already produced by bubblewrap does not identify an inner Cargo signal.
    termination: ChildTermination,
    retained_target: Option<PathBuf>,
    provenance: OperationProvenance,
}

fn run_operation(
    profile: Profile,
    release_mode: ReleaseAuthorizationMode,
    build_identity: String,
    shared: Option<Arc<SharedRuntime>>,
    stopped: Arc<AtomicBool>,
    output: OperationOutput<'_>,
    prepared_inputs: Option<remote_operation::RemoteOperationInputs>,
) -> io::Result<OperationOutcome> {
    let unconfirmed_cleanup = Arc::new(AtomicBool::new(false));
    let result = run_operation_owned(
        profile,
        release_mode,
        build_identity,
        shared,
        stopped,
        output,
        OperationCustody {
            prepared_inputs,
            unconfirmed_cleanup: Arc::clone(&unconfirmed_cleanup),
        },
    );
    // Every operation-owned coordinator has dropped or explicitly finished
    // before this barrier, including errors before execution or readiness.
    if unconfirmed_cleanup.load(Ordering::Acquire) {
        return Err(io::Error::other(UnconfirmedCleanup(
            "canonical operation coordinator cleanup was not confirmed".to_owned(),
        )));
    }
    result
}

struct OperationCustody {
    prepared_inputs: Option<remote_operation::RemoteOperationInputs>,
    unconfirmed_cleanup: Arc<AtomicBool>,
}

fn run_operation_owned(
    profile: Profile,
    release_mode: ReleaseAuthorizationMode,
    build_identity: String,
    shared: Option<Arc<SharedRuntime>>,
    stopped: Arc<AtomicBool>,
    mut output: OperationOutput<'_>,
    custody: OperationCustody,
) -> io::Result<OperationOutcome> {
    // Internal callers must satisfy the same fresh execution bound before any
    // source capture, namespace probe or operation-owned allocation.
    profile.execution_slots()?;
    let OperationCustody {
        prepared_inputs,
        unconfirmed_cleanup,
    } = custody;
    let remote_operation = prepared_inputs.is_some();
    // Only the authenticated frontend can construct remote input custody. Keep
    // its peer scope independent of all logical settings and source metadata.
    let authenticated_edge_pin = prepared_inputs
        .as_ref()
        .map(remote_operation::RemoteOperationInputs::authenticated_edge_pin);
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
        .filter(|_| !remote_operation)
        .map(|runtime| {
            runtime
                .toolchains
                .acquire(&profile.toolchain_root, timeout, cancelled)
        })
        .transpose()?;
    // Runtime sockets and writable output always use the configured operation
    // root, even when uploaded source/SDK custody lives on another volume.
    let owner = Arc::new(
        tempfile::Builder::new()
            .prefix("rabs-compile-")
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir_in(&profile.operation_root)?,
    );
    let (mut source, captured_toolchain, request, input_owner, received_toolchain) =
        match prepared_inputs {
            Some(inputs) => {
                inputs.verify_for_profile(&profile, &cancelled)?;
                (
                    inputs.source,
                    Some(Arc::clone(inputs.toolchain.image())),
                    inputs.request,
                    Some(inputs.owner),
                    Some(inputs.toolchain),
                )
            }
            None => {
                let bundle = owner.path().join("bundle");
                let prepared = super::source_delivery::prepare_local_bundle_controlled(
                    &profile.source_root,
                    &profile.source_specification()?,
                    &bundle,
                    retained_toolchain.clone(),
                    &preparation,
                )?;
                let (_, request_bytes) = read_stable(
                    &bundle.join("request.json"),
                    super::worker_delivery::MAX_LOCAL_CANONICAL_REQUEST_BYTES as u64,
                )?;
                let request: Value = serde_json::from_slice(&request_bytes)?;
                super::worker_delivery::validate_local_canonical_request(&request)?;
                (prepared.source, prepared.toolchain, request, None, None)
            }
        };
    let retain_paths = |mappings| {
        let paths = match (&input_owner, &received_toolchain) {
            (Some(inputs), Some(toolchain)) => CanonicalPaths::new_with_received_toolchain(
                Arc::clone(&owner),
                Arc::clone(inputs),
                Arc::clone(toolchain),
                mappings,
            ),
            (None, None) => CanonicalPaths::new_with_retained_toolchain(
                Arc::clone(&owner),
                mappings,
                retained_toolchain.clone(),
            ),
            _ => Err("remote source and compiler custody must be retained together".into()),
        };
        paths
            .and_then(|paths| paths.with_captured_toolchain(captured_toolchain.clone()))
            .map_err(io::Error::other)
    };
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
    let captured_stdin = match profile.stdin_policy()? {
        ProfileStdin::Captured(path) => Some(CapturedStdin::capture(
            &mut source,
            path,
            cargo_projection
                .as_ref()
                .and_then(CargoHomeProjection::workspace_manifest),
            owner.path(),
            &cancelled,
        )?),
        ProfileStdin::Closed | ProfileStdin::Inherit => None,
    };
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
    let toolchain = match (&retained_toolchain, &captured_toolchain) {
        (Some(retained), None) => retained.root().to_path_buf(),
        (None, Some(captured)) => captured.root().to_path_buf(),
        _ => {
            return Err(invalid(
                "canonical operation requires one retained compiler owner",
            ));
        }
    };
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
    let paths = retain_paths(vec![
        ("/__rabs/workspace".into(), workspace.clone()),
        ("/__rabs/cargo-home".into(), cargo_root.clone()),
        ("/__rabs/toolchain".into(), toolchain.clone()),
        (TARGET.into(), target_root.clone()),
        ("/__rabs/home".into(), home_root.clone()),
    ])?;
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
    if profile.command == CompilationCommand::Nextest {
        let runner = paths
            .physical(Path::new(CARGO_NEXTEST))
            .map_err(io::Error::other)?;
        let metadata = fs::symlink_metadata(runner)?;
        require(
            metadata.is_file() && metadata.mode() & 0o111 != 0,
            "nextest requires captured ordinary executable bin/cargo-nextest",
        )?;
    }
    if profile.command == CompilationCommand::Doc {
        let rustdoc = paths
            .physical(Path::new(RUSTDOC))
            .map_err(io::Error::other)?;
        let metadata = fs::symlink_metadata(rustdoc)?;
        require(
            metadata.is_file() && metadata.mode() & 0o111 != 0,
            "documentation requires captured ordinary executable bin/rustdoc",
        )?;
    }
    preparation.checkpoint()?;
    if let Some(retained) = &retained_toolchain {
        retained.image().verify_retained_generation(cancelled)?;
    }
    paths.verify_captured_toolchain(&cancelled)?;
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
        profile.graph_program(),
        &graph_args,
        CargoOutput::Capture {
            directory: owner.path().join("unit-graph-drain"),
            maximum: MAX_GRAPH_BYTES,
        },
        None,
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
        let mut prepare = || -> io::Result<(TargetState<'_>, Option<PathBuf>)> {
            let _cache_guard = shared
                .as_ref()
                .map(|runtime| acquire_target_cache_lock(&runtime.target_cache_lock, &cancelled))
                .transpose()?;
            preparation.checkpoint()?;
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
                authenticated_edge_pin,
            }
            .key(config)?;
            let mut cache = TargetState::open(
                &state_root,
                config,
                key,
                &workspace,
                workspace_manifest,
                &cancelled,
            )?;
            let candidate = owner.path().join("restored-target");
            let restored = match create_private(&candidate).and_then(|()| cache.restore(&candidate))
            {
                Ok(restored) => restored.then_some(candidate),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => return Err(error),
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
            Err(error) if error.kind() == io::ErrorKind::Interrupted => return Err(error),
            Err(error) => output.warning("restore", &error)?,
        }
    }
    preparation.checkpoint()?;
    // A failed restore remains in unmounted private staging. The live endpoint
    // receives only the completely selected target's retained inode capability.
    let paths = retain_paths(vec![
        ("/__rabs/workspace".into(), workspace),
        ("/__rabs/cargo-home".into(), cargo_root),
        ("/__rabs/toolchain".into(), toolchain),
        (TARGET.into(), target_root.clone()),
        ("/__rabs/home".into(), home_root.clone()),
    ])?;
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
    // The edge must drain before target capture, but current producer standing
    // must still be checked after that potentially lengthy copy. Give the
    // standalone coordinator its own lifetime, just as a shared service does.
    // Its signal listener remains active through capture and final delivery;
    // an unexpected coordinator exit still cancels the operation.
    let standalone_coordinator = shared
        .is_none()
        .then(|| {
            let controller = Arc::new(ShutdownController::new());
            controller.listen_for_signals();
            ServerOwner::start_operation(
                None,
                Some(Arc::clone(&coord)),
                Arc::clone(&stopped),
                controller,
            )
            .map(|owner| TrackedServerOwner::new(owner, Arc::clone(&unconfirmed_cleanup)))
        })
        .transpose()?;
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
    let server = ServerOwner::start_operation(
        Some(edge),
        None,
        Arc::clone(&stopped),
        Arc::new(ShutdownController::new()),
    )
    .map(|owner| TrackedServerOwner::new(owner, Arc::clone(&unconfirmed_cleanup)))?;
    wait_ready(&server, &socket, &coord, &stopped)?;
    // A private target clone can make Cargo skip an unchanged producer. Restore
    // its installation witnesses only after this coordinator owns live
    // authority, and before Cargo can observe the restored outputs. Known
    // revoked provenance is terminal here: dropping just the witnesses would
    // still let Cargo's own Fresh path consume the revoked artifact bytes.
    let restored_committed_outputs = match target_state
        .as_mut()
        .and_then(TargetState::take_restored_provenance)
    {
        Some(provenance) => {
            let restored = paths.rehydrate_committed_outputs(&coord, provenance, &cancelled);
            preparation.checkpoint()?;
            restored.map_err(|error| {
                io::Error::other(format!(
                    "restored target provenance is no longer valid: {error}"
                ))
            })?
        }
        None => 0,
    };
    preparation.checkpoint()?;
    output.event(
        json!({"kind":"canonical-compilation-started", "version":PROFILE_VERSION,
        "command":profile.command.as_str(), "namespace":"canonical",
        "cache_scope":"external-dependency-metadata-and-worker-rlib",
        "private_target_state":private_target_state,
        "restored_committed_outputs":restored_committed_outputs,
        "test_execution":matches!(profile.command, CompilationCommand::Test | CompilationCommand::Nextest) && !profile.no_run(),
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
        profile.inherits_stdin()?,
    )?;
    let streamed = matches!(&cargo_output, CargoOutput::Stream { .. });
    let result = execute_controlled(
        &spec,
        &support,
        profile.program(),
        &compilation_args,
        cargo_output,
        captured_stdin,
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
    let retain_target = target_state.is_some()
        && result.as_ref().is_ok_and(|compiled| {
            // An ordinary Cargo failure can leave many successfully compiled
            // dependencies. Cargo must rerun the failed unit, but its private
            // fingerprints may reuse those completed dependencies next time.
            // Bubblewrap can encode an inner signal as an ordinary 128+signal
            // exit, so reject that range as well as direct signal statuses.
            compiled
                .status
                .code()
                .is_some_and(|code| (0..128).contains(&code))
        });
    // Export after the last publication. The coordinator remains live through
    // capture and completion; this historical seed inventory is not a final
    // producer-safety decision. Persistence still requires a clean edge drain
    // and a verified private tree copy.
    let target_provenance = (retain_target && publication_drain.is_ok())
        .then(|| paths.export_committed_outputs(&coord, &cancelled));
    let shutdown = server.finish();
    let receipt = shutdown?;
    // Always join the standalone authority and retain its real shutdown receipt,
    // including cancelled execution and failed capture/publication barriers.
    // No intermediate error can bypass the final coordinator cleanup evidence.
    let completion = (|| -> io::Result<(DrainedOutput, Option<PathBuf>)> {
        if !receipt.clean() {
            return Err(io::Error::other(UnconfirmedCleanup(
                "canonical operation edge did not drain cleanly".to_owned(),
            )));
        }
        let compiled = result?;
        publication_drain.map_err(io::Error::other)?;
        // The operator-owned image is mounted read-only in the build, but a
        // host mutation must still invalidate this operation before publication
        // or delivery. Do not substitute the mutable toolchain source.
        preparation.checkpoint()?;
        if let Some(retained) = &retained_toolchain {
            retained.image().verify_retained_generation(cancelled)?;
        }
        paths.verify_captured_toolchain(&cancelled)?;
        if let Some(Err(CommittedOutputExportError::InvalidProducer(reason))) = &target_provenance {
            return Err(io::Error::other(format!(
                "completed target provenance is no longer valid: {reason}"
            )));
        }
        if !streamed {
            output.replay(&compiled)?;
        }
        if let (Some(cache), Some(provenance)) = (&target_state, target_provenance) {
            // Compiler, session and publication writers are gone. The separate
            // coordinator remains live only for current safety checks. Normal
            // compiler, lint, program and harness failures can retain completed
            // artifacts too. Cargo and the requested bodies execute again;
            // no outcome is saved or promoted to successful delivery.
            let capture = || -> io::Result<()> {
                // An export failure must preserve the old seed. Capturing with
                // an empty inventory would erase known Fresh provenance.
                let provenance = provenance.map_err(io::Error::other)?;
                let _cache_guard = shared
                    .as_ref()
                    .map(|runtime| {
                        acquire_target_cache_lock(&runtime.target_cache_lock, &cancelled)
                    })
                    .transpose()?;
                preparation.checkpoint()?;
                cache.capture(&target_root, &provenance)
            };
            if let Err(error) = capture() {
                if error.kind() == io::ErrorKind::Interrupted {
                    return Err(error);
                }
                output.warning("capture", &error)?;
            }
        }
        // This barrier is mandatory even with target retention disabled or an
        // optional capture warning. Another service root can revoke a known
        // producer while this root waits, copies or hashes its private target.
        paths.verify_completed_producers(&coord, &cancelled)?;
        let delivered = if compiled.status.success()
            && (matches!(
                profile.command,
                CompilationCommand::Build | CompilationCommand::Doc
            ) || profile.no_run())
        {
            require(
                paths
                    .physical(Path::new(TARGET))
                    .map_err(io::Error::other)?
                    == target_root,
                "completed target differs from its retained canonical mount",
            )?;
            // Remote targets remain under their runtime operation owner until
            // verified transfer and its final acknowledgment release custody.
            let parent = if remote_operation {
                owner.path()
            } else {
                &profile.operation_root
            };
            Some(retain_build_target(parent, &target_root)?)
        } else {
            None
        };
        // The rename's fsync can block too. Producer checks use the original
        // registered identities, not the now-moved target's physical paths.
        paths.verify_completed_producers(&coord, &cancelled)?;
        Ok((compiled, delivered))
    })();
    let coordinator_shutdown = standalone_coordinator
        .map(TrackedServerOwner::finish)
        .transpose()?;
    let receipt = match coordinator_shutdown {
        Some(coordinator_receipt) => merge_shutdown_receipts(receipt, coordinator_receipt),
        None => receipt,
    };
    if !receipt.clean() {
        return Err(io::Error::other(UnconfirmedCleanup(
            "canonical coordinator did not drain cleanly".to_owned(),
        )));
    }
    let (compiled, delivered) = completion?;
    output.line(&receipt.to_json_line())?;
    preparation.checkpoint()?;
    if shared.is_some() {
        // Shared publication writers outlive this operation, including receipt
        // I/O above. Standalone writers have cleanly joined under StateOwner.
        paths.verify_completed_producers(&coord, &cancelled)?;
    }
    if let Some(delivered) = &delivered {
        output.event(
            json!({"kind":"canonical-build-completed", "version":PROFILE_VERSION,
                "command":profile.command.as_str(), "tests_executed":false,
                "canonical_target":TARGET, "target_directory":delivered}),
        )?;
    }
    use std::os::unix::process::ExitStatusExt;
    Ok(OperationOutcome {
        termination: native_termination(compiled.status)?,
        exit_code: compiled
            .status
            .code()
            .unwrap_or_else(|| 128 + compiled.status.signal().unwrap_or(1)),
        retained_target: delivered,
        provenance: OperationProvenance {
            _source: source,
            paths,
            coord,
        },
    })
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
    // None is the existing local-only family. Remote families are separated by
    // the SPKI authenticated by the service, never by a client declaration.
    authenticated_edge_pin: Option<[u8; 32]>,
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
        let key: [u8; 32] = Sha256::digest(serde_json::to_vec(&identity)?).into();
        let Some(peer) = self.authenticated_edge_pin else {
            // Preserve existing local seeds without weakening any of their
            // compatibility inputs or migrating their on-disk generations.
            return Ok(key);
        };
        require(
            peer != [0; 32],
            "private target requires an authenticated edge key",
        )?;
        let mut hash = Sha256::new();
        hash.update(b"rabs.remote-private-cargo-target.v1\0");
        hash.update(peer);
        hash.update(key);
        Ok(hash.finalize().into())
    }
}

/// Move, rather than recopy, a fully drained target to a newly allocated private
/// owner on the same filesystem. There is no caller-selected overwrite target
/// and no retained copy of source or toolchain inputs. Successful builds,
/// documentation and Test/bench --no-run calls use this; other paths keep temporary target ownership.
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

/// One already transferred source member, independently copied into the
/// operation's private control directory. Only a read-only descriptor crosses
/// into Cargo; neither this pathname nor a writable alias is mounted there.
/// Planning never receives this descriptor and execution can take it only once.
#[derive(Debug)]
struct CapturedStdin {
    root: File,
    root_path: PathBuf,
    file: File,
    generation: FileSig,
    expected: SourceFile,
    handed_off: bool,
}

impl CapturedStdin {
    fn checkpoint(stopped: &impl Fn() -> bool) -> io::Result<()> {
        if stopped() {
            Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "captured standard input cancelled",
            ))
        } else {
            Ok(())
        }
    }

    fn verify_root(root: &File, path: &Path) -> io::Result<()> {
        private_directory(path)?;
        let held = root.metadata()?;
        let named = fs::symlink_metadata(path)?;
        require(
            held.is_dir()
                && held.uid() == rustix::process::geteuid().as_raw()
                && held.mode() & 0o077 == 0
                && (held.dev(), held.ino()) == (named.dev(), named.ino()),
            "captured stdin directory was replaced",
        )
    }

    fn open_member(root: &File, create: bool) -> io::Result<File> {
        use rustix::fs::{Mode, OFlags};
        let flags = OFlags::CLOEXEC
            | OFlags::NOFOLLOW
            | OFlags::NONBLOCK
            | if create {
                OFlags::RDWR | OFlags::CREATE | OFlags::EXCL
            } else {
                OFlags::RDONLY
            };
        let mode = if create {
            Mode::RUSR | Mode::WUSR
        } else {
            Mode::empty()
        };
        #[cfg(target_os = "linux")]
        let descriptor = rustix::fs::openat2(
            root,
            "stdin",
            flags,
            mode,
            rustix::fs::ResolveFlags::BENEATH
                | rustix::fs::ResolveFlags::NO_SYMLINKS
                | rustix::fs::ResolveFlags::NO_MAGICLINKS
                | rustix::fs::ResolveFlags::NO_XDEV,
        )?;
        #[cfg(not(target_os = "linux"))]
        let descriptor = rustix::fs::openat(root, "stdin", flags, mode)?;
        Ok(File::from(descriptor))
    }

    fn capture(
        source: &mut SourceReceiver,
        path: &str,
        workspace: Option<&SourceManifest>,
        parent: &Path,
        stopped: &impl Fn() -> bool,
    ) -> io::Result<Self> {
        use rustix::fs::{Mode, OFlags};
        Self::checkpoint(stopped)?;
        require(
            source.sealed_root().is_some() && relative_member(path),
            "captured stdin requires a sealed source and an ordinary relative member",
        )?;
        let workspace = workspace.unwrap_or_else(|| source.manifest());
        let expected = workspace
            .files()
            .iter()
            .find(|file| file.path == path)
            .cloned()
            .ok_or_else(|| invalid("stdin_file is not a captured workspace file"))?;
        private_directory(parent)?;
        let root = File::from(rustix::fs::open(
            parent,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?);
        Self::verify_root(&root, parent)?;
        let destination = Self::open_member(&root, true)?;
        let copied =
            source
                .checkpoint_file(path, destination, stopped)
                .map_err(|error| match error {
                    SourceCheckpointError::Source(error)
                    | SourceCheckpointError::Destination(error) => error,
                })?;
        require(
            copied.expected() == &expected,
            "captured stdin differs from its workspace input declaration",
        )?;
        let written = copied.into_file();
        written.set_permissions(fs::Permissions::from_mode(0o400))?;
        let generation = FileSig::of(&written.metadata()?);
        let file = Self::open_member(&root, false)?;
        require(
            FileSig::of(&file.metadata()?) == generation,
            "captured stdin changed while opening its read-only descriptor",
        )?;
        drop(written);
        let input = Self {
            root,
            root_path: parent.to_path_buf(),
            file,
            generation,
            expected,
            handed_off: false,
        };
        input.verify(stopped)?;
        Ok(input)
    }

    fn verify(&self, stopped: &impl Fn() -> bool) -> io::Result<()> {
        Self::checkpoint(stopped)?;
        Self::verify_root(&self.root, &self.root_path)?;
        let check_file = |file: &File| -> io::Result<()> {
            let metadata = file.metadata()?;
            require(
                metadata.is_file()
                    && metadata.uid() == rustix::process::geteuid().as_raw()
                    && metadata.nlink() == 1
                    && metadata.mode() & 0o777 == 0o400
                    && metadata.dev() == self.root.metadata()?.dev()
                    && FileSig::of(&metadata) == self.generation,
                "captured stdin file identity, bytes or ownership changed",
            )
        };
        check_file(&self.file)?;
        check_file(&Self::open_member(&self.root, false)?)?;
        let mut hash = Sha256::new();
        let mut bytes = [0u8; MAX_SOURCE_CHUNK];
        let mut offset = 0;
        while offset < self.expected.len {
            Self::checkpoint(stopped)?;
            let count = (self.expected.len - offset).min(bytes.len() as u64) as usize;
            self.file.read_exact_at(&mut bytes[..count], offset)?;
            hash.update(&bytes[..count]);
            offset += count as u64;
        }
        require(
            self.file.read_at(&mut bytes[..1], offset)? == 0
                && <[u8; 32]>::from(hash.finalize()) == self.expected.sha256,
            "captured stdin bytes differ from the sealed source",
        )?;
        check_file(&self.file)?;
        check_file(&Self::open_member(&self.root, false)?)?;
        Self::verify_root(&self.root, &self.root_path)?;
        Self::checkpoint(stopped)
    }

    fn take_stdio(&mut self, stopped: &impl Fn() -> bool) -> io::Result<Stdio> {
        require(
            !self.handed_off,
            "captured stdin was already handed to Cargo",
        )?;
        self.verify(stopped)?;
        let file = self.file.try_clone()?;
        self.handed_off = true;
        Ok(Stdio::from(file))
    }
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
    mut captured_stdin: Option<CapturedStdin>,
    timeout: Duration,
    stopped: &AtomicBool,
    shared: Option<&SharedRuntime>,
    destination: &mut OperationOutput<'_>,
) -> io::Result<DrainedOutput> {
    require(
        !matches!(&output, CargoOutput::Capture { .. }) || captured_stdin.is_none(),
        "Cargo planning cannot consume captured stdin",
    )?;
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
            // Only a noninteractive run/test/bench execution with inherited
            // input consumes caller stdin. Planning probes, other commands
            // and tests without an explicit input policy retain EOF.
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
    if let Some(input) = &mut captured_stdin {
        command.stdin(input.take_stdio(&|| {
            stopped.load(Ordering::Acquire) || shared.is_some_and(|runtime| !runtime.healthy())
        })?);
    }
    let process = match ManagedProcessGroup::spawn_command(command, Attribution::default()) {
        Ok(process) => process,
        Err(error) => {
            // Formation verification can fail after the child was created.
            // Its best-effort guard is not a verified descendant-closure receipt.
            if let Some(runtime) = shared {
                runtime.stopped.store(true, Ordering::Release);
            }
            std::mem::forget(root);
            return Err(io::Error::new(
                error.kind(),
                UnconfirmedCleanup(format!(
                    "canonical Cargo spawn did not prove process-group closure: {error}"
                )),
            ));
        }
    };
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
        Err(_) => !rabs_asupersync::process_groups::members_from_proc(group)
            .is_ok_and(|members| members.is_empty()),
    };
    if unresolved {
        if let Some(runtime) = shared {
            runtime.stopped.store(true, Ordering::Release);
        }
        // Failed cleanup is neither a free root nor a clean cancellation. The
        // admission also retains the state lock until the service process exits.
        std::mem::forget(root);
        return Err(io::Error::other(UnconfirmedCleanup(
            "canonical Cargo process group did not drain".to_owned(),
        )));
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
    if let Some(input) = &captured_stdin {
        input.verify(&|| {
            stopped.load(Ordering::Acquire) || shared.is_some_and(|runtime| !runtime.healthy())
        })?;
    }
    Ok(output)
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

/// Retain actual cleanup evidence even when an early return relies on Drop.
/// This wraps only an operation's private edge/standalone coordinator; the
/// persistent service coordinator keeps its existing lifecycle.
struct TrackedServerOwner {
    owner: Option<ServerOwner>,
    unconfirmed_cleanup: Arc<AtomicBool>,
}

impl TrackedServerOwner {
    fn new(owner: ServerOwner, unconfirmed_cleanup: Arc<AtomicBool>) -> Self {
        Self {
            owner: Some(owner),
            unconfirmed_cleanup,
        }
    }

    fn finish(mut self) -> io::Result<ShutdownReceipt> {
        let result = self.owner.take().expect("live coordinator owner").finish();
        if !result.as_ref().is_ok_and(|receipt| receipt.clean()) {
            self.unconfirmed_cleanup.store(true, Ordering::Release);
        }
        result
    }
}

impl std::ops::Deref for TrackedServerOwner {
    type Target = ServerOwner;

    fn deref(&self) -> &ServerOwner {
        self.owner.as_ref().expect("live coordinator owner")
    }
}

impl Drop for TrackedServerOwner {
    fn drop(&mut self) {
        if let Some(owner) = self.owner.take()
            && !owner.finish().is_ok_and(|receipt| receipt.clean())
        {
            self.unconfirmed_cleanup.store(true, Ordering::Release);
        }
    }
}

struct ServerOwner {
    controller: Arc<ShutdownController>,
    worker: Option<JoinHandle<Result<ShutdownReceipt, DaemonError>>>,
    normal_shutdown: Option<Arc<AtomicBool>>,
}
impl ServerOwner {
    fn start_operation(
        edge: Option<SubsystemWork>,
        coordinator: Option<Arc<CoordLive>>,
        stopped: Arc<AtomicBool>,
        controller: Arc<ShutdownController>,
    ) -> io::Result<Self> {
        // Both standalone and shared operations still have target capture and
        // delivery work after their scoped daemon drains. Expected subsystem
        // shutdown must not manufacture cancellation of that completed Cargo
        // invocation. Unexpected exit, panic and prior cancellation still stop
        // the caller; the cancellation flag is never reset.
        let normal_shutdown = Arc::new(AtomicBool::new(false));
        let options = DaemonRunOptions {
            edge_work: edge.map(|edge| {
                stop_on_unexpected_exit(
                    edge,
                    Arc::clone(&stopped),
                    Arc::clone(&controller),
                    Arc::clone(&normal_shutdown),
                )
            }),
            coord_work: coordinator.map(|coord| {
                stop_on_unexpected_exit(
                    coordinator_work(coord),
                    Arc::clone(&stopped),
                    Arc::clone(&controller),
                    Arc::clone(&normal_shutdown),
                )
            }),
            ..DaemonRunOptions::default()
        };
        let worker_controller = Arc::clone(&controller);
        let worker = std::thread::Builder::new()
            .name("rabs-canonical-coord".into())
            .spawn(move || run_daemon_controlled(options, worker_controller))?;
        Ok(Self {
            controller,
            worker: Some(worker),
            normal_shutdown: Some(normal_shutdown),
        })
    }

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
            .ok_or_else(|| {
                io::Error::other(UnconfirmedCleanup(
                    "canonical coordinator already joined".to_owned(),
                ))
            })?
            .join()
            .map_err(|_| {
                io::Error::other(UnconfirmedCleanup(
                    "canonical coordinator panicked".to_owned(),
                ))
            })?
            .map_err(|error| {
                io::Error::other(UnconfirmedCleanup(format!(
                    "canonical coordinator shutdown failed: {error}"
                )))
            })
    }
}

/// Preserve both owners' actual subsystem outcomes in the operation's existing
/// single receipt. Timings are aggregate measured durations; cleanliness still
/// comes only from the runtime's recorded obligation outcomes.
fn merge_shutdown_receipts(
    mut edge: ShutdownReceipt,
    coordinator: ShutdownReceipt,
) -> ShutdownReceipt {
    edge.subsystems.extend(coordinator.subsystems);
    edge.boot_ms = edge.boot_ms.saturating_add(coordinator.boot_ms);
    edge.shutdown_ms = edge.shutdown_ms.saturating_add(coordinator.shutdown_ms);
    edge.recovered_from_unclean |= coordinator.recovered_from_unclean;
    edge
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
        if stopped.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "canonical coordinator startup cancelled",
            ));
        }
        if server
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
    fn nextest_fresh_admission_keeps_build_and_test_parallelism_independent() {
        let mut profile = application_environment_profile();
        profile.command = CompilationCommand::Nextest;
        for (build_jobs, test_threads, expected) in [(2, 8, 8), (8, 1, 8)] {
            profile.jobs = build_jobs;
            profile.selection = Some(CompilationSelection {
                test_threads: Some(test_threads),
                ..Default::default()
            });
            profile.validate_logical().unwrap();
            assert_eq!(profile.execution_slots().unwrap(), expected);
            let arguments = profile.compilation_args().unwrap();
            assert!(arguments.windows(2).any(|pair| {
                pair == ["--build-jobs".to_owned(), build_jobs.to_string()]
            }));
            assert!(arguments.windows(2).any(|pair| {
                pair == ["--test-threads".to_owned(), test_threads.to_string()]
            }));
        }
        profile.selection = None;
        // The original wire intent remains readable for retained operations.
        profile.validate_logical().unwrap();
        assert!(profile.execution_slots().is_err());
        profile.selection = Some(CompilationSelection {
            no_run: true,
            ..Default::default()
        });
        assert_eq!(profile.execution_slots().unwrap(), profile.jobs);
        profile.command = CompilationCommand::Build;
        profile.selection = None;
        assert_eq!(profile.execution_slots().unwrap(), profile.jobs);
    }

    #[test]
    fn nextest_uses_captured_runner_and_cargo_only_for_nonexecuting_graphs() {
        let mut profile = application_environment_profile();
        profile.command = CompilationCommand::Nextest;
        profile.jobs = 3;
        profile.selection = Some(CompilationSelection {
            workspace: true,
            profile: Some("release".into()),
            runner_profile: Some("ci".into()),
            test_threads: Some(1),
            filtersets: vec!["package(core)".into()],
            test_filter: Some("roundtrip".into()),
            test_args: vec!["--exact".into()],
            ..Default::default()
        });
        assert_eq!(profile.program(), CARGO_NEXTEST);
        assert_eq!(profile.graph_program(), CARGO);
        assert_eq!(
            profile.compilation_args().unwrap(),
            [
                "nextest",
                "run",
                "--workspace",
                "--cargo-profile",
                "release",
                "--profile",
                "ci",
                "--test-threads",
                "1",
                "--filterset",
                "package(core)",
                "roundtrip",
                "--offline",
                "--locked",
                "--manifest-path",
                "/__rabs/workspace/Cargo.toml",
                "--build-jobs",
                "3",
                "--",
                "--exact",
            ]
        );
        assert_eq!(
            profile.graph_args(None).unwrap(),
            [
                "test",
                "--workspace",
                "--no-run",
                "--profile",
                "release",
                "--offline",
                "--locked",
                "--manifest-path",
                "/__rabs/workspace/Cargo.toml",
                "--message-format=json",
                "--jobs",
                "3",
                "--unit-graph",
                "-Z",
                "unstable-options",
            ]
        );
        let request = profile.source_specification().unwrap();
        assert_eq!(request["program"], CARGO_NEXTEST);
        assert_eq!(request["command_context"]["env"]["CARGO"], CARGO);
        assert!(matches!(
            profile.stdin_policy().unwrap(),
            ProfileStdin::Closed
        ));
        profile.stdin_file = Some("fixtures/input".into());
        assert!(matches!(
            profile.stdin_policy().unwrap(),
            ProfileStdin::Captured(_)
        ));
        profile.selection.as_mut().unwrap().no_run = true;
        assert!(profile.no_run());
        assert!(profile.stdin_policy().is_err());
        profile.stdin_file = None;
        profile.selection = None;
        assert_eq!(
            &profile.compilation_args().unwrap()[..2],
            ["nextest", "run"]
        );
        assert!(
            profile
                .graph_args(None)
                .unwrap()
                .iter()
                .any(|arg| arg == "--no-run")
        );
    }

    #[test]
    fn source_selection_is_typed_and_retains_the_exact_native_execution_request() {
        let mut profile = application_environment_profile();
        assert!(
            profile.source_specification().unwrap()["cargo_source"]
                .get("selection")
                .is_none()
        );
        profile.source_selection = SourceSelection::UnitGraph;
        profile.manifest = "member/Cargo.toml".into();
        profile.cargo_home_source = Some(PathBuf::from("/approved-cargo-home"));
        profile.jobs = 7;
        profile
            .env
            .insert("APP_INPUT".into(), "literal\nvalue".into());
        for command in [
            CompilationCommand::Check,
            CompilationCommand::Build,
            CompilationCommand::Test,
            CompilationCommand::Clippy,
            CompilationCommand::Doc,
            CompilationCommand::Run,
            CompilationCommand::Bench,
        ] {
            profile.command = command;
            let request = profile.source_specification().unwrap();
            assert_eq!(
                request["cargo_source"],
                json!({"manifest":"member/Cargo.toml", "cargo_home_source":"/approved-cargo-home",
                    "selection":"cargo-unit-graph-v1"})
            );
            assert_eq!(request["args"], json!(profile.compilation_args().unwrap()));
            assert_eq!(
                request["program"],
                if command == CompilationCommand::Clippy {
                    CARGO_CLIPPY
                } else {
                    CARGO
                }
            );
            assert_eq!(
                request["command_context"]["cwd"],
                "/__rabs/workspace/member"
            );
            let expected: BTreeMap<_, _> =
                profile.command_environment().unwrap().into_iter().collect();
            assert_eq!(request["command_context"]["env"], json!(expected));
            assert!(
                !profile
                    .compilation_args()
                    .unwrap()
                    .iter()
                    .any(|argument| argument == "--target-dir")
            );
        }
        for selection in [
            Value::Null,
            json!(true),
            json!({}),
            json!("future"),
            json!("Complete"),
        ] {
            let invalid = json!({
                "version":PROFILE_VERSION, "source_root":"/source", "toolchain_root":"/toolchain",
                "state_root":"/state", "operation_root":"/operations", "wrapper":"/bin/rabs-wrap",
                "source_selection":selection,
            });
            assert!(serde_json::from_value::<Profile>(invalid).is_err());
        }
    }

    #[test]
    fn selected_vendor_profiles_preserve_source_and_command_controls() {
        for command in [
            CompilationCommand::Check,
            CompilationCommand::Build,
            CompilationCommand::Clippy,
            CompilationCommand::Test,
            CompilationCommand::Nextest,
        ] {
            let mut profile = application_environment_profile();
            profile.command = command;
            profile.source_selection = SourceSelection::UnitGraph;
            profile.vendor = Some("vendor".into());
            profile.selection = Some(CompilationSelection {
                no_run: matches!(command, CompilationCommand::Test | CompilationCommand::Nextest),
                ..Default::default()
            });
            profile.validate_logical().unwrap();
            let request = profile.source_specification().unwrap();
            assert_eq!(
                request["cargo_source"],
                json!({"manifest":"Cargo.toml", "vendor":"vendor",
                    "selection":"cargo-unit-graph-v1"})
            );
            assert_eq!(request["args"], json!(profile.compilation_args().unwrap()));
            assert_eq!(request["program"], profile.program());
            assert!(request.get("publication_authorized").is_none());
            profile.cargo_home_source = Some("/unapproved-cargo-home".into());
            assert!(
                profile.validate_logical().unwrap_err().to_string()
                    .contains("choose vendor or cargo_home_source")
            );
            profile.cargo_home_source = None;
            profile.vendor = Some("../vendor".into());
            assert!(
                profile.validate_logical().unwrap_err().to_string()
                    .contains("vendor must be an ordinary relative path")
            );
        }
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
            CompilationCommand::Doc,
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
            if matches!(command, CompilationCommand::Test | CompilationCommand::Doc) {
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
        for command in ["rustc", "rustdoc"] {
            assert!(serde_json::from_value::<Profile>(json!({
                "version":PROFILE_VERSION, "command":command,
                "source_root":"/source", "toolchain_root":"/toolchain",
                "state_root":"/state", "operation_root":"/operations", "wrapper":"/bin/rabs-wrap"
            })).is_err());
        }
    }

    #[test]
    fn documentation_keeps_captured_rustdoc_and_identical_planning_selection() {
        let mut profile = application_environment_profile();
        profile.command = CompilationCommand::Doc;
        profile.selection = Some(
            serde_json::from_value(json!({
                "packages":["app"], "lib":true, "no_deps":true,
                "document_private_items":true, "target":["host-tuple"], "profile":"release"
            }))
            .unwrap(),
        );
        let arguments = profile.compilation_args().unwrap();
        assert_eq!(
            &arguments[..4],
            ["doc", "--lib", "--no-deps", "--document-private-items"]
        );
        assert!(!arguments.iter().any(|argument| argument == "--"));
        let graph = profile.graph_args(None).unwrap();
        assert_eq!(&graph[..arguments.len()], arguments.as_slice());
        assert!(
            graph
                .windows(2)
                .any(|pair| pair == ["-Z", "unstable-options"])
        );
        assert!(graph.iter().any(|argument| argument == "--unit-graph"));
        let request = profile.source_specification().unwrap();
        assert_eq!(request["program"], CARGO);
        assert_eq!(request["args"], json!(arguments));
        assert_eq!(request["command_context"]["env"]["RUSTDOC"], RUSTDOC);
        assert_eq!(request["command_context"]["env"]["RUSTC"], RUSTC);
        assert!(!profile.inherits_stdin().unwrap());
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
    fn command_defaults_keep_test_stdin_closed_and_run_and_bench_inherited() {
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
            assert_eq!(
                profile.inherits_stdin().unwrap(),
                inherits_stdin,
                "{command:?}"
            );
            assert!(profile.validate_stdin(false).is_ok(), "{command:?}");
            assert_eq!(
                profile.validate_stdin(true).is_err(),
                inherits_stdin,
                "{command:?}, no_run={no_run}"
            );
        }
    }

    #[test]
    fn explicit_closed_stdin_preserves_run_and_bench_intent_and_selects_eof() {
        for command in [CompilationCommand::Run, CompilationCommand::Bench] {
            let mut profile = application_environment_profile();
            profile.command = command;
            profile.selection = Some(CompilationSelection {
                bin: if command == CompilationCommand::Run {
                    vec!["app".into()]
                } else {
                    Vec::new()
                },
                run_args: if command == CompilationCommand::Run {
                    vec!["--literal".into(), String::new()]
                } else {
                    Vec::new()
                },
                test_args: if command == CompilationCommand::Bench {
                    vec!["--literal".into(), String::new()]
                } else {
                    Vec::new()
                },
                ..CompilationSelection::default()
            });
            let request = profile.source_specification().unwrap();
            let selected = if command == CompilationCommand::Run {
                Some(
                    run_build_selection(profile.selection.as_ref().unwrap(), &Value::Null, None)
                        .unwrap(),
                )
            } else {
                None
            };
            let plan = profile.graph_args(selected.as_ref()).unwrap();
            assert!(profile.inherits_stdin().unwrap());
            profile.stdin = Some(CompilationStdin::Closed);
            profile.validate_logical().unwrap();
            profile.validate_stdin(true).unwrap();
            assert!(!profile.inherits_stdin().unwrap());
            assert_eq!(profile.graph_args(selected.as_ref()).unwrap(), plan);
            // The native profile carries runtime input policy. The existing
            // compiler preparation request does not claim captured stdin or
            // authority to reuse an executed program's result.
            assert_eq!(profile.source_specification().unwrap(), request);
            let stopped = AtomicBool::new(false);
            let stdout = tempfile::tempfile().unwrap();
            let stderr = tempfile::tempfile().unwrap();
            assert!(matches!(
                OperationOutput::inherited(
                    &stdout,
                    &stderr,
                    &stopped,
                    Instant::now() + Duration::from_secs(5),
                )
                .unwrap()
                .cargo_output(PathBuf::new(), profile.inherits_stdin().unwrap())
                .unwrap(),
                CargoOutput::Inherit {
                    inherit_stdin: false
                },
            ));
        }
    }

    #[test]
    fn captured_stdin_profiles_preserve_command_selection_and_compilation_identity() {
        for command in [
            CompilationCommand::Run,
            CompilationCommand::Test,
            CompilationCommand::Bench,
        ] {
            let mut profile = application_environment_profile();
            profile.command = command;
            profile.selection = Some(CompilationSelection {
                bin: if command == CompilationCommand::Run {
                    vec!["app".into()]
                } else {
                    Vec::new()
                },
                ..CompilationSelection::default()
            });
            let original = profile.source_specification().unwrap();
            profile.stdin_file = Some("inputs/binary.dat".into());
            profile.validate_logical().unwrap();
            profile.validate_stdin(true).unwrap();
            assert_eq!(
                profile.stdin_policy().unwrap(),
                ProfileStdin::Captured("inputs/binary.dat")
            );
            assert!(!profile.inherits_stdin().unwrap());
            // Runtime input does not become a compiler argument, configuration
            // field or program-result cache authority. Its bytes are already
            // members of this operation's independently captured source.
            assert_eq!(profile.source_specification().unwrap(), original);
        }
    }

    #[test]
    fn captured_stdin_profiles_reject_ambiguous_policies_and_nonexecution_commands() {
        let mut profile = application_environment_profile();
        profile.stdin_file = Some("inputs/binary.dat".into());
        for command in [
            CompilationCommand::Check,
            CompilationCommand::Build,
            CompilationCommand::Clippy,
            CompilationCommand::Doc,
        ] {
            profile.command = command;
            assert!(profile.validate_logical().is_err(), "{command:?}");
        }
        profile.selection = Some(CompilationSelection {
            no_run: true,
            ..CompilationSelection::default()
        });
        for command in [CompilationCommand::Test, CompilationCommand::Bench] {
            profile.command = command;
            assert!(profile.validate_logical().is_err(), "{command:?}");
        }
        profile.selection = None;
        for policy in [CompilationStdin::Closed, CompilationStdin::Inherit] {
            profile.stdin = Some(policy);
            assert!(profile.validate_logical().is_err(), "{policy:?}");
        }
        profile.stdin = None;
        for path in [
            "",
            "/dev/stdin",
            "../private",
            "inputs/../private",
            "inputs//data",
            "inputs/./data",
            "inputs\\data",
            "inputs/data\n",
        ] {
            profile.stdin_file = Some(path.into());
            assert!(profile.validate_logical().is_err(), "{path:?}");
        }
        profile.stdin_file = Some("x".repeat(1025));
        assert!(profile.validate_logical().is_err());
    }

    #[test]
    fn stdin_execution_policy_distinguishes_cargo_no_run_from_harness_arguments() {
        for command in [CompilationCommand::Test, CompilationCommand::Bench] {
            for captured in [false, true] {
                let mut profile = application_environment_profile();
                profile.command = command;
                profile.selection = Some(CompilationSelection {
                    test_args: vec!["--no-run".into()],
                    ..CompilationSelection::default()
                });
                if captured {
                    profile.stdin_file = Some("inputs/binary.dat".into());
                } else {
                    profile.stdin = Some(CompilationStdin::Inherit);
                }
                // A literal argument after `--` belongs to the executed
                // harness. Only Cargo's typed no_run selection disables it.
                profile.validate_logical().unwrap();
                assert!(!profile.no_run());
                assert!(
                    profile
                        .compilation_args()
                        .unwrap()
                        .ends_with(&["--".into(), "--no-run".into()])
                );
                profile.selection.as_mut().unwrap().no_run = true;
                assert!(profile.validate_logical().is_err());
            }
        }
    }

    fn captured_stdin_fixture(bytes: &[u8]) -> (tempfile::TempDir, SourceReceiver, PathBuf) {
        let owner = crate::test_util::private_tempdir();
        let expected = SourceFile {
            path: "inputs/binary.dat".into(),
            len: bytes.len() as u64,
            sha256: Sha256::digest(bytes).into(),
            executable: false,
        };
        let mut source = SourceReceiver::create(
            &owner.path().join("source"),
            SourceManifest::new(vec![expected]).unwrap(),
        )
        .unwrap();
        for (index, chunk) in bytes.chunks(MAX_SOURCE_CHUNK).enumerate() {
            source
                .write_chunk(
                    "inputs/binary.dat",
                    (index * MAX_SOURCE_CHUNK) as u64,
                    chunk,
                    Sha256::digest(chunk).into(),
                )
                .unwrap();
        }
        source.seal().unwrap();
        let control = owner.path().join("control");
        create_private(&control).unwrap();
        (owner, source, control)
    }

    #[test]
    fn captured_stdin_runs_once_from_independent_verified_read_only_bytes() {
        for bytes in [
            Vec::new(),
            b"binary\0input\xff\n".to_vec(),
            vec![73; MAX_SOURCE_CHUNK + 17],
        ] {
            let (_owner, mut source, control) = captured_stdin_fixture(&bytes);
            let mut input =
                CapturedStdin::capture(&mut source, "inputs/binary.dat", None, &control, &|| false)
                    .unwrap();
            assert_eq!(
                input.expected.sha256,
                <[u8; 32]>::from(Sha256::digest(&bytes))
            );
            assert!(input.file.write_at(b"forbidden", 0).is_err());
            // Later changes to the original snapshot cannot redirect the
            // descriptor into newly opened input. Overall source provenance
            // remains the operation owner's separate completion obligation.
            let original = source.sealed_root().unwrap().join("inputs/binary.dat");
            let permissions = fs::metadata(&original).unwrap().permissions();
            fs::set_permissions(&original, fs::Permissions::from_mode(0o600)).unwrap();
            fs::write(&original, b"changed").unwrap();
            fs::set_permissions(&original, permissions).unwrap();
            let output = std::process::Command::new("/bin/cat")
                .stdin(input.take_stdio(&|| false).unwrap())
                .output()
                .unwrap();
            assert!(output.status.success());
            assert_eq!(output.stdout, bytes);
            assert!(output.stderr.is_empty());
            input.verify(&|| false).unwrap();
            assert!(input.take_stdio(&|| false).is_err());
        }
    }

    #[test]
    fn captured_stdin_reaches_real_cargo_test_harnesses_on_every_execution() {
        // This exercises host Cargo, actual libtest/custom-harness children,
        // and production input custody. Namespace/service execution has its
        // separate controlled-host integration fixture.
        let bytes = b"test\0captured input\xff\n";
        let compiler = std::env::var_os("RUSTC").unwrap_or_else(|| {
            let sibling = Path::new(env!("CARGO")).with_file_name("rustc");
            if sibling.is_file() {
                sibling.into_os_string()
            } else {
                "rustc".into()
            }
        });
        for harness in [true, false] {
            let (owner, mut source, control) = captured_stdin_fixture(bytes);
            let project = owner.path().join("project");
            fs::create_dir(&project).unwrap();
            fs::write(
                project.join("Cargo.toml"),
                format!(
                    "[package]\nname='captured-test-input'\nversion='0.1.0'\nedition='2021'\n\
                     [workspace]\n[[test]]\nname='reader'\npath='reader.rs'\nharness={harness}\n"
                ),
            )
            .unwrap();
            fs::write(
                project.join("Cargo.lock"),
                "version = 4\n[[package]]\nname = \"captured-test-input\"\nversion = \"0.1.0\"\n",
            )
            .unwrap();
            fs::write(project.join("expected.bin"), bytes).unwrap();
            let reader = r#"use std::io::Read;
fn consume_current_input() {
    let mut input = Vec::new();
    std::io::stdin().read_to_end(&mut input).unwrap();
    assert_eq!(input.as_slice(), &include_bytes!("expected.bin")[..]);
    let path = std::env::var_os("EXECUTION_COUNTER").unwrap();
    let count: u32 = std::fs::read_to_string(&path).ok().map(|value| value.parse().unwrap()).unwrap_or(0) + 1;
    std::fs::write(path, count.to_string()).unwrap();
    println!("CURRENT_CAPTURED_TEST_INPUT={count}:{}", input.len());
    assert_eq!(std::env::var("FAIL_CURRENT_TEST").unwrap(), "false", "current failure must be preserved");
}
"#;
            let entrypoint = if harness {
                "#[test]\nfn reads_current_input() { consume_current_input(); }\n"
            } else {
                "fn main() { consume_current_input(); }\n"
            };
            fs::write(project.join("reader.rs"), format!("{reader}{entrypoint}")).unwrap();
            let mut profile = application_environment_profile();
            profile.command = CompilationCommand::Test;
            profile.stdin_file = Some("inputs/binary.dat".into());
            profile.selection = Some(CompilationSelection {
                test: vec!["reader".into()],
                test_args: vec!["--nocapture".into()],
                ..CompilationSelection::default()
            });
            profile.validate_logical().unwrap();
            let ProfileStdin::Captured(path) = profile.stdin_policy().unwrap() else {
                panic!("executing tests must retain their captured input policy");
            };
            let selection = profile.selection.as_ref().unwrap();
            for (attempt, fail) in [false, true, false].into_iter().enumerate() {
                let execution = control.join(attempt.to_string());
                create_private(&execution).unwrap();
                let mut input =
                    CapturedStdin::capture(&mut source, path, None, &execution, &|| false).unwrap();
                let mut command = std::process::Command::new(env!("CARGO"));
                command
                    .current_dir(&project)
                    .args(selection.cargo_arguments(profile.command).unwrap())
                    .args(["--offline", "--locked", "--jobs", "1", "--target-dir"])
                    .arg(project.join("target"))
                    .args(selection.runtime_arguments(profile.command).unwrap())
                    .env("CARGO_HOME", project.join("cargo-home"))
                    .env("RUSTC", &compiler)
                    .env("RUSTC_WRAPPER", "")
                    .env("RUSTC_WORKSPACE_WRAPPER", "")
                    .env("EXECUTION_COUNTER", project.join("executions"))
                    .env("FAIL_CURRENT_TEST", fail.to_string())
                    .stdin(input.take_stdio(&|| false).unwrap())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped());
                let deadline = Instant::now() + Duration::from_secs(60);
                let mut timed_out = false;
                let output = ManagedProcessGroup::spawn_command(command, Attribution::default())
                    .unwrap()
                    .wait_with_bounded_drain_budget(
                        &DrainLimits::new(execution.join("output")),
                        1024 * 1024,
                        || {
                            timed_out |= Instant::now() >= deadline;
                            timed_out
                        },
                    )
                    .unwrap();
                let stdout = io::read_to_string(output.stdout.reader().unwrap()).unwrap();
                let stderr = io::read_to_string(output.stderr.reader().unwrap()).unwrap();
                assert!(!timed_out, "{stdout}\n{stderr}");
                assert_eq!(output.residual_group_members, 0);
                assert_eq!(
                    output.status.code(),
                    Some(if fail { 101 } else { 0 }),
                    "harness={harness}, attempt={attempt}: {stdout}\n{stderr}",
                );
                assert!(
                    stdout.contains(&format!(
                        "CURRENT_CAPTURED_TEST_INPUT={}:{}",
                        attempt + 1,
                        bytes.len(),
                    )),
                    "{stdout}\n{stderr}",
                );
                input.verify(&|| false).unwrap();
                assert!(input.take_stdio(&|| false).is_err());
            }
        }
    }

    #[test]
    fn captured_stdin_requires_a_current_member_of_the_compiler_visible_workspace() {
        let (_owner, mut source, control) = captured_stdin_fixture(b"captured");
        assert!(CapturedStdin::capture(&mut source, "missing", None, &control, &|| false).is_err());
        // An isolated Cargo-home member may exist in the transport tree while
        // intentionally being absent from its compiler-visible workspace.
        let workspace = SourceManifest::new(vec![SourceFile {
            path: "Cargo.toml".into(),
            len: 0,
            sha256: Sha256::digest([]).into(),
            executable: false,
        }])
        .unwrap();
        assert!(
            CapturedStdin::capture(
                &mut source,
                "inputs/binary.dat",
                Some(&workspace),
                &control,
                &|| false,
            )
            .is_err()
        );
        assert!(!control.join("stdin").exists());
        let original = source.sealed_root().unwrap().join("inputs/binary.dat");
        let permissions = fs::metadata(&original).unwrap().permissions();
        fs::set_permissions(&original, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&original, b"mutated!").unwrap();
        fs::set_permissions(&original, permissions).unwrap();
        assert!(
            CapturedStdin::capture(&mut source, "inputs/binary.dat", None, &control, &|| false,)
                .is_err()
        );
    }

    #[test]
    fn captured_stdin_rejects_replaced_files_roots_aliases_and_modified_bytes() {
        for mutation in ["replace", "root", "alias", "bytes", "symlink"] {
            let (owner, mut source, control) = captured_stdin_fixture(b"captured");
            let mut input =
                CapturedStdin::capture(&mut source, "inputs/binary.dat", None, &control, &|| false)
                    .unwrap();
            let path = control.join("stdin");
            match mutation {
                "replace" => {
                    fs::rename(&path, control.join("saved-input")).unwrap();
                    fs::write(&path, b"captured").unwrap();
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
                }
                "root" => {
                    fs::rename(&control, owner.path().join("saved-control")).unwrap();
                    create_private(&control).unwrap();
                }
                "alias" => fs::hard_link(&path, control.join("alias")).unwrap(),
                "bytes" => {
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
                    fs::write(&path, b"modified").unwrap();
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
                }
                "symlink" => {
                    fs::rename(&path, control.join("saved-input")).unwrap();
                    std::os::unix::fs::symlink("saved-input", &path).unwrap();
                }
                _ => unreachable!(),
            }
            assert!(input.verify(&|| false).is_err(), "{mutation}");
            assert!(input.take_stdio(&|| false).is_err(), "{mutation}");
        }
    }

    #[test]
    fn captured_stdin_observes_cancellation_during_copy_verification_and_handoff() {
        let (owner, mut source, control) = captured_stdin_fixture(&vec![91; 8 * MAX_SOURCE_CHUNK]);
        let checks = std::cell::Cell::new(0);
        let stopped = || {
            let count = checks.get() + 1;
            checks.set(count);
            count >= 7
        };
        let error =
            CapturedStdin::capture(&mut source, "inputs/binary.dat", None, &control, &stopped)
                .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
        assert!(checks.get() >= 7);
        // Cancelled copying cannot poison intact captured source or hand a
        // partial prefix to Cargo. A new operation can take a fresh full copy.
        let retry = owner.path().join("retry");
        create_private(&retry).unwrap();
        let mut input =
            CapturedStdin::capture(&mut source, "inputs/binary.dat", None, &retry, &|| false)
                .unwrap();
        assert_eq!(
            input.verify(&|| true).unwrap_err().kind(),
            io::ErrorKind::Interrupted
        );
        assert_eq!(
            input.take_stdio(&|| true).unwrap_err().kind(),
            io::ErrorKind::Interrupted
        );
        assert!(!input.handed_off);
        input.verify(&|| false).unwrap();
    }

    #[test]
    fn explicit_inherited_stdin_retains_terminal_and_command_refusals() {
        let mut profile = application_environment_profile();
        profile.stdin = Some(CompilationStdin::Inherit);
        assert!(profile.validate_logical().is_err());
        assert!(profile.validate_stdin(false).is_err());
        for command in [
            CompilationCommand::Run,
            CompilationCommand::Test,
            CompilationCommand::Bench,
        ] {
            profile.command = command;
            profile.validate_logical().unwrap();
            profile.validate_stdin(false).unwrap();
            assert!(profile.validate_stdin(true).is_err());
        }
        profile.selection = Some(CompilationSelection {
            no_run: true,
            ..CompilationSelection::default()
        });
        for command in [CompilationCommand::Test, CompilationCommand::Bench] {
            profile.command = command;
            assert!(profile.validate_logical().is_err(), "{command:?}");
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
        assert!(profile.inherits_stdin().unwrap());
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
        assert!(profile.inherits_stdin().unwrap());
        assert!(profile.validate_stdin(true).is_err());
        assert!(!args.iter().any(|arg| arg == "--release"));
        profile.selection = Some(CompilationSelection {
            bench: vec!["timing".into()],
            no_run: true,
            ..CompilationSelection::default()
        });
        assert!(profile.no_run());
        assert!(!profile.inherits_stdin().unwrap());
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
    fn cancelled_target_cache_waiter_leaves_while_another_root_keeps_the_lock() {
        let lock = Arc::new(Mutex::new(()));
        let held = lock.lock().unwrap();
        let cancelled = Arc::new(AtomicBool::new(false));
        let (polled, observe_poll) = std::sync::mpsc::sync_channel(1);
        let (completed, observe_completion) = std::sync::mpsc::channel();
        let waiter = {
            let lock = Arc::clone(&lock);
            let cancelled = Arc::clone(&cancelled);
            std::thread::spawn(move || {
                let result = acquire_target_cache_lock(&lock, &|| {
                    let _ = polled.try_send(());
                    cancelled.load(Ordering::Acquire)
                })
                .map(|_guard| ());
                completed.send(result).unwrap();
            })
        };
        observe_poll.recv_timeout(Duration::from_secs(2)).unwrap();
        cancelled.store(true, Ordering::Release);
        let result = observe_completion
            .recv_timeout(Duration::from_secs(2))
            .unwrap();
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Interrupted);
        waiter.join().unwrap();
        assert!(matches!(lock.try_lock(), Err(TryLockError::WouldBlock)));
        drop(held);
        assert!(acquire_target_cache_lock(&lock, &|| false).is_ok());
    }

    #[test]
    fn target_cache_lock_rechecks_cancellation_before_admitting_state_changes() {
        let lock = Mutex::new(());
        assert_eq!(
            acquire_target_cache_lock(&lock, &|| true)
                .unwrap_err()
                .kind(),
            io::ErrorKind::Interrupted
        );
        let polls = std::cell::Cell::new(0);
        let result = acquire_target_cache_lock(&lock, &|| {
            polls.set(polls.get() + 1);
            polls.get() >= 2
        });
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Interrupted);
        assert_eq!(polls.get(), 2);
        assert!(
            lock.try_lock().is_ok(),
            "cancelled admission must release its lock"
        );
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
        let edge: SubsystemWork = Box::new(|_, _| Box::pin(async { Ok(()) }));
        let server =
            ServerOwner::start_operation(Some(edge), None, Arc::clone(&stopped), controller)
                .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while !stopped.load(Ordering::Acquire) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(stopped.load(Ordering::Acquire));
        assert!(server.finish().unwrap().clean());
    }

    #[test]
    fn normal_operation_shutdown_never_clears_a_prior_cancellation() {
        let stopped = Arc::new(AtomicBool::new(false));
        let controller = Arc::new(ShutdownController::new());
        let (ready, started) = std::sync::mpsc::sync_channel(1);
        let edge: SubsystemWork = Box::new(move |_, mut shutdown| {
            Box::pin(async move {
                ready.send(()).unwrap();
                shutdown.wait().await;
                Ok(())
            })
        });
        let server =
            ServerOwner::start_operation(Some(edge), None, Arc::clone(&stopped), controller)
                .unwrap();
        started.recv_timeout(Duration::from_secs(5)).unwrap();
        stopped.store(true, Ordering::Release);
        assert!(server.finish().unwrap().clean());
        assert!(stopped.load(Ordering::Acquire));
        let cancelled = || stopped.load(Ordering::Acquire);
        assert_eq!(
            PreparationControl::new(&cancelled, None)
                .checkpoint()
                .unwrap_err()
                .kind(),
            io::ErrorKind::Interrupted
        );
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

    fn captured_driver_diagnostics(owner: &Path) -> DrainedOutput {
        let mut command = std::process::Command::new("/bin/sh");
        command
            .args([
                "-c",
                "printf 'stdout\\000\\377'; printf 'stderr\\000\\376' >&2",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let process = ManagedProcessGroup::spawn_command(command, Attribution::default()).unwrap();
        let output = process
            .wait_with_bounded_drain_budget(
                &DrainLimits {
                    resident_bound: 2,
                    spill_dir: owner.join("diagnostics"),
                },
                1024,
                || false,
            )
            .unwrap();
        assert!(output.status.success());
        assert_eq!(output.residual_group_members, 0);
        assert!(output.stdout.spilled_bytes() > 0);
        assert!(output.stderr.spilled_bytes() > 0);
        output
    }

    fn full_diagnostic_pipe() -> (std::os::fd::OwnedFd, File) {
        let (reader, writer) = rustix::pipe::pipe_with(
            rustix::pipe::PipeFlags::NONBLOCK | rustix::pipe::PipeFlags::CLOEXEC,
        )
        .unwrap();
        let bytes = [0x5a; 4096];
        loop {
            match rustix::io::write(&writer, &bytes) {
                Ok(count) => assert!(count > 0),
                Err(rustix::io::Errno::AGAIN) => break,
                result => panic!("unexpected caller-pipe fill: {result:?}"),
            }
        }
        let flags = rustix::fs::fcntl_getfl(&writer).unwrap();
        rustix::fs::fcntl_setfl(&writer, flags & !rustix::fs::OFlags::NONBLOCK).unwrap();
        (reader, File::from(writer))
    }

    #[test]
    fn inherited_diagnostic_replay_keeps_spilled_bytes_and_original_file_offsets() {
        let owner = crate::test_util::private_tempdir();
        let captured = captured_driver_diagnostics(owner.path());
        let mut stdout = tempfile::tempfile().unwrap();
        let mut stderr = tempfile::tempfile().unwrap();
        stdout.write_all(b"before-").unwrap();
        stderr.write_all(b"prior-").unwrap();
        let stopped = AtomicBool::new(false);
        let mut output = OperationOutput::inherited(
            &stdout,
            &stderr,
            &stopped,
            Instant::now() + Duration::from_secs(5),
        )
        .unwrap();
        output.replay(&captured).unwrap();
        stdout.write_all(b"-after").unwrap();
        stderr.write_all(b"-after").unwrap();
        let mut bytes = vec![0; stdout.metadata().unwrap().len() as usize];
        stdout.read_exact_at(&mut bytes, 0).unwrap();
        assert_eq!(bytes, b"before-stdout\0\xff-after");
        bytes.resize(stderr.metadata().unwrap().len() as usize, 0);
        stderr.read_exact_at(&mut bytes, 0).unwrap();
        assert_eq!(bytes, b"prior-stderr\0\xfe-after");
    }

    #[test]
    fn inherited_diagnostic_backpressure_releases_state_after_cancellation_or_deadline() {
        for replay in [false, true] {
            for cancel in [false, true] {
                let owner = crate::test_util::private_tempdir();
                let captured = captured_driver_diagnostics(owner.path());
                let state = StateOwner::acquire(owner.path()).unwrap();
                let (_reader, writer) = full_diagnostic_pipe();
                let flags = rustix::fs::fcntl_getfl(&writer).unwrap();
                let stdout = if replay {
                    writer.try_clone().unwrap()
                } else {
                    tempfile::tempfile().unwrap()
                };
                let stderr = if replay {
                    tempfile::tempfile().unwrap()
                } else {
                    writer.try_clone().unwrap()
                };
                let stopped = Arc::new(AtomicBool::new(false));
                let child_stopped = Arc::clone(&stopped);
                let (ready, started) = std::sync::mpsc::channel();
                let (finished, result) = std::sync::mpsc::channel();
                let child = std::thread::spawn(move || {
                    let _state = state;
                    let deadline = Instant::now()
                        + if cancel {
                            Duration::from_secs(5)
                        } else {
                            Duration::from_millis(500)
                        };
                    let mut output =
                        OperationOutput::inherited(&stdout, &stderr, &child_stopped, deadline)
                            .unwrap();
                    ready.send(()).unwrap();
                    let outcome = if replay {
                        output.replay(&captured)
                    } else {
                        output.event(json!({"kind":"canonical-driver-diagnostic"}))
                    };
                    finished.send(outcome).unwrap();
                });
                started.recv_timeout(Duration::from_secs(5)).unwrap();
                assert!(StateOwner::acquire(owner.path()).is_err());
                assert!(matches!(
                    result.recv_timeout(Duration::from_millis(75)),
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout),
                ));
                if cancel {
                    stopped.store(true, Ordering::Release);
                }
                assert_eq!(
                    result
                        .recv_timeout(Duration::from_secs(5))
                        .expect("driver output must not strand the operation owner")
                        .unwrap_err()
                        .kind(),
                    if cancel {
                        io::ErrorKind::Interrupted
                    } else {
                        io::ErrorKind::TimedOut
                    },
                );
                child.join().unwrap();
                StateOwner::acquire(owner.path()).unwrap();
                assert_eq!(rustix::fs::fcntl_getfl(&writer).unwrap(), flags);
            }
        }
    }

    #[test]
    fn native_termination_child() {
        let Some(mode) = std::env::var_os("RABS_NATIVE_TERMINATION_CASE") else {
            return;
        };
        let mode = mode.to_str().unwrap();
        let root = PathBuf::from(std::env::var_os("RABS_NATIVE_TERMINATION_ROOT").unwrap());
        let state = StateOwner::acquire(&root).unwrap();
        let termination = if mode == "pending-int" {
            let cancellation = OperationCancellation::start_native().unwrap();
            signal_hook::low_level::raise(signal_hook::consts::SIGINT).unwrap();
            cancellation
                .finish(Ok(ChildTermination::Exited(0)), true)
                .unwrap()
        } else if mode.starts_with("cancel-") {
            let cancellation = OperationCancellation::start_native().unwrap();
            let mut command = std::process::Command::new("/bin/sh");
            command.args(["-c", "trap '' TERM; /bin/sleep 30 & wait"]);
            let process =
                ManagedProcessGroup::spawn_command(command, Attribution::default()).unwrap();
            fs::write(root.join("group"), process.pgid().to_string()).unwrap();
            fs::write(root.join("signal-ready"), b"owned").unwrap();
            let mut later_signal_sent = false;
            let drained = process
                .wait_with_bounded_drain_budget(&DrainLimits::default(), 4096, || {
                    if cancellation.stopped.load(Ordering::Acquire) && !later_signal_sent {
                        later_signal_sent = true;
                        // The first cancellation stays authoritative while a
                        // different signal arrives during descendant cleanup.
                        let later = if mode == "cancel-term" {
                            rustix::process::Signal::HUP
                        } else {
                            rustix::process::Signal::TERM
                        };
                        rustix::process::kill_process(rustix::process::getpid(), later).unwrap();
                    }
                    cancellation.stopped.load(Ordering::Acquire)
                })
                .unwrap();
            assert_eq!(drained.residual_group_members, 0);
            assert!(later_signal_sent);
            cancellation
                .finish(
                    Err(io::Error::new(
                        io::ErrorKind::Interrupted,
                        "native cancellation",
                    )),
                    true,
                )
                .unwrap()
        } else {
            let script = match mode {
                "exit-143" => "exit 143",
                "exit-137" => "exit 137",
                "term" => "kill -TERM $$",
                "kill" => "kill -KILL $$",
                _ => panic!("unknown native termination case"),
            };
            let status = std::process::Command::new("/bin/sh")
                .args(["-c", script])
                .status()
                .unwrap();
            native_termination(status).unwrap()
        };
        drop(state);
        fs::write(root.join("cleanup-completed"), b"drained").unwrap();
        exit_like(termination);
    }

    #[test]
    fn native_exit_and_first_cancellation_signal_survive_process_cleanup() {
        use std::os::unix::process::ExitStatusExt;
        struct ChildOwner(std::process::Child);
        impl Drop for ChildOwner {
            fn drop(&mut self) {
                if self.0.try_wait().ok().flatten().is_none() {
                    let _ = self.0.kill();
                    let _ = self.0.wait();
                }
            }
        }
        for (mode, code, signal) in [
            ("exit-143", Some(143), None),
            ("exit-137", Some(137), None),
            ("term", None, Some(rustix::process::Signal::TERM)),
            ("kill", None, Some(rustix::process::Signal::KILL)),
            ("pending-int", None, Some(rustix::process::Signal::INT)),
            ("cancel-int", None, Some(rustix::process::Signal::INT)),
            ("cancel-term", None, Some(rustix::process::Signal::TERM)),
            ("cancel-hup", None, Some(rustix::process::Signal::HUP)),
        ] {
            let root = crate::test_util::private_tempdir();
            let log = OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(root.path().join("child.log"))
                .unwrap();
            let mut child = ChildOwner(
                std::process::Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "coord::canonical_local::tests::native_termination_child",
                        "--nocapture",
                    ])
                    .env("RABS_NATIVE_TERMINATION_CASE", mode)
                    .env("RABS_NATIVE_TERMINATION_ROOT", root.path())
                    .stdin(Stdio::null())
                    .stdout(log.try_clone().unwrap())
                    .stderr(log)
                    .spawn()
                    .unwrap(),
            );
            let deadline = Instant::now() + Duration::from_secs(30);
            if mode.starts_with("cancel-") {
                while !root.path().join("signal-ready").exists() {
                    assert!(
                        child.0.try_wait().unwrap().is_none() && Instant::now() < deadline,
                        "{mode} did not become ready: {}",
                        fs::read_to_string(root.path().join("child.log")).unwrap()
                    );
                    std::thread::sleep(Duration::from_millis(10));
                }
                assert!(StateOwner::acquire(root.path()).is_err());
                let pid =
                    rustix::process::Pid::from_raw(i32::try_from(child.0.id()).unwrap()).unwrap();
                rustix::process::kill_process(pid, signal.unwrap()).unwrap();
            }
            let status = loop {
                if let Some(status) = child.0.try_wait().unwrap() {
                    break status;
                }
                assert!(Instant::now() < deadline, "{mode} did not finish cleanup");
                std::thread::sleep(Duration::from_millis(10));
            };
            assert_eq!(status.code(), code, "{mode}");
            assert_eq!(
                status.signal(),
                signal.map(|value| value.as_raw()),
                "{mode}"
            );
            assert_eq!(
                fs::read(root.path().join("cleanup-completed")).unwrap(),
                b"drained"
            );
            StateOwner::acquire(root.path()).unwrap();
            if mode.starts_with("cancel-") {
                let group = fs::read_to_string(root.path().join("group"))
                    .unwrap()
                    .parse()
                    .unwrap();
                assert!(
                    rabs_asupersync::process_groups::members_from_proc(group)
                        .unwrap()
                        .is_empty(),
                    "{mode} left live descendants"
                );
            }
        }
    }

    #[test]
    fn native_cancellation_cannot_hide_unconfirmed_process_cleanup() {
        for kind in [io::ErrorKind::Other, io::ErrorKind::Interrupted] {
            let cancellation = OperationCancellation::start_native().unwrap();
            cancellation.first_signal.store(15, Ordering::Release);
            let result = cancellation.finish(
                Err(io::Error::new(
                    kind,
                    UnconfirmedCleanup("unresolved descendants".into()),
                )),
                true,
            );
            let error = result.unwrap_err();
            assert_eq!(error.kind(), kind);
            assert!(error.get_ref().unwrap().is::<UnconfirmedCleanup>());
        }
    }

    #[test]
    fn native_cancellation_preserves_unrelated_failures() {
        for kind in [
            io::ErrorKind::InvalidInput,
            io::ErrorKind::Other,
            io::ErrorKind::TimedOut,
        ] {
            let cancellation = OperationCancellation::start_native().unwrap();
            cancellation.first_signal.store(15, Ordering::Release);
            let error = cancellation
                .finish(Err(io::Error::new(kind, "independent failure")), true)
                .unwrap_err();
            assert_eq!(error.kind(), kind);
            assert_eq!(error.to_string(), "independent failure");
        }
    }

    #[test]
    fn coordinator_cleanup_failure_is_retained_on_early_return() {
        for explicit_finish in [false, true] {
            let unconfirmed = Arc::new(AtomicBool::new(false));
            let owner = TrackedServerOwner::new(
                ServerOwner {
                    controller: Arc::new(ShutdownController::new()),
                    worker: Some(std::thread::spawn(|| panic!("failed coordinator cleanup"))),
                    normal_shutdown: None,
                },
                Arc::clone(&unconfirmed),
            );
            if explicit_finish {
                let error = owner.finish().unwrap_err();
                assert!(error.get_ref().unwrap().is::<UnconfirmedCleanup>());
            } else {
                // This is the same owner path used when readiness, source
                // verification or output fails before normal finalization.
                let result = (|| -> io::Result<()> {
                    let _owner = owner;
                    Err(io::Error::new(
                        io::ErrorKind::Interrupted,
                        "cancelled before execution",
                    ))
                })();
                assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Interrupted);
            }
            assert!(unconfirmed.load(Ordering::Acquire));
        }
    }

    #[test]
    fn inherited_diagnostic_signal_child() {
        let Some(root) = std::env::var_os("RABS_DIAGNOSTIC_SIGNAL_TEST_ROOT") else {
            return;
        };
        let root = PathBuf::from(root);
        let _state = StateOwner::acquire(&root).unwrap();
        let cancellation = OperationCancellation::start().unwrap();
        let (_reader, writer) = full_diagnostic_pipe();
        let mut output = OperationOutput::inherited(
            &writer,
            &writer,
            &cancellation.stopped,
            Instant::now() + Duration::from_secs(10),
        )
        .unwrap();
        fs::write(root.join("signal-ready"), b"signal listeners installed").unwrap();
        assert_eq!(
            output
                .event(json!({"kind":"blocked-native-diagnostic"}))
                .unwrap_err()
                .kind(),
            io::ErrorKind::Interrupted,
        );
        fs::write(root.join("signal-observed"), b"cancelled").unwrap();
    }

    #[test]
    fn inherited_diagnostic_output_observes_real_sigterm() {
        // Signals are process-global. Exercise the production bridge in a
        // dedicated instance of this test binary, never the parallel runner.
        struct ChildOwner(std::process::Child);
        impl Drop for ChildOwner {
            fn drop(&mut self) {
                if self.0.try_wait().ok().flatten().is_none() {
                    let _ = self.0.kill();
                    let _ = self.0.wait();
                }
            }
        }
        let root = crate::test_util::private_tempdir();
        let log = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(root.path().join("child.log"))
            .unwrap();
        let mut child = ChildOwner(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "coord::canonical_local::tests::inherited_diagnostic_signal_child",
                    "--nocapture",
                ])
                .env("RABS_DIAGNOSTIC_SIGNAL_TEST_ROOT", root.path())
                .stdin(Stdio::null())
                .stdout(log.try_clone().unwrap())
                .stderr(log)
                .spawn()
                .unwrap(),
        );
        let deadline = Instant::now() + Duration::from_secs(30);
        while !root.path().join("signal-ready").exists() {
            assert!(
                child.0.try_wait().unwrap().is_none() && Instant::now() < deadline,
                "signal child failed to become ready: {}",
                fs::read_to_string(root.path().join("child.log")).unwrap(),
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(StateOwner::acquire(root.path()).is_err());
        let pid = rustix::process::Pid::from_raw(i32::try_from(child.0.id()).unwrap()).unwrap();
        rustix::process::kill_process(pid, rustix::process::Signal::TERM).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let status = loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                break status;
            }
            assert!(
                Instant::now() < deadline,
                "SIGTERM did not release the blocked diagnostic writer"
            );
            std::thread::sleep(Duration::from_millis(10));
        };
        assert!(
            status.success(),
            "signal child failed: {}",
            fs::read_to_string(root.path().join("child.log")).unwrap(),
        );
        assert_eq!(
            fs::read(root.path().join("signal-observed")).unwrap(),
            b"cancelled"
        );
        StateOwner::acquire(root.path()).unwrap();
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
        let coordinator = ServerOwner::start_operation(
            None,
            Some(Arc::clone(&coord)),
            Arc::clone(&stopped),
            controller,
        )
        .unwrap();
        let activity = CanonicalActivity::new();
        let edge = canonical_edge_work(
            EdgeServerConfig {
                socket_path: socket.clone(),
                state_dir: owner.path().join("shadow"),
                coord: coord.edge_subscriber(),
                prepared_operations: None,
                live_dependency: Some(LiveDependencyLane::new(coord.clone())),
            },
            Arc::clone(&paths),
            Arc::clone(&activity),
        );
        let server = ServerOwner::start_operation(
            Some(edge),
            None,
            Arc::clone(&stopped),
            Arc::new(ShutdownController::new()),
        )
        .unwrap();
        wait_ready(&server, &socket, &coord, &stopped).unwrap();
        let authority = coord.authority().unwrap();
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
        let edge_receipt = server.finish().unwrap();
        assert!(edge_receipt.clean());
        assert!(!socket.exists());
        assert!(!stopped.load(Ordering::Acquire));
        assert!(coord.available());
        assert_eq!(coord.authority().unwrap(), authority);
        assert_eq!(activity.active_sessions(), 0);
        let cancelled = || stopped.load(Ordering::Acquire);
        PreparationControl::new(&cancelled, None)
            .checkpoint()
            .expect("clean edge shutdown must allow target capture under live authority");
        paths
            .verify_completed_producers(&coord, &cancelled)
            .unwrap();
        let coordinator_receipt = coordinator.finish().unwrap();
        assert!(coordinator_receipt.clean());
        assert!(!coord.available());
        assert!(!stopped.load(Ordering::Acquire));
        assert!(
            paths
                .verify_completed_producers(&coord, &cancelled)
                .is_err()
        );
        let outcomes = edge_receipt.subsystems.len() + coordinator_receipt.subsystems.len();
        let receipt = merge_shutdown_receipts(edge_receipt, coordinator_receipt);
        assert!(receipt.clean());
        assert_eq!(receipt.subsystems.len(), outcomes);
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
        authenticated_edge_pin: Option<[u8; 32]>,
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
                authenticated_edge_pin: None,
            }
        }

        fn key(&self) -> [u8; 32] {
            self.try_key().unwrap()
        }

        fn try_key(&self) -> io::Result<[u8; 32]> {
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
                authenticated_edge_pin: self.authenticated_edge_pin,
            }
            .key(&self.config)
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
    fn remote_private_target_keys_bind_authenticated_peers_without_weakening_inputs() {
        let mut first = ReuseKeyFixture::new();
        let local = first.key();
        first.authenticated_edge_pin = Some([1; 32]);
        let remote = first.key();
        assert_ne!(remote, local);

        let mut second = ReuseKeyFixture::new();
        second.authenticated_edge_pin = Some([1; 32]);
        assert_eq!(second.key(), remote);
        second.authenticated_edge_pin = Some([2; 32]);
        assert_ne!(second.key(), remote);
        second.authenticated_edge_pin = Some([0; 32]);
        assert_eq!(
            second.try_key().unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );

        // The peer namespace wraps the full existing compatibility contract.
        // Compiler-only checks still permit the existing safe source-edit
        // family; codegen retains every captured source byte in its key.
        first.source = reuse_source(b"pub const VALUE:u8=2;", b"manifest", None);
        assert_eq!(first.key(), remote);
        first.source = reuse_source(b"pub const VALUE:u8=2;", b"changed manifest", None);
        assert_ne!(first.key(), remote);
        first.source = reuse_source(b"pub const VALUE:u8=1;", b"manifest", None);
        first.args[0] = "build".into();
        let build = first.key();
        first.source = reuse_source(b"pub const VALUE:u8=2;", b"manifest", None);
        assert_ne!(first.key(), build);

        for changed in ["toolchain", "epoch", "wrapper", "driver", "environment"] {
            let mut fixture = ReuseKeyFixture::new();
            fixture.authenticated_edge_pin = Some([1; 32]);
            match changed {
                "toolchain" => {
                    fixture.request["toolchain_identity"]["sha256"] = json!("cd".repeat(32))
                }
                "epoch" => fixture.config.runtime_epoch = "host-2".into(),
                "wrapper" => fixture.wrapper = [6; 32],
                "driver" => fixture.driver = "driver-2".into(),
                "environment" => {
                    fixture.spec.env.push(("INPUT".into(), "changed".into()));
                }
                _ => unreachable!(),
            }
            assert_ne!(fixture.key(), remote, "changed {changed}");
        }
    }

    #[test]
    fn remote_private_target_restore_is_peer_scoped_under_one_aggregate_budget() {
        use crate::coord::live_dependency::canonical::CommittedOutputSeeds;

        let state = crate::test_util::private_tempdir();
        let workspace = crate::test_util::private_tempdir();
        create_private(&workspace.path().join("src")).unwrap();
        fs::write(workspace.path().join("Cargo.toml"), b"manifest").unwrap();
        fs::write(
            workspace.path().join("src/lib.rs"),
            b"pub const VALUE:u8=1;",
        )
        .unwrap();
        let target = crate::test_util::private_tempdir();
        fs::write(target.path().join("artifact"), b"first edge output").unwrap();
        let mut fixture = ReuseKeyFixture::new();
        let local = fixture.key();
        fixture.authenticated_edge_pin = Some([1; 32]);
        let first = fixture.key();
        fixture.authenticated_edge_pin = Some([2; 32]);
        let second = fixture.key();
        let mut config = fixture.config.clone();
        let manifest = &fixture.source;
        let capture = |key, config: &TargetCacheConfig| {
            TargetState::open(
                state.path(),
                config,
                key,
                workspace.path(),
                manifest,
                &|| false,
            )
            .unwrap()
            .capture(target.path(), &CommittedOutputSeeds::default())
            .unwrap();
        };
        let restore = |key, config: &TargetCacheConfig| {
            let candidate = crate::test_util::private_tempdir();
            let mut cache = TargetState::open(
                state.path(),
                config,
                key,
                workspace.path(),
                manifest,
                &|| false,
            )
            .unwrap();
            cache.restore(candidate.path()).unwrap().then(|| {
                let bytes = fs::read(candidate.path().join("artifact")).unwrap();
                // A private restored target can be mutated independently.
                fs::write(candidate.path().join("artifact"), b"private edit").unwrap();
                bytes
            })
        };

        capture(first, &config);
        assert_eq!(
            restore(first, &config).as_deref(),
            Some(b"first edge output".as_slice())
        );
        assert!(restore(second, &config).is_none());
        assert!(restore(local, &config).is_none());
        assert_eq!(
            restore(first, &config).as_deref(),
            Some(b"first edge output".as_slice())
        );

        // Keys share the same store and retention limit, rather than granting
        // every enrolled edge its own independently growing byte/family quota.
        config.max_families = 1;
        fs::write(target.path().join("artifact"), b"second edge output").unwrap();
        capture(second, &config);
        assert_eq!(
            restore(second, &config).as_deref(),
            Some(b"second edge output".as_slice())
        );
        assert!(restore(first, &config).is_none());
        assert!(restore(local, &config).is_none());
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
