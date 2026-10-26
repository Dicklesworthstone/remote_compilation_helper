//! Local canonical Cargo execution connected to the coordinator's rustc cache.
//!
//! This explicit profile runs a selected Cargo check or build offline and locked against
//! captured inputs and a captured toolchain. Cargo itself runs at canonical
//! paths, so unit hashes and rustc arguments are stable across checkouts. A
//! fresh operation-scoped socket admits only rustc requests; the persistent
//! CAS and the ordinary daemon socket are never visible to the build.
//!
//! The actual selected Cargo unit graph must contain no build scripts or
//! procedural macros. Inactive package targets do not grant code execution.
//! Eligible external dependencies use the existing evidence-gated lane;
//! archive codegen requires an isolated worker. Workspace crates and unsupported rustc invocations still compile
//! normally in the namespace; this does not promote a workspace cache class.

use super::live::{CoordLive, cluster_id};
use super::live_dependency::LiveDependencyLane;
use super::live_dependency::canonical::CanonicalPaths;
use crate::edge::live_facts::{FileSig, read_stable};
use crate::edge::server::{CanonicalActivity, EdgeServerConfig, canonical_edge_work};
use asupersync::signal::ShutdownController;
use rabs_asupersync::daemon_runtime::{
    DaemonError, DaemonRunOptions, ShutdownReceipt, SubsystemWork, run_daemon_controlled,
};
use rabs_asupersync::process_groups::ManagedProcessGroup;
use rabs_asupersync::region_tree::Attribution;
use rabs_asupersync::stream_drain::{DrainLimits, DrainedOutput};
use rabs_protocol::release_authorization::ReleaseAuthorizationMode;
use rabs_sandbox::canonical_mounts::{CanonicalMountPlan, UnitMount};
use rabs_sandbox::canonical_namespace::{
    CanonicalNamespaceSpec, HostIsolationSupport, build_canonical_argv, command_for,
};
use rabs_sandbox::cargo_check::{
    CompilationCommand, CompilationSelection, validate_compilation_unit_graph,
};
use rabs_sandbox::cargo_home::CargoHomeProjection;
use serde::Deserialize;
use serde_json::{Value, json};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

const PROFILE_VERSION: &str = "canonical-compile-local-v1";
const CARGO: &str = "/__rabs/toolchain/bin/cargo";
const RUSTC: &str = "/__rabs/toolchain/bin/rustc";
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
struct StateOwner {
    root: PathBuf,
    _lock: File,
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
        Ok(Self { root, _lock: file })
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
        self.compilation_args()?;
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

    fn compilation_args(&self) -> io::Result<Vec<String>> {
        let mut args = match &self.selection {
            Some(selection) => selection.cargo_arguments(self.command)?,
            None if self.command == CompilationCommand::Check => {
                vec!["check".into(), "--lib".into()]
            }
            None => vec![self.command.as_str().into()],
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

    fn source_specification(&self) -> io::Result<Value> {
        let mut source = json!({"manifest":self.manifest});
        if let Some(vendor) = &self.vendor {
            source["vendor"] = json!(vendor);
        }
        if let Some(home) = &self.cargo_home_source {
            source["cargo_home_source"] = json!(home);
        }
        Ok(json!({
            "kind":"canonical-exec", "request_id":1, "program":CARGO,
            "args":self.compilation_args()?, "toolchain_source":self.toolchain_root,
            "cargo_source":source,
            "command_context":{"version":"env-cwd-v1", "cwd":self.cwd(),
                "env":{"CARGO_INCREMENTAL":"0", "CARGO_TARGET_DIR":TARGET, "RUSTC":RUSTC}}
        }))
    }
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
    profile.validate()?;
    let state = StateOwner::acquire(&profile.state_root)?;
    let support = HostIsolationSupport::probe();
    require(
        support.missing_for_canonical().is_empty(),
        &format!(
            "canonical local compilation requires measured namespace support: {:?}",
            support.missing_for_canonical()
        ),
    )?;
    let owner = Arc::new(
        tempfile::Builder::new()
            .prefix("rabs-compile-")
            .tempdir_in(&profile.operation_root)?,
    );
    let bundle = owner.path().join("bundle");
    let (_report, source) = super::source_delivery::prepare_local_bundle(
        &profile.source_root,
        &profile.source_specification()?,
        &bundle,
    )?;
    let (_, request_bytes) = read_stable(
        &bundle.join("request.json"),
        super::worker_delivery::MAX_FRAME_BYTES as u64,
    )?;
    let request: Value = serde_json::from_slice(&request_bytes)?;
    let source_root = source
        .sealed_root()
        .ok_or_else(|| invalid("source was not sealed"))?;
    let cargo_home = request
        .get("cargo_home")
        .map(|home| {
            let version = home["version"]
                .as_str()
                .ok_or_else(|| invalid("Cargo home version missing"))?;
            let prefix = home["prefix"]
                .as_str()
                .ok_or_else(|| invalid("Cargo home prefix missing"))?;
            CargoHomeProjection::for_version(version, prefix, source.manifest())?.prepare(
                &source,
                &owner.path().join("inputs"),
                || false,
            )
        })
        .transpose()?;
    let workspace = cargo_home
        .as_ref()
        .and_then(|home| home.projected_workspace())
        .unwrap_or(source_root)
        .to_path_buf();
    let home_root = owner.path().join("home");
    let target_root = owner.path().join("target");
    create_private(&home_root)?;
    create_private(&target_root)?;
    let cargo_root = if let Some(home) = &cargo_home {
        home.root().to_path_buf()
    } else {
        let path = owner.path().join("cargo-home");
        create_private(&path)?;
        path
    };
    let toolchain = bundle.join("toolchain");
    let mut plan = CanonicalMountPlan::new(&toolchain, &workspace, &cargo_root, &home_root);
    plan.out_units.push(UnitMount {
        unit: "cargo".into(),
        backing: target_root.clone(),
    });
    plan.extra_env.extend([
        ("CARGO_TARGET_DIR".into(), TARGET.into()),
        ("CARGO_INCREMENTAL".into(), "0".into()),
        ("RUSTC".into(), RUSTC.into()),
    ]);
    let mut spec = plan.to_spec().map_err(|error| invalid(error.to_string()))?;
    spec.cwd = profile.cwd();
    // Source and HOME are immutable inside the build. In particular, mounting
    // the control directory below a writable HOME would let a later parent
    // bind obscure its protection in the namespace builder's mount ordering.
    make_read_only(&mut spec, "/__rabs/workspace")?;
    make_read_only(&mut spec, "/__rabs/home")?;
    let paths = CanonicalPaths::new(
        owner.clone(),
        vec![
            ("/__rabs/workspace".into(), workspace),
            ("/__rabs/cargo-home".into(), cargo_root),
            ("/__rabs/toolchain".into(), toolchain),
            (TARGET.into(), target_root.clone()),
            ("/__rabs/home".into(), home_root.clone()),
        ],
    )
    .map_err(io::Error::other)?;
    let stopped = Arc::new(AtomicBool::new(false));
    let timeout = Duration::from_secs(profile.timeout_seconds);
    let compilation_args = profile.compilation_args()?;
    // Ask the captured Cargo for the exact units this command would compile.
    // Metadata's package list includes inactive optional/dev targets and cannot
    // establish which build scripts or proc macros a selected check executes.
    // The unit-graph query does not compile/run units, and the cache endpoint
    // does not exist yet. Unsupported Cargo versions fail closed here.
    let mut graph_args = compilation_args.clone();
    graph_args.extend([
        "--unit-graph".into(),
        "-Z".into(),
        "unstable-options".into(),
    ]);
    let planned = execute(
        &spec,
        &support,
        &graph_args,
        CargoOutput::Capture {
            directory: owner.path().join("unit-graph-drain"),
            maximum: MAX_GRAPH_BYTES,
        },
        timeout,
        &stopped,
    )?;
    if !planned.status.success() {
        replay(&planned)?;
        return Err(invalid(
            "captured Cargo unit planning failed (nightly Cargo with --unit-graph is required); no rustc cache endpoint was started",
        ));
    }
    let graph: Value = serde_json::from_reader(planned.stdout.reader()?)?;
    let graph = validate_compilation_unit_graph(&graph, profile.command)?;
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
    let socket = control.join("rustc.sock");
    // sockaddr_un includes its terminating NUL. Refuse before boot, rather
    // than silently selecting a shorter socket outside this operation owner.
    require(
        socket.as_os_str().as_encoded_bytes().len() < 108,
        "operation_root is too long for the owned Unix socket (choose a shorter path)",
    )?;
    let mounted = Arc::new(
        crate::janitor::store::mount_and_reconcile(&state.root.join("cas"))
            .map_err(io::Error::other)?,
    );
    let coord = Arc::new(
        CoordLive::with_cas(mounted).with_release_authorization(build_identity, release_mode),
    );
    let controller = Arc::new(ShutdownController::new());
    controller.listen_for_signals();
    let activity = CanonicalActivity::new();
    let edge = canonical_edge_work(
        EdgeServerConfig {
            socket_path: socket.clone(),
            state_dir: state.root.join("shadow"),
            coord: coord.edge_subscriber(),
            prepared_operations: None,
            live_dependency: Some(LiveDependencyLane::new(coord.clone())),
        },
        Arc::clone(&paths),
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
    let worker = std::thread::Builder::new()
        .name("rabs-canonical-coord".into())
        .spawn(move || run_daemon_controlled(options, worker_controller))?;
    let server = ServerOwner {
        controller,
        worker: Some(worker),
    };
    wait_ready(&server, &socket, &coord, &stopped)?;
    spec.env.extend([
        ("RUSTC_WRAPPER".into(), WRAPPER.into()),
        ("RABS_SOCKET_PATH".into(), SOCKET.into()),
        (
            "RABS_BREAKER_FILE".into(),
            "/__rabs/cargo-home/.rabs-breaker".into(),
        ),
    ]);
    eprintln!(
        "{}",
        json!({"kind":"canonical-compilation-started", "version":PROFILE_VERSION,
        "command":profile.command.as_str(), "namespace":"canonical",
        "cache_scope":"external-dependency-metadata-and-worker-rlib",
        "workspace_cache":false, "source_sha256":request["source_manifest"]["manifest_sha256"],
        "selected_units":graph.units, "selected_packages":graph.packages,
        "selected_roots":graph.roots})
    );
    let result = execute(
        &spec,
        &support,
        &compilation_args,
        CargoOutput::Inherit,
        timeout,
        &stopped,
    );
    // A successful wrapper exits after capture ACK; publication can still be
    // queued on that same session. Seal admission only after Cargo's process
    // group is gone, then keep coordinator authority alive through the last
    // session/publication before requesting subsystem shutdown.
    let publication_drain = if result.is_ok() {
        activity.seal_and_wait(Duration::from_secs(60), || stopped.load(Ordering::Acquire))
    } else {
        Ok(())
    };
    let shutdown = server.finish();
    let output = result?;
    publication_drain.map_err(io::Error::other)?;
    let receipt = shutdown?;
    require(
        receipt.clean(),
        "canonical coordinator did not drain cleanly",
    )?;
    eprintln!("{}", receipt.to_json_line());
    if output.status.success() && profile.command == CompilationCommand::Build {
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
        eprintln!(
            "{}",
            json!({"kind":"canonical-build-completed", "version":PROFILE_VERSION,
                "canonical_target":TARGET, "target_directory":delivered})
        );
    }
    use std::os::unix::process::ExitStatusExt;
    Ok(output
        .status
        .code()
        .unwrap_or_else(|| 128 + output.status.signal().unwrap_or(1)))
}

/// Move, rather than recopy, a fully drained target to a newly allocated private
/// owner on the same filesystem. There is no caller-selected overwrite target
/// and no retained copy of source or toolchain inputs. Only successful builds
/// call this; check/error/cancellation paths keep temporary target ownership.
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
    Capture { directory: PathBuf, maximum: u64 },
    Inherit,
}

fn execute(
    spec: &CanonicalNamespaceSpec,
    support: &HostIsolationSupport,
    args: &[String],
    output: CargoOutput,
    timeout: Duration,
    stopped: &AtomicBool,
) -> io::Result<DrainedOutput> {
    let launch = build_canonical_argv(spec, support, CARGO, args)
        .map_err(|error| invalid(error.to_string()))?;
    let mut command = command_for(&launch);
    command.stdin(Stdio::null());
    let (limits, maximum) = match output {
        CargoOutput::Capture { directory, maximum } => {
            command.stdout(Stdio::piped()).stderr(Stdio::piped());
            (DrainLimits::new(directory), maximum)
        }
        CargoOutput::Inherit => {
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
            )
        }
    };
    let process = ManagedProcessGroup::spawn_command(command, Attribution::default())?;
    let start = Instant::now();
    let mut cancelled = false;
    let mut timed_out = false;
    let output = process.wait_with_bounded_drain_budget(&limits, maximum, || {
        cancelled |= stopped.load(Ordering::Acquire);
        timed_out |= start.elapsed() >= timeout;
        cancelled || timed_out
    })?;
    cancelled |= stopped.load(Ordering::Acquire);
    timed_out |= start.elapsed() >= timeout;
    if cancelled || timed_out {
        replay(&output)?;
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
    require(
        output.residual_group_members == 0,
        "canonical Cargo process group did not drain",
    )?;
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

struct ServerOwner {
    controller: Arc<ShutdownController>,
    worker: Option<JoinHandle<Result<ShutdownReceipt, DaemonError>>>,
}
impl ServerOwner {
    fn finish(mut self) -> io::Result<ShutdownReceipt> {
        self.controller.shutdown();
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
        self.controller.shutdown();
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
        assert!(serde_json::from_value::<Profile>(value).is_err());
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
        for command in ["test", "run", "bench", "rustc", "clippy"] {
            assert!(serde_json::from_value::<Profile>(json!({
                "version":PROFILE_VERSION, "command":command,
                "source_root":"/source", "toolchain_root":"/toolchain",
                "state_root":"/state", "operation_root":"/operations", "wrapper":"/bin/rabs-wrap"
            })).is_err());
        }
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
    fn scoped_socket_refuses_generic_daemon_authority_and_drains_its_open_session() {
        use std::io::{BufRead, BufReader};
        let owner = Arc::new(tempfile::tempdir().unwrap());
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
}
