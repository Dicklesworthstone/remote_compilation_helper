//! Persistent, private service for independent canonical Cargo invocations.
//!
//! The service owns one coordinator incarnation. Each connected operation
//! owns its captures, edge endpoint, processes, diagnostic files and cancel
//! flag. A lost client cancels that operation; it never authorizes a local
//! retry or releases the shared coordinator while another operation is live.

mod wire;

use super::{
    Profile, SharedRuntime, ordinary_directory, overlap, plain_absolute, private_directory,
};
use crate::edge::live_facts::read_stable;
use asupersync::signal::ShutdownController;
use rabs_protocol::canonical_service::{
    Header, Kind, MAX_CHUNK_BYTES, MAX_FAILURE_BYTES, MAX_PROFILE_BYTES, ResponseState,
};
use rabs_protocol::release_authorization::ReleaseAuthorizationMode;
use rabs_sandbox::socket_endpoint::EndpointLease;
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::VecDeque;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{FileExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

const SERVICE_VERSION: &str = "canonical-compile-service-v1";
const REQUEST_VERSION: &str = "canonical-compile-service-request-v1";
const HANDSHAKE_BUDGET: Duration = Duration::from_secs(10);
const DELIVERY_BUDGET: Duration = Duration::from_secs(120);
const CARGO_OUTPUT_BYTES: u64 = 64 * 1024 * 1024;

fn invalid(detail: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, detail.into())
}

fn require(condition: bool, detail: &str) -> io::Result<()> {
    if condition {
        Ok(())
    } else {
        Err(invalid(detail))
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ServiceProfile {
    version: String,
    state_root: PathBuf,
    socket: PathBuf,
    max_roots: usize,
    /// Waiting clients retain only their bounded request and connection. They
    /// cannot capture inputs or start Cargo until an operation slot is free.
    #[serde(default)]
    max_queued_roots: usize,
    jobs_per_root: u32,
}

impl ServiceProfile {
    fn validate(&self) -> io::Result<()> {
        require(
            self.version == SERVICE_VERSION,
            "unsupported canonical service profile version",
        )?;
        require(
            (1..=32).contains(&self.max_roots),
            "canonical service max_roots must be between 1 and 32",
        )?;
        require(
            self.max_queued_roots <= 128,
            "canonical service max_queued_roots must be between 0 and 128",
        )?;
        require(
            (1..=4096).contains(&self.jobs_per_root),
            "canonical service jobs_per_root must be between 1 and 4096",
        )?;
        require(
            self.max_roots
                .checked_mul(self.jobs_per_root as usize)
                .is_some_and(|slots| slots <= 4096),
            "canonical service aggregate compiler capacity exceeds 4096",
        )?;
        private_directory(&self.state_root)?;
        validate_socket_path(&self.socket)?;
        Ok(())
    }

    fn max_sessions(&self) -> usize {
        self.max_roots + self.max_queued_roots
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BuildRequest {
    version: String,
    build_identity: String,
    require_release: bool,
    profile: Value,
}

fn require_policy(
    request: &BuildRequest,
    release_mode: ReleaseAuthorizationMode,
    build_identity: &str,
) -> io::Result<()> {
    require(
        request.version == REQUEST_VERSION,
        "unsupported canonical service request version",
    )?;
    require(
        request.build_identity == build_identity,
        "canonical client and service build identities differ",
    )?;
    require(
        !request.require_release || release_mode == ReleaseAuthorizationMode::Required,
        "canonical service cannot downgrade the client's required release authorization",
    )
}

fn validate_socket_path(path: &Path) -> io::Result<()> {
    require(
        plain_absolute(path) && path.as_os_str().as_encoded_bytes().len() < 108,
        "canonical service endpoint must be a bounded ordinary absolute Unix socket path",
    )?;
    let parent = path
        .parent()
        .ok_or_else(|| invalid("canonical service endpoint has no parent"))?;
    ordinary_directory(parent)?;
    private_directory(parent)
}

fn socket_identity(path: &Path) -> io::Result<(u64, u64, i64, i64)> {
    validate_socket_path(path)?;
    let metadata = fs::symlink_metadata(path)?;
    require(
        metadata.file_type().is_socket()
            && metadata.uid() == rustix::process::geteuid().as_raw()
            && metadata.mode() & 0o777 == 0o600
            && metadata.nlink() == 1,
        "canonical service endpoint must be an owned private ordinary socket",
    )?;
    Ok((
        metadata.dev(),
        metadata.ino(),
        metadata.ctime(),
        metadata.ctime_nsec(),
    ))
}

fn validate_profile_route(profile: &Profile, socket: &Path) -> io::Result<()> {
    require(
        profile.service_socket.as_deref() == Some(socket),
        "canonical request names a different service endpoint",
    )?;
    validate_socket_path(socket)?;
    for root in [
        &profile.source_root,
        &profile.toolchain_root,
        &profile.operation_root,
    ]
    .into_iter()
    .chain(profile.cargo_home_source.as_ref())
    {
        require(
            !overlap(root, socket),
            "canonical service endpoint overlaps a captured input or operation root",
        )?;
    }
    require(
        !profile.inherits_stdin(),
        "shared canonical service does not forward inherited stdin; use a standalone profile for run or executing bench",
    )
}

struct ListenerOwner {
    listener: Option<UnixListener>,
    lease: EndpointLease,
}

impl ListenerOwner {
    fn reserve(path: &Path) -> io::Result<EndpointLease> {
        validate_socket_path(path)?;
        let lease = EndpointLease::acquire(path)?;
        if let Some(observed) = lease.observe()? {
            match wire::connect(
                lease.path(),
                Instant::now() + HANDSHAKE_BUDGET,
                &AtomicBool::new(false),
            ) {
                Ok(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::AddrInUse,
                        "canonical service endpoint is already live",
                    ));
                }
                Err(error) => lease.retire_refused(observed, &error)?,
            }
        }
        lease.verify()?;
        Ok(lease)
    }

    fn bind_reserved(mut lease: EndpointLease) -> io::Result<Self> {
        lease.verify()?;
        let listener = UnixListener::bind(lease.path())?;
        lease.claim_bound()?;
        listener.set_nonblocking(true)?;
        Ok(Self {
            listener: Some(listener),
            lease,
        })
    }

    #[cfg(test)]
    fn bind(path: &Path) -> io::Result<Self> {
        Self::bind_reserved(Self::reserve(path)?)
    }
}

impl Drop for ListenerOwner {
    fn drop(&mut self) {
        self.listener.take();
        if let Err(error) = self.lease.retire_bound() {
            let _ = writeln!(
                io::stderr().lock(),
                "{}",
                json!({"kind":"canonical-service-endpoint-retirement-refused","reason":error.to_string()})
            );
        }
    }
}

/// Admission of complete operations, before source capture. This bounds the
/// work that can reach the existing Cargo root-permit broker; it never grants
/// compiler tokens or replaces the coordinator's action/worker scheduling.
struct OperationAdmissions {
    maximum: usize,
    capacity: usize,
    state: Mutex<AdmissionState>,
}

#[derive(Default)]
struct AdmissionState {
    next_ticket: u64,
    waiting: VecDeque<u64>,
    active: usize,
}

impl OperationAdmissions {
    fn new(maximum: usize, queued: usize) -> Arc<Self> {
        Arc::new(Self {
            maximum,
            capacity: maximum + queued,
            state: Mutex::new(AdmissionState::default()),
        })
    }

    fn enqueue(self: &Arc<Self>) -> io::Result<WaitingOperation> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| io::Error::other("canonical operation admission lock poisoned"))?;
        if state.active + state.waiting.len() >= self.capacity {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "canonical service is busy; no build was admitted",
            ));
        }
        state.next_ticket = state
            .next_ticket
            .checked_add(1)
            .ok_or_else(|| io::Error::other("canonical operation admission sequence exhausted"))?;
        let ticket = state.next_ticket;
        state.waiting.push_back(ticket);
        Ok(WaitingOperation {
            admissions: Arc::clone(self),
            ticket,
            queued: true,
        })
    }

    fn acquire(
        self: &Arc<Self>,
        stream: &mut UnixStream,
        runtime: &SharedRuntime,
        stopped: &AtomicBool,
        budget: Duration,
    ) -> io::Result<AdmittedOperation> {
        self.acquire_while(stream, stopped, budget, || runtime.healthy())
    }

    fn acquire_while(
        self: &Arc<Self>,
        stream: &mut UnixStream,
        stopped: &AtomicBool,
        budget: Duration,
        healthy: impl Fn() -> bool,
    ) -> io::Result<AdmittedOperation> {
        let deadline = Instant::now()
            .checked_add(budget)
            .ok_or_else(|| invalid("canonical operation admission deadline overflow"))?;
        let mut waiting = self.enqueue()?;
        let mut reported = false;
        loop {
            if stopped.load(Ordering::Acquire) || !healthy() {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "canonical operation cancelled while awaiting admission",
                ));
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "canonical operation admission timed out",
                ));
            }
            wire::check_client(stream)?;
            if let Some(admitted) = waiting.try_start()? {
                return Ok(admitted);
            }
            if !reported {
                let _ = writeln!(
                    io::stderr().lock(),
                    "{}",
                    json!({"kind":"canonical-service-queued", "ticket":waiting.ticket})
                );
                reported = true;
            }
            // No capture, Cargo process or root token exists while waiting.
            // The same bounded poll as live delivery observes client loss and
            // shutdown, including when an earlier ticket was cancelled.
            std::thread::sleep(wire::POLL.min(remaining));
        }
    }
}

struct WaitingOperation {
    admissions: Arc<OperationAdmissions>,
    ticket: u64,
    queued: bool,
}

impl WaitingOperation {
    fn try_start(&mut self) -> io::Result<Option<AdmittedOperation>> {
        let mut state = self
            .admissions
            .state
            .lock()
            .map_err(|_| io::Error::other("canonical operation admission lock poisoned"))?;
        if !self.queued
            || state.active >= self.admissions.maximum
            || state.waiting.front() != Some(&self.ticket)
        {
            return Ok(None);
        }
        state.waiting.pop_front();
        state.active += 1;
        self.queued = false;
        Ok(Some(AdmittedOperation(Arc::clone(&self.admissions))))
    }
}

impl Drop for WaitingOperation {
    fn drop(&mut self) {
        if self.queued {
            self.admissions
                .state
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .waiting
                .retain(|ticket| *ticket != self.ticket);
        }
    }
}

struct AdmittedOperation(Arc<OperationAdmissions>);

impl Drop for AdmittedOperation {
    fn drop(&mut self) {
        self.0
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .active -= 1;
    }
}

struct OperationOwner {
    stopped: Arc<AtomicBool>,
    thread: Option<JoinHandle<io::Result<i32>>>,
}

impl OperationOwner {
    fn finished(&self) -> bool {
        self.thread.as_ref().is_none_or(JoinHandle::is_finished)
    }

    fn join(&mut self) -> io::Result<i32> {
        self.thread
            .take()
            .ok_or_else(|| io::Error::other("canonical operation already joined"))?
            .join()
            .unwrap_or_else(|_| Err(io::Error::other("canonical operation panicked")))
    }
}

impl Drop for OperationOwner {
    fn drop(&mut self) {
        if self.thread.is_some() {
            self.stopped.store(true, Ordering::Release);
            let _ = self.join();
        }
    }
}

struct Session {
    stopped: Arc<AtomicBool>,
    thread: Option<JoinHandle<io::Result<()>>>,
}

impl Session {
    fn join(&mut self) {
        if let Some(thread) = self.thread.take() {
            let outcome = thread
                .join()
                .unwrap_or_else(|_| Err(io::Error::other("canonical service session panicked")));
            if let Err(error) = outcome {
                let _ = writeln!(
                    io::stderr().lock(),
                    "{}",
                    json!({"kind":"canonical-service-session-error","reason":error.to_string()})
                );
            }
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        if self.thread.is_some() {
            self.stopped.store(true, Ordering::Release);
            self.join();
        }
    }
}

#[derive(Default)]
struct Sessions(Vec<Session>);

impl Sessions {
    fn reap(&mut self) {
        let mut index = 0;
        while index < self.0.len() {
            if self.0[index]
                .thread
                .as_ref()
                .is_none_or(JoinHandle::is_finished)
            {
                self.0.swap_remove(index).join();
            } else {
                index += 1;
            }
        }
    }

    fn stop_and_join(&mut self) {
        for session in &self.0 {
            session.stopped.store(true, Ordering::Release);
        }
        for session in &mut self.0 {
            session.join();
        }
        self.0.clear();
    }
}

impl Drop for Sessions {
    fn drop(&mut self) {
        self.stop_and_join();
    }
}

fn failed(stream: &mut UnixStream, detail: &str) {
    let mut end = detail.len().min(MAX_FAILURE_BYTES);
    while !detail.is_char_boundary(end) {
        end -= 1;
    }
    let detail = if end == 0 {
        "canonical service request failed"
    } else {
        &detail[..end]
    };
    let _ = wire::send(
        stream,
        Kind::Failed,
        detail.as_bytes(),
        Instant::now() + Duration::from_secs(1),
        &AtomicBool::new(false),
    );
}

fn output_file(parent: &Path, name: &str) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(parent.join(name))
}

fn send_response(
    stream: &mut UnixStream,
    state: &mut ResponseState,
    kind: Kind,
    bytes: &[u8],
    deadline: Instant,
    stopped: &AtomicBool,
) -> io::Result<()> {
    let header = Header::new(kind, bytes.len()).map_err(io::Error::other)?;
    state.observe(header, bytes).map_err(io::Error::other)?;
    if let Err(error) = wire::send(stream, kind, bytes, deadline, stopped) {
        // A prefix of this frame may already be visible. The outer failure
        // reporter must not append a new header inside its truncated payload.
        let _ = stream.shutdown(std::net::Shutdown::Write);
        return Err(error);
    }
    Ok(())
}

/// Independent cursors over the writer's retained file descriptions. A cloned
/// File shares its seek offset, so ordinary read/seek could rewind the live
/// writer and corrupt output. Positional reads never move that shared offset.
struct ServiceOutput {
    stdout: File,
    stderr: File,
    sent: [u64; 2],
    state: ResponseState,
    buffer: Vec<u8>,
}

impl ServiceOutput {
    fn accepted(stdout: File, stderr: File) -> io::Result<Self> {
        let mut state = ResponseState::default();
        state
            .observe(
                Header::new(Kind::Accepted, 0).map_err(io::Error::other)?,
                &[],
            )
            .map_err(io::Error::other)?;
        Ok(Self {
            stdout,
            stderr,
            sent: [0; 2],
            state,
            buffer: vec![0; MAX_CHUNK_BYTES],
        })
    }

    /// At most one chunk from each stream per turn: continuous stdout cannot
    /// starve stderr, disconnect detection or cancellation. Per-stream order
    /// is exact; no cross-stream chronology is fabricated.
    fn send_available(
        &mut self,
        stream: &mut UnixStream,
        deadline: Instant,
        stopped: &AtomicBool,
    ) -> io::Result<bool> {
        let mut progress = false;
        for ((kind, source), offset) in [(Kind::Stdout, &self.stdout), (Kind::Stderr, &self.stderr)]
            .into_iter()
            .zip(self.sent.iter_mut())
        {
            if source.metadata()?.len() < *offset {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "canonical operation output was truncated during delivery",
                ));
            }
            let count = loop {
                match source.read_at(&mut self.buffer, *offset) {
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    result => break result?,
                }
            };
            if count == 0 {
                continue;
            }
            send_response(
                stream,
                &mut self.state,
                kind,
                &self.buffer[..count],
                deadline,
                stopped,
            )?;
            *offset = offset
                .checked_add(count as u64)
                .ok_or_else(|| io::Error::other("canonical output cursor overflow"))?;
            progress = true;
        }
        Ok(progress)
    }
}

fn relay_operation(
    stream: &mut UnixStream,
    mut operation: OperationOwner,
    mut output: ServiceOutput,
    healthy: impl Fn() -> bool,
) -> io::Result<()> {
    while !operation.finished() {
        if operation.stopped.load(Ordering::Acquire) || !healthy() {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "canonical operation cancelled during service shutdown",
            ));
        }
        wire::check_client(stream)?;
        let progress =
            output.send_available(stream, Instant::now() + DELIVERY_BUDGET, &operation.stopped)?;
        if !progress {
            std::thread::sleep(wire::POLL);
        }
    }
    // Join all writers before sending the last tail or a terminal result. The
    // same cursors continue; bytes already streamed are never replayed here.
    let outcome = operation.join();
    wire::check_client(stream)?;
    let deadline = Instant::now() + DELIVERY_BUDGET;
    while output.send_available(stream, deadline, &operation.stopped)? {}
    match outcome {
        Ok(code) => send_response(
            stream,
            &mut output.state,
            Kind::Completed,
            &code.to_be_bytes(),
            deadline,
            &operation.stopped,
        ),
        Err(error) => Err(error),
    }
}

fn handle_session(
    stream: &mut UnixStream,
    runtime: Arc<SharedRuntime>,
    config: &ServiceProfile,
    admissions: &Arc<OperationAdmissions>,
    release_mode: ReleaseAuthorizationMode,
    build_identity: &str,
    stopped: Arc<AtomicBool>,
) -> io::Result<()> {
    wire::require_owner(stream)?;
    let (header, bytes) = wire::receive(stream, Instant::now() + HANDSHAKE_BUDGET, &stopped)?;
    require(
        header.kind() == Kind::Profile,
        "canonical service expects exactly one profile request",
    )?;
    let request: BuildRequest =
        serde_json::from_slice(&bytes).map_err(|error| invalid(error.to_string()))?;
    require_policy(&request, release_mode, build_identity)?;
    let profile: Profile = serde_json::from_value(request.profile.clone())
        .map_err(|error| invalid(error.to_string()))?;
    validate_profile_route(&profile, &config.socket)?;
    require(
        profile.state_root == config.state_root,
        "canonical profile must use this service's state_root",
    )?;
    require(
        profile.jobs <= config.jobs_per_root,
        "canonical profile jobs exceeds the service per-root grant",
    )?;
    profile.validate()?;
    require(
        runtime.healthy(),
        "canonical service coordinator is unavailable",
    )?;
    let profile_bytes = serde_json::to_vec(&request.profile)?;
    require(
        profile_bytes.len() <= MAX_PROFILE_BYTES,
        "canonical profile exceeds the native byte bound",
    )?;
    let _admission = admissions.acquire(
        stream,
        &runtime,
        &stopped,
        Duration::from_secs(profile.timeout_seconds),
    )?;
    let owner = tempfile::Builder::new()
        .prefix("canonical-service-output-")
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir_in(&config.state_root)?;
    let stdout = output_file(owner.path(), "stdout")?;
    let stderr = output_file(owner.path(), "stderr")?;
    let child_stdout = stdout.try_clone()?;
    let child_stderr = stderr.try_clone()?;
    wire::send(
        stream,
        Kind::Accepted,
        &[],
        Instant::now() + HANDSHAKE_BUDGET,
        &stopped,
    )?;
    let child_stop = Arc::clone(&stopped);
    let child_runtime = Arc::clone(&runtime);
    let thread = std::thread::Builder::new()
        .name("rabs-canonical-build".into())
        .spawn(move || {
            super::run_shared_profile(
                &profile_bytes,
                child_runtime,
                child_stop,
                child_stdout,
                child_stderr,
                CARGO_OUTPUT_BYTES,
            )
        })?;
    let operation = OperationOwner {
        stopped: Arc::clone(&stopped),
        thread: Some(thread),
    };
    relay_operation(
        stream,
        operation,
        ServiceOutput::accepted(stdout, stderr)?,
        || runtime.healthy(),
    )
}

/// Run until SIGINT/SIGTERM, retaining one authority through all build drains.
pub fn run_service_profile(
    path: &Path,
    release_mode: ReleaseAuthorizationMode,
    build_identity: String,
) -> io::Result<()> {
    let (_, bytes) = read_stable(path, MAX_PROFILE_BYTES as u64)?;
    let config: ServiceProfile =
        serde_json::from_slice(&bytes).map_err(|error| invalid(error.to_string()))?;
    config.validate()?;
    let config = Arc::new(config);
    // Hold endpoint ownership before mounting an authority that would otherwise
    // have to shut down if another service already owned this endpoint.
    let lease = ListenerOwner::reserve(&config.socket)?;
    let runtime = SharedRuntime::start(
        &config.state_root,
        release_mode,
        build_identity.clone(),
        config.max_roots,
        config.jobs_per_root,
    )?;
    // Publish readiness only after the coordinator is healthy. Clients may
    // connect as soon as the socket appears, including during a cold startup.
    let mut listener = ListenerOwner::bind_reserved(lease)?;
    let shutdown = Arc::new(ShutdownController::new());
    shutdown.listen_for_signals();
    let mut sessions = Sessions::default();
    let admissions = OperationAdmissions::new(config.max_roots, config.max_queued_roots);
    let mut sequence = 0_u64;
    let _ = writeln!(
        io::stderr().lock(),
        "{}",
        json!({
            "kind":"canonical-service-listening", "version":SERVICE_VERSION,
            "socket":config.socket, "max_roots":config.max_roots,
            "max_queued_roots":config.max_queued_roots,
            "jobs_per_root":config.jobs_per_root, "build_identity":build_identity,
            "required_release":release_mode == ReleaseAuthorizationMode::Required,
            "workspace_cache":false
        })
    );
    let result = loop {
        sessions.reap();
        if shutdown.is_shutting_down() {
            break Ok(());
        }
        if !runtime.healthy() {
            break Err(io::Error::other("canonical service coordinator stopped"));
        }
        listener.lease.verify()?;
        match listener
            .listener
            .as_ref()
            .expect("service acceptor is open")
            .accept()
        {
            Ok((mut stream, _)) => {
                wire::configure(&stream)?;
                if let Err(error) = wire::require_owner(&stream) {
                    failed(&mut stream, &error.to_string());
                    continue;
                }
                if sessions.0.len() >= config.max_sessions() {
                    failed(
                        &mut stream,
                        "canonical service is busy; no build was admitted",
                    );
                    continue;
                }
                sequence = sequence.checked_add(1).ok_or_else(|| {
                    io::Error::other("canonical service operation sequence exhausted")
                })?;
                let stopped = Arc::new(AtomicBool::new(false));
                let child_stop = Arc::clone(&stopped);
                let child_runtime = Arc::clone(&runtime);
                let child_admissions = Arc::clone(&admissions);
                let child_config = Arc::clone(&config);
                let identity = build_identity.clone();
                let thread = std::thread::Builder::new()
                    .name(format!("rabs-canonical-session-{sequence}"))
                    .spawn(move || {
                        let result = handle_session(
                            &mut stream,
                            child_runtime,
                            &child_config,
                            &child_admissions,
                            release_mode,
                            &identity,
                            child_stop,
                        );
                        if let Err(error) = &result {
                            failed(&mut stream, &error.to_string());
                        }
                        result
                    })?;
                sessions.0.push(Session {
                    stopped,
                    thread: Some(thread),
                });
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(wire::POLL)
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => break Err(error),
        }
    };
    // New connections stop first; endpoint ownership survives every joined
    // writer, and coordinator authority survives every compiler/session drain.
    listener.listener.take();
    sessions.stop_and_join();
    let drained = runtime.shutdown();
    result.and(drained)
}

/// Attach one existing profile to its explicitly selected running service.
/// Failure is terminal: this path never starts a daemon or falls back locally.
pub fn run_client_profile(
    path: &Path,
    release_mode: ReleaseAuthorizationMode,
    build_identity: String,
) -> io::Result<i32> {
    let (_, bytes) = read_stable(path, MAX_PROFILE_BYTES as u64)?;
    let profile: Profile =
        serde_json::from_slice(&bytes).map_err(|error| invalid(error.to_string()))?;
    let socket = profile
        .service_socket
        .as_deref()
        .ok_or_else(|| invalid("canonical service_socket is required"))?;
    validate_profile_route(&profile, socket)?;
    require(
        (1..=7200).contains(&profile.timeout_seconds),
        "canonical timeout_seconds must be between 1 and 7200",
    )?;
    let endpoint_error = |error: io::Error| {
        io::Error::new(
            error.kind(),
            format!("canonical service endpoint {}: {error}", socket.display()),
        )
    };
    let identity = socket_identity(socket).map_err(endpoint_error)?;
    let stopped = AtomicBool::new(false);
    let mut stream = wire::connect(socket, Instant::now() + HANDSHAKE_BUDGET, &stopped)
        .map_err(endpoint_error)?;
    require(
        socket_identity(socket).map_err(endpoint_error)? == identity,
        "canonical service endpoint changed while connecting",
    )?;
    let request = json!({
        "version":REQUEST_VERSION, "build_identity":build_identity,
        "require_release":release_mode == ReleaseAuthorizationMode::Required,
        "profile":serde_json::from_slice::<Value>(&bytes)?
    });
    let mut early_refusal = wire::submit(
        &mut stream,
        &serde_json::to_vec(&request)?,
        Instant::now() + HANDSHAKE_BUDGET,
        &stopped,
    )?;
    // Admission can wait for one operation budget before capture starts.
    // Planning can then run two bounded Cargo queries before compilation.
    // Capture and publication drain have an additional finite client allowance.
    let budget = Duration::from_secs(
        profile
            .timeout_seconds
            .saturating_mul(4)
            .saturating_add(600),
    );
    let deadline = Instant::now()
        .checked_add(budget)
        .ok_or_else(|| invalid("canonical service deadline overflow"))?;
    let mut state = ResponseState::default();
    let mut result = None;
    while !state.is_finished() {
        let (header, payload) = match early_refusal.take() {
            Some(frame) => frame,
            None => wire::receive(&mut stream, deadline, &stopped)?,
        };
        state.observe(header, &payload).map_err(io::Error::other)?;
        match header.kind() {
            Kind::Accepted => {}
            Kind::Stdout => {
                let mut output = io::stdout().lock();
                output.write_all(&payload)?;
                output.flush()?;
            }
            Kind::Stderr => {
                let mut output = io::stderr().lock();
                output.write_all(&payload)?;
                output.flush()?;
            }
            Kind::Completed => {
                let bytes: [u8; 4] = payload
                    .as_slice()
                    .try_into()
                    .map_err(|_| invalid("invalid native exit code"))?;
                result = Some(Ok(i32::from_be_bytes(bytes)));
            }
            Kind::Failed => {
                result = Some(Err(io::Error::other(
                    String::from_utf8(payload).map_err(io::Error::other)?,
                )))
            }
            Kind::Profile => return Err(invalid("service sent a client profile")),
        }
    }
    if let Err(error) = wire::expect_eof(&mut stream, Instant::now() + HANDSHAKE_BUDGET, &stopped) {
        // Closing an unread request after an early refusal can reset AF_UNIX.
        // Keep that failure's reason; a successful result still requires EOF.
        return Err(match result {
            Some(Err(reason)) => io::Error::other(format!("{reason}; terminal delivery: {error}")),
            _ => error,
        });
    }
    state.finish().map_err(io::Error::other)?;
    result.ok_or_else(|| io::Error::other("canonical service omitted its terminal result"))?
}

#[cfg(test)]
mod tests {
    use super::*;

    struct LiveFixture {
        operation: OperationOwner,
        output: ServiceOutput,
        release: std::sync::mpsc::Sender<()>,
        stopped: Arc<AtomicBool>,
        finished: Arc<AtomicBool>,
    }

    fn live_fixture(root: &Path, bytes: Vec<u8>) -> LiveFixture {
        let stdout = output_file(root, "stdout").unwrap();
        let stderr = output_file(root, "stderr").unwrap();
        let mut child_stdout = stdout.try_clone().unwrap();
        let mut child_stderr = stderr.try_clone().unwrap();
        let (release, released) = std::sync::mpsc::channel();
        let (ready, prepared) = std::sync::mpsc::channel();
        let stopped = Arc::new(AtomicBool::new(false));
        let child_stop = Arc::clone(&stopped);
        let finished = Arc::new(AtomicBool::new(false));
        let child_finished = Arc::clone(&finished);
        let thread = std::thread::spawn(move || {
            let result = (|| {
                child_stdout.write_all(&bytes)?;
                child_stderr.write_all(b"warning\0\xff")?;
                ready.send(()).map_err(io::Error::other)?;
                let deadline = Instant::now() + Duration::from_secs(10);
                loop {
                    if child_stop.load(Ordering::Acquire) {
                        return Err(io::Error::new(
                            io::ErrorKind::Interrupted,
                            "fixture cancelled",
                        ));
                    }
                    if Instant::now() >= deadline {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "fixture not released",
                        ));
                    }
                    match released.recv_timeout(Duration::from_millis(5)) {
                        Ok(()) => break,
                        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                        Err(error) => return Err(io::Error::other(error)),
                    }
                }
                child_stdout.write_all(b"tail")?;
                child_stderr.write_all(b"end")?;
                Ok(7)
            })();
            child_finished.store(true, Ordering::Release);
            result
        });
        prepared.recv_timeout(Duration::from_secs(5)).unwrap();
        LiveFixture {
            operation: OperationOwner {
                stopped: Arc::clone(&stopped),
                thread: Some(thread),
            },
            output: ServiceOutput::accepted(stdout, stderr).unwrap(),
            release,
            stopped,
            finished,
        }
    }

    #[test]
    fn service_streams_before_completion_without_rewinding_writers_or_replaying_prefixes() {
        let root = crate::test_util::private_tempdir();
        let prefix: Vec<_> = (0..MAX_CHUNK_BYTES * 2 + 13)
            .map(|index| (index % 251) as u8)
            .collect();
        let LiveFixture {
            operation,
            output,
            release,
            stopped: _,
            finished,
        } = live_fixture(root.path(), prefix.clone());
        let (mut client, mut server) = UnixStream::pair().unwrap();
        wire::configure(&client).unwrap();
        wire::configure(&server).unwrap();
        let relay = std::thread::spawn(move || {
            wire::send(
                &mut server,
                Kind::Accepted,
                &[],
                Instant::now() + Duration::from_secs(5),
                &AtomicBool::new(false),
            )?;
            relay_operation(&mut server, operation, output, || true)
        });
        let deadline = Instant::now() + Duration::from_secs(10);
        let stopped = AtomicBool::new(false);
        let mut state = ResponseState::default();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut early_kinds = Vec::new();
        while stdout.len() < prefix.len() || stderr.len() < b"warning\0\xff".len() {
            let (header, bytes) = wire::receive(&mut client, deadline, &stopped).unwrap();
            state.observe(header, &bytes).unwrap();
            match header.kind() {
                Kind::Accepted => {}
                Kind::Stdout => stdout.extend(bytes),
                Kind::Stderr => stderr.extend(bytes),
                _ => panic!("terminal result arrived before the operation was released"),
            }
            early_kinds.push(header.kind());
        }
        assert_eq!(stdout, prefix);
        assert_eq!(stderr, b"warning\0\xff");
        assert!(!finished.load(Ordering::Acquire));
        assert!(!relay.is_finished());
        assert!(
            early_kinds
                .iter()
                .position(|kind| *kind == Kind::Stderr)
                .unwrap()
                <= 2,
            "large stdout starved the already available stderr prefix"
        );
        release.send(()).unwrap();
        while !state.is_finished() {
            let (header, bytes) = wire::receive(&mut client, deadline, &stopped).unwrap();
            state.observe(header, &bytes).unwrap();
            match header.kind() {
                Kind::Stdout => stdout.extend(bytes),
                Kind::Stderr => stderr.extend(bytes),
                Kind::Completed => assert_eq!(bytes, 7_i32.to_be_bytes()),
                _ => panic!("unexpected completion frame"),
            }
        }
        wire::expect_eof(&mut client, deadline, &stopped).unwrap();
        state.finish().unwrap();
        relay.join().unwrap().unwrap();
        assert!(finished.load(Ordering::Acquire));
        let mut expected = prefix;
        expected.extend_from_slice(b"tail");
        assert_eq!(stdout, expected);
        assert_eq!(stderr, b"warning\0\xffend");
        assert_eq!(fs::read(root.path().join("stdout")).unwrap(), stdout);
        assert_eq!(fs::read(root.path().join("stderr")).unwrap(), stderr);
    }

    #[test]
    fn disconnected_streaming_client_cancels_and_joins_its_operation() {
        let root = crate::test_util::private_tempdir();
        let LiveFixture {
            operation,
            output,
            release: _release,
            stopped,
            finished,
        } = live_fixture(root.path(), b"already visible".to_vec());
        let (mut client, mut server) = UnixStream::pair().unwrap();
        wire::configure(&client).unwrap();
        wire::configure(&server).unwrap();
        let relay =
            std::thread::spawn(move || relay_operation(&mut server, operation, output, || true));
        let (header, bytes) = wire::receive(
            &mut client,
            Instant::now() + Duration::from_secs(5),
            &AtomicBool::new(false),
        )
        .unwrap();
        assert_eq!(header.kind(), Kind::Stdout);
        assert_eq!(bytes, b"already visible");
        drop(client);
        assert!(relay.join().unwrap().is_err());
        assert!(stopped.load(Ordering::Acquire));
        assert!(
            finished.load(Ordering::Acquire),
            "the file writer was detached"
        );
        assert_eq!(
            fs::read(root.path().join("stdout")).unwrap(),
            b"already visible"
        );
    }

    #[test]
    fn cancellation_interrupts_output_backpressure_without_sending_a_success() {
        let root = crate::test_util::private_tempdir();
        let LiveFixture {
            operation,
            output,
            release: _release,
            stopped,
            finished,
        } = live_fixture(root.path(), vec![0x7f; 8 * 1024 * 1024]);
        let (mut client, mut server) = UnixStream::pair().unwrap();
        wire::configure(&client).unwrap();
        wire::configure(&server).unwrap();
        let relay = std::thread::spawn(move || {
            let result = relay_operation(&mut server, operation, output, || true);
            if let Err(error) = &result {
                failed(&mut server, &error.to_string());
            }
            result
        });
        let deadline = Instant::now() + Duration::from_secs(5);
        assert_eq!(
            wire::receive(&mut client, deadline, &AtomicBool::new(false))
                .unwrap()
                .0
                .kind(),
            Kind::Stdout
        );
        // Leave this reader open but do not consume the remaining multi-MiB
        // output. Socket backpressure must not hold the operation alive.
        std::thread::sleep(Duration::from_millis(200));
        let cancelled = Instant::now();
        stopped.store(true, Ordering::Release);
        assert_eq!(
            relay.join().unwrap().unwrap_err().kind(),
            io::ErrorKind::Interrupted
        );
        assert!(cancelled.elapsed() < Duration::from_secs(5));
        assert!(finished.load(Ordering::Acquire));
        let deadline = Instant::now() + Duration::from_secs(5);
        while let Ok((header, _)) = wire::receive(&mut client, deadline, &AtomicBool::new(false)) {
            assert_ne!(header.kind(), Kind::Completed);
        }
    }

    #[test]
    fn client_release_requirement_and_build_identity_cannot_be_downgraded() {
        let mut request = BuildRequest {
            version: REQUEST_VERSION.into(),
            build_identity: "driver-a".into(),
            require_release: true,
            profile: json!({}),
        };
        assert!(require_policy(&request, ReleaseAuthorizationMode::Required, "driver-a").is_ok());
        assert!(require_policy(&request, ReleaseAuthorizationMode::Advisory, "driver-a").is_err());
        assert!(require_policy(&request, ReleaseAuthorizationMode::Required, "driver-b").is_err());
        request.require_release = false;
        assert!(require_policy(&request, ReleaseAuthorizationMode::Required, "driver-a").is_ok());
        assert!(require_policy(&request, ReleaseAuthorizationMode::Advisory, "driver-a").is_ok());
        request.version = "unknown".into();
        assert!(require_policy(&request, ReleaseAuthorizationMode::Required, "driver-a").is_err());
    }

    #[test]
    fn endpoint_lease_rejects_second_owner_and_preserves_replacement() {
        let root = crate::test_util::private_tempdir();
        let path = root.path().join("service.sock");
        let first = ListenerOwner::bind(&path).unwrap();
        assert!(ListenerOwner::bind(&path).is_err());
        let old = root.path().join("old.sock");
        fs::rename(&path, &old).unwrap();
        let replacement = UnixListener::bind(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        drop(first);
        assert!(
            path.exists(),
            "a replaced endpoint must survive another owner's drop"
        );
        assert!(UnixStream::connect(&path).is_ok());
        drop(replacement);
    }

    #[test]
    fn independent_operation_owners_cancel_and_join_only_their_own_thread() {
        let start = |code| {
            let stopped = Arc::new(AtomicBool::new(false));
            let observed = Arc::clone(&stopped);
            let thread = std::thread::spawn(move || {
                while !observed.load(Ordering::Acquire) {
                    std::thread::sleep(Duration::from_millis(1));
                }
                Ok(code)
            });
            OperationOwner {
                stopped,
                thread: Some(thread),
            }
        };
        let first = start(11);
        let mut second = start(22);
        drop(first);
        assert!(!second.stopped.load(Ordering::Acquire));
        assert!(!second.finished());
        second.stopped.store(true, Ordering::Release);
        assert_eq!(second.join().unwrap(), 22);
    }

    #[test]
    fn service_config_requires_bounded_capacity_and_exact_fields() {
        let root = crate::test_util::private_tempdir();
        let base = json!({"version":SERVICE_VERSION,"state_root":root.path(),"socket":root.path().join("service.sock"),"max_roots":2,"jobs_per_root":4});
        let profile: ServiceProfile = serde_json::from_value(base.clone()).unwrap();
        profile.validate().unwrap();
        assert_eq!(profile.max_queued_roots, 0);
        assert_eq!(profile.max_sessions(), 2);
        let mut queued = base.clone();
        queued["max_queued_roots"] = json!(128);
        let queued: ServiceProfile = serde_json::from_value(queued).unwrap();
        queued.validate().unwrap();
        assert_eq!(queued.max_sessions(), 130);
        for (field, value) in [
            ("max_roots", 0),
            ("max_roots", 33),
            ("jobs_per_root", 0),
            ("jobs_per_root", 4097),
            ("max_queued_roots", 129),
        ] {
            let mut invalid = base.clone();
            invalid[field] = json!(value);
            assert!(
                serde_json::from_value::<ServiceProfile>(invalid)
                    .unwrap()
                    .validate()
                    .is_err()
            );
        }
        let mut over = base.clone();
        over["max_roots"] = json!(32);
        over["jobs_per_root"] = json!(4096);
        assert!(
            serde_json::from_value::<ServiceProfile>(over)
                .unwrap()
                .validate()
                .is_err()
        );
        let mut unknown = base;
        unknown["worker"] = json!("untrusted-hint");
        assert!(serde_json::from_value::<ServiceProfile>(unknown).is_err());
    }

    #[test]
    fn operation_admission_is_bounded_fifo_and_cannot_be_barged() {
        let admissions = OperationAdmissions::new(1, 2);
        let mut first = admissions.enqueue().unwrap();
        let active = first.try_start().unwrap().unwrap();
        let mut second = admissions.enqueue().unwrap();
        let mut third = admissions.enqueue().unwrap();
        assert!(second.try_start().unwrap().is_none());
        assert!(third.try_start().unwrap().is_none());
        assert!(matches!(
            admissions.enqueue(),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock
        ));
        drop(active);
        assert!(third.try_start().unwrap().is_none());
        let second_active = second.try_start().unwrap().unwrap();
        assert!(second.try_start().unwrap().is_none());
        let mut newcomer = admissions.enqueue().unwrap();
        drop(second_active);
        assert!(newcomer.try_start().unwrap().is_none());
        let third_active = third.try_start().unwrap().unwrap();
        assert!(newcomer.try_start().unwrap().is_none());
        drop(third_active);
        drop(newcomer.try_start().unwrap().unwrap());
        let state = admissions.state.lock().unwrap();
        assert_eq!(state.active, 0);
        assert!(state.waiting.is_empty());
    }

    #[test]
    fn cancelled_queue_head_leaves_no_slot_or_ticket_and_next_caller_can_start() {
        let admissions = OperationAdmissions::new(1, 2);
        let active = admissions.enqueue().unwrap().try_start().unwrap().unwrap();
        let head = admissions.enqueue().unwrap();
        let mut tail = admissions.enqueue().unwrap();
        drop(head);
        assert!(tail.try_start().unwrap().is_none());
        assert_eq!(admissions.state.lock().unwrap().active, 1);
        drop(active);
        drop(tail.try_start().unwrap().unwrap());
        assert!(admissions.state.lock().unwrap().waiting.is_empty());
        assert_eq!(admissions.state.lock().unwrap().active, 0);
    }

    #[test]
    fn queued_client_disconnect_and_extra_input_do_not_start_work_or_block_successors() {
        for extra_input in [false, true] {
            let admissions = OperationAdmissions::new(1, 1);
            let active = admissions.enqueue().unwrap().try_start().unwrap().unwrap();
            let (mut client, mut server) = UnixStream::pair().unwrap();
            wire::configure(&server).unwrap();
            let queued = Arc::clone(&admissions);
            let waiter = std::thread::spawn(move || {
                queued.acquire_while(
                    &mut server,
                    &AtomicBool::new(false),
                    Duration::from_secs(3),
                    || true,
                )
            });
            let deadline = Instant::now() + Duration::from_secs(2);
            while admissions.state.lock().unwrap().waiting.is_empty() {
                assert!(Instant::now() < deadline, "caller never joined queue");
                std::thread::sleep(Duration::from_millis(1));
            }
            if extra_input {
                client.write_all(b"not another request").unwrap();
            } else {
                client.shutdown(std::net::Shutdown::Both).unwrap();
            }
            let error = waiter.join().unwrap().err().expect("queued caller refused");
            assert_eq!(
                error.kind(),
                if extra_input {
                    io::ErrorKind::InvalidInput
                } else {
                    io::ErrorKind::ConnectionAborted
                }
            );
            assert_eq!(admissions.state.lock().unwrap().active, 1);
            assert!(admissions.state.lock().unwrap().waiting.is_empty());
            let mut next = admissions.enqueue().unwrap();
            drop(active);
            drop(next.try_start().unwrap().unwrap());
            assert_eq!(admissions.state.lock().unwrap().active, 0);
        }
    }

    #[test]
    fn admission_timeout_cancellation_and_shutdown_retire_waiting_interest() {
        for (cancelled, healthy, expected) in [
            (false, true, io::ErrorKind::TimedOut),
            (true, true, io::ErrorKind::Interrupted),
            (false, false, io::ErrorKind::Interrupted),
        ] {
            let admissions = OperationAdmissions::new(1, 1);
            let active = admissions.enqueue().unwrap().try_start().unwrap().unwrap();
            let (_client, mut server) = UnixStream::pair().unwrap();
            wire::configure(&server).unwrap();
            let result = admissions.acquire_while(
                &mut server,
                &AtomicBool::new(cancelled),
                Duration::from_millis(15),
                || healthy,
            );
            assert_eq!(result.err().expect("not admitted").kind(), expected);
            assert_eq!(admissions.state.lock().unwrap().active, 1);
            assert!(admissions.state.lock().unwrap().waiting.is_empty());
            let mut successor = admissions.enqueue().unwrap();
            drop(active);
            drop(successor.try_start().unwrap().unwrap());
        }
    }
}
