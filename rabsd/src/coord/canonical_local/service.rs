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
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
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

fn send_output(
    stream: &mut UnixStream,
    source: &mut File,
    kind: Kind,
    state: &mut ResponseState,
    deadline: Instant,
    stopped: &AtomicBool,
) -> io::Result<()> {
    source.seek(SeekFrom::Start(0))?;
    let mut bytes = vec![0; MAX_CHUNK_BYTES];
    loop {
        let count = source.read(&mut bytes)?;
        if count == 0 {
            return Ok(());
        }
        let header = Header::new(kind, count).map_err(io::Error::other)?;
        state
            .observe(header, &bytes[..count])
            .map_err(io::Error::other)?;
        wire::send(stream, kind, &bytes[..count], deadline, stopped)?;
    }
}

fn handle_session(
    stream: &mut UnixStream,
    runtime: Arc<SharedRuntime>,
    config: &ServiceProfile,
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
    let owner = tempfile::Builder::new()
        .prefix("canonical-service-output-")
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir_in(&config.state_root)?;
    let mut stdout = output_file(owner.path(), "stdout")?;
    let mut stderr = output_file(owner.path(), "stderr")?;
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
    let mut operation = OperationOwner {
        stopped: Arc::clone(&stopped),
        thread: Some(thread),
    };
    let mut extra = [0];
    while !operation.finished() {
        if stopped.load(Ordering::Acquire) || !runtime.healthy() {
            stopped.store(true, Ordering::Release);
            let _ = operation.join();
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "canonical operation cancelled during service shutdown",
            ));
        }
        match stream.read(&mut extra) {
            Ok(0) => {
                stopped.store(true, Ordering::Release);
                let _ = operation.join();
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "canonical client disconnected; its operation was drained",
                ));
            }
            Ok(_) => {
                stopped.store(true, Ordering::Release);
                let _ = operation.join();
                return Err(invalid(
                    "canonical client sent another request on an active connection",
                ));
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) => {}
            Err(error) => {
                stopped.store(true, Ordering::Release);
                let _ = operation.join();
                return Err(error);
            }
        }
    }
    let outcome = operation.join();
    let mut response = ResponseState::default();
    response
        .observe(
            Header::new(Kind::Accepted, 0).map_err(io::Error::other)?,
            &[],
        )
        .map_err(io::Error::other)?;
    let deadline = Instant::now() + DELIVERY_BUDGET;
    // The process and scoped edge have drained. Per-stream bytes are exact;
    // no cross-stream chronology is invented by this final replay.
    send_output(
        stream,
        &mut stdout,
        Kind::Stdout,
        &mut response,
        deadline,
        &stopped,
    )?;
    send_output(
        stream,
        &mut stderr,
        Kind::Stderr,
        &mut response,
        deadline,
        &stopped,
    )?;
    match outcome {
        Ok(code) => wire::send(
            stream,
            Kind::Completed,
            &code.to_be_bytes(),
            deadline,
            &stopped,
        ),
        Err(error) => Err(error),
    }
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
    let mut sequence = 0_u64;
    let _ = writeln!(
        io::stderr().lock(),
        "{}",
        json!({
            "kind":"canonical-service-listening", "version":SERVICE_VERSION,
            "socket":config.socket, "max_roots":config.max_roots,
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
                if sessions.0.len() >= config.max_roots {
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
                let child_config = Arc::clone(&config);
                let identity = build_identity.clone();
                let thread = std::thread::Builder::new()
                    .name(format!("rabs-canonical-session-{sequence}"))
                    .spawn(move || {
                        let result = handle_session(
                            &mut stream,
                            child_runtime,
                            &child_config,
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
    // Planning can run up to two bounded Cargo queries before compilation.
    // Capture and publication drain have an additional finite client allowance.
    let budget = Duration::from_secs(
        profile
            .timeout_seconds
            .saturating_mul(3)
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
            Kind::Stdout => io::stdout().lock().write_all(&payload)?,
            Kind::Stderr => io::stderr().lock().write_all(&payload)?,
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
        for (field, value) in [
            ("max_roots", 0),
            ("max_roots", 33),
            ("jobs_per_root", 0),
            ("jobs_per_root", 4097),
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
}
