//! Authenticated cross-host access to one persistent canonical Cargo runtime.
//!
//! Cargo executes at the coordinator. Independent clients share its existing
//! dependency engine, root permits and publication authority, while each owns
//! separate inputs, diagnostics, cancellation and artifact delivery. The local
//! path-based Unix service is deliberately not used as a network protocol.

mod client;
mod wire;

pub use client::run_client_profile;

use super::remote_artifacts::CapturedTarget;
use super::remote_operation::{self, RemoteOperationInputs, RemoteOperationOutcome};
use super::remote_toolchains::{
    ReceivedToolchain, RemoteToolchainCache, ToolchainAcquisition, UploadPoll, UploadPublisher,
};
use super::service::{AdmittedOperation, OperationAdmissions};
use super::target_state::TargetCacheConfig;
use super::{SharedRuntime, ordinary_directory, overlap, plain_absolute, private_directory};
use crate::coord::{source_manifest, worker_delivery};
use crate::edge::live_facts::read_stable;
use asupersync::io::{AsyncRead, AsyncWrite};
use asupersync::net::TcpListener;
use asupersync::runtime::RuntimeBuilder;
use asupersync::signal::ShutdownController;
use rabs_asupersync::daemon_runtime::block_on_top_level;
use rabs_asupersync::worker_transport::{TlsFiles, accept_edge_peer, runtime_transport_now};
use rabs_protocol::raw_bytes::encode_hex;
use rabs_protocol::release_authorization::ReleaseAuthorizationMode;
use rabs_sandbox::source_transfer::{MAX_SOURCE_CHUNK, SourceReceiver};
use rabs_sandbox::toolchain_dataset::{ToolchainIdentity, ToolchainLimits};
use rabs_sandbox::toolchain_transfer::{
    TOOLCHAIN_INPUT_BUDGET, TOOLCHAIN_TRANSFER_VERSION, ToolchainReceiver,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::fs::{self, File, OpenOptions};
use std::io;
use std::net::SocketAddr;
use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use wire::{
    Chunk, Manifest, Message, Output, ToolchainDisposition, WIRE_VERSION, Window, Wire, checkpoint,
    digest, invalid, require,
};

const SERVICE_VERSION: &str = "canonical-compile-remote-service-v1";
const PROFILE_BYTES: u64 = 64 * 1024;
const OUTPUT_BYTES: u64 = 64 * 1024 * 1024;
const OUTPUT_TOTAL_BYTES: u64 = OUTPUT_BYTES + super::MAX_GRAPH_BYTES + 64 * 1024;
const DELIVERY_BUDGET: Duration = Duration::from_secs(10 * 60);
const ACCEPT_POLL: Duration = Duration::from_millis(100);

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TlsProfile {
    ca: PathBuf,
    certificate: PathBuf,
    private_key: PathBuf,
}

impl TlsProfile {
    fn files(&self) -> io::Result<TlsFiles> {
        for path in [&self.ca, &self.certificate, &self.private_key] {
            require(
                plain_absolute(path),
                "TLS files must use ordinary absolute paths",
            )?;
        }
        Ok(TlsFiles {
            ca: self.ca.clone(),
            certificate: self.certificate.clone(),
            private_key: self.private_key.clone(),
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ServiceProfile {
    version: String,
    listen: SocketAddr,
    state_root: PathBuf,
    input_root: PathBuf,
    operation_root: PathBuf,
    wrapper: PathBuf,
    tls: TlsProfile,
    allowed_edge_pins: Vec<String>,
    max_roots: usize,
    /// Waiting authenticated callers retain only their declaration and wire.
    #[serde(default)]
    max_queued_roots: usize,
    #[serde(default = "default_queue_timeout_seconds")]
    queue_timeout_seconds: u64,
    /// Retain only verified SDKs, independently of each operation's source.
    #[serde(default)]
    toolchain_cache_bytes: u64,
    #[serde(default = "default_toolchain_cache_entries")]
    toolchain_cache_entries: usize,
    /// Restore only private target copies, partitioned by authenticated edge.
    #[serde(default)]
    target_cache: Option<TargetCacheConfig>,
    jobs_per_root: u32,
}

fn default_queue_timeout_seconds() -> u64 {
    300
}

fn default_toolchain_cache_entries() -> usize {
    4
}

impl ServiceProfile {
    fn validate(&self) -> io::Result<Vec<[u8; 32]>> {
        require(
            self.version == SERVICE_VERSION,
            "unsupported remote canonical service profile",
        )?;
        require(
            (1..=32).contains(&self.max_roots)
                && (1..=4096).contains(&self.jobs_per_root)
                && self.max_roots * self.jobs_per_root as usize <= 4096,
            "remote service capacity must be 1..32 roots, 1..4096 jobs per root, and at most 4096 aggregate jobs",
        )?;
        require(
            self.max_queued_roots <= 128,
            "remote service max_queued_roots must be between 0 and 128",
        )?;
        require(
            (1..=wire::ADMISSION_BUDGET.as_secs()).contains(&self.queue_timeout_seconds),
            "remote service queue_timeout_seconds must be between 1 and 1800",
        )?;
        require(
            self.toolchain_cache_bytes <= 64 * 1024 * 1024 * 1024
                && (1..=32).contains(&self.toolchain_cache_entries),
            "remote toolchain cache must be at most 64 GiB and between 1 and 32 entries",
        )?;
        if let Some(cache) = &self.target_cache {
            cache.validate()?;
        }
        let roots = [&self.state_root, &self.input_root, &self.operation_root];
        for (index, root) in roots.iter().enumerate() {
            private_directory(root)?;
            for other in &roots[index + 1..] {
                require(
                    !overlap(root, other),
                    "remote service state, input and operation roots must be disjoint",
                )?;
            }
        }
        require(
            plain_absolute(&self.wrapper),
            "remote service wrapper must be an absolute executable",
        )?;
        ordinary_directory(
            self.wrapper
                .parent()
                .ok_or_else(|| invalid("wrapper has no parent"))?,
        )?;
        let wrapper = fs::symlink_metadata(&self.wrapper)?;
        require(
            wrapper.is_file()
                && wrapper.mode() & 0o111 != 0
                && roots.iter().all(|root| !self.wrapper.starts_with(root)),
            "remote service wrapper must be an ordinary executable outside its mutable roots",
        )?;
        require(
            (1..=256).contains(&self.allowed_edge_pins.len()),
            "enroll between 1 and 256 explicit edge keys",
        )?;
        let mut pins = self
            .allowed_edge_pins
            .iter()
            .map(|pin| digest(pin))
            .collect::<io::Result<Vec<_>>>()?;
        require(
            pins.iter().all(|pin| *pin != [0; 32]),
            "zero is not an enrolled edge key",
        )?;
        pins.sort_unstable();
        require(
            pins.windows(2).all(|pair| pair[0] != pair[1]),
            "duplicate edge key enrollment",
        )?;
        self.tls.files()?;
        Ok(pins)
    }

    fn max_sessions(&self) -> usize {
        self.max_roots + self.max_queued_roots
    }
}

/// Bounded session slots cover authentication, waiting, upload and delivery.
/// Unauthenticated connections cannot create input trees or grow a work queue.
struct Session {
    stopped: Arc<AtomicBool>,
    thread: Option<JoinHandle<io::Result<()>>>,
}

impl Session {
    fn finished(&self) -> bool {
        self.thread.as_ref().is_none_or(JoinHandle::is_finished)
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[derive(Default)]
struct Sessions(Vec<Session>);

impl Sessions {
    fn reap(&mut self) {
        let mut index = 0;
        while index < self.0.len() {
            if self.0[index].finished() {
                let mut session = self.0.swap_remove(index);
                if let Some(thread) = session.thread.take() {
                    match thread.join() {
                        Ok(Ok(())) => {}
                        Ok(Err(error)) => eprintln!("remote canonical session: {error}"),
                        Err(_) => eprintln!("remote canonical session thread panicked"),
                    }
                }
            } else {
                index += 1;
            }
        }
    }
}

impl Drop for Sessions {
    fn drop(&mut self) {
        // Cancel every operation before joining any of them. A slow drain
        // cannot leave another client running after service shutdown begins.
        for session in &self.0 {
            session.stopped.store(true, Ordering::Release);
        }
    }
}

/// Serve enrolled edge clients until SIGINT/SIGTERM or coordinator failure.
/// No client can ask this process to open a path on its own behalf.
pub fn run_service_profile(
    path: &Path,
    release_mode: ReleaseAuthorizationMode,
    build_identity: String,
) -> io::Result<()> {
    let (_, bytes) = read_stable(path, PROFILE_BYTES)?;
    let config: ServiceProfile =
        serde_json::from_slice(&bytes).map_err(|error| invalid(error.to_string()))?;
    let pins = Arc::new(config.validate()?);
    let acceptor = Arc::new(
        config
            .tls
            .files()?
            .edge_coordinator_acceptor()
            .map_err(io::Error::other)?,
    );
    let network = RuntimeBuilder::current_thread()
        .build()
        .map_err(|error| io::Error::other(format!("remote listener runtime: {error:?}")))?;
    let listener = block_on_top_level(&network, TcpListener::bind(config.listen))?;
    let runtime = SharedRuntime::start(
        &config.state_root,
        release_mode,
        build_identity.clone(),
        config.max_roots,
        config.jobs_per_root,
    )?;
    let admissions = OperationAdmissions::new(config.max_roots, config.max_queued_roots);
    let toolchains = Arc::new(RemoteToolchainCache::new(
        config.toolchain_cache_bytes,
        config.toolchain_cache_entries,
    )?);
    let config = Arc::new(config);
    let shutdown = Arc::new(ShutdownController::new());
    shutdown.listen_for_signals();
    let mut sessions = Sessions::default();
    eprintln!(
        "{}",
        json!({"kind":"canonical-remote-service-listening", "version":SERVICE_VERSION,
        "address":listener.local_addr()?.to_string(), "max_roots":config.max_roots,
        "max_queued_roots":config.max_queued_roots,
        "queue_timeout_seconds":config.queue_timeout_seconds,
        "toolchain_cache_bytes":config.toolchain_cache_bytes,
        "toolchain_cache_entries":config.toolchain_cache_entries,
        "target_cache":config.target_cache.as_ref().map(|cache| json!({
            "runtime_epoch":cache.runtime_epoch,
            "max_bytes":cache.max_bytes, "max_families":cache.max_families})),
        "jobs_per_root":config.jobs_per_root, "build_identity":build_identity,
        "required_release":release_mode == ReleaseAuthorizationMode::Required,
        "transport":"mutual-tls-atp", "cargo_location":"coordinator"})
    );
    let result = loop {
        sessions.reap();
        if shutdown.is_shutting_down() {
            break Ok(());
        }
        if !runtime.healthy() {
            break Err(io::Error::other("remote canonical coordinator stopped"));
        }
        let accepted = block_on_top_level(
            &network,
            asupersync::time::timeout(runtime_transport_now(), ACCEPT_POLL, listener.accept()),
        );
        let stream = match accepted {
            Err(_) => continue,
            Ok(Err(error)) => break Err(error),
            Ok(Ok((stream, _))) => stream,
        };
        if sessions.0.len() >= config.max_sessions() {
            // No plaintext rejection on an authenticated-only endpoint. No
            // admission took place, and clients never automatically retry.
            drop(stream);
            continue;
        }
        let stopped = Arc::new(AtomicBool::new(false));
        let child_stop = Arc::clone(&stopped);
        let child_config = Arc::clone(&config);
        let child_runtime = Arc::clone(&runtime);
        let child_admissions = Arc::clone(&admissions);
        let child_toolchains = Arc::clone(&toolchains);
        let child_acceptor = Arc::clone(&acceptor);
        let child_pins = Arc::clone(&pins);
        // The accepted socket has not been polled. Its first I/O registration
        // belongs to this session runtime, never the listener's reactor.
        let thread = match std::thread::Builder::new()
            .name("rabs-remote-session".into())
            .spawn(move || {
                let network = RuntimeBuilder::current_thread().build().map_err(|error| {
                    io::Error::other(format!("remote session runtime: {error:?}"))
                })?;
                block_on_top_level(&network, async {
                    let peer = accept_edge_peer(&child_acceptor, stream, &child_pins)
                        .await
                        .map_err(io::Error::other)?;
                    // Namespace reuse by the key actually authenticated and
                    // enrolled by TLS, never a client-supplied Hello field.
                    let edge_pin = peer.identity.peer_id;
                    let mut wire = Wire::new(peer.stream);
                    let result = handle_session(
                        &mut wire,
                        child_runtime,
                        &child_config,
                        &child_admissions,
                        &child_toolchains,
                        edge_pin,
                        &child_stop,
                    )
                    .await;
                    if let Err(error) = &result {
                        let _ = wire
                            .send(
                                &Message::Failure {
                                    message: error.to_string().chars().take(4096).collect(),
                                },
                                &child_stop,
                                Instant::now() + wire::IO_BUDGET,
                            )
                            .await;
                    }
                    result
                })
            }) {
            Ok(thread) => thread,
            Err(error) => break Err(error),
        };
        sessions.0.push(Session {
            stopped,
            thread: Some(thread),
        });
    };
    drop(listener);
    drop(sessions);
    let drained = runtime.shutdown();
    result.and(drained)
}

fn output_file(parent: &Path, name: &str) -> io::Result<File> {
    OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .mode(0o600)
        .open(parent.join(name))
}

fn read_output(file: &File, offset: &mut u64) -> io::Result<Output> {
    let length = file.metadata()?.len();
    require(
        length <= OUTPUT_TOTAL_BYTES && *offset <= length,
        "remote diagnostic output exceeded its bound or changed",
    )?;
    let mut bytes = vec![0; (length - *offset).min(MAX_SOURCE_CHUNK as u64) as usize];
    let start = *offset;
    if !bytes.is_empty() {
        file.read_exact_at(&mut bytes, start)?;
    }
    *offset += bytes.len() as u64;
    Ok(Output {
        offset: start,
        bytes: encode_hex(&bytes),
    })
}

/// Synthesize compiler intent from logical settings. Only these typed content
/// identities come from the network; all physical paths are supplied locally.
fn prepared_request(
    settings: &remote_operation::RemoteOperationSettings,
    toolchain_root: &Path,
    source: &Manifest,
    toolchain: &wire::Toolchain,
    cargo_home: &Option<wire::CargoHome>,
) -> io::Result<Value> {
    let specification = settings.source_specification(toolchain_root, None)?;
    let mut request = json!({});
    for field in ["kind", "request_id", "program", "args", "command_context"] {
        request[field] = specification[field].clone();
    }
    request["source_manifest"] = serde_json::to_value(source)?;
    request["toolchain_identity"] = serde_json::to_value(toolchain)?;
    request["toolchain_transfer"] = json!(TOOLCHAIN_TRANSFER_VERSION);
    if let Some(home) = cargo_home {
        request["cargo_home"] = serde_json::to_value(home)?;
    }
    worker_delivery::validate_request(&request)?;
    source_manifest::request_manifest(&request)?;
    Ok(request)
}

/// A transfer decision retains its exact SDK custody through source upload.
/// Announcing reuse cannot later select a receiver or another cached image.
enum ToolchainInput {
    Upload {
        receiver: Box<ToolchainReceiver>,
        owner: Arc<tempfile::TempDir>,
    },
    Reuse(Arc<ReceivedToolchain>),
}

impl ToolchainInput {
    fn disposition(&self) -> ToolchainDisposition {
        match self {
            Self::Upload { .. } => ToolchainDisposition::Upload,
            Self::Reuse(_) => ToolchainDisposition::Reuse,
        }
    }
}

/// Prepared only after acquiring an operation permit. A pending SDK upload
/// retains a bounded ticket and this declaration, without allocating input
/// trees. The original admission deadline also bounds publisher handoff.
struct ToolchainAdmission<'a> {
    cache: &'a RemoteToolchainCache,
    edge_pin: [u8; 32],
    identity: ToolchainIdentity,
    input_root: &'a Path,
}

impl<'a> ToolchainAdmission<'a> {
    async fn prepare<S: AsyncRead + AsyncWrite + Unpin>(
        self,
        wire: &mut Wire<S>,
        stopped: &AtomicBool,
        deadline: Instant,
        healthy: impl Fn() -> bool,
    ) -> io::Result<(ToolchainInput, Option<UploadPublisher<'a>>)> {
        let cancelled = || {
            stopped.load(Ordering::Acquire) || !healthy() || Instant::now() >= deadline
        };
        loop {
            match self.cache.acquire(self.edge_pin, &self.identity, &cancelled)? {
                ToolchainAcquisition::Ready(lease) => {
                    return Ok((ToolchainInput::Reuse(lease), None));
                }
                ToolchainAcquisition::Upload(publisher) => {
                    checkpoint(stopped, deadline)?;
                    require(healthy(), "remote coordinator stopped before SDK upload")?;
                    // SDK custody remains separate from source and diagnostics.
                    // A failed creation drops the publisher and lets an existing
                    // waiter elect a successor within its own fixed deadline.
                    let owner = Arc::new(
                        tempfile::Builder::new()
                            .prefix("canonical-remote-sdk-")
                            .permissions(fs::Permissions::from_mode(0o700))
                            .tempdir_in(self.input_root)?,
                    );
                    let receiver = ToolchainReceiver::create(
                        &owner.path().join("toolchain"),
                        self.identity,
                        ToolchainLimits::default(),
                    )?;
                    checkpoint(stopped, deadline)?;
                    require(healthy(), "remote coordinator stopped before SDK upload")?;
                    return Ok((
                        ToolchainInput::Upload {
                            receiver: Box::new(receiver),
                            owner,
                        },
                        Some(publisher),
                    ));
                }
                ToolchainAcquisition::Wait(waiter) => loop {
                    match waiter.poll(&cancelled)? {
                        UploadPoll::Ready(lease) => {
                            return Ok((ToolchainInput::Reuse(lease), None));
                        }
                        UploadPoll::Abandoned => break,
                        UploadPoll::Pending => {
                            wire.send(&Message::Queued {}, stopped, deadline).await?;
                            require(
                                matches!(wire.receive(stopped, deadline).await?, Message::Poll {}),
                                "expected an admission status poll while awaiting an SDK upload",
                            )?;
                        }
                    }
                },
            }
        }
    }
}

fn require_wire_identity(version: &str, build_identity: &str, expected: &str) -> io::Result<()> {
    require(
        version == WIRE_VERSION && build_identity == expected,
        "remote client and service protocol/build identities differ",
    )
}

async fn handle_session<S: AsyncRead + AsyncWrite + Unpin>(
    wire: &mut Wire<S>,
    runtime: Arc<SharedRuntime>,
    config: &ServiceProfile,
    admissions: &Arc<OperationAdmissions>,
    toolchains: &RemoteToolchainCache,
    edge_pin: [u8; 32],
    stopped: &Arc<AtomicBool>,
) -> io::Result<()> {
    let declaration_deadline = Instant::now() + wire::IO_BUDGET;
    let Message::Hello {
        version,
        build_identity,
        require_release,
        settings,
        source_manifest,
        toolchain_identity,
        cargo_home,
    } = wire.receive(stopped, declaration_deadline).await?
    else {
        return Err(invalid("remote operation must begin with hello"));
    };
    require_wire_identity(&version, &build_identity, &runtime.build_identity)?;
    require(
        !require_release || runtime.release_mode == ReleaseAuthorizationMode::Required,
        "remote service cannot downgrade required release authorization",
    )?;
    settings.validate()?;
    require(
        settings.jobs <= runtime.jobs_per_root && runtime.healthy(),
        "remote service unavailable or requested jobs exceed its root grant",
    )?;
    let manifest = source_manifest.native()?;
    let identity = toolchain_identity.native()?;
    // The synthesized request discards physical capture paths. Validate its
    // complete logical declaration before reserving work or creating any tree.
    let request = prepared_request(
        &settings,
        &config.input_root.join("toolchain"),
        &source_manifest,
        &toolchain_identity,
        &cargo_home,
    )?;
    let queue_deadline = Instant::now()
        .checked_add(Duration::from_secs(config.queue_timeout_seconds))
        .ok_or_else(|| invalid("remote operation admission deadline overflow"))?;
    // Keep this permit through input custody, execution, final delivery and
    // every error/drop path. It is separate from the existing Cargo root token.
    let _admission = acquire_operation(wire, admissions, stopped, queue_deadline, || {
        runtime.healthy()
    })
    .await?;
    let (toolchain, publisher) = ToolchainAdmission {
        cache: toolchains,
        edge_pin,
        identity,
        input_root: &config.input_root,
    }
    .prepare(wire, stopped, queue_deadline, || runtime.healthy())
    .await?;
    // Waiting for a shared cold SDK cannot consume the caller's upload budget.
    // Polls and publisher loss never renew the original admission deadline.
    let input_deadline = Instant::now() + TOOLCHAIN_INPUT_BUDGET;
    let cancelled = || {
        stopped.load(Ordering::Acquire) || !runtime.healthy() || Instant::now() >= input_deadline
    };
    let disposition = toolchain.disposition();
    let owner = Arc::new(
        tempfile::Builder::new()
            .prefix("canonical-remote-input-")
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir_in(&config.input_root)?,
    );
    let source = SourceReceiver::create(&owner.path().join("source"), manifest)?;
    wire.send(
        &Message::Ready {
            toolchain: disposition,
        },
        stopped,
        input_deadline,
    )
    .await?;
    let (source, toolchain) =
        receive_inputs(wire, source, toolchain, stopped, input_deadline).await?;
    let toolchain = match disposition {
        ToolchainDisposition::Upload => toolchains.adopt(edge_pin, toolchain, &cancelled)?,
        ToolchainDisposition::Reuse => toolchain,
    };
    if let Some(publisher) = publisher {
        // Only the exact sealed SDK crosses this handoff. The publisher leaves
        // the pending registry before existing waiters receive its lease.
        publisher.publish(Arc::clone(&toolchain), &cancelled)?;
    }
    let inputs = RemoteOperationInputs::new(
        Arc::clone(&owner),
        source,
        toolchain,
        request,
        edge_pin,
        &cancelled,
    )?;
    checkpoint(stopped, input_deadline)?;
    let stdout = output_file(owner.path(), "stdout")?;
    let stderr = output_file(owner.path(), "stderr")?;
    let execution_deadline =
        Instant::now() + Duration::from_secs(settings.timeout_seconds) + DELIVERY_BUDGET;
    // Acceptance means execution may begin. An interruption from this point
    // never selects a retry, another coordinator or local compilation.
    wire.send(&Message::Accepted {}, stopped, input_deadline)
        .await?;
    let operation = remote_operation::start(
        Arc::clone(&runtime),
        config.wrapper.clone(),
        config.operation_root.clone(),
        config.target_cache.clone(),
        inputs,
        *settings,
        stdout.try_clone()?,
        stderr.try_clone()?,
        Arc::clone(stopped),
        OUTPUT_BYTES,
    )?;
    let mut stdout_offset = 0;
    let mut stderr_offset = 0;
    let mut operation = Some(operation);
    let mut outcome = None;
    loop {
        checkpoint(stopped, execution_deadline)?;
        require(
            runtime.healthy(),
            "remote canonical coordinator became unavailable",
        )?;
        require(
            matches!(
                wire.receive(stopped, execution_deadline).await?,
                Message::Poll {}
            ),
            "expected an operation status poll",
        )?;
        if operation
            .as_ref()
            .is_some_and(remote_operation::RemoteOperationOwner::finished)
        {
            outcome = Some(
                operation
                    .take()
                    .expect("finished operation is owned")
                    .join()?,
            );
        }
        let stdout_chunk = read_output(&stdout, &mut stdout_offset)?;
        let stderr_chunk = read_output(&stderr, &mut stderr_offset)?;
        if !stdout_chunk.bytes.is_empty() || !stderr_chunk.bytes.is_empty() || outcome.is_none() {
            wire.send(
                &Message::Progress {
                    stdout: stdout_chunk,
                    stderr: stderr_chunk,
                },
                stopped,
                execution_deadline,
            )
            .await?;
            continue;
        }
        break;
    }
    let outcome = outcome.ok_or_else(|| invalid("remote operation completed without its owner"))?;
    let delivery_deadline = Instant::now() + DELIVERY_BUDGET;
    let cancelled = || {
        stopped.load(Ordering::Acquire) || !runtime.healthy() || Instant::now() >= delivery_deadline
    };
    let target = outcome
        .retained_target
        .as_deref()
        .map(|path| CapturedTarget::capture(path, &cancelled))
        .transpose()?;
    outcome.verify_before_delivery(&cancelled)?;
    checkpoint(stopped, delivery_deadline)?;
    wire.send(
        &Message::BuildFinished {
            exit_code: outcome.exit_code,
            stdout_bytes: stdout_offset,
            stderr_bytes: stderr_offset,
            target: target
                .as_ref()
                .map(|target| Manifest::from_native(target.manifest())),
        },
        stopped,
        delivery_deadline,
    )
    .await?;
    deliver_result(
        wire,
        &outcome,
        target.as_ref(),
        stopped,
        delivery_deadline,
        &cancelled,
    )
    .await
}

/// One authenticated declaration owns a FIFO ticket, never an input tree or
/// Cargo process, until admitted. Each poll receives exactly Queued or Ready;
/// Ready is sent by the caller only after its receivers have been created.
async fn acquire_operation<S: AsyncRead + AsyncWrite + Unpin>(
    wire: &mut Wire<S>,
    admissions: &Arc<OperationAdmissions>,
    stopped: &AtomicBool,
    deadline: Instant,
    healthy: impl Fn() -> bool,
) -> io::Result<AdmittedOperation> {
    checkpoint(stopped, deadline)?;
    let mut waiting = admissions.enqueue()?;
    loop {
        checkpoint(stopped, deadline)?;
        if !healthy() {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "remote canonical coordinator stopped while awaiting admission",
            ));
        }
        if let Some(admitted) = waiting.try_start()? {
            return Ok(admitted);
        }
        wire.send(&Message::Queued {}, stopped, deadline).await?;
        // Do not renew the queue deadline on activity or consume upload bytes.
        // The bounded read also observes EOF, Cancel and service shutdown.
        require(
            matches!(wire.receive(stopped, deadline).await?, Message::Poll {}),
            "expected an admission status poll before input upload",
        )?;
    }
}

/// The same finite upload receiver serves production sessions and native
/// transport tests. Only sealed byte owners can cross into execution admission.
async fn receive_inputs<S: AsyncRead + AsyncWrite + Unpin>(
    wire: &mut Wire<S>,
    mut source: SourceReceiver,
    mut toolchain: ToolchainInput,
    stopped: &AtomicBool,
    input_deadline: Instant,
) -> io::Result<(SourceReceiver, Arc<ReceivedToolchain>)> {
    let mut window = Window::default();
    let mut source_finished = false;
    let cancelled = || stopped.load(Ordering::Acquire) || Instant::now() >= input_deadline;
    loop {
        checkpoint(stopped, input_deadline)?;
        let message = wire.receive_until(stopped, input_deadline).await?;
        match message {
            Message::SourceChunk { chunk } => {
                require(
                    !source_finished,
                    "source bytes arrived after the toolchain phase",
                )?;
                window.record()?;
                let (bytes, sha256) = chunk.verified_bytes()?;
                source.write_chunk(&chunk.path, chunk.offset, &bytes, sha256)?;
            }
            Message::ToolchainEntry { entry } => {
                let ToolchainInput::Upload { receiver, .. } = &mut toolchain else {
                    return Err(invalid(
                        "SDK entries are forbidden after toolchain reuse admission",
                    ));
                };
                window.record()?;
                if !source_finished {
                    source.seal_cancellable(&cancelled)?;
                    source_finished = true;
                }
                receiver.entry(entry.native())?;
            }
            Message::ToolchainChunk { chunk } => {
                let ToolchainInput::Upload { receiver, .. } = &mut toolchain else {
                    return Err(invalid(
                        "SDK bytes are forbidden after toolchain reuse admission",
                    ));
                };
                require(source_finished, "toolchain bytes arrived before its entry")?;
                window.record()?;
                let (bytes, sha256) = chunk.verified_bytes()?;
                receiver.write_chunk(&chunk.path, chunk.offset, &bytes, sha256)?;
            }
            Message::WindowEnd { count } => {
                window.acknowledge(count)?;
                wire.send(&Message::Window { count }, stopped, input_deadline)
                    .await?;
            }
            Message::InputsDone {} => {
                require(
                    !window.pending(),
                    "remote inputs ended before their complete acknowledged transfer",
                )?;
                if !source_finished {
                    require(
                        matches!(toolchain, ToolchainInput::Reuse(_)),
                        "remote inputs ended before the declared SDK upload",
                    )?;
                    // A hit skips only the SDK transfer. Source still crosses
                    // the same complete manifest/byte sealing boundary.
                    source.seal_cancellable(&cancelled)?;
                }
                break;
            }
            _ => return Err(invalid("unexpected message during remote input transfer")),
        }
    }
    let toolchain = match toolchain {
        ToolchainInput::Upload {
            mut receiver,
            owner,
        } => Arc::new(ReceivedToolchain::new(
            owner,
            Arc::new(receiver.seal(&cancelled)?),
            &cancelled,
        )?),
        ToolchainInput::Reuse(lease) => {
            // Recheck the exact owner pinned before Ready. Corruption or
            // cancellation cannot trigger a hidden upload or a different hit.
            lease.verify(&cancelled)?;
            lease
        }
    };
    checkpoint(stopped, input_deadline)?;
    Ok((source, toolchain))
}

async fn send_window<S: AsyncRead + AsyncWrite + Unpin>(
    wire: &mut Wire<S>,
    window: &mut Window,
    stopped: &AtomicBool,
    deadline: Instant,
) -> io::Result<()> {
    if !window.pending() {
        return Ok(());
    }
    wire.send(
        &Message::WindowEnd {
            count: window.count(),
        },
        stopped,
        deadline,
    )
    .await?;
    let Message::Window { count } = wire.receive(stopped, deadline).await? else {
        return Err(invalid("expected artifact window acknowledgment"));
    };
    window.acknowledge(count)
}

async fn deliver_result<S: AsyncRead + AsyncWrite + Unpin>(
    wire: &mut Wire<S>,
    outcome: &RemoteOperationOutcome,
    target: Option<&CapturedTarget>,
    stopped: &AtomicBool,
    deadline: Instant,
    cancelled: &impl Fn() -> bool,
) -> io::Result<()> {
    if let Some(target) = target {
        require(
            outcome.exit_code == 0,
            "failed compilation cannot publish a target",
        )?;
        require(
            matches!(
                wire.receive(stopped, deadline).await?,
                Message::ReceiveTarget {}
            ),
            "client did not accept the declared target",
        )?;
        let mut window = Window::default();
        for file in target.manifest().files() {
            let mut offset = 0;
            while offset < file.len {
                checkpoint(stopped, deadline)?;
                let bytes = target.read_chunk(&file.path, offset, MAX_SOURCE_CHUNK, cancelled)?;
                require(
                    !bytes.is_empty(),
                    "artifact source ended before its declared length",
                )?;
                wire.send(
                    &Message::ArtifactChunk {
                        chunk: Chunk::new(&file.path, offset, &bytes)?,
                    },
                    stopped,
                    deadline,
                )
                .await?;
                offset += bytes.len() as u64;
                if window.record()? {
                    send_window(wire, &mut window, stopped, deadline).await?;
                }
            }
        }
        send_window(wire, &mut window, stopped, deadline).await?;
        wire.send(&Message::ArtifactEnd {}, stopped, deadline)
            .await?;
        let manifest_sha256 = encode_hex(&target.manifest().digest());
        let Message::Received {
            manifest_sha256: received,
        } = wire.receive_until(stopped, deadline).await?
        else {
            return Err(invalid("client did not seal the complete target"));
        };
        require(
            received == manifest_sha256,
            "client sealed a different target manifest",
        )?;
        target.verify(cancelled)?;
        outcome.verify_before_delivery(cancelled)?;
        wire.send(
            &Message::Commit {
                manifest_sha256: manifest_sha256.clone(),
            },
            stopped,
            deadline,
        )
        .await?;
        let Message::Published {
            manifest_sha256: published,
        } = wire.receive_until(stopped, deadline).await?
        else {
            return Err(invalid("client did not acknowledge target installation"));
        };
        require(
            published == manifest_sha256,
            "client installed a different target manifest",
        )?;
    } else {
        require(
            matches!(wire.receive(stopped, deadline).await?, Message::Close {}),
            "expected completion acknowledgment",
        )?;
    }
    outcome.verify_before_delivery(cancelled)?;
    checkpoint(stopped, deadline)?;
    wire.send(
        &Message::Complete {
            exit_code: outcome.exit_code,
        },
        stopped,
        deadline,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use asupersync::io::ReadBuf;
    use rabs_sandbox::source_transfer::{SourceFile, SourceManifest};
    use rabs_sandbox::toolchain_dataset::ToolchainIdentity;
    use sha2::{Digest, Sha256};
    use std::future::Future;
    use std::os::unix::fs::DirBuilderExt;
    use std::pin::{Pin, pin};
    use std::sync::Mutex;
    use std::task::{Context, Poll, Waker};

    /// An explicitly scripted transport, not a TLS/compiler substitute. Tests
    /// exercise the production queue's frame handling and permit ownership.
    struct AdmissionPeer {
        input: Vec<u8>,
        offset: usize,
        eof: bool,
        output: Arc<Mutex<Vec<u8>>>,
        before_read: Option<Box<dyn FnOnce() + Send>>,
    }

    impl AdmissionPeer {
        fn new(input: Vec<u8>) -> Self {
            Self {
                input,
                offset: 0,
                eof: true,
                output: Arc::new(Mutex::new(Vec::new())),
                before_read: None,
            }
        }
    }

    impl AsyncRead for AdmissionPeer {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            output: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let peer = self.get_mut();
            if let Some(effect) = peer.before_read.take() {
                effect();
            }
            if peer.offset == peer.input.len() && !peer.eof {
                // No peer wakeup: cancellation/expiry must use the real timer.
                return Poll::Pending;
            }
            let count = output
                .remaining()
                .min(3)
                .min(peer.input.len() - peer.offset);
            output.put_slice(&peer.input[peer.offset..peer.offset + count]);
            peer.offset += count;
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for AdmissionPeer {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            let count = bytes.len().min(3);
            self.output
                .lock()
                .unwrap()
                .extend_from_slice(&bytes[..count]);
            Poll::Ready(Ok(count))
        }

        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.poll_flush(cx)
        }
    }

    fn record(message: &Message) -> Vec<u8> {
        let mut bytes = serde_json::to_vec(message).unwrap();
        bytes.push(b'\n');
        bytes
    }

    fn messages(output: &Arc<Mutex<Vec<u8>>>) -> Vec<Value> {
        std::str::from_utf8(&output.lock().unwrap())
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    fn ready<T>(future: impl Future<Output = T>) -> T {
        let mut future = pin!(future);
        let mut context = Context::from_waker(Waker::noop());
        for _ in 0..100_000 {
            if let Poll::Ready(value) = future.as_mut().poll(&mut context) {
                return value;
            }
        }
        panic!("scripted remote admission did not settle");
    }

    fn service_profile() -> (tempfile::TempDir, ServiceProfile) {
        let owner = tempfile::Builder::new()
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        for name in ["state", "inputs", "operations"] {
            fs::DirBuilder::new()
                .mode(0o700)
                .create(owner.path().join(name))
                .unwrap();
        }
        let wrapper = owner.path().join("rabs-wrap");
        fs::write(&wrapper, b"#!/bin/sh\nexit 99\n").unwrap();
        fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o700)).unwrap();
        let profile: ServiceProfile = serde_json::from_value(json!({
            "version": SERVICE_VERSION, "listen":"127.0.0.1:0",
            "state_root":owner.path().join("state"),
            "input_root":owner.path().join("inputs"),
            "operation_root":owner.path().join("operations"), "wrapper":wrapper,
            "tls":{"ca":owner.path().join("ca.pem"),
                "certificate":owner.path().join("cert.pem"),
                "private_key":owner.path().join("key.pem")},
            "allowed_edge_pins":["ab".repeat(32)], "max_roots":2, "jobs_per_root":2,
        }))
        .unwrap();
        (owner, profile)
    }

    #[test]
    fn remote_queue_defaults_and_capacity_are_bounded() {
        let (_owner, mut profile) = service_profile();
        assert_eq!(profile.max_queued_roots, 0);
        assert_eq!(profile.queue_timeout_seconds, 300);
        assert_eq!(profile.toolchain_cache_bytes, 0);
        assert_eq!(profile.toolchain_cache_entries, 4);
        assert!(profile.target_cache.is_none());
        assert_eq!(profile.max_sessions(), 2);
        profile.validate().unwrap();
        profile.max_roots = 32;
        profile.max_queued_roots = 128;
        profile.queue_timeout_seconds = 1800;
        profile.validate().unwrap();
        assert_eq!(profile.max_sessions(), 160);
        profile.max_queued_roots = 129;
        assert!(profile.validate().is_err());
        profile.max_queued_roots = 128;
        for timeout in [0, 1801, u64::MAX] {
            profile.queue_timeout_seconds = timeout;
            assert!(profile.validate().is_err(), "timeout {timeout}");
        }
        profile.queue_timeout_seconds = 300;
        profile.toolchain_cache_bytes = 64 * 1024 * 1024 * 1024;
        profile.toolchain_cache_entries = 32;
        profile.validate().unwrap();
        for entries in [0, 33, usize::MAX] {
            profile.toolchain_cache_entries = entries;
            assert!(profile.validate().is_err(), "cache entries {entries}");
        }
        profile.toolchain_cache_entries = 4;
        for bytes in [64 * 1024 * 1024 * 1024 + 1, u64::MAX] {
            profile.toolchain_cache_bytes = bytes;
            assert!(profile.validate().is_err(), "cache bytes {bytes}");
        }
    }

    #[test]
    fn remote_target_state_is_explicit_bounded_server_policy() {
        let (_owner, mut profile) = service_profile();
        profile.validate().unwrap();
        assert!(profile.target_cache.is_none());

        let cache: TargetCacheConfig =
            serde_json::from_value(json!({"runtime_epoch":"coordinator-runtime-1"})).unwrap();
        assert_eq!(cache.max_bytes, 1024 * 1024 * 1024);
        assert_eq!(cache.max_families, 8);
        profile.target_cache = Some(cache);
        profile.validate().unwrap();

        for value in [
            json!({"runtime_epoch":"coordinator-runtime-1", "max_bytes":1, "max_families":1}),
            json!({"runtime_epoch":"a".repeat(256), "max_bytes":8_u64 * 1024 * 1024 * 1024,
                "max_families":32}),
        ] {
            profile.target_cache = Some(serde_json::from_value(value).unwrap());
            profile.validate().unwrap();
        }
        for value in [
            json!({"runtime_epoch":""}),
            json!({"runtime_epoch":"a".repeat(257)}),
            json!({"runtime_epoch":"runtime/escape"}),
            json!({"runtime_epoch":"runtime\n"}),
            json!({"runtime_epoch":"runtime", "max_bytes":0}),
            json!({"runtime_epoch":"runtime", "max_bytes":8_u64 * 1024 * 1024 * 1024 + 1}),
            json!({"runtime_epoch":"runtime", "max_families":0}),
            json!({"runtime_epoch":"runtime", "max_families":33}),
        ] {
            profile.target_cache = Some(serde_json::from_value(value.clone()).unwrap());
            assert!(profile.validate().is_err(), "{value}");
        }
        for value in [
            json!({}),
            json!({"runtime_epoch":"runtime", "path":"/peer/cache"}),
            json!({"runtime_epoch":"runtime", "authenticated_edge_pin":"ab".repeat(32)}),
        ] {
            assert!(serde_json::from_value::<TargetCacheConfig>(value).is_err());
        }
    }

    #[test]
    fn remote_sdk_decision_requires_v2_wire_and_exact_build_identity() {
        require_wire_identity("canonical-compile-remote-v2", "build-one", "build-one").unwrap();
        for (version, identity) in [
            ("canonical-compile-remote-v1", "build-one"),
            ("canonical-compile-remote-v2", "build-two"),
            ("", "build-one"),
        ] {
            assert_eq!(
                require_wire_identity(version, identity, "build-one")
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidData
            );
        }
    }

    fn received_sdk() -> Arc<ReceivedToolchain> {
        let original = crate::test_util::private_tempdir();
        fs::write(original.path().join("compiler-data"), b"verified SDK").unwrap();
        let owner = Arc::new(crate::test_util::private_tempdir());
        let image = rabs_sandbox::toolchain_dataset::capture_toolchain(
            original.path(),
            &owner.path().join("toolchain"),
            None,
            &ToolchainLimits::default(),
            || false,
        )
        .unwrap();
        Arc::new(ReceivedToolchain::new(owner, Arc::new(image), || false).unwrap())
    }

    fn source_receiver(owner: &Path, bytes: &[u8]) -> SourceReceiver {
        let manifest = SourceManifest::new(vec![SourceFile {
            path: "src/lib.rs".into(),
            len: bytes.len() as u64,
            sha256: Sha256::digest(bytes).into(),
            executable: false,
        }])
        .unwrap();
        SourceReceiver::create(&owner.join("source"), manifest).unwrap()
    }

    fn source_upload(bytes: &[u8]) -> Vec<u8> {
        let mut input = Vec::new();
        if !bytes.is_empty() {
            input.extend(record(&Message::SourceChunk {
                chunk: Chunk::new("src/lib.rs", 0, bytes).unwrap(),
            }));
            input.extend(record(&Message::WindowEnd { count: 1 }));
        }
        input.extend(record(&Message::InputsDone {}));
        input
    }

    fn prepare_toolchain_input(
        cache: &RemoteToolchainCache,
        edge_pin: [u8; 32],
        identity: ToolchainIdentity,
        input_root: &Path,
        cancelled: impl Fn() -> bool,
    ) -> io::Result<ToolchainInput> {
        let mut wire = Wire::new(AdmissionPeer::new(Vec::new()));
        let (input, _publisher) = ready(
            ToolchainAdmission {
                cache,
                edge_pin,
                identity,
                input_root,
            }
            .prepare(
                &mut wire,
                &AtomicBool::new(false),
                Instant::now() + Duration::from_secs(5),
                || !cancelled(),
            ),
        )?;
        Ok(input)
    }

    #[test]
    fn verified_sdk_hit_is_peer_scoped_and_creates_no_upload_tree() {
        let cache = RemoteToolchainCache::new(1024, 4).unwrap();
        let sdk = received_sdk();
        let pin = [7; 32];
        let retained = cache.adopt(pin, Arc::clone(&sdk), || false).unwrap();
        assert!(Arc::ptr_eq(&retained, &sdk));
        let inputs = crate::test_util::private_tempdir();
        let selection =
            prepare_toolchain_input(&cache, pin, *sdk.identity(), inputs.path(), || false).unwrap();
        assert_eq!(selection.disposition(), ToolchainDisposition::Reuse);
        let ToolchainInput::Reuse(hit) = selection else {
            panic!("verified retained SDK should skip upload");
        };
        assert!(Arc::ptr_eq(&hit, &sdk));
        assert_eq!(fs::read_dir(inputs.path()).unwrap().count(), 0);

        // Another enrolled principal must upload its own independently
        // verified data, even with an identical declared content digest.
        let selection =
            prepare_toolchain_input(&cache, [8; 32], *sdk.identity(), inputs.path(), || false)
                .unwrap();
        assert_eq!(selection.disposition(), ToolchainDisposition::Upload);
        let ToolchainInput::Upload { owner, .. } = selection else {
            panic!("a different authenticated peer must upload its own SDK");
        };
        assert!(owner.path().starts_with(inputs.path()));
        assert_ne!(owner.path(), sdk.owner().path());
        assert_eq!(fs::read_dir(inputs.path()).unwrap().count(), 1);
        sdk.verify(|| false).unwrap();
    }

    #[test]
    fn cold_sdk_waiters_share_one_sealed_upload_without_persistent_retention() {
        use std::sync::mpsc;

        let cache = RemoteToolchainCache::new(0, 1).unwrap();
        let sdk = received_sdk();
        let pin = [17; 32];
        let identity = *sdk.identity();
        let ToolchainAcquisition::Upload(publisher) =
            cache.acquire(pin, &identity, || false).unwrap()
        else {
            panic!("the first cold operation must own its upload");
        };
        let inputs = crate::test_util::private_tempdir();
        let input_root = inputs.path().to_path_buf();
        let (release, waiting) = mpsc::channel();
        let (published, acknowledgment) = mpsc::channel();
        let peer_sdk = Arc::clone(&sdk);
        let cache_ref = &cache;
        std::thread::scope(|scope| {
            let leader = scope.spawn(move || {
                waiting.recv_timeout(Duration::from_secs(5)).unwrap();
                let lease = cache_ref.adopt(pin, peer_sdk, || false).unwrap();
                publisher.publish(lease, || false).unwrap();
                published.send(()).unwrap();
            });
            let mut peer = AdmissionPeer::new(record(&Message::Poll {}));
            let output = Arc::clone(&peer.output);
            peer.before_read = Some(Box::new(move || {
                assert_eq!(fs::read_dir(&input_root).unwrap().count(), 0);
                release.send(()).unwrap();
                acknowledgment.recv_timeout(Duration::from_secs(5)).unwrap();
            }));
            let mut wire = Wire::new(peer);
            let (input, publisher) = ready(
                ToolchainAdmission {
                    cache: &cache,
                    edge_pin: pin,
                    identity,
                    input_root: inputs.path(),
                }
                .prepare(
                    &mut wire,
                    &AtomicBool::new(false),
                    Instant::now() + Duration::from_secs(5),
                    || true,
                ),
            )
            .unwrap();
            assert!(publisher.is_none());
            let ToolchainInput::Reuse(reused) = input else {
                panic!("the waiting operation must reuse the completed upload");
            };
            assert!(Arc::ptr_eq(&sdk, &reused));
            assert_eq!(fs::read_dir(inputs.path()).unwrap().count(), 0);
            assert_eq!(messages(&output), vec![json!({"kind":"queued"})]);
            leader.join().unwrap();
        });
        // The ordinary cache is disabled. Active input sharing cannot turn a
        // completed flight into a retained image for a later operation.
        assert!(matches!(
            cache.acquire(pin, &identity, || false).unwrap(),
            ToolchainAcquisition::Upload(_)
        ));
    }

    #[test]
    fn abandoned_cold_sdk_publisher_hands_upload_to_an_existing_waiter() {
        use std::sync::mpsc;

        let cache = RemoteToolchainCache::new(0, 1).unwrap();
        let sdk = received_sdk();
        let identity = *sdk.identity();
        let pin = [18; 32];
        let ToolchainAcquisition::Upload(publisher) =
            cache.acquire(pin, &identity, || false).unwrap()
        else {
            panic!("the first cold operation must own its upload");
        };
        let inputs = crate::test_util::private_tempdir();
        let (release, waiting) = mpsc::channel();
        let (abandoned, acknowledgment) = mpsc::channel();
        std::thread::scope(|scope| {
            let leader = scope.spawn(move || {
                waiting.recv_timeout(Duration::from_secs(5)).unwrap();
                drop(publisher);
                abandoned.send(()).unwrap();
            });
            let mut peer = AdmissionPeer::new(record(&Message::Poll {}));
            let output = Arc::clone(&peer.output);
            peer.before_read = Some(Box::new(move || {
                release.send(()).unwrap();
                acknowledgment.recv_timeout(Duration::from_secs(5)).unwrap();
            }));
            let mut wire = Wire::new(peer);
            let (input, publisher) = ready(
                ToolchainAdmission {
                    cache: &cache,
                    edge_pin: pin,
                    identity,
                    input_root: inputs.path(),
                }
                .prepare(
                    &mut wire,
                    &AtomicBool::new(false),
                    Instant::now() + Duration::from_secs(5),
                    || true,
                ),
            )
            .unwrap();
            assert!(publisher.is_some());
            assert!(matches!(input, ToolchainInput::Upload { .. }));
            assert_eq!(fs::read_dir(inputs.path()).unwrap().count(), 1);
            assert_eq!(messages(&output), vec![json!({"kind":"queued"})]);
            assert!(matches!(
                cache.acquire(pin, &identity, || false).unwrap(),
                ToolchainAcquisition::Wait(_)
            ));
            leader.join().unwrap();
        });
    }

    #[test]
    fn waiting_for_a_cold_sdk_rejects_early_bytes_cancel_and_disconnect() {
        let sdk = received_sdk();
        let identity = *sdk.identity();
        for input in [
            Vec::new(),
            record(&Message::Cancel {}),
            record(&Message::SourceChunk {
                chunk: Chunk::new("src/lib.rs", 0, b"too early").unwrap(),
            }),
            record(&Message::InputsDone {}),
        ] {
            let cache = RemoteToolchainCache::new(0, 1).unwrap();
            let pin = [19; 32];
            let ToolchainAcquisition::Upload(_publisher) =
                cache.acquire(pin, &identity, || false).unwrap()
            else {
                panic!("the first cold operation must own its upload");
            };
            let inputs = crate::test_util::private_tempdir();
            let peer = AdmissionPeer::new(input);
            let output = Arc::clone(&peer.output);
            let mut wire = Wire::new(peer);
            assert!(ready(
                ToolchainAdmission {
                    cache: &cache,
                    edge_pin: pin,
                    identity,
                    input_root: inputs.path(),
                }
                .prepare(
                    &mut wire,
                    &AtomicBool::new(false),
                    Instant::now() + Duration::from_secs(5),
                    || true,
                ),
            )
            .is_err());
            assert_eq!(fs::read_dir(inputs.path()).unwrap().count(), 0);
            assert_eq!(messages(&output), vec![json!({"kind":"queued"})]);
            assert!(matches!(
                cache.acquire(pin, &identity, || false).unwrap(),
                ToolchainAcquisition::Wait(_)
            ));
        }
    }

    #[test]
    fn cold_sdk_waiting_preserves_cancellation_and_the_original_deadline() {
        let sdk = received_sdk();
        let identity = *sdk.identity();
        for expire in [false, true] {
            let cache = RemoteToolchainCache::new(0, 1).unwrap();
            let pin = [20; 32];
            let ToolchainAcquisition::Upload(_publisher) =
                cache.acquire(pin, &identity, || false).unwrap()
            else {
                panic!("the first cold operation must own its upload");
            };
            let inputs = crate::test_util::private_tempdir();
            let stopped = Arc::new(AtomicBool::new(false));
            let child_stop = Arc::clone(&stopped);
            let mut peer = AdmissionPeer::new(record(&Message::Poll {}));
            peer.before_read = Some(Box::new(move || {
                if expire {
                    std::thread::sleep(Duration::from_millis(40));
                } else {
                    child_stop.store(true, Ordering::Release);
                }
            }));
            let output = Arc::clone(&peer.output);
            let mut wire = Wire::new(peer);
            let deadline = Instant::now()
                + if expire {
                    Duration::from_millis(20)
                } else {
                    Duration::from_secs(5)
                };
            let error = ready(
                ToolchainAdmission {
                    cache: &cache,
                    edge_pin: pin,
                    identity,
                    input_root: inputs.path(),
                }
                .prepare(&mut wire, &stopped, deadline, || true),
            )
            .err()
            .expect("polling must not renew admission or discard cancellation");
            assert!(matches!(
                error.kind(),
                io::ErrorKind::Interrupted | io::ErrorKind::TimedOut
            ));
            assert_eq!(fs::read_dir(inputs.path()).unwrap().count(), 0);
            assert!(messages(&output).iter().all(|message| message["kind"] == "queued"));
            assert!(matches!(
                cache.acquire(pin, &identity, || false).unwrap(),
                ToolchainAcquisition::Wait(_)
            ));
        }
    }

    #[test]
    fn reused_sdk_seals_fresh_source_without_any_toolchain_frame() {
        for bytes in [b"new source bytes".as_slice(), b"".as_slice()] {
            let sdk = received_sdk();
            let owner = crate::test_util::private_tempdir();
            let source = source_receiver(owner.path(), bytes);
            let manifest = source.manifest().clone();
            let peer = AdmissionPeer::new(source_upload(bytes));
            let output = Arc::clone(&peer.output);
            let mut wire = Wire::new(peer);
            let (source, retained) = ready(receive_inputs(
                &mut wire,
                source,
                ToolchainInput::Reuse(Arc::clone(&sdk)),
                &AtomicBool::new(false),
                Instant::now() + Duration::from_secs(5),
            ))
            .unwrap();
            assert!(Arc::ptr_eq(&retained, &sdk));
            assert_eq!(source.manifest(), &manifest);
            assert_eq!(
                fs::read(source.sealed_root().unwrap().join("src/lib.rs")).unwrap(),
                bytes
            );
            assert!(!sdk.root().starts_with(owner.path()));
            assert!(!owner.path().join("toolchain").exists());
            assert_eq!(
                messages(&output),
                if bytes.is_empty() {
                    Vec::<Value>::new()
                } else {
                    vec![json!({"kind":"window", "count":1})]
                }
            );
            sdk.verify(|| false).unwrap();
        }
    }

    #[test]
    fn reuse_refuses_incomplete_unacknowledged_or_unrequested_input_bytes() {
        let bytes = b"fresh input";
        let chunk = record(&Message::SourceChunk {
            chunk: Chunk::new("src/lib.rs", 0, bytes).unwrap(),
        });
        let incomplete = record(&Message::SourceChunk {
            chunk: Chunk::new("src/lib.rs", 0, &bytes[..2]).unwrap(),
        });
        let wrong = record(&Message::SourceChunk {
            chunk: Chunk::new("src/lib.rs", 0, b"wrong input").unwrap(),
        });
        let window = record(&Message::WindowEnd { count: 1 });
        let done = record(&Message::InputsDone {});
        for input in [
            done.clone(),
            [chunk, done.clone()].concat(),
            [incomplete, window.clone(), done.clone()].concat(),
            [wrong, window, done].concat(),
            record(&Message::ToolchainEntry {
                entry: wire::Entry::Directory { path: "lib".into() },
            }),
            record(&Message::ToolchainChunk {
                chunk: Chunk::new("compiler-data", 0, b"injected SDK").unwrap(),
            }),
        ] {
            let sdk = received_sdk();
            let owner = crate::test_util::private_tempdir();
            let source = source_receiver(owner.path(), bytes);
            let peer = AdmissionPeer::new(input);
            let output = Arc::clone(&peer.output);
            let mut wire = Wire::new(peer);
            let error = ready(receive_inputs(
                &mut wire,
                source,
                ToolchainInput::Reuse(Arc::clone(&sdk)),
                &AtomicBool::new(false),
                Instant::now() + Duration::from_secs(5),
            ))
            .err()
            .expect("reuse must preserve complete source and fixed SDK custody");
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            assert!(
                messages(&output)
                    .iter()
                    .all(|message| message["kind"] == "window")
            );
            assert_eq!(
                fs::read(sdk.root().join("compiler-data")).unwrap(),
                b"verified SDK"
            );
            sdk.verify(|| false).unwrap();
        }
    }

    #[test]
    fn reused_sdk_mutation_during_source_upload_refuses_without_an_upload_retry() {
        let sdk = received_sdk();
        let owner = crate::test_util::private_tempdir();
        let bytes = b"complete new source";
        let source = source_receiver(owner.path(), bytes);
        let mut peer = AdmissionPeer::new(source_upload(bytes));
        let output = Arc::clone(&peer.output);
        let changed = Arc::clone(&sdk);
        peer.before_read = Some(Box::new(move || {
            let path = changed.root().join("compiler-data");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            fs::write(path, b"tampered SDK").unwrap();
        }));
        let mut wire = Wire::new(peer);
        assert!(
            ready(receive_inputs(
                &mut wire,
                source,
                ToolchainInput::Reuse(sdk),
                &AtomicBool::new(false),
                Instant::now() + Duration::from_secs(5),
            ))
            .is_err()
        );
        assert_eq!(messages(&output), vec![json!({"kind":"window", "count":1})]);
        assert!(!owner.path().join("toolchain").exists());
    }

    #[test]
    fn corrupt_cached_sdk_refuses_before_ready_without_creating_a_replacement() {
        let cache = RemoteToolchainCache::new(1024, 4).unwrap();
        let sdk = received_sdk();
        let pin = [9; 32];
        cache.adopt(pin, Arc::clone(&sdk), || false).unwrap();
        let path = sdk.root().join("compiler-data");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(path, b"tampered SDK").unwrap();
        let inputs = crate::test_util::private_tempdir();
        assert!(
            prepare_toolchain_input(&cache, pin, *sdk.identity(), inputs.path(), || false,)
                .is_err()
        );
        assert_eq!(fs::read_dir(inputs.path()).unwrap().count(), 0);
    }

    #[test]
    fn immediate_remote_admission_holds_capacity_until_owner_drop() {
        let admissions = OperationAdmissions::new(1, 0);
        let peer = AdmissionPeer::new(Vec::new());
        let output = Arc::clone(&peer.output);
        let mut wire = Wire::new(peer);
        let stopped = AtomicBool::new(false);
        let admitted = ready(acquire_operation(
            &mut wire,
            &admissions,
            &stopped,
            Instant::now() + Duration::from_secs(1),
            || true,
        ))
        .unwrap();
        assert!(messages(&output).is_empty());
        assert!(matches!(
            admissions.enqueue(),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock
        ));
        drop(admitted);
        drop(admissions.enqueue().unwrap().try_start().unwrap().unwrap());
    }

    #[test]
    fn remote_poll_admission_preserves_fifo_and_cannot_be_barged() {
        let admissions = OperationAdmissions::new(1, 2);
        let active = admissions.enqueue().unwrap().try_start().unwrap().unwrap();
        let tail = Arc::new(Mutex::new(None));
        let queued_tail = Arc::clone(&tail);
        let peer_admissions = Arc::clone(&admissions);
        let mut peer = AdmissionPeer::new(record(&Message::Poll {}));
        let output = Arc::clone(&peer.output);
        peer.before_read = Some(Box::new(move || {
            *queued_tail.lock().unwrap() = Some(peer_admissions.enqueue().unwrap());
            drop(active);
        }));
        let mut wire = Wire::new(peer);
        let admitted = ready(acquire_operation(
            &mut wire,
            &admissions,
            &AtomicBool::new(false),
            Instant::now() + Duration::from_secs(1),
            || true,
        ))
        .unwrap();
        assert_eq!(messages(&output), vec![json!({"kind":"queued"})]);
        let mut tail = tail.lock().unwrap().take().unwrap();
        assert!(tail.try_start().unwrap().is_none());
        let mut newcomer = admissions.enqueue().unwrap();
        drop(admitted);
        assert!(newcomer.try_start().unwrap().is_none());
        drop(tail.try_start().unwrap().unwrap());
        drop(newcomer.try_start().unwrap().unwrap());
    }

    #[test]
    fn queued_remote_disconnect_cancel_and_early_upload_release_only_their_ticket() {
        for (input, expected) in [
            (Vec::new(), io::ErrorKind::UnexpectedEof),
            (record(&Message::Cancel {}), io::ErrorKind::Interrupted),
            (record(&Message::InputsDone {}), io::ErrorKind::InvalidData),
            (
                record(&Message::SourceChunk {
                    chunk: Chunk::new("src/lib.rs", 0, b"not admitted").unwrap(),
                }),
                io::ErrorKind::InvalidData,
            ),
            (b"not-json\n".to_vec(), io::ErrorKind::InvalidData),
        ] {
            let admissions = OperationAdmissions::new(1, 1);
            let active = admissions.enqueue().unwrap().try_start().unwrap().unwrap();
            let peer = AdmissionPeer::new(input);
            let output = Arc::clone(&peer.output);
            let mut wire = Wire::new(peer);
            let error = ready(acquire_operation(
                &mut wire,
                &admissions,
                &AtomicBool::new(false),
                Instant::now() + Duration::from_secs(1),
                || true,
            ))
            .err()
            .expect("waiting client was not admitted");
            assert_eq!(error.kind(), expected);
            assert_eq!(messages(&output), vec![json!({"kind":"queued"})]);
            let mut successor = admissions.enqueue().unwrap();
            assert!(successor.try_start().unwrap().is_none());
            drop(active);
            drop(successor.try_start().unwrap().unwrap());
        }
    }

    #[test]
    fn remote_queue_refuses_overflow_expiry_and_unhealthy_runtime_before_grant() {
        let admissions = OperationAdmissions::new(1, 1);
        let active = admissions.enqueue().unwrap().try_start().unwrap().unwrap();
        let waiting = admissions.enqueue().unwrap();
        let peer = AdmissionPeer::new(Vec::new());
        let output = Arc::clone(&peer.output);
        let mut wire = Wire::new(peer);
        let error = ready(acquire_operation(
            &mut wire,
            &admissions,
            &AtomicBool::new(false),
            Instant::now() + Duration::from_secs(1),
            || true,
        ))
        .err()
        .unwrap();
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        assert!(messages(&output).is_empty());
        drop(waiting);
        drop(active);
        for (cancelled, healthy, budget, expected) in [
            (false, true, Duration::ZERO, io::ErrorKind::TimedOut),
            (
                true,
                true,
                Duration::from_secs(1),
                io::ErrorKind::Interrupted,
            ),
            (
                false,
                false,
                Duration::from_secs(1),
                io::ErrorKind::Interrupted,
            ),
        ] {
            let error = ready(acquire_operation(
                &mut wire,
                &admissions,
                &AtomicBool::new(cancelled),
                Instant::now() + budget,
                || healthy,
            ))
            .err()
            .unwrap();
            assert_eq!(error.kind(), expected);
            drop(admissions.enqueue().unwrap().try_start().unwrap().unwrap());
        }
    }

    #[test]
    fn queued_remote_runtime_failure_cannot_take_a_newly_freed_slot() {
        let admissions = OperationAdmissions::new(1, 1);
        let active = admissions.enqueue().unwrap().try_start().unwrap().unwrap();
        let healthy = Arc::new(AtomicBool::new(true));
        let peer_health = Arc::clone(&healthy);
        let mut peer = AdmissionPeer::new(record(&Message::Poll {}));
        let output = Arc::clone(&peer.output);
        peer.before_read = Some(Box::new(move || {
            peer_health.store(false, Ordering::Release);
            drop(active);
        }));
        let mut wire = Wire::new(peer);
        let error = ready(acquire_operation(
            &mut wire,
            &admissions,
            &AtomicBool::new(false),
            Instant::now() + Duration::from_secs(1),
            || healthy.load(Ordering::Acquire),
        ))
        .err()
        .unwrap();
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
        assert_eq!(messages(&output), vec![json!({"kind":"queued"})]);
        drop(admissions.enqueue().unwrap().try_start().unwrap().unwrap());
    }

    #[test]
    fn silent_remote_queue_wait_ends_on_original_deadline_or_shutdown_without_peer_wakeup() {
        for cancellation in [false, true] {
            let runtime = RuntimeBuilder::current_thread().build().unwrap();
            let handle = runtime.handle();
            block_on_top_level(&runtime, async move {
                handle
                    .spawn(async move {
                        let admissions = OperationAdmissions::new(1, 1);
                        let active = admissions.enqueue().unwrap().try_start().unwrap().unwrap();
                        let stopped = Arc::new(AtomicBool::new(false));
                        let mut peer = AdmissionPeer::new(Vec::new());
                        peer.eof = false;
                        let output = Arc::clone(&peer.output);
                        let mut wire = Wire::new(peer);
                        let stop_thread = cancellation.then(|| {
                            let stopped = Arc::clone(&stopped);
                            let output = Arc::clone(&output);
                            std::thread::spawn(move || {
                                let deadline = Instant::now() + Duration::from_secs(1);
                                while !output.lock().unwrap().ends_with(b"\n") {
                                    assert!(
                                        Instant::now() < deadline,
                                        "client never entered queue"
                                    );
                                    std::thread::sleep(Duration::from_millis(1));
                                }
                                stopped.store(true, Ordering::Release);
                            })
                        });
                        let budget = if cancellation {
                            Duration::from_secs(1)
                        } else {
                            Duration::from_millis(20)
                        };
                        let error = asupersync::time::timeout(
                            runtime_transport_now(),
                            Duration::from_secs(2),
                            acquire_operation(
                                &mut wire,
                                &admissions,
                                &stopped,
                                Instant::now() + budget,
                                || true,
                            ),
                        )
                        .await
                        .expect("queue control did not wake silent peer")
                        .err()
                        .expect("quiet waiter must not start work");
                        if let Some(thread) = stop_thread {
                            thread.join().unwrap();
                        }
                        assert_eq!(
                            error.kind(),
                            if cancellation {
                                io::ErrorKind::Interrupted
                            } else {
                                io::ErrorKind::TimedOut
                            }
                        );
                        assert_eq!(messages(&output), vec![json!({"kind":"queued"})]);
                        let mut successor = admissions.enqueue().unwrap();
                        assert!(successor.try_start().unwrap().is_none());
                        drop(active);
                        drop(successor.try_start().unwrap().unwrap());
                    })
                    .await
            });
        }
    }

    #[test]
    fn generated_remote_request_contains_only_bound_logical_intent() {
        let settings = serde_json::from_value(json!({"command":"check", "jobs":2,
            "env":{"FEATURE_INPUT":"enabled"}}))
        .unwrap();
        let source = SourceManifest::new(vec![SourceFile {
            path: "Cargo.toml".into(),
            len: 1,
            sha256: Sha256::digest(b"x").into(),
            executable: false,
        }])
        .unwrap();
        let toolchain = ToolchainIdentity {
            sha256: [7; 32],
            files: 2,
            bytes: 5,
        };
        let request = prepared_request(
            &settings,
            Path::new("/private/server-owned/sdk"),
            &Manifest::from_native(&source),
            &wire::Toolchain::from_native(&toolchain),
            &None,
        )
        .unwrap();
        assert_eq!(
            request,
            prepared_request(
                &settings,
                Path::new("/different/input-owner/toolchain"),
                &Manifest::from_native(&source),
                &wire::Toolchain::from_native(&toolchain),
                &None,
            )
            .unwrap(),
            "validating the declaration before capture allocation cannot retain a physical path"
        );
        let encoded = request.to_string();
        assert!(!encoded.contains("/private/server-owned"));
        assert!(!encoded.contains("toolchain_source"));
        assert!(!encoded.contains("cargo_source"));
        assert_eq!(
            source_manifest::request_manifest(&request).unwrap(),
            Some(source)
        );
        assert_eq!(
            worker_delivery::toolchain_identity(&request).unwrap(),
            Some(toolchain)
        );
        assert_eq!(
            request["command_context"]["env"]["FEATURE_INPUT"],
            "enabled"
        );
    }

    #[test]
    fn output_reads_preserve_binary_bytes_and_reject_truncation() {
        use std::io::Write;
        let parent = tempfile::tempdir().unwrap();
        let mut file = output_file(parent.path(), "stdout").unwrap();
        file.write_all(b"x\0\xff").unwrap();
        let mut offset = 0;
        let chunk = read_output(&file, &mut offset).unwrap();
        assert_eq!(wire::decode_hex(&chunk.bytes, 3).unwrap(), b"x\0\xff");
        assert_eq!(chunk.offset, 0);
        assert_eq!(offset, 3);
        assert!(read_output(&file, &mut offset).unwrap().bytes.is_empty());
        file.set_len(1).unwrap();
        assert!(read_output(&file, &mut offset).is_err());
    }
}
