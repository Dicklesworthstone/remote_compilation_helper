//! Authenticated cross-host access to one persistent canonical Cargo runtime.
//!
//! Cargo executes at the coordinator. Independent clients share its existing
//! dependency engine, root permits and publication authority, while each owns
//! separate inputs, diagnostics, cancellation and artifact delivery. The local
//! path-based Unix service is deliberately not used as a network protocol.

mod client;
mod operations;
mod source_inputs;
mod toolchain_inputs;
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
use operations::{Attachment, Claim, DiagnosticFrontier, Registry};
use rabs_asupersync::daemon_runtime::block_on_top_level;
use rabs_asupersync::worker_transport::{TlsFiles, accept_edge_peer, runtime_transport_now};
use rabs_protocol::raw_bytes::encode_hex;
use rabs_protocol::release_authorization::ReleaseAuthorizationMode;
use rabs_sandbox::source_cache::MAX_SOURCE_CACHE_BYTES;
use rabs_sandbox::source_transfer::{MAX_SOURCE_CHUNK, SourceFile, SourceReceiver};
use rabs_sandbox::toolchain_dataset::{ToolchainIdentity, ToolchainLimits};
use rabs_sandbox::toolchain_file_cache::MAX_TOOLCHAIN_FILE_CACHE_BYTES;
use rabs_sandbox::toolchain_transfer::{
    TOOLCHAIN_INPUT_BUDGET, TOOLCHAIN_TRANSFER_VERSION, ToolchainReceiver,
};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use source_inputs::{RemoteSourceCache, SourceInput};
use std::fs::{self, File, OpenOptions};
use std::io;
use std::net::SocketAddr;
use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use toolchain_inputs::{RemoteToolchainFileCache, ToolchainFileInput};
use wire::{
    ARTIFACT_PAGE_FILES, ArtifactDeclaration, ArtifactPage, ArtifactPlan, Chunk, Manifest, Message,
    OperationToken, Output, SourceDeclaration, SourcePages, ToolchainDisposition, WIRE_VERSION,
    Window, Wire, checkpoint, digest, invalid, require,
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
    /// Retain verified source bytes under one authenticated-peer-aware budget.
    #[serde(default)]
    source_cache_bytes: u64,
    /// Retain only verified SDKs, independently of each operation's source.
    #[serde(default)]
    toolchain_cache_bytes: u64,
    #[serde(default = "default_toolchain_cache_entries")]
    toolchain_cache_entries: usize,
    /// Optional completed-file and prefix reuse under one shared peer-scoped
    /// budget, separate from complete-image retention.
    #[serde(default)]
    toolchain_file_cache_bytes: u64,
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
            self.source_cache_bytes <= MAX_SOURCE_CACHE_BYTES,
            "remote source cache must be at most 8 GiB",
        )?;
        require(
            self.toolchain_cache_bytes <= 64 * 1024 * 1024 * 1024
                && (1..=32).contains(&self.toolchain_cache_entries),
            "remote toolchain cache must be at most 64 GiB and between 1 and 32 entries",
        )?;
        require(
            self.toolchain_file_cache_bytes <= MAX_TOOLCHAIN_FILE_CACHE_BYTES,
            "remote toolchain file cache must be at most 64 GiB",
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
        // A failed transport may not yet have observed EOF when its client
        // reconnects. Headroom grants no extra operation or input permits.
        2 * self.max_roots + self.max_queued_roots
    }
}

/// Reuse budgets belong to the service, not to individual connections or peers.
struct InputCaches {
    toolchains: RemoteToolchainCache,
    toolchain_files: Option<RemoteToolchainFileCache>,
    sources: Option<RemoteSourceCache>,
}

impl InputCaches {
    fn new(config: &ServiceProfile) -> io::Result<Self> {
        let toolchains = RemoteToolchainCache::new(
            config.toolchain_cache_bytes,
            config.toolchain_cache_entries,
        )?;
        let sources = if config.source_cache_bytes == 0 {
            None
        } else {
            Some(RemoteSourceCache::new(
                &config.input_root,
                config.source_cache_bytes,
            )?)
        };
        let toolchain_files = if config.toolchain_file_cache_bytes == 0 {
            None
        } else {
            Some(RemoteToolchainFileCache::new(
                &config.input_root,
                config.toolchain_file_cache_bytes,
            )?)
        };
        Ok(Self {
            toolchains,
            toolchain_files,
            sources,
        })
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
    fn cancel_all(&self) {
        for session in &self.0 {
            session.stopped.store(true, Ordering::Release);
        }
    }

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
        self.cancel_all();
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
    // Finish fallible cache setup before starting the coordinator's threads.
    let caches = Arc::new(InputCaches::new(&config)?);
    let runtime = SharedRuntime::start(
        &config.state_root,
        release_mode,
        build_identity.clone(),
        config.max_roots,
        config.jobs_per_root,
    )?;
    let admissions = OperationAdmissions::new(config.max_roots, config.max_queued_roots);
    let operations = match runtime
        .coord
        .authority()
        .ok_or_else(|| invalid("remote canonical coordinator has no active authority"))
        .and_then(|authority| {
            Registry::<RemoteBuild>::new(authority, config.max_roots, wire::RESUME_GRACE)
        }) {
        Ok(operations) => operations,
        Err(error) => {
            let _ = runtime.shutdown();
            return Err(error);
        }
    };
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
        "source_cache_bytes":config.source_cache_bytes,
        "toolchain_cache_bytes":config.toolchain_cache_bytes,
        "toolchain_file_cache_bytes":config.toolchain_file_cache_bytes,
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
        operations.reap(Instant::now());
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
            // admission took place. Only an already issued operation token
            // can reattach; a new command is never automatically replayed.
            drop(stream);
            continue;
        }
        let stopped = Arc::new(AtomicBool::new(false));
        let child_stop = Arc::clone(&stopped);
        let child_config = Arc::clone(&config);
        let child_runtime = Arc::clone(&runtime);
        let child_admissions = Arc::clone(&admissions);
        let child_operations = Arc::clone(&operations);
        let child_caches = Arc::clone(&caches);
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
                        &child_operations,
                        &child_caches,
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
    // Stop queued and pre-Ready sessions before releasing any retained permit.
    // Detached owners may take time to join; no waiting caller should acquire
    // a fresh input tree while that drain is in progress.
    sessions.cancel_all();
    operations.shutdown();
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
    worker_delivery::validate_local_canonical_request(&request)?;
    source_manifest::request_manifest(&request)?;
    Ok(request)
}

/// A transfer decision retains its exact SDK custody through source upload.
/// Announcing reuse cannot later select a receiver or another cached image.
enum ToolchainInput {
    Upload {
        receiver: Box<ToolchainReceiver>,
        owner: Arc<tempfile::TempDir>,
        files: Option<Box<ToolchainFileInput>>,
    },
    Reuse(Arc<ReceivedToolchain>),
}

impl ToolchainInput {
    fn disposition(&self) -> ToolchainDisposition {
        match self {
            Self::Upload { files: Some(_), .. } => ToolchainDisposition::UploadFiles,
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
    file_cache: Option<&'a RemoteToolchainFileCache>,
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
        let cancelled =
            || stopped.load(Ordering::Acquire) || !healthy() || Instant::now() >= deadline;
        loop {
            match self
                .cache
                .acquire(self.edge_pin, &self.identity, cancelled)?
            {
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
                    let files = self
                        .file_cache
                        .map(|cache| cache.for_peer(self.edge_pin, self.identity, &cancelled))
                        .transpose()?
                        .map(Box::new);
                    checkpoint(stopped, deadline)?;
                    require(healthy(), "remote coordinator stopped before SDK upload")?;
                    return Ok((
                        ToolchainInput::Upload {
                            receiver: Box::new(receiver),
                            owner,
                            files,
                        },
                        Some(publisher),
                    ));
                }
                ToolchainAcquisition::Wait(waiter) => loop {
                    match waiter.poll(cancelled)? {
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

/// Execution and publication custody outlive a transport attachment. Field
/// order drains the writer before releasing its input owner/admission permit.
struct RemoteBuild {
    operation: Option<remote_operation::RemoteOperationOwner>,
    outcome: Option<RemoteOperationOutcome>,
    target: Option<CapturedTarget>,
    stdout: File,
    stderr: File,
    diagnostics: DiagnosticFrontier,
    delivery_deadline: Option<Instant>,
    commit_authorized: bool,
    _owner: Arc<tempfile::TempDir>,
    _admission: AdmittedOperation,
}

#[allow(clippy::too_many_arguments)]
async fn handle_session<S: AsyncRead + AsyncWrite + Unpin>(
    wire: &mut Wire<S>,
    runtime: Arc<SharedRuntime>,
    config: &ServiceProfile,
    admissions: &Arc<OperationAdmissions>,
    operations: &Arc<Registry<RemoteBuild>>,
    caches: &InputCaches,
    edge_pin: [u8; 32],
    stopped: &Arc<AtomicBool>,
) -> io::Result<()> {
    let declaration_deadline = Instant::now() + wire::IO_BUDGET;
    let first = wire.receive(stopped, declaration_deadline).await?;
    if let Message::CancelOperation {
        version,
        build_identity,
        require_release,
        token,
    } = first
    {
        require_wire_identity(&version, &build_identity, &runtime.build_identity)?;
        require(
            !require_release || runtime.release_mode == ReleaseAuthorizationMode::Required,
            "remote service cannot downgrade required release authorization",
        )?;
        let authority = runtime
            .coord
            .authority()
            .ok_or_else(|| invalid("remote canonical coordinator has no active authority"))?;
        operations.cancel(&authority, edge_pin, &token.native()?)?;
        return wire
            .send(&Message::Cancelled {}, stopped, declaration_deadline)
            .await;
    }
    if let Message::Resume {
        version,
        build_identity,
        require_release,
        token,
        stdout_offset,
        stderr_offset,
    } = first
    {
        require_wire_identity(&version, &build_identity, &runtime.build_identity)?;
        require(
            !require_release || runtime.release_mode == ReleaseAuthorizationMode::Required,
            "remote service cannot downgrade required release authorization",
        )?;
        require(
            runtime.healthy(),
            "remote canonical coordinator is unavailable",
        )?;
        let authority = runtime
            .coord
            .authority()
            .ok_or_else(|| invalid("remote canonical coordinator has no active authority"))?;
        return match operations.claim(
            &authority,
            edge_pin,
            &token.native()?,
            Arc::clone(stopped),
            Instant::now(),
        )? {
            Claim::Pending => {
                wire.send(&Message::ResumePending {}, stopped, declaration_deadline)
                    .await
            }
            Claim::Attached(operation) => {
                serve_attachment(
                    wire,
                    &runtime,
                    operation,
                    stopped,
                    (stdout_offset, stderr_offset),
                )
                .await
            }
        };
    }
    let Message::Hello {
        version,
        build_identity,
        require_release,
        settings,
        source_manifest,
        toolchain_identity,
        cargo_home,
    } = first
    else {
        return Err(invalid("remote operation must begin with hello or resume"));
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
    let identity = toolchain_identity.native()?;
    let manifest =
        receive_source_manifest(wire, source_manifest, stopped, declaration_deadline).await?;
    // The synthesized request discards physical capture paths. Validate its
    // complete logical declaration before reserving work or creating any tree.
    let request = prepared_request(
        &settings,
        &config.input_root.join("toolchain"),
        &Manifest::from_native(&manifest),
        &toolchain_identity,
        &cargo_home,
    )?;
    let queue_deadline = Instant::now()
        .checked_add(Duration::from_secs(config.queue_timeout_seconds))
        .ok_or_else(|| invalid("remote operation admission deadline overflow"))?;
    // Keep this permit through input custody, execution, final delivery and
    // every error/drop path. It is separate from the existing Cargo root token.
    let admission = acquire_operation(wire, admissions, stopped, queue_deadline, || {
        runtime.healthy()
    })
    .await?;
    let (toolchain, publisher) = ToolchainAdmission {
        cache: &caches.toolchains,
        file_cache: caches.toolchain_files.as_ref(),
        edge_pin,
        identity,
        input_root: &config.input_root,
    }
    .prepare(wire, stopped, queue_deadline, || runtime.healthy())
    .await?;
    let owner = Arc::new(
        tempfile::Builder::new()
            .prefix("canonical-remote-input-")
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir_in(&config.input_root)?,
    );
    let source = SourceReceiver::create(&owner.path().join("source"), manifest)?;
    let source_cache = caches
        .sources
        .as_ref()
        .map(|cache| cache.for_peer(edge_pin, Arc::clone(stopped), queue_deadline))
        .transpose()?;
    let source = SourceInput::prepare(source, source_cache, || {
        stopped.load(Ordering::Acquire) || !runtime.healthy() || Instant::now() >= queue_deadline
    })?;
    checkpoint(stopped, queue_deadline)?;
    require(
        runtime.healthy(),
        "remote coordinator stopped before input admission",
    )?;
    // Both SDK handoff and verified source prefill use the original admission
    // deadline. Only completed readiness grants one fresh input-transfer budget.
    let input_deadline = Instant::now() + TOOLCHAIN_INPUT_BUDGET;
    // Issue the resume credential before the client can attempt InputsDone.
    // Only this reservation's original input owner can activate execution.
    let reservation = operations.reserve(
        edge_pin,
        Arc::clone(stopped),
        input_deadline,
        Instant::now(),
    )?;
    let cancelled = || {
        stopped.load(Ordering::Acquire) || !runtime.healthy() || Instant::now() >= input_deadline
    };
    let disposition = toolchain.disposition();
    wire.send(
        &Message::Ready {
            toolchain: disposition,
            source: source.plan().clone(),
            resume: OperationToken::from_native(reservation.token()),
        },
        stopped,
        input_deadline,
    )
    .await?;
    let (source, toolchain) =
        receive_inputs(wire, source, toolchain, stopped, input_deadline).await?;
    let toolchain = match disposition {
        ToolchainDisposition::Upload | ToolchainDisposition::UploadFiles => {
            caches.toolchains.adopt(edge_pin, toolchain, cancelled)?
        }
        ToolchainDisposition::Reuse => toolchain,
    };
    if let Some(publisher) = publisher {
        // Only the exact sealed SDK crosses this handoff. The publisher leaves
        // the pending registry before existing waiters receive its lease.
        publisher.publish(Arc::clone(&toolchain), cancelled)?;
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
    // Execution belongs to the reservation before Accepted can be lost. The
    // resume path above can only take this owner, never call start again.
    let operation = remote_operation::start(
        Arc::clone(&runtime),
        config.wrapper.clone(),
        config.operation_root.clone(),
        config.target_cache.clone(),
        inputs,
        *settings,
        stdout.try_clone()?,
        stderr.try_clone()?,
        reservation.operation_stop(),
        OUTPUT_BYTES,
    )?;
    let operation = reservation.activate(
        RemoteBuild {
            operation: Some(operation),
            outcome: None,
            target: None,
            stdout,
            stderr,
            diagnostics: DiagnosticFrontier::default(),
            delivery_deadline: None,
            commit_authorized: false,
            _owner: owner,
            _admission: admission,
        },
        execution_deadline,
        Instant::now(),
    )?;
    serve_attachment(wire, &runtime, operation, stopped, (0, 0)).await
}

/// One transport may expose one complete diagnostic record at a time. Only
/// transport failures explicitly detach; every other exit cancels and joins.
async fn serve_attachment<S: AsyncRead + AsyncWrite + Unpin>(
    wire: &mut Wire<S>,
    runtime: &SharedRuntime,
    mut operation: Attachment<RemoteBuild>,
    stopped: &AtomicBool,
    exposed: (u64, u64),
) -> io::Result<()> {
    let operation_stop = operation.operation_stop();
    let result = serve_attached(wire, runtime, &mut operation, stopped, exposed).await;
    if let Err(error) = &result
        && wire.can_resume_after(error)
        && !stopped.load(Ordering::Acquire)
        && !operation_stop.load(Ordering::Acquire)
        && runtime.healthy()
        && Instant::now() < operation.deadline()
    {
        operation.detach(Instant::now())?;
    }
    result
}

async fn serve_attached<S: AsyncRead + AsyncWrite + Unpin>(
    wire: &mut Wire<S>,
    runtime: &SharedRuntime,
    operation: &mut Attachment<RemoteBuild>,
    stopped: &AtomicBool,
    exposed: (u64, u64),
) -> io::Result<()> {
    operation.diagnostics.reattach(exposed)?;
    let execution_deadline = operation.deadline();
    wire.send(&Message::Accepted {}, stopped, execution_deadline)
        .await?;
    let (stdout_offset, stderr_offset) = loop {
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
        let (mut stdout_offset, mut stderr_offset) = operation.diagnostics.acknowledge_poll();
        if operation
            .operation
            .as_ref()
            .is_some_and(remote_operation::RemoteOperationOwner::finished)
        {
            operation.outcome = Some(
                operation
                    .operation
                    .take()
                    .expect("finished operation is owned")
                    .join()?,
            );
        }
        let stdout_chunk = read_output(&operation.stdout, &mut stdout_offset)?;
        let stderr_chunk = read_output(&operation.stderr, &mut stderr_offset)?;
        operation.diagnostics.offer(stdout_offset, stderr_offset)?;
        if !stdout_chunk.bytes.is_empty()
            || !stderr_chunk.bytes.is_empty()
            || operation.outcome.is_none()
        {
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
        break (stdout_offset, stderr_offset);
    };
    let delivery_deadline = operation
        .delivery_deadline
        .unwrap_or_else(|| (Instant::now() + DELIVERY_BUDGET).min(execution_deadline));
    operation.shorten_deadline(delivery_deadline);
    let operation_stop = operation.operation_stop();
    let cancelled = || {
        stopped.load(Ordering::Acquire)
            || operation_stop.load(Ordering::Acquire)
            || !runtime.healthy()
            || Instant::now() >= delivery_deadline
    };
    if operation.delivery_deadline.is_none() {
        let outcome = operation
            .outcome
            .as_ref()
            .ok_or_else(|| invalid("remote operation completed without its owner"))?;
        operation.target = outcome
            .retained_target
            .as_deref()
            .map(|path| CapturedTarget::capture(path, &cancelled))
            .transpose()?;
        operation.delivery_deadline = Some(delivery_deadline);
    }
    let outcome = operation
        .outcome
        .as_ref()
        .ok_or_else(|| invalid("remote operation completed without its owner"))?;
    outcome.verify_before_delivery(&cancelled)?;
    checkpoint(stopped, delivery_deadline)?;
    wire.send(
        &Message::BuildFinished {
            exit_code: outcome.exit_code,
            stdout_bytes: stdout_offset,
            stderr_bytes: stderr_offset,
            target: operation
                .target
                .as_ref()
                .map(|target| ArtifactDeclaration::from_native(target.manifest())),
        },
        stopped,
        delivery_deadline,
    )
    .await?;
    deliver_result(wire, operation, stopped, delivery_deadline, &cancelled).await
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

/// Receive metadata only, before operation/SDK admission or any source tree
/// creation. Missing/duplicate pages, malformed windows, early payloads and a
/// mismatched complete identity refuse without starting a build.
async fn receive_source_manifest<S: AsyncRead + AsyncWrite + Unpin>(
    wire: &mut Wire<S>,
    declaration: SourceDeclaration,
    stopped: &AtomicBool,
    deadline: Instant,
) -> io::Result<rabs_sandbox::source_transfer::SourceManifest> {
    let mut pages = SourcePages::new(declaration)?;
    let mut window = Window::default();
    loop {
        match wire.receive(stopped, deadline).await? {
            Message::SourceManifestPage { page } => {
                window.record()?;
                pages.push(page)?;
            }
            Message::WindowEnd { count } => {
                window.acknowledge(count)?;
                wire.send(&Message::Window { count }, stopped, deadline)
                    .await?;
            }
            Message::SourceManifestEnd {} => {
                require(
                    !window.pending(),
                    "remote source manifest ended before its last window acknowledgment",
                )?;
                checkpoint(stopped, deadline)?;
                return pages.finish();
            }
            _ => {
                return Err(invalid(
                    "unexpected message during remote source manifest transfer",
                ));
            }
        }
    }
}

/// The same finite upload receiver serves production sessions and native
/// transport tests. Only sealed byte owners can cross into execution admission.
async fn receive_inputs<S: AsyncRead + AsyncWrite + Unpin>(
    wire: &mut Wire<S>,
    mut source: SourceInput,
    mut toolchain: ToolchainInput,
    stopped: &AtomicBool,
    input_deadline: Instant,
) -> io::Result<(SourceReceiver, Arc<ReceivedToolchain>)> {
    checkpoint(stopped, input_deadline)?;
    source.begin_transfer(input_deadline)?;
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
                source.write_chunk(&chunk.path, chunk.offset, &bytes, sha256, cancelled)?;
            }
            Message::ToolchainFilePage { page } => {
                require(
                    !window.pending(),
                    "SDK file negotiation preceded source window acknowledgment",
                )?;
                let ToolchainInput::Upload {
                    files: Some(files), ..
                } = &mut toolchain
                else {
                    return Err(invalid("SDK file reuse was not admitted"));
                };
                if !source_finished {
                    source.seal(cancelled)?;
                    source_finished = true;
                }
                let plan = files.page(&page, &cancelled)?;
                wire.send(
                    &Message::ToolchainFilePlan { plan },
                    stopped,
                    input_deadline,
                )
                .await?;
            }
            Message::ToolchainFilesEnd {} => {
                require(
                    source_finished && !window.pending(),
                    "SDK file inventory ended before its transfer phase",
                )?;
                let ToolchainInput::Upload {
                    files: Some(files), ..
                } = &mut toolchain
                else {
                    return Err(invalid("SDK file reuse was not admitted"));
                };
                let (files, bytes) = files.seal_manifest(&cancelled)?;
                wire.send(
                    &Message::ToolchainFilesReady { files, bytes },
                    stopped,
                    input_deadline,
                )
                .await?;
            }
            Message::ToolchainFilesDecline {} => {
                require(
                    !window.pending(),
                    "SDK file decline preceded source window acknowledgment",
                )?;
                let ToolchainInput::Upload { files, .. } = &mut toolchain else {
                    return Err(invalid("SDK file reuse was not admitted"));
                };
                require(
                    files.as_ref().is_some_and(|files| files.can_decline()),
                    "SDK file reuse can be declined only before its first page",
                )?;
                if !source_finished {
                    source.seal(cancelled)?;
                    source_finished = true;
                }
                files.take();
                wire.send(&Message::ToolchainFilesDeclined {}, stopped, input_deadline)
                    .await?;
            }
            Message::ToolchainEntry { entry } => {
                let ToolchainInput::Upload {
                    receiver, files, ..
                } = &mut toolchain
                else {
                    return Err(invalid(
                        "SDK entries are forbidden after toolchain reuse admission",
                    ));
                };
                require(
                    files.is_none(),
                    "negotiated SDK files require explicit prefix selections",
                )?;
                window.record()?;
                if !source_finished {
                    source.seal(cancelled)?;
                    source_finished = true;
                }
                receiver.entry(entry.native())?;
            }
            Message::ToolchainResumedEntry { entry, resume } => {
                let ToolchainInput::Upload {
                    receiver,
                    files: Some(files),
                    ..
                } = &mut toolchain
                else {
                    return Err(invalid("SDK prefix selection was not admitted"));
                };
                require(
                    source_finished,
                    "SDK entries arrived before their file inventory",
                )?;
                window.record()?;
                files.entry(receiver, entry.native(), resume, &cancelled)?;
            }
            Message::ToolchainChunk { chunk } => {
                let ToolchainInput::Upload {
                    receiver, files, ..
                } = &mut toolchain
                else {
                    return Err(invalid(
                        "SDK bytes are forbidden after toolchain reuse admission",
                    ));
                };
                require(source_finished, "toolchain bytes arrived before its entry")?;
                window.record()?;
                let (bytes, sha256) = chunk.verified_bytes()?;
                if let Some(files) = files {
                    files.write_chunk(
                        receiver,
                        &chunk.path,
                        chunk.offset,
                        &bytes,
                        sha256,
                        &cancelled,
                    )?;
                } else {
                    receiver.write_chunk(&chunk.path, chunk.offset, &bytes, sha256)?;
                }
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
                    // Reuse skips only requested network bytes. Source still
                    // crosses the complete manifest/byte sealing boundary.
                    source.seal(cancelled)?;
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
            mut files,
        } => {
            if let Some(files) = &mut files {
                files.finish(&cancelled)?;
            }
            Arc::new(ReceivedToolchain::new(
                owner,
                Arc::new(receiver.seal(cancelled)?),
                cancelled,
            )?)
        }
        ToolchainInput::Reuse(lease) => {
            // Recheck the exact owner pinned before Ready. Corruption or
            // cancellation cannot trigger a hidden upload or a different hit.
            lease.verify(cancelled)?;
            lease
        }
    };
    let source = source.finish(cancelled)?;
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
    operation: &mut RemoteBuild,
    stopped: &AtomicBool,
    deadline: Instant,
    cancelled: &impl Fn() -> bool,
) -> io::Result<()> {
    let outcome = operation
        .outcome
        .as_ref()
        .ok_or_else(|| invalid("remote operation completed without its owner"))?;
    if let Some(target) = &operation.target {
        require(
            outcome.exit_code == 0,
            "failed compilation cannot publish a target",
        )?;
        let receipt = deliver_artifacts(
            wire,
            target,
            stopped,
            deadline,
            cancelled,
            operation.commit_authorized,
        )
        .await?;
        if let ArtifactDelivery::Sealed(manifest_sha256) = receipt {
            outcome.verify_before_delivery(cancelled)?;
            // Retain authorization before attempting the write. A surviving
            // client may have installed the exact target even if the response
            // or its acknowledgment never reached this connection.
            operation.commit_authorized = true;
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
        }
        target.verify(cancelled)?;
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
    .await?;
    // The client can recover a lost Complete while this owner still exists.
    // A lost Delivered only retains bounded custody; it never reruns Cargo.
    require(
        matches!(
            wire.receive(stopped, deadline).await?,
            Message::Delivered {}
        ),
        "expected terminal delivery acknowledgment",
    )
}

#[derive(Debug, PartialEq, Eq)]
enum ArtifactDelivery {
    Sealed(String),
    Published,
}

/// Transfer only the requested payloads, but retain the complete captured
/// target through its final byte check. Client reuse never supplies producer
/// authority or waives the existing Commit/Published/Complete exchange.
async fn deliver_artifacts<S: AsyncRead + AsyncWrite + Unpin>(
    wire: &mut Wire<S>,
    target: &CapturedTarget,
    stopped: &AtomicBool,
    deadline: Instant,
    cancelled: &impl Fn() -> bool,
    commit_authorized: bool,
) -> io::Result<ArtifactDelivery> {
    let request = wire.receive(stopped, deadline).await?;
    if let Message::Published { manifest_sha256 } = request {
        require(
            commit_authorized && digest(&manifest_sha256)? == target.manifest().digest(),
            "installed artifact receipt lacks the original commit authorization",
        )?;
        target.verify(cancelled)?;
        return Ok(ArtifactDelivery::Published);
    }
    require(
        matches!(request, Message::ReceiveTarget {}),
        "client did not accept the declared target",
    )?;
    send_artifact_manifest(wire, target.manifest(), stopped, deadline).await?;
    let Message::ReceiveArtifacts {
        manifest_sha256,
        missing_files,
        prefixes,
        file_index,
        offset,
    } = wire.receive_until(stopped, deadline).await?
    else {
        return Err(invalid(
            "client did not validate the complete artifact manifest",
        ));
    };
    // Validate the entire request before reading or sending any payload. A
    // malicious subset cannot create extra files, repeat bytes or select a
    // path from another target generation.
    let plan =
        ArtifactPlan::from_request(manifest_sha256, missing_files, prefixes, target.manifest())?;
    plan.validate_cursor(target.manifest(), file_index, offset)?;
    let mut window = Window::default();
    for &index in &plan.missing_files {
        if u32::from(index) < file_index {
            continue;
        }
        let file = &target.manifest().files()[usize::from(index)];
        // Accepted bytes belong to the retained live receiver. An original
        // optional prefix offer must never rewind or jump over this cursor.
        // Only an untouched file may select its frozen hint again.
        let mut offset = if u32::from(index) == file_index && offset != 0 {
            offset
        } else {
            artifact_prefix_offset(
                target,
                file,
                plan.prefix_for(usize::from(index)),
                stopped,
                deadline,
                cancelled,
            )?
        };
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
    let Message::Received {
        manifest_sha256: received,
    } = wire.receive_until(stopped, deadline).await?
    else {
        return Err(invalid("client did not seal the complete target"));
    };
    require(
        received == plan.manifest_sha256,
        "client sealed a different target manifest",
    )?;
    // Include every locally reused member, not just the files read above.
    target.verify(cancelled)?;
    Ok(ArtifactDelivery::Sealed(plan.manifest_sha256))
}

/// An offer saves network bytes only when the producer independently confirms
/// the exact retained prefix. The first nonempty payload selects that offset;
/// a mismatch simply sends the whole file. Nothing here grants result authority.
fn artifact_prefix_offset(
    target: &CapturedTarget,
    file: &SourceFile,
    offered: Option<&wire::ArtifactPrefixOffer>,
    stopped: &AtomicBool,
    deadline: Instant,
    cancelled: &impl Fn() -> bool,
) -> io::Result<u64> {
    checkpoint(stopped, deadline)?;
    let Some(offered) = offered else {
        return Ok(0);
    };
    require(
        offered.offset != 0 && offered.offset < file.len,
        "artifact prefix must leave a nonempty payload tail",
    )?;
    let expected = wire::digest(&offered.sha256)?;
    let mut hash = Sha256::new();
    let mut offset = 0;
    while offset < offered.offset {
        checkpoint(stopped, deadline)?;
        let count = (offered.offset - offset).min(MAX_SOURCE_CHUNK as u64) as usize;
        let bytes = target.read_chunk(&file.path, offset, count, cancelled)?;
        require(
            bytes.len() == count,
            "artifact source ended before its offered prefix",
        )?;
        hash.update(&bytes);
        offset += bytes.len() as u64;
    }
    checkpoint(stopped, deadline)?;
    Ok(if <[u8; 32]>::from(hash.finalize()) == expected {
        offered.offset
    } else {
        0
    })
}

async fn send_artifact_manifest<S: AsyncRead + AsyncWrite + Unpin>(
    wire: &mut Wire<S>,
    manifest: &rabs_sandbox::source_transfer::ArtifactManifest,
    stopped: &AtomicBool,
    deadline: Instant,
) -> io::Result<()> {
    let mut window = Window::default();
    for (index, files) in manifest.files().chunks(ARTIFACT_PAGE_FILES).enumerate() {
        checkpoint(stopped, deadline)?;
        wire.send(
            &Message::ArtifactManifestPage {
                page: ArtifactPage::from_native(index * ARTIFACT_PAGE_FILES, files)?,
            },
            stopped,
            deadline,
        )
        .await?;
        if window.record()? {
            send_window(wire, &mut window, stopped, deadline).await?;
        }
    }
    send_window(wire, &mut window, stopped, deadline).await?;
    wire.send(&Message::ArtifactManifestEnd {}, stopped, deadline)
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use asupersync::io::ReadBuf;
    use rabs_sandbox::source_transfer::{SourceFile, SourceManifest};
    use rabs_sandbox::toolchain_dataset::ToolchainIdentity;
    use sha2::{Digest, Sha256};
    use std::collections::BTreeMap;
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
        assert_eq!(profile.source_cache_bytes, 0);
        assert_eq!(profile.toolchain_cache_bytes, 0);
        assert_eq!(profile.toolchain_cache_entries, 4);
        assert_eq!(profile.toolchain_file_cache_bytes, 0);
        assert!(profile.target_cache.is_none());
        assert_eq!(profile.max_sessions(), 4);
        profile.validate().unwrap();
        profile.max_roots = 32;
        profile.max_queued_roots = 128;
        profile.queue_timeout_seconds = 1800;
        profile.validate().unwrap();
        assert_eq!(profile.max_sessions(), 192);
        profile.max_queued_roots = 129;
        assert!(profile.validate().is_err());
        profile.max_queued_roots = 128;
        for timeout in [0, 1801, u64::MAX] {
            profile.queue_timeout_seconds = timeout;
            assert!(profile.validate().is_err(), "timeout {timeout}");
        }
        profile.queue_timeout_seconds = 300;
        profile.source_cache_bytes = MAX_SOURCE_CACHE_BYTES;
        profile.validate().unwrap();
        for bytes in [MAX_SOURCE_CACHE_BYTES + 1, u64::MAX] {
            profile.source_cache_bytes = bytes;
            assert!(profile.validate().is_err(), "source cache bytes {bytes}");
        }
        profile.source_cache_bytes = 0;
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
        profile.toolchain_cache_bytes = 0;
        profile.toolchain_file_cache_bytes = MAX_TOOLCHAIN_FILE_CACHE_BYTES;
        profile.validate().unwrap();
        for bytes in [MAX_TOOLCHAIN_FILE_CACHE_BYTES + 1, u64::MAX] {
            profile.toolchain_file_cache_bytes = bytes;
            assert!(profile.validate().is_err(), "SDK file cache bytes {bytes}");
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
    fn remote_delivery_requires_v10_wire_and_exact_build_identity() {
        require_wire_identity("canonical-compile-remote-v10", "build-one", "build-one").unwrap();
        for (version, identity) in [
            ("canonical-compile-remote-v1", "build-one"),
            ("canonical-compile-remote-v2", "build-one"),
            ("canonical-compile-remote-v3", "build-one"),
            ("canonical-compile-remote-v4", "build-one"),
            ("canonical-compile-remote-v5", "build-one"),
            ("canonical-compile-remote-v6", "build-one"),
            ("canonical-compile-remote-v7", "build-one"),
            ("canonical-compile-remote-v8", "build-one"),
            ("canonical-compile-remote-v9", "build-one"),
            ("canonical-compile-remote-v10", "build-two"),
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

    fn paged_source(count: usize) -> SourceManifest {
        SourceManifest::new(
            (0..count)
                .map(|index| SourceFile {
                    path: format!("workspace/src/{index:04}.rs"),
                    len: 0,
                    sha256: Sha256::digest([]).into(),
                    executable: false,
                })
                .collect(),
        )
        .unwrap()
    }

    #[test]
    fn source_manifest_receiver_finishes_complete_windows_before_next_phase() {
        let manifest = paged_source(wire::SOURCE_PAGE_FILES * 6 + 1);
        let mut input = Vec::new();
        let mut window = Window::default();
        for (index, files) in manifest.files().chunks(wire::SOURCE_PAGE_FILES).enumerate() {
            input.extend(record(&Message::SourceManifestPage {
                page: wire::SourcePage::from_native(index * wire::SOURCE_PAGE_FILES, files)
                    .unwrap(),
            }));
            if window.record().unwrap() {
                let count = window.count();
                input.extend(record(&Message::WindowEnd { count }));
                window.acknowledge(count).unwrap();
            }
        }
        input.extend(record(&Message::WindowEnd { count: 7 }));
        input.extend(record(&Message::SourceManifestEnd {}));
        input.extend(record(&Message::InputsDone {}));
        let peer = AdmissionPeer::new(input);
        let output = Arc::clone(&peer.output);
        let mut transport = Wire::new(peer);
        let stopped = AtomicBool::new(false);
        let deadline = Instant::now() + wire::IO_BUDGET;
        let received = ready(receive_source_manifest(
            &mut transport,
            SourceDeclaration::from_native(&manifest),
            &stopped,
            deadline,
        ))
        .unwrap();
        assert_eq!(received, manifest);
        assert_eq!(
            messages(&output),
            [
                json!({"kind":"window","count":4}),
                json!({"kind":"window","count":7})
            ]
        );
        assert!(matches!(
            ready(transport.receive(&stopped, deadline)).unwrap(),
            Message::InputsDone {}
        ));
    }

    #[test]
    fn source_manifest_receiver_refuses_partial_out_of_phase_and_unacknowledged_inputs() {
        let manifest = paged_source(wire::SOURCE_PAGE_FILES * 5);
        let page = |index: usize| Message::SourceManifestPage {
            page: wire::SourcePage::from_native(
                index * wire::SOURCE_PAGE_FILES,
                &manifest.files()
                    [index * wire::SOURCE_PAGE_FILES..(index + 1) * wire::SOURCE_PAGE_FILES],
            )
            .unwrap(),
        };
        for case in 0..8 {
            let input = match case {
                0 => vec![
                    page(0),
                    Message::WindowEnd { count: 1 },
                    Message::SourceManifestEnd {},
                ],
                1 => vec![Message::SourceChunk {
                    chunk: Chunk::new("not-admitted", 0, b"x").unwrap(),
                }],
                2 => vec![page(0), page(0)],
                3 => (0..5).map(page).collect(),
                4 => vec![page(0), Message::WindowEnd { count: 2 }],
                5 => vec![page(0), Message::SourceManifestEnd {}],
                6 => vec![Message::SourceManifestEnd {}],
                _ => vec![page(0)],
            };
            let peer = AdmissionPeer::new(input.iter().flat_map(record).collect());
            let output = Arc::clone(&peer.output);
            let mut transport = Wire::new(peer);
            let result = ready(receive_source_manifest(
                &mut transport,
                SourceDeclaration::from_native(&manifest),
                &AtomicBool::new(false),
                Instant::now() + wire::IO_BUDGET,
            ));
            assert!(result.is_err(), "{case}");
            assert!(
                messages(&output)
                    .iter()
                    .all(|reply| reply["kind"] == "window")
            );
        }
    }

    #[test]
    fn source_manifest_receiver_observes_cancellation_and_fixed_deadline() {
        let manifest = paged_source(1);
        for cancel in [false, true] {
            let stopped = Arc::new(AtomicBool::new(false));
            let mut peer = AdmissionPeer::new(record(&Message::SourceManifestPage {
                page: wire::SourcePage::from_native(0, manifest.files()).unwrap(),
            }));
            if cancel {
                let stop = Arc::clone(&stopped);
                peer.before_read = Some(Box::new(move || stop.store(true, Ordering::Release)));
            }
            let output = Arc::clone(&peer.output);
            let mut transport = Wire::new(peer);
            let deadline = if cancel {
                Instant::now() + wire::IO_BUDGET
            } else {
                Instant::now()
            };
            let error = ready(receive_source_manifest(
                &mut transport,
                SourceDeclaration::from_native(&manifest),
                &stopped,
                deadline,
            ))
            .unwrap_err();
            assert_eq!(
                error.kind(),
                if cancel {
                    io::ErrorKind::Interrupted
                } else {
                    io::ErrorKind::TimedOut
                }
            );
            assert!(messages(&output).is_empty());
        }
    }

    #[test]
    fn artifact_manifest_sender_honors_bounded_windows_and_exact_page_order() {
        let manifest = rabs_sandbox::source_transfer::ArtifactManifest::new(
            (0..ARTIFACT_PAGE_FILES * 6 + 1)
                .map(|index| SourceFile {
                    path: format!("target/{index:04}"),
                    len: 0,
                    sha256: Sha256::digest([]).into(),
                    executable: false,
                })
                .collect(),
        )
        .unwrap();
        for wrong_ack in [false, true] {
            let mut input = record(&Message::Window {
                count: if wrong_ack { 3 } else { 4 },
            });
            input.extend(record(&Message::Window { count: 7 }));
            let peer = AdmissionPeer::new(input);
            let output = Arc::clone(&peer.output);
            let mut transport = Wire::new(peer);
            let result = ready(send_artifact_manifest(
                &mut transport,
                &manifest,
                &AtomicBool::new(false),
                Instant::now() + Duration::from_secs(15),
            ));
            let sent = messages(&output);
            if wrong_ack {
                assert!(result.is_err());
                assert_eq!(sent.len(), 5);
                assert_eq!(sent.last().unwrap()["kind"], "window-end");
                continue;
            }
            result.unwrap();
            let mut received =
                wire::ArtifactPages::new(ArtifactDeclaration::from_native(&manifest)).unwrap();
            let mut window_counts = Vec::new();
            for message in sent {
                match serde_json::from_value::<Message>(message).unwrap() {
                    Message::ArtifactManifestPage { page } => received.push(page).unwrap(),
                    Message::WindowEnd { count } => window_counts.push(count),
                    Message::ArtifactManifestEnd {} => {}
                    _ => panic!("sender emitted a message from another phase"),
                }
            }
            assert_eq!(window_counts, [4, 7]);
            assert_eq!(received.finish().unwrap(), manifest);
        }
    }

    #[test]
    fn artifact_manifest_sender_observes_cancellation_while_awaiting_window_ack() {
        let manifest = rabs_sandbox::source_transfer::ArtifactManifest::new(
            (0..ARTIFACT_PAGE_FILES * 5)
                .map(|index| SourceFile {
                    path: format!("target/{index:04}"),
                    len: 0,
                    sha256: Sha256::digest([]).into(),
                    executable: false,
                })
                .collect(),
        )
        .unwrap();
        let stopped = Arc::new(AtomicBool::new(false));
        let cancel = Arc::clone(&stopped);
        let mut peer = AdmissionPeer::new(record(&Message::Window { count: 4 }));
        peer.before_read = Some(Box::new(move || cancel.store(true, Ordering::Release)));
        let output = Arc::clone(&peer.output);
        let mut transport = Wire::new(peer);
        let result = ready(send_artifact_manifest(
            &mut transport,
            &manifest,
            &stopped,
            Instant::now() + Duration::from_secs(15),
        ));
        assert!(matches!(result, Err(error) if error.kind() == io::ErrorKind::Interrupted));
        let sent = messages(&output);
        assert_eq!(sent.len(), 5);
        assert_eq!(sent.last().unwrap()["kind"], "window-end");
        assert!(
            sent.iter()
                .all(|message| message["kind"] != "artifact-manifest-end")
        );
    }

    fn artifact_delivery_fixture() -> (tempfile::TempDir, CapturedTarget, Vec<u8>) {
        let owner = tempfile::Builder::new()
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let target = owner.path().join("target");
        fs::DirBuilder::new().mode(0o700).create(&target).unwrap();
        let bytes: Vec<_> = (0..MAX_SOURCE_CHUNK * 4 + 17)
            .map(|index| (index % 251) as u8)
            .collect();
        fs::write(target.join("a-reused"), b"old").unwrap();
        fs::write(target.join("b-empty"), []).unwrap();
        fs::write(target.join("c-needed"), &bytes).unwrap();
        fs::write(target.join("d-reused"), b"ok").unwrap();
        let captured = CapturedTarget::capture(&target, &|| false).unwrap();
        (owner, captured, bytes)
    }

    fn artifact_delivery_input(
        plan: ArtifactPlan,
        windows: &[u64],
        received: Option<&str>,
    ) -> Vec<u8> {
        let mut input = record(&Message::ReceiveTarget {});
        input.extend(record(&Message::Window { count: 1 }));
        input.extend(record(&Message::ReceiveArtifacts {
            manifest_sha256: plan.manifest_sha256,
            // This fixture declares exactly four canonical members.
            file_index: plan
                .missing_files
                .first()
                .map_or(4, |index| u32::from(*index)),
            offset: 0,
            missing_files: plan.missing_files,
            prefixes: plan.prefixes,
        }));
        for count in windows {
            input.extend(record(&Message::Window { count: *count }));
        }
        if let Some(received) = received {
            input.extend(record(&Message::Received {
                manifest_sha256: received.to_owned(),
            }));
        }
        input
    }

    #[test]
    fn artifact_delivery_reuses_complete_files_without_changing_manifest_or_windows() {
        // Real captured files and the production sender/manifest state machine;
        // the fragmented peer is explicitly scripted, not TLS/Cargo proof.
        let (_owner, captured, needed) = artifact_delivery_fixture();
        let identity = encode_hex(&captured.manifest().digest());
        for (missing, windows) in [
            (vec![0, 2, 3], vec![4, 7]),
            (vec![2], vec![4, 5]),
            (vec![], vec![]),
        ] {
            let plan = ArtifactPlan::new(captured.manifest(), missing.clone()).unwrap();
            let peer = AdmissionPeer::new(artifact_delivery_input(plan, &windows, Some(&identity)));
            let output = Arc::clone(&peer.output);
            let received = ready(deliver_artifacts(
                &mut Wire::new(peer),
                &captured,
                &AtomicBool::new(false),
                Instant::now() + wire::IO_BUDGET,
                &|| false,
                false,
            ))
            .unwrap();
            assert_eq!(received, ArtifactDelivery::Sealed(identity.clone()));
            let mut pages =
                wire::ArtifactPages::new(ArtifactDeclaration::from_native(captured.manifest()))
                    .unwrap();
            let mut delivered: BTreeMap<String, Vec<u8>> = BTreeMap::new();
            let mut acknowledgments = Vec::new();
            let sent = messages(&output);
            for value in &sent {
                match serde_json::from_value::<Message>(value.clone()).unwrap() {
                    Message::ArtifactManifestPage { page } => pages.push(page).unwrap(),
                    Message::ArtifactChunk { chunk } => {
                        let (bytes, _) = chunk.verified_bytes().unwrap();
                        let file = delivered.entry(chunk.path).or_default();
                        assert_eq!(chunk.offset, file.len() as u64);
                        file.extend(bytes);
                    }
                    Message::WindowEnd { count } => acknowledgments.push(count),
                    Message::ArtifactManifestEnd {} | Message::ArtifactEnd {} => {}
                    _ => panic!("artifact sender crossed into commit or execution authority"),
                }
            }
            assert_eq!(pages.finish().unwrap(), *captured.manifest());
            assert_eq!(
                delivered.keys().map(String::as_str).collect::<Vec<_>>(),
                missing
                    .iter()
                    .map(|index| captured.manifest().files()[usize::from(*index)]
                        .path
                        .as_str())
                    .collect::<Vec<_>>(),
            );
            if missing.contains(&0) {
                assert_eq!(delivered["a-reused"], b"old");
            }
            if missing.contains(&2) {
                assert_eq!(delivered["c-needed"], needed);
            }
            if missing.contains(&3) {
                assert_eq!(delivered["d-reused"], b"ok");
            }
            let expected_windows: Vec<_> = std::iter::once(1).chain(windows).collect();
            assert_eq!(acknowledgments, expected_windows);
            assert_eq!(sent.last().unwrap()["kind"], "artifact-end");
        }
    }

    #[test]
    fn artifact_delivery_confirms_prefixes_and_sends_only_the_selected_tail() {
        let (_owner, captured, needed) = artifact_delivery_fixture();
        let identity = encode_hex(&captured.manifest().digest());
        for (offered, matching, windows) in [
            (1, true, vec![4, 5]),
            (MAX_SOURCE_CHUNK, true, vec![4]),
            (MAX_SOURCE_CHUNK + 1, true, vec![4]),
            (needed.len() - 1, true, vec![1]),
            (MAX_SOURCE_CHUNK + 1, false, vec![4, 5]),
        ] {
            let hash = if matching {
                Sha256::digest(&needed[..offered])
            } else {
                Sha256::digest(b"unrelated old bytes")
            };
            let plan = ArtifactPlan::with_prefixes(
                captured.manifest(),
                vec![2],
                vec![wire::ArtifactPrefixOffer {
                    index: 2,
                    offset: offered as u64,
                    sha256: encode_hex(&hash),
                }],
            )
            .unwrap();
            let peer = AdmissionPeer::new(artifact_delivery_input(plan, &windows, Some(&identity)));
            let output = Arc::clone(&peer.output);
            assert_eq!(
                ready(deliver_artifacts(
                    &mut Wire::new(peer),
                    &captured,
                    &AtomicBool::new(false),
                    Instant::now() + wire::IO_BUDGET,
                    &|| false,
                    false,
                ))
                .unwrap(),
                ArtifactDelivery::Sealed(identity.clone()),
            );
            let selected = if matching { offered } else { 0 };
            let mut offset = selected;
            let mut tail = Vec::new();
            let mut acknowledgments = Vec::new();
            let mut pages =
                wire::ArtifactPages::new(ArtifactDeclaration::from_native(captured.manifest()))
                    .unwrap();
            let sent = messages(&output);
            for value in &sent {
                match serde_json::from_value::<Message>(value.clone()).unwrap() {
                    Message::ArtifactManifestPage { page } => pages.push(page).unwrap(),
                    Message::ArtifactChunk { chunk } => {
                        assert_eq!(chunk.path, "c-needed");
                        assert_eq!(chunk.offset, offset as u64);
                        let (bytes, _) = chunk.verified_bytes().unwrap();
                        offset += bytes.len();
                        tail.extend(bytes);
                    }
                    Message::WindowEnd { count } => acknowledgments.push(count),
                    Message::ArtifactManifestEnd {} | Message::ArtifactEnd {} => {}
                    _ => panic!("prefix selection crossed the result authority boundary"),
                }
            }
            assert_eq!(pages.finish().unwrap(), *captured.manifest());
            assert_eq!(offset, needed.len());
            assert_eq!(tail, needed[selected..]);
            assert!(!tail.is_empty());
            assert_eq!(
                acknowledgments,
                std::iter::once(1).chain(windows).collect::<Vec<_>>(),
            );
            assert_eq!(sent.last().unwrap()["kind"], "artifact-end");
        }
    }

    #[test]
    fn artifact_prefixes_share_the_window_with_full_files_and_independent_misses() {
        let (_owner, captured, needed) = artifact_delivery_fixture();
        let identity = encode_hex(&captured.manifest().digest());
        let offered = MAX_SOURCE_CHUNK + 3;
        let plan = ArtifactPlan::with_prefixes(
            captured.manifest(),
            vec![0, 2, 3],
            vec![
                wire::ArtifactPrefixOffer {
                    index: 0,
                    offset: 1,
                    sha256: encode_hex(&Sha256::digest(b"wrong prefix")),
                },
                wire::ArtifactPrefixOffer {
                    index: 2,
                    offset: offered as u64,
                    sha256: encode_hex(&Sha256::digest(&needed[..offered])),
                },
            ],
        )
        .unwrap();
        // One rejected prefix, four tail chunks and one ordinary whole file.
        let peer = AdmissionPeer::new(artifact_delivery_input(plan, &[4, 6], Some(&identity)));
        let output = Arc::clone(&peer.output);
        ready(deliver_artifacts(
            &mut Wire::new(peer),
            &captured,
            &AtomicBool::new(false),
            Instant::now() + wire::IO_BUDGET,
            &|| false,
            false,
        ))
        .unwrap();
        let mut chunks = Vec::new();
        let mut windows = Vec::new();
        for value in messages(&output) {
            match serde_json::from_value::<Message>(value).unwrap() {
                Message::ArtifactChunk { chunk } => chunks.push(chunk),
                Message::WindowEnd { count } => windows.push(count),
                _ => {}
            }
        }
        assert_eq!(windows, [1, 4, 6]);
        assert_eq!(chunks.len(), 6);
        assert_eq!(chunks[0].path, "a-reused");
        assert_eq!(chunks[0].offset, 0);
        assert_eq!(chunks[0].verified_bytes().unwrap().0, b"old");
        let mut received = needed[..offered].to_vec();
        for chunk in &chunks[1..5] {
            assert_eq!(chunk.path, "c-needed");
            assert_eq!(chunk.offset, received.len() as u64);
            received.extend(chunk.verified_bytes().unwrap().0);
        }
        assert_eq!(received, needed);
        assert_eq!(chunks[5].path, "d-reused");
        assert_eq!(chunks[5].offset, 0);
        assert_eq!(chunks[5].verified_bytes().unwrap().0, b"ok");
    }

    #[test]
    fn artifact_prefix_inspection_observes_cancellation_deadline_and_capture_mutation() {
        use std::cell::Cell;
        let (owner, captured, needed) = artifact_delivery_fixture();
        let file = &captured.manifest().files()[2];
        let offered = wire::ArtifactPrefixOffer {
            index: 2,
            offset: (MAX_SOURCE_CHUNK * 2) as u64,
            sha256: encode_hex(&Sha256::digest(&needed[..MAX_SOURCE_CHUNK * 2])),
        };
        let stopped = AtomicBool::new(false);
        assert_eq!(
            artifact_prefix_offset(
                &captured,
                file,
                Some(&offered),
                &stopped,
                Instant::now(),
                &|| false,
            )
            .unwrap_err()
            .kind(),
            io::ErrorKind::TimedOut,
        );
        let checkpoints = Cell::new(0);
        let error = artifact_prefix_offset(
            &captured,
            file,
            Some(&offered),
            &stopped,
            Instant::now() + wire::IO_BUDGET,
            &|| {
                checkpoints.set(checkpoints.get() + 1);
                checkpoints.get() >= 3
            },
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
        let capture = fs::read_dir(owner.path())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| {
                path.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with("rabs-target-capture-")
            })
            .unwrap();
        let changed = capture.join("files/c-needed");
        let checkpoints = Cell::new(0);
        assert!(
            artifact_prefix_offset(
                &captured,
                file,
                Some(&offered),
                &stopped,
                Instant::now() + wire::IO_BUDGET,
                &|| {
                    checkpoints.set(checkpoints.get() + 1);
                    if checkpoints.get() == 2 {
                        fs::set_permissions(&changed, fs::Permissions::from_mode(0o600)).unwrap();
                        let writer = OpenOptions::new().write(true).open(&changed).unwrap();
                        writer
                            .write_all_at(b"changed", MAX_SOURCE_CHUNK as u64)
                            .unwrap();
                        fs::set_permissions(&changed, fs::Permissions::from_mode(0o444)).unwrap();
                    }
                    false
                },
            )
            .is_err()
        );
    }

    #[test]
    fn artifact_delivery_refuses_invalid_plans_before_any_payload() {
        let (_owner, captured, _) = artifact_delivery_fixture();
        let identity = encode_hex(&captured.manifest().digest());
        let mut invalid_plans: Vec<_> = [
            vec![0, 0],
            vec![2, 0],
            vec![1],
            vec![4],
            vec![u16::MAX],
            vec![0; rabs_sandbox::artifact_tree::MAX_ARTIFACT_FILES + 1],
        ]
        .into_iter()
        .map(|missing_files| ArtifactPlan {
            manifest_sha256: identity.clone(),
            missing_files,
            prefixes: vec![],
        })
        .collect();
        invalid_plans.push(ArtifactPlan {
            manifest_sha256: "00".repeat(32),
            missing_files: vec![],
            prefixes: vec![],
        });
        let prefix = |index, offset| wire::ArtifactPrefixOffer {
            index,
            offset,
            sha256: encode_hex(&Sha256::digest(b"untrusted prefix")),
        };
        for prefixes in [
            vec![prefix(0, 1)],
            vec![prefix(1, 1)],
            vec![prefix(4, 1)],
            vec![prefix(2, 0)],
            vec![prefix(2, captured.manifest().files()[2].len)],
            vec![prefix(2, u64::MAX)],
            vec![prefix(2, 1), prefix(2, 2)],
            vec![wire::ArtifactPrefixOffer {
                index: 2,
                offset: 1,
                sha256: "FF".repeat(32),
            }],
        ] {
            invalid_plans.push(ArtifactPlan {
                manifest_sha256: identity.clone(),
                missing_files: vec![2],
                prefixes,
            });
        }
        for plan in invalid_plans {
            let peer = AdmissionPeer::new(artifact_delivery_input(plan, &[], Some(&identity)));
            let output = Arc::clone(&peer.output);
            assert!(
                ready(deliver_artifacts(
                    &mut Wire::new(peer),
                    &captured,
                    &AtomicBool::new(false),
                    Instant::now() + wire::IO_BUDGET,
                    &|| false,
                    false,
                ))
                .is_err()
            );
            assert!(messages(&output).iter().all(|message| {
                !matches!(
                    message["kind"].as_str(),
                    Some("artifact-chunk" | "artifact-end")
                )
            }));
        }
    }

    #[test]
    fn artifact_delivery_resumes_a_partial_file_and_accepts_a_sealed_cursor() {
        let (_owner, captured, needed) = artifact_delivery_fixture();
        let identity = encode_hex(&captured.manifest().digest());
        let start = MAX_SOURCE_CHUNK as u64 + 17;
        for (file_index, offset, windows) in [(2, start, vec![3]), (4, 0, vec![])] {
            let mut input = record(&Message::ReceiveTarget {});
            input.extend(record(&Message::Window { count: 1 }));
            input.extend(record(&Message::ReceiveArtifacts {
                manifest_sha256: identity.clone(),
                missing_files: vec![2],
                // A prior rejected hint is larger than the accepted cursor.
                // Reattachment must neither retry that hint nor rewind to 0.
                prefixes: vec![wire::ArtifactPrefixOffer {
                    index: 2,
                    offset: (MAX_SOURCE_CHUNK * 2) as u64,
                    sha256: "00".repeat(32),
                }],
                file_index,
                offset,
            }));
            for count in windows {
                input.extend(record(&Message::Window { count }));
            }
            input.extend(record(&Message::Received {
                manifest_sha256: identity.clone(),
            }));
            let peer = AdmissionPeer::new(input);
            let output = Arc::clone(&peer.output);
            assert_eq!(
                ready(deliver_artifacts(
                    &mut Wire::new(peer),
                    &captured,
                    &AtomicBool::new(false),
                    Instant::now() + wire::IO_BUDGET,
                    &|| false,
                    false,
                ))
                .unwrap(),
                ArtifactDelivery::Sealed(identity.clone())
            );
            let mut actual = Vec::new();
            for value in messages(&output) {
                if let Message::ArtifactChunk { chunk } = serde_json::from_value(value).unwrap() {
                    assert_eq!(chunk.path, "c-needed");
                    assert_eq!(chunk.offset, offset + actual.len() as u64);
                    actual.extend(chunk.verified_bytes().unwrap().0);
                }
            }
            if file_index == 2 {
                assert_eq!(actual, needed[start as usize..]);
            } else {
                assert!(actual.is_empty());
            }
        }
    }

    #[test]
    fn artifact_resume_rejects_invalid_cursors_before_payload() {
        let (_owner, captured, needed) = artifact_delivery_fixture();
        let identity = encode_hex(&captured.manifest().digest());
        for (file_index, offset) in [(0, 0), (1, 0), (2, needed.len() as u64), (4, 1), (5, 0)] {
            let mut input = record(&Message::ReceiveTarget {});
            input.extend(record(&Message::Window { count: 1 }));
            input.extend(record(&Message::ReceiveArtifacts {
                manifest_sha256: identity.clone(),
                missing_files: vec![2],
                prefixes: vec![],
                file_index,
                offset,
            }));
            let peer = AdmissionPeer::new(input);
            let output = Arc::clone(&peer.output);
            assert!(
                ready(deliver_artifacts(
                    &mut Wire::new(peer),
                    &captured,
                    &AtomicBool::new(false),
                    Instant::now() + wire::IO_BUDGET,
                    &|| false,
                    false,
                ))
                .is_err()
            );
            assert!(messages(&output).iter().all(|message| {
                !matches!(
                    message["kind"].as_str(),
                    Some("artifact-chunk" | "artifact-end")
                )
            }));
        }
    }

    #[test]
    fn installed_receipt_reconciliation_requires_the_original_commit_and_target() {
        let (_owner, captured, _) = artifact_delivery_fixture();
        let identity = encode_hex(&captured.manifest().digest());
        for (authorized, supplied, success) in [
            (false, identity.clone(), false),
            (true, "00".repeat(32), false),
            (true, identity.clone(), true),
        ] {
            let peer = AdmissionPeer::new(record(&Message::Published {
                manifest_sha256: supplied,
            }));
            let output = Arc::clone(&peer.output);
            let result = ready(deliver_artifacts(
                &mut Wire::new(peer),
                &captured,
                &AtomicBool::new(false),
                Instant::now() + wire::IO_BUDGET,
                &|| false,
                authorized,
            ));
            if success {
                assert_eq!(result.unwrap(), ArtifactDelivery::Published);
            } else {
                assert!(result.is_err());
            }
            // Reconciliation never resends artifacts or issues another Commit.
            assert!(messages(&output).is_empty());
        }
    }

    #[test]
    fn artifact_reuse_still_requires_exact_window_and_full_receipt_acknowledgments() {
        let (_owner, captured, _) = artifact_delivery_fixture();
        let identity = encode_hex(&captured.manifest().digest());
        for (missing, windows, received, expected_chunks, ended) in [
            (vec![2], vec![3], Some(identity.as_str()), 4, false),
            (vec![2], vec![4], None, 5, false),
            (vec![], vec![], None, 0, true),
            (vec![], vec![], Some("different-manifest"), 0, true),
        ] {
            let plan = ArtifactPlan::new(captured.manifest(), missing).unwrap();
            let peer = AdmissionPeer::new(artifact_delivery_input(plan, &windows, received));
            let output = Arc::clone(&peer.output);
            assert!(
                ready(deliver_artifacts(
                    &mut Wire::new(peer),
                    &captured,
                    &AtomicBool::new(false),
                    Instant::now() + wire::IO_BUDGET,
                    &|| false,
                    false,
                ))
                .is_err()
            );
            let sent = messages(&output);
            assert_eq!(
                sent.iter()
                    .filter(|message| message["kind"] == "artifact-chunk")
                    .count(),
                expected_chunks,
            );
            assert_eq!(
                sent.iter().any(|message| message["kind"] == "artifact-end"),
                ended,
            );
        }
    }

    #[test]
    fn artifact_reuse_revalidates_skipped_producer_files_and_original_deadline() {
        let (owner, captured, _) = artifact_delivery_fixture();
        let identity = encode_hex(&captured.manifest().digest());
        for cancel in [false, true] {
            let peer = AdmissionPeer::new(artifact_delivery_input(
                ArtifactPlan::new(captured.manifest(), vec![]).unwrap(),
                &[],
                Some(&identity),
            ));
            let output = Arc::clone(&peer.output);
            let error = ready(deliver_artifacts(
                &mut Wire::new(peer),
                &captured,
                &AtomicBool::new(cancel),
                if cancel {
                    Instant::now() + wire::IO_BUDGET
                } else {
                    Instant::now()
                },
                &|| false,
                false,
            ))
            .unwrap_err();
            assert_eq!(
                error.kind(),
                if cancel {
                    io::ErrorKind::Interrupted
                } else {
                    io::ErrorKind::TimedOut
                },
            );
            assert!(messages(&output).is_empty());
        }
        // The receiver can reuse every payload and acknowledge the complete
        // manifest; corruption of an untransmitted producer file still refuses.
        let capture = fs::read_dir(owner.path())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| {
                path.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with("rabs-target-capture-")
            })
            .unwrap();
        let corrupt = capture.join("files/a-reused");
        let mut peer = AdmissionPeer::new(artifact_delivery_input(
            ArtifactPlan::new(captured.manifest(), vec![]).unwrap(),
            &[],
            Some(&identity),
        ));
        peer.before_read = Some(Box::new(move || {
            fs::set_permissions(&corrupt, fs::Permissions::from_mode(0o600)).unwrap();
            fs::write(&corrupt, b"bad").unwrap();
            fs::set_permissions(&corrupt, fs::Permissions::from_mode(0o444)).unwrap();
        }));
        let output = Arc::clone(&peer.output);
        assert!(
            ready(deliver_artifacts(
                &mut Wire::new(peer),
                &captured,
                &AtomicBool::new(false),
                Instant::now() + wire::IO_BUDGET,
                &|| false,
                false,
            ))
            .is_err()
        );
        let sent = messages(&output);
        assert_eq!(sent.last().unwrap()["kind"], "artifact-end");
        assert!(
            sent.iter()
                .all(|message| message["kind"] != "artifact-chunk")
        );
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
                file_cache: None,
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
                    file_cache: None,
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
                    file_cache: None,
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
            assert!(
                ready(
                    ToolchainAdmission {
                        cache: &cache,
                        file_cache: None,
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
                .is_err()
            );
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
                    file_cache: None,
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
            assert!(
                messages(&output)
                    .iter()
                    .all(|message| message["kind"] == "queued")
            );
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
                SourceInput::uncached(source).unwrap(),
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
    fn source_delta_transport_reconstructs_cold_warm_edited_and_peer_scoped_inputs() {
        let cache_parent = crate::test_util::private_tempdir();
        let cache = RemoteSourceCache::new(cache_parent.path(), 1024).unwrap();
        let sdk = received_sdk();
        let stopped = Arc::new(AtomicBool::new(false));
        let mut owners = Vec::new();
        let mut roots: Vec<PathBuf> = Vec::new();
        let cases: [([u8; 32], &[u8], &[u16]); 4] = [
            ([7; 32], b"first main", &[1, 2]),
            ([7; 32], b"first main", &[]),
            ([7; 32], b"edited main", &[2]),
            ([8; 32], b"edited main", &[1, 2]),
        ];
        for (pin, main, missing) in cases {
            let owner = crate::test_util::private_tempdir();
            let files: [(&str, &[u8]); 3] = [
                ("empty", b""),
                ("src/lib.rs", b"unchanged library"),
                ("src/main.rs", main),
            ];
            let manifest = SourceManifest::new(
                files
                    .iter()
                    .map(|(path, bytes)| SourceFile {
                        path: (*path).into(),
                        len: bytes.len() as u64,
                        sha256: Sha256::digest(bytes).into(),
                        executable: false,
                    })
                    .collect(),
            )
            .unwrap();
            let deadline = Instant::now() + Duration::from_secs(10);
            let receiver =
                SourceReceiver::create(&owner.path().join("source"), manifest.clone()).unwrap();
            let source = SourceInput::prepare(
                receiver,
                Some(cache.for_peer(pin, Arc::clone(&stopped), deadline).unwrap()),
                || false,
            )
            .unwrap();
            assert_eq!(source.plan().missing_files.as_slice(), missing);
            source.plan().validate(&manifest).unwrap();
            let mut input = Vec::new();
            for index in missing {
                let (path, bytes) = files[usize::from(*index)];
                input.extend(record(&Message::SourceChunk {
                    chunk: Chunk::new(path, 0, bytes).unwrap(),
                }));
            }
            if !missing.is_empty() {
                input.extend(record(&Message::WindowEnd {
                    count: missing.len() as u64,
                }));
            }
            input.extend(record(&Message::InputsDone {}));
            let peer = AdmissionPeer::new(input);
            let output = Arc::clone(&peer.output);
            let mut wire = Wire::new(peer);
            let (source, retained) = ready(receive_inputs(
                &mut wire,
                source,
                ToolchainInput::Reuse(Arc::clone(&sdk)),
                &stopped,
                deadline,
            ))
            .unwrap();
            assert!(Arc::ptr_eq(&retained, &sdk));
            assert_eq!(source.manifest(), &manifest);
            let root = source.sealed_root().unwrap().to_path_buf();
            for (path, bytes) in files {
                assert_eq!(fs::read(root.join(path)).unwrap(), bytes);
            }
            let current = fs::metadata(root.join("src/lib.rs")).unwrap();
            for previous in &roots {
                let previous = fs::metadata(previous.join("src/lib.rs")).unwrap();
                assert_ne!(
                    (current.dev(), current.ino()),
                    (previous.dev(), previous.ino()),
                    "reused bytes must not share execution inodes"
                );
            }
            assert_eq!(
                messages(&output),
                if missing.is_empty() {
                    Vec::<Value>::new()
                } else {
                    vec![json!({"kind":"window", "count":missing.len()})]
                }
            );
            roots.push(root);
            owners.push(owner);
        }
        sdk.verify(|| false).unwrap();
    }

    #[test]
    fn warm_source_transport_refuses_unrequested_chunks_before_acknowledgment() {
        let cache_parent = crate::test_util::private_tempdir();
        let cache = RemoteSourceCache::new(cache_parent.path(), 1024).unwrap();
        let stopped = Arc::new(AtomicBool::new(false));
        let deadline = Instant::now() + Duration::from_secs(10);
        let pin = [9; 32];
        let bytes = b"verified source";
        let seed_owner = crate::test_util::private_tempdir();
        let mut seed = SourceInput::prepare(
            source_receiver(seed_owner.path(), bytes),
            Some(cache.for_peer(pin, Arc::clone(&stopped), deadline).unwrap()),
            || false,
        )
        .unwrap();
        seed.begin_transfer(deadline).unwrap();
        seed.write_chunk("src/lib.rs", 0, bytes, Sha256::digest(bytes).into(), || {
            false
        })
        .unwrap();
        seed.finish(|| false).unwrap();
        let owner = crate::test_util::private_tempdir();
        let source = SourceInput::prepare(
            source_receiver(owner.path(), bytes),
            Some(cache.for_peer(pin, Arc::clone(&stopped), deadline).unwrap()),
            || false,
        )
        .unwrap();
        assert!(source.plan().missing_files.is_empty());
        // Even byte-identical retries are forbidden for an omitted member.
        let peer = AdmissionPeer::new(source_upload(bytes));
        let output = Arc::clone(&peer.output);
        let mut wire = Wire::new(peer);
        let error = ready(receive_inputs(
            &mut wire,
            source,
            ToolchainInput::Reuse(received_sdk()),
            &stopped,
            deadline,
        ))
        .err()
        .expect("cache-hit members were not requested for upload");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(messages(&output).is_empty());
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
                SourceInput::uncached(source).unwrap(),
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
                SourceInput::uncached(source).unwrap(),
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
