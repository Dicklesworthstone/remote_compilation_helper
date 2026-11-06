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
use rabs_sandbox::toolchain_dataset::{PreparedToolchain, ToolchainLimits};
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
    Chunk, Manifest, Message, Output, VERSION, Window, Wire, checkpoint, digest, invalid, require,
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
    jobs_per_root: u32,
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
}

/// A session slot covers authentication, upload, execution and final receipt.
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
    let config = Arc::new(config);
    let shutdown = Arc::new(ShutdownController::new());
    shutdown.listen_for_signals();
    let mut sessions = Sessions::default();
    eprintln!(
        "{}",
        json!({"kind":"canonical-remote-service-listening", "version":SERVICE_VERSION,
        "address":listener.local_addr()?.to_string(), "max_roots":config.max_roots,
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
        if sessions.0.len() >= config.max_roots {
            // No plaintext rejection on an authenticated-only endpoint. No
            // admission took place, and clients never automatically retry.
            drop(stream);
            continue;
        }
        let stopped = Arc::new(AtomicBool::new(false));
        let child_stop = Arc::clone(&stopped);
        let child_config = Arc::clone(&config);
        let child_runtime = Arc::clone(&runtime);
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
                    let mut wire = Wire::new(peer.stream);
                    let result =
                        handle_session(&mut wire, child_runtime, &child_config, &child_stop).await;
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

async fn handle_session<S: AsyncRead + AsyncWrite + Unpin>(
    wire: &mut Wire<S>,
    runtime: Arc<SharedRuntime>,
    config: &ServiceProfile,
    stopped: &Arc<AtomicBool>,
) -> io::Result<()> {
    let input_deadline = Instant::now() + TOOLCHAIN_INPUT_BUDGET;
    let Message::Hello {
        version,
        build_identity,
        require_release,
        settings,
        source_manifest,
        toolchain_identity,
        cargo_home,
    } = wire.receive(stopped, input_deadline).await?
    else {
        return Err(invalid("remote operation must begin with hello"));
    };
    require(
        version == VERSION && build_identity == runtime.build_identity,
        "remote client and service protocol/build identities differ",
    )?;
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
    let owner = Arc::new(
        tempfile::Builder::new()
            .prefix("canonical-remote-input-")
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir_in(&config.input_root)?,
    );
    let request = prepared_request(
        &settings,
        &owner.path().join("toolchain"),
        &source_manifest,
        &toolchain_identity,
        &cargo_home,
    )?;
    let source = SourceReceiver::create(&owner.path().join("source"), manifest)?;
    let toolchain = ToolchainReceiver::create(
        &owner.path().join("toolchain"),
        identity,
        ToolchainLimits::default(),
    )?;
    wire.send(&Message::Ready, stopped, input_deadline).await?;
    let (source, toolchain) =
        receive_inputs(wire, source, toolchain, stopped, input_deadline).await?;
    let inputs =
        RemoteOperationInputs::new(Arc::clone(&owner), source, toolchain, request, &|| {
            stopped.load(Ordering::Acquire) || Instant::now() >= input_deadline
        })?;
    checkpoint(stopped, input_deadline)?;
    let stdout = output_file(owner.path(), "stdout")?;
    let stderr = output_file(owner.path(), "stderr")?;
    let execution_deadline =
        Instant::now() + Duration::from_secs(settings.timeout_seconds) + DELIVERY_BUDGET;
    // Acceptance means execution may begin. An interruption from this point
    // never selects a retry, another coordinator or local compilation.
    wire.send(&Message::Accepted, stopped, input_deadline)
        .await?;
    let operation = remote_operation::start(
        Arc::clone(&runtime),
        config.wrapper.clone(),
        config.operation_root.clone(),
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
                Message::Poll
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

/// The same finite upload receiver serves production sessions and native
/// transport tests. Only sealed byte owners can cross into execution admission.
async fn receive_inputs<S: AsyncRead + AsyncWrite + Unpin>(
    wire: &mut Wire<S>,
    mut source: SourceReceiver,
    mut toolchain: ToolchainReceiver,
    stopped: &AtomicBool,
    input_deadline: Instant,
) -> io::Result<(SourceReceiver, Arc<PreparedToolchain>)> {
    let mut window = Window::default();
    let mut source_finished = false;
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
                window.record()?;
                if !source_finished {
                    source.seal_cancellable(|| {
                        stopped.load(Ordering::Acquire) || Instant::now() >= input_deadline
                    })?;
                    source_finished = true;
                }
                toolchain.entry(entry.native())?;
            }
            Message::ToolchainChunk { chunk } => {
                require(source_finished, "toolchain bytes arrived before its entry")?;
                window.record()?;
                let (bytes, sha256) = chunk.verified_bytes()?;
                toolchain.write_chunk(&chunk.path, chunk.offset, &bytes, sha256)?;
            }
            Message::WindowEnd { count } => {
                window.acknowledge(count)?;
                wire.send(&Message::Window { count }, stopped, input_deadline)
                    .await?;
            }
            Message::InputsDone => {
                require(
                    source_finished && !window.pending(),
                    "remote inputs ended before their complete acknowledged transfer",
                )?;
                break;
            }
            _ => return Err(invalid("unexpected message during remote input transfer")),
        }
    }
    let toolchain = Arc::new(
        toolchain.seal(|| stopped.load(Ordering::Acquire) || Instant::now() >= input_deadline)?,
    );
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
                Message::ReceiveTarget
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
        wire.send(&Message::ArtifactEnd, stopped, deadline).await?;
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
            matches!(wire.receive(stopped, deadline).await?, Message::Close),
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
    use rabs_sandbox::source_transfer::{SourceFile, SourceManifest};
    use rabs_sandbox::toolchain_dataset::ToolchainIdentity;
    use sha2::{Digest, Sha256};

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
