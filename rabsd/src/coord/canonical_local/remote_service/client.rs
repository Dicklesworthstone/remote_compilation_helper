//! Local capture and verified result installation for a remote operation.

use super::super::remote_artifacts::ReceivedTarget;
use super::super::remote_operation::RemoteOperationSettings;
use super::wire::{
    ADMISSION_BUDGET, ADMISSION_POLL, CargoHome, Chunk, Entry, Manifest, Message, Output,
    SourcePlan, Toolchain, ToolchainDisposition, VERSION, WIRE_VERSION, Window, Wire, checkpoint,
    controlled_future, decode_hex, digest, invalid, require,
};
use super::{
    DELIVERY_BUDGET, OUTPUT_TOTAL_BYTES, PROFILE_BYTES, TlsProfile, ordinary_directory, overlap,
    plain_absolute, private_directory,
};
use crate::coord::source_delivery::control::PreparationControl;
use crate::coord::source_delivery::{PreparedLocalBundle, prepare_local_bundle_controlled};
use crate::edge::live_facts::read_stable;
use asupersync::io::{AsyncRead, AsyncWrite};
use asupersync::runtime::RuntimeBuilder;
use asupersync::signal::ShutdownController;
use rabs_asupersync::daemon_runtime::block_on_top_level;
use rabs_asupersync::worker_transport::{
    MAX_JSON_RECORD, connect_coordinator_peer, runtime_transport_now,
};
use rabs_protocol::raw_bytes::encode_hex;
use rabs_protocol::release_authorization::ReleaseAuthorizationMode;
use rabs_sandbox::source_transfer::{MAX_SOURCE_CHUNK, SourceCheckpointError, SourceManifest};
use rabs_sandbox::toolchain_transfer::{TOOLCHAIN_INPUT_BUDGET, ToolchainEntryKind};
use serde::Deserialize;
use serde_json::{Value, json};
use std::fs;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClientProfile {
    version: String,
    coordinator: String,
    server_name: String,
    coordinator_pin: String,
    tls: TlsProfile,
    source_root: PathBuf,
    toolchain_root: PathBuf,
    cargo_home_source: Option<PathBuf>,
    staging_root: PathBuf,
    output_destination: PathBuf,
    settings: RemoteOperationSettings,
}

impl ClientProfile {
    fn validate(&self) -> io::Result<[u8; 32]> {
        require(
            self.version == VERSION,
            "unsupported remote canonical client profile",
        )?;
        require(
            !self.coordinator.is_empty()
                && self.coordinator.len() <= 1024
                && !self.server_name.is_empty()
                && self.server_name.len() <= 253
                && !self.coordinator.chars().any(char::is_control)
                && !self.server_name.chars().any(char::is_control),
            "remote coordinator address and TLS server name must be bounded and explicit",
        )?;
        let pin = digest(&self.coordinator_pin)?;
        require(pin != [0; 32], "zero is not an enrolled coordinator key")?;
        self.settings.validate()?;
        ordinary_directory(&self.source_root)?;
        ordinary_directory(&self.toolchain_root)?;
        private_directory(&self.staging_root)?;
        require(
            plain_absolute(&self.output_destination),
            "remote output destination must be an ordinary absolute path",
        )?;
        let output_parent = self
            .output_destination
            .parent()
            .ok_or_else(|| invalid("remote output destination has no parent"))?;
        private_directory(output_parent)?;
        require_absent(&self.output_destination)?;
        let mut roots = vec![
            self.source_root.as_path(),
            self.toolchain_root.as_path(),
            self.staging_root.as_path(),
            output_parent,
        ];
        if let Some(home) = &self.cargo_home_source {
            ordinary_directory(home)?;
            roots.push(home);
        }
        for (index, root) in roots.iter().enumerate() {
            for other in &roots[index + 1..] {
                require(
                    !overlap(root, other),
                    "remote client source, compiler, Cargo home, staging and output roots must be disjoint",
                )?;
            }
        }
        self.tls.files()?;
        for root in [&self.source_root, &self.toolchain_root]
            .into_iter()
            .chain(self.cargo_home_source.as_ref())
        {
            require(
                !self.tls.private_key.starts_with(root),
                "the edge authentication key must be outside captured inputs",
            )?;
        }
        Ok(pin)
    }
}

fn require_absent(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "remote output destination already exists; choose a new directory",
        )),
    }
}

/// Synchronous local capture also needs cancellation before the network
/// runtime exists. This owned signal bridge stops and joins with the command.
struct ClientCancellation {
    stopped: Arc<AtomicBool>,
    done: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl ClientCancellation {
    fn start() -> io::Result<Self> {
        let shutdown = Arc::new(ShutdownController::new());
        shutdown.listen_for_signals();
        let stopped = Arc::new(AtomicBool::new(false));
        let done = Arc::new(AtomicBool::new(false));
        let child_stop = Arc::clone(&stopped);
        let child_done = Arc::clone(&done);
        let thread = std::thread::Builder::new()
            .name("rabs-remote-client-signals".into())
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
        })
    }
}

impl Drop for ClientCancellation {
    fn drop(&mut self) {
        self.done.store(true, Ordering::Release);
        self.stopped.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Capture local inputs once, submit to the pinned coordinator once, and
/// install only a sealed successful artifact result at the local destination.
/// No transport failure starts another execution or selects local fallback.
pub fn run_client_profile(
    path: &Path,
    release_mode: ReleaseAuthorizationMode,
    build_identity: String,
) -> io::Result<i32> {
    let (_, bytes) = read_stable(path, PROFILE_BYTES)?;
    let config: ClientProfile =
        serde_json::from_slice(&bytes).map_err(|error| invalid(error.to_string()))?;
    let pin = config.validate()?;
    let tls = config.tls.files()?;
    tls.local_identity().map_err(io::Error::other)?;
    let cancellation = ClientCancellation::start()?;
    let stopped = &cancellation.stopped;
    let owner = tempfile::Builder::new()
        .prefix("canonical-remote-capture-")
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir_in(&config.staging_root)?;
    let capture_deadline = Instant::now() + TOOLCHAIN_INPUT_BUDGET;
    let cancelled = || stopped.load(Ordering::Acquire) || Instant::now() >= capture_deadline;
    let specification = config
        .settings
        .source_specification(&config.toolchain_root, config.cargo_home_source.as_deref())?;
    let bundle_path = owner.path().join("bundle");
    let mut bundle = prepare_local_bundle_controlled(
        &config.source_root,
        &specification,
        &bundle_path,
        None,
        &PreparationControl::new(&cancelled, None),
    )?;
    checkpoint(stopped, capture_deadline)?;
    let (_, request_bytes) =
        read_stable(&bundle_path.join("request.json"), MAX_JSON_RECORD as u64)?;
    let request: Value = serde_json::from_slice(&request_bytes)?;
    let cargo_home: Option<CargoHome> = request
        .get("cargo_home")
        .cloned()
        .map(serde_json::from_value)
        .transpose()
        .map_err(|error| invalid(error.to_string()))?;
    let toolchain = bundle
        .toolchain
        .as_ref()
        .ok_or_else(|| invalid("remote canonical capture did not retain its compiler"))?;
    let hello = Message::Hello {
        version: WIRE_VERSION.into(),
        build_identity,
        require_release: release_mode == ReleaseAuthorizationMode::Required,
        settings: Box::new(config.settings.clone()),
        source_manifest: Manifest::from_native(bundle.source.manifest()),
        toolchain_identity: Toolchain::from_native(toolchain.identity()),
        cargo_home,
    };
    // Refuse a manifest that cannot fit this protocol before connecting. An
    // oversized source declaration never becomes a partial remote operation.
    require(
        serde_json::to_vec(&hello)?.len() <= MAX_JSON_RECORD,
        "captured source declaration exceeds the remote ATP record bound",
    )?;
    let network = RuntimeBuilder::current_thread()
        .build()
        .map_err(|error| io::Error::other(format!("remote client runtime: {error:?}")))?;
    block_on_top_level(&network, async {
        let peer = connect_coordinator_peer(&config.coordinator, &config.server_name, &tls, pin)
            .await
            .map_err(io::Error::other)?;
        let mut wire = Wire::new(peer.stream);
        let admission_deadline = Instant::now() + ADMISSION_BUDGET;
        wire.send(&hello, stopped, admission_deadline).await?;
        let (input_deadline, toolchain_disposition, source_plan) = await_input_admission(
            &mut wire,
            bundle.source.manifest(),
            stopped,
            &config.coordinator,
            admission_deadline,
        )
        .await?;
        upload_inputs(
            &mut wire,
            &mut bundle,
            owner.path(),
            toolchain_disposition,
            &source_plan,
            stopped,
            input_deadline,
        )
        .await?;
        wire.send(&Message::InputsDone {}, stopped, input_deadline)
            .await?;
        require(
            matches!(
                wire.receive_until(stopped, input_deadline).await?,
                Message::Accepted {}
            ),
            "coordinator did not acknowledge operation admission",
        )?;
        eprintln!(
            "{}",
            json!({"kind":"canonical-remote-accepted", "coordinator":config.coordinator,
            "cargo_location":"coordinator", "automatic_retry":false})
        );
        receive_operation(&mut wire, &config, stopped).await
    })
}

/// Remain on the authenticated connection while the coordinator owns our queue
/// position. Only Ready permits input bytes, with a fresh upload budget; neither
/// a queued reply nor a poll renews the fixed admission deadline.
async fn await_input_admission<S: AsyncRead + AsyncWrite + Unpin>(
    wire: &mut Wire<S>,
    source_manifest: &SourceManifest,
    stopped: &AtomicBool,
    coordinator: &str,
    admission_deadline: Instant,
) -> io::Result<(Instant, ToolchainDisposition, SourcePlan)> {
    let mut reported_queue = false;
    loop {
        match wire.receive_until(stopped, admission_deadline).await? {
            Message::Ready { toolchain, source } => {
                let input_deadline = Instant::now() + TOOLCHAIN_INPUT_BUDGET;
                source.validate(source_manifest)?;
                return Ok((input_deadline, toolchain, source));
            }
            Message::Queued {} => {
                if !reported_queue {
                    eprintln!(
                        "{}",
                        json!({"kind":"canonical-remote-queued", "coordinator":coordinator,
                            "cargo_location":"coordinator", "automatic_retry":false})
                    );
                    reported_queue = true;
                }
                controlled_future(stopped, admission_deadline, async {
                    asupersync::time::sleep(runtime_transport_now(), ADMISSION_POLL).await;
                    Ok(())
                })
                .await?;
                wire.send(&Message::Poll {}, stopped, admission_deadline)
                    .await?;
            }
            _ => {
                return Err(invalid(
                    "coordinator did not grant or queue input admission",
                ));
            }
        }
    }
}

async fn flush_window<S: AsyncRead + AsyncWrite + Unpin>(
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
    let Message::Window { count } = wire.receive_until(stopped, deadline).await? else {
        return Err(invalid("expected input window acknowledgment"));
    };
    window.acknowledge(count)
}

async fn upload_message<S: AsyncRead + AsyncWrite + Unpin>(
    wire: &mut Wire<S>,
    window: &mut Window,
    message: Message,
    stopped: &AtomicBool,
    deadline: Instant,
) -> io::Result<()> {
    wire.send(&message, stopped, deadline).await?;
    if window.record()? {
        flush_window(wire, window, stopped, deadline).await?;
    }
    Ok(())
}

async fn upload_inputs<S: AsyncRead + AsyncWrite + Unpin>(
    wire: &mut Wire<S>,
    bundle: &mut PreparedLocalBundle,
    scratch: &Path,
    toolchain_disposition: ToolchainDisposition,
    source_plan: &SourcePlan,
    stopped: &AtomicBool,
    deadline: Instant,
) -> io::Result<()> {
    source_plan.validate(bundle.source.manifest())?;
    let cancelled = || stopped.load(Ordering::Acquire) || Instant::now() >= deadline;
    let mut window = Window::default();
    let files = bundle.source.manifest().files().to_vec();
    let mut requested = source_plan.missing_files.iter().copied().peekable();
    for (index, file) in files.into_iter().enumerate() {
        checkpoint(stopped, deadline)?;
        // Every captured member is checked, including reused and empty files.
        // The checkpoint API hashes through retained descriptors and refuses
        // replacement/mutation. A remote hit never replaces local custody.
        let checkpoint_file = tempfile::NamedTempFile::new_in(scratch)?;
        let mut verified = bundle
            .source
            .checkpoint_file(
                &file.path,
                checkpoint_file.as_file().try_clone()?,
                cancelled,
            )
            .map_err(|error| match error {
                SourceCheckpointError::Source(error)
                | SourceCheckpointError::Destination(error) => error,
            })?
            .into_file();
        if requested.peek().copied().map(usize::from) != Some(index) {
            continue;
        }
        requested.next();
        verified.seek(SeekFrom::Start(0))?;
        let mut offset = 0;
        // Held across awaits: an inline array would sit in the future, and
        // every move of the composed upload future copies it (bd-yxl32).
        let mut buffer = vec![0_u8; MAX_SOURCE_CHUNK];
        while offset < file.len {
            checkpoint(stopped, deadline)?;
            let length = (file.len - offset).min(buffer.len() as u64) as usize;
            verified.read_exact(&mut buffer[..length])?;
            upload_message(
                wire,
                &mut window,
                Message::SourceChunk {
                    chunk: Chunk::new(&file.path, offset, &buffer[..length])?,
                },
                stopped,
                deadline,
            )
            .await?;
            offset += length as u64;
        }
    }
    let toolchain = bundle
        .toolchain
        .as_ref()
        .ok_or_else(|| invalid("captured compiler owner disappeared"))?;
    if toolchain_disposition == ToolchainDisposition::Upload {
        for entry in toolchain.entries()? {
            checkpoint(stopped, deadline)?;
            let file = match &entry.kind {
                ToolchainEntryKind::File { bytes, .. } => Some((entry.path.clone(), *bytes)),
                _ => None,
            };
            upload_message(
                wire,
                &mut window,
                Message::ToolchainEntry {
                    entry: Entry::from_native(entry),
                },
                stopped,
                deadline,
            )
            .await?;
            if let Some((path, length)) = file {
                let mut offset = 0;
                while offset < length {
                    checkpoint(stopped, deadline)?;
                    let bytes = toolchain.read_chunk(&path, offset, MAX_SOURCE_CHUNK, cancelled)?;
                    require(
                        !bytes.is_empty(),
                        "captured compiler file ended before its declaration",
                    )?;
                    upload_message(
                        wire,
                        &mut window,
                        Message::ToolchainChunk {
                            chunk: Chunk::new(&path, offset, &bytes)?,
                        },
                        stopped,
                        deadline,
                    )
                    .await?;
                    offset += bytes.len() as u64;
                }
            }
        }
    }
    flush_window(wire, &mut window, stopped, deadline).await?;
    // A server cache hit does not waive custody of the SDK that this client
    // captured and declared. Mutation still refuses InputsDone and execution.
    toolchain.verify_retained_generation(cancelled)?;
    checkpoint(stopped, deadline)
}

fn write_output(output: Output, offset: &mut u64, writer: &mut impl Write) -> io::Result<bool> {
    require(
        output.offset == *offset,
        "remote diagnostic offset is duplicated or missing",
    )?;
    let bytes = decode_hex(&output.bytes, MAX_SOURCE_CHUNK)?;
    let next = offset
        .checked_add(bytes.len() as u64)
        .filter(|next| *next <= OUTPUT_TOTAL_BYTES)
        .ok_or_else(|| invalid("remote diagnostic stream exceeds its bound"))?;
    writer.write_all(&bytes)?;
    writer.flush()?;
    *offset = next;
    Ok(!bytes.is_empty())
}

async fn receive_operation<S: AsyncRead + AsyncWrite + Unpin>(
    wire: &mut Wire<S>,
    config: &ClientProfile,
    stopped: &AtomicBool,
) -> io::Result<i32> {
    let execution_deadline =
        Instant::now() + Duration::from_secs(config.settings.timeout_seconds) + DELIVERY_BUDGET;
    let mut stdout_offset = 0;
    let mut stderr_offset = 0;
    let (exit_code, target) = loop {
        wire.send(&Message::Poll {}, stopped, execution_deadline)
            .await?;
        match wire.receive_until(stopped, execution_deadline).await? {
            Message::Progress { stdout, stderr } => {
                let first = write_output(stdout, &mut stdout_offset, &mut io::stdout().lock())?;
                let second = write_output(stderr, &mut stderr_offset, &mut io::stderr().lock())?;
                require(
                    stdout_offset + stderr_offset <= OUTPUT_TOTAL_BYTES,
                    "remote aggregate diagnostic output exceeds its bound",
                )?;
                if !first && !second {
                    asupersync::time::sleep(runtime_transport_now(), Duration::from_millis(100))
                        .await;
                }
            }
            Message::BuildFinished {
                exit_code,
                stdout_bytes,
                stderr_bytes,
                target,
            } => {
                require(
                    (0..=255).contains(&exit_code)
                        && stdout_bytes == stdout_offset
                        && stderr_bytes == stderr_offset,
                    "remote completion has an invalid exit code or incomplete diagnostics",
                )?;
                require(
                    exit_code == 0 || target.is_none(),
                    "failed remote operation offered successful artifacts",
                )?;
                break (exit_code, target);
            }
            _ => {
                return Err(invalid(
                    "unexpected message while awaiting remote compilation",
                ));
            }
        }
    };
    let delivery_deadline = Instant::now() + DELIVERY_BUDGET;
    let installed = if let Some(manifest) = target {
        receive_target(
            wire,
            manifest,
            &config.output_destination,
            stopped,
            delivery_deadline,
        )
        .await?;
        Some(&config.output_destination)
    } else {
        wire.send(&Message::Close {}, stopped, delivery_deadline)
            .await?;
        None
    };
    let Message::Complete {
        exit_code: completed,
    } = wire.receive_until(stopped, delivery_deadline).await?
    else {
        return Err(invalid(
            "remote operation ended without its terminal completion receipt",
        ));
    };
    require(
        completed == exit_code,
        "remote terminal exit status changed",
    )?;
    // This locally chosen path is reported only after the final coordinator
    // receipt. Diagnostic JSON from Cargo never authorizes installation.
    eprintln!(
        "{}",
        json!({"kind":"canonical-remote-completed", "exit_code":exit_code,
        "target_root":installed, "coordinator":config.coordinator, "cargo_location":"coordinator"})
    );
    Ok(exit_code)
}

async fn receive_target<S: AsyncRead + AsyncWrite + Unpin>(
    wire: &mut Wire<S>,
    manifest: Manifest,
    destination: &Path,
    stopped: &AtomicBool,
    deadline: Instant,
) -> io::Result<()> {
    require_absent(destination)?;
    let native = manifest.native()?;
    let manifest_sha256 = encode_hex(&native.digest());
    let mut target = ReceivedTarget::new(
        destination
            .parent()
            .ok_or_else(|| invalid("target parent missing"))?,
        native,
    )?;
    wire.send(&Message::ReceiveTarget {}, stopped, deadline)
        .await?;
    let mut window = Window::default();
    loop {
        match wire.receive_until(stopped, deadline).await? {
            Message::ArtifactChunk { chunk } => {
                window.record()?;
                let (bytes, sha256) = chunk.verified_bytes()?;
                target.write_chunk(&chunk.path, chunk.offset, &bytes, sha256)?;
            }
            Message::WindowEnd { count } => {
                window.acknowledge(count)?;
                wire.send(&Message::Window { count }, stopped, deadline)
                    .await?;
            }
            Message::ArtifactEnd {} => {
                require(
                    !window.pending(),
                    "remote artifacts ended before their last window acknowledgment",
                )?;
                break;
            }
            _ => {
                return Err(invalid(
                    "unexpected message during remote artifact transfer",
                ));
            }
        }
    }
    let cancelled = || stopped.load(Ordering::Acquire) || Instant::now() >= deadline;
    target.seal(&cancelled)?;
    checkpoint(stopped, deadline)?;
    wire.send(
        &Message::Received {
            manifest_sha256: manifest_sha256.clone(),
        },
        stopped,
        deadline,
    )
    .await?;
    let Message::Commit {
        manifest_sha256: committed,
    } = wire.receive_until(stopped, deadline).await?
    else {
        return Err(invalid(
            "coordinator did not authorize delivery of the verified target",
        ));
    };
    require(
        committed == manifest_sha256,
        "coordinator authorized a different target manifest",
    )?;
    target.publish(destination, &cancelled)?;
    // A lost response after this rename leaves an installed directory and an
    // uncertain command result. Never remove it or reexecute automatically.
    wire.send(&Message::Published { manifest_sha256 }, stopped, deadline)
        .await
}

#[cfg(test)]
mod tests {
    use super::super::ToolchainInput;
    use super::super::source_inputs::SourceInput;
    use super::super::wire;
    use super::*;
    use asupersync::io::ReadBuf;
    use asupersync::net::{TcpListener, TcpStream};
    use rabs_asupersync::worker_transport::{JsonAtpStream, runtime_transport_now};
    use rabs_sandbox::snapshot_capture::capture_sealed_source;
    use rabs_sandbox::source_transfer::{MAX_SOURCE_BYTES, SourceFile, SourceReceiver};
    use rabs_sandbox::toolchain_dataset::{ToolchainLimits, capture_toolchain};
    use rabs_sandbox::toolchain_transfer::ToolchainReceiver;
    use sha2::{Digest, Sha256};
    use std::future::Future;
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, symlink};
    use std::pin::{Pin, pin};
    use std::sync::{Mutex, mpsc};
    use std::task::{Context, Poll};

    fn private() -> tempfile::TempDir {
        tempfile::Builder::new()
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap()
    }

    fn native<T>(future: impl Future<Output = T>) -> T {
        let runtime = RuntimeBuilder::current_thread().build().unwrap();
        block_on_top_level(&runtime, async {
            asupersync::time::timeout(runtime_transport_now(), Duration::from_secs(30), future)
                .await
                .expect("native canonical input transfer exceeded its deadline")
        })
    }

    /// Exercise the real wire and client state machine without opening a socket.
    /// This is a fragmented byte peer, not TLS or remote compiler qualification.
    struct AdmissionStream {
        input: Vec<u8>,
        offset: usize,
        quantum: usize,
        repeat: bool,
        output: Arc<Mutex<Vec<u8>>>,
        ready_offset: Option<usize>,
        ready_seen: Arc<Mutex<Option<Instant>>>,
        first_read: Option<mpsc::Sender<()>>,
    }

    impl AdmissionStream {
        fn new(messages: &[Message], repeat: bool) -> Self {
            let mut input = Vec::new();
            let mut ready_offset = None;
            for message in messages {
                if matches!(message, Message::Ready { .. }) && ready_offset.is_none() {
                    ready_offset = Some(input.len());
                }
                input.extend(serde_json::to_vec(message).unwrap());
                input.push(b'\n');
            }
            Self {
                input,
                offset: 0,
                quantum: 3,
                repeat,
                output: Arc::new(Mutex::new(Vec::new())),
                ready_offset,
                ready_seen: Arc::new(Mutex::new(None)),
                first_read: None,
            }
        }
    }

    impl AsyncRead for AdmissionStream {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            output: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let stream = self.get_mut();
            if let Some(observed) = stream.first_read.take() {
                observed.send(()).unwrap();
            }
            if stream.repeat && stream.offset == stream.input.len() {
                stream.offset = 0;
            }
            let count = output
                .remaining()
                .min(stream.quantum)
                .min(stream.input.len() - stream.offset);
            if stream
                .ready_offset
                .is_some_and(|offset| stream.offset <= offset && offset < stream.offset + count)
            {
                *stream.ready_seen.lock().unwrap() = Some(Instant::now());
            }
            output.put_slice(&stream.input[stream.offset..stream.offset + count]);
            stream.offset += count;
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for AdmissionStream {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            let count = bytes.len().min(self.quantum);
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

    fn admission_messages(output: &Mutex<Vec<u8>>) -> Vec<Value> {
        output
            .lock()
            .unwrap()
            .split(|byte| *byte == b'\n')
            .filter(|record| !record.is_empty())
            .map(|record| serde_json::from_slice(record).unwrap())
            .collect()
    }

    fn admission_manifest() -> SourceManifest {
        SourceManifest::new(vec![
            SourceFile {
                path: "Cargo.toml".into(),
                len: b"approved input".len() as u64,
                sha256: Sha256::digest(b"approved input").into(),
                executable: false,
            },
            SourceFile {
                path: "empty".into(),
                len: 0,
                sha256: Sha256::digest([]).into(),
                executable: false,
            },
            SourceFile {
                path: "src/lib.rs".into(),
                len: 1,
                sha256: Sha256::digest(b"x").into(),
                executable: false,
            },
        ])
        .unwrap()
    }

    #[test]
    fn admission_wait_polls_only_queued_peer_and_gives_upload_its_full_budget() {
        native(async {
            let manifest = admission_manifest();
            let stream = AdmissionStream::new(
                &[
                    Message::Queued {},
                    Message::Queued {},
                    Message::Ready {
                        toolchain: ToolchainDisposition::Upload,
                        source: SourcePlan::all(&manifest).unwrap(),
                    },
                    Message::Accepted {},
                ],
                false,
            );
            let output = Arc::clone(&stream.output);
            let ready_seen = Arc::clone(&stream.ready_seen);
            let mut wire = Wire::new(stream);
            let stopped = AtomicBool::new(false);
            let started = Instant::now();
            let admission_deadline = started + Duration::from_secs(5);
            let (input_deadline, toolchain_disposition, source_plan) = await_input_admission(
                &mut wire,
                &manifest,
                &stopped,
                "fixture",
                admission_deadline,
            )
            .await
            .unwrap();
            assert_eq!(toolchain_disposition, ToolchainDisposition::Upload);
            assert_eq!(source_plan, SourcePlan::all(&manifest).unwrap());
            // Waiting does not subtract from or reset the upload phase's budget.
            assert!(input_deadline >= ready_seen.lock().unwrap().unwrap() + TOOLCHAIN_INPUT_BUDGET);
            assert!(input_deadline <= Instant::now() + TOOLCHAIN_INPUT_BUDGET);
            assert!(input_deadline > admission_deadline);
            assert_eq!(
                admission_messages(&output),
                [json!({"kind":"poll"}), json!({"kind":"poll"})]
            );
            // Ready ends admission exactly; a buffered next-phase response is
            // not mistaken for another queue reply or consumed by the wait.
            assert!(matches!(
                wire.receive_until(&stopped, input_deadline).await.unwrap(),
                Message::Accepted {}
            ));
        });
    }

    #[test]
    fn admission_ready_does_not_poll_and_only_then_allows_input_bytes() {
        native(async {
            let manifest = admission_manifest();
            let stream = AdmissionStream::new(
                &[Message::Ready {
                    toolchain: ToolchainDisposition::Reuse,
                    source: SourcePlan::all(&manifest).unwrap(),
                }],
                false,
            );
            let output = Arc::clone(&stream.output);
            let mut wire = Wire::new(stream);
            let stopped = AtomicBool::new(false);
            let started = Instant::now();
            let (input_deadline, toolchain_disposition, source_plan) = await_input_admission(
                &mut wire,
                &manifest,
                &stopped,
                "fixture",
                started + ADMISSION_BUDGET,
            )
            .await
            .unwrap();
            assert_eq!(toolchain_disposition, ToolchainDisposition::Reuse);
            assert_eq!(source_plan, SourcePlan::all(&manifest).unwrap());
            assert!(input_deadline >= started + TOOLCHAIN_INPUT_BUDGET);
            assert!(input_deadline <= Instant::now() + TOOLCHAIN_INPUT_BUDGET);
            assert!(output.lock().unwrap().is_empty());
            wire.send(
                &Message::SourceChunk {
                    chunk: Chunk::new("Cargo.toml", 0, b"approved input").unwrap(),
                },
                &stopped,
                input_deadline,
            )
            .await
            .unwrap();
            let messages = admission_messages(&output);
            assert_eq!(messages.len(), 1);
            assert_eq!(messages[0]["kind"], "source-chunk");
        });
    }

    #[test]
    fn admission_queue_replies_cannot_renew_the_absolute_deadline() {
        native(async {
            let manifest = admission_manifest();
            let stream = AdmissionStream::new(&[Message::Queued {}], true);
            let output = Arc::clone(&stream.output);
            let mut wire = Wire::new(stream);
            let stopped = AtomicBool::new(false);
            let deadline = Instant::now() + ADMISSION_POLL + ADMISSION_POLL / 2;
            assert_eq!(
                await_input_admission(&mut wire, &manifest, &stopped, "fixture", deadline)
                    .await
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::TimedOut
            );
            let messages = admission_messages(&output);
            assert!(messages.len() <= 1);
            assert!(
                messages
                    .iter()
                    .all(|message| message == &json!({"kind":"poll"}))
            );
        });
    }

    #[test]
    fn admission_idle_poll_wait_observes_local_cancellation() {
        let stopped = Arc::new(AtomicBool::new(false));
        let cancel = Arc::clone(&stopped);
        let (observed, waiting) = mpsc::channel();
        let setter = std::thread::spawn(move || {
            waiting.recv_timeout(Duration::from_secs(5)).unwrap();
            std::thread::sleep(Duration::from_millis(25));
            cancel.store(true, Ordering::Release);
        });
        let mut stream = AdmissionStream::new(&[Message::Queued {}], true);
        stream.first_read = Some(observed);
        let output = Arc::clone(&stream.output);
        let mut wire = Wire::new(stream);
        let manifest = admission_manifest();
        let result = native(await_input_admission(
            &mut wire,
            &manifest,
            &stopped,
            "fixture",
            Instant::now() + Duration::from_secs(5),
        ));
        setter.join().unwrap();
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Interrupted);
        assert!(
            admission_messages(&output)
                .iter()
                .all(|message| message == &json!({"kind":"poll"}))
        );
    }

    #[test]
    fn admission_refusal_disconnect_and_wrong_phase_never_become_ready_or_retry() {
        native(async {
            let manifest = admission_manifest();
            for (reply, kind) in [
                (
                    Some(Message::Failure {
                        message: "queue capacity exhausted".into(),
                    }),
                    io::ErrorKind::InvalidData,
                ),
                (Some(Message::Cancel {}), io::ErrorKind::Interrupted),
                (Some(Message::Accepted {}), io::ErrorKind::InvalidData),
                (
                    Some(Message::Window { count: 1 }),
                    io::ErrorKind::InvalidData,
                ),
                (None, io::ErrorKind::UnexpectedEof),
            ] {
                let mut replies = vec![Message::Queued {}];
                replies.extend(reply);
                let stream = AdmissionStream::new(&replies, false);
                let output = Arc::clone(&stream.output);
                let mut wire = Wire::new(stream);
                let error = await_input_admission(
                    &mut wire,
                    &manifest,
                    &AtomicBool::new(false),
                    "fixture",
                    Instant::now() + Duration::from_secs(5),
                )
                .await
                .unwrap_err();
                assert_eq!(error.kind(), kind);
                assert_eq!(admission_messages(&output), [json!({"kind":"poll"})]);
            }
            let stream = AdmissionStream::new(&[Message::Accepted {}], false);
            let output = Arc::clone(&stream.output);
            let mut wire = Wire::new(stream);
            assert!(
                await_input_admission(
                    &mut wire,
                    &manifest,
                    &AtomicBool::new(false),
                    "fixture",
                    Instant::now() + Duration::from_secs(5),
                )
                .await
                .is_err()
            );
            assert!(output.lock().unwrap().is_empty());
        });
    }

    #[test]
    fn admission_refuses_invalid_source_plans_before_any_input_bytes() {
        native(async {
            let manifest = admission_manifest();
            let all = SourcePlan::all(&manifest).unwrap();
            let mut invalid_plans = vec![
                SourcePlan {
                    manifest_sha256: "00".repeat(32),
                    ..all.clone()
                },
                SourcePlan {
                    manifest_sha256: "FF".repeat(32),
                    ..all.clone()
                },
            ];
            for missing_files in [
                vec![0, 0],
                vec![2, 0],
                vec![1],
                vec![3],
                vec![u16::MAX],
                vec![0; rabs_sandbox::source_transfer::MAX_SOURCE_FILES + 1],
            ] {
                invalid_plans.push(SourcePlan {
                    missing_files,
                    ..all.clone()
                });
            }
            for toolchain in [ToolchainDisposition::Upload, ToolchainDisposition::Reuse] {
                for source in &invalid_plans {
                    let peer = AdmissionStream::new(
                        &[Message::Ready {
                            toolchain,
                            source: source.clone(),
                        }],
                        false,
                    );
                    let output = Arc::clone(&peer.output);
                    let mut wire = Wire::new(peer);
                    let error = await_input_admission(
                        &mut wire,
                        &manifest,
                        &AtomicBool::new(false),
                        "fixture",
                        Instant::now() + Duration::from_secs(5),
                    )
                    .await
                    .unwrap_err();
                    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
                    assert!(output.lock().unwrap().is_empty());
                }
            }
        });
    }

    struct InputFixture {
        owner: tempfile::TempDir,
        bundle: PreparedLocalBundle,
        source_bytes: Vec<u8>,
        runtime_bytes: Vec<u8>,
    }

    impl InputFixture {
        fn new() -> Self {
            let owner = private();
            let original = owner.path().join("original-source");
            fs::DirBuilder::new().mode(0o700).create(&original).unwrap();
            let source_bytes: Vec<_> = (0..MAX_SOURCE_CHUNK * 6 + 19)
                .map(|index| (index % 251) as u8)
                .collect();
            fs::write(original.join("a-binary"), &source_bytes).unwrap();
            fs::write(original.join("b-empty"), []).unwrap();
            fs::write(original.join("c-executable"), b"#!/bin/sh\nexit 0\n").unwrap();
            fs::set_permissions(
                original.join("c-executable"),
                fs::Permissions::from_mode(0o755),
            )
            .unwrap();
            let image = Arc::new(
                capture_sealed_source(
                    &[("workspace".into(), original.clone())],
                    false,
                    2,
                    MAX_SOURCE_BYTES,
                )
                .unwrap(),
            );
            let selected = ["a-binary", "b-empty", "c-executable"].map(str::to_owned);
            let upload = crate::coord::source_delivery::SourceUpload::from_snapshot(
                Arc::clone(&image),
                "workspace",
                &selected,
            )
            .unwrap();
            let declaration: Manifest = serde_json::from_value(upload.wire_manifest()).unwrap();
            let manifest = declaration.native().unwrap();
            let mut source =
                SourceReceiver::create(&owner.path().join("sealed-source"), manifest.clone())
                    .unwrap();
            for file in manifest.files() {
                let bytes = image.file_bytes("workspace", &file.path).unwrap();
                for (index, chunk) in bytes.chunks(MAX_SOURCE_CHUNK).enumerate() {
                    source
                        .write_chunk(
                            &file.path,
                            index as u64 * MAX_SOURCE_CHUNK as u64,
                            chunk,
                            Sha256::digest(chunk).into(),
                        )
                        .unwrap();
                }
            }
            source.seal().unwrap();
            fs::write(original.join("a-binary"), b"changed after source capture").unwrap();

            let sdk = owner.path().join("original-sdk");
            for directory in ["", "bin", "lib", "lib/empty"] {
                fs::DirBuilder::new()
                    .mode(0o700)
                    .create(sdk.join(directory))
                    .unwrap();
            }
            let runtime_bytes: Vec<_> = (0..MAX_SOURCE_CHUNK * 6 + 37)
                .map(|index| (index % 239) as u8)
                .collect();
            fs::write(sdk.join("lib/runtime"), &runtime_bytes).unwrap();
            fs::write(sdk.join("bin/compiler"), b"#!/bin/sh\nexit 0\n").unwrap();
            fs::set_permissions(sdk.join("bin/compiler"), fs::Permissions::from_mode(0o755))
                .unwrap();
            fs::write(sdk.join("empty-file"), []).unwrap();
            symlink("../lib/runtime", sdk.join("bin/runtime")).unwrap();
            symlink("bin/compiler", sdk.join("compiler")).unwrap();
            let toolchain = capture_toolchain(
                &sdk,
                &owner.path().join("sealed-sdk"),
                None,
                &ToolchainLimits::default(),
                || false,
            )
            .unwrap();
            toolchain.sync(|| false).unwrap();
            fs::write(sdk.join("lib/runtime"), b"changed after SDK capture").unwrap();
            fs::DirBuilder::new()
                .mode(0o700)
                .create(owner.path().join("scratch"))
                .unwrap();
            Self {
                owner,
                bundle: PreparedLocalBundle {
                    report: Value::Null,
                    source,
                    toolchain: Some(Arc::new(toolchain)),
                },
                source_bytes,
                runtime_bytes,
            }
        }

        fn receivers(
            &self,
            source_parent: &Path,
            sdk_parent: &Path,
        ) -> (SourceReceiver, ToolchainReceiver) {
            (
                SourceReceiver::create(
                    &source_parent.join("source"),
                    self.bundle.source.manifest().clone(),
                )
                .unwrap(),
                ToolchainReceiver::create(
                    &sdk_parent.join("toolchain"),
                    *self.bundle.toolchain.as_ref().unwrap().identity(),
                    ToolchainLimits::default(),
                )
                .unwrap(),
            )
        }

        fn upload_peer(
            &self,
            disposition: ToolchainDisposition,
            source: SourcePlan,
        ) -> AdmissionStream {
            source.validate(self.bundle.source.manifest()).unwrap();
            let mut frames: u64 = source
                .missing_files
                .iter()
                .map(|index| {
                    self.bundle.source.manifest().files()[usize::from(*index)]
                        .len
                        .div_ceil(MAX_SOURCE_CHUNK as u64)
                })
                .sum();
            if disposition == ToolchainDisposition::Upload {
                for entry in self.bundle.toolchain.as_ref().unwrap().entries().unwrap() {
                    frames += 1;
                    if let ToolchainEntryKind::File { bytes, .. } = entry.kind {
                        frames += bytes.div_ceil(MAX_SOURCE_CHUNK as u64);
                    }
                }
            }
            let mut replies = vec![Message::Ready {
                toolchain: disposition,
                source,
            }];
            // Like the production receiver, acknowledge exact cumulative counts.
            let mut acknowledged = 0;
            while frames != 0 {
                let count = frames.min(wire::WINDOW);
                acknowledged += count;
                replies.push(Message::Window {
                    count: acknowledged,
                });
                frames -= count;
            }
            let mut peer = AdmissionStream::new(&replies, false);
            peer.quantum = MAX_JSON_RECORD;
            peer
        }
    }

    #[test]
    fn sdk_reuse_omits_only_sdk_frames_and_preserves_exact_source_transfer() {
        // Both paths run the production uploader over bounded in-memory wire
        // records and seal the resulting bytes with real filesystem receivers.
        // This proves byte transfer behavior, not TLS or remote Cargo execution.
        for disposition in [ToolchainDisposition::Upload, ToolchainDisposition::Reuse] {
            let mut fixture = InputFixture::new();
            let expected_sdk = *fixture.bundle.toolchain.as_ref().unwrap().identity();
            let peer = fixture.upload_peer(
                disposition,
                SourcePlan::all(fixture.bundle.source.manifest()).unwrap(),
            );
            let output = Arc::clone(&peer.output);
            let mut wire = Wire::new(peer);
            let stopped = AtomicBool::new(false);
            native(async {
                let (deadline, selected, source_plan) = await_input_admission(
                    &mut wire,
                    fixture.bundle.source.manifest(),
                    &stopped,
                    "fixture",
                    Instant::now() + Duration::from_secs(5),
                )
                .await
                .unwrap();
                assert_eq!(selected, disposition);
                assert!(output.lock().unwrap().is_empty());
                upload_inputs(
                    &mut wire,
                    &mut fixture.bundle,
                    &fixture.owner.path().join("scratch"),
                    selected,
                    &source_plan,
                    &stopped,
                    deadline,
                )
                .await
                .unwrap();
                wire.send(&Message::InputsDone {}, &stopped, deadline)
                    .await
                    .unwrap();
            });
            let destination = private();
            let sdk_destination = private();
            let (mut source, mut sdk) =
                fixture.receivers(destination.path(), sdk_destination.path());
            let mut source_bytes = 0_u64;
            let mut sdk_bytes = 0_u64;
            let mut sdk_entries = 0_usize;
            let mut frames = 0_u64;
            let mut window_total = 0_u64;
            let mut completed = false;
            for record in admission_messages(&output) {
                assert!(!completed, "no frames may follow InputsDone");
                match serde_json::from_value::<Message>(record).unwrap() {
                    Message::SourceChunk { chunk } => {
                        let (bytes, sha256) = chunk.verified_bytes().unwrap();
                        source
                            .write_chunk(&chunk.path, chunk.offset, &bytes, sha256)
                            .unwrap();
                        source_bytes += bytes.len() as u64;
                        frames += 1;
                    }
                    Message::ToolchainEntry { entry } => {
                        assert_eq!(disposition, ToolchainDisposition::Upload);
                        sdk.entry(entry.native()).unwrap();
                        sdk_entries += 1;
                        frames += 1;
                    }
                    Message::ToolchainChunk { chunk } => {
                        assert_eq!(disposition, ToolchainDisposition::Upload);
                        let (bytes, sha256) = chunk.verified_bytes().unwrap();
                        sdk.write_chunk(&chunk.path, chunk.offset, &bytes, sha256)
                            .unwrap();
                        sdk_bytes += bytes.len() as u64;
                        frames += 1;
                    }
                    Message::WindowEnd { count } => {
                        // Each window holds 1..=WINDOW frames; the end marker
                        // carries the exact cumulative count (see wire::Window).
                        assert!((1..=wire::WINDOW).contains(&frames));
                        window_total += frames;
                        assert_eq!(count, window_total);
                        frames = 0;
                    }
                    Message::InputsDone {} => {
                        assert_eq!(frames, 0);
                        completed = true;
                    }
                    message => panic!("unexpected upload message: {message:?}"),
                }
                assert!(frames <= wire::WINDOW);
            }
            assert!(completed);
            source.seal().unwrap();
            assert_eq!(source.manifest(), fixture.bundle.source.manifest());
            let source_root = source.sealed_root().unwrap();
            assert_eq!(
                fs::read(source_root.join("a-binary")).unwrap(),
                fixture.source_bytes
            );
            assert!(fs::read(source_root.join("b-empty")).unwrap().is_empty());
            assert_eq!(
                fs::read(source_root.join("c-executable")).unwrap(),
                b"#!/bin/sh\nexit 0\n"
            );
            assert_eq!(
                fs::metadata(source_root.join("c-executable"))
                    .unwrap()
                    .mode()
                    & 0o7777,
                0o555
            );
            assert_eq!(
                source_bytes,
                (fixture.source_bytes.len() + b"#!/bin/sh\nexit 0\n".len()) as u64
            );
            if disposition == ToolchainDisposition::Upload {
                let received_sdk = sdk.seal(|| false).unwrap();
                assert_eq!(received_sdk.identity(), &expected_sdk);
                assert_eq!(sdk_bytes, expected_sdk.bytes);
                assert!(sdk_entries > 0);
                assert_eq!(
                    fs::read(received_sdk.root().join("lib/runtime")).unwrap(),
                    fixture.runtime_bytes
                );
            } else {
                assert_eq!((sdk_bytes, sdk_entries), (0, 0));
                assert_eq!(sdk.entry_count(), 0);
            }
            assert_eq!(
                fs::read_dir(fixture.owner.path().join("scratch"))
                    .unwrap()
                    .count(),
                0
            );
        }
    }

    #[test]
    fn source_delta_uploads_only_missing_bytes_and_reconstructs_the_complete_tree() {
        // The byte peer selects real captured members. Seed its other members
        // into a fresh receiver, then apply exactly the production client's
        // emitted frames. This is input transfer proof, not a TLS/Cargo claim.
        for disposition in [ToolchainDisposition::Upload, ToolchainDisposition::Reuse] {
            for missing in [Vec::new(), vec![0], vec![2]] {
                let mut fixture = InputFixture::new();
                let manifest = fixture.bundle.source.manifest().clone();
                let plan = SourcePlan::new(&manifest, missing).unwrap();
                let expected_bytes: u64 = plan
                    .missing_files
                    .iter()
                    .map(|index| manifest.files()[usize::from(*index)].len)
                    .sum();
                let destination = private();
                let mut receiver = SourceReceiver::create(
                    &destination.path().join("source"),
                    manifest.clone(),
                )
                .unwrap();
                for (index, file) in manifest.files().iter().enumerate() {
                    let index = u16::try_from(index).unwrap();
                    if file.len == 0 || plan.missing_files.contains(&index) {
                        continue;
                    }
                    let spool = tempfile::NamedTempFile::new_in(destination.path()).unwrap();
                    let mut verified = fixture
                        .bundle
                        .source
                        .checkpoint_file(
                            &file.path,
                            spool.as_file().try_clone().unwrap(),
                            || false,
                        )
                        .unwrap()
                        .into_file();
                    receiver
                        .import_file_with_cloner(
                            &file.path,
                            &mut verified,
                            || false,
                            rabs_cas::materialization::try_verified_reflink,
                        )
                        .unwrap();
                }
                let peer = fixture.upload_peer(disposition, plan.clone());
                let output = Arc::clone(&peer.output);
                let mut wire = Wire::new(peer);
                let stopped = AtomicBool::new(false);
                native(async {
                    let (deadline, selected, source_plan) = await_input_admission(
                        &mut wire,
                        &manifest,
                        &stopped,
                        "fixture",
                        Instant::now() + Duration::from_secs(5),
                    )
                    .await
                    .unwrap();
                    assert_eq!(selected, disposition);
                    assert_eq!(source_plan, plan);
                    upload_inputs(
                        &mut wire,
                        &mut fixture.bundle,
                        &fixture.owner.path().join("scratch"),
                        selected,
                        &source_plan,
                        &stopped,
                        deadline,
                    )
                    .await
                    .unwrap();
                    wire.send(&Message::InputsDone {}, &stopped, deadline)
                        .await
                        .unwrap();
                });
                let mut source_bytes = 0_u64;
                let mut sdk_bytes = 0_u64;
                let mut sdk_entries = 0;
                let mut pending = 0_u64;
                let mut cumulative = 0_u64;
                let mut completed = false;
                for record in admission_messages(&output) {
                    assert!(!completed, "no frames may follow InputsDone");
                    match serde_json::from_value::<Message>(record).unwrap() {
                        Message::SourceChunk { chunk } => {
                            let index = manifest
                                .files()
                                .iter()
                                .position(|file| file.path == chunk.path)
                                .unwrap();
                            assert!(plan.missing_files.contains(&u16::try_from(index).unwrap()));
                            let (bytes, sha256) = chunk.verified_bytes().unwrap();
                            receiver
                                .write_chunk(&chunk.path, chunk.offset, &bytes, sha256)
                                .unwrap();
                            source_bytes += bytes.len() as u64;
                            pending += 1;
                        }
                        Message::ToolchainEntry { .. } => {
                            assert_eq!(disposition, ToolchainDisposition::Upload);
                            sdk_entries += 1;
                            pending += 1;
                        }
                        Message::ToolchainChunk { chunk } => {
                            assert_eq!(disposition, ToolchainDisposition::Upload);
                            sdk_bytes += chunk.verified_bytes().unwrap().0.len() as u64;
                            pending += 1;
                        }
                        Message::WindowEnd { count } => {
                            assert!((1..=wire::WINDOW).contains(&pending));
                            cumulative += pending;
                            assert_eq!(count, cumulative);
                            pending = 0;
                        }
                        Message::InputsDone {} => {
                            assert_eq!(pending, 0);
                            completed = true;
                        }
                        message => panic!("unexpected delta upload message: {message:?}"),
                    }
                    assert!(pending <= wire::WINDOW);
                }
                assert!(completed);
                assert_eq!(source_bytes, expected_bytes);
                if disposition == ToolchainDisposition::Upload {
                    assert!(sdk_entries > 0);
                    assert_eq!(
                        sdk_bytes,
                        fixture.bundle.toolchain.as_ref().unwrap().identity().bytes,
                    );
                } else {
                    assert_eq!((sdk_bytes, sdk_entries), (0, 0));
                }
                receiver.seal().unwrap();
                assert_eq!(receiver.manifest(), &manifest);
                let root = receiver.sealed_root().unwrap();
                assert_eq!(fs::read(root.join("a-binary")).unwrap(), fixture.source_bytes);
                assert!(fs::read(root.join("b-empty")).unwrap().is_empty());
                assert_eq!(
                    fs::read(root.join("c-executable")).unwrap(),
                    b"#!/bin/sh\nexit 0\n",
                );
                assert_eq!(
                    fs::metadata(root.join("c-executable")).unwrap().mode() & 0o7777,
                    0o555,
                );
                for file in manifest.files() {
                    let received = fs::metadata(root.join(&file.path)).unwrap();
                    let captured = fs::metadata(
                        fixture.bundle.source.sealed_root().unwrap().join(&file.path),
                    )
                    .unwrap();
                    assert_eq!(received.nlink(), 1);
                    assert_ne!((received.dev(), received.ino()), (captured.dev(), captured.ino()));
                }
                assert_eq!(
                    fs::read_dir(fixture.owner.path().join("scratch")).unwrap().count(),
                    0,
                );
            }
        }
    }

    #[test]
    fn full_source_reuse_does_not_skip_changed_or_empty_members_or_sdk_custody() {
        for member in ["a-binary", "b-empty", "c-executable", "sdk"] {
            let mut fixture = InputFixture::new();
            let plan = SourcePlan::new(fixture.bundle.source.manifest(), Vec::new()).unwrap();
            let peer = fixture.upload_peer(ToolchainDisposition::Reuse, plan);
            let path = if member == "sdk" {
                fixture.bundle.toolchain.as_ref().unwrap().root().join("lib/runtime")
            } else {
                fixture.bundle.source.sealed_root().unwrap().join(member)
            };
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            fs::write(path, b"changed retained bytes").unwrap();
            let output = Arc::clone(&peer.output);
            let mut wire = Wire::new(peer);
            let stopped = AtomicBool::new(false);
            let result = native(async {
                let (deadline, disposition, source_plan) = await_input_admission(
                    &mut wire,
                    fixture.bundle.source.manifest(),
                    &stopped,
                    "fixture",
                    Instant::now() + Duration::from_secs(5),
                )
                .await?;
                upload_inputs(
                    &mut wire,
                    &mut fixture.bundle,
                    &fixture.owner.path().join("scratch"),
                    disposition,
                    &source_plan,
                    &stopped,
                    deadline,
                )
                .await?;
                wire.send(&Message::InputsDone {}, &stopped, deadline).await
            });
            assert!(result.is_err(), "a warm hint cannot hide changed {member}");
            assert!(output.lock().unwrap().is_empty());
            assert_eq!(
                fs::read_dir(fixture.owner.path().join("scratch")).unwrap().count(),
                0,
            );
        }
    }

    #[test]
    fn uploader_validates_the_complete_plan_before_opening_scratch_or_sending_bytes() {
        let mut fixture = InputFixture::new();
        let mut source_plan = SourcePlan::all(fixture.bundle.source.manifest()).unwrap();
        source_plan.missing_files.push(0);
        let peer = AdmissionStream::new(&[], false);
        let output = Arc::clone(&peer.output);
        let mut wire = Wire::new(peer);
        let error = native(upload_inputs(
            &mut wire,
            &mut fixture.bundle,
            &fixture.owner.path().join("absent-scratch"),
            ToolchainDisposition::Upload,
            &source_plan,
            &AtomicBool::new(false),
            Instant::now() + Duration::from_secs(5),
        ))
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(output.lock().unwrap().is_empty());
        assert!(!fixture.owner.path().join("absent-scratch").exists());
    }

    #[test]
    fn sdk_reuse_still_refuses_mutated_source_or_retained_sdk_before_inputs_done() {
        for mutate_sdk in [false, true] {
            let mut fixture = InputFixture::new();
            let peer = fixture.upload_peer(
                ToolchainDisposition::Reuse,
                SourcePlan::all(fixture.bundle.source.manifest()).unwrap(),
            );
            let path = if mutate_sdk {
                fixture
                    .bundle
                    .toolchain
                    .as_ref()
                    .unwrap()
                    .root()
                    .join("lib/runtime")
            } else {
                fixture
                    .bundle
                    .source
                    .sealed_root()
                    .unwrap()
                    .join("a-binary")
            };
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            fs::write(path, b"changed retained input").unwrap();
            let output = Arc::clone(&peer.output);
            let mut wire = Wire::new(peer);
            let stopped = AtomicBool::new(false);
            let result = native(async {
                let (deadline, disposition, source_plan) = await_input_admission(
                    &mut wire,
                    fixture.bundle.source.manifest(),
                    &stopped,
                    "fixture",
                    Instant::now() + Duration::from_secs(5),
                )
                .await?;
                upload_inputs(
                    &mut wire,
                    &mut fixture.bundle,
                    &fixture.owner.path().join("scratch"),
                    disposition,
                    &source_plan,
                    &stopped,
                    deadline,
                )
                .await?;
                wire.send(&Message::InputsDone {}, &stopped, deadline).await
            });
            assert!(result.is_err(), "changed retained inputs cannot execute");
            for message in admission_messages(&output) {
                assert!(matches!(
                    message["kind"].as_str(),
                    Some("source-chunk" | "window-end")
                ));
            }
        }
    }

    #[test]
    fn sdk_reuse_failure_or_second_disposition_never_restarts_the_upload() {
        for case in 0..4 {
            let mut fixture = InputFixture::new();
            let source = SourcePlan::all(fixture.bundle.source.manifest()).unwrap();
            let (reply, expected) = match case {
                0 => (
                    Some(Message::Ready {
                        toolchain: ToolchainDisposition::Upload,
                        source: source.clone(),
                    }),
                    io::ErrorKind::InvalidData,
                ),
                1 => (
                    Some(Message::Failure {
                        message: "cached SDK became unavailable".into(),
                    }),
                    io::ErrorKind::InvalidData,
                ),
                2 => (Some(Message::Cancel {}), io::ErrorKind::Interrupted),
                _ => (None, io::ErrorKind::UnexpectedEof),
            };
            let mut replies = vec![Message::Ready {
                toolchain: ToolchainDisposition::Reuse,
                source,
            }];
            replies.extend(reply);
            let mut peer = AdmissionStream::new(&replies, false);
            peer.quantum = MAX_JSON_RECORD;
            let output = Arc::clone(&peer.output);
            let mut wire = Wire::new(peer);
            let stopped = AtomicBool::new(false);
            let result = native(async {
                let (deadline, disposition, source_plan) = await_input_admission(
                    &mut wire,
                    fixture.bundle.source.manifest(),
                    &stopped,
                    "fixture",
                    Instant::now() + Duration::from_secs(5),
                )
                .await?;
                upload_inputs(
                    &mut wire,
                    &mut fixture.bundle,
                    &fixture.owner.path().join("scratch"),
                    disposition,
                    &source_plan,
                    &stopped,
                    deadline,
                )
                .await?;
                wire.send(&Message::InputsDone {}, &stopped, deadline).await
            });
            assert_eq!(result.unwrap_err().kind(), expected);
            let messages = admission_messages(&output);
            assert_eq!(messages.len(), wire::WINDOW as usize + 1);
            assert!(
                messages[..wire::WINDOW as usize]
                    .iter()
                    .all(|message| message["kind"] == "source-chunk")
            );
            assert_eq!(
                messages.last().unwrap(),
                &json!({"kind":"window-end", "count":wire::WINDOW})
            );
        }
    }

    #[test]
    fn diagnostics_are_binary_exact_and_refuse_gaps_or_duplicates() {
        let mut destination = Vec::new();
        let mut offset = 0;
        write_output(
            Output {
                offset: 0,
                bytes: encode_hex(b"out\0\xff"),
            },
            &mut offset,
            &mut destination,
        )
        .unwrap();
        assert_eq!(destination, b"out\0\xff");
        assert_eq!(offset, 5);
        for wrong in [0, 4, 6] {
            assert!(
                write_output(
                    Output {
                        offset: wrong,
                        bytes: "61".into()
                    },
                    &mut offset,
                    &mut destination
                )
                .is_err()
            );
        }
        assert_eq!(destination, b"out\0\xff");
    }

    #[test]
    fn output_preflight_preserves_existing_files_and_empty_directories() {
        let owner = tempfile::tempdir().unwrap();
        let file = owner.path().join("file");
        fs::write(&file, b"previous").unwrap();
        let empty = owner.path().join("empty");
        fs::create_dir(&empty).unwrap();
        assert_eq!(
            require_absent(&file).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(
            require_absent(&empty).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        assert!(require_absent(&owner.path().join("new")).is_ok());
        assert_eq!(fs::read(file).unwrap(), b"previous");
    }

    #[test]
    fn native_atp_upload_seals_exact_source_and_sdk_across_multiple_windows() {
        // This is a byte-custody integration test. The tiny SDK contains no
        // real Rust compiler; plaintext ATP is confined to test loopback.
        let mut fixture = InputFixture::new();
        let destination = private();
        let sdk_destination = Arc::new(private());
        let (source, toolchain) = fixture.receivers(destination.path(), sdk_destination.path());
        let expected_source = fixture.bundle.source.manifest().clone();
        let expected_sdk = *fixture.bundle.toolchain.as_ref().unwrap().identity();
        assert!(fixture.source_bytes.len() > MAX_SOURCE_CHUNK * wire::WINDOW as usize);
        assert!(fixture.runtime_bytes.len() > MAX_SOURCE_CHUNK * wire::WINDOW as usize);
        let scratch = fixture.owner.path().join("scratch");
        let source_plan = SourcePlan::all(fixture.bundle.source.manifest()).unwrap();
        let received = std::thread::scope(|scope| {
            let (addresses, address) = std::sync::mpsc::sync_channel(1);
            let server = scope.spawn(move || {
                native(async {
                    let listener = TcpListener::bind("127.0.0.1:0").await?;
                    addresses.send(listener.local_addr()?.to_string()).unwrap();
                    let (stream, _) = listener.accept().await?;
                    let mut wire = Wire::new(JsonAtpStream::new(stream));
                    let stopped = AtomicBool::new(false);
                    let deadline = Instant::now() + Duration::from_secs(25);
                    let sealed = super::super::receive_inputs(
                        &mut wire,
                        SourceInput::uncached(source)?,
                        ToolchainInput::Upload {
                            receiver: Box::new(toolchain),
                            owner: sdk_destination,
                        },
                        &stopped,
                        deadline,
                    )
                    .await?;
                    wire.send(&Message::Accepted {}, &stopped, deadline).await?;
                    Ok::<_, io::Error>(sealed)
                })
            });
            let address = address.recv_timeout(Duration::from_secs(10)).unwrap();
            let sent = native(async {
                let stream = TcpStream::connect(address).await?;
                let mut wire = Wire::new(JsonAtpStream::new(stream));
                let stopped = AtomicBool::new(false);
                let deadline = Instant::now() + Duration::from_secs(25);
                upload_inputs(
                    &mut wire,
                    &mut fixture.bundle,
                    &scratch,
                    ToolchainDisposition::Upload,
                    &source_plan,
                    &stopped,
                    deadline,
                )
                .await?;
                wire.send(&Message::InputsDone {}, &stopped, deadline)
                    .await?;
                require(
                    matches!(
                        wire.receive_until(&stopped, deadline).await?,
                        Message::Accepted {}
                    ),
                    "native receiver did not seal the complete transfer",
                )
            });
            let received = server.join().unwrap();
            sent.unwrap();
            received.unwrap()
        });
        let (source, sdk) = received;
        assert_eq!(source.manifest(), &expected_source);
        let root = source
            .sealed_root()
            .expect("received source must be sealed");
        assert_eq!(
            fs::read(root.join("a-binary")).unwrap(),
            fixture.source_bytes
        );
        assert!(fs::read(root.join("b-empty")).unwrap().is_empty());
        assert_eq!(
            fs::metadata(root.join("c-executable")).unwrap().mode() & 0o7777,
            0o555,
        );
        assert_eq!(fs::metadata(root.join("a-binary")).unwrap().nlink(), 1);
        assert_eq!(sdk.identity(), &expected_sdk);
        assert_eq!(
            fs::read(sdk.root().join("lib/runtime")).unwrap(),
            fixture.runtime_bytes
        );
        assert!(sdk.root().join("lib/empty").is_dir());
        assert!(fs::read(sdk.root().join("empty-file")).unwrap().is_empty());
        assert_eq!(
            fs::read_link(sdk.root().join("bin/runtime")).unwrap(),
            Path::new("../lib/runtime")
        );
        assert_eq!(
            fs::read_link(sdk.root().join("compiler")).unwrap(),
            Path::new("bin/compiler")
        );
        assert_eq!(
            fs::metadata(sdk.root().join("bin/compiler"))
                .unwrap()
                .mode()
                & 0o7777,
            0o555
        );
        sdk.image().verify_retained_generation(|| false).unwrap();
        assert_eq!(fs::read_dir(scratch).unwrap().count(), 0);
    }

    #[test]
    fn native_atp_cancel_or_disconnect_after_a_real_window_never_accepts_execution() {
        for cancel in [true, false] {
            let mut fixture = InputFixture::new();
            let destination = private();
            let sdk_destination = Arc::new(private());
            let sdk_root = sdk_destination.path().join("toolchain");
            let (mut source, toolchain) =
                fixture.receivers(destination.path(), sdk_destination.path());
            let client_stop = Arc::new(AtomicBool::new(false));
            let disconnect = Arc::new(AtomicBool::new(false));
            let accepted = Arc::new(AtomicBool::new(false));
            let scratch = fixture.owner.path().join("scratch");
            let source_plan = SourcePlan::all(fixture.bundle.source.manifest()).unwrap();
            let (sent, received) = std::thread::scope(|scope| {
                let (addresses, address) = std::sync::mpsc::sync_channel(1);
                let server_cancel = Arc::clone(&client_stop);
                let server_disconnect = Arc::clone(&disconnect);
                let server_accepted = Arc::clone(&accepted);
                let server = scope.spawn(move || {
                    native(async {
                        let listener = TcpListener::bind("127.0.0.1:0").await?;
                        addresses.send(listener.local_addr()?.to_string()).unwrap();
                        let (stream, _) = listener.accept().await?;
                        let mut wire = Wire::new(JsonAtpStream::new(stream));
                        let stopped = AtomicBool::new(false);
                        let deadline = Instant::now() + Duration::from_secs(25);
                        // Consume and verify an actual first window, withholding
                        // only its acknowledgment so interruption is deterministic.
                        for index in 0..wire::WINDOW {
                            let Message::SourceChunk { chunk } =
                                wire.receive_until(&stopped, deadline).await?
                            else {
                                return Err(invalid("expected the first source window"));
                            };
                            assert_eq!(chunk.path, "a-binary");
                            assert_eq!(chunk.offset, index * MAX_SOURCE_CHUNK as u64);
                            let (bytes, sha256) = chunk.verified_bytes()?;
                            source.write_chunk(&chunk.path, chunk.offset, &bytes, sha256)?;
                        }
                        require(
                            matches!(wire.receive_until(&stopped, deadline).await?,
                                Message::WindowEnd { count } if count == wire::WINDOW),
                            "client failed to stop at the real window bound",
                        )?;
                        assert!(source.sealed_root().is_none());
                        assert_eq!(toolchain.entry_count(), 0);
                        if cancel {
                            server_cancel.store(true, Ordering::Release);
                        } else {
                            server_disconnect.store(true, Ordering::Release);
                        }
                        // The production receiver retains the real prefix.
                        // Neither EOF nor cancellation can return sealed owners.
                        let received = super::super::receive_inputs(
                            &mut wire,
                            SourceInput::uncached(source)?,
                            ToolchainInput::Upload {
                                receiver: Box::new(toolchain),
                                owner: sdk_destination,
                            },
                            &stopped,
                            deadline,
                        )
                        .await;
                        match received {
                            Ok(_) => {
                                server_accepted.store(true, Ordering::Release);
                                wire.send(&Message::Accepted {}, &stopped, deadline).await?;
                                Ok(())
                            }
                            Err(error) => Err(error),
                        }
                    })
                });
                let address = address.recv_timeout(Duration::from_secs(10)).unwrap();
                let sent = native(async {
                    let stream = TcpStream::connect(address).await.unwrap();
                    let mut wire = Wire::new(JsonAtpStream::new(stream));
                    let deadline = Instant::now() + Duration::from_secs(25);
                    let result = {
                        let mut upload = pin!(upload_inputs(
                            &mut wire,
                            &mut fixture.bundle,
                            &scratch,
                            ToolchainDisposition::Upload,
                            &source_plan,
                            &client_stop,
                            deadline,
                        ));
                        loop {
                            if disconnect.load(Ordering::Acquire) {
                                break None;
                            }
                            // Keep the SAME pending upload future across timer
                            // ticks; partial I/O is never restarted or retried.
                            if let Ok(result) = asupersync::time::timeout(
                                runtime_transport_now(),
                                Duration::from_millis(10),
                                upload.as_mut(),
                            )
                            .await
                            {
                                break Some(result);
                            }
                        }
                    };
                    drop(wire);
                    result
                });
                (sent, server.join().unwrap())
            });
            if cancel {
                assert_eq!(
                    sent.unwrap().unwrap_err().kind(),
                    io::ErrorKind::Interrupted
                );
            } else {
                assert!(sent.is_none(), "disconnect must interrupt a pending upload");
            }
            assert!(received.is_err());
            assert!(!accepted.load(Ordering::Acquire));
            let prefix = fs::read(destination.path().join("source/a-binary")).unwrap();
            assert_eq!(prefix.len(), MAX_SOURCE_CHUNK * wire::WINDOW as usize);
            assert_eq!(prefix, fixture.source_bytes[..prefix.len()]);
            assert!(!sdk_root.join("bin/compiler").exists());
        }
    }
}
