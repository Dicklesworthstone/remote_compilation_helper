//! `rabs-wkr` — the RABS trusted worker daemon binary (bead S5).
//!
//! Blocking sandbox execution has one session-owned ExecutionTask; control
//! traffic remains responsive. Negotiated diagnostic and artifact ranges retain
//! immutable snapshots until identity-bound ACKs. These are post-execution
//! offers, not publications, authenticated ATP or durable reconnect resume.
//!
//! CLI: rabs-wkr --coordinator <host:port> [--worker-id ID] [--once]
//! `--once` waits for every negotiated output/artifact acceptance before exiting.
//! Durable worker/endpoint admission survives restarts. Request-status reconciles
//! outcome metadata, never restores scratch artifacts or authorizes a rerun.

use asupersync::cx::Cx;
use asupersync::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use asupersync::net::TcpStream;
use asupersync::runtime::RuntimeBuilder;
use rabs_wkr::artifacts::{self, ARTIFACT_TRANSFER, ArtifactPlan, ArtifactTransferState, CapturedArtifacts};
use rabs_wkr::execution::{DEFAULT_EXECUTION_TIMEOUT, ExecutionCompletion, ExecutionTask, StopReason};
use rabs_wkr::output::{CapturedOutputs, MAX_OUTPUT_CHUNK_BYTES};
use rabs_wkr::request_journal::{RECOVERY_PROTOCOL, WorkerJournal};
use rabs_wkr::session::{CanonicalExecRequest, execute_canonical_controlled, probe_capability, sample_pressure};
use std::future::{Future, poll_fn};
use std::io;
use std::path::PathBuf;
use std::pin::pin;
use std::task::Poll;
use std::time::Duration;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const MAX_FRAME_BYTES: usize = 1 << 20;
const OUTPUT_TRANSFER: &str = "ranges-v1";

fn json_string(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn worker_state_path(worker: &str, coordinator: &str) -> io::Result<PathBuf> {
    if let Some(path) = std::env::var_os("RABS_WORKER_STATE_DIR") {
        let path = PathBuf::from(path);
        return if path.is_absolute() {
            Ok(path)
        } else {
            Err(io::Error::new(io::ErrorKind::InvalidInput, "RABS_WORKER_STATE_DIR must be absolute"))
        };
    }
    let base = std::env::var_os("XDG_STATE_HOME").map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/state")))
        .filter(|path| path.is_absolute())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "set RABS_WORKER_STATE_DIR or an absolute HOME/XDG_STATE_HOME"))?;
    let binding = serde_json::json!(["rabs.worker-state.v1", worker, coordinator]).to_string();
    Ok(base.join("rabs/workers").join(rabs_wkr::session::sha256_hex(binding.as_bytes())))
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("--version") => { println!("rabs-wkr {VERSION}"); return; }
        Some("--help") => {
            println!(
                "rabs-wkr {VERSION} — RABS trusted worker daemon\n\
                 USAGE: rabs-wkr --coordinator <host:port> [--worker-id ID] [--once]\n\
                 Serves canonical-exec requests through the sandbox launcher; offers results, never commits.\n\
                 Select output_transfer=ranges-v1 and artifact_transfer=files-v1 in session-ok\n\
                 to retrieve diagnostics and declared compiled artifacts.\n\
                 Request IDs must increase across restarts; request-status reconciles outcomes.\n\
                 RABS_WORKER_STATE_DIR selects a private durable directory (never reset it to retry work)."
            );
            return;
        }
        _ => {}
    }
    let mut coordinator = None;
    let mut worker_id = std::env::var("RABS_WORKER_ID").unwrap_or_else(|_| {
        std::process::Command::new("hostname").arg("-s").output().ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| s.trim().to_string()).unwrap_or_else(|| "worker".to_string())
    });
    let mut once = false;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--coordinator" => coordinator = iter.next().cloned(),
            "--worker-id" => { if let Some(id) = iter.next() { worker_id = id.clone(); } }
            "--once" => once = true,
            other => { eprintln!("rabs-wkr: unknown argument {other:?} (see --help)"); std::process::exit(2); }
        }
    }
    let Some(coordinator) = coordinator else {
        eprintln!("rabs-wkr: --coordinator <host:port> is required"); std::process::exit(2);
    };
    // Persist ownership before any runtime task or network advertisement. An IO
    // error never falls back to a fresh temporary journal that forgets history.
    let mut journal = match worker_state_path(&worker_id, &coordinator)
        .and_then(|root| WorkerJournal::open(&root, &worker_id, &coordinator))
    {
        Ok(journal) => journal,
        Err(error) => {
            eprintln!("rabs-wkr: durable ownership unavailable: {error}");
            std::process::exit(1);
        }
    };
    let report = probe_capability(&worker_id);
    eprintln!(
        "{{\"v\":1,\"kind\":\"rabs-wkr-boot\",\"worker_id\":{},\"canonical\":{},\"slots\":{}}}",
        json_string(&report.worker_id), report.canonical_namespace, report.slots
    );
    let runtime = match RuntimeBuilder::current_thread().build() {
        Ok(runtime) => runtime,
        Err(error) => { eprintln!("rabs-wkr: runtime build failed: {error:?}"); std::process::exit(1); }
    };
    let handle = runtime.handle();
    let exit_code: i32 = runtime.block_on(async move {
        handle.spawn(async move {
            let cx = Cx::current().expect("runtime task Cx");
            match session_loop(&cx, &coordinator, &report, once, &mut journal).await {
                Ok(()) => 0,
                Err(error) => { eprintln!("rabs-wkr: session ended: {error}"); 1 }
            }
        }).await
    });
    std::process::exit(exit_code);
}

/// Partial input belongs to the session, not to a disposable read future.
#[derive(Default)]
struct FrameReader { pending: Vec<u8> }

impl FrameReader {
    async fn read<R: AsyncRead + Unpin>(&mut self, stream: &mut R) -> io::Result<Option<String>> {
        let mut byte = [0_u8; 1];
        loop {
            if stream.read(&mut byte).await? == 0 {
                return if self.pending.is_empty() { Ok(None) }
                else { Err(io::Error::new(io::ErrorKind::UnexpectedEof, "truncated frame")) };
            }
            if byte[0] == b'\n' {
                return String::from_utf8(std::mem::take(&mut self.pending)).map(Some)
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "non-UTF-8 frame"));
            }
            if self.pending.len() == MAX_FRAME_BYTES {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "frame too large"));
            }
            self.pending.push(byte[0]);
        }
    }
}

async fn write_frame<W: AsyncWrite + Unpin>(stream: &mut W, line: &str) -> io::Result<()> {
    let mut bytes = line.as_bytes().to_vec(); bytes.push(b'\n');
    stream.write_all(&bytes).await
}

enum SessionEvent {
    Frame(io::Result<Option<String>>),
    Completed { request_id: u64, result: Result<ExecutionCompletion, String> },
}

async fn next_event<R: AsyncRead + Unpin>(
    reader: &mut FrameReader, stream: &mut R, active: &mut Option<ExecutionTask>,
) -> SessionEvent {
    let mut read = pin!(reader.read(stream));
    poll_fn(|cx| {
        // A flood of immediately-readable pings cannot starve completion.
        if let Some(task) = active.as_mut() && let Poll::Ready(result) = task.poll_completion(cx) {
            return Poll::Ready(SessionEvent::Completed { request_id: task.request_id(), result });
        }
        read.as_mut().poll(cx).map(SessionEvent::Frame)
    }).await
}

fn completion_frame(completion: &ExecutionCompletion) -> String {
    let result = &completion.result;
    serde_json::json!({
        "kind": "exec-result", "request_id": result.request_id, "exit_code": result.exit_code,
        "stdout_sha256": result.stdout_sha256, "stderr_sha256": result.stderr_sha256,
        "executed": result.executed, "residual_group_members": result.residual_group_members,
        "stdout_spill_bytes": result.stdout_spill_bytes, "stderr_spill_bytes": result.stderr_spill_bytes,
        "stdout_spill_path": result.stdout_spill_path, "stderr_spill_path": result.stderr_spill_path,
        "stop_reason": completion.stop_reason.map(StopReason::label),
        "output_transfer": completion.outputs.as_ref().map(|_| OUTPUT_TRANSFER),
        "stdout_bytes": completion.outputs.as_ref().map(|outputs| outputs.stdout.len()),
        "stderr_bytes": completion.outputs.as_ref().map(|outputs| outputs.stderr.len()),
        "output_ack_required": completion.outputs.is_some(),
        "artifact_transfer": completion.artifacts.as_ref().map(|_| ARTIFACT_TRANSFER),
        "artifact_manifest": completion.artifacts.as_ref().map(CapturedArtifacts::manifest),
        "artifact_ack_required": completion.artifacts.is_some(),
    }).to_string()
}

/// Persist bounded outcome metadata before network delivery, not scratch paths,
/// artifact manifests or transfer promises. Completion remains not publication.
fn journal_completion(
    journal: Option<&mut WorkerJournal>,
    request_id: u64,
    result: &Result<ExecutionCompletion, String>,
) -> Result<(), String> {
    let Some(journal) = journal else { return Ok(()); };
    let (receipt, resolved) = match result {
        Ok(completion) => {
            let result = &completion.result;
            (serde_json::json!({
                "kind": "exec-result", "request_id": result.request_id,
                "exit_code": result.exit_code, "executed": result.executed,
                "stdout_sha256": result.stdout_sha256, "stderr_sha256": result.stderr_sha256,
                "residual_group_members": result.residual_group_members,
                "stop_reason": completion.stop_reason.map(StopReason::label),
            }), result.executed && result.residual_group_members == 0)
        }
        Err(error) => (serde_json::json!({
            "kind": "error", "request_id": request_id,
            "reason": "execution-completion-failed", "execution_may_have_run": true,
            "error_sha256": rabs_wkr::session::sha256_hex(error.as_bytes()),
        }), false),
    };
    journal.finish(request_id, &receipt, resolved)
        .map_err(|error| format!("persist execution outcome: {error}"))
}

fn request_error(request_id: Option<u64>, reason: &str) -> String {
    serde_json::json!({"kind": "error", "request_id": request_id, "reason": reason}).to_string()
}

/// An ACK is the receiver's claim after verification, not proof of publication.
#[derive(Debug, Clone, PartialEq, Eq)]
struct OutputIdentity {
    request_id: u64,
    stdout_sha256: String,
    stderr_sha256: String,
    stdout_bytes: u64,
    stderr_bytes: u64,
}

impl OutputIdentity {
    fn new(request_id: u64, outputs: &CapturedOutputs) -> Self {
        Self { request_id, stdout_sha256: outputs.stdout.sha256().to_owned(),
            stderr_sha256: outputs.stderr.sha256().to_owned(), stdout_bytes: outputs.stdout.len(),
            stderr_bytes: outputs.stderr.len() }
    }
    fn from_ack(value: &serde_json::Value) -> Option<Self> {
        Some(Self { request_id: value.get("request_id")?.as_u64()?,
            stdout_sha256: value.get("stdout_sha256")?.as_str()?.to_owned(),
            stderr_sha256: value.get("stderr_sha256")?.as_str()?.to_owned(),
            stdout_bytes: value.get("stdout_bytes")?.as_u64()?, stderr_bytes: value.get("stderr_bytes")?.as_u64()? })
    }
}

struct PendingOutput { identity: OutputIdentity, outputs: CapturedOutputs }

impl PendingOutput {
    fn new(request_id: u64, outputs: CapturedOutputs) -> Self {
        Self { identity: OutputIdentity::new(request_id, &outputs), outputs }
    }
    fn read_frame(&mut self, value: &serde_json::Value) -> Result<String, String> {
        if value.get("request_id").and_then(serde_json::Value::as_u64) != Some(self.identity.request_id) {
            return Err("unknown-output-request".to_owned());
        }
        if value.get("path").is_some() { return Err("output-paths-not-accepted".to_owned()); }
        let name = value.get("stream").and_then(serde_json::Value::as_str).ok_or("output stream must be stdout or stderr")?;
        let stream = match name {
            "stdout" => &mut self.outputs.stdout, "stderr" => &mut self.outputs.stderr,
            _ => return Err("output stream must be stdout or stderr".to_owned()),
        };
        let offset = value.get("offset").and_then(serde_json::Value::as_u64).ok_or("output offset must be an unsigned integer")?;
        let max_bytes = match value.get("max_bytes") {
            None => MAX_OUTPUT_CHUNK_BYTES,
            Some(value) => value.as_u64().and_then(|size| usize::try_from(size).ok())
                .filter(|size| *size > 0 && *size <= MAX_OUTPUT_CHUNK_BYTES).ok_or("invalid output chunk size")?,
        };
        let bytes = stream.read_chunk(offset, max_bytes).map_err(|error| format!("output read: {error}"))?;
        let next_offset = offset.checked_add(bytes.len() as u64).ok_or("output offset overflow")?;
        let data_hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
        Ok(serde_json::json!({
            "kind": "output-chunk", "request_id": self.identity.request_id, "stream": name,
            "offset": offset, "next_offset": next_offset, "total_bytes": stream.len(),
            "eof": next_offset == stream.len(), "data_hex": data_hex,
            "sha256": stream.sha256(), "chunk_sha256": rabs_wkr::session::sha256_hex(&bytes),
        }).to_string())
    }
}

/// Production always supplies a durable journal. None is a test seam, never an
/// IO-failure fallback. Uncertain durable work blocks admission across restarts;
/// both output owners survive until their own ACKs. The launch seam lets tests
/// exercise this driver without pretending to sandbox. Artifact negotiation is
/// checked BEFORE durable admission, so a refused capability never burns an ID.
async fn drive_session<S, L, H>(
    stream: &mut S, report: &rabs_wkr::session::CapabilityReport, once: bool,
    mut journal: Option<&mut WorkerJournal>, artifact_transfer_enabled: bool,
    mut launch: L, mut heartbeat: H,
) -> Result<(), String>
where
    S: AsyncRead + AsyncWrite + Unpin,
    L: FnMut(CanonicalExecRequest, Duration, Option<ArtifactPlan>) -> io::Result<ExecutionTask>,
    H: FnMut() -> rabs_wkr::session::PressureSample,
{
    let mut reader = FrameReader::default();
    let mut active: Option<ExecutionTask> = None;
    let mut last_admitted: Option<u64> = None;
    let mut pending_output: Option<PendingOutput> = None;
    let mut last_output_ack: Option<OutputIdentity> = None;
    let mut artifact_transfer = ArtifactTransferState::default();
    let outcome = async {
        loop {
            if Cx::current().is_some_and(|cx| cx.checkpoint().is_err()) { return Err("session cancelled".to_owned()); }
            let mut exit_after_reply = false;
            let reply = match next_event(&mut reader, stream, &mut active).await {
                SessionEvent::Completed { request_id, result } => {
                    drop(active.take());
                    journal_completion(journal.as_deref_mut(), request_id, &result)?;
                    let reply = match result {
                        Ok(mut completion) => {
                            let reply = completion_frame(&completion);
                            pending_output = completion.outputs.take().map(|outputs| PendingOutput::new(request_id, outputs));
                            if let Some(bundle) = completion.artifacts.take() { artifact_transfer.retain(request_id, bundle)?; }
                            reply
                        }
                        Err(reason) => serde_json::json!({
                            "kind": "error", "request_id": request_id, "reason": reason,
                            "execution_may_have_run": true, "stage": "execution-completion",
                        }).to_string(),
                    };
                    write_frame(stream, &reply).await.map_err(|e| format!("result write: {e}"))?;
                    if once && pending_output.is_none() && !artifact_transfer.is_pending() { return Ok(()); }
                    continue;
                }
                SessionEvent::Frame(Ok(None)) => return Ok(()),
                SessionEvent::Frame(Err(error)) => return Err(format!("frame read: {error}")),
                SessionEvent::Frame(Ok(Some(frame))) => {
                    let value = match serde_json::from_str::<serde_json::Value>(&frame) {
                        Ok(value) => value,
                        Err(_) => {
                            write_frame(stream, &request_error(None, "malformed")).await.map_err(|e| format!("error write: {e}"))?;
                            continue;
                        }
                    };
                    let request_id = value.get("request_id").and_then(serde_json::Value::as_u64);
                    match value.get("kind").and_then(|kind| kind.as_str()) {
                        Some("ping") => {
                            let pressure = heartbeat();
                            serde_json::json!({
                                "kind": "heartbeat", "worker_id": report.worker_id,
                                "load_x100": pressure.load_x100, "free_disk_mib": pressure.free_disk_mib,
                                "active_request_id": active.as_ref().map(ExecutionTask::request_id),
                                "pending_output_request_id": pending_output.as_ref().map(|output| output.identity.request_id),
                                "pending_artifact_request_id": artifact_transfer.pending_request_id(),
                            }).to_string()
                        }
                        Some("request-status") => match (journal.as_deref(), request_id) {
                            (Some(journal), Some(id)) => {
                                let mut status = journal.status(id);
                                status["active_in_this_session"] = serde_json::json!(active.as_ref().is_some_and(|task| task.request_id() == id));
                                status["output_available_in_this_session"] = serde_json::json!(pending_output.as_ref().is_some_and(|output| output.identity.request_id == id));
                                status["artifacts_available_in_this_session"] = serde_json::json!(artifact_transfer.pending_request_id() == Some(id));
                                status.to_string()
                            }
                            (None, _) => request_error(request_id, "request-journal-unavailable"),
                            (_, None) => request_error(None, "request-status-requires-request-id"),
                        },
                        Some("artifact-read") => artifact_transfer.read_frame(&value)
                            .unwrap_or_else(|reason| request_error(request_id, &reason)),
                        Some("artifact-ack") => match artifact_transfer.acknowledge(&value) {
                            Ok(reply) => {
                                exit_after_reply = once && pending_output.is_none() && !artifact_transfer.is_pending();
                                reply
                            }
                            Err(reason) => request_error(request_id, &reason),
                        },
                        Some("output-read") => match pending_output.as_mut() {
                            Some(output) => output.read_frame(&value).unwrap_or_else(|reason| request_error(request_id, &reason)),
                            None => request_error(request_id, "unknown-output-request"),
                        },
                        Some("output-ack") => match OutputIdentity::from_ack(&value) {
                            Some(ack) if pending_output.as_ref().is_some_and(|output| output.identity == ack) => {
                                drop(pending_output.take()); last_output_ack = Some(ack);
                                exit_after_reply = once && !artifact_transfer.is_pending();
                                serde_json::json!({"kind": "output-acknowledged", "request_id": request_id, "already_released": false}).to_string()
                            }
                            Some(ack) if last_output_ack.as_ref() == Some(&ack) => {
                                serde_json::json!({"kind": "output-acknowledged", "request_id": request_id, "already_released": true}).to_string()
                            }
                            _ => request_error(request_id, "output-ack-mismatch"),
                        },
                        Some("cancel") => match (&active, request_id) {
                            (Some(task), Some(id)) if task.request_id() == id => {
                                let accepted = task.cancel(StopReason::Cancelled);
                                serde_json::json!({"kind": "cancel-accepted", "request_id": id, "accepted": accepted, "cleanup_pending": true}).to_string()
                            }
                            _ => request_error(request_id, "unknown-request"),
                        },
                        Some("canonical-exec") => {
                            let parsed = parse_exec_request(&value).and_then(|request| {
                                let timeout = parse_timeout(&value)?;
                                let artifacts = artifacts::parse_plan(&value)?;
                                if artifacts.is_some() && !artifact_transfer_enabled {
                                    return Err("artifact transfer not negotiated".to_owned());
                                }
                                Ok((request, timeout, artifacts))
                            });
                            match parsed {
                                Err(reason) => request_error(request_id, &reason),
                                Ok((request, _, _)) if last_admitted.is_some_and(|last| request.request_id <= last) => request_error(Some(request.request_id), "stale-request-id"),
                                Ok((request, _, _)) if active.is_some() => request_error(Some(request.request_id), "worker-busy"),
                                Ok((request, _, _)) if pending_output.is_some() => request_error(Some(request.request_id), "output-unacknowledged"),
                                Ok((request, _, _)) if artifact_transfer.is_pending() => request_error(Some(request.request_id), "artifacts-unacknowledged"),
                                Ok((request, timeout, artifacts)) => {
                                    let id = request.request_id;
                                    let refusal = match journal.as_deref_mut() {
                                        // This fingerprint binds the complete wire request,
                                        // including its exact artifact declaration and timeout.
                                        Some(journal) => journal.admit(&value, timeout)
                                            .map_err(|error| format!("persist execution admission: {error}"))?,
                                        None => None,
                                    };
                                    if let Some(reason) = refusal {
                                        request_error(Some(id), reason)
                                    } else {
                                        match launch(request, timeout, artifacts) {
                                            Ok(task) => { last_admitted = Some(id); active = Some(task); continue; }
                                            Err(error) => {
                                                if let Some(journal) = journal.as_deref_mut() {
                                                    journal.finish(id, &serde_json::json!({
                                                        "kind": "error", "request_id": id,
                                                        "reason": "execution-start-failed", "execution_may_have_run": true,
                                                    }), false).map_err(|error| format!("persist launch failure: {error}"))?;
                                                }
                                                request_error(Some(id), &format!("execution start: {error}"))
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        _ => request_error(request_id, "unknown-frame"),
                    }
                }
            };
            write_frame(stream, &reply).await.map_err(|e| format!("control write: {e}"))?;
            if exit_after_reply { return Ok(()); }
        }
    }.await;
    // All transport failure/EOF paths cancel and await the single owned process.
    // Completed snapshots are connection-owned and disappear on disconnect.
    if let Some(mut task) = active.take() {
        task.cancel(StopReason::SessionLost);
        let request_id = task.request_id();
        let cleanup = task.wait().await;
        journal_completion(journal.as_deref_mut(), request_id, &cleanup)?;
        if outcome.is_ok() { cleanup.map_err(|e| format!("session cleanup: {e}"))?; }
    }
    drop(pending_output);
    drop(artifact_transfer);
    outcome
}

fn worker_hello(report: &rabs_wkr::session::CapabilityReport, journal: &WorkerJournal) -> String {
    serde_json::json!({
        "kind": "worker-hello", "worker_id": report.worker_id,
        "canonical": report.canonical_namespace, "slots": report.slots, "token_id": 1,
        "output_transfers": [OUTPUT_TRANSFER], "artifact_transfers": [ARTIFACT_TRANSFER],
        "recovery_protocols": [RECOVERY_PROTOCOL],
        "boot_generation": journal.boot_generation().0,
        "incarnation": format!("{:032x}", journal.incarnation().0),
        "request_high_water": journal.high_water(),
        "request_id_policy": "worker-endpoint-monotonic",
    }).to_string()
}

async fn session_loop(
    cx: &Cx, coordinator: &str, report: &rabs_wkr::session::CapabilityReport, once: bool,
    journal: &mut WorkerJournal,
) -> Result<(), String> {
    let mut stream = TcpStream::connect(coordinator.to_string()).await.map_err(|e| format!("connect {coordinator}: {e}"))?;
    cx.trace("rabs-wkr connected to coordinator");
    // Durable identity metadata is not authentication; ATP enrollment is separate.
    let hello = worker_hello(report, journal);
    write_frame(&mut stream, &hello).await.map_err(|e| format!("hello write: {e}"))?;
    let ack = FrameReader::default().read(&mut stream).await.map_err(|e| format!("handshake read: {e}"))?
        .ok_or_else(|| "no session-ok".to_string())?;
    if !session_ack_accepted(&ack) { return Err(format!("handshake refused: {ack}")); }
    let capture_output = output_transfer_requested(&ack)?;
    let capture_artifacts = artifacts::transfer_requested(&ack)?;
    validate_recovery_selection(&ack)?;
    let cargo_home = std::env::temp_dir().join(format!("rabs-wkr-ch-{}", std::process::id()));
    let home = std::env::temp_dir().join(format!("rabs-wkr-home-{}", std::process::id()));
    let spills = std::env::temp_dir().join(format!("rabs-wkr-spill-{}", std::process::id()));
    for path in [&cargo_home, &home, &spills] {
        std::fs::create_dir_all(path).map_err(|e| format!("prepare {}: {e}", path.display()))?;
    }
    drive_session(&mut stream, report, once, Some(journal), capture_artifacts, |request, timeout, artifacts| {
        let cargo_home = cargo_home.clone(); let home = home.clone(); let spills = spills.clone();
        let slots = report.slots;
        let id = request.request_id;
        let execute = move |control: rabs_wkr::execution::ExecutionControl| {
            if capture_output { control.request_output_capture(); }
            execute_canonical_controlled(&request, &cargo_home, &home, slots, &spills, &control)
        };
        match artifacts {
            Some(plan) => ExecutionTask::spawn_with_artifacts(id, timeout, plan, execute),
            None => ExecutionTask::spawn(id, timeout, execute),
        }
    }, || sample_pressure(&cargo_home)).await
}

fn session_ack_accepted(frame: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(frame).ok().and_then(|value| {
        value.get("kind").and_then(|kind| kind.as_str()).map(|kind| kind == "session-ok")
    }).unwrap_or(false)
}

fn validate_recovery_selection(frame: &str) -> Result<(), String> {
    let value: serde_json::Value = serde_json::from_str(frame).map_err(|e| format!("handshake JSON: {e}"))?;
    match value.get("recovery_protocol") {
        None => Ok(()), // Admission remains durable without status negotiation.
        Some(value) if value.as_str() == Some(RECOVERY_PROTOCOL) => Ok(()),
        Some(_) => Err("unsupported recovery_protocol selection".to_owned()),
    }
}

fn output_transfer_requested(frame: &str) -> Result<bool, String> {
    let value: serde_json::Value = serde_json::from_str(frame).map_err(|e| format!("handshake JSON: {e}"))?;
    match value.get("output_transfer") {
        None => Ok(false), Some(value) if value.as_str() == Some(OUTPUT_TRANSFER) => Ok(true),
        Some(_) => Err("unsupported output_transfer selection".to_owned()),
    }
}

fn parse_timeout(value: &serde_json::Value) -> Result<Duration, String> {
    match value.get("timeout_ms") {
        None => Ok(DEFAULT_EXECUTION_TIMEOUT),
        Some(value) => {
            let millis = value.as_u64().filter(|millis| *millis != 0).ok_or("timeout_ms must be a positive integer")?;
            Ok(Duration::from_millis(millis).min(DEFAULT_EXECUTION_TIMEOUT))
        }
    }
}

fn parse_exec_request(value: &serde_json::Value) -> Result<CanonicalExecRequest, String> {
    let text = |name: &str| -> Result<String, String> {
        value.get(name).and_then(serde_json::Value::as_str).filter(|text| !text.is_empty() && !text.contains('\0'))
            .map(str::to_owned).ok_or_else(|| format!("exec request missing or invalid {name}"))
    };
    let args = match value.get("args") {
        None => Vec::new(),
        Some(value) => value.as_array().ok_or("args must be an array")?.iter()
            .map(|item| item.as_str().filter(|arg| !arg.contains('\0')).map(str::to_owned)
                .ok_or_else(|| "every argument must be a NUL-free string".to_owned())).collect::<Result<Vec<_>, _>>()?,
    };
    let jobserver_grant = match value.get("jobserver_grant") {
        None => None,
        Some(value) => Some(u32::try_from(value.as_u64().ok_or("jobserver_grant must be an unsigned integer")?).unwrap_or(u32::MAX)),
    };
    Ok(CanonicalExecRequest {
        request_id: value.get("request_id").and_then(serde_json::Value::as_u64).ok_or("exec request missing request_id")?,
        program: text("program")?, args, toolchain_backing: text("toolchain_backing")?,
        workspace_backing: text("workspace_backing")?, jobserver_grant,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use asupersync::io::ReadBuf;
    use std::collections::VecDeque;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Wake, Waker};
    use std::time::Instant;

    #[derive(Default)]
    struct WireState {
        input: VecDeque<u8>, output: Vec<u8>, eof: bool, fail_write: bool, reader: Option<Waker>,
    }

    /// Fragmented async peer; tests run the production driver and owned threads.
    #[derive(Clone, Default)]
    struct Wire(Arc<Mutex<WireState>>);

    impl Wire {
        fn bytes(&self, bytes: &[u8]) {
            let wake = {
                let mut state = self.0.lock().unwrap(); state.input.extend(bytes); state.reader.take()
            };
            if let Some(waker) = wake { waker.wake(); }
        }
        fn frame(&self, value: serde_json::Value) { self.bytes(format!("{value}\n").as_bytes()); }
        fn close(&self) {
            let wake = {
                let mut state = self.0.lock().unwrap(); state.eof = true; state.reader.take()
            };
            if let Some(waker) = wake { waker.wake(); }
        }
        fn replies(&self) -> Vec<serde_json::Value> {
            let state = self.0.lock().unwrap();
            String::from_utf8(state.output.clone()).unwrap().lines().map(|line| serde_json::from_str(line).unwrap()).collect()
        }
    }

    impl AsyncRead for Wire {
        fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            if buf.remaining() == 0 { return Poll::Ready(Ok(())); }
            let mut state = self.0.lock().unwrap();
            if let Some(byte) = state.input.pop_front() { buf.put_slice(&[byte]); Poll::Ready(Ok(())) }
            else if state.eof { Poll::Ready(Ok(())) }
            else { state.reader = Some(cx.waker().clone()); Poll::Pending }
        }
    }
    impl AsyncWrite for Wire {
        fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
            let mut state = self.0.lock().unwrap();
            if state.fail_write { return Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed peer"))); }
            state.output.extend_from_slice(bytes); Poll::Ready(Ok(bytes.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> { Poll::Ready(Ok(())) }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> { Poll::Ready(Ok(())) }
    }
    struct ThreadWake(std::thread::Thread);
    impl Wake for ThreadWake { fn wake(self: Arc<Self>) { self.0.unpark(); } }

    fn wait<F: Future>(future: F) -> F::Output {
        let mut future = pin!(future);
        let waker = Waker::from(Arc::new(ThreadWake(std::thread::current())));
        let mut cx = Context::from_waker(&waker);
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Poll::Ready(result) = future.as_mut().poll(&mut cx) { return result; }
            assert!(Instant::now() < deadline, "session test timed out");
            std::thread::park_timeout(Duration::from_millis(10));
        }
    }
    fn report() -> rabs_wkr::session::CapabilityReport {
        rabs_wkr::session::CapabilityReport { worker_id: "session-test".to_owned(), canonical_namespace: true, missing: vec![], slots: 4 }
    }
    fn pressure() -> rabs_wkr::session::PressureSample {
        rabs_wkr::session::PressureSample { load_x100: 10, free_disk_mib: 100 }
    }
    fn result(id: u64) -> rabs_wkr::session::ExecResult {
        rabs_wkr::session::ExecResult {
            request_id: id, exit_code: 0, stdout_sha256: rabs_wkr::session::sha256_hex(b"output"),
            stderr_sha256: rabs_wkr::session::sha256_hex(b""), executed: true, residual_group_members: 0,
            stdout_spill_bytes: 0, stderr_spill_bytes: 0, stdout_spill_path: None, stderr_spill_path: None,
        }
    }

    #[test]
    fn active_execution_handles_ping_exact_cancel_and_busy_without_duplicate_launch() {
        let mut wire = Wire::default(); let peer = wire.clone();
        peer.frame(request(1)); peer.frame(serde_json::json!({"kind": "ping"}));
        peer.frame(serde_json::json!({"kind": "cancel", "request_id": 999}));
        peer.frame(request(1)); peer.frame(request(2));
        peer.frame(serde_json::json!({"kind": "cancel", "request_id": 1}));
        let launches = Arc::new(AtomicUsize::new(0));
        let cleaned = Arc::new(AtomicBool::new(false)); let worker_cleaned = Arc::clone(&cleaned);
        wait(drive_session(&mut wire, &report(), true, None, false, |request, timeout, _| {
            launches.fetch_add(1, Ordering::SeqCst);
            let cleaned = Arc::clone(&worker_cleaned);
            ExecutionTask::spawn(request.request_id, timeout, move |control| {
                while control.reason().is_none() { std::thread::sleep(Duration::from_millis(1)); }
                cleaned.store(true, Ordering::Release); result(request.request_id)
            })
        }, pressure)).unwrap();
        assert_eq!(launches.load(Ordering::SeqCst), 1); assert!(cleaned.load(Ordering::Acquire));
        let replies = peer.replies();
        assert_eq!(replies[0]["kind"], "heartbeat"); assert_eq!(replies[0]["active_request_id"], 1);
        assert_eq!(replies[1]["reason"], "unknown-request"); assert_eq!(replies[2]["reason"], "stale-request-id");
        assert_eq!(replies[3]["reason"], "worker-busy"); assert_eq!(replies[4]["kind"], "cancel-accepted");
        assert_eq!(replies[4]["cleanup_pending"], true); assert_eq!(replies[5]["kind"], "exec-result");
        assert_eq!(replies[5]["stop_reason"], "cancelled"); assert_eq!(replies[5]["exit_code"], 130);
    }

    #[test]
    fn disconnect_and_write_failure_wait_for_session_owned_cleanup() {
        for write_failure in [false, true] {
            let mut wire = Wire::default(); wire.frame(request(1));
            if write_failure { wire.frame(serde_json::json!({"kind": "ping"})); wire.0.lock().unwrap().fail_write = true; }
            else { wire.close(); }
            let cleaned = Arc::new(AtomicBool::new(false)); let worker_cleaned = Arc::clone(&cleaned);
            let outcome = wait(drive_session(&mut wire, &report(), false, None, false, |request, timeout, _| {
                let cleaned = Arc::clone(&worker_cleaned);
                ExecutionTask::spawn(request.request_id, timeout, move |control| {
                    while control.reason().is_none() { std::thread::sleep(Duration::from_millis(1)); }
                    assert_eq!(control.reason(), Some(StopReason::SessionLost));
                    cleaned.store(true, Ordering::Release); result(request.request_id)
                })
            }, pressure));
            assert_eq!(outcome.is_err(), write_failure); assert!(cleaned.load(Ordering::Acquire), "session returned before cleanup");
        }
    }

    #[test]
    fn request_budget_expires_without_another_incoming_frame() {
        let mut wire = Wire::default(); let peer = wire.clone(); let mut frame = request(7);
        frame["timeout_ms"] = serde_json::json!(15); peer.frame(frame);
        wait(drive_session(&mut wire, &report(), true, None, false, |request, timeout, _| {
            assert_eq!(timeout, Duration::from_millis(15));
            ExecutionTask::spawn(request.request_id, timeout, move |control| {
                while control.reason().is_none() { std::thread::sleep(Duration::from_millis(1)); }
                result(request.request_id)
            })
        }, pressure)).unwrap();
        let replies = peer.replies(); assert_eq!(replies.len(), 1);
        assert_eq!(replies[0]["stop_reason"], "deadline-exceeded"); assert_eq!(replies[0]["exit_code"], 124);
    }

    #[test]
    fn completed_request_is_not_rerun_and_newer_work_can_use_the_slot() {
        let mut wire = Wire::default(); let peer = wire.clone(); peer.frame(request(9));
        let launches = Arc::new(AtomicUsize::new(0)); let report = report();
        let mut driver = Box::pin(drive_session(&mut wire, &report, false, None, false, |request, timeout, _| {
            launches.fetch_add(1, Ordering::SeqCst);
            ExecutionTask::spawn(request.request_id, timeout, move |_| result(request.request_id))
        }, pressure));
        let waker = Waker::from(Arc::new(ThreadWake(std::thread::current()))); let mut cx = Context::from_waker(&waker);
        let deadline = Instant::now() + Duration::from_secs(5);
        for expected_results in 1..=2 {
            loop {
                assert!(driver.as_mut().poll(&mut cx).is_pending());
                let count = peer.replies().iter().filter(|frame| frame["kind"] == "exec-result").count();
                if count == expected_results { break; }
                assert!(Instant::now() < deadline, "completion not delivered");
                std::thread::park_timeout(Duration::from_millis(10));
            }
            if expected_results == 1 { peer.frame(request(9)); peer.frame(request(10)); }
        }
        peer.close(); wait(driver).unwrap(); assert_eq!(launches.load(Ordering::SeqCst), 2);
        let replies = peer.replies(); assert_eq!(replies[0]["request_id"], 9); assert!(replies[0]["stop_reason"].is_null());
        assert_eq!(replies[1]["reason"], "stale-request-id"); assert_eq!(replies[2]["request_id"], 10);
    }

    #[test]
    fn completion_preserves_a_partially_received_control_frame() {
        let mut wire = Wire::default(); let peer = wire.clone(); peer.bytes(b"{\"kind\":");
        let release = Arc::new(AtomicBool::new(false)); let worker_release = Arc::clone(&release);
        let mut active = Some(ExecutionTask::spawn(1, Duration::from_secs(5), move |control| {
            while !worker_release.load(Ordering::Acquire) && control.reason().is_none() { std::thread::sleep(Duration::from_millis(1)); }
            result(1)
        }).unwrap());
        let mut reader = FrameReader::default(); let mut event = Box::pin(next_event(&mut reader, &mut wire, &mut active));
        let waker = Waker::from(Arc::new(ThreadWake(std::thread::current())));
        assert!(event.as_mut().poll(&mut Context::from_waker(&waker)).is_pending());
        release.store(true, Ordering::Release);
        assert!(matches!(wait(event), SessionEvent::Completed { request_id: 1, result: Ok(_) }));
        drop(active.take()); peer.bytes(b"\"ping\"}\n");
        assert_eq!(wait(reader.read(&mut wire)).unwrap(), Some("{\"kind\":\"ping\"}".to_owned()));
    }

    #[test]
    fn malformed_transport_is_not_lossily_decoded_or_treated_as_clean_eof() {
        for (bytes, kind) in [
            (vec![0xff, b'\n'], io::ErrorKind::InvalidData), (b"{\"kind\":".to_vec(), io::ErrorKind::UnexpectedEof),
            (vec![b'x'; MAX_FRAME_BYTES + 1], io::ErrorKind::InvalidData),
        ] {
            let mut wire = Wire::default(); wire.bytes(&bytes); wire.close();
            assert_eq!(wait(FrameReader::default().read(&mut wire)).unwrap_err().kind(), kind);
        }
    }

    #[test]
    fn session_ack_requires_success_message_kind() {
        assert!(session_ack_accepted(r#"{"kind":"session-ok","session_id":7}"#));
        for frame in [r#"{"kind":"error","reason":"session-ok denied"}"#, r#"{"reason":"session-ok"}"#,
            r#""session-ok""#, r#"{"kind":"session-ok"} trailing"#] {
            assert!(!session_ack_accepted(frame), "accepted invalid acknowledgment: {frame}");
        }
    }

    #[test]
    fn i003_remote_request_carries_no_local_descriptors() {
        let frame = serde_json::json!({
            "kind": "canonical-exec", "request_id": 1, "program": "true", "args": [],
            "toolchain_backing": "/tc", "workspace_backing": "/ws", "jobserver_fds": "3,4",
            "jobserver_auth_fd": 7, "--jobserver-auth": "fifo:/tmp/x", "inherited_fds": [3,4,5],
            "descriptor_socket": "/tmp/ancillary.sock"
        });
        let CanonicalExecRequest { request_id, program, args, toolchain_backing, workspace_backing, jobserver_grant } = parse_exec_request(&frame).expect("parses");
        assert_eq!(request_id, 1); assert_eq!(program, "true"); assert!(args.is_empty());
        assert_eq!(toolchain_backing, "/tc"); assert_eq!(workspace_backing, "/ws"); assert_eq!(jobserver_grant, None);
    }

    #[test]
    fn i003_grant_field_is_the_only_capacity_channel() {
        let mut frame = request(2); frame["jobserver_grant"] = serde_json::json!(65536);
        assert_eq!(parse_exec_request(&frame).unwrap().jobserver_grant, Some(65536));
        frame["jobserver_grant"] = serde_json::json!(4294967296_u64);
        assert_eq!(parse_exec_request(&frame).unwrap().jobserver_grant, Some(u32::MAX));
    }

    fn request(id: u64) -> serde_json::Value {
        serde_json::json!({"kind": "canonical-exec", "request_id": id, "program": "true", "args": [], "toolchain_backing": "/tc", "workspace_backing": "/ws"})
    }

    #[test]
    fn budgets_only_shorten_and_malformed_commands_are_never_rewritten() {
        assert_eq!(parse_timeout(&request(1)).unwrap(), DEFAULT_EXECUTION_TIMEOUT);
        let mut frame = request(1); frame["timeout_ms"] = serde_json::json!(25);
        assert_eq!(parse_timeout(&frame).unwrap(), Duration::from_millis(25));
        frame["timeout_ms"] = serde_json::json!(u64::MAX); assert_eq!(parse_timeout(&frame).unwrap(), DEFAULT_EXECUTION_TIMEOUT);
        for bad in [serde_json::json!(0), serde_json::json!(-1), serde_json::json!("10"), serde_json::Value::Null] {
            frame["timeout_ms"] = bad; assert!(parse_timeout(&frame).is_err());
        }
        for bad in [serde_json::json!(["safe",17,"arg"]), serde_json::json!("arg"), serde_json::json!(["\u{0000}"])] {
            frame["args"] = bad; assert!(parse_exec_request(&frame).is_err());
        }
    }

    fn capture_launch(request: CanonicalExecRequest, timeout: Duration, artifacts: Option<ArtifactPlan>) -> io::Result<ExecutionTask> {
        assert!(artifacts.is_none());
        ExecutionTask::spawn(request.request_id, timeout, move |control| {
            let outputs = CapturedOutputs {
                stdout: rabs_wkr::output::CapturedStream::from_reader(&b"A\0\xffB"[..], 4).unwrap(),
                stderr: rabs_wkr::output::CapturedStream::from_reader(&b""[..], 0).unwrap(),
            };
            let mut result = result(request.request_id);
            result.stdout_sha256 = outputs.stdout.sha256().to_owned(); result.stderr_sha256 = outputs.stderr.sha256().to_owned();
            control.retain_outputs(Ok(outputs)).unwrap(); result
        })
    }
    fn output_read(id: u64, stream: &str, offset: u64, max_bytes: usize) -> serde_json::Value {
        serde_json::json!({"kind": "output-read", "request_id": id, "stream": stream, "offset": offset, "max_bytes": max_bytes})
    }
    fn output_ack(id: u64) -> serde_json::Value {
        serde_json::json!({"kind": "output-ack", "request_id": id, "stdout_sha256": rabs_wkr::session::sha256_hex(b"A\0\xffB"),
            "stderr_sha256": rabs_wkr::session::sha256_hex(b""), "stdout_bytes": 4, "stderr_bytes": 0})
    }
    fn pump<F: Future>(mut driver: Pin<&mut F>, peer: &Wire, count: usize) {
        let waker = Waker::from(Arc::new(ThreadWake(std::thread::current()))); let mut cx = Context::from_waker(&waker);
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            assert!(driver.as_mut().poll(&mut cx).is_pending(), "session exited before output acknowledgement");
            if peer.replies().len() >= count { return; }
            assert!(Instant::now() < deadline, "output response deadline"); std::thread::park_timeout(Duration::from_millis(5));
        }
    }

    #[test]
    fn once_retains_binary_output_until_exact_ack_and_does_not_evict_for_new_work() {
        let mut wire = Wire::default(); let peer = wire.clone(); peer.frame(request(10));
        let report = report(); let launches = AtomicUsize::new(0);
        let mut driver = Box::pin(drive_session(&mut wire, &report, true, None, false, |request, timeout, artifacts| {
            launches.fetch_add(1, Ordering::SeqCst); capture_launch(request, timeout, artifacts)
        }, pressure));
        pump(driver.as_mut(), &peer, 1); assert_eq!(peer.replies()[0]["output_transfer"], OUTPUT_TRANSFER); assert_eq!(peer.replies()[0]["stdout_bytes"], 4);
        peer.frame(output_read(10, "stdout", 0, 2)); peer.frame(output_read(10, "stdout", 2, 2));
        peer.frame(output_read(10, "stdout", 0, 2)); peer.frame(output_read(10, "stderr", 0, 1)); peer.frame(request(11));
        pump(driver.as_mut(), &peer, 6); let replies = peer.replies();
        assert_eq!(replies[1]["data_hex"], "4100"); assert_eq!(replies[2]["data_hex"], "ff42"); assert_eq!(replies[2]["eof"], true);
        assert_eq!(replies[1], replies[3], "a range retry changes no stream cursor contract");
        assert_eq!(replies[4]["data_hex"], ""); assert_eq!(replies[4]["eof"], true); assert_eq!(replies[5]["reason"], "output-unacknowledged");
        assert_eq!(launches.load(Ordering::SeqCst), 1);
        let mut wrong_ack = output_ack(10); wrong_ack["stdout_bytes"] = serde_json::json!(3);
        peer.frame(wrong_ack); peer.frame(serde_json::json!({"kind": "ping"})); pump(driver.as_mut(), &peer, 8);
        assert_eq!(peer.replies()[6]["reason"], "output-ack-mismatch"); assert_eq!(peer.replies()[7]["pending_output_request_id"], 10);
        peer.frame(output_ack(10)); wait(driver).unwrap(); assert_eq!(peer.replies()[8]["kind"], "output-acknowledged");
    }

    #[test]
    fn duplicate_ack_cannot_release_new_output_and_disconnect_does_not_expose_it_to_next_session() {
        let mut wire = Wire::default(); let peer = wire.clone(); peer.frame(request(20)); let report = report();
        let mut driver = Box::pin(drive_session(&mut wire, &report, false, None, false, capture_launch, pressure));
        pump(driver.as_mut(), &peer, 1); peer.frame(output_ack(20)); peer.frame(request(21)); pump(driver.as_mut(), &peer, 3);
        peer.frame(output_ack(20)); peer.frame(output_read(21, "stdout", 0, 64)); pump(driver.as_mut(), &peer, 5);
        assert_eq!(peer.replies()[3]["already_released"], true); assert_eq!(peer.replies()[4]["data_hex"], "4100ff42");
        peer.close(); wait(driver).unwrap();
        let mut next = Wire::default(); let next_peer = next.clone(); next.frame(output_read(21, "stdout", 0, 64)); next.close();
        wait(drive_session(&mut next, &report, false, None, false, capture_launch, pressure)).unwrap();
        assert_eq!(next_peer.replies()[0]["reason"], "unknown-output-request");
    }

    #[test]
    fn output_ranges_refuse_foreign_ids_paths_and_invalid_bounds() {
        let mut task = capture_launch(parse_exec_request(&request(30)).unwrap(), Duration::from_secs(5), None).unwrap();
        let completion = wait(task.wait()).unwrap(); let mut pending = PendingOutput::new(30, completion.outputs.unwrap());
        let mut path = output_read(30, "stdout", 0, 1); path["path"] = serde_json::json!("/etc/passwd");
        for bad in [output_read(31, "stdout", 0, 1), path, output_read(30, "../../etc/passwd", 0, 1),
            output_read(30, "stdout", u64::MAX, 1), output_read(30, "stdout", 0, 0), output_read(30, "stdout", 0, MAX_OUTPUT_CHUNK_BYTES + 1)] {
            assert!(pending.read_frame(&bad).is_err(), "accepted {bad}");
        }
        let valid: serde_json::Value = serde_json::from_str(&pending.read_frame(&output_read(30, "stdout", 0, 64)).unwrap()).unwrap();
        assert_eq!(valid["data_hex"], "4100ff42", "refusals do not damage retained output");
    }

    #[test]
    fn output_transfer_negotiation_is_explicit_and_unknown_versions_refuse() {
        assert!(!output_transfer_requested(r#"{"kind":"session-ok"}"#).unwrap());
        assert!(output_transfer_requested(r#"{"kind":"session-ok","output_transfer":"ranges-v1"}"#).unwrap());
        for value in [serde_json::json!("ranges-v2"), serde_json::json!(true), serde_json::Value::Null] {
            assert!(output_transfer_requested(&serde_json::json!({"kind": "session-ok", "output_transfer": value}).to_string()).is_err());
        }
    }

    fn artifact_request(id: u64) -> serde_json::Value {
        let mut value = request(id);
        value["artifacts"] = serde_json::json!({"unit": "dep", "files": ["lib.rlib"]}); value
    }

    fn artifact_launch(request: CanonicalExecRequest, timeout: Duration, plan: Option<ArtifactPlan>) -> io::Result<ExecutionTask> {
        ExecutionTask::spawn_with_artifacts(request.request_id, timeout, plan.unwrap(), move |control| {
            let prepared = artifacts::PreparedArtifacts::new(control.artifact_plan().unwrap()).unwrap();
            std::fs::write(prepared.backing().join("lib.rlib"), b"archive\0\xff").unwrap();
            control.retain_artifacts(Ok(prepared.capture(|| false).unwrap())).unwrap();
            let outputs = CapturedOutputs {
                stdout: rabs_wkr::output::CapturedStream::from_reader(&b"A\0\xffB"[..], 4).unwrap(),
                stderr: rabs_wkr::output::CapturedStream::from_reader(&b""[..], 0).unwrap(),
            };
            let mut result = result(request.request_id);
            result.stdout_sha256 = outputs.stdout.sha256().into(); result.stderr_sha256 = outputs.stderr.sha256().into();
            control.retain_outputs(Ok(outputs)).unwrap(); result
        })
    }

    #[test]
    fn both_output_owners_must_ack_before_once_exits_in_either_order() {
        for artifacts_first in [false, true] {
            let mut wire = Wire::default(); let peer = wire.clone(); peer.frame(artifact_request(40)); let report = report();
            let launches = AtomicUsize::new(0);
            let mut driver = Box::pin(drive_session(&mut wire, &report, true, None, true, |request, timeout, plan| {
                launches.fetch_add(1, Ordering::SeqCst); artifact_launch(request, timeout, plan)
            }, pressure));
            pump(driver.as_mut(), &peer, 1);
            let offer = peer.replies()[0].clone();
            assert_eq!(offer["artifact_transfer"], ARTIFACT_TRANSFER); assert_eq!(offer["artifact_ack_required"], true);
            let ack = serde_json::json!({"kind": "artifact-ack", "request_id": 40,
                "manifest_sha256": offer["artifact_manifest"]["manifest_sha256"], "total_bytes": offer["artifact_manifest"]["total_bytes"]});
            peer.frame(serde_json::json!({"kind": "artifact-read", "request_id": 40, "name": "lib.rlib", "offset": 0, "max_bytes": 64}));
            pump(driver.as_mut(), &peer, 2); assert_eq!(peer.replies()[1]["data_hex"], "6172636869766500ff");
            if artifacts_first { peer.frame(ack.clone()); } else { peer.frame(output_ack(40)); }
            peer.frame(artifact_request(41)); peer.frame(serde_json::json!({"kind": "ping"}));
            pump(driver.as_mut(), &peer, 5);
            assert_eq!(peer.replies()[3]["reason"], if artifacts_first { "output-unacknowledged" } else { "artifacts-unacknowledged" });
            assert_eq!(launches.load(Ordering::SeqCst), 1);
            if artifacts_first { peer.frame(output_ack(40)); } else { peer.frame(ack); }
            wait(driver).unwrap(); assert_eq!(peer.replies().len(), 6);
        }
    }

    #[test]
    fn malformed_artifact_declarations_do_not_launch_and_connection_loss_clears_retention() {
        let mut wire = Wire::default(); let peer = wire.clone(); let mut bad = artifact_request(1);
        bad["artifacts"]["files"] = serde_json::json!(["a", "../escape"]); peer.frame(bad);
        peer.frame(artifact_request(2)); let report = report(); let launches = AtomicUsize::new(0);
        let mut driver = Box::pin(drive_session(&mut wire, &report, false, None, true, |request, timeout, plan| {
            launches.fetch_add(1, Ordering::SeqCst); artifact_launch(request, timeout, plan)
        }, pressure));
        pump(driver.as_mut(), &peer, 2); assert_eq!(peer.replies()[0]["kind"], "error"); assert_eq!(launches.load(Ordering::SeqCst), 1);
        peer.close(); wait(driver).unwrap();
        let mut next = Wire::default(); let next_peer = next.clone();
        next.frame(serde_json::json!({"kind": "artifact-read", "request_id": 2, "name": "lib.rlib", "offset": 0})); next.close();
        wait(drive_session(&mut next, &report, false, None, true, artifact_launch, pressure)).unwrap();
        assert_eq!(next_peer.replies()[0]["reason"], "unknown-artifact-request");
    }

    #[cfg(unix)]
    #[test]
    fn journaled_result_write_failure_reconciles_without_duplicate_execution() {
        let root = tempfile::tempdir().unwrap();
        let mut journal = WorkerJournal::open(root.path(), "session-test", "coord").unwrap();
        let mut wire = Wire::default();
        wire.frame(request(40));
        wire.0.lock().unwrap().fail_write = true;
        let launches = AtomicUsize::new(0);
        let outcome = wait(drive_session(&mut wire, &report(), true, Some(&mut journal), false, |request, timeout, artifacts| {
            let state: serde_json::Value = serde_json::from_slice(&std::fs::read(root.path().join("requests.json")).unwrap()).unwrap();
            assert_eq!(state["last"]["request_id"], 40, "admission precedes the launch seam");
            assert_eq!(state["last"]["resolved"], false);
            launches.fetch_add(1, Ordering::SeqCst);
            capture_launch(request, timeout, artifacts)
        }, pressure));
        assert!(outcome.is_err());
        assert_eq!(launches.load(Ordering::SeqCst), 1);
        drop(journal);
        let mut journal = WorkerJournal::open(root.path(), "session-test", "coord").unwrap();
        let mut next = Wire::default();
        let peer = next.clone();
        next.frame(serde_json::json!({"kind":"request-status","request_id":40}));
        next.frame(request(40));
        next.close();
        wait(drive_session(&mut next, &report(), false, Some(&mut journal), false, |_, _, _| {
            panic!("a lost result write must never rerun the process")
        }, pressure)).unwrap();
        let replies = peer.replies();
        assert_eq!(replies[0]["kind"], "request-status");
        assert_eq!(replies[0]["status"], "terminal-observed");
        assert_eq!(replies[0]["receipt"]["exit_code"], 0);
        assert_eq!(replies[0]["output_recovery"], "unavailable");
        assert_eq!(replies[0]["output_available_in_this_session"], false);
        assert_eq!(replies[0]["publication_authorized"], false);
        assert_eq!(replies[1]["reason"], "durable-request-already-admitted");
    }

    #[cfg(unix)]
    #[test]
    fn journaled_disconnect_records_only_after_session_owned_cleanup() {
        let root = tempfile::tempdir().unwrap();
        let mut journal = WorkerJournal::open(root.path(), "session-test", "coord").unwrap();
        let mut wire = Wire::default();
        wire.frame(request(50));
        wire.close();
        let cleaned = Arc::new(AtomicBool::new(false));
        let worker_cleaned = Arc::clone(&cleaned);
        wait(drive_session(&mut wire, &report(), false, Some(&mut journal), false, |request, timeout, _| {
            let cleaned = Arc::clone(&worker_cleaned);
            ExecutionTask::spawn(request.request_id, timeout, move |control| {
                while control.reason().is_none() {
                    std::thread::sleep(Duration::from_millis(1));
                }
                cleaned.store(true, Ordering::Release);
                result(request.request_id)
            })
        }, pressure)).unwrap();
        assert!(cleaned.load(Ordering::Acquire));
        drop(journal);
        let journal = WorkerJournal::open(root.path(), "session-test", "coord").unwrap();
        let status = journal.status(50);
        assert_eq!(status["status"], "terminal-observed");
        assert_eq!(status["receipt"]["stop_reason"], StopReason::SessionLost.label());
        assert_ne!(status["receipt"]["exit_code"], 0);
    }

    #[cfg(unix)]
    #[test]
    fn journaled_unfinished_admission_blocks_replay_and_new_work() {
        let root = tempfile::tempdir().unwrap();
        let mut journal = WorkerJournal::open(root.path(), "session-test", "coord").unwrap();
        journal.admit(&request(60), DEFAULT_EXECUTION_TIMEOUT).unwrap();
        drop(journal);
        let mut journal = WorkerJournal::open(root.path(), "session-test", "coord").unwrap();
        let mut wire = Wire::default();
        let peer = wire.clone();
        wire.frame(request(60));
        wire.frame(request(61));
        wire.frame(serde_json::json!({"kind":"request-status","request_id":60}));
        wire.close();
        wait(drive_session(&mut wire, &report(), false, Some(&mut journal), false, |_, _, _| {
            panic!("uncertain prior ownership must block all process launch")
        }, pressure)).unwrap();
        let replies = peer.replies();
        assert_eq!(replies[0]["reason"], "durable-request-already-admitted");
        assert_eq!(replies[1]["reason"], "prior-execution-uncertain");
        assert_eq!(replies[2]["status"], "execution-uncertain");
        assert_eq!(replies[2]["replay_authorized"], false);
    }

    #[cfg(unix)]
    #[test]
    fn journaled_launch_failure_does_not_authorize_another_attempt() {
        let root = tempfile::tempdir().unwrap();
        let mut journal = WorkerJournal::open(root.path(), "session-test", "coord").unwrap();
        let mut wire = Wire::default();
        let peer = wire.clone();
        wire.frame(request(70));
        wire.frame(request(71));
        wire.close();
        let launches = AtomicUsize::new(0);
        wait(drive_session(&mut wire, &report(), false, Some(&mut journal), false, |_, _, _| {
            launches.fetch_add(1, Ordering::SeqCst);
            Err(io::Error::other("injected launch failure"))
        }, pressure)).unwrap();
        assert_eq!(launches.load(Ordering::SeqCst), 1);
        assert_eq!(peer.replies()[1]["reason"], "prior-execution-uncertain");
        assert_eq!(journal.status(70)["status"], "execution-uncertain");
    }

    #[cfg(unix)]
    #[test]
    fn journal_handshake_advertises_identity_and_recovery_version() {
        let root = tempfile::tempdir().unwrap();
        let mut journal = WorkerJournal::open(root.path(), "session-test", "coord").unwrap();
        journal.admit(&request(80), DEFAULT_EXECUTION_TIMEOUT).unwrap();
        let hello: serde_json::Value = serde_json::from_str(&worker_hello(&report(), &journal)).unwrap();
        assert_eq!(hello["boot_generation"], journal.boot_generation().0);
        assert_eq!(hello["incarnation"], format!("{:032x}", journal.incarnation().0));
        assert_eq!(hello["request_high_water"], 80);
        assert_eq!(hello["recovery_protocols"][0], RECOVERY_PROTOCOL);
        assert!(validate_recovery_selection(r#"{"kind":"session-ok"}"#).is_ok());
        assert!(validate_recovery_selection(&serde_json::json!({"kind":"session-ok","recovery_protocol":RECOVERY_PROTOCOL}).to_string()).is_ok());
        for bad in [serde_json::json!("other"), serde_json::json!(true), serde_json::Value::Null] {
            assert!(validate_recovery_selection(&serde_json::json!({"kind":"session-ok","recovery_protocol":bad}).to_string()).is_err());
        }
    }

    #[cfg(unix)]
    #[test]
    fn unnegotiated_artifact_request_does_not_burn_durable_admission() {
        let root = tempfile::tempdir().unwrap();
        let mut journal = WorkerJournal::open(root.path(), "session-test", "coord").unwrap();
        let mut wire = Wire::default(); let peer = wire.clone();
        wire.frame(artifact_request(90));
        wire.frame(serde_json::json!({"kind": "request-status", "request_id": 90}));
        wire.close();
        wait(drive_session(&mut wire, &report(), false, Some(&mut journal), false, |_, _, _| {
            panic!("unnegotiated capture must not launch")
        }, pressure)).unwrap();
        assert_eq!(peer.replies()[0]["reason"], "artifact transfer not negotiated");
        assert_eq!(peer.replies()[1]["status"], "unknown");
        assert_eq!(journal.high_water(), None);
    }

    #[cfg(unix)]
    #[test]
    fn durable_artifact_identity_survives_restart_without_claiming_scratch_recovery() {
        let root = tempfile::tempdir().unwrap();
        let mut journal = WorkerJournal::open(root.path(), "session-test", "coord").unwrap();
        let mut wire = Wire::default(); let peer = wire.clone(); let report = report();
        wire.frame(artifact_request(100));
        let mut driver = Box::pin(drive_session(&mut wire, &report, false, Some(&mut journal), true, artifact_launch, pressure));
        pump(driver.as_mut(), &peer, 1);
        peer.frame(serde_json::json!({"kind": "request-status", "request_id": 100}));
        pump(driver.as_mut(), &peer, 2);
        let status = peer.replies()[1].clone();
        assert_eq!(status["status"], "terminal-observed");
        assert_eq!(status["artifacts_available_in_this_session"], true);
        assert!(status["receipt"].get("artifact_manifest").is_none());
        peer.close(); wait(driver).unwrap(); drop(journal);

        let mut journal = WorkerJournal::open(root.path(), "session-test", "coord").unwrap();
        let mut next = Wire::default(); let peer = next.clone();
        next.frame(serde_json::json!({"kind": "request-status", "request_id": 100}));
        next.frame(artifact_request(100));
        let mut changed = artifact_request(100);
        changed["artifacts"]["files"] = serde_json::json!(["different.rlib"]);
        next.frame(changed); next.close();
        wait(drive_session(&mut next, &report, false, Some(&mut journal), true, |_, _, _| {
            panic!("neither lost output nor a changed declaration authorizes rerun")
        }, pressure)).unwrap();
        let replies = peer.replies();
        assert_eq!(replies[0]["status"], "terminal-observed");
        assert_eq!(replies[0]["artifacts_available_in_this_session"], false);
        assert_eq!(replies[0]["output_available_in_this_session"], false);
        assert_eq!(replies[1]["reason"], "durable-request-already-admitted");
        assert_eq!(replies[2]["reason"], "durable-request-conflict");
    }
}
