//! `rabs-wkr` — the RABS trusted worker daemon binary (bead S5).
//!
//! Boots the asupersync runtime and connects to the coordinator. Blocking
//! sandbox execution has one session-owned ExecutionTask; the reactor keeps
//! accepting control frames while that task owns the process and drain work.
//! The prototype newline transport is not authenticated ATP. Results remain
//! offers, never publications; this binary has no coordinator commit API.
//!
//! CLI: rabs-wkr --coordinator <host:port> [--worker-id ID] [--once]
//! `--once` exits after one admitted execution completes, not after a ping.

use asupersync::cx::Cx;
use asupersync::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use asupersync::net::TcpStream;
use asupersync::runtime::RuntimeBuilder;
use rabs_wkr::execution::{
    DEFAULT_EXECUTION_TIMEOUT, ExecutionCompletion, ExecutionTask, StopReason,
};
use rabs_wkr::session::{
    CanonicalExecRequest, execute_canonical_controlled, probe_capability, sample_pressure,
};
use std::future::{Future, poll_fn};
use std::io;
use std::pin::pin;
use std::task::Poll;
use std::time::Duration;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const MAX_FRAME_BYTES: usize = 1 << 20;

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

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("--version") => {
            println!("rabs-wkr {VERSION}");
            return;
        }
        Some("--help") => {
            println!(
                "rabs-wkr {VERSION} — RABS trusted worker daemon\n\
                 USAGE: rabs-wkr --coordinator <host:port> [--worker-id ID] [--once]\n\
                 Serves canonical-exec requests through the sandbox launcher; \
                 offers results, never commits (R50)."
            );
            return;
        }
        _ => {}
    }

    let mut coordinator = None;
    let mut worker_id = std::env::var("RABS_WORKER_ID").unwrap_or_else(|_| {
        std::process::Command::new("hostname")
            .arg("-s")
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|| "worker".to_string())
    });
    let mut once = false;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--coordinator" => coordinator = iter.next().cloned(),
            "--worker-id" => {
                if let Some(id) = iter.next() {
                    worker_id = id.clone();
                }
            }
            "--once" => once = true,
            other => {
                eprintln!("rabs-wkr: unknown argument {other:?} (see --help)");
                std::process::exit(2);
            }
        }
    }
    let Some(coordinator) = coordinator else {
        eprintln!("rabs-wkr: --coordinator <host:port> is required");
        std::process::exit(2);
    };

    let report = probe_capability(&worker_id);
    eprintln!(
        "{{\"v\":1,\"kind\":\"rabs-wkr-boot\",\"worker_id\":\"{}\",\"canonical\":{},\"slots\":{}}}",
        report.worker_id, report.canonical_namespace, report.slots
    );

    let runtime = match RuntimeBuilder::current_thread().build() {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("rabs-wkr: runtime build failed: {error:?}");
            std::process::exit(1);
        }
    };

    let handle = runtime.handle();
    let exit_code: i32 = runtime.block_on(async move {
        handle
            .spawn(async move {
                let cx = Cx::current().expect("runtime task Cx");
                match session_loop(&cx, &coordinator, &report, once).await {
                    Ok(()) => 0,
                    Err(error) => {
                        eprintln!("rabs-wkr: session ended: {error}");
                        1
                    }
                }
            })
            .await
    });
    std::process::exit(exit_code);
}

/// Partial input belongs to the session, not to a disposable read future.
/// Completion may win a race after a prefix has arrived; the next read must
/// continue that exact frame instead of interpreting its suffix as a new one.
#[derive(Default)]
struct FrameReader {
    pending: Vec<u8>,
}

impl FrameReader {
    async fn read<R: AsyncRead + Unpin>(&mut self, stream: &mut R) -> io::Result<Option<String>> {
        let mut byte = [0_u8; 1];
        loop {
            if stream.read(&mut byte).await? == 0 {
                return if self.pending.is_empty() {
                    Ok(None)
                } else {
                    Err(io::Error::new(io::ErrorKind::UnexpectedEof, "truncated frame"))
                };
            }
            if byte[0] == b'\n' {
                return String::from_utf8(std::mem::take(&mut self.pending))
                    .map(Some)
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
    let mut bytes = line.as_bytes().to_vec();
    bytes.push(b'\n');
    stream.write_all(&bytes).await
}

enum SessionEvent {
    Frame(io::Result<Option<String>>),
    Completed {
        request_id: u64,
        result: Result<ExecutionCompletion, String>,
    },
}

async fn next_event<R: AsyncRead + Unpin>(
    reader: &mut FrameReader,
    stream: &mut R,
    active: &mut Option<ExecutionTask>,
) -> SessionEvent {
    let mut read = pin!(reader.read(stream));
    poll_fn(|cx| {
        // A flood of immediately-readable pings cannot starve completion.
        if let Some(task) = active.as_mut()
            && let Poll::Ready(result) = task.poll_completion(cx)
        {
            return Poll::Ready(SessionEvent::Completed {
                request_id: task.request_id(),
                result,
            });
        }
        read.as_mut().poll(cx).map(SessionEvent::Frame)
    })
    .await
}

fn completion_frame(completion: &ExecutionCompletion) -> String {
    let result = &completion.result;
    serde_json::json!({
        "kind": "exec-result",
        "request_id": result.request_id,
        "exit_code": result.exit_code,
        "stdout_sha256": result.stdout_sha256,
        "stderr_sha256": result.stderr_sha256,
        "executed": result.executed,
        "residual_group_members": result.residual_group_members,
        "stdout_spill_bytes": result.stdout_spill_bytes,
        "stderr_spill_bytes": result.stderr_spill_bytes,
        "stdout_spill_path": result.stdout_spill_path,
        "stderr_spill_path": result.stderr_spill_path,
        "stop_reason": completion.stop_reason.map(StopReason::label),
    })
    .to_string()
}

fn request_error(request_id: Option<u64>, reason: &str) -> String {
    serde_json::json!({"kind": "error", "request_id": request_id, "reason": reason}).to_string()
}

/// The actual steady-state driver. The launch seam keeps tests independent of
/// host isolation support; production supplies only execute_canonical_controlled.
/// There is one active execution and no hidden queue. Request IDs must increase
/// within a session: reconnect/resumption requires a separate durable protocol,
/// and retransmitting an uncertain request here never launches it again.
async fn drive_session<S, L, H>(
    stream: &mut S,
    report: &rabs_wkr::session::CapabilityReport,
    once: bool,
    mut launch: L,
    mut heartbeat: H,
) -> Result<(), String>
where
    S: AsyncRead + AsyncWrite + Unpin,
    L: FnMut(CanonicalExecRequest, Duration) -> io::Result<ExecutionTask>,
    H: FnMut() -> rabs_wkr::session::PressureSample,
{
    let mut reader = FrameReader::default();
    let mut active: Option<ExecutionTask> = None;
    let mut last_admitted: Option<u64> = None;
    let outcome = async {
        loop {
            if Cx::current().is_some_and(|cx| cx.checkpoint().is_err()) {
                return Err("session cancelled".to_owned());
            }
            let reply = match next_event(&mut reader, stream, &mut active).await {
                SessionEvent::Completed { request_id, result } => {
                    // Completion consumes the thread only AFTER drain and reap.
                    // Clearing active now releases capacity; cancellation ACKs do not.
                    drop(active.take());
                    let reply = match result {
                        Ok(completion) => completion_frame(&completion),
                        Err(reason) => request_error(Some(request_id), &reason),
                    };
                    write_frame(stream, &reply).await.map_err(|e| format!("result write: {e}"))?;
                    if once {
                        return Ok(());
                    }
                    continue;
                }
                SessionEvent::Frame(Ok(None)) => return Ok(()),
                SessionEvent::Frame(Err(error)) => return Err(format!("frame read: {error}")),
                SessionEvent::Frame(Ok(Some(frame))) => {
                    let value = match serde_json::from_str::<serde_json::Value>(&frame) {
                        Ok(value) => value,
                        Err(_) => {
                            write_frame(stream, &request_error(None, "malformed"))
                                .await.map_err(|e| format!("error write: {e}"))?;
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
                            }).to_string()
                        }
                        Some("cancel") => match (&active, request_id) {
                            (Some(task), Some(id)) if task.request_id() == id => {
                                let accepted = task.cancel(StopReason::Cancelled);
                                serde_json::json!({
                                    "kind": "cancel-accepted", "request_id": id, "accepted": accepted,
                                    "cleanup_pending": true,
                                }).to_string()
                            }
                            _ => request_error(request_id, "unknown-request"),
                        },
                        Some("canonical-exec") => {
                            let parsed = parse_exec_request(&value)
                                .and_then(|request| parse_timeout(&value).map(|timeout| (request, timeout)));
                            match parsed {
                                Err(reason) => request_error(request_id, &reason),
                                Ok((request, _)) if last_admitted.is_some_and(|last| request.request_id <= last) => {
                                    request_error(Some(request.request_id), "stale-request-id")
                                }
                                Ok((request, _)) if active.is_some() => {
                                    request_error(Some(request.request_id), "worker-busy")
                                }
                                Ok((request, timeout)) => {
                                    let id = request.request_id;
                                    match launch(request, timeout) {
                                        Ok(task) => {
                                            last_admitted = Some(id);
                                            active = Some(task);
                                            continue;
                                        }
                                        Err(error) => request_error(Some(id), &format!("execution start: {error}")),
                                    }
                                }
                            }
                        }
                        _ => request_error(request_id, "unknown-frame"),
                    }
                }
            };
            write_frame(stream, &reply).await.map_err(|e| format!("control write: {e}"))?;
        }
    }.await;

    // EOF, malformed/truncated transport, failed writes and cooperative runtime
    // cancellation all revoke the session's work and await cleanup asynchronously.
    // Future-drop/panic still falls back to ExecutionTask's cancel-and-join guard.
    if let Some(mut task) = active.take() {
        task.cancel(StopReason::SessionLost);
        let cleanup = task.wait().await;
        if outcome.is_ok() {
            cleanup.map_err(|e| format!("session cleanup: {e}"))?;
        }
    }
    outcome
}

async fn session_loop(
    cx: &Cx,
    coordinator: &str,
    report: &rabs_wkr::session::CapabilityReport,
    once: bool,
) -> Result<(), String> {
    let mut stream = TcpStream::connect(coordinator.to_string())
        .await
        .map_err(|e| format!("connect {coordinator}: {e}"))?;
    cx.trace("rabs-wkr connected to coordinator");

    // This retains the existing prototype handshake; it does NOT upgrade the
    // fixed-token newline transport into authenticated ATP.
    let hello = format!(
        "{{\"kind\":\"worker-hello\",\"worker_id\":{},\"canonical\":{},\"slots\":{},\"token_id\":1}}",
        json_string(&report.worker_id), report.canonical_namespace, report.slots,
    );
    write_frame(&mut stream, &hello).await.map_err(|e| format!("hello write: {e}"))?;
    let ack = FrameReader::default().read(&mut stream).await
        .map_err(|e| format!("handshake read: {e}"))?
        .ok_or_else(|| "no session-ok".to_string())?;
    if !session_ack_accepted(&ack) {
        return Err(format!("handshake refused: {ack}"));
    }

    let cargo_home = std::env::temp_dir().join(format!("rabs-wkr-ch-{}", std::process::id()));
    let home = std::env::temp_dir().join(format!("rabs-wkr-home-{}", std::process::id()));
    let spills = std::env::temp_dir().join(format!("rabs-wkr-spill-{}", std::process::id()));
    for path in [&cargo_home, &home, &spills] {
        std::fs::create_dir_all(path).map_err(|e| format!("prepare {}: {e}", path.display()))?;
    }
    drive_session(
        &mut stream,
        report,
        once,
        |request, timeout| {
            let cargo_home = cargo_home.clone();
            let home = home.clone();
            let spills = spills.clone();
            let slots = report.slots;
            ExecutionTask::spawn(request.request_id, timeout, move |control| {
                execute_canonical_controlled(&request, &cargo_home, &home, slots, &spills, &control)
            })
        },
        || sample_pressure(&cargo_home),
    ).await
}

fn session_ack_accepted(frame: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(frame)
        .ok()
        .and_then(|value| {
            value.get("kind").and_then(|kind| kind.as_str()).map(|kind| kind == "session-ok")
        })
        .unwrap_or(false)
}

fn parse_timeout(value: &serde_json::Value) -> Result<Duration, String> {
    match value.get("timeout_ms") {
        None => Ok(DEFAULT_EXECUTION_TIMEOUT),
        Some(value) => {
            let millis = value.as_u64().filter(|millis| *millis != 0)
                .ok_or("timeout_ms must be a positive integer")?;
            Ok(Duration::from_millis(millis).min(DEFAULT_EXECUTION_TIMEOUT))
        }
    }
}

fn parse_exec_request(value: &serde_json::Value) -> Result<CanonicalExecRequest, String> {
    let text = |name: &str| -> Result<String, String> {
        value.get(name).and_then(serde_json::Value::as_str)
            .filter(|text| !text.is_empty() && !text.contains('\0'))
            .map(str::to_owned).ok_or_else(|| format!("exec request missing or invalid {name}"))
    };
    let args = match value.get("args") {
        None => Vec::new(),
        Some(value) => value.as_array().ok_or("args must be an array")?.iter()
            .map(|item| item.as_str().filter(|arg| !arg.contains('\0')).map(str::to_owned)
                .ok_or_else(|| "every argument must be a NUL-free string".to_owned()))
            .collect::<Result<Vec<_>, _>>()?,
    };
    let jobserver_grant = match value.get("jobserver_grant") {
        None => None,
        Some(value) => Some(u32::try_from(value.as_u64()
            .ok_or("jobserver_grant must be an unsigned integer")?).unwrap_or(u32::MAX)),
    };
    Ok(CanonicalExecRequest {
        request_id: value.get("request_id").and_then(serde_json::Value::as_u64)
            .ok_or("exec request missing request_id")?,
        program: text("program")?,
        args,
        toolchain_backing: text("toolchain_backing")?,
        workspace_backing: text("workspace_backing")?,
        jobserver_grant,
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
        input: VecDeque<u8>,
        output: Vec<u8>,
        eof: bool,
        fail_write: bool,
        reader: Option<Waker>,
    }

    /// A fragmented async peer, not an alternate execution implementation.
    /// Tests run the production driver and real session-owned execution threads.
    #[derive(Clone, Default)]
    struct Wire(Arc<Mutex<WireState>>);

    impl Wire {
        fn bytes(&self, bytes: &[u8]) {
            let wake = {
                let mut state = self.0.lock().unwrap();
                state.input.extend(bytes);
                state.reader.take()
            };
            if let Some(waker) = wake {
                waker.wake();
            }
        }

        fn frame(&self, value: serde_json::Value) {
            self.bytes(format!("{value}\n").as_bytes());
        }

        fn close(&self) {
            let wake = {
                let mut state = self.0.lock().unwrap();
                state.eof = true;
                state.reader.take()
            };
            if let Some(waker) = wake {
                waker.wake();
            }
        }

        fn replies(&self) -> Vec<serde_json::Value> {
            let state = self.0.lock().unwrap();
            String::from_utf8(state.output.clone()).unwrap().lines()
                .map(|line| serde_json::from_str(line).unwrap()).collect()
        }
    }

    impl AsyncRead for Wire {
        fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            if buf.remaining() == 0 {
                return Poll::Ready(Ok(()));
            }
            let mut state = self.0.lock().unwrap();
            if let Some(byte) = state.input.pop_front() {
                buf.put_slice(&[byte]);
                Poll::Ready(Ok(()))
            } else if state.eof {
                Poll::Ready(Ok(()))
            } else {
                state.reader = Some(cx.waker().clone());
                Poll::Pending
            }
        }
    }

    impl AsyncWrite for Wire {
        fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
            let mut state = self.0.lock().unwrap();
            if state.fail_write {
                return Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed peer")));
            }
            state.output.extend_from_slice(bytes);
            Poll::Ready(Ok(bytes.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    struct ThreadWake(std::thread::Thread);
    impl Wake for ThreadWake {
        fn wake(self: Arc<Self>) {
            self.0.unpark();
        }
    }

    fn wait<F: Future>(future: F) -> F::Output {
        let mut future = pin!(future);
        let waker = Waker::from(Arc::new(ThreadWake(std::thread::current())));
        let mut cx = Context::from_waker(&waker);
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Poll::Ready(result) = future.as_mut().poll(&mut cx) {
                return result;
            }
            assert!(Instant::now() < deadline, "session test timed out");
            std::thread::park_timeout(Duration::from_millis(10));
        }
    }

    fn report() -> rabs_wkr::session::CapabilityReport {
        rabs_wkr::session::CapabilityReport {
            worker_id: "session-test".to_owned(), canonical_namespace: true,
            missing: vec![], slots: 4,
        }
    }

    fn pressure() -> rabs_wkr::session::PressureSample {
        rabs_wkr::session::PressureSample { load_x100: 10, free_disk_mib: 100 }
    }

    fn result(id: u64) -> rabs_wkr::session::ExecResult {
        rabs_wkr::session::ExecResult {
            request_id: id, exit_code: 0,
            stdout_sha256: rabs_wkr::session::sha256_hex(b"output"),
            stderr_sha256: rabs_wkr::session::sha256_hex(b""), executed: true,
            residual_group_members: 0, stdout_spill_bytes: 0, stderr_spill_bytes: 0,
            stdout_spill_path: None, stderr_spill_path: None,
        }
    }

    #[test]
    fn active_execution_handles_ping_exact_cancel_and_busy_without_duplicate_launch() {
        let mut wire = Wire::default();
        let peer = wire.clone();
        peer.frame(request(1));
        peer.frame(serde_json::json!({"kind": "ping"}));
        peer.frame(serde_json::json!({"kind": "cancel", "request_id": 999}));
        peer.frame(request(1));
        peer.frame(request(2));
        peer.frame(serde_json::json!({"kind": "cancel", "request_id": 1}));
        let launches = Arc::new(AtomicUsize::new(0));
        let cleaned = Arc::new(AtomicBool::new(false));
        let worker_cleaned = Arc::clone(&cleaned);
        wait(drive_session(&mut wire, &report(), true, |request, timeout| {
            launches.fetch_add(1, Ordering::SeqCst);
            let cleaned = Arc::clone(&worker_cleaned);
            ExecutionTask::spawn(request.request_id, timeout, move |control| {
                while control.reason().is_none() {
                    std::thread::sleep(Duration::from_millis(1));
                }
                cleaned.store(true, Ordering::Release);
                result(request.request_id) // Deliberately zero: interruption wins.
            })
        }, pressure)).unwrap();
        assert_eq!(launches.load(Ordering::SeqCst), 1);
        assert!(cleaned.load(Ordering::Acquire));
        let replies = peer.replies();
        assert_eq!(replies[0]["kind"], "heartbeat");
        assert_eq!(replies[0]["active_request_id"], 1);
        assert_eq!(replies[1]["reason"], "unknown-request");
        assert_eq!(replies[2]["reason"], "stale-request-id");
        assert_eq!(replies[3]["reason"], "worker-busy");
        assert_eq!(replies[4]["kind"], "cancel-accepted");
        assert_eq!(replies[4]["cleanup_pending"], true);
        assert_eq!(replies[5]["kind"], "exec-result");
        assert_eq!(replies[5]["stop_reason"], "cancelled");
        assert_eq!(replies[5]["exit_code"], 130);
    }

    #[test]
    fn disconnect_and_write_failure_wait_for_session_owned_cleanup() {
        for write_failure in [false, true] {
            let mut wire = Wire::default();
            wire.frame(request(1));
            if write_failure {
                wire.frame(serde_json::json!({"kind": "ping"}));
                wire.0.lock().unwrap().fail_write = true;
            } else {
                wire.close();
            }
            let cleaned = Arc::new(AtomicBool::new(false));
            let worker_cleaned = Arc::clone(&cleaned);
            let outcome = wait(drive_session(&mut wire, &report(), false, |request, timeout| {
                let cleaned = Arc::clone(&worker_cleaned);
                ExecutionTask::spawn(request.request_id, timeout, move |control| {
                    while control.reason().is_none() {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    assert_eq!(control.reason(), Some(StopReason::SessionLost));
                    cleaned.store(true, Ordering::Release);
                    result(request.request_id)
                })
            }, pressure));
            assert_eq!(outcome.is_err(), write_failure);
            assert!(cleaned.load(Ordering::Acquire), "session returned before cleanup");
        }
    }

    #[test]
    fn request_budget_expires_without_another_incoming_frame() {
        let mut wire = Wire::default();
        let peer = wire.clone();
        let mut frame = request(7);
        frame["timeout_ms"] = serde_json::json!(15);
        peer.frame(frame);
        wait(drive_session(&mut wire, &report(), true, |request, timeout| {
            assert_eq!(timeout, Duration::from_millis(15));
            ExecutionTask::spawn(request.request_id, timeout, move |control| {
                while control.reason().is_none() {
                    std::thread::sleep(Duration::from_millis(1));
                }
                result(request.request_id)
            })
        }, pressure)).unwrap();
        let replies = peer.replies();
        assert_eq!(replies.len(), 1);
        assert_eq!(replies[0]["stop_reason"], "deadline-exceeded");
        assert_eq!(replies[0]["exit_code"], 124);
    }

    #[test]
    fn completed_request_is_not_rerun_and_newer_work_can_use_the_slot() {
        let mut wire = Wire::default();
        let peer = wire.clone();
        peer.frame(request(9));
        let launches = Arc::new(AtomicUsize::new(0));
        let report = report();
        let mut driver = Box::pin(drive_session(&mut wire, &report, false, |request, timeout| {
            launches.fetch_add(1, Ordering::SeqCst);
            ExecutionTask::spawn(request.request_id, timeout, move |_| result(request.request_id))
        }, pressure));
        let waker = Waker::from(Arc::new(ThreadWake(std::thread::current())));
        let mut cx = Context::from_waker(&waker);
        let deadline = Instant::now() + Duration::from_secs(5);
        for expected_results in 1..=2 {
            loop {
                assert!(driver.as_mut().poll(&mut cx).is_pending());
                let count = peer.replies().iter().filter(|frame| frame["kind"] == "exec-result").count();
                if count == expected_results {
                    break;
                }
                assert!(Instant::now() < deadline, "completion not delivered");
                std::thread::park_timeout(Duration::from_millis(10));
            }
            if expected_results == 1 {
                peer.frame(request(9)); // Lost-response retransmission: no new process.
                peer.frame(request(10)); // A fresh identity may reuse the released slot.
            }
        }
        peer.close();
        wait(driver).unwrap();
        assert_eq!(launches.load(Ordering::SeqCst), 2);
        let replies = peer.replies();
        assert_eq!(replies[0]["request_id"], 9);
        assert!(replies[0]["stop_reason"].is_null());
        assert_eq!(replies[1]["reason"], "stale-request-id");
        assert_eq!(replies[2]["request_id"], 10);
    }

    #[test]
    fn completion_preserves_a_partially_received_control_frame() {
        let mut wire = Wire::default();
        let peer = wire.clone();
        peer.bytes(b"{\"kind\":");
        let release = Arc::new(AtomicBool::new(false));
        let worker_release = Arc::clone(&release);
        let mut active = Some(ExecutionTask::spawn(1, Duration::from_secs(5), move |control| {
            while !worker_release.load(Ordering::Acquire) && control.reason().is_none() {
                std::thread::sleep(Duration::from_millis(1));
            }
            result(1)
        }).unwrap());
        let mut reader = FrameReader::default();
        let mut event = Box::pin(next_event(&mut reader, &mut wire, &mut active));
        let waker = Waker::from(Arc::new(ThreadWake(std::thread::current())));
        assert!(event.as_mut().poll(&mut Context::from_waker(&waker)).is_pending());
        release.store(true, Ordering::Release);
        assert!(matches!(wait(event), SessionEvent::Completed { request_id: 1, result: Ok(_) }));
        drop(active.take());
        peer.bytes(b"\"ping\"}\n");
        assert_eq!(wait(reader.read(&mut wire)).unwrap(), Some("{\"kind\":\"ping\"}".to_owned()));
    }

    #[test]
    fn malformed_transport_is_not_lossily_decoded_or_treated_as_clean_eof() {
        for (bytes, kind) in [
            (vec![0xff, b'\n'], io::ErrorKind::InvalidData),
            (b"{\"kind\":".to_vec(), io::ErrorKind::UnexpectedEof),
            (vec![b'x'; MAX_FRAME_BYTES + 1], io::ErrorKind::InvalidData),
        ] {
            let mut wire = Wire::default();
            wire.bytes(&bytes);
            wire.close();
            assert_eq!(wait(FrameReader::default().read(&mut wire)).unwrap_err().kind(), kind);
        }
    }

    #[test]
    fn session_ack_requires_success_message_kind() {
        assert!(session_ack_accepted(r#"{"kind":"session-ok","session_id":7}"#));
        for frame in [
            r#"{"kind":"error","reason":"session-ok denied"}"#,
            r#"{"reason":"session-ok"}"#,
            r#""session-ok""#,
            r#"{"kind":"session-ok"} trailing"#,
        ] {
            assert!(!session_ack_accepted(frame), "accepted invalid acknowledgment: {frame}");
        }
    }

    #[test]
    fn i003_remote_request_carries_no_local_descriptors() {
        let frame = serde_json::json!({
            "kind": "canonical-exec", "request_id": 1, "program": "true", "args": [],
            "toolchain_backing": "/tc", "workspace_backing": "/ws",
            "jobserver_fds": "3,4", "jobserver_auth_fd": 7, "--jobserver-auth": "fifo:/tmp/x",
            "inherited_fds": [3, 4, 5], "descriptor_socket": "/tmp/ancillary.sock"
        });
        let CanonicalExecRequest {
            request_id, program, args, toolchain_backing, workspace_backing, jobserver_grant,
        } = parse_exec_request(&frame).expect("parses");
        assert_eq!(request_id, 1);
        assert_eq!(program, "true");
        assert!(args.is_empty());
        assert_eq!(toolchain_backing, "/tc");
        assert_eq!(workspace_backing, "/ws");
        assert_eq!(jobserver_grant, None);
    }

    #[test]
    fn i003_grant_field_is_the_only_capacity_channel() {
        let mut frame = request(2);
        frame["jobserver_grant"] = serde_json::json!(65536);
        assert_eq!(parse_exec_request(&frame).unwrap().jobserver_grant, Some(65536));
        frame["jobserver_grant"] = serde_json::json!(4294967296_u64);
        assert_eq!(parse_exec_request(&frame).unwrap().jobserver_grant, Some(u32::MAX));
    }

    fn request(id: u64) -> serde_json::Value {
        serde_json::json!({
            "kind": "canonical-exec", "request_id": id, "program": "true", "args": [],
            "toolchain_backing": "/tc", "workspace_backing": "/ws"
        })
    }

    #[test]
    fn budgets_only_shorten_and_malformed_commands_are_never_rewritten() {
        assert_eq!(parse_timeout(&request(1)).unwrap(), DEFAULT_EXECUTION_TIMEOUT);
        let mut frame = request(1);
        frame["timeout_ms"] = serde_json::json!(25);
        assert_eq!(parse_timeout(&frame).unwrap(), Duration::from_millis(25));
        frame["timeout_ms"] = serde_json::json!(u64::MAX);
        assert_eq!(parse_timeout(&frame).unwrap(), DEFAULT_EXECUTION_TIMEOUT);
        for bad in [serde_json::json!(0), serde_json::json!(-1), serde_json::json!("10"), serde_json::Value::Null] {
            frame["timeout_ms"] = bad;
            assert!(parse_timeout(&frame).is_err());
        }
        for bad in [serde_json::json!(["safe", 17, "arg"]), serde_json::json!("arg"), serde_json::json!(["\u{0000}"])] {
            frame["args"] = bad;
            assert!(parse_exec_request(&frame).is_err());
        }
    }
}
