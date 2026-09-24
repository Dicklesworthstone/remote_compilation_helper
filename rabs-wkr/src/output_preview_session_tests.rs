//! Production control-session routing with actual managed Linux children,
//! bounded pipe drains, durable admission, leases and retained diagnostics.
//! Only the transport and canonical namespace launcher are replaced by fixtures.
#![cfg(target_os = "linux")]

use super::*;
use asupersync::io::ReadBuf;
use rabs_asupersync::process_groups::ManagedProcessGroup;
use rabs_asupersync::region_tree::Attribution;
use rabs_asupersync::stream_drain::DrainLimits;
use rabs_asupersync::stream_drain::preview::{LiveOutputPreview, MAX_PREVIEW_BYTES, PreviewStream};
use serde_json::{Value, json};
use std::path::Path;
use std::pin::Pin;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Wake, Waker};
use std::time::Instant;

const REQUEST: u64 = 103;
const SESSION: u64 = 113;
const LEASE: u64 = 123;
const STDOUT: &[u8] = b"out\0\xff";
const STDERR: &[u8] = b"err\0\xfe";

#[derive(Default)]
struct WireState {
    input: VecDeque<u8>,
    output: Vec<u8>,
    eof: bool,
    reader: Option<Waker>,
}

#[derive(Clone, Default)]
struct Wire(Arc<Mutex<WireState>>);

impl Wire {
    fn bytes(&self, bytes: &[u8]) {
        let wake = {
            let mut state = self.0.lock().unwrap();
            state.input.extend(bytes);
            state.reader.take()
        };
        if let Some(wake) = wake {
            wake.wake();
        }
    }

    fn frame(&self, value: Value) {
        self.bytes(format!("{value}\n").as_bytes());
    }

    fn close(&self) {
        let wake = {
            let mut state = self.0.lock().unwrap();
            state.eof = true;
            state.reader.take()
        };
        if let Some(wake) = wake {
            wake.wake();
        }
    }

    fn replies(&self) -> Vec<Value> {
        self.0
            .lock()
            .unwrap()
            .output
            .split_inclusive(|byte| *byte == b'\n')
            .filter(|line| line.last() == Some(&b'\n'))
            .map(|line| serde_json::from_slice(line).unwrap())
            .collect()
    }
}

impl AsyncRead for Wire {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buffer.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let mut state = self.0.lock().unwrap();
        if let Some(byte) = state.input.pop_front() {
            buffer.put_slice(&[byte]);
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
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.0.lock().unwrap().output.extend_from_slice(bytes);
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

fn pump_until<F: Future>(mut driver: Pin<&mut F>, mut ready: impl FnMut() -> bool) {
    let waker = Waker::from(Arc::new(ThreadWake(std::thread::current())));
    let mut cx = Context::from_waker(&waker);
    let until = Instant::now() + Duration::from_secs(6);
    loop {
        assert!(
            driver.as_mut().poll(&mut cx).is_pending(),
            "session ended before observation"
        );
        if ready() {
            return;
        }
        assert!(
            Instant::now() < until,
            "preview session made no bounded progress"
        );
        std::thread::park_timeout(Duration::from_millis(5));
    }
}

fn wait<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    let waker = Waker::from(Arc::new(ThreadWake(std::thread::current())));
    let mut cx = Context::from_waker(&waker);
    let until = Instant::now() + Duration::from_secs(6);
    loop {
        if let Poll::Ready(result) = future.as_mut().poll(&mut cx) {
            return result;
        }
        assert!(Instant::now() < until, "preview session cleanup timed out");
        std::thread::park_timeout(Duration::from_millis(5));
    }
}

fn exchange<F: Future>(mut driver: Pin<&mut F>, peer: &Wire, request: Value) -> Value {
    let before = peer.replies().len();
    peer.frame(request);
    pump_until(driver.as_mut(), || peer.replies().len() > before);
    peer.replies()[before].clone()
}

fn report() -> rabs_wkr::session::CapabilityReport {
    rabs_wkr::session::CapabilityReport {
        worker_id: "preview-session-test".into(),
        canonical_namespace: true,
        missing: vec![],
        slots: 1,
    }
}

fn pressure() -> rabs_wkr::session::PressureSample {
    rabs_wkr::session::PressureSample {
        load_x100: 0,
        free_disk_mib: 100,
    }
}

fn request() -> Value {
    json!({"kind":"canonical-exec", "request_id":REQUEST,
        "program":"managed-preview-fixture", "args":[], "timeout_ms":15000,
        "toolchain_backing":"/fixture-toolchain", "workspace_backing":"/fixture-workspace"})
}

fn selection(journal: &WorkerJournal, ttl_ms: u64) -> ExecutionLeaseSelection {
    let request = request();
    let grant = json!({"kind":"session-ok", "session_id":SESSION, "execution_lease":{
        "version":REQUEST_EXECUTION_LEASE_VERSION, "session_id":SESSION, "lease_id":LEASE,
        "request_id":REQUEST, "request_sha256":rabs_wkr::session::sha256_hex(&serde_json::to_vec(&request).unwrap()),
        "boot_generation":journal.boot_generation().0,
        "incarnation":format!("{:032x}", journal.incarnation().0), "ttl_ms":ttl_ms}});
    execution_lease_selection(&grant.to_string(), true, Some(SESSION), journal).unwrap()
}

fn query(id: u64) -> Value {
    json!({"kind":"output-preview", "request_id":id})
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[derive(Clone, Copy)]
enum Workload {
    LiveUntilGate,
    UntilCancelled,
    LargeCapture,
}

#[derive(Clone, Default)]
struct Evidence {
    launches: Arc<AtomicUsize>,
    started: Arc<AtomicBool>,
    capture_ready: Arc<AtomicBool>,
    allow_completion: Arc<AtomicBool>,
    observer: Arc<Mutex<Option<Arc<LiveOutputPreview>>>>,
}

#[allow(clippy::too_many_arguments)]
fn launch(
    root: &Path,
    request: CanonicalExecRequest,
    timeout: Duration,
    artifacts: Option<ArtifactPlan>,
    source: Option<SourceOwner>,
    lease: Option<(RequestExecutionLeaseIdentity, u64)>,
    evidence: Evidence,
    workload: Workload,
) -> io::Result<ExecutionTask> {
    assert!(artifacts.is_none() && source.is_none() && lease.is_some());
    evidence.launches.fetch_add(1, Ordering::SeqCst);
    let root = root.to_path_buf();
    let retention = RetentionTarget::from_admitted(
        &root,
        request.request_id,
        ResultRecipient::TlsSpki([7; 32]),
    )?;
    ExecutionTask::spawn_for_delivery_with_lease(
        request.request_id,
        timeout,
        None,
        Some(retention),
        lease,
        move |control| {
            let observer = control.output_observer();
            *evidence.observer.lock().unwrap() = Some(Arc::clone(&observer));
            let script = match workload {
                Workload::LiveUntilGate => {
                    r#"printf 'out\000\377'; printf 'err\000\376' >&2; while [ ! -e "$GATE" ]; do sleep 0.01; done; printf tail"#
                }
                Workload::UntilCancelled => {
                    r"printf 'out\000\377'; printf 'err\000\376' >&2; exec sleep 30"
                }
                Workload::LargeCapture => r#"cat "$PAYLOAD"; printf 'err\000\376' >&2"#,
            };
            let mut command = Command::new("/bin/sh");
            command
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .env("GATE", root.join("continue"))
                .env("PAYLOAD", root.join("payload"))
                .args(["-c", script])
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            let group =
                ManagedProcessGroup::spawn_command(command, Attribution::default()).unwrap();
            evidence.started.store(true, Ordering::Release);
            let drained = group
                .wait_with_bounded_drain_preview(
                    &DrainLimits {
                        resident_bound: 2,
                        spill_dir: root.join("spill"),
                    },
                    128 * 1024,
                    Some(observer),
                    || control.reason().is_some(),
                )
                .unwrap();
            assert_eq!(
                drained.residual_group_members, 0,
                "preview handling left a live process"
            );
            let outputs = CapturedOutputs::from_lanes(&drained.stdout, &drained.stderr).unwrap();
            let result = rabs_wkr::session::ExecResult {
                request_id: request.request_id,
                exit_code: drained.status.code().unwrap_or(125),
                stdout_sha256: outputs.stdout.sha256().to_owned(),
                stderr_sha256: outputs.stderr.sha256().to_owned(),
                executed: true,
                residual_group_members: drained.residual_group_members,
                stdout_spill_bytes: drained.stdout.spilled_bytes(),
                stderr_spill_bytes: drained.stderr.spilled_bytes(),
                stdout_spill_path: drained
                    .stdout
                    .spill()
                    .map(|spill| spill.path.display().to_string()),
                stderr_spill_path: drained
                    .stderr
                    .spill()
                    .map(|spill| spill.path.display().to_string()),
            };
            evidence.capture_ready.store(true, Ordering::Release);
            // The large capture is completely drained before queries are allowed.
            // Keep the real execution owner active to make tail offsets deterministic
            // without assuming a sleeping test thread means a pipe has drained.
            while matches!(workload, Workload::LargeCapture)
                && !evidence.allow_completion.load(Ordering::Acquire)
                && control.reason().is_none()
            {
                std::thread::sleep(Duration::from_millis(1));
            }
            control.retain_outputs(Ok(outputs)).unwrap();
            result
        },
    )
}

fn terminal(peer: &Wire) -> Option<Value> {
    peer.replies()
        .into_iter()
        .find(|frame| frame["kind"] == "exec-result")
}

fn assert_observation(reply: &Value, active: bool) {
    assert_eq!(reply["kind"], "output-preview");
    assert_eq!(reply["version"], "tail-v1");
    assert_eq!(reply["request_id"], REQUEST);
    assert_eq!(reply["active"], active);
    assert_eq!(reply["complete"], false);
    assert_eq!(reply["publication_authorized"], false);
    assert!(reply.get("exit_code").is_none() && reply.get("retained_result_sha256").is_none());
}

fn collect_prefix<F: Future>(mut driver: Pin<&mut F>, peer: &Wire) {
    let until = Instant::now() + Duration::from_secs(3);
    let (mut stdout, mut stderr) = (String::new(), String::new());
    while stdout != hex(STDOUT) || stderr != hex(STDERR) {
        let reply = exchange(driver.as_mut(), peer, query(REQUEST));
        assert_observation(&reply, true);
        for segment in reply["segments"].as_array().unwrap() {
            let lane = match segment["stream"].as_str().unwrap() {
                "stdout" => &mut stdout,
                "stderr" => &mut stderr,
                _ => panic!("unknown preview stream"),
            };
            assert_eq!(segment["offset"], lane.len() / 2);
            assert_eq!(segment["skipped_bytes"], 0);
            lane.push_str(segment["data_hex"].as_str().unwrap());
        }
        assert!(
            Instant::now() < until,
            "live binary preview was missing or consumed by a refused query"
        );
    }
    assert!(terminal(peer).is_none());
}

fn assert_full_outputs<F: Future>(
    mut driver: Pin<&mut F>,
    peer: &Wire,
    stdout: &[u8],
    stderr: &[u8],
) {
    let completed = terminal(peer).unwrap();
    assert!(
        completed["retained_result_sha256"]
            .as_str()
            .is_some_and(|digest| digest.len() == 64)
    );
    for (stream, bytes) in [("stdout", stdout), ("stderr", stderr)] {
        let reply = exchange(
            driver.as_mut(),
            peer,
            json!({"kind":"output-read", "request_id":REQUEST,
            "stream":stream, "offset":0, "max_bytes":65536}),
        );
        assert_eq!(reply["kind"], "output-chunk");
        assert_eq!(reply["request_id"], REQUEST);
        assert_eq!(reply["stream"], stream);
        assert_eq!(reply["data_hex"], hex(bytes));
        assert_eq!(reply["total_bytes"], bytes.len());
        assert_eq!(reply["eof"], true);
        let digest = rabs_wkr::session::sha256_hex(bytes);
        assert_eq!(reply["sha256"], digest);
        assert_eq!(reply["chunk_sha256"], digest);
        assert_eq!(completed[format!("{stream}_sha256")], digest);
    }
}

#[test]
fn live_preview_refusals_preserve_bytes_and_partial_query_survives_terminal_race() {
    let root = tempfile::tempdir().unwrap();
    let mut journal =
        WorkerJournal::open(root.path(), "preview-session-test", "coordinator").unwrap();
    let selected = selection(&journal, 5000);
    let evidence = Evidence::default();
    let report = report();
    let mut wire = Wire::default();
    let peer = wire.clone();
    peer.frame(request());
    let mut driver = Box::pin(drive_session_with_previews(
        &mut wire,
        &report,
        false,
        Some(&mut journal),
        false,
        false,
        true,
        &selected,
        |request, timeout, artifacts, source, lease| {
            launch(
                root.path(),
                request,
                timeout,
                artifacts,
                source,
                lease,
                evidence.clone(),
                Workload::LiveUntilGate,
            )
        },
        pressure,
    ));
    pump_until(driver.as_mut(), || evidence.started.load(Ordering::Acquire));
    for refused in [
        query(REQUEST + 1),
        json!({"kind":"output-preview", "request_id":REQUEST, "path":"/private"}),
        json!({"kind":"output-preview", "request_id":REQUEST.to_string()}),
    ] {
        assert_eq!(exchange(driver.as_mut(), &peer, refused)["kind"], "error");
    }
    collect_prefix(driver.as_mut(), &peer);
    assert!(
        !evidence.capture_ready.load(Ordering::Acquire),
        "preview arrived only after child exit"
    );
    let partial = format!("{}\n", query(REQUEST));
    let split = partial.len() / 2;
    peer.bytes(&partial.as_bytes()[..split]);
    pump_until(driver.as_mut(), || peer.0.lock().unwrap().input.is_empty());
    std::fs::write(root.path().join("continue"), b"go").unwrap();
    pump_until(driver.as_mut(), || terminal(&peer).is_some());
    assert_eq!(terminal(&peer).unwrap()["exit_code"], 0);
    assert!(evidence.capture_ready.load(Ordering::Acquire));
    let count = peer.replies().len();
    peer.bytes(&partial.as_bytes()[split..]);
    pump_until(driver.as_mut(), || peer.replies().len() > count);
    let inactive = &peer.replies()[count];
    assert_observation(inactive, false);
    assert_eq!(inactive["segments"], json!([]));
    let stdout = [STDOUT, b"tail"].concat();
    assert_full_outputs(driver.as_mut(), &peer, &stdout, STDERR);
    assert_eq!(evidence.launches.load(Ordering::SeqCst), 1);
    peer.close();
    wait(driver).unwrap();
    assert_eq!(journal.high_water(), Some(REQUEST));
}

#[test]
fn negotiation_gates_consumption_and_real_capture_reports_exact_bounded_tail_gaps() {
    let payload: Vec<_> = (0..MAX_PREVIEW_BYTES * 3 + 19)
        .map(|index| (index % 256) as u8)
        .collect();
    for enabled in [false, true] {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("payload"), &payload).unwrap();
        let mut journal =
            WorkerJournal::open(root.path(), "preview-session-test", "coordinator").unwrap();
        let selected = selection(&journal, 5000);
        let evidence = Evidence::default();
        let report = report();
        let mut wire = Wire::default();
        let peer = wire.clone();
        peer.frame(request());
        let mut driver = Box::pin(drive_session_with_previews(
            &mut wire,
            &report,
            false,
            Some(&mut journal),
            false,
            false,
            enabled,
            &selected,
            |request, timeout, artifacts, source, lease| {
                launch(
                    root.path(),
                    request,
                    timeout,
                    artifacts,
                    source,
                    lease,
                    evidence.clone(),
                    Workload::LargeCapture,
                )
            },
            pressure,
        ));
        pump_until(driver.as_mut(), || {
            evidence.capture_ready.load(Ordering::Acquire)
        });
        assert!(terminal(&peer).is_none());
        if enabled {
            // Every byte is already observed here, so these refusals must
            // preserve the cursor even when there is a full tail to consume.
            for refused in [
                query(REQUEST + 1),
                json!({"kind":"output-preview", "request_id":REQUEST, "path":"/private"}),
            ] {
                assert_eq!(exchange(driver.as_mut(), &peer, refused)["kind"], "error");
            }
        }
        let reply = exchange(driver.as_mut(), &peer, query(REQUEST));
        let skipped = payload.len() - MAX_PREVIEW_BYTES;
        if enabled {
            assert_observation(&reply, true);
            let segments = reply["segments"].as_array().unwrap();
            assert_eq!(segments.len(), 2);
            let stdout = segments
                .iter()
                .find(|segment| segment["stream"] == "stdout")
                .unwrap();
            assert_eq!(stdout["offset"], skipped);
            assert_eq!(stdout["skipped_bytes"], skipped);
            assert_eq!(stdout["observed_bytes"], payload.len());
            assert_eq!(stdout["data_hex"], hex(&payload[skipped..]));
            assert!(serde_json::to_vec(&reply).unwrap().len() < 36 * 1024);
            assert_eq!(
                exchange(driver.as_mut(), &peer, query(REQUEST))["segments"],
                json!([])
            );
        } else {
            assert_eq!(reply["kind"], "error");
            assert_eq!(reply["reason"], "output preview not negotiated");
            let observer = evidence.observer.lock().unwrap().as_ref().unwrap().clone();
            let stdout = observer.take(PreviewStream::Stdout).unwrap();
            assert_eq!(stdout.offset, skipped as u64);
            assert_eq!(stdout.skipped_bytes, skipped as u64);
            assert_eq!(stdout.bytes, payload[skipped..]);
            assert_eq!(observer.take(PreviewStream::Stderr).unwrap().bytes, STDERR);
        }
        evidence.allow_completion.store(true, Ordering::Release);
        pump_until(driver.as_mut(), || terminal(&peer).is_some());
        assert_eq!(terminal(&peer).unwrap()["exit_code"], 0);
        assert_full_outputs(driver.as_mut(), &peer, &payload, STDERR);
        assert_eq!(evidence.launches.load(Ordering::SeqCst), 1);
        peer.close();
        wait(driver).unwrap();
    }
}

#[test]
fn preview_polling_preserves_lease_renewal_and_cancellation_with_complete_diagnostics() {
    let root = tempfile::tempdir().unwrap();
    let mut journal =
        WorkerJournal::open(root.path(), "preview-session-test", "coordinator").unwrap();
    let ttl_ms = rabs_protocol::lease_semantics::MIN_TTL_MS;
    let selected = selection(&journal, ttl_ms);
    let evidence = Evidence::default();
    let report = report();
    let mut wire = Wire::default();
    let peer = wire.clone();
    peer.frame(request());
    let mut driver = Box::pin(drive_session_with_previews(
        &mut wire,
        &report,
        false,
        Some(&mut journal),
        false,
        false,
        true,
        &selected,
        |request, timeout, artifacts, source, lease| {
            launch(
                root.path(),
                request,
                timeout,
                artifacts,
                source,
                lease,
                evidence.clone(),
                Workload::UntilCancelled,
            )
        },
        pressure,
    ));
    pump_until(driver.as_mut(), || evidence.started.load(Ordering::Acquire));
    collect_prefix(driver.as_mut(), &peer);
    let started = Instant::now();
    let mut sequence = 0_u64;
    while started.elapsed() <= Duration::from_millis(ttl_ms * 2) {
        sequence += 1;
        let renewal = exchange(
            driver.as_mut(),
            &peer,
            json!({"kind":"execution-lease-renew",
            "session_id":SESSION, "lease_id":LEASE, "request_id":REQUEST, "renewal_seq":sequence}),
        );
        assert_eq!(renewal["kind"], "execution-lease-renewed");
        assert_eq!(renewal["accepted"], true);
        assert_eq!(renewal["renewal_seq"], sequence);
        assert_observation(&exchange(driver.as_mut(), &peer, query(REQUEST)), true);
        assert!(!evidence.capture_ready.load(Ordering::Acquire));
        assert!(terminal(&peer).is_none());
        std::thread::sleep(Duration::from_millis(100));
    }
    let cancel = exchange(
        driver.as_mut(),
        &peer,
        json!({"kind":"cancel", "request_id":REQUEST}),
    );
    assert_eq!(cancel["kind"], "cancel-accepted");
    assert_eq!(cancel["accepted"], true);
    assert_eq!(cancel["cleanup_pending"], true);
    pump_until(driver.as_mut(), || terminal(&peer).is_some());
    let completed = terminal(&peer).unwrap();
    assert_eq!(completed["stop_reason"], "cancelled");
    assert_eq!(completed["exit_code"], 130);
    assert_eq!(completed["residual_group_members"], 0);
    assert!(evidence.capture_ready.load(Ordering::Acquire));
    assert_full_outputs(driver.as_mut(), &peer, STDOUT, STDERR);
    assert_eq!(evidence.launches.load(Ordering::SeqCst), 1);
    peer.close();
    wait(driver).unwrap();
}
