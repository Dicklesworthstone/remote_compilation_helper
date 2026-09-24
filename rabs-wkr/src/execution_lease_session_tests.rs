//! Lease integration through the production control-session driver, durable
//! journal, owned execution thread and real managed Linux process group.
//! The byte-fragmenting peer replaces transport only; the injected launcher runs
//! a shell child without claiming TLS or canonical-namespace coverage.
#![cfg(target_os = "linux")]

use super::*;
use asupersync::io::ReadBuf;
use rabs_asupersync::process_groups::ManagedProcessGroup;
use rabs_asupersync::region_tree::Attribution;
use rabs_asupersync::stream_drain::DrainLimits;
use serde_json::{Value, json};
use std::path::Path;
use std::pin::Pin;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Wake, Waker};
use std::time::Instant;

const SESSION: u64 = 71;
const LEASE: u64 = 81;
const REQUEST: u64 = 91;
const TTL_MS: u64 = rabs_protocol::lease_semantics::MIN_TTL_MS;
const STDOUT: &[u8] = b"alive\0\xff\n";
const STDERR: &[u8] = b"error\0\xff\n";

#[derive(Default)]
struct WireState {
    input: VecDeque<u8>,
    output: Vec<u8>,
    eof: bool,
    block_writes: bool,
    reader: Option<Waker>,
    writer: Option<Waker>,
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

    fn block_writes(&self, blocked: bool) {
        let wake = {
            let mut state = self.0.lock().unwrap();
            state.block_writes = blocked;
            state.writer.take()
        };
        if let Some(wake) = wake {
            wake.wake();
        }
    }

    fn replies(&self) -> Vec<Value> {
        let state = self.0.lock().unwrap();
        state
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
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut state = self.0.lock().unwrap();
        if state.block_writes {
            state.writer = Some(cx.waker().clone());
            return Poll::Pending;
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

fn pump_until<F: Future>(mut driver: Pin<&mut F>, mut ready: impl FnMut() -> bool) {
    let waker = Waker::from(Arc::new(ThreadWake(std::thread::current())));
    let mut cx = Context::from_waker(&waker);
    let until = Instant::now() + Duration::from_secs(6);
    loop {
        assert!(
            driver.as_mut().poll(&mut cx).is_pending(),
            "session exited before its retained delivery was observed"
        );
        if ready() {
            return;
        }
        assert!(
            Instant::now() < until,
            "lease session did not make bounded progress"
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
        if let Poll::Ready(value) = future.as_mut().poll(&mut cx) {
            return value;
        }
        assert!(Instant::now() < until, "lease session cleanup timed out");
        std::thread::park_timeout(Duration::from_millis(5));
    }
}

fn report() -> rabs_wkr::session::CapabilityReport {
    // Admission is already selected for these driver tests. The launcher below
    // deliberately tests managed process ownership, not host isolation support.
    rabs_wkr::session::CapabilityReport {
        worker_id: "lease-session-test".into(),
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
        "program":"managed-lease-fixture", "args":[], "timeout_ms":15000,
        "toolchain_backing":"/fixture-toolchain", "workspace_backing":"/fixture-workspace"})
}

fn grant_frame(journal: &WorkerJournal, request: &Value) -> Value {
    json!({"kind":"session-ok", "session_id":SESSION, "execution_lease":{
        "version":REQUEST_EXECUTION_LEASE_VERSION,
        "session_id":SESSION, "lease_id":LEASE, "request_id":request["request_id"],
        "request_sha256":rabs_wkr::session::sha256_hex(&serde_json::to_vec(request).unwrap()),
        "boot_generation":journal.boot_generation().0,
        "incarnation":format!("{:032x}", journal.incarnation().0), "ttl_ms":TTL_MS}})
}

fn selection(journal: &WorkerJournal, request: &Value) -> ExecutionLeaseSelection {
    execution_lease_selection(
        &grant_frame(journal, request).to_string(),
        true,
        Some(SESSION),
        journal,
    )
    .unwrap()
}

fn renewal(sequence: u64) -> Value {
    json!({"kind":"execution-lease-renew", "session_id":SESSION,
        "lease_id":LEASE, "request_id":REQUEST, "renewal_seq":sequence})
}

#[derive(Clone, Default)]
struct ChildEvidence {
    launches: Arc<AtomicUsize>,
    started: Arc<AtomicBool>,
    cleaned: Arc<AtomicBool>,
}

fn launch(
    root: &Path,
    request: CanonicalExecRequest,
    timeout: Duration,
    artifacts: Option<ArtifactPlan>,
    source: Option<SourceOwner>,
    lease: Option<(RequestExecutionLeaseIdentity, u64)>,
    evidence: ChildEvidence,
) -> io::Result<ExecutionTask> {
    assert!(artifacts.is_none() && source.is_none());
    assert!(
        lease.is_some(),
        "the production driver omitted its negotiated lease"
    );
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
            let mut command = Command::new("/bin/sh");
            command
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .args([
                    "-c",
                    r"printf 'alive\000\377\n'; printf 'error\000\377\n' >&2; exec sleep 30",
                ])
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            let group =
                ManagedProcessGroup::spawn_command(command, Attribution::default()).unwrap();
            evidence.started.store(true, Ordering::Release);
            let drained = group
                .wait_with_bounded_drain_budget(
                    &DrainLimits {
                        resident_bound: 1024,
                        spill_dir: root.join("spill"),
                    },
                    4096,
                    || control.reason().is_some(),
                )
                .unwrap();
            assert_eq!(
                drained.residual_group_members, 0,
                "lease expiry left a live process descendant"
            );
            let outputs = CapturedOutputs::from_lanes(&drained.stdout, &drained.stderr).unwrap();
            let result = rabs_wkr::session::ExecResult {
                request_id: request.request_id,
                exit_code: drained.status.code().unwrap_or(125),
                stdout_sha256: outputs.stdout.sha256().to_owned(),
                stderr_sha256: outputs.stderr.sha256().to_owned(),
                executed: true,
                residual_group_members: drained.residual_group_members,
                stdout_spill_bytes: 0,
                stderr_spill_bytes: 0,
                stdout_spill_path: None,
                stderr_spill_path: None,
            };
            control.retain_outputs(Ok(outputs)).unwrap();
            evidence.cleaned.store(true, Ordering::Release);
            result
        },
    )
}

fn terminal(peer: &Wire) -> Option<Value> {
    peer.replies()
        .into_iter()
        .find(|frame| frame["kind"] == "exec-result")
}

#[test]
fn lease_selection_checks_session_boot_bounds_and_exact_shape() {
    let root = tempfile::tempdir().unwrap();
    let journal = WorkerJournal::open(root.path(), "lease-session-test", "coordinator").unwrap();
    let original = grant_frame(&journal, &request());
    selection(&journal, &request());
    let mut zero = request();
    zero["request_id"] = json!(0);
    assert_eq!(
        selection(&journal, &zero)
            .execution_grant(&zero)
            .unwrap()
            .unwrap()
            .0
            .request_id,
        0
    );
    let mut invalid = Vec::new();
    for (field, value) in [
        ("version", json!("request-renewal-v2")),
        ("session_id", json!(SESSION + 1)),
        ("lease_id", json!(0)),
        ("request_sha256", json!("00".repeat(32))),
        ("boot_generation", json!(journal.boot_generation().0 + 1)),
        ("incarnation", json!("00".repeat(16))),
        ("ttl_ms", json!(TTL_MS - 1)),
    ] {
        let mut changed = original.clone();
        changed["execution_lease"][field] = value;
        invalid.push(changed);
    }
    let mut extra = original.clone();
    extra["execution_lease"]["unknown"] = json!(true);
    invalid.push(extra);
    for frame in invalid {
        assert!(
            execution_lease_selection(&frame.to_string(), true, Some(SESSION), &journal).is_err(),
            "accepted {frame}"
        );
    }
    assert!(
        execution_lease_selection(&original.to_string(), true, Some(SESSION + 1), &journal)
            .is_err()
    );
    assert_eq!(journal.high_water(), None);
}

#[test]
fn mismatched_request_and_missing_authenticated_lease_never_reach_journal_admission() {
    for missing_lease in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let mut journal =
            WorkerJournal::open(root.path(), "lease-session-test", "coordinator").unwrap();
        let before = std::fs::read(root.path().join("requests.json")).unwrap();
        let original = request();
        let selected = if missing_lease {
            execution_lease_selection(
                &json!({"kind":"session-ok", "session_id":SESSION}).to_string(),
                true,
                Some(SESSION),
                &journal,
            )
            .unwrap()
        } else {
            selection(&journal, &original)
        };
        let mut wire = Wire::default();
        let peer = wire.clone();
        let mut changed = original;
        if !missing_lease {
            changed["args"] = json!(["another-execution"]);
        }
        peer.frame(changed);
        peer.close();
        wait(drive_session_with_sources(
            &mut wire,
            &report(),
            false,
            Some(&mut journal),
            false,
            false,
            &selected,
            |_, _, _, _, _| panic!("unbound command reached execution"),
            pressure,
        ))
        .unwrap();
        let replies = peer.replies();
        assert_eq!(replies.len(), 1);
        assert_eq!(replies[0]["kind"], "error");
        assert!(
            replies[0]["reason"]
                .as_str()
                .unwrap()
                .contains(if missing_lease {
                    "requires request-renewal-v1"
                } else {
                    "exact request"
                })
        );
        assert_eq!(journal.high_water(), None);
        assert_eq!(
            std::fs::read(root.path().join("requests.json")).unwrap(),
            before
        );
    }
}

#[test]
fn valid_renewals_keep_the_real_child_alive_and_foreign_or_replayed_renewals_refuse() {
    let root = tempfile::tempdir().unwrap();
    let mut journal =
        WorkerJournal::open(root.path(), "lease-session-test", "coordinator").unwrap();
    let selected = selection(&journal, &request());
    let evidence = ChildEvidence::default();
    let mut wire = Wire::default();
    let peer = wire.clone();
    peer.frame(request());
    let report = report();
    let mut driver = Box::pin(drive_session_with_sources(
        &mut wire,
        &report,
        false,
        Some(&mut journal),
        false,
        false,
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
            )
        },
        pressure,
    ));
    pump_until(driver.as_mut(), || evidence.started.load(Ordering::Acquire));
    peer.frame(renewal(1));
    pump_until(driver.as_mut(), || peer.replies().len() == 1);
    assert_eq!(peer.replies()[0]["accepted"], true);
    let mut refusals = vec![renewal(1)];
    for (field, value) in [
        ("session_id", SESSION + 1),
        ("lease_id", LEASE + 1),
        ("request_id", REQUEST + 1),
    ] {
        let mut wrong = renewal(2);
        wrong[field] = json!(value);
        refusals.push(wrong);
    }
    for refused in refusals {
        peer.frame(refused);
    }
    pump_until(driver.as_mut(), || peer.replies().len() == 5);
    assert!(
        peer.replies()[1..]
            .iter()
            .all(|reply| reply["kind"] == "execution-lease-renewed" && reply["accepted"] == false)
    );
    let started = Instant::now();
    let mut sequence = 1;
    while started.elapsed() <= Duration::from_millis(TTL_MS * 2) {
        std::thread::sleep(Duration::from_millis(100));
        sequence += 1;
        let count = peer.replies().len();
        peer.frame(renewal(sequence));
        pump_until(driver.as_mut(), || peer.replies().len() > count);
        let replies = peer.replies();
        assert_eq!(replies.last().unwrap()["renewal_seq"], sequence);
        assert_eq!(replies.last().unwrap()["accepted"], true);
        assert!(!evidence.cleaned.load(Ordering::Acquire));
        assert!(terminal(&peer).is_none());
    }
    peer.frame(json!({"kind":"cancel", "request_id":REQUEST}));
    pump_until(driver.as_mut(), || terminal(&peer).is_some());
    assert_eq!(terminal(&peer).unwrap()["stop_reason"], "cancelled");
    assert!(evidence.cleaned.load(Ordering::Acquire));
    assert_eq!(evidence.launches.load(Ordering::SeqCst), 1);
    peer.close();
    wait(driver).unwrap();
}

#[test]
fn silent_connection_expires_drains_and_recovers_the_retained_result_without_rerun() {
    let root = tempfile::tempdir().unwrap();
    let original = request();
    let mut journal =
        WorkerJournal::open(root.path(), "lease-session-test", "coordinator").unwrap();
    let selected = selection(&journal, &original);
    let evidence = ChildEvidence::default();
    let mut wire = Wire::default();
    let peer = wire.clone();
    peer.frame(original.clone());
    let report = report();
    let mut driver = Box::pin(drive_session_with_sources(
        &mut wire,
        &report,
        false,
        Some(&mut journal),
        false,
        false,
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
            )
        },
        pressure,
    ));
    pump_until(driver.as_mut(), || terminal(&peer).is_some());
    let expired = terminal(&peer).unwrap();
    assert_eq!(expired["stop_reason"], "lease-expired");
    assert_eq!(expired["exit_code"], 125);
    assert_eq!(expired["residual_group_members"], 0);
    assert!(evidence.cleaned.load(Ordering::Acquire));
    peer.frame(renewal(1));
    pump_until(driver.as_mut(), || peer.replies().len() == 2);
    assert_eq!(peer.replies()[1]["accepted"], false);
    peer.close();
    wait(driver).unwrap();
    let digest = journal.status(REQUEST)["receipt"]["retained_result_sha256"].clone();
    assert!(digest.as_str().is_some_and(|digest| digest.len() == 64));
    drop(journal);

    let mut journal =
        WorkerJournal::open(root.path(), "lease-session-test", "coordinator").unwrap();
    journal.authorize_result_recipient(ResultRecipient::TlsSpki([7; 32]));
    let selected = selection(&journal, &original);
    let mut wire = Wire::default();
    let peer = wire.clone();
    peer.frame(original.clone());
    peer.frame(json!({"kind":"result-resume", "request_id":REQUEST, "request":original}));
    let mut driver = Box::pin(drive_session_with_sources(
        &mut wire,
        &report,
        false,
        Some(&mut journal),
        false,
        false,
        &selected,
        |_, _, _, _, _| panic!("lease-expired result was executed again"),
        pressure,
    ));
    pump_until(driver.as_mut(), || peer.replies().len() == 2);
    let replies = peer.replies();
    assert_eq!(replies[0]["reason"], "durable-request-already-admitted");
    assert_eq!(replies[1]["kind"], "exec-result");
    assert_eq!(replies[1]["resumed"], true);
    assert_eq!(replies[1]["stop_reason"], "lease-expired");
    assert_eq!(replies[1]["exit_code"], 125);
    assert_eq!(replies[1]["retained_result_sha256"], digest);
    for name in ["stdout", "stderr"] {
        peer.frame(json!({"kind":"output-read", "request_id":REQUEST, "stream":name, "offset":0, "max_bytes":64}));
    }
    pump_until(driver.as_mut(), || peer.replies().len() == 4);
    let replies = peer.replies();
    let hex = |bytes: &[u8]| {
        bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    assert_eq!(replies[2]["data_hex"], hex(STDOUT));
    assert_eq!(replies[3]["data_hex"], hex(STDERR));
    assert_eq!(evidence.launches.load(Ordering::SeqCst), 1);
    peer.close();
    wait(driver).unwrap();
}

#[test]
fn blocked_renewal_reply_cannot_prevent_worker_local_expiry_and_process_cleanup() {
    let root = tempfile::tempdir().unwrap();
    let mut journal =
        WorkerJournal::open(root.path(), "lease-session-test", "coordinator").unwrap();
    let selected = selection(&journal, &request());
    let evidence = ChildEvidence::default();
    let mut wire = Wire::default();
    let peer = wire.clone();
    peer.frame(request());
    let report = report();
    let mut driver = Box::pin(drive_session_with_sources(
        &mut wire,
        &report,
        false,
        Some(&mut journal),
        false,
        false,
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
            )
        },
        pressure,
    ));
    pump_until(driver.as_mut(), || evidence.started.load(Ordering::Acquire));
    peer.block_writes(true);
    peer.frame(renewal(1));
    pump_until(driver.as_mut(), || peer.0.lock().unwrap().writer.is_some());
    pump_until(driver.as_mut(), || evidence.cleaned.load(Ordering::Acquire));
    assert!(
        peer.replies().is_empty(),
        "the fixture did not actually block the renewal reply"
    );
    assert_eq!(evidence.launches.load(Ordering::SeqCst), 1);
    peer.block_writes(false);
    pump_until(driver.as_mut(), || terminal(&peer).is_some());
    assert_eq!(peer.replies()[0]["kind"], "execution-lease-renewed");
    assert_eq!(peer.replies()[0]["accepted"], true);
    assert_eq!(terminal(&peer).unwrap()["stop_reason"], "lease-expired");
    peer.close();
    wait(driver).unwrap();
}

#[test]
fn partial_renewal_survives_completion_cancelling_the_pending_frame_read() {
    let root = tempfile::tempdir().unwrap();
    let mut journal =
        WorkerJournal::open(root.path(), "lease-session-test", "coordinator").unwrap();
    let selected = selection(&journal, &request());
    let evidence = ChildEvidence::default();
    let mut wire = Wire::default();
    let peer = wire.clone();
    peer.frame(request());
    let report = report();
    let mut driver = Box::pin(drive_session_with_sources(
        &mut wire,
        &report,
        false,
        Some(&mut journal),
        false,
        false,
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
            )
        },
        pressure,
    ));
    pump_until(driver.as_mut(), || evidence.started.load(Ordering::Acquire));
    let frame = format!("{}\n", renewal(1));
    let split = frame.len() / 2;
    peer.bytes(&frame.as_bytes()[..split]);
    pump_until(driver.as_mut(), || peer.0.lock().unwrap().input.is_empty());
    pump_until(driver.as_mut(), || terminal(&peer).is_some());
    assert_eq!(terminal(&peer).unwrap()["stop_reason"], "lease-expired");
    peer.bytes(&frame.as_bytes()[split..]);
    peer.frame(json!({"kind":"ping"}));
    pump_until(driver.as_mut(), || peer.replies().len() == 3);
    let replies = peer.replies();
    assert_eq!(replies[1]["kind"], "execution-lease-renewed");
    assert_eq!(replies[1]["request_id"], REQUEST);
    assert_eq!(replies[1]["accepted"], false);
    assert_eq!(replies[2]["kind"], "heartbeat");
    assert_eq!(evidence.launches.load(Ordering::SeqCst), 1);
    assert!(evidence.cleaned.load(Ordering::Acquire));
    peer.close();
    wait(driver).unwrap();
}
