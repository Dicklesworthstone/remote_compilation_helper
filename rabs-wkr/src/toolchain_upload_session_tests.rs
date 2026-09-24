//! Uploaded toolchains through the production session driver and shared receiver.
//! The fragmenting peer supplies transport bytes only. The execution fixture runs
//! an actual uploaded shell script under a managed Linux process group; it does
//! not claim TLS authentication or canonical namespace qualification.
#![cfg(target_os = "linux")]

use super::*;
use asupersync::io::ReadBuf;
use rabs_asupersync::process_groups::ManagedProcessGroup;
use rabs_asupersync::region_tree::Attribution;
use rabs_asupersync::stream_drain::DrainLimits;
use rabs_sandbox::source_transfer::{SourceFile, SourceManifest};
use rabs_sandbox::toolchain_dataset::{
    TOOLCHAIN_DATASET_VERSION, ToolchainIdentity, ToolchainLimits, fingerprint_toolchain,
};
use rabs_sandbox::toolchain_transfer::TOOLCHAIN_TRANSFER_VERSION;
use rabs_wkr::toolchain_transfer::{ToolchainOwner, ToolchainTransferTask};
use serde_json::{Value, json};
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::Path;
use std::pin::Pin;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Wake, Waker};
use std::time::Instant;

const REQUEST: u64 = 117;
const SESSION: u64 = 118;
const LEASE: u64 = 119;
const SOURCE: &[u8] = b"fn main() {}\n";
const BINARY: &[u8] = b"toolchain input\0\xff\n";
const STDERR: &[u8] = b"compiler diagnostic\0\xfe\n";
const SCRIPT: &[u8] = br#"#!/bin/sh
set -eu
test -d "$TOOLCHAIN/empty"
test ! -s "$TOOLCHAIN/lib/empty"
cat "$TOOLCHAIN/data-link"
printf 'compiler diagnostic\000\376\n' >&2
while [ ! -e "$GATE" ]; do sleep 0.01; done
cat "$TOOLCHAIN/lib/binary"
"#;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

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
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut state = self.0.lock().unwrap();
        if state.block_writes {
            state.writer = Some(cx.waker().clone());
            return Poll::Pending;
        }
        // Fragment both directions, including replies large enough to cross
        // several writes, to exercise the real newline framing loop.
        let len = bytes.len().min(7);
        state.output.extend_from_slice(&bytes[..len]);
        Poll::Ready(Ok(len))
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
    let until = Instant::now() + Duration::from_secs(8);
    loop {
        assert!(
            driver.as_mut().poll(&mut cx).is_pending(),
            "toolchain session exited before observation"
        );
        if ready() {
            return;
        }
        assert!(Instant::now() < until, "toolchain session made no progress");
        std::thread::park_timeout(Duration::from_millis(5));
    }
}

fn wait<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    let waker = Waker::from(Arc::new(ThreadWake(std::thread::current())));
    let mut cx = Context::from_waker(&waker);
    let until = Instant::now() + Duration::from_secs(8);
    loop {
        if let Poll::Ready(value) = future.as_mut().poll(&mut cx) {
            return value;
        }
        assert!(
            Instant::now() < until,
            "toolchain session cleanup timed out"
        );
        std::thread::park_timeout(Duration::from_millis(5));
    }
}

fn exchange<F: Future>(mut driver: Pin<&mut F>, peer: &Wire, frame: Value) -> Value {
    let before = peer.replies().len();
    peer.frame(frame);
    pump_until(driver.as_mut(), || peer.replies().len() > before);
    peer.replies()[before].clone()
}

fn report() -> rabs_wkr::session::CapabilityReport {
    rabs_wkr::session::CapabilityReport {
        worker_id: "toolchain-upload-session-test".to_owned(),
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

fn fixture(parent: &Path) -> ToolchainIdentity {
    fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();
    let root = parent.join("original-toolchain");
    fs::create_dir_all(root.join("bin")).unwrap();
    fs::create_dir_all(root.join("lib")).unwrap();
    fs::create_dir_all(root.join("empty")).unwrap();
    fs::write(root.join("bin/compiler"), SCRIPT).unwrap();
    fs::set_permissions(root.join("bin/compiler"), fs::Permissions::from_mode(0o755)).unwrap();
    fs::write(root.join("lib/binary"), BINARY).unwrap();
    fs::write(root.join("lib/empty"), b"").unwrap();
    symlink("compiler", root.join("bin/runner")).unwrap();
    symlink("lib/binary", root.join("data-link")).unwrap();
    fingerprint_toolchain(&root, &ToolchainLimits::default(), || false).unwrap()
}

fn identity_json(identity: ToolchainIdentity) -> Value {
    json!({
        "version": TOOLCHAIN_DATASET_VERSION,
        "sha256": hex(&identity.sha256),
        "files": identity.files,
        "bytes": identity.bytes,
    })
}

fn request(identity: ToolchainIdentity) -> Value {
    use sha2::{Digest, Sha256};
    let manifest = SourceManifest::new(vec![SourceFile {
        path: "src/main.rs".to_owned(),
        len: SOURCE.len() as u64,
        sha256: Sha256::digest(SOURCE).into(),
        executable: false,
    }])
    .unwrap();
    json!({"kind":"canonical-exec", "request_id":REQUEST,
    "program":"/__rabs/toolchain/bin/runner", "args":[], "timeout_ms":15_000,
    "toolchain_transfer":TOOLCHAIN_TRANSFER_VERSION,
    "toolchain_identity":identity_json(identity),
    "source_manifest":{
        "manifest_sha256":hex(&manifest.digest()),
        "files":[{"path":"src/main.rs", "bytes":SOURCE.len(),
            "sha256":hex(&Sha256::digest(SOURCE)), "executable":false}],
    }})
}

fn upload_source<F: Future>(mut driver: Pin<&mut F>, peer: &Wire, original: &Value) {
    let manifest = &original["source_manifest"];
    for frame in [
        json!({"kind":"source-begin", "request_id":original["request_id"], "manifest":manifest}),
        json!({"kind":"source-chunk", "request_id":original["request_id"],
            "manifest_sha256":manifest["manifest_sha256"], "path":"src/main.rs", "offset":0,
            "data_hex":hex(SOURCE), "chunk_sha256":rabs_wkr::session::sha256_hex(SOURCE)}),
        json!({"kind":"source-seal", "request_id":original["request_id"],
            "manifest_sha256":manifest["manifest_sha256"]}),
    ] {
        assert_ne!(exchange(driver.as_mut(), peer, frame)["kind"], "error");
    }
}

fn begin(identity: ToolchainIdentity) -> Value {
    json!({"kind":"toolchain-begin", "request_id":REQUEST,
        "identity":identity_json(identity), "entries":9})
}

fn entry(identity: ToolchainIdentity, path: &str, value: Value) -> Value {
    json!({"kind":"toolchain-entry", "request_id":REQUEST,
        "sha256":hex(&identity.sha256), "path":path, "entry":value})
}

fn chunk(identity: ToolchainIdentity, path: &str, offset: usize, bytes: &[u8]) -> Value {
    json!({"kind":"toolchain-chunk", "request_id":REQUEST,
        "sha256":hex(&identity.sha256), "path":path, "offset":offset,
        "data_hex":hex(bytes), "chunk_sha256":rabs_wkr::session::sha256_hex(bytes)})
}

fn seal(identity: ToolchainIdentity) -> Value {
    json!({"kind":"toolchain-seal", "request_id":REQUEST,
        "sha256":hex(&identity.sha256)})
}

/// Deliberately spell out wire entries independently of the receiver/exporter.
/// The expected identity comes from the existing complete local-tree scanner.
fn frames(identity: ToolchainIdentity) -> Vec<Value> {
    let split = SCRIPT.len() / 2;
    vec![
        begin(identity),
        entry(identity, "", json!({"kind":"directory"})),
        entry(identity, "bin", json!({"kind":"directory"})),
        entry(
            identity,
            "bin/compiler",
            json!({"kind":"file", "bytes":SCRIPT.len(), "executable":true}),
        ),
        chunk(identity, "bin/compiler", 0, &SCRIPT[..split]),
        chunk(identity, "bin/compiler", split, &SCRIPT[split..]),
        entry(
            identity,
            "bin/runner",
            json!({"kind":"symlink", "target":"compiler"}),
        ),
        entry(
            identity,
            "data-link",
            json!({"kind":"symlink", "target":"lib/binary"}),
        ),
        entry(identity, "empty", json!({"kind":"directory"})),
        entry(identity, "lib", json!({"kind":"directory"})),
        entry(
            identity,
            "lib/binary",
            json!({"kind":"file", "bytes":BINARY.len(), "executable":false}),
        ),
        chunk(identity, "lib/binary", 0, &BINARY[..5]),
        chunk(identity, "lib/binary", 5, &BINARY[5..]),
        entry(
            identity,
            "lib/empty",
            json!({"kind":"file", "bytes":0, "executable":false}),
        ),
        seal(identity),
    ]
}

fn upload<F: Future>(mut driver: Pin<&mut F>, peer: &Wire, identity: ToolchainIdentity) {
    for frame in frames(identity) {
        let reply = exchange(driver.as_mut(), peer, frame);
        assert_ne!(reply["kind"], "error", "toolchain upload refused: {reply}");
        assert_eq!(reply["request_id"], REQUEST);
        assert_eq!(reply["sha256"], hex(&identity.sha256));
    }
    assert_eq!(peer.replies().last().unwrap()["sealed"], true);
}

fn selection(journal: &WorkerJournal, request: &Value) -> ExecutionLeaseSelection {
    let frame = json!({"kind":"session-ok", "session_id":SESSION,
    "execution_lease":{
        "version":REQUEST_EXECUTION_LEASE_VERSION,
        "session_id":SESSION, "lease_id":LEASE, "request_id":request["request_id"],
        "request_sha256":rabs_wkr::session::sha256_hex(&serde_json::to_vec(request).unwrap()),
        "boot_generation":journal.boot_generation().0,
        "incarnation":format!("{:032x}", journal.incarnation().0),
        "ttl_ms":30_000,
    }});
    execution_lease_selection(&frame.to_string(), true, Some(SESSION), journal).unwrap()
}

#[derive(Clone, Default)]
struct Evidence {
    launches: Arc<AtomicUsize>,
    started: Arc<AtomicBool>,
    drained: Arc<AtomicBool>,
    private_root: Arc<Mutex<Option<PathBuf>>>,
}

fn assert_tree(root: &Path) {
    assert!(root.join("empty").is_dir());
    assert_eq!(fs::read(root.join("bin/compiler")).unwrap(), SCRIPT);
    assert_eq!(fs::read(root.join("lib/binary")).unwrap(), BINARY);
    assert!(fs::read(root.join("lib/empty")).unwrap().is_empty());
    assert_eq!(
        fs::read_link(root.join("bin/runner")).unwrap(),
        Path::new("compiler")
    );
    assert_eq!(
        fs::read_link(root.join("data-link")).unwrap(),
        Path::new("lib/binary")
    );
    assert_ne!(
        fs::metadata(root.join("bin/compiler"))
            .unwrap()
            .permissions()
            .mode()
            & 0o111,
        0
    );
    assert_eq!(
        fs::metadata(root.join("lib/binary"))
            .unwrap()
            .permissions()
            .mode()
            & 0o111,
        0
    );
}

fn terminal(peer: &Wire) -> Option<Value> {
    peer.replies()
        .into_iter()
        .find(|reply| reply["kind"] == "exec-result")
}

#[allow(clippy::too_many_arguments)]
fn launch(
    root: &Path,
    request: CanonicalExecRequest,
    timeout: Duration,
    artifacts: Option<ArtifactPlan>,
    source: Option<SourceOwner>,
    toolchain: Option<ToolchainOwner>,
    lease: Option<(RequestExecutionLeaseIdentity, u64)>,
    evidence: Evidence,
) -> io::Result<ExecutionTask> {
    assert!(artifacts.is_none());
    assert!(
        source.is_some(),
        "driver omitted the accompanying source owner"
    );
    assert!(
        toolchain.is_some(),
        "driver omitted the uploaded tree owner"
    );
    evidence.launches.fetch_add(1, Ordering::SeqCst);
    let private_root = PathBuf::from(&request.toolchain_backing);
    assert_ne!(private_root, root.join("original-toolchain"));
    assert_tree(&private_root);
    *evidence.private_root.lock().unwrap() = Some(private_root.clone());
    let root = root.to_path_buf();
    let workspace = PathBuf::from(&request.workspace_backing);
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
            let _source = source;
            let _toolchain = toolchain;
            assert_eq!(fs::read(workspace.join("src/main.rs")).unwrap(), SOURCE);
            assert_tree(&private_root);
            let mut command = Command::new(private_root.join("bin/runner"));
            command
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .env("TOOLCHAIN", &private_root)
                .env("GATE", root.join("continue"))
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            let group =
                ManagedProcessGroup::spawn_command(command, Attribution::default()).unwrap();
            evidence.started.store(true, Ordering::Release);
            let drained = group
                .wait_with_bounded_drain_budget(
                    &DrainLimits {
                        resident_bound: 2,
                        spill_dir: root.join("spill"),
                    },
                    4096,
                    || control.reason().is_some(),
                )
                .unwrap();
            assert_eq!(drained.residual_group_members, 0);
            // Cancellation/session loss must not discard the upload while an
            // owned process or its inherited writers are still being drained.
            assert_tree(&private_root);
            assert_eq!(fs::read(workspace.join("src/main.rs")).unwrap(), SOURCE);
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
            control.retain_outputs(Ok(outputs)).unwrap();
            evidence.drained.store(true, Ordering::Release);
            result
        },
    )
}

#[test]
fn unnegotiated_and_partial_toolchains_never_reach_durable_admission() {
    for enabled in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let identity = fixture(root.path());
        let original = request(identity);
        let report = report();
        let mut journal =
            WorkerJournal::open(root.path(), &report.worker_id, "coordinator").unwrap();
        let selected = selection(&journal, &original);
        let mut wire = Wire::default();
        let peer = wire.clone();
        let mut driver = Box::pin(drive_session_with_inputs(
            &mut wire,
            &report,
            false,
            Some(&mut journal),
            false,
            true,
            enabled,
            false,
            &selected,
            |_, _, _, _, _, _| panic!("incomplete toolchain launched"),
            pressure,
        ));
        upload_source(driver.as_mut(), &peer, &original);
        assert_eq!(
            exchange(driver.as_mut(), &peer, original.clone())["kind"],
            "error"
        );
        for frame in frames(identity).into_iter().take(5) {
            let reply = exchange(driver.as_mut(), &peer, frame);
            if enabled {
                assert_ne!(reply["kind"], "error", "{reply}");
            } else {
                assert_eq!(reply["kind"], "error");
                assert_eq!(reply["reason"], "toolchain transfer not negotiated");
            }
        }
        assert_eq!(
            exchange(driver.as_mut(), &peer, original.clone())["kind"],
            "error"
        );
        assert_eq!(
            exchange(driver.as_mut(), &peer, seal(identity))["kind"],
            "error"
        );
        assert_eq!(exchange(driver.as_mut(), &peer, original)["kind"], "error");
        let status = exchange(
            driver.as_mut(),
            &peer,
            json!({"kind":"request-status", "request_id":REQUEST}),
        );
        assert_eq!(status["status"], "unknown");
        let heartbeat = exchange(driver.as_mut(), &peer, json!({"kind":"ping"}));
        assert!(heartbeat["active_request_id"].is_null());
        peer.close();
        wait(driver).unwrap();
        assert_eq!(journal.high_water(), None);
    }
}

#[test]
fn pipelined_toolchain_chunks_preserve_order_while_ping_bypasses_filesystem_work() {
    let root = tempfile::tempdir().unwrap();
    let identity = fixture(root.path());
    let report = report();
    let mut journal = WorkerJournal::open(root.path(), &report.worker_id, "coordinator").unwrap();
    let selected = ExecutionLeaseSelection::default();
    let mut wire = Wire::default();
    let peer = wire.clone();
    let mut driver = Box::pin(drive_session_with_inputs(
        &mut wire,
        &report,
        false,
        Some(&mut journal),
        false,
        true,
        true,
        false,
        &selected,
        |_, _, _, _, _, _| panic!("toolchain upload is not execution admission"),
        pressure,
    ));
    upload_source(driver.as_mut(), &peer, &request(identity));
    let frames = frames(identity);
    for frame in &frames[..3] {
        assert_ne!(
            exchange(driver.as_mut(), &peer, frame.clone())["kind"],
            "error"
        );
    }
    let before = peer.replies().len();
    peer.frame(frames[3].clone());
    peer.frame(frames[4].clone());
    peer.frame(json!({"kind":"ping"}));
    peer.frame(frames[5].clone());
    peer.frame(frames[6].clone());
    peer.frame(json!({"kind":"ping"}));
    pump_until(driver.as_mut(), || peer.replies().len() == before + 6);
    let replies = peer.replies();
    let controls: Vec<_> = replies[before..]
        .iter()
        .filter(|reply| reply["kind"] == "heartbeat")
        .collect();
    assert_eq!(controls.len(), 2);
    for heartbeat in controls {
        assert!(heartbeat["active_request_id"].is_null());
        assert_eq!(heartbeat["pending_toolchain_request_id"], REQUEST);
    }
    let ordered: Vec<_> = replies[before..]
        .iter()
        .filter(|reply| reply["kind"] != "heartbeat")
        .collect();
    assert_eq!(ordered.len(), 4);
    assert_eq!(ordered[0]["kind"], "toolchain-entry-accepted");
    assert_eq!(ordered[0]["path"], "bin/compiler");
    assert_eq!(ordered[1]["kind"], "toolchain-chunk-accepted");
    assert_eq!(ordered[1]["next_offset"], SCRIPT.len() / 2);
    assert_eq!(ordered[2]["next_offset"], SCRIPT.len());
    assert_eq!(ordered[3]["path"], "bin/runner");
    for frame in &frames[7..] {
        assert_ne!(
            exchange(driver.as_mut(), &peer, frame.clone())["kind"],
            "error"
        );
    }
    assert_eq!(peer.replies().last().unwrap()["sealed"], true);
    let status = exchange(
        driver.as_mut(),
        &peer,
        json!({"kind":"request-status", "request_id":REQUEST}),
    );
    assert_eq!(status["status"], "unknown");
    peer.close();
    wait(driver).unwrap();
    assert_eq!(journal.high_water(), None);
}

#[test]
fn uploaded_executable_runs_private_bytes_and_journals_the_exact_original_request() {
    for request_id in [REQUEST, 0] {
        let root = tempfile::tempdir().unwrap();
        let identity = fixture(root.path());
        let mut original = request(identity);
        original["request_id"] = json!(request_id);
        let report = report();
        let mut journal =
            WorkerJournal::open(root.path(), &report.worker_id, "coordinator").unwrap();
        let selected = selection(&journal, &original);
        let evidence = Evidence::default();
        let mut wire = Wire::default();
        let peer = wire.clone();
        let mut driver = Box::pin(drive_session_with_inputs(
            &mut wire,
            &report,
            false,
            Some(&mut journal),
            false,
            true,
            true,
            false,
            &selected,
            |request, timeout, artifacts, source, toolchain, lease| {
                assert!(lease.is_some());
                launch(
                    root.path(),
                    request,
                    timeout,
                    artifacts,
                    source,
                    toolchain,
                    lease,
                    evidence.clone(),
                )
            },
            pressure,
        ));
        upload_source(driver.as_mut(), &peer, &original);
        let frames: Vec<_> = frames(identity)
            .into_iter()
            .map(|mut frame| {
                frame["request_id"] = json!(request_id);
                frame
            })
            .collect();
        for frame in &frames[..frames.len() - 1] {
            assert_ne!(
                exchange(driver.as_mut(), &peer, frame.clone())["kind"],
                "error"
            );
        }
        assert_eq!(
            exchange(driver.as_mut(), &peer, original.clone())["kind"],
            "error"
        );
        assert_eq!(evidence.launches.load(Ordering::SeqCst), 0);
        let ready = exchange(driver.as_mut(), &peer, frames.last().unwrap().clone());
        assert_eq!(ready["kind"], "toolchain-ready");
        assert_eq!(ready["sealed"], true);
        // The execution cannot fall back to the coordinator's mutable fixture.
        fs::write(
            root.path().join("original-toolchain/lib/binary"),
            b"changed after upload",
        )
        .unwrap();
        peer.frame(original.clone());
        pump_until(driver.as_mut(), || evidence.started.load(Ordering::Acquire));
        assert_eq!(evidence.launches.load(Ordering::SeqCst), 1);
        assert!(!evidence.drained.load(Ordering::Acquire));
        let private = evidence.private_root.lock().unwrap().clone().unwrap();
        assert_tree(&private);
        let saved: Value =
            serde_json::from_slice(&fs::read(root.path().join("requests.json")).unwrap()).unwrap();
        assert_eq!(
            saved["last"]["fingerprint"],
            rabs_wkr::request_journal::request_fingerprint(
                &original,
                Duration::from_millis(15_000)
            )
        );
        assert_eq!(saved["last"]["resolved"], false);
        let heartbeat = exchange(driver.as_mut(), &peer, json!({"kind":"ping"}));
        assert_eq!(heartbeat["active_request_id"], request_id);
        fs::write(root.path().join("continue"), b"go").unwrap();
        pump_until(driver.as_mut(), || terminal(&peer).is_some());
        let completed = terminal(&peer).unwrap();
        assert_eq!(completed["request_id"], request_id);
        assert_eq!(completed["exit_code"], 0);
        assert_eq!(completed["executed"], true);
        assert_eq!(completed["residual_group_members"], 0);
        assert!(completed["stop_reason"].is_null());
        assert!(evidence.drained.load(Ordering::Acquire));
        assert!(
            !private.exists(),
            "uploaded tree outlived its execution owner"
        );
        let stdout = [BINARY, BINARY].concat();
        for (name, bytes) in [("stdout", stdout.as_slice()), ("stderr", STDERR)] {
            let reply = exchange(
                driver.as_mut(),
                &peer,
                json!({"kind":"output-read", "request_id":request_id,
            "stream":name, "offset":0, "max_bytes":4096}),
            );
            assert_eq!(reply["kind"], "output-chunk");
            assert_eq!(reply["data_hex"], hex(bytes));
            assert_eq!(reply["total_bytes"], bytes.len());
            assert_eq!(reply["eof"], true);
            assert_eq!(reply["sha256"], rabs_wkr::session::sha256_hex(bytes));
            assert_eq!(completed[format!("{name}_sha256")], reply["sha256"]);
        }
        peer.close();
        wait(driver).unwrap();
        assert_eq!(journal.high_water(), Some(request_id));
    }
}

#[test]
fn sealed_toolchain_refuses_foreign_original_identity_without_consuming_the_owner() {
    let root = tempfile::tempdir().unwrap();
    let identity = fixture(root.path());
    let original = request(identity);
    let report = report();
    let mut journal = WorkerJournal::open(root.path(), &report.worker_id, "coordinator").unwrap();
    let selected = ExecutionLeaseSelection::default();
    let evidence = Evidence::default();
    let mut wire = Wire::default();
    let peer = wire.clone();
    let mut driver = Box::pin(drive_session_with_inputs(
        &mut wire,
        &report,
        false,
        Some(&mut journal),
        false,
        true,
        true,
        false,
        &selected,
        |request, timeout, artifacts, source, toolchain, lease| {
            launch(
                root.path(),
                request,
                timeout,
                artifacts,
                source,
                toolchain,
                lease,
                evidence.clone(),
            )
        },
        pressure,
    ));
    upload_source(driver.as_mut(), &peer, &original);
    upload(driver.as_mut(), &peer, identity);
    for case in 0..6 {
        let mut changed = original.clone();
        match case {
            0 => changed["request_id"] = json!(REQUEST + 1),
            1 => changed["toolchain_identity"]["sha256"] = json!("00".repeat(32)),
            2 => changed["toolchain_identity"]["files"] = json!(identity.files + 1),
            3 => changed["toolchain_identity"]["bytes"] = json!(identity.bytes + 1),
            4 => changed["toolchain_backing"] = json!("/arbitrary-worker-path"),
            _ => changed["toolchain_source"] = json!("/arbitrary-coordinator-path"),
        }
        assert_eq!(
            exchange(driver.as_mut(), &peer, changed)["kind"],
            "error",
            "case {case}"
        );
        assert_eq!(evidence.launches.load(Ordering::SeqCst), 0);
    }
    let status = exchange(
        driver.as_mut(),
        &peer,
        json!({"kind":"request-status", "request_id":REQUEST}),
    );
    assert_eq!(status["status"], "unknown");
    fs::write(root.path().join("continue"), b"go").unwrap();
    peer.frame(original);
    pump_until(driver.as_mut(), || terminal(&peer).is_some());
    assert_eq!(terminal(&peer).unwrap()["exit_code"], 0);
    assert_eq!(evidence.launches.load(Ordering::SeqCst), 1);
    peer.close();
    wait(driver).unwrap();
    assert_eq!(journal.high_water(), Some(REQUEST));
}

#[test]
fn disconnect_retains_the_uploaded_toolchain_until_the_real_child_is_drained() {
    let root = tempfile::tempdir().unwrap();
    let identity = fixture(root.path());
    let original = request(identity);
    let report = report();
    let mut journal = WorkerJournal::open(root.path(), &report.worker_id, "coordinator").unwrap();
    let selected = selection(&journal, &original);
    let evidence = Evidence::default();
    let mut wire = Wire::default();
    let peer = wire.clone();
    let mut driver = Box::pin(drive_session_with_inputs(
        &mut wire,
        &report,
        false,
        Some(&mut journal),
        false,
        true,
        true,
        false,
        &selected,
        |request, timeout, artifacts, source, toolchain, lease| {
            launch(
                root.path(),
                request,
                timeout,
                artifacts,
                source,
                toolchain,
                lease,
                evidence.clone(),
            )
        },
        pressure,
    ));
    upload_source(driver.as_mut(), &peer, &original);
    upload(driver.as_mut(), &peer, identity);
    peer.frame(original);
    pump_until(driver.as_mut(), || evidence.started.load(Ordering::Acquire));
    let private = evidence.private_root.lock().unwrap().clone().unwrap();
    assert!(private.exists());
    assert!(!evidence.drained.load(Ordering::Acquire));
    peer.close();
    wait(driver).unwrap();
    assert!(evidence.drained.load(Ordering::Acquire));
    assert!(!private.exists());
    assert_eq!(evidence.launches.load(Ordering::SeqCst), 1);
    assert_eq!(
        journal.status(REQUEST)["receipt"]["stop_reason"],
        "session-lost"
    );
    assert_eq!(
        journal.status(REQUEST)["receipt"]["residual_group_members"],
        0
    );
}

#[test]
fn cancel_before_seal_and_after_seal_blocks_later_execution_and_reupload() {
    for sealed in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let identity = fixture(root.path());
        let original = request(identity);
        let report = report();
        let mut journal =
            WorkerJournal::open(root.path(), &report.worker_id, "coordinator").unwrap();
        let selected = selection(&journal, &original);
        let mut wire = Wire::default();
        let peer = wire.clone();
        let mut driver = Box::pin(drive_session_with_inputs(
            &mut wire,
            &report,
            false,
            Some(&mut journal),
            false,
            true,
            true,
            false,
            &selected,
            |_, _, _, _, _, _| panic!("cancelled upload reached execution"),
            pressure,
        ));
        upload_source(driver.as_mut(), &peer, &original);
        let frames = frames(identity);
        let count = if sealed { frames.len() } else { 5 };
        for frame in &frames[..count] {
            assert_ne!(
                exchange(driver.as_mut(), &peer, frame.clone())["kind"],
                "error"
            );
        }
        let foreign = exchange(
            driver.as_mut(),
            &peer,
            json!({"kind":"cancel", "request_id":REQUEST + 1}),
        );
        assert_eq!(foreign["reason"], "unknown-request");
        for accepted in [true, false] {
            let reply = exchange(
                driver.as_mut(),
                &peer,
                json!({"kind":"cancel", "request_id":REQUEST}),
            );
            assert_eq!(reply["kind"], "cancel-accepted");
            assert_eq!(reply["request_id"], REQUEST);
            assert_eq!(reply["accepted"], accepted);
            assert_eq!(reply["cleanup_pending"], true);
        }
        for frame in [seal(identity), original, begin(identity)] {
            assert_eq!(exchange(driver.as_mut(), &peer, frame)["kind"], "error");
        }
        let status = exchange(
            driver.as_mut(),
            &peer,
            json!({"kind":"request-status", "request_id":REQUEST}),
        );
        assert_eq!(status["status"], "unknown");
        peer.close();
        wait(driver).unwrap();
        assert_eq!(journal.high_water(), None);
    }
}

#[test]
fn cancelling_a_pending_real_seal_discards_any_late_filesystem_success() {
    let root = tempfile::tempdir().unwrap();
    let identity = fixture(root.path());
    let original = request(identity);
    let mut task = ToolchainTransferTask::default();
    let finish =
        |task: &mut ToolchainTransferTask| wait(poll_fn(|cx| task.poll_completion(cx))).unwrap();
    let frames = frames(identity);
    for frame in &frames[..frames.len() - 1] {
        task.submit(frame, true, false).unwrap();
        assert!(finish(&mut task).response.is_ok());
    }
    task.submit(&seal(identity), true, false).unwrap();
    // No filesystem delay is faked. The real operation may still be running
    // or may already have completed; its result has not been consumed by the
    // reactor. Cancellation must fence both cases without exposing an owner.
    assert!(task.is_pending());
    assert_eq!(task.cancel(REQUEST + 1), None);
    assert_eq!(task.cancel(REQUEST), Some(true));
    assert_eq!(task.cancel(REQUEST), Some(false));
    let completed = finish(&mut task);
    assert_eq!(completed.request_id, REQUEST);
    assert_eq!(
        completed.response.unwrap_err(),
        "toolchain upload cancelled"
    );
    assert!(!task.is_pending());
    assert!(task.prepared_path(&original, true).is_err());
    assert!(task.take_prepared(&original).is_err());
    assert!(task.submit(&begin(identity), true, false).is_err());
}

#[test]
fn a_blocked_seal_reply_does_not_admit_pipelined_execution_after_cancel() {
    let root = tempfile::tempdir().unwrap();
    let identity = fixture(root.path());
    let original = request(identity);
    let report = report();
    let mut journal = WorkerJournal::open(root.path(), &report.worker_id, "coordinator").unwrap();
    let selected = selection(&journal, &original);
    let mut wire = Wire::default();
    let peer = wire.clone();
    let mut driver = Box::pin(drive_session_with_inputs(
        &mut wire,
        &report,
        false,
        Some(&mut journal),
        false,
        true,
        true,
        false,
        &selected,
        |_, _, _, _, _, _| panic!("cancelled pipelined request launched"),
        pressure,
    ));
    upload_source(driver.as_mut(), &peer, &original);
    let frames = frames(identity);
    for frame in &frames[..frames.len() - 1] {
        assert_ne!(
            exchange(driver.as_mut(), &peer, frame.clone())["kind"],
            "error"
        );
    }
    let before = peer.replies().len();
    peer.block_writes(true);
    peer.frame(seal(identity));
    pump_until(driver.as_mut(), || peer.0.lock().unwrap().writer.is_some());
    assert_eq!(peer.replies().len(), before);
    peer.frame(json!({"kind":"cancel", "request_id":REQUEST}));
    let execution = format!("{original}\n");
    let split = execution.len() / 2;
    peer.bytes(&execution.as_bytes()[..split]);
    peer.block_writes(false);
    pump_until(driver.as_mut(), || peer.replies().len() == before + 2);
    assert_eq!(peer.replies()[before]["sealed"], true);
    assert_eq!(peer.replies()[before + 1]["kind"], "cancel-accepted");
    assert_eq!(peer.replies()[before + 1]["accepted"], true);
    peer.bytes(&execution.as_bytes()[split..]);
    pump_until(driver.as_mut(), || peer.replies().len() == before + 3);
    assert_eq!(peer.replies()[before + 2]["kind"], "error");
    let status = exchange(
        driver.as_mut(),
        &peer,
        json!({"kind":"request-status", "request_id":REQUEST}),
    );
    assert_eq!(status["status"], "unknown");
    peer.close();
    wait(driver).unwrap();
    assert_eq!(journal.high_water(), None);
}
