//! Input liveness through the production session driver and a real native
//! current-thread runtime. The fragmenting byte peer replaces transport only;
//! the managed shell fixture does not claim TLS or canonical-namespace proof.
#![cfg(target_os = "linux")]

use super::*;
use asupersync::io::ReadBuf;
use asupersync::runtime::RuntimeBuilder;
use rabs_asupersync::process_groups::ManagedProcessGroup;
use rabs_asupersync::region_tree::Attribution;
use rabs_asupersync::stream_drain::DrainLimits;
use rabs_sandbox::source_transfer::{SourceFile, SourceManifest};
use rabs_sandbox::toolchain_dataset::{
    TOOLCHAIN_DATASET_VERSION, ToolchainIdentity, ToolchainLimits, fingerprint_toolchain,
};
use rabs_wkr::source_transfer::hex;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::pin::Pin;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Waker};
use std::time::Instant;

// Zero is a valid request identity, including for deadline ownership.
const REQUEST: u64 = 0;
const SOURCE: &[u8] = b"source bytes\0\xff";
const SCRIPT: &[u8] =
    b"#!/bin/sh\nwhile [ ! -e \"$GATE\" ]; do sleep 0.01; done\nprintf 'done\\n'\n";
const WATCHDOG: Duration = Duration::from_secs(8);

#[derive(Default)]
struct WireState {
    input: VecDeque<u8>,
    output: Vec<u8>,
    eof: bool,
    reader: Option<Waker>,
    write_limit: Option<usize>,
    block_flush: bool,
}

#[derive(Clone, Default)]
struct Wire(Arc<Mutex<WireState>>);

impl Wire {
    fn frame(&self, value: Value) {
        let wake = {
            let mut state = self.0.lock().unwrap();
            state.input.extend(format!("{value}\n").bytes());
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
        let mut state = self.0.lock().unwrap();
        let len = bytes
            .len()
            .min(7)
            .min(state.write_limit.unwrap_or(usize::MAX));
        if len == 0 && !bytes.is_empty() {
            // Intentionally never wakes: only the session's timer can make
            // this permanently non-reading peer release its input owner.
            return Poll::Pending;
        }
        state.output.extend_from_slice(&bytes[..len]);
        if let Some(limit) = state.write_limit.as_mut() {
            *limit -= len;
        }
        Poll::Ready(Ok(len))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.0.lock().unwrap().block_flush {
            Poll::Pending
        } else {
            Poll::Ready(Ok(()))
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

fn in_runtime(future: impl Future<Output = ()> + Send + 'static) {
    let runtime = RuntimeBuilder::current_thread().build().unwrap();
    let handle = runtime.handle();
    runtime.block_on(async move { handle.spawn(future).await });
}

/// Poll with the actual runtime task's waker. Source-thread completions wake
/// exchanges; there is no synchronous park/sleep loop driving timers for them.
async fn observe<F: Future<Output = Result<(), String>>>(
    mut driver: Pin<&mut F>,
    mut ready: impl FnMut() -> bool,
) {
    asupersync::time::timeout(
        asupersync::time::wall_now(),
        WATCHDOG,
        poll_fn(|cx| {
            assert!(
                driver.as_mut().poll(cx).is_pending(),
                "session exited before observation"
            );
            if ready() {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        }),
    )
    .await
    .expect("session observation exceeded watchdog");
}

async fn exchange<F: Future<Output = Result<(), String>>>(
    mut driver: Pin<&mut F>,
    peer: &Wire,
    frame: Value,
) -> Value {
    let before = peer.replies().len();
    peer.frame(frame);
    observe(driver.as_mut(), || peer.replies().len() > before).await;
    peer.replies()[before].clone()
}

async fn hold_pending<F: Future<Output = Result<(), String>>>(
    mut driver: Pin<&mut F>,
    duration: Duration,
) {
    let mut timer = pin!(asupersync::time::sleep(
        asupersync::time::wall_now(),
        duration
    ));
    poll_fn(|cx| {
        assert!(
            driver.as_mut().poll(cx).is_pending(),
            "session expired before its budget"
        );
        timer.as_mut().poll(cx)
    })
    .await;
}

async fn finish<F: Future<Output = Result<(), String>>>(driver: F) -> Result<(), String> {
    asupersync::time::timeout(asupersync::time::wall_now(), WATCHDOG, driver)
        .await
        .expect("session did not wake for its own input deadline")
}

fn report() -> rabs_wkr::session::CapabilityReport {
    rabs_wkr::session::CapabilityReport {
        worker_id: "input-deadline-test".to_owned(),
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

fn private_root() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    root
}

fn source_request() -> Value {
    let manifest = SourceManifest::new(vec![SourceFile {
        path: "src/lib.rs".to_owned(),
        len: SOURCE.len() as u64,
        sha256: Sha256::digest(SOURCE).into(),
        executable: false,
    }])
    .unwrap();
    json!({"kind":"canonical-exec", "request_id":REQUEST,
    "program":"/__rabs/toolchain/compiler", "args":[], "timeout_ms":15_000,
    "toolchain_backing":"/fixture-toolchain",
    "source_manifest":{
        "manifest_sha256":hex(&manifest.digest()),
        "files":[{"path":"src/lib.rs", "bytes":SOURCE.len(),
            "sha256":hex(&Sha256::digest(SOURCE)), "executable":false}],
    }})
}

fn source_begin(request: &Value) -> Value {
    json!({"kind":"source-begin", "request_id":request["request_id"],
        "manifest":request["source_manifest"]})
}

fn source_chunk(request: &Value, offset: usize, bytes: &[u8]) -> Value {
    json!({"kind":"source-chunk", "request_id":request["request_id"],
        "manifest_sha256":request["source_manifest"]["manifest_sha256"],
        "path":"src/lib.rs", "offset":offset, "data_hex":hex(bytes),
        "chunk_sha256":hex(&Sha256::digest(bytes))})
}

fn source_seal(request: &Value) -> Value {
    json!({"kind":"source-seal", "request_id":request["request_id"],
        "manifest_sha256":request["source_manifest"]["manifest_sha256"]})
}

async fn upload_source<F: Future<Output = Result<(), String>>>(
    mut driver: Pin<&mut F>,
    peer: &Wire,
    request: &Value,
) {
    for frame in [
        source_begin(request),
        source_chunk(request, 0, SOURCE),
        source_seal(request),
    ] {
        let reply = exchange(driver.as_mut(), peer, frame).await;
        assert_ne!(reply["kind"], "error", "{reply}");
    }
    assert_eq!(peer.replies().last().unwrap()["sealed"], true);
}

fn identity_json(identity: ToolchainIdentity) -> Value {
    json!({"version":TOOLCHAIN_DATASET_VERSION, "sha256":hex(&identity.sha256),
        "files":identity.files, "bytes":identity.bytes})
}

fn toolchain_fixture(root: &Path) -> (Value, ToolchainIdentity) {
    let tree = root.join("original-toolchain");
    fs::create_dir(&tree).unwrap();
    fs::write(tree.join("compiler"), SCRIPT).unwrap();
    fs::set_permissions(tree.join("compiler"), fs::Permissions::from_mode(0o755)).unwrap();
    let identity = fingerprint_toolchain(&tree, &ToolchainLimits::default(), || false).unwrap();
    let mut request = source_request();
    request.as_object_mut().unwrap().remove("toolchain_backing");
    request["toolchain_transfer"] = json!(TOOLCHAIN_TRANSFER_VERSION);
    request["toolchain_identity"] = identity_json(identity);
    (request, identity)
}

fn toolchain_frames(identity: ToolchainIdentity) -> Vec<Value> {
    let digest = hex(&identity.sha256);
    vec![
        json!({"kind":"toolchain-begin", "request_id":REQUEST,
            "identity":identity_json(identity), "entries":2}),
        json!({"kind":"toolchain-entry", "request_id":REQUEST,
            "sha256":digest, "path":"", "entry":{"kind":"directory"}}),
        json!({"kind":"toolchain-entry", "request_id":REQUEST,
            "sha256":digest, "path":"compiler",
            "entry":{"kind":"file", "bytes":SCRIPT.len(), "executable":true}}),
        json!({"kind":"toolchain-chunk", "request_id":REQUEST,
            "sha256":digest, "path":"compiler", "offset":0,
            "data_hex":hex(SCRIPT), "chunk_sha256":hex(&Sha256::digest(SCRIPT))}),
        json!({"kind":"toolchain-seal", "request_id":REQUEST, "sha256":digest}),
    ]
}

async fn upload_toolchain<F: Future<Output = Result<(), String>>>(
    mut driver: Pin<&mut F>,
    peer: &Wire,
    identity: ToolchainIdentity,
) {
    for frame in toolchain_frames(identity) {
        let reply = exchange(driver.as_mut(), peer, frame).await;
        assert_ne!(reply["kind"], "error", "{reply}");
    }
    assert_eq!(peer.replies().last().unwrap()["sealed"], true);
}

fn short_budgets() -> InputBudgets {
    InputBudgets {
        source: Duration::from_secs(2),
        toolchain: Duration::from_secs(2),
        total: Duration::from_secs(3),
    }
}

#[test]
fn silent_partial_source_and_sealed_inputs_expire_without_another_peer_frame() {
    in_runtime(async {
        // Each case finishes by awaiting the driver directly. The peer sends
        // neither EOF nor another byte that could incidentally check expiry.
        for stage in 0..3 {
            let root = private_root();
            let (request, identity) = toolchain_fixture(root.path());
            let report = report();
            let mut journal = WorkerJournal::open(root.path(), &report.worker_id, "coord").unwrap();
            let selected = ExecutionLeaseSelection::default();
            let mut wire = Wire::default();
            let peer = wire.clone();
            let started = Instant::now();
            let mut driver = Box::pin(drive_session_with_input_budgets(
                &mut wire,
                &report,
                false,
                Some(&mut journal),
                false,
                true,
                stage == 2,
                false,
                &selected,
                false,
                short_budgets(),
                |_, _, _, _, _, _| panic!("idle input acquired execution admission"),
                pressure,
            ));
            if stage == 0 {
                assert_eq!(
                    exchange(driver.as_mut(), &peer, source_begin(&request)).await["kind"],
                    "source-ready"
                );
            } else {
                upload_source(driver.as_mut(), &peer, &request).await;
                if stage == 2 {
                    upload_toolchain(driver.as_mut(), &peer, identity).await;
                }
            }
            assert_eq!(
                finish(driver).await.unwrap_err(),
                "input-upload-deadline-exceeded"
            );
            assert!(
                started.elapsed() < Duration::from_secs(6),
                "watchdog woke a missing session timer"
            );
            assert_eq!(journal.high_water(), None);
            assert_eq!(journal.status(REQUEST)["status"], "unknown");
            assert!(
                !peer
                    .replies()
                    .iter()
                    .any(|reply| reply["kind"] == "exec-result")
            );
        }
    });
}

#[test]
fn stalled_input_reply_write_and_flush_expire_without_appending_another_frame() {
    in_runtime(async {
        for flush in [false, true] {
            let root = private_root();
            let report = report();
            let mut journal = WorkerJournal::open(root.path(), &report.worker_id, "coord").unwrap();
            let selected = ExecutionLeaseSelection::default();
            let mut wire = Wire::default();
            let peer = wire.clone();
            {
                let mut state = peer.0.lock().unwrap();
                state.block_flush = flush;
                state.write_limit = if flush { None } else { Some(7) };
            }
            peer.frame(source_begin(&source_request()));
            let started = Instant::now();
            let driver = drive_session_with_input_budgets(
                &mut wire,
                &report,
                false,
                Some(&mut journal),
                false,
                true,
                false,
                false,
                &selected,
                false,
                short_budgets(),
                |_, _, _, _, _, _| panic!("blocked input reply launched execution"),
                pressure,
            );
            assert_eq!(
                finish(driver).await.unwrap_err(),
                "input-upload-deadline-exceeded"
            );
            assert!(started.elapsed() < Duration::from_secs(5));
            let bytes = &peer.0.lock().unwrap().output;
            if flush {
                assert_eq!(bytes.iter().filter(|byte| **byte == b'\n').count(), 1);
                let reply: Value = serde_json::from_slice(bytes).unwrap();
                assert_eq!(reply["kind"], "source-ready");
            } else {
                assert_eq!(
                    bytes.len(),
                    7,
                    "a second frame was appended after a partial reply"
                );
                assert!(!bytes.contains(&b'\n'));
            }
            assert_eq!(journal.high_water(), None);
        }
    });
}

#[test]
fn accepted_chunks_pings_and_refused_frames_do_not_renew_the_source_budget() {
    in_runtime(async {
        let root = private_root();
        let report = report();
        let mut journal = WorkerJournal::open(root.path(), &report.worker_id, "coord").unwrap();
        let selected = ExecutionLeaseSelection::default();
        let request = source_request();
        let mut wire = Wire::default();
        let peer = wire.clone();
        let budgets = InputBudgets {
            source: Duration::from_secs(3),
            toolchain: Duration::from_secs(5),
            total: Duration::from_secs(6),
        };
        let started = Instant::now();
        let mut driver = Box::pin(drive_session_with_input_budgets(
            &mut wire,
            &report,
            false,
            Some(&mut journal),
            false,
            true,
            true,
            false,
            &selected,
            false,
            budgets,
            |_, _, _, _, _, _| panic!("source activity acquired execution admission"),
            pressure,
        ));
        assert_eq!(
            exchange(driver.as_mut(), &peer, source_begin(&request)).await["kind"],
            "source-ready"
        );
        let split = SOURCE.len() / 2;
        for (offset, bytes) in [(0, &SOURCE[..split]), (split, &SOURCE[split..])] {
            hold_pending(driver.as_mut(), Duration::from_secs(1)).await;
            assert_eq!(
                exchange(
                    driver.as_mut(),
                    &peer,
                    source_chunk(&request, offset, bytes)
                )
                .await["kind"],
                "source-chunk-accepted"
            );
            assert_eq!(
                exchange(driver.as_mut(), &peer, json!({"kind":"ping"})).await["pending_source_request_id"],
                REQUEST
            );
            assert_eq!(
                exchange(driver.as_mut(), &peer, source_begin(&request)).await["kind"],
                "source-ready"
            );
            let mut foreign = source_begin(&request);
            foreign["request_id"] = json!(REQUEST + 1);
            assert_eq!(
                exchange(driver.as_mut(), &peer, foreign).await["kind"],
                "error"
            );
            assert_eq!(
                exchange(driver.as_mut(), &peer, json!({"kind":"unknown-frame"})).await["kind"],
                "error"
            );
        }
        assert_eq!(
            exchange(driver.as_mut(), &peer, source_seal(&request)).await["sealed"],
            true
        );
        // Even with sealed source, an invalid first toolchain begin cannot
        // extend this request into the longer toolchain phase.
        assert_eq!(
            exchange(
                driver.as_mut(),
                &peer,
                json!({"kind":"toolchain-begin", "request_id":REQUEST})
            )
            .await["kind"],
            "error"
        );
        assert_eq!(
            finish(driver).await.unwrap_err(),
            "input-upload-deadline-exceeded"
        );
        // Restarting on the last successful chunk or refusal takes at least
        // five seconds; the original budget is three seconds.
        assert!(started.elapsed() < Duration::from_secs(4));
        assert_eq!(journal.high_water(), None);
    });
}

#[test]
fn source_to_toolchain_transition_keeps_the_original_total_input_cap() {
    in_runtime(async {
        let root = private_root();
        let (request, identity) = toolchain_fixture(root.path());
        let report = report();
        let mut journal = WorkerJournal::open(root.path(), &report.worker_id, "coord").unwrap();
        let selected = ExecutionLeaseSelection::default();
        let mut wire = Wire::default();
        let peer = wire.clone();
        let started = Instant::now();
        let mut driver = Box::pin(drive_session_with_input_budgets(
            &mut wire,
            &report,
            false,
            Some(&mut journal),
            false,
            true,
            true,
            false,
            &selected,
            false,
            InputBudgets {
                source: Duration::from_secs(4),
                toolchain: Duration::from_secs(4),
                total: Duration::from_secs(6),
            },
            |_, _, _, _, _, _| panic!("partial toolchain launched execution"),
            pressure,
        ));
        upload_source(driver.as_mut(), &peer, &request).await;
        hold_pending(driver.as_mut(), Duration::from_secs(3)).await;
        let frames = toolchain_frames(identity);
        assert_eq!(
            exchange(driver.as_mut(), &peer, frames[0].clone()).await["kind"],
            "toolchain-ready"
        );
        assert_eq!(
            exchange(driver.as_mut(), &peer, frames[1].clone()).await["kind"],
            "toolchain-entry-accepted"
        );
        // It really transitioned beyond the original four-second source
        // deadline, but may use only the remainder of the six-second cap.
        hold_pending(driver.as_mut(), Duration::from_millis(1_400)).await;
        assert_eq!(
            exchange(driver.as_mut(), &peer, json!({"kind":"ping"})).await["pending_toolchain_request_id"],
            REQUEST
        );
        assert_eq!(
            finish(driver).await.unwrap_err(),
            "input-upload-deadline-exceeded"
        );
        assert!(started.elapsed() >= Duration::from_secs(6));
        assert!(
            started.elapsed() < Duration::from_millis(6_700),
            "toolchain begin reset the total input cap"
        );
        assert_eq!(journal.high_water(), None);
    });
}

#[test]
fn staged_input_identity_cannot_be_bypassed_by_execution_or_result_recovery() {
    in_runtime(async {
        let root = private_root();
        let (request, identity) = toolchain_fixture(root.path());
        let report = report();
        let mut journal = WorkerJournal::open(root.path(), &report.worker_id, "coord").unwrap();
        let selected = ExecutionLeaseSelection::default();
        let mut wire = Wire::default();
        let peer = wire.clone();
        let mut driver = Box::pin(drive_session_with_input_budgets(
            &mut wire,
            &report,
            false,
            Some(&mut journal),
            false,
            true,
            true,
            false,
            &selected,
            false,
            short_budgets(),
            |_, _, _, _, _, _| panic!("mixed input ownership passed durable admission"),
            pressure,
        ));
        let premature_toolchain = toolchain_frames(identity)[0].clone();
        assert_eq!(
            exchange(driver.as_mut(), &peer, premature_toolchain.clone()).await["reason"],
            "toolchain upload requires this request's sealed source"
        );
        assert_eq!(
            exchange(driver.as_mut(), &peer, source_begin(&request)).await["kind"],
            "source-ready"
        );
        assert_eq!(
            exchange(driver.as_mut(), &peer, premature_toolchain).await["reason"],
            "toolchain upload requires this request's sealed source"
        );
        assert!(exchange(driver.as_mut(), &peer, json!({"kind":"ping"})).await["pending_toolchain_request_id"].is_null());
        upload_source(driver.as_mut(), &peer, &request).await;
        let mut worker_local = source_request();
        worker_local
            .as_object_mut()
            .unwrap()
            .remove("source_manifest");
        worker_local["workspace_backing"] = json!("/fixture-workspace");
        assert_eq!(
            exchange(driver.as_mut(), &peer, worker_local).await["reason"],
            "input-upload-request-mismatch"
        );
        let mut foreign = request.clone();
        foreign["request_id"] = json!(REQUEST + 1);
        assert_eq!(
            exchange(driver.as_mut(), &peer, foreign).await["reason"],
            "input-upload-request-mismatch"
        );
        upload_toolchain(driver.as_mut(), &peer, identity).await;
        // A source-bound request with the same ID still cannot abandon the
        // toolchain owned by that input clock in favor of a worker-local path.
        assert_eq!(
            exchange(driver.as_mut(), &peer, source_request()).await["reason"],
            "input-upload-request-mismatch"
        );
        assert_eq!(
            exchange(
                driver.as_mut(),
                &peer,
                json!({"kind":"result-resume",
            "request_id":REQUEST, "request":request})
            )
            .await["reason"],
            "worker-busy-or-result-pending"
        );
        assert_eq!(
            exchange(
                driver.as_mut(),
                &peer,
                json!({"kind":"request-status", "request_id":REQUEST})
            )
            .await["status"],
            "unknown"
        );
        peer.close();
        finish(driver).await.unwrap();
        assert_eq!(journal.high_water(), None);
    });
}

#[test]
fn prelaunch_input_refusal_resolves_durable_admission_and_survives_restart() {
    in_runtime(async {
        for cancel_owner in [false, true] {
            let root = private_root();
            let report = report();
            let request = source_request();
            let timeout = parse_timeout(&request).unwrap();
            parse_exec_request(&request).unwrap();
            let mut source = SourceTransferTask::default();
            let mut toolchain = ToolchainTransferTask::default();
            let mut sealed = None;
            for frame in [
                source_begin(&request),
                source_chunk(&request, 0, SOURCE),
                source_seal(&request),
            ] {
                source.submit(&frame, true, false).unwrap();
                let completed = asupersync::time::timeout(
                    asupersync::time::wall_now(),
                    WATCHDOG,
                    poll_fn(|cx| source.poll_completion(cx)),
                )
                .await
                .unwrap()
                .unwrap();
                assert!(completed.response.is_ok());
                sealed = Some(completed);
            }
            let path = PathBuf::from(source.prepared_path(&request, true).unwrap().unwrap());
            assert_eq!(fs::read(path.join("src/lib.rs")).unwrap(), SOURCE);
            let mut journal = WorkerJournal::open(root.path(), &report.worker_id, "coord").unwrap();

            // Exercise the production boundary after a REAL successful source
            // seal and durable admit. No prediction of fsync timing is needed:
            // the boundary is entered with either an expired native clock or
            // an actually revoked source owner, before any launcher is called.
            let mut deadline = InputDeadline::new(if cancel_owner {
                InputBudgets::default()
            } else {
                InputBudgets {
                    source: Duration::from_millis(150),
                    toolchain: Duration::from_secs(1),
                    total: Duration::from_secs(1),
                }
            });
            deadline.source_submitted(REQUEST, Instant::now());
            deadline.source_completed(sealed.as_ref().unwrap());
            assert_eq!(journal.admit(&request, timeout).unwrap(), None);
            assert_eq!(journal.status(REQUEST)["status"], "execution-uncertain");
            if cancel_owner {
                assert_eq!(source.cancel(REQUEST), Some(true));
            } else {
                asupersync::time::timeout(
                    asupersync::time::wall_now(),
                    WATCHDOG,
                    poll_fn(|cx| {
                        if deadline.poll_expired(cx) {
                            Poll::Ready(())
                        } else {
                            Poll::Pending
                        }
                    }),
                )
                .await
                .expect("native input timer failed to wake");
            }
            let error = take_execution_inputs(
                &request,
                &mut source,
                &mut toolchain,
                &deadline,
                Some(&mut journal),
            )
            .err()
            .expect("unusable input crossed the production launch boundary");
            if cancel_owner {
                assert!(error.starts_with("source ownership:"));
            } else {
                assert_eq!(error, INPUT_DEADLINE_EXCEEDED);
            }
            let status = journal.status(REQUEST);
            assert_eq!(status["status"], "terminal-observed");
            assert_eq!(status["receipt"]["executed"], false);
            assert_eq!(status["receipt"]["execution_may_have_run"], false);
            assert_eq!(status["receipt"]["stage"], "execution-admission");
            assert_eq!(
                status["receipt"]["reason"],
                if cancel_owner {
                    "execution-inputs-unavailable"
                } else {
                    INPUT_DEADLINE_EXCEEDED
                }
            );
            let saved: Value =
                serde_json::from_slice(&fs::read(root.path().join("requests.json")).unwrap())
                    .unwrap();
            assert_eq!(
                saved["last"]["fingerprint"],
                rabs_wkr::request_journal::request_fingerprint(&request, timeout)
            );
            assert_eq!(saved["last"]["resolved"], true);
            drop(source);
            drop(toolchain);
            assert!(!path.exists(), "prelaunch refusal retained its source tree");
            drop(journal);

            let mut reopened =
                WorkerJournal::open(root.path(), &report.worker_id, "coord").unwrap();
            assert_eq!(reopened.status(REQUEST)["receipt"], status["receipt"]);
            assert_eq!(
                reopened.admit(&request, timeout).unwrap(),
                Some("durable-request-already-admitted")
            );
            let mut newer = request.clone();
            newer["request_id"] = json!(REQUEST + 1);
            assert_eq!(
                reopened.admit(&newer, timeout).unwrap(),
                None,
                "proved prelaunch refusal stranded later work behind an uncertain admission"
            );
        }
    });
}

fn execution_selection(journal: &WorkerJournal, request: &Value) -> ExecutionLeaseSelection {
    let grant = json!({"kind":"session-ok", "session_id":71,
    "execution_lease":{
        "version":REQUEST_EXECUTION_LEASE_VERSION,
        "session_id":71, "lease_id":81, "request_id":REQUEST,
        "request_sha256":rabs_wkr::session::sha256_hex(&serde_json::to_vec(request).unwrap()),
        "boot_generation":journal.boot_generation().0,
        "incarnation":format!("{:032x}", journal.incarnation().0), "ttl_ms":30_000,
    }});
    execution_lease_selection(&grant.to_string(), true, Some(71), journal).unwrap()
}

#[test]
fn handed_off_source_and_toolchain_outlive_the_upload_clock_with_the_managed_child() {
    in_runtime(async {
        let root = private_root();
        let (original, identity) = toolchain_fixture(root.path());
        let report = report();
        let mut journal = WorkerJournal::open(root.path(), &report.worker_id, "coord").unwrap();
        let selected = execution_selection(&journal, &original);
        let private_paths = Arc::new(Mutex::new(None::<(PathBuf, PathBuf)>));
        let observed = Arc::clone(&private_paths);
        let child_started = Arc::new(AtomicBool::new(false));
        let mut wire = Wire::default();
        let peer = wire.clone();
        let mut driver = Box::pin(drive_session_with_input_budgets(
            &mut wire,
            &report,
            true,
            Some(&mut journal),
            false,
            true,
            true,
            false,
            &selected,
            false,
            short_budgets(),
            |request, timeout, artifacts, source, toolchain, lease| {
                assert!(artifacts.is_none());
                assert!(source.is_some() && toolchain.is_some() && lease.is_some());
                let workspace = PathBuf::from(&request.workspace_backing);
                let tree = PathBuf::from(&request.toolchain_backing);
                *observed.lock().unwrap() = Some((workspace.clone(), tree.clone()));
                let started = Arc::clone(&child_started);
                let gate = root.path().join("release-child");
                let spill = root.path().join("spill");
                ExecutionTask::spawn_for_delivery_with_lease(
                    request.request_id,
                    timeout,
                    None,
                    None,
                    lease,
                    move |control| {
                        let _source_owner = source;
                        let _toolchain_owner = toolchain;
                        let mut command = Command::new(tree.join("compiler"));
                        command
                            .env_clear()
                            .env("PATH", "/usr/bin:/bin")
                            .env("GATE", gate)
                            .stdin(Stdio::null())
                            .stdout(Stdio::piped())
                            .stderr(Stdio::piped());
                        let group =
                            ManagedProcessGroup::spawn_command(command, Attribution::default())
                                .unwrap();
                        started.store(true, Ordering::Release);
                        let drained = group
                            .wait_with_bounded_drain_budget(
                                &DrainLimits {
                                    resident_bound: 1024,
                                    spill_dir: spill,
                                },
                                4096,
                                || control.reason().is_some(),
                            )
                            .unwrap();
                        assert_eq!(
                            control.reason(),
                            None,
                            "upload clock cancelled admitted execution"
                        );
                        assert!(drained.status.success());
                        assert_eq!(drained.residual_group_members, 0);
                        assert_eq!(fs::read(workspace.join("src/lib.rs")).unwrap(), SOURCE);
                        assert_eq!(fs::read(tree.join("compiler")).unwrap(), SCRIPT);
                        let outputs =
                            CapturedOutputs::from_lanes(&drained.stdout, &drained.stderr).unwrap();
                        assert_eq!(
                            outputs.stdout.sha256(),
                            rabs_wkr::session::sha256_hex(b"done\n")
                        );
                        rabs_wkr::session::ExecResult {
                            request_id: request.request_id,
                            exit_code: 0,
                            stdout_sha256: outputs.stdout.sha256().to_owned(),
                            stderr_sha256: outputs.stderr.sha256().to_owned(),
                            executed: true,
                            residual_group_members: 0,
                            stdout_spill_bytes: 0,
                            stderr_spill_bytes: 0,
                            stdout_spill_path: None,
                            stderr_spill_path: None,
                        }
                    },
                )
            },
            pressure,
        ));
        upload_source(driver.as_mut(), &peer, &original).await;
        upload_toolchain(driver.as_mut(), &peer, identity).await;
        peer.frame(original);
        observe(driver.as_mut(), || private_paths.lock().unwrap().is_some()).await;
        let start_watchdog = Instant::now();
        while !child_started.load(Ordering::Acquire) {
            // The filesystem/execution owner starts on a joined thread. Yield
            // through the native timer until that actual process has spawned;
            // a queued ExecutionTask alone is insufficient lifetime evidence.
            hold_pending(driver.as_mut(), Duration::from_millis(5)).await;
            assert!(
                start_watchdog.elapsed() < WATCHDOG,
                "managed child did not start"
            );
        }
        // Deliberately exceed even the total input budget after ownership has
        // moved. Execution still has its own 15-second timeout and bound lease.
        hold_pending(driver.as_mut(), Duration::from_millis(3_200)).await;
        let heartbeat = exchange(driver.as_mut(), &peer, json!({"kind":"ping"})).await;
        assert_eq!(heartbeat["active_request_id"], REQUEST);
        assert!(heartbeat["pending_source_request_id"].is_null());
        assert!(heartbeat["pending_toolchain_request_id"].is_null());
        fs::write(root.path().join("release-child"), b"release").unwrap();
        finish(driver).await.unwrap();
        let (workspace, tree) = private_paths.lock().unwrap().clone().unwrap();
        assert!(
            !workspace.exists() && !tree.exists(),
            "completed execution retained private inputs"
        );
        assert_eq!(journal.status(REQUEST)["status"], "terminal-observed");
        let terminal = peer
            .replies()
            .into_iter()
            .find(|reply| reply["kind"] == "exec-result")
            .unwrap();
        assert_eq!(terminal["exit_code"], 0);
        assert!(terminal["stop_reason"].is_null());
    });
}
