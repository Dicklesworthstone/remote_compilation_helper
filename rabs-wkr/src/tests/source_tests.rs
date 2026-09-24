//! Source upload through the production driver and real execution ownership.
//! Executors here are explicit fixtures, not canonical/compiler qualification.

use super::*;
use rabs_sandbox::source_transfer::{SourceFile, SourceManifest};
use rabs_wkr::source_transfer::hex;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const SOURCE: &[u8] = b"source bytes\0\xff";

fn source_request(id: u64) -> Value {
    let file = SourceFile { path:"src/lib.rs".to_owned(), len:SOURCE.len() as u64,
        sha256:Sha256::digest(SOURCE).into(), executable:false };
    let manifest = SourceManifest::new(vec![file]).unwrap();
    let mut request = request(id);
    request.as_object_mut().unwrap().remove("workspace_backing");
    request["source_manifest"] = json!({
        "manifest_sha256":hex(&manifest.digest()),
        "files":[{"path":"src/lib.rs", "bytes":SOURCE.len(),
            "sha256":hex(&Sha256::digest(SOURCE)), "executable":false}],
    });
    request
}

fn begin(request: &Value) -> Value {
    json!({"kind":"source-begin", "request_id":request["request_id"], "manifest":request["source_manifest"]})
}

fn chunk(request: &Value) -> Value {
    json!({"kind":"source-chunk", "request_id":request["request_id"],
        "manifest_sha256":request["source_manifest"]["manifest_sha256"],
        "path":"src/lib.rs", "offset":0, "data_hex":hex(SOURCE),
        "chunk_sha256":hex(&Sha256::digest(SOURCE))})
}

fn seal(request: &Value) -> Value {
    json!({"kind":"source-seal", "request_id":request["request_id"],
        "manifest_sha256":request["source_manifest"]["manifest_sha256"]})
}

fn upload(peer: &Wire, request: &Value) {
    peer.frame(begin(request)); peer.frame(chunk(request)); peer.frame(seal(request));
}

#[test]
fn partial_or_unnegotiated_source_never_burns_execution_admission() {
    for enabled in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let mut journal = WorkerJournal::open(root.path(), "session-test", "coord").unwrap();
        let mut wire = Wire::default(); let peer = wire.clone();
        let request = source_request(1);
        peer.frame(request.clone());
        peer.frame(begin(&request));
        peer.frame(seal(&request));
        peer.frame(request.clone());
        let mut corrupt = chunk(&request); corrupt["chunk_sha256"] = json!("00".repeat(32));
        peer.frame(corrupt);
        peer.frame(json!({"kind":"request-status", "request_id":1}));
        let report = report();
        let lease = ExecutionLeaseSelection::default();
        let mut driver = Box::pin(drive_session_with_sources(&mut wire, &report, false, Some(&mut journal),
            false, enabled, &lease, |_, _, _, _, _| panic!("incomplete input launched"), pressure));
        // Observe all requested refusals before disconnecting. Closing while
        // source I/O is pending now intentionally abandons queued requests.
        pump(driver.as_mut(), &peer, 6);
        peer.close(); wait(driver).unwrap();
        let replies = peer.replies();
        assert_eq!(replies[0]["kind"], "error");
        assert_eq!(replies[2]["kind"], "error");
        assert_eq!(replies[3]["kind"], "error");
        assert_eq!(replies[4]["kind"], "error");
        assert_eq!(replies[5]["status"], "unknown");
        assert_eq!(journal.high_water(), None);
    }
}

#[test]
fn verified_source_is_execution_owned_but_the_original_request_is_journaled() {
    let root = tempfile::tempdir().unwrap();
    let mut journal = WorkerJournal::open(root.path(), "session-test", "coord").unwrap();
    let mut wire = Wire::default(); let peer = wire.clone();
    let original = source_request(2);
    upload(&peer, &original); peer.frame(original.clone());
    let path = Arc::new(Mutex::new(None::<PathBuf>)); let observed = Arc::clone(&path);
    let fingerprint = rabs_wkr::request_journal::request_fingerprint(&original, DEFAULT_EXECUTION_TIMEOUT);
    wait(drive_session_with_sources(&mut wire, &report(), true, Some(&mut journal), false, true,
        &ExecutionLeaseSelection::default(), |request, timeout, artifacts, source, lease| {
            assert!(lease.is_none());
            assert!(artifacts.is_none()); assert!(source.is_some());
            let saved: Value = serde_json::from_slice(&std::fs::read(root.path().join("requests.json")).unwrap()).unwrap();
            assert_eq!(saved["last"]["fingerprint"], fingerprint);
            assert_eq!(saved["last"]["resolved"], false);
            assert_ne!(request.workspace_backing, "/ws");
            *observed.lock().unwrap() = Some(PathBuf::from(&request.workspace_backing));
            ExecutionTask::spawn(request.request_id, timeout, move |_| {
                let _owner = source;
                assert_eq!(std::fs::read(PathBuf::from(&request.workspace_backing).join("src/lib.rs")).unwrap(), SOURCE);
                result(request.request_id)
            })
        }, pressure)).unwrap();
    assert_eq!(journal.status(2)["status"], "terminal-observed");
    assert_eq!(peer.replies().last().unwrap()["kind"], "exec-result");
    assert!(!path.lock().unwrap().as_ref().unwrap().exists(), "source released after execution cleanup");
    assert_eq!(journal.admit(&original, DEFAULT_EXECUTION_TIMEOUT).unwrap(), Some("durable-request-already-admitted"));
    let mut changed = original.clone(); changed["source_manifest"]["files"][0]["executable"] = json!(true);
    assert_eq!(journal.admit(&changed, DEFAULT_EXECUTION_TIMEOUT).unwrap(), Some("durable-request-conflict"));
}

#[test]
fn disconnect_does_not_remove_source_before_the_execution_owner_drains() {
    let root = tempfile::tempdir().unwrap();
    let mut journal = WorkerJournal::open(root.path(), "session-test", "coord").unwrap();
    let mut wire = Wire::default(); let peer = wire.clone();
    let original = source_request(3);
    upload(&peer, &original);
    let cleaned = Arc::new(AtomicBool::new(false)); let observed = Arc::clone(&cleaned);
    let report = report();
    let lease = ExecutionLeaseSelection::default();
    let mut driver = Box::pin(drive_session_with_sources(&mut wire, &report, false, Some(&mut journal), false, true,
        &lease, |request, timeout, _, source, _| {
            let cleaned = Arc::clone(&observed);
            ExecutionTask::spawn(request.request_id, timeout, move |control| {
                let _owner = source;
                while control.reason().is_none() { std::thread::sleep(Duration::from_millis(1)); }
                assert_eq!(control.reason(), Some(StopReason::SessionLost));
                assert_eq!(std::fs::read(PathBuf::from(&request.workspace_backing).join("src/lib.rs")).unwrap(), SOURCE);
                cleaned.store(true, Ordering::Release);
                result(request.request_id)
            })
        }, pressure));
    pump(driver.as_mut(), &peer, 3);
    peer.frame(original); peer.frame(json!({"kind":"ping"}));
    pump(driver.as_mut(), &peer, 4);
    assert_eq!(peer.replies()[3]["active_request_id"], 3, "disconnect must exercise an admitted execution");
    peer.close(); wait(driver).unwrap();
    assert!(cleaned.load(Ordering::Acquire));
    assert_eq!(journal.status(3)["receipt"]["stop_reason"], "session-lost");
}

#[test]
fn resumed_source_bound_results_need_no_worker_source_directory_or_new_upload() {
    let root = tempfile::tempdir().unwrap();
    let mut journal = WorkerJournal::open(root.path(), "session-test", "coord").unwrap();
    let mut wire = Wire::default(); let peer = wire.clone(); let report = report();
    let original = source_request(4);
    upload(&peer, &original); peer.frame(original.clone());
    let path = Arc::new(Mutex::new(None::<PathBuf>)); let observed = Arc::clone(&path);
    let lease = ExecutionLeaseSelection::default();
    let mut driver = Box::pin(drive_session_with_sources(&mut wire, &report, false, Some(&mut journal), false, true,
        &lease, |request, timeout, _, source, _| {
            *observed.lock().unwrap() = Some(PathBuf::from(&request.workspace_backing));
            let target = RetentionTarget::from_admitted(root.path(), request.request_id, ResultRecipient::TlsSpki([7; 32]))?;
            ExecutionTask::spawn_for_delivery(request.request_id, timeout, None, Some(target), move |control| {
                let _owner = source;
                let bytes = std::fs::read(PathBuf::from(&request.workspace_backing).join("src/lib.rs")).unwrap();
                let outputs = CapturedOutputs {
                    stdout:rabs_wkr::output::CapturedStream::from_reader(&bytes[..], bytes.len() as u64).unwrap(),
                    stderr:rabs_wkr::output::CapturedStream::from_reader(&b""[..], 0).unwrap(),
                };
                let mut result = result(request.request_id);
                result.stdout_sha256 = outputs.stdout.sha256().to_owned();
                result.stderr_sha256 = outputs.stderr.sha256().to_owned();
                control.retain_outputs(Ok(outputs)).unwrap(); result
            })
        }, pressure));
    pump(driver.as_mut(), &peer, 4);
    peer.close(); wait(driver).unwrap();
    assert!(!path.lock().unwrap().as_ref().unwrap().exists());
    journal.prepare_reconnect().unwrap();
    journal.authorize_result_recipient(ResultRecipient::TlsSpki([7; 32]));
    let mut next = Wire::default(); let peer = next.clone();
    peer.frame(json!({"kind":"result-resume", "request_id":4, "request":original}));
    let mut driver = Box::pin(drive_session_with_sources(&mut next, &report, true, Some(&mut journal), false, false,
        &lease, |_, _, _, _, _| panic!("resumption must not launch or require source reupload"), pressure));
    pump(driver.as_mut(), &peer, 1);
    assert_eq!(peer.replies()[0]["resumed"], true);
    peer.frame(output_read(4, "stdout", 0, 64)); pump(driver.as_mut(), &peer, 2);
    assert_eq!(peer.replies()[1]["data_hex"], hex(SOURCE));
    peer.frame(json!({"kind":"output-ack", "request_id":4,
        "stdout_sha256":hex(&Sha256::digest(SOURCE)), "stderr_sha256":hex(&Sha256::digest(b"")),
        "stdout_bytes":SOURCE.len(), "stderr_bytes":0}));
    wait(driver).unwrap();
    assert!(!journal.has_retained_result());
    assert_eq!(journal.high_water(), Some(4));
}

#[test]
fn pipelined_source_frames_finish_in_order_and_controls_can_interleave() {
    let root = tempfile::tempdir().unwrap();
    let mut journal = WorkerJournal::open(root.path(), "session-test", "coord").unwrap();
    let mut wire = Wire::default(); let peer = wire.clone(); let report = report();
    let original = source_request(10);
    peer.frame(begin(&original));
    peer.frame(chunk(&original));
    peer.frame(json!({"kind":"ping"}));
    peer.frame(seal(&original));
    peer.frame(json!({"kind":"request-status", "request_id":10}));
    let lease = ExecutionLeaseSelection::default();
    let mut driver = Box::pin(drive_session_with_sources(&mut wire, &report, false, Some(&mut journal),
        false, true, &lease, |_, _, _, _, _| panic!("upload is not execution admission"), pressure));
    pump(driver.as_mut(), &peer, 5);
    peer.close(); wait(driver).unwrap();
    let replies = peer.replies();
    let control: Vec<_> = replies.iter().filter(|reply| reply["kind"] == "heartbeat").collect();
    assert_eq!(control.len(), 1);
    assert!(control[0]["active_request_id"].is_null());
    assert_eq!(control[0]["pending_source_request_id"], 10);
    let ordered: Vec<_> = replies.iter().filter(|reply| reply["kind"] != "heartbeat").collect();
    assert_eq!(ordered.len(), 4);
    assert_eq!(ordered[0]["kind"], "source-ready"); assert_eq!(ordered[0]["sealed"], false);
    assert_eq!(ordered[1]["kind"], "source-chunk-accepted");
    assert_eq!(ordered[1]["next_offset"], SOURCE.len());
    assert_eq!(ordered[2]["kind"], "source-ready"); assert_eq!(ordered[2]["sealed"], true);
    assert_eq!(ordered[3]["status"], "unknown");
    assert!(journal.high_water().is_none());
}

#[test]
fn cancelling_a_sealed_upload_is_exact_id_idempotent_and_prevents_admission() {
    let root = tempfile::tempdir().unwrap();
    let mut journal = WorkerJournal::open(root.path(), "session-test", "coord").unwrap();
    let mut wire = Wire::default(); let peer = wire.clone(); let report = report();
    let original = source_request(11);
    upload(&peer, &original);
    let lease = ExecutionLeaseSelection::default();
    let mut driver = Box::pin(drive_session_with_sources(&mut wire, &report, false, Some(&mut journal),
        false, true, &lease, |_, _, _, _, _| panic!("cancelled source reached durable execution admission"), pressure));
    pump(driver.as_mut(), &peer, 3);
    assert_eq!(peer.replies()[2]["sealed"], true);
    peer.frame(json!({"kind":"cancel", "request_id":12}));
    peer.frame(json!({"kind":"cancel", "request_id":11}));
    peer.frame(json!({"kind":"cancel", "request_id":11}));
    peer.frame(original.clone());
    peer.frame(begin(&original));
    peer.frame(json!({"kind":"request-status", "request_id":11}));
    peer.frame(json!({"kind":"ping"}));
    pump(driver.as_mut(), &peer, 10);
    peer.close(); wait(driver).unwrap();
    let replies = peer.replies();
    assert_eq!(replies[3]["reason"], "unknown-request");
    assert_eq!(replies[4]["kind"], "cancel-accepted");
    assert_eq!(replies[4]["request_id"], 11);
    assert_eq!(replies[4]["stage"], "source-upload");
    assert_eq!(replies[4]["accepted"], true);
    assert_eq!(replies[5]["accepted"], false);
    assert_eq!(replies[6]["kind"], "error");
    assert_eq!(replies[7]["reason"], "source upload cancelled");
    assert_eq!(replies[8]["status"], "unknown");
    assert_eq!(replies[9]["kind"], "heartbeat");
    assert!(replies[9]["active_request_id"].is_null());
    assert!(journal.high_water().is_none());
}

#[test]
fn source_completion_wakes_a_partial_control_frame_without_losing_bytes() {
    let mut wire = Wire::default(); let peer = wire.clone(); peer.bytes(b"{\"kind\":");
    let mut source = SourceTransferTask::default();
    source.submit(&begin(&source_request(12)), true, false).unwrap();
    let mut reader = FrameReader::default(); let mut deferred = DeferredFrames::default();
    let mut active = None;
    let mut toolchain = ToolchainTransferTask::default();
    match wait(next_event(&mut reader, &mut wire, &mut active, &mut source, &mut toolchain, &mut deferred)) {
        SessionEvent::SourceCompleted(result) => {
            let completed = (*result).unwrap();
            assert_eq!(completed.request_id, 12);
            assert_eq!(completed.response.unwrap()["sealed"], false);
        }
        _ => panic!("source completion was lost while the control frame was incomplete"),
    }
    peer.bytes(b"\"ping\"}\n");
    assert_eq!(wait(reader.read(&mut wire)).unwrap(), Some("{\"kind\":\"ping\"}".to_owned()));
}

#[test]
fn source_pipeline_bounds_count_and_bytes_without_mutating_on_refusal() {
    let mut queue = DeferredFrames::default();
    for n in 0..DeferredFrames::MAX_FRAMES {
        queue.push(n.to_string()).unwrap();
    }
    let bytes = queue.bytes;
    assert_eq!(queue.push("overflow".to_owned()).unwrap_err(), "source-pipeline-limit");
    assert_eq!(queue.bytes, bytes);
    for n in 0..DeferredFrames::MAX_FRAMES { assert_eq!(queue.pop().unwrap(), n.to_string()); }
    assert!(queue.pop().is_none()); assert_eq!(queue.bytes, 0);

    let frame = "x".repeat(MAX_FRAME_BYTES);
    queue.push(frame.clone()).unwrap(); queue.push(frame.clone()).unwrap();
    assert_eq!(queue.bytes, DeferredFrames::MAX_BYTES);
    assert!(queue.push("x".to_owned()).is_err());
    assert_eq!(queue.pop().unwrap(), frame);
    assert_eq!(queue.pop().unwrap(), frame);
    assert_eq!(queue.bytes, 0);
    assert!(queue.push("x".repeat(MAX_FRAME_BYTES + 1)).is_err());
    assert!(queue.frames.is_empty());
}
