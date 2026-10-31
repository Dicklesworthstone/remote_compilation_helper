//! The production result receiver over real Unix sockets and private files.
//!
//! Transport authentication facts are supplied by this protocol fixture. These
//! tests qualify receiver sequencing and byte verification, not TLS admission,
//! compiler execution, coordinator publication or a native Cargo build.

#![cfg(unix)]

use rabsd::coord::worker_delivery::{
    ArtifactByteCache, ArtifactCachePeer, CHUNK_BYTES, Delivery, DeliveryFailure, DeliveryMode,
    MAX_FRAME_BYTES, ResumePeer, ResumeSource, SealedResult, WorkerAuthentication, WorkerPeer,
    receive_operation, worker_transport_error,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::io::{self, BufRead, BufReader, Write};
use std::net::Shutdown;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

const STDOUT: &[u8] = b"diagnostic\0\xff";
const STDERR: &[u8] = b"compiler warning\n";
const ARTIFACT: &[u8] = b"A\0\xffB";

fn hash(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn field(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

fn artifact_manifest(bytes: &[u8], executable: bool) -> Value {
    let sha256 = hash(bytes);
    let mut hasher = Sha256::new();
    field(&mut hasher, b"rabs.worker-artifact-manifest.v1");
    field(&mut hasher, b"dep");
    hasher.update(1_u64.to_be_bytes());
    field(&mut hasher, b"a");
    hasher.update([u8::from(executable)]);
    hasher.update((bytes.len() as u64).to_be_bytes());
    field(&mut hasher, sha256.as_bytes());
    let manifest_sha256: String = hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    json!({
        "unit":"dep", "files":[{"name":"a", "bytes":bytes.len(),
        "sha256":sha256, "executable":executable}],
        "total_bytes":bytes.len(), "manifest_sha256":manifest_sha256,
    })
}

fn request() -> Value {
    json!({
        "kind":"canonical-exec", "request_id":7, "program":"rustc", "args":["lib.rs"],
        "toolchain_backing":"/tc", "workspace_backing":"/ws",
        "artifacts":{"unit":"dep", "files":["a"]},
    })
}

fn authentication(session_id: u64) -> WorkerAuthentication {
    WorkerAuthentication {
        spki_sha256: [0x42; 32],
        session_id,
        identity_generation: 1,
    }
}

#[derive(Clone, Copy)]
enum Ending {
    BeforeResult,
    AfterResult,
    Complete,
    CorruptArtifact,
    LostAcknowledgment,
}

struct Session {
    hello: Value,
    result: Value,
    ending: Ending,
    stdout_collision: Option<PathBuf>,
}

impl Session {
    fn new(resumed: bool, ending: Ending) -> Self {
        let mut result = json!({
            "kind":"exec-result", "request_id":7, "executed":true, "exit_code":0,
            "residual_group_members":0, "stop_reason":null,
            "output_transfer":"ranges-v1", "output_ack_required":true,
            "stdout_bytes":STDOUT.len(), "stdout_sha256":hash(STDOUT),
            "stderr_bytes":STDERR.len(), "stderr_sha256":hash(STDERR),
            "artifact_transfer":"files-v1", "artifact_ack_required":true,
            "artifact_manifest":artifact_manifest(ARTIFACT, false),
            "result_retention":"durable-result-v1",
            "retained_result_sha256":hash(b"retained successful result"),
        });
        if resumed {
            result["resumed"] = json!(true);
        }
        Self {
            hello: json!({
                "kind":"worker-hello", "worker_id":"worker", "canonical":true, "slots":4,
                "boot_generation":1, "incarnation":"00000000000000000000000000000001",
                "request_high_water":if resumed { json!(7) } else { Value::Null },
                "recovery_protocols":["request-journal-v1"], "output_transfers":["ranges-v1"],
                "artifact_transfers":["files-v1"], "result_retentions":["durable-result-v1"],
            }),
            result,
            ending,
            stdout_collision: None,
        }
    }
}

fn read_frame(reader: &mut BufReader<UnixStream>) -> io::Result<Value> {
    let mut bytes = Vec::new();
    if reader
        .read_until(b'\n', &mut bytes)
        .map_err(worker_transport_error)?
        == 0
    {
        return Err(worker_transport_error(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "socket closed",
        )));
    }
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame too large",
        ));
    }
    serde_json::from_slice(&bytes).map_err(io::Error::other)
}

fn write_frame(stream: &mut UnixStream, frame: &Value) -> io::Result<()> {
    let mut bytes = serde_json::to_vec(frame)?;
    bytes.push(b'\n');
    stream.write_all(&bytes).map_err(worker_transport_error)?;
    stream.flush().map_err(worker_transport_error)
}

fn respond_range(frame: &Value, result: &Value) -> Value {
    let artifact = frame["kind"] == "artifact-read";
    let (name, bytes) = if artifact {
        ("a", ARTIFACT)
    } else if frame["stream"] == "stdout" {
        ("stdout", STDOUT)
    } else {
        ("stderr", STDERR)
    };
    let offset = usize::try_from(frame["offset"].as_u64().unwrap()).unwrap();
    let end = bytes.len().min(offset + CHUNK_BYTES);
    let chunk = &bytes[offset..end];
    let mut response = json!({
        "kind":if artifact {"artifact-chunk"} else {"output-chunk"}, "request_id":7,
        "offset":offset, "next_offset":end, "total_bytes":bytes.len(),
        "sha256":hash(bytes), "chunk_sha256":hash(chunk), "eof":end == bytes.len(),
        "data_hex":chunk.iter().map(|byte| format!("{byte:02x}")).collect::<String>(),
    });
    response[if artifact { "name" } else { "stream" }] = json!(name);
    if artifact {
        response["manifest_sha256"] = result["artifact_manifest"]["manifest_sha256"].clone();
        response["executable"] = json!(false);
    }
    response
}

fn serve(stream: UnixStream, session: Session) -> Vec<Value> {
    let mut reader = BufReader::new(stream);
    let mut frames = Vec::new();
    if write_frame(reader.get_mut(), &session.hello).is_err() {
        return frames;
    }
    for _ in 0..2 {
        let Ok(frame) = read_frame(&mut reader) else {
            return frames;
        };
        frames.push(frame);
    }
    if matches!(session.ending, Ending::BeforeResult) {
        return frames;
    }
    if let Some(collision) = session.stdout_collision {
        std::fs::create_dir(collision).unwrap();
    }
    if write_frame(reader.get_mut(), &session.result).is_err()
        || matches!(session.ending, Ending::AfterResult)
    {
        return frames;
    }
    while let Ok(frame) = read_frame(&mut reader) {
        frames.push(frame.clone());
        let response = match frame["kind"].as_str() {
            Some("output-read" | "artifact-read") => {
                let mut response = respond_range(&frame, &session.result);
                if matches!(session.ending, Ending::CorruptArtifact)
                    && frame["kind"] == "artifact-read"
                {
                    response["chunk_sha256"] = json!(hash(b"corrupt"));
                }
                response
            }
            Some("output-ack" | "artifact-ack") => {
                if matches!(session.ending, Ending::LostAcknowledgment) {
                    break;
                }
                json!({
                    "kind":if frame["kind"] == "output-ack" {
                        "output-acknowledged"
                    } else {
                        "artifact-acknowledged"
                    },
                    "request_id":7, "already_released":false,
                })
            }
            _ => break,
        };
        if write_frame(reader.get_mut(), &response).is_err() || frame["kind"] == "artifact-ack" {
            break;
        }
    }
    frames
}

struct SocketPeer {
    reader: BufReader<UnixStream>,
    authentication: Option<WorkerAuthentication>,
    negotiated: bool,
    deadline: Option<Instant>,
    continuation: Option<SealedResult>,
}

impl WorkerPeer for SocketPeer {
    fn send(&mut self, frame: &Value) -> io::Result<()> {
        self.checkpoint()?;
        write_frame(self.reader.get_mut(), frame)
    }

    fn receive(&mut self) -> io::Result<Value> {
        self.checkpoint()?;
        read_frame(&mut self.reader)
    }

    fn negotiate(&mut self, _hello: &Value, grant: &Value) -> io::Result<()> {
        self.send(grant)?;
        self.negotiated = true;
        Ok(())
    }

    fn authentication(&self) -> Option<WorkerAuthentication> {
        self.negotiated.then_some(self.authentication).flatten()
    }

    fn transfer_deadline(&self) -> Option<Instant> {
        self.deadline
    }

    fn live_continuation(&self) -> Option<&SealedResult> {
        self.continuation.as_ref()
    }

    fn checkpoint(&mut self) -> io::Result<()> {
        if self
            .deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "original deadline"));
        }
        Ok(())
    }
}

fn start(session: Session) -> (SocketPeer, JoinHandle<Vec<Value>>) {
    let (client, server) = UnixStream::pair().unwrap();
    for stream in [&client, &server] {
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(3)))
            .unwrap();
    }
    let server = std::thread::spawn(move || serve(server, session));
    (
        SocketPeer {
            reader: BufReader::new(client),
            authentication: Some(authentication(41)),
            negotiated: false,
            deadline: Some(Instant::now() + Duration::from_secs(30)),
            continuation: None,
        },
        server,
    )
}

fn finish(peer: SocketPeer, server: JoinHandle<Vec<Value>>) -> Vec<Value> {
    let _ = peer.reader.get_ref().shutdown(Shutdown::Both);
    drop(peer);
    server.join().unwrap()
}

fn interrupted(owner: &Path, name: &str) -> (SealedResult, Vec<Value>) {
    let (mut peer, server) = start(Session::new(false, Ending::AfterResult));
    let deadline = peer.deadline.unwrap();
    let failure = receive_operation(
        &mut peer,
        &request(),
        "worker",
        &owner.join(name),
        DeliveryMode::Execute,
    )
    .unwrap_err();
    assert!(failure.execution_may_have_run);
    assert!(failure.transport_interrupted, "{}", failure.detail);
    let evidence = *failure.sealed_result.expect("authenticated sealed header");
    assert_eq!(evidence.deadline(), deadline);
    (evidence, finish(peer, server))
}

fn count(frames: &[Value], kind: &str) -> usize {
    frames.iter().filter(|frame| frame["kind"] == kind).count()
}

fn no_data_or_ack(frames: &[Value]) {
    for kind in ["output-read", "artifact-read", "output-ack", "artifact-ack"] {
        assert_eq!(count(frames, kind), 0, "unexpected {kind}: {frames:?}");
    }
}

fn resume(
    evidence: &SealedResult,
    session: Session,
    destination: &Path,
) -> (Result<Delivery, DeliveryFailure>, Vec<Value>) {
    let (mut peer, server) = start(session);
    peer.authentication = Some(authentication(42));
    peer.deadline = Some(evidence.deadline());
    peer.continuation = Some(evidence.clone());
    let result = receive_operation(
        &mut peer,
        &request(),
        "worker",
        destination,
        DeliveryMode::Resume,
    );
    (result, finish(peer, server))
}

#[test]
fn interrupted_sealed_result_continues_without_another_execution() {
    let owner = tempfile::tempdir().unwrap();
    let (evidence, initial_frames) = interrupted(owner.path(), "first");
    assert_eq!(count(&initial_frames, "canonical-exec"), 1);
    assert_eq!(count(&initial_frames, "output-ack"), 0);
    let (result, frames) = resume(
        &evidence,
        Session::new(true, Ending::Complete),
        &owner.path().join("continued"),
    );
    let delivery = result.unwrap();
    evidence.verify_delivery(&delivery, &request()).unwrap();
    assert!(delivery.acknowledgments_confirmed);
    assert_eq!(count(&frames, "result-resume"), 1);
    assert_eq!(count(&frames, "canonical-exec"), 0);
    assert_eq!(count(&frames, "source-begin"), 0);
    assert_eq!(count(&frames, "output-ack"), 1);
    assert_eq!(count(&frames, "artifact-ack"), 1);
    assert_eq!(
        std::fs::read(delivery.directory.join("diagnostics/stdout")).unwrap(),
        STDOUT
    );
    assert_eq!(
        std::fs::read(delivery.directory.join("diagnostics/stderr")).unwrap(),
        STDERR
    );
    assert_eq!(
        std::fs::read(delivery.directory.join("artifacts/a")).unwrap(),
        ARTIFACT
    );
    assert_eq!(
        delivery.receipt["worker_identity_scope"],
        "delivery-session"
    );
    assert!(delivery.receipt["execution_boot_generation"].is_null());
    assert_eq!(delivery.receipt["publication_authorized"], false);
}

#[test]
fn incomplete_unauthenticated_failed_or_unsealed_results_cannot_create_evidence() {
    for case in 0..8 {
        let owner = tempfile::tempdir().unwrap();
        let mut session = Session::new(false, Ending::AfterResult);
        match case {
            0 => session.ending = Ending::BeforeResult,
            1 => {
                session.hello["result_retentions"] = json!([]);
                session
                    .result
                    .as_object_mut()
                    .unwrap()
                    .remove("result_retention");
                session
                    .result
                    .as_object_mut()
                    .unwrap()
                    .remove("retained_result_sha256");
            }
            2 => {
                session.result["exit_code"] = json!(1);
                session.result["artifact_manifest"] = Value::Null;
                session.result["artifact_ack_required"] = json!(false);
            }
            3 => session.result["residual_group_members"] = json!(1),
            4 => session.result["artifact_manifest"]["manifest_sha256"] = json!(hash(b"wrong")),
            5 => session.result["resumed"] = json!(true),
            _ => {}
        }
        let (mut peer, server) = start(session);
        if case == 6 {
            peer.authentication = None;
        }
        if case == 7 {
            peer.deadline = None;
        }
        let failure = receive_operation(
            &mut peer,
            &request(),
            "worker",
            &owner.path().join("attempt"),
            DeliveryMode::Execute,
        )
        .unwrap_err();
        assert!(failure.sealed_result.is_none(), "case {case}");
        let frames = finish(peer, server);
        assert_eq!(count(&frames, "output-ack"), 0);
        assert_eq!(count(&frames, "artifact-ack"), 0);
    }
}

#[test]
fn restarted_or_different_worker_is_refused_before_result_resume() {
    let owner = tempfile::tempdir().unwrap();
    let (evidence, _) = interrupted(owner.path(), "original");
    for case in 0..5 {
        let mut session = Session::new(true, Ending::Complete);
        match case {
            0 => session.hello["boot_generation"] = json!(2),
            1 => session.hello["incarnation"] = json!("00000000000000000000000000000002"),
            2 => session.hello["request_high_water"] = json!(8),
            _ => {}
        }
        let (mut peer, server) = start(session);
        peer.deadline = Some(evidence.deadline());
        peer.continuation = Some(evidence.clone());
        if case == 3 {
            peer.authentication.as_mut().unwrap().spki_sha256 = [0x43; 32];
        }
        if case == 4 {
            peer.authentication.as_mut().unwrap().identity_generation = 2;
        }
        let failure = receive_operation(
            &mut peer,
            &request(),
            "worker",
            &owner.path().join(format!("continued-{case}")),
            DeliveryMode::Resume,
        )
        .unwrap_err();
        assert!(!failure.transport_interrupted, "{}", failure.detail);
        assert!(failure.sealed_result.is_none());
        let frames = finish(peer, server);
        assert_eq!(count(&frames, "result-resume"), 0, "case {case}");
        no_data_or_ack(&frames);
    }
}

#[test]
fn changed_sealed_output_identity_is_refused_before_ranges_and_ack() {
    let owner = tempfile::tempdir().unwrap();
    let (evidence, _) = interrupted(owner.path(), "original");
    for case in 0..7 {
        let mut session = Session::new(true, Ending::Complete);
        match case {
            0 => session.result["retained_result_sha256"] = json!(hash(b"other result")),
            1 => session.result["stdout_sha256"] = json!(hash(b"changed output")),
            2 => session.result["stdout_bytes"] = json!(STDOUT.len() + 1),
            3 => session.result["stderr_sha256"] = json!(hash(b"changed diagnostic")),
            4 => session.result["artifact_manifest"] = artifact_manifest(b"replacement", false),
            5 => session.result["artifact_manifest"] = artifact_manifest(ARTIFACT, true),
            _ => {
                session.result["exit_code"] = json!(1);
                session.result["artifact_manifest"] = Value::Null;
                session.result["artifact_ack_required"] = json!(false);
            }
        }
        let destination = owner.path().join(format!("continued-{case}"));
        let (result, frames) = resume(&evidence, session, &destination);
        let failure = result.unwrap_err();
        assert!(!failure.transport_interrupted, "{}", failure.detail);
        assert!(failure.sealed_result.is_none());
        assert_eq!(count(&frames, "result-resume"), 1);
        no_data_or_ack(&frames);
        assert!(!destination.join("diagnostics/stdout").exists());
        assert!(!destination.join("delivery.json").exists());
    }
}

#[test]
fn filesystem_and_corrupt_byte_failures_do_not_become_transport_interruptions() {
    for filesystem_collision in [false, true] {
        let owner = tempfile::tempdir().unwrap();
        let destination = owner.path().join("attempt");
        let mut session = Session::new(false, Ending::CorruptArtifact);
        if filesystem_collision {
            session.stdout_collision = Some(destination.join("diagnostics/stdout"));
        }
        let (mut peer, server) = start(session);
        let failure = receive_operation(
            &mut peer,
            &request(),
            "worker",
            &destination,
            DeliveryMode::Execute,
        )
        .unwrap_err();
        assert!(failure.sealed_result.is_some());
        assert!(!failure.transport_interrupted, "{}", failure.detail);
        let frames = finish(peer, server);
        assert_eq!(count(&frames, "output-ack"), 0);
        assert_eq!(count(&frames, "artifact-ack"), 0);
        assert!(!destination.join("delivery.json").exists());
    }
}

#[test]
fn generic_resume_never_mints_live_execution_evidence() {
    let owner = tempfile::tempdir().unwrap();
    let (mut peer, server) = start(Session::new(true, Ending::AfterResult));
    let failure = receive_operation(
        &mut peer,
        &request(),
        "worker",
        &owner.path().join("resume"),
        DeliveryMode::Resume,
    )
    .unwrap_err();
    assert!(failure.transport_interrupted);
    assert!(failure.sealed_result.is_none());
    let frames = finish(peer, server);
    assert_eq!(count(&frames, "result-resume"), 1);
    assert_eq!(count(&frames, "canonical-exec"), 0);
}

#[test]
fn lost_acknowledgment_keeps_verified_delivery_and_original_identity() {
    let owner = tempfile::tempdir().unwrap();
    let (evidence, _) = interrupted(owner.path(), "original");
    let (result, frames) = resume(
        &evidence,
        Session::new(true, Ending::LostAcknowledgment),
        &owner.path().join("continued"),
    );
    let delivery = result.unwrap();
    evidence.verify_delivery(&delivery, &request()).unwrap();
    assert!(!delivery.acknowledgments_confirmed);
    assert!(delivery.acknowledgment_interrupted);
    assert!(delivery.directory.join("delivery.json").is_file());
    assert_eq!(count(&frames, "result-resume"), 1);
    assert_eq!(count(&frames, "output-ack"), 1);
    assert_eq!(count(&frames, "artifact-ack"), 0);
    assert_eq!(count(&frames, "canonical-exec"), 0);
}

#[test]
fn live_evidence_rejects_changed_requests_and_new_execution_before_io() {
    let owner = tempfile::tempdir().unwrap();
    let (evidence, _) = interrupted(owner.path(), "original");
    for mode in [DeliveryMode::Resume, DeliveryMode::Execute] {
        let (mut peer, server) = start(Session::new(true, Ending::Complete));
        peer.continuation = Some(evidence.clone());
        let mut selected = request();
        if mode == DeliveryMode::Resume {
            selected["args"] = json!(["another.rs"]);
        }
        let destination = owner.path().join(format!("refused-{mode:?}"));
        let failure =
            receive_operation(&mut peer, &selected, "worker", &destination, mode).unwrap_err();
        assert!(failure.sealed_result.is_none());
        assert!(!failure.transport_interrupted);
        assert!(!destination.exists());
        let frames = finish(peer, server);
        assert!(frames.is_empty());
    }
}

#[test]
fn reconnect_cannot_refresh_the_original_transfer_deadline() {
    let owner = tempfile::tempdir().unwrap();
    let (mut peer, server) = start(Session::new(false, Ending::AfterResult));
    let deadline = Instant::now() + Duration::from_secs(2);
    peer.deadline = Some(deadline);
    let failure = receive_operation(
        &mut peer,
        &request(),
        "worker",
        &owner.path().join("original"),
        DeliveryMode::Execute,
    )
    .unwrap_err();
    let evidence = *failure.sealed_result.expect("sealed terminal result");
    finish(peer, server);
    assert_eq!(evidence.deadline(), deadline);
    std::thread::sleep(deadline.saturating_duration_since(Instant::now()));
    assert_eq!(
        evidence.verify_request(&request()).unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );

    let (mut peer, server) = start(Session::new(true, Ending::Complete));
    assert!(peer.deadline.unwrap() > deadline);
    peer.continuation = Some(evidence);
    let destination = owner.path().join("refused");
    let failure = receive_operation(
        &mut peer,
        &request(),
        "worker",
        &destination,
        DeliveryMode::Resume,
    )
    .unwrap_err();
    assert!(failure.detail.contains("original transfer deadline"));
    assert!(!failure.transport_interrupted);
    assert!(failure.sealed_result.is_none());
    assert!(!destination.exists());
    assert!(finish(peer, server).is_empty());
}

#[test]
fn byte_hint_wrappers_preserve_live_evidence_and_original_deadline() {
    let owner = tempfile::tempdir().unwrap();
    let (evidence, _) = interrupted(owner.path(), "original");
    let source = ResumeSource::open(owner.path()).unwrap();
    let cache_parent = owner.path().join("cache");
    std::fs::create_dir(&cache_parent).unwrap();
    std::fs::set_permissions(&cache_parent, std::fs::Permissions::from_mode(0o700)).unwrap();
    let cache = ArtifactByteCache::open(&cache_parent, 1_048_576, 16).unwrap();
    let (mut peer, server) = start(Session::new(true, Ending::BeforeResult));
    peer.continuation = Some(evidence.clone());
    peer.deadline = Some(evidence.deadline());
    let mut cached = ArtifactCachePeer::new(&mut peer, &cache);
    let resumed = ResumePeer::new(&mut cached, &source);
    assert_eq!(resumed.transfer_deadline(), Some(evidence.deadline()));
    assert_eq!(
        resumed.live_continuation().unwrap().deadline(),
        evidence.deadline()
    );
    finish(peer, server);
}
