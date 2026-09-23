//! Drive the real delivery receiver, including prefix recovery and release ACKs.
//! The peer is scripted. These tests prove bounded protocol ordering and byte
//! verification, not throughput, TLS, compiler execution or fleet qualification.
#![cfg(unix)]

use rabsd::coord::delivery_recovery::{DeliveryTrust, recover_existing_delivery};
use rabsd::coord::worker_delivery::{
    CHUNK_BYTES, DeliveryMode, ResumePeer, ResumeSource, WorkerPeer, receive_operation,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, VecDeque};
use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn hash(bytes: &[u8]) -> String { hex(&Sha256::digest(bytes)) }
fn binary(len: usize) -> Vec<u8> { (0..len).map(|index| (index % 251) as u8).collect() }
fn field(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

#[derive(Clone, Copy, Default)]
enum Fault {
    #[default]
    None,
    ForeignFirstChunk,
    ReverseFirstBatch,
    WrongFirstEof,
    ValidChunkWrongFileHash,
    TimeoutSecondChunk,
    FailThirdWrite,
}

struct Peer {
    destination: PathBuf,
    request: Value,
    result: Value,
    files: BTreeMap<String, Vec<u8>>,
    replies: VecDeque<Value>,
    sent: Vec<Value>,
    scheduled: BTreeMap<String, usize>,
    pending: usize,
    maximum_pending: usize,
    draining: bool,
    batches: Vec<usize>,
    range_writes: usize,
    chunk_reads: usize,
    acknowledgments: usize,
    fault: Fault,
}

impl Peer {
    fn new(destination: &Path, stdout_len: usize, mode: DeliveryMode) -> Self {
        let files: BTreeMap<String, Vec<u8>> = BTreeMap::from([
            ("diagnostics/stdout".into(), binary(stdout_len)),
            ("diagnostics/stderr".into(), Vec::new()),
            ("artifacts/bin/app".into(), binary(5 * CHUNK_BYTES + 7)),
            ("artifacts/deps/lib.rlib".into(), b"dependency\0\xff".to_vec()),
        ]);
        let mut manifest_hash = Sha256::new();
        field(&mut manifest_hash, b"rabs.worker-artifact-manifest.v1");
        field(&mut manifest_hash, b"build");
        manifest_hash.update(2_u64.to_be_bytes());
        let mut rows = Vec::new();
        let mut total = 0_usize;
        for (path, bytes) in &files {
            let Some(name) = path.strip_prefix("artifacts/") else { continue; };
            let executable = name == "bin/app";
            let digest = hash(bytes);
            field(&mut manifest_hash, name.as_bytes());
            manifest_hash.update([u8::from(executable)]);
            manifest_hash.update((bytes.len() as u64).to_be_bytes());
            field(&mut manifest_hash, digest.as_bytes());
            total += bytes.len();
            rows.push(json!({"name":name, "bytes":bytes.len(), "sha256":digest, "executable":executable}));
        }
        let manifest = json!({"unit":"build", "files":rows, "total_bytes":total,
            "manifest_sha256":hex(&manifest_hash.finalize())});
        let request = json!({"kind":"canonical-exec", "request_id":7,
            "program":"rustc", "args":["lib.rs"], "workspace_backing":"/ws",
            "toolchain_backing":"/tc", "artifacts":{"unit":"build",
                "tree":"tree-files-v1", "files":["bin/app"]}});
        let mut result = json!({"kind":"exec-result", "request_id":7, "executed":true,
            "exit_code":0, "stop_reason":null, "residual_group_members":0,
            "output_transfer":"ranges-v1", "output_ack_required":true,
            "stdout_bytes":stdout_len, "stdout_sha256":hash(&files["diagnostics/stdout"]),
            "stderr_bytes":0, "stderr_sha256":hash(&[]),
            "artifact_transfer":"files-v1", "artifact_ack_required":true,
            "artifact_manifest":manifest, "result_retention":"durable-result-v1",
            "retained_result_sha256":hash(b"one immutable result")});
        if mode == DeliveryMode::Resume { result["resumed"] = json!(true); }
        let hello = json!({"kind":"worker-hello", "worker_id":"worker",
            "canonical":true, "slots":1, "boot_generation":2,
            "incarnation":"00000000000000000000000000000002",
            "request_high_water":if mode == DeliveryMode::Resume {json!(7)} else {Value::Null},
            "recovery_protocols":["request-journal-v1"], "result_retentions":["durable-result-v1"],
            "output_transfers":["ranges-v1"], "artifact_transfers":["files-v1"]});
        Self {
            destination:destination.to_path_buf(), request, result, files,
            replies:VecDeque::from([hello]), sent:Vec::new(), scheduled:BTreeMap::new(),
            pending:0, maximum_pending:0, draining:false, batches:Vec::new(),
            range_writes:0, chunk_reads:0, acknowledgments:0, fault:Fault::None,
        }
    }

    fn delivered_bytes(&self) {
        for (name, bytes) in &self.files {
            assert_eq!(fs::read(self.destination.join(name)).unwrap(), *bytes);
        }
        let marker: Value = serde_json::from_slice(&fs::read(self.destination.join("delivery.json")).unwrap()).unwrap();
        assert_eq!(marker["publication_authorized"], false);
        assert_eq!(marker["request_sha256"], hash(&serde_json::to_vec(&self.request).unwrap()));
    }

    fn dispatch(&mut self, mode: DeliveryMode, source: Option<&ResumeSource>)
        -> Result<rabsd::coord::worker_delivery::Delivery, rabsd::coord::worker_delivery::DeliveryFailure>
    {
        let request = self.request.clone();
        let destination = self.destination.clone();
        match source {
            Some(source) => receive_operation(&mut ResumePeer::new(self, source),
                &request, "worker", &destination, mode),
            None => receive_operation(self, &request, "worker", &destination, mode),
        }
    }
}

impl WorkerPeer for Peer {
    fn send(&mut self, frame: &Value) -> io::Result<()> {
        self.sent.push(frame.clone());
        match frame["kind"].as_str() {
            Some("session-ok") => assert_eq!(frame["result_retention"], "durable-result-v1"),
            Some("canonical-exec") => {
                assert_eq!(*frame, self.request);
                assert!(self.result.get("resumed").is_none());
                self.replies.push_back(self.result.clone());
            }
            Some("result-resume") => {
                assert_eq!(*frame, json!({"kind":"result-resume", "request_id":7, "request":self.request}));
                assert_eq!(self.result["resumed"], true);
                self.replies.push_back(self.result.clone());
            }
            Some("output-read" | "artifact-read") => {
                assert!(!self.draining, "a batch must drain before new range requests");
                self.pending += 1;
                self.range_writes += 1;
                self.maximum_pending = self.maximum_pending.max(self.pending);
                assert!(self.pending <= 4, "bounded result pipeline");
                assert_eq!(frame["request_id"], 7);
                assert_eq!(frame["max_bytes"], CHUNK_BYTES);
                let artifact = frame["kind"] == "artifact-read";
                let name = frame[if artifact {"name"} else {"stream"}].as_str().unwrap();
                let key = format!("{}/{name}", if artifact {"artifacts"} else {"diagnostics"});
                let bytes = &self.files[&key];
                let offset = frame["offset"].as_u64().unwrap() as usize;
                assert!(offset <= bytes.len());
                if let Some(previous) = self.scheduled.get(&key) { assert_eq!(*previous, offset); }
                let end = (offset + CHUNK_BYTES).min(bytes.len());
                self.scheduled.insert(key, end);
                let mut payload = bytes[offset..end].to_vec();
                if matches!(self.fault, Fault::ValidChunkWrongFileHash) && self.range_writes == 1 {
                    payload[0] ^= 1;
                }
                let mut reply = json!({"kind":if artifact {"artifact-chunk"} else {"output-chunk"},
                    "request_id":7, "offset":offset, "next_offset":end, "total_bytes":bytes.len(),
                    "sha256":hash(bytes), "chunk_sha256":hash(&payload),
                    "data_hex":hex(&payload), "eof":end == bytes.len()});
                reply[if artifact {"name"} else {"stream"}] = json!(name);
                if artifact {
                    reply["manifest_sha256"] = self.result["artifact_manifest"]["manifest_sha256"].clone();
                    reply["executable"] = json!(name == "bin/app");
                }
                self.replies.push_back(reply);
                if matches!(self.fault, Fault::FailThirdWrite) && self.range_writes == 3 {
                    return Err(io::Error::new(io::ErrorKind::BrokenPipe, "possibly accepted range write"));
                }
            }
            Some("output-ack" | "artifact-ack") => {
                assert_eq!(self.pending, 0);
                self.delivered_bytes(); // Full local durability marker precedes either release.
                self.acknowledgments += 1;
                let output = frame["kind"] == "output-ack";
                if output {
                    assert_eq!(frame["stdout_sha256"], self.result["stdout_sha256"]);
                    assert_eq!(frame["stderr_sha256"], self.result["stderr_sha256"]);
                } else {
                    assert_eq!(frame["manifest_sha256"], self.result["artifact_manifest"]["manifest_sha256"]);
                }
                self.replies.push_back(json!({"kind":if output {"output-acknowledged"} else {"artifact-acknowledged"},
                    "request_id":7, "already_released":false}));
            }
            _ => panic!("unexpected receiver request: {frame}"),
        }
        Ok(())
    }

    fn receive(&mut self) -> io::Result<Value> {
        if matches!(self.fault, Fault::ReverseFirstBatch) && self.chunk_reads == 0 && self.pending >= 2 {
            self.replies.swap(0, 1);
        }
        let mut frame = self.replies.pop_front()
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "missing response"))?;
        if matches!(frame["kind"].as_str(), Some("output-chunk" | "artifact-chunk")) {
            if !self.draining {
                self.batches.push(self.pending);
                self.draining = true;
            }
            self.pending -= 1;
            self.draining = self.pending != 0;
            self.chunk_reads += 1;
            if self.chunk_reads == 1 {
                match self.fault {
                    Fault::ForeignFirstChunk => frame["request_id"] = json!(8),
                    Fault::WrongFirstEof => frame["eof"] = json!(true),
                    _ => {}
                }
            }
            if matches!(self.fault, Fault::TimeoutSecondChunk) && self.chunk_reads == 2 {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "original transfer deadline"));
            }
        }
        Ok(frame)
    }
}

#[test]
fn output_pipeline_drains_four_range_batches_and_the_final_tail_before_release() {
    let owner = tempfile::tempdir().unwrap();
    let destination = owner.path().join("delivery");
    let mut peer = Peer::new(&destination, 9 * CHUNK_BYTES + 13, DeliveryMode::Execute);
    let delivery = peer.dispatch(DeliveryMode::Execute, None).unwrap();
    assert!(delivery.acknowledgments_confirmed);
    peer.delivered_bytes();
    assert_eq!(peer.batches, [4, 4, 2, 1, 4, 2, 1]);
    assert_eq!(peer.maximum_pending, 4, "serial range I/O must fail this gate");
    assert_eq!(peer.acknowledgments, 2);
    assert!(peer.replies.is_empty());
    assert_eq!(peer.sent.iter().filter(|frame| frame["kind"] == "canonical-exec").count(), 1);
    recover_existing_delivery(&peer.request, "worker", &destination, DeliveryTrust::Loopback)
        .unwrap().unwrap();
}

#[test]
fn output_pipeline_covers_empty_and_exact_boundary_files_without_phantom_ranges() {
    for length in [0, 1, CHUNK_BYTES, CHUNK_BYTES + 1, 4 * CHUNK_BYTES, 4 * CHUNK_BYTES + 1] {
        let owner = tempfile::tempdir().unwrap();
        let mut peer = Peer::new(&owner.path().join("delivery"), length, DeliveryMode::Execute);
        peer.dispatch(DeliveryMode::Execute, None).unwrap();
        let ranges: Vec<_> = peer.sent.iter()
            .filter(|frame| frame["kind"] == "output-read" && frame["stream"] == "stdout")
            .map(|frame| frame["offset"].as_u64().unwrap()).collect();
        let expected = length.div_ceil(CHUNK_BYTES).max(1);
        assert_eq!(ranges, (0..expected).map(|n| (n * CHUNK_BYTES) as u64).collect::<Vec<_>>());
        peer.delivered_bytes();
        assert_eq!(peer.acknowledgments, 2);
    }
}

#[test]
fn output_pipeline_refuses_foreign_reordered_or_contradictory_ranges_before_refilling() {
    for fault in [Fault::ForeignFirstChunk, Fault::ReverseFirstBatch, Fault::WrongFirstEof] {
        let owner = tempfile::tempdir().unwrap();
        let mut peer = Peer::new(&owner.path().join("delivery"), 10 * CHUNK_BYTES, DeliveryMode::Execute);
        peer.fault = fault;
        let failure = peer.dispatch(DeliveryMode::Execute, None).unwrap_err();
        assert!(failure.execution_may_have_run);
        assert_eq!(peer.range_writes, 4);
        assert_eq!(peer.chunk_reads, 1);
        assert_eq!(peer.acknowledgments, 0);
        assert!(!peer.destination.join("delivery.json").exists());
    }
}

#[test]
fn output_pipeline_valid_chunk_hashes_cannot_replace_complete_file_verification() {
    let owner = tempfile::tempdir().unwrap();
    let mut peer = Peer::new(&owner.path().join("delivery"), 9 * CHUNK_BYTES + 3, DeliveryMode::Execute);
    peer.fault = Fault::ValidChunkWrongFileHash;
    let failure = peer.dispatch(DeliveryMode::Execute, None).unwrap_err();
    assert!(failure.detail.contains("complete file digest mismatch"));
    assert_eq!(peer.range_writes, 10);
    assert_eq!(peer.acknowledgments, 0);
    assert!(peer.sent.iter().all(|frame| frame["kind"] != "artifact-read"));
    assert!(!peer.destination.join("delivery.json").exists());
}

#[test]
fn output_pipeline_lost_writes_and_deadlines_never_retry_or_release_partial_output() {
    for fault in [Fault::FailThirdWrite, Fault::TimeoutSecondChunk] {
        let owner = tempfile::tempdir().unwrap();
        let mut peer = Peer::new(&owner.path().join("delivery"), 10 * CHUNK_BYTES, DeliveryMode::Resume);
        peer.fault = fault;
        let failure = peer.dispatch(DeliveryMode::Resume, None).unwrap_err();
        assert!(failure.execution_may_have_run);
        assert_eq!(peer.range_writes, if matches!(fault, Fault::FailThirdWrite) {3} else {4});
        assert_eq!(peer.acknowledgments, 0);
        assert!(peer.sent.iter().all(|frame| frame["kind"] != "canonical-exec"));
        assert_eq!(peer.sent.iter().filter(|frame| frame["kind"] == "result-resume").count(), 1);
        assert!(!peer.destination.join("delivery.json").exists());
    }
}

#[test]
fn output_pipeline_resumes_unaligned_prefixes_and_skips_complete_local_files() {
    let owner = tempfile::tempdir().unwrap();
    let root = owner.path().canonicalize().unwrap();
    let old = root.join("old");
    let mut peer = Peer::new(&root.join("new"), 10 * CHUNK_BYTES + 17, DeliveryMode::Resume);
    fs::create_dir_all(old.join("diagnostics")).unwrap();
    fs::create_dir_all(old.join("artifacts/bin")).unwrap();
    let prefix = CHUNK_BYTES + 11;
    fs::write(old.join("diagnostics/stdout"), &peer.files["diagnostics/stdout"][..prefix]).unwrap();
    fs::write(old.join("artifacts/bin/app"), &peer.files["artifacts/bin/app"]).unwrap();
    fs::write(old.join("delivery.json"), b"untrusted old marker").unwrap();
    let old_inode = fs::metadata(old.join("artifacts/bin/app")).unwrap().ino();
    let source = ResumeSource::open(&old).unwrap();
    peer.dispatch(DeliveryMode::Resume, Some(&source)).unwrap();
    peer.delivered_bytes();
    let ranges: Vec<_> = peer.sent.iter()
        .filter(|frame| frame["kind"] == "output-read" && frame["stream"] == "stdout")
        .map(|frame| frame["offset"].as_u64().unwrap()).collect();
    assert_eq!(ranges[0], prefix as u64);
    assert_eq!(ranges.len(), 10);
    assert_eq!(peer.batches, [4, 4, 2, 1, 1]);
    assert!(peer.sent.iter().all(|frame| !(frame["kind"] == "artifact-read" && frame["name"] == "bin/app")));
    assert_ne!(old_inode, fs::metadata(peer.destination.join("artifacts/bin/app")).unwrap().ino());
    assert_eq!(fs::metadata(old.join("artifacts/bin/app")).unwrap().ino(), old_inode);
    assert_eq!(fs::read(old.join("diagnostics/stdout")).unwrap(), peer.files["diagnostics/stdout"][..prefix]);
    assert_eq!(fs::read(old.join("delivery.json")).unwrap(), b"untrusted old marker");
    assert!(peer.sent.iter().all(|frame| frame["kind"] != "canonical-exec"));
}

#[test]
fn output_pipeline_corrupt_prefix_plus_correct_remote_tail_never_acknowledges() {
    let owner = tempfile::tempdir().unwrap();
    let root = owner.path().canonicalize().unwrap();
    let old = root.join("old");
    fs::create_dir_all(old.join("diagnostics")).unwrap();
    let mut peer = Peer::new(&root.join("new"), 8 * CHUNK_BYTES + 7, DeliveryMode::Resume);
    let mut prefix = peer.files["diagnostics/stdout"][..CHUNK_BYTES + 3].to_vec();
    prefix[0] ^= 1;
    fs::write(old.join("diagnostics/stdout"), &prefix).unwrap();
    let source = ResumeSource::open(&old).unwrap();
    let failure = peer.dispatch(DeliveryMode::Resume, Some(&source)).unwrap_err();
    assert!(failure.detail.contains("complete file digest mismatch"));
    assert_eq!(peer.acknowledgments, 0);
    assert_eq!(fs::read(old.join("diagnostics/stdout")).unwrap(), prefix);
    assert!(!peer.destination.join("delivery.json").exists());
    assert!(peer.sent.iter().all(|frame| frame["kind"] != "canonical-exec"));
}
