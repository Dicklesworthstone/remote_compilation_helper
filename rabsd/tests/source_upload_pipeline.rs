//! Exercise the production source sender against the real filesystem receiver.
//! The transport is scripted; no compiler or fleet performance is claimed.
#![cfg(unix)]

use rabs_sandbox::snapshot_capture::capture_sealed_source;
use rabs_sandbox::source_transfer::{MAX_SOURCE_CHUNK, SourceReceiver};
use rabsd::coord::source_delivery::{SourcePeer, SourceUpload, request_manifest};
use rabsd::coord::worker_delivery::WorkerPeer;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs;
use std::io;
use std::path::PathBuf;
use std::sync::Arc;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn decode(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);
    value.as_bytes().chunks_exact(2).map(|pair| {
        u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap()
    }).collect()
}

struct Fixture {
    _owner: tempfile::TempDir,
    root: PathBuf,
    files: BTreeMap<String, Vec<u8>>,
    upload: SourceUpload,
    request: Value,
}

impl Fixture {
    fn new(files: BTreeMap<String, Vec<u8>>) -> Self {
        let owner = tempfile::tempdir().unwrap();
        let root = owner.path().canonicalize().unwrap();
        for (name, bytes) in &files {
            let path = root.join(name);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, bytes).unwrap();
        }
        fs::write(root.join("unselected.txt"), b"not approved for transmission").unwrap();
        let image = capture_sealed_source(
            &[("workspace".into(), root.clone())], false, 2, 8 * 1024 * 1024,
        ).unwrap();
        let paths: Vec<_> = files.keys().cloned().collect();
        let upload = SourceUpload::from_snapshot(Arc::new(image), "workspace", &paths).unwrap();
        let request = json!({"kind":"canonical-exec", "request_id":17,
            "program":"rustc", "args":["lib.rs"], "toolchain_backing":"/tc",
            "source_manifest":upload.wire_manifest()});
        Self { _owner:owner, root, files, upload, request }
    }

    fn transfer(&self, peer: &mut ReceiverPeer) -> io::Result<()> {
        SourcePeer::new(peer, &self.upload, &self.request)?.negotiate(
            &json!({"source_transfers":["source-files-v1"]}),
            &json!({"kind":"session-ok"}),
        )
    }
}

#[derive(Clone, Copy, Default)]
enum Fault {
    #[default]
    None,
    ForeignFirstAck,
    WrongManifestFirstAck,
    RegressingFirstAck,
    TimeoutFirstAck,
    FailThirdWrite,
}

struct ReceiverPeer {
    owner: tempfile::TempDir,
    receiver: Option<SourceReceiver>,
    files: BTreeMap<String, Vec<u8>>,
    missing: Option<BTreeSet<String>>,
    replies: VecDeque<(Value, usize)>,
    sent: Vec<Value>,
    pending: usize,
    pending_bytes: usize,
    maximum_pending: usize,
    maximum_pending_bytes: usize,
    draining: bool,
    batches: Vec<usize>,
    chunks: usize,
    acks: usize,
    fault: Fault,
}

impl ReceiverPeer {
    fn new(fixture: &Fixture) -> Self {
        Self {
            owner:tempfile::tempdir().unwrap(), receiver:None,
            files:fixture.files.clone(), missing:None, replies:VecDeque::new(),
            sent:Vec::new(), pending:0, pending_bytes:0, maximum_pending:0,
            maximum_pending_bytes:0, draining:false, batches:Vec::new(),
            chunks:0, acks:0, fault:Fault::None,
        }
    }

    fn assert_complete(&self) {
        let root = self.receiver.as_ref().unwrap().sealed_root().unwrap();
        for (name, bytes) in &self.files {
            assert_eq!(fs::read(root.join(name)).unwrap(), *bytes);
        }
        assert!(!root.join("unselected.txt").exists());
        assert!(self.replies.is_empty());
        assert_eq!(self.pending, 0);
        assert_eq!(self.pending_bytes, 0);
        assert_eq!(self.sent.iter().filter(|frame| frame["kind"] == "source-seal").count(), 1);
        assert!(self.sent.iter().all(|frame| frame["kind"] != "canonical-exec"));
    }
}

impl WorkerPeer for ReceiverPeer {
    fn send(&mut self, frame: &Value) -> io::Result<()> {
        self.sent.push(frame.clone());
        let id = frame["request_id"].clone();
        let identity = frame["manifest_sha256"].clone();
        match frame["kind"].as_str() {
            Some("session-ok") => {
                assert_eq!(frame["source_transfer"], "source-files-v1");
            }
            Some("source-begin") => {
                assert!(self.receiver.is_none());
                let manifest = request_manifest(&json!({"source_manifest":frame["manifest"]}))?
                    .expect("source manifest");
                let mut receiver = SourceReceiver::create(&self.owner.path().join("source"), manifest)?;
                if let Some(missing) = &self.missing {
                    for (name, bytes) in &self.files {
                        if missing.contains(name) { continue; }
                        for (index, chunk) in bytes.chunks(MAX_SOURCE_CHUNK).enumerate() {
                            receiver.write_chunk(name, (index * MAX_SOURCE_CHUNK) as u64,
                                chunk, Sha256::digest(chunk).into())?;
                        }
                    }
                }
                let mut reply = json!({"kind":"source-ready", "request_id":id,
                    "manifest_sha256":frame["manifest"]["manifest_sha256"], "sealed":false});
                if let Some(missing) = &self.missing {
                    reply["missing_files"] = json!(missing);
                }
                self.receiver = Some(receiver);
                self.replies.push_back((reply, 0));
            }
            Some("source-chunk") => {
                assert!(!self.draining, "do not refill before the previous batch drains");
                self.chunks += 1;
                self.pending += 1;
                let encoded_size = serde_json::to_vec(frame)?.len();
                self.pending_bytes += encoded_size;
                self.maximum_pending = self.maximum_pending.max(self.pending);
                self.maximum_pending_bytes = self.maximum_pending_bytes.max(self.pending_bytes);
                assert!(self.pending <= 4, "bounded source pipeline");
                assert!(self.pending_bytes < 2 * 1024 * 1024, "worker deferred byte limit");
                let path = frame["path"].as_str().unwrap();
                let bytes = decode(frame["data_hex"].as_str().unwrap());
                let claimed_hash: [u8; 32] = decode(frame["chunk_sha256"].as_str().unwrap())
                    .try_into().unwrap();
                let next = self.receiver.as_mut().unwrap().write_chunk(
                    path, frame["offset"].as_u64().unwrap(), &bytes, claimed_hash,
                )?;
                self.replies.push_back((json!({"kind":"source-chunk-accepted",
                    "request_id":id, "manifest_sha256":identity, "path":path,
                    "next_offset":next}), encoded_size));
                if matches!(self.fault, Fault::FailThirdWrite) && self.chunks == 3 {
                    return Err(io::Error::new(io::ErrorKind::BrokenPipe, "possibly accepted third write"));
                }
            }
            Some("source-seal") => {
                assert_eq!(self.pending, 0, "seal cannot overtake any acknowledgment");
                assert!(self.replies.is_empty());
                self.receiver.as_mut().unwrap().seal()?;
                self.replies.push_back((json!({"kind":"source-ready", "request_id":id,
                    "manifest_sha256":identity, "sealed":true}), 0));
            }
            _ => panic!("source transfer cannot execute work: {frame}"),
        }
        Ok(())
    }

    fn receive(&mut self) -> io::Result<Value> {
        let (mut reply, bytes) = self.replies.pop_front()
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "missing source reply"))?;
        if reply["kind"] == "source-chunk-accepted" {
            if !self.draining {
                self.batches.push(self.pending);
                self.draining = true;
            }
            self.pending -= 1;
            self.pending_bytes -= bytes;
            self.draining = self.pending != 0;
            self.acks += 1;
            if self.acks == 1 {
                match self.fault {
                    Fault::ForeignFirstAck => reply["request_id"] = json!(18),
                    Fault::WrongManifestFirstAck => reply["manifest_sha256"] = json!("00".repeat(32)),
                    Fault::RegressingFirstAck => reply["next_offset"] = json!(0),
                    Fault::TimeoutFirstAck => return Err(io::Error::new(io::ErrorKind::TimedOut, "absolute upload deadline")),
                    Fault::None | Fault::FailThirdWrite => {}
                }
            }
        }
        Ok(reply)
    }
}

#[test]
fn source_pipeline_batches_small_files_across_file_boundaries() {
    let fixture = Fixture::new((0..11).map(|index| {
        (format!("src/f{index:02}"), vec![index as u8, 0, 255])
    }).collect());
    let original = fixture.request.clone();
    let mut peer = ReceiverPeer::new(&fixture);
    fixture.transfer(&mut peer).unwrap();
    peer.assert_complete();
    assert_eq!(peer.batches, [4, 4, 3], "serial send/ack must not pass this gate");
    assert_eq!(peer.maximum_pending, 4);
    assert_eq!(fixture.request, original);
}

#[test]
fn source_pipeline_uses_captured_binary_chunks_and_drains_the_partial_batch() {
    let bytes: Vec<_> = (0..9 * MAX_SOURCE_CHUNK + 13).map(|n| (n % 251) as u8).collect();
    let fixture = Fixture::new(BTreeMap::from([
        ("empty".into(), Vec::new()), ("src/lib.rs".into(), bytes.clone()),
    ]));
    fs::write(fixture.root.join("src/lib.rs"), b"new mutable checkout").unwrap();
    let mut peer = ReceiverPeer::new(&fixture);
    fixture.transfer(&mut peer).unwrap();
    peer.assert_complete();
    assert_eq!(peer.batches, [4, 4, 2]);
    assert_eq!(peer.maximum_pending, 4);
    let offsets: Vec<_> = peer.sent.iter().filter(|frame| frame["kind"] == "source-chunk")
        .map(|frame| frame["offset"].as_u64().unwrap()).collect();
    assert_eq!(offsets, (0..10).map(|n| (n * MAX_SOURCE_CHUNK) as u64).collect::<Vec<_>>());
    assert_eq!(peer.sent.last().unwrap()["kind"], "source-seal");
    assert_eq!(hex(&Sha256::digest(&bytes)), fixture.request["source_manifest"]["files"][1]["sha256"]);
}

#[test]
fn source_pipeline_respects_exact_missing_sets_including_a_completely_warm_transfer() {
    let fixture = Fixture::new((0..9).map(|index| {
        (format!("src/f{index}"), vec![index as u8; 7])
    }).collect());
    for missing in [BTreeSet::new(), BTreeSet::from([
        "src/f0".into(), "src/f2".into(), "src/f4".into(), "src/f6".into(), "src/f8".into(),
    ])] {
        let mut peer = ReceiverPeer::new(&fixture);
        peer.missing = Some(missing.clone());
        fixture.transfer(&mut peer).unwrap();
        peer.assert_complete();
        let sent: BTreeSet<_> = peer.sent.iter().filter(|frame| frame["kind"] == "source-chunk")
            .map(|frame| frame["path"].as_str().unwrap().to_owned()).collect();
        assert_eq!(sent, missing);
        assert_eq!(peer.batches, if missing.is_empty() { vec![] } else { vec![4, 1] });
    }
}

#[test]
fn source_pipeline_failed_acknowledgment_stops_at_the_bounded_batch_without_sealing() {
    let fixture = Fixture::new((0..9).map(|index| {
        (format!("src/f{index}"), vec![index as u8; 3])
    }).collect());
    for fault in [Fault::ForeignFirstAck, Fault::WrongManifestFirstAck,
        Fault::RegressingFirstAck, Fault::TimeoutFirstAck]
    {
        let mut peer = ReceiverPeer::new(&fixture);
        peer.fault = fault;
        let error = fixture.transfer(&mut peer).unwrap_err();
        assert_eq!(peer.chunks, 4, "no next batch after a failed response");
        assert_eq!(peer.acks, 1);
        assert!(peer.receiver.as_ref().unwrap().sealed_root().is_none());
        assert!(peer.sent.iter().all(|frame| frame["kind"] != "source-seal"));
        if matches!(fault, Fault::TimeoutFirstAck) {
            assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        }
    }
}

#[test]
fn source_pipeline_partial_batch_write_burns_negotiation_without_retry() {
    let fixture = Fixture::new((0..9).map(|index| {
        (format!("src/f{index}"), vec![index as u8; 3])
    }).collect());
    let mut peer = ReceiverPeer::new(&fixture);
    peer.fault = Fault::FailThirdWrite;
    let mut source = SourcePeer::new(&mut peer, &fixture.upload, &fixture.request).unwrap();
    let hello = json!({"source_transfers":["source-files-v1"]});
    let grant = json!({"kind":"session-ok"});
    assert_eq!(source.negotiate(&hello, &grant).unwrap_err().kind(), io::ErrorKind::BrokenPipe);
    assert!(source.negotiate(&hello, &grant).is_err());
    assert_eq!(peer.chunks, 3);
    assert_eq!(peer.acks, 0);
    assert!(peer.receiver.as_ref().unwrap().sealed_root().is_none());
    assert!(peer.sent.iter().all(|frame| frame["kind"] != "source-seal"));
}
