//! The production sender and real filesystem receiver, with an instrumented
//! transport. These test protocol causality and bounds, not network speedup.

use super::*;
use super::super::pipeline::{ExpectedAck, MAX_IN_FLIGHT_BYTES, UploadWindow};

struct TracedPeer {
    receiver: ReceiverPeer,
    bursts: Vec<Vec<String>>,
    current: Vec<String>,
    control_acks: usize,
    fault: Option<&'static str>,
    last_ack: Option<Value>,
    fail_send: bool,
    attempted: usize,
}

impl TracedPeer {
    fn new() -> Self {
        Self {
            receiver: ReceiverPeer::new(), bursts: Vec::new(), current: Vec::new(),
            control_acks: 0, fault: None, last_ack: None, fail_send: false, attempted: 0,
        }
    }
}

impl WorkerPeer for TracedPeer {
    fn send(&mut self, frame: &Value) -> io::Result<()> {
        let kind = frame["kind"].as_str().unwrap();
        if kind == "toolchain-seal" {
            assert!(self.receiver.replies.is_empty(), "seal cannot overtake a pending acknowledgment");
            assert!(self.current.is_empty());
        }
        if matches!(kind, "toolchain-entry" | "toolchain-chunk") {
            self.attempted += 1;
            if self.fail_send && self.attempted == 3 {
                // A partial control write is indistinguishable from this error.
                return Err(io::Error::new(io::ErrorKind::ConnectionAborted, "partial control write"));
            }
            self.current.push(kind.to_owned());
        }
        self.receiver.send(frame)
    }

    fn receive(&mut self) -> io::Result<Value> {
        if !self.current.is_empty() {
            self.bursts.push(std::mem::take(&mut self.current));
        }
        let mut reply = self.receiver.receive()?;
        if matches!(reply["kind"].as_str(), Some("toolchain-entry-accepted" | "toolchain-chunk-accepted")) {
            self.control_acks += 1;
            if self.control_acks == 2 {
                match self.fault {
                    Some("path") => reply["path"] = json!("foreign"),
                    Some("request") => reply["request_id"] = json!(999),
                    Some("identity") => reply["sha256"] = json!("ab".repeat(32)),
                    Some("kind") => reply["kind"] = json!("toolchain-ready"),
                    Some("extra") => reply["unexpected"] = json!(true),
                    Some("duplicate") => reply = self.last_ack.clone().unwrap(),
                    Some("lost") => return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "missing entry ACK")),
                    _ => {}
                }
            }
            if reply["kind"] == "toolchain-chunk-accepted" && self.fault == Some("offset") {
                reply["next_offset"] = json!(0);
            }
            self.last_ack = Some(reply.clone());
        }
        Ok(reply)
    }
}

#[test]
fn the_first_cold_burst_spans_metadata_and_file_bytes_before_waiting() {
    let root = tempfile::tempdir().unwrap();
    let (upload, request, bytes) = fixture(root.path());
    let mut peer = TracedPeer::new();
    upload.transmit(&mut peer, &request, false).unwrap();
    // Root, bin directory, compiler entry, then its first chunk. The old sender
    // waits after each entry, so its first burst has only one control.
    assert_eq!(peer.bursts[0], ["toolchain-entry", "toolchain-entry", "toolchain-entry", "toolchain-chunk"]);
    assert!(peer.bursts.iter().all(|burst| burst.len() <= CHUNK_WINDOW));
    assert_eq!(peer.receiver.maximum_pending, CHUNK_WINDOW);
    assert_eq!(peer.control_acks, peer.attempted);
    assert!(peer.receiver.replies.is_empty());
    let received = peer.receiver.sealed.as_ref().unwrap();
    received.verify(|| false).unwrap();
    assert_eq!(received.identity(), upload.prepared.identity());
    assert_eq!(received.entries().unwrap(), upload.prepared.entries().unwrap());
    assert_eq!(fs::read(received.root().join("rustc")).unwrap(), bytes);
}

fn empty_files(root: &Path, count: usize) -> (ToolchainUpload, Value) {
    let source = root.join("source");
    fs::create_dir(&source).unwrap();
    for i in 0..count {
        fs::write(source.join(format!("file-{i:03}")), []).unwrap();
    }
    let prepared = capture_toolchain(&source, &root.join("retained"), None,
        &ToolchainLimits::default(), || false).unwrap();
    let request = json!({"kind":"canonical-exec", "request_id":0, "toolchain_transfer":TOOLCHAIN_TRANSFER_VERSION,
        "toolchain_identity":toolchain_identity_value(prepared.identity())});
    (ToolchainUpload::new(prepared, &request).unwrap(), request)
}

#[test]
fn empty_files_share_windows_and_the_final_short_batch_is_drained() {
    for count in [0, 1, 2, 3, 4, 10] {
        let root = tempfile::tempdir().unwrap();
        let (upload, request) = empty_files(root.path(), count);
        let mut peer = TracedPeer::new();
        upload.transmit(&mut peer, &request, false).unwrap();
        let entries = count + 1; // the root is an identity-bearing entry too
        assert_eq!(peer.attempted, entries);
        assert_eq!(peer.control_acks, entries);
        assert_eq!(peer.bursts.len(), entries.div_ceil(CHUNK_WINDOW));
        assert_eq!(peer.bursts[0].len(), entries.min(CHUNK_WINDOW));
        assert!(peer.bursts.iter().flatten().all(|kind| kind == "toolchain-entry"));
        assert!(peer.receiver.replies.is_empty());
        assert_eq!(peer.receiver.sent.last().unwrap()["kind"], "toolchain-seal");
        let received = peer.receiver.sealed.as_ref().unwrap();
        received.verify(|| false).unwrap();
        assert_eq!(received.identity(), upload.prepared.identity());
    }
}

#[test]
fn every_batched_ack_stays_correlated_and_errors_never_send_a_seal() {
    let root = tempfile::tempdir().unwrap();
    let (upload, request, _) = fixture(root.path());
    for fault in ["path", "request", "identity", "kind", "extra", "duplicate", "lost", "offset"] {
        let mut peer = TracedPeer::new();
        peer.fault = Some(fault);
        assert!(upload.transmit(&mut peer, &request, false).is_err(), "{fault}");
        assert_eq!(peer.attempted, CHUNK_WINDOW, "failure cannot send the next window: {fault}");
        assert!(peer.receiver.sealed.is_none());
        assert!(peer.receiver.sent.iter().all(|frame|
            !matches!(frame["kind"].as_str(), Some("toolchain-seal" | "canonical-exec"))));
    }
}

#[test]
fn failed_send_stops_immediately_without_retry_or_automatic_draining() {
    let root = tempfile::tempdir().unwrap();
    let (upload, request, _) = fixture(root.path());
    let mut peer = TracedPeer::new();
    peer.fail_send = true;
    assert_eq!(upload.transmit(&mut peer, &request, false).unwrap_err().kind(), io::ErrorKind::ConnectionAborted);
    assert_eq!(peer.attempted, 3);
    assert_eq!(peer.control_acks, 0);
    assert!(peer.receiver.sealed.is_none());
    assert_eq!(peer.receiver.replies.len(), 2, "unconfirmed writes are not retried or silently accepted");
}

// A transport-only fixture for the byte-bound cases: large metadata must be
// rejected/drained by the window before it could reach any filesystem parser.
#[derive(Default)]
struct EchoPeer {
    replies: VecDeque<(Value, usize)>,
    bytes: usize,
    peak: usize,
    writes: usize,
    reads: usize,
    corrupt: bool,
}

impl WorkerPeer for EchoPeer {
    fn send(&mut self, frame: &Value) -> io::Result<()> {
        let size = serde_json::to_vec(frame)?.len() + 1;
        self.bytes += size;
        self.peak = self.peak.max(self.bytes);
        self.writes += 1;
        self.replies.push_back((json!({"kind":"toolchain-entry-accepted",
            "request_id":if self.corrupt {1} else {0}, "sha256":frame["sha256"], "path":frame["path"]}), size));
        Ok(())
    }

    fn receive(&mut self) -> io::Result<Value> {
        self.reads += 1;
        let (reply, bytes) = self.replies.pop_front().ok_or_else(|| invalid("missing ACK"))?;
        self.bytes -= bytes;
        Ok(reply)
    }
}

fn metadata_frame(bytes: usize) -> Value {
    json!({"kind":"toolchain-entry", "request_id":0, "sha256":"11".repeat(32),
        "path":"unit", "entry":{"kind":"symlink", "target":"x".repeat(bytes)}})
}

#[test]
fn metadata_bytes_force_a_drain_before_the_frame_count_ceiling() {
    let mut peer = EchoPeer::default();
    let frame = metadata_frame(MAX_IN_FLIGHT_BYTES / 2);
    let mut window = UploadWindow::new(&mut peer, 0, [0x11; 32]);
    for _ in 0..3 {
        window.queue(&frame, ExpectedAck::Entry { path: "unit" }).unwrap();
    }
    window.finish().unwrap();
    assert_eq!(peer.writes, 3);
    assert_eq!(peer.reads, 3);
    assert_eq!(peer.peak, serde_json::to_vec(&frame).unwrap().len() + 1);
    assert!(peer.peak <= MAX_IN_FLIGHT_BYTES);
    assert_eq!(peer.bytes, 0);
}

#[test]
fn oversized_or_foreign_controls_fail_before_writing_and_poison_the_window() {
    for case in ["large", "request", "path", "kind"] {
        let mut peer = EchoPeer::default();
        let mut frame = metadata_frame(if case == "large" {MAX_IN_FLIGHT_BYTES} else {1});
        match case {
            "request" => frame["request_id"] = json!(2),
            "path" => frame["path"] = json!("foreign"),
            "kind" => frame["kind"] = json!("canonical-exec"),
            _ => {}
        }
        let mut window = UploadWindow::new(&mut peer, 0, [0x11; 32]);
        assert!(window.queue(&frame, ExpectedAck::Entry { path: "unit" }).is_err(), "{case}");
        assert!(window.queue(&metadata_frame(1), ExpectedAck::Entry { path: "unit" }).is_err());
        assert!(window.finish().is_err());
        assert_eq!((peer.writes, peer.reads), (0, 0));
    }
}

#[test]
fn a_failed_ack_prevents_all_later_window_use() {
    let mut peer = EchoPeer { corrupt: true, ..EchoPeer::default() };
    let mut window = UploadWindow::new(&mut peer, 0, [0x11; 32]);
    for _ in 0..CHUNK_WINDOW - 1 {
        window.queue(&metadata_frame(1), ExpectedAck::Entry { path: "unit" }).unwrap();
    }
    assert!(window.queue(&metadata_frame(1), ExpectedAck::Entry { path: "unit" }).is_err());
    assert!(window.queue(&metadata_frame(1), ExpectedAck::Entry { path: "unit" }).is_err());
    assert!(window.finish().is_err());
    assert_eq!(peer.writes, CHUNK_WINDOW);
    assert_eq!(peer.reads, 1);
}
