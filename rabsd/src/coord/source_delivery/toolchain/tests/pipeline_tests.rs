//! The production sender and real filesystem receiver, with an instrumented
//! transport. These test protocol causality and bounds, not network speedup.

use super::super::pipeline::{ExpectedAck, MAX_IN_FLIGHT_BYTES, UploadWindow};
use super::*;

struct TracedPeer {
    receiver: ReceiverPeer,
    bursts: Vec<Vec<String>>,
    current: Vec<String>,
    control_acks: usize,
    fault: Option<&'static str>,
    last_ack: Option<Value>,
    fail_send: bool,
    attempted: usize,
    depth_at_ack: Vec<usize>,
}

impl TracedPeer {
    fn new() -> Self {
        Self {
            receiver: ReceiverPeer::new(),
            bursts: Vec::new(),
            current: Vec::new(),
            control_acks: 0,
            fault: None,
            last_ack: None,
            fail_send: false,
            attempted: 0,
            depth_at_ack: Vec::new(),
        }
    }
}

impl WorkerPeer for TracedPeer {
    fn send(&mut self, frame: &Value) -> io::Result<()> {
        let kind = frame["kind"].as_str().unwrap();
        if kind == "toolchain-seal" {
            assert!(
                self.receiver.replies.is_empty(),
                "seal cannot overtake a pending acknowledgment"
            );
            assert!(self.current.is_empty());
        }
        if matches!(kind, "toolchain-entry" | "toolchain-chunk") {
            self.attempted += 1;
            if self.fail_send && self.attempted == 3 {
                // A partial control write is indistinguishable from this error.
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "partial control write",
                ));
            }
            self.current.push(kind.to_owned());
        }
        self.receiver.send(frame)
    }

    fn receive(&mut self) -> io::Result<Value> {
        if !self.current.is_empty() {
            self.bursts.push(std::mem::take(&mut self.current));
        }
        let depth = self.receiver.replies.len();
        let mut reply = self.receiver.receive()?;
        if matches!(
            reply["kind"].as_str(),
            Some("toolchain-entry-accepted" | "toolchain-chunk-accepted")
        ) {
            self.control_acks += 1;
            self.depth_at_ack.push(depth);
            if self.control_acks == 2 {
                match self.fault {
                    Some("path") => reply["path"] = json!("foreign"),
                    Some("request") => reply["request_id"] = json!(999),
                    Some("identity") => reply["sha256"] = json!("ab".repeat(32)),
                    Some("kind") => reply["kind"] = json!("toolchain-ready"),
                    Some("extra") => reply["unexpected"] = json!(true),
                    Some("duplicate") => reply = self.last_ack.clone().unwrap(),
                    Some("lost") => {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "missing entry ACK",
                        ));
                    }
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
    assert_eq!(
        peer.bursts[0],
        [
            "toolchain-entry",
            "toolchain-entry",
            "toolchain-entry",
            "toolchain-chunk"
        ]
    );
    assert!(peer.bursts.iter().all(|burst| burst.len() <= CHUNK_WINDOW));
    assert_eq!(peer.receiver.maximum_pending, CHUNK_WINDOW);
    assert_eq!(peer.control_acks, peer.attempted);
    assert!(peer.receiver.replies.is_empty());
    let received = peer.receiver.sealed.as_ref().unwrap();
    received.verify(|| false).unwrap();
    assert_eq!(received.identity(), upload.prepared.identity());
    assert_eq!(
        received.entries().unwrap(),
        upload.prepared.entries().unwrap()
    );
    assert_eq!(fs::read(received.root().join("rustc")).unwrap(), bytes);
}

fn empty_files(root: &Path, count: usize) -> (ToolchainUpload, Value) {
    let source = root.join("source");
    fs::create_dir(&source).unwrap();
    for i in 0..count {
        fs::write(source.join(format!("file-{i:03}")), []).unwrap();
    }
    let prepared = capture_toolchain(
        &source,
        &root.join("retained"),
        None,
        &ToolchainLimits::default(),
        || false,
    )
    .unwrap();
    let request = json!({"kind":"canonical-exec", "request_id":0, "toolchain_transfer":TOOLCHAIN_TRANSFER_VERSION,
        "toolchain_identity":toolchain_identity_value(prepared.identity())});
    (ToolchainUpload::new(prepared, &request).unwrap(), request)
}

#[test]
fn empty_files_share_windows_and_the_final_short_batch_is_drained() {
    for count in [0, 1, 2, 3, 4, 10] {
        let root = crate::test_util::private_tempdir();
        let (upload, request) = empty_files(root.path(), count);
        let mut peer = TracedPeer::new();
        upload.transmit(&mut peer, &request, false).unwrap();
        let entries = count + 1; // the root is an identity-bearing entry too
        assert_eq!(peer.attempted, entries);
        assert_eq!(peer.control_acks, entries);
        assert_eq!(peer.bursts.len(), 1 + entries.saturating_sub(CHUNK_WINDOW));
        assert_eq!(peer.bursts[0].len(), entries.min(CHUNK_WINDOW));
        assert!(peer.bursts[1..].iter().all(|burst| burst.len() == 1));
        assert!(
            peer.bursts
                .iter()
                .flatten()
                .all(|kind| kind == "toolchain-entry")
        );
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
    for fault in [
        "path",
        "request",
        "identity",
        "kind",
        "extra",
        "duplicate",
        "lost",
        "offset",
    ] {
        let mut peer = TracedPeer::new();
        peer.fault = Some(fault);
        assert!(
            upload.transmit(&mut peer, &request, false).is_err(),
            "{fault}"
        );
        assert_eq!(
            peer.attempted,
            CHUNK_WINDOW + peer.control_acks - 1,
            "only earlier valid ACKs may replenish the bounded window: {fault}"
        );
        assert_eq!(peer.receiver.maximum_pending, CHUNK_WINDOW);
        assert!(peer.receiver.sealed.is_none());
        assert!(peer.receiver.sent.iter().all(|frame| !matches!(
            frame["kind"].as_str(),
            Some("toolchain-seal" | "canonical-exec")
        )));
    }
}

#[test]
fn failed_send_stops_immediately_without_retry_or_automatic_draining() {
    let root = tempfile::tempdir().unwrap();
    let (upload, request, _) = fixture(root.path());
    let mut peer = TracedPeer::new();
    peer.fail_send = true;
    assert_eq!(
        upload
            .transmit(&mut peer, &request, false)
            .unwrap_err()
            .kind(),
        io::ErrorKind::ConnectionAborted
    );
    assert_eq!(peer.attempted, 3);
    assert_eq!(peer.control_acks, 0);
    assert!(peer.receiver.sealed.is_none());
    assert_eq!(
        peer.receiver.replies.len(),
        2,
        "unconfirmed writes are not retried or silently accepted"
    );
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
    reads_at_send: Vec<usize>,
    corrupt_ack: Option<usize>,
}

impl WorkerPeer for EchoPeer {
    fn send(&mut self, frame: &Value) -> io::Result<()> {
        self.reads_at_send.push(self.reads);
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
        let (mut reply, bytes) = self
            .replies
            .pop_front()
            .ok_or_else(|| invalid("missing ACK"))?;
        self.bytes -= bytes;
        if self.corrupt_ack == Some(self.reads) {
            reply["request_id"] = json!(999);
        }
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
        window
            .queue(&frame, ExpectedAck::Entry { path: "unit" })
            .unwrap();
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
        let mut frame = metadata_frame(if case == "large" {
            MAX_IN_FLIGHT_BYTES
        } else {
            1
        });
        match case {
            "request" => frame["request_id"] = json!(2),
            "path" => frame["path"] = json!("foreign"),
            "kind" => frame["kind"] = json!("canonical-exec"),
            _ => {}
        }
        let mut window = UploadWindow::new(&mut peer, 0, [0x11; 32]);
        assert!(
            window
                .queue(&frame, ExpectedAck::Entry { path: "unit" })
                .is_err(),
            "{case}"
        );
        assert!(
            window
                .queue(&metadata_frame(1), ExpectedAck::Entry { path: "unit" })
                .is_err()
        );
        assert!(window.finish().is_err());
        assert_eq!((peer.writes, peer.reads), (0, 0));
    }
}

#[test]
fn a_failed_ack_prevents_all_later_window_use() {
    let mut peer = EchoPeer {
        corrupt: true,
        ..EchoPeer::default()
    };
    let mut window = UploadWindow::new(&mut peer, 0, [0x11; 32]);
    for _ in 0..CHUNK_WINDOW - 1 {
        window
            .queue(&metadata_frame(1), ExpectedAck::Entry { path: "unit" })
            .unwrap();
    }
    assert!(
        window
            .queue(&metadata_frame(1), ExpectedAck::Entry { path: "unit" })
            .is_err()
    );
    assert!(
        window
            .queue(&metadata_frame(1), ExpectedAck::Entry { path: "unit" })
            .is_err()
    );
    assert!(window.finish().is_err());
    assert_eq!(peer.writes, CHUNK_WINDOW);
    assert_eq!(peer.reads, 1);
}

#[test]
fn cold_transfer_refills_after_each_ack_without_emptying_the_pipeline() {
    let root = crate::test_util::private_tempdir();
    let (upload, request, bytes) = fixture(root.path());
    let mut peer = TracedPeer::new();
    upload.transmit(&mut peer, &request, false).unwrap();
    let controls = peer.attempted;
    assert!(controls > CHUNK_WINDOW * 2, "exercise sustained transfer");
    let full_reads = controls - CHUNK_WINDOW + 1;
    assert_eq!(
        peer.depth_at_ack[..full_reads],
        vec![CHUNK_WINDOW; full_reads]
    );
    assert_eq!(
        peer.depth_at_ack[full_reads..],
        (1..CHUNK_WINDOW).rev().collect::<Vec<_>>()
    );
    assert!(peer.bursts[1..].iter().all(|burst| burst.len() == 1));
    assert_eq!(peer.control_acks, controls);
    assert!(peer.receiver.replies.is_empty());
    assert_eq!(peer.receiver.sent.last().unwrap()["kind"], "toolchain-seal");
    let sealed = peer.receiver.sealed.as_ref().unwrap();
    sealed.verify(|| false).unwrap();
    assert_eq!(sealed.identity(), upload.prepared.identity());
    assert_eq!(fs::read(sealed.root().join("rustc")).unwrap(), bytes);
}

#[test]
fn byte_pressure_returns_only_the_credit_needed_for_the_next_control() {
    for (sizes, expected_reads) in [
        (
            [
                MAX_IN_FLIGHT_BYTES / 4,
                MAX_IN_FLIGHT_BYTES / 4,
                MAX_IN_FLIGHT_BYTES / 10,
                MAX_IN_FLIGHT_BYTES / 2,
            ],
            1,
        ),
        (
            [
                MAX_IN_FLIGHT_BYTES / 5,
                MAX_IN_FLIGHT_BYTES / 5,
                MAX_IN_FLIGHT_BYTES / 5,
                MAX_IN_FLIGHT_BYTES * 7 / 10,
            ],
            2,
        ),
    ] {
        let mut peer = EchoPeer::default();
        let mut window = UploadWindow::new(&mut peer, 0, [0x11; 32]);
        for size in sizes {
            window
                .queue(&metadata_frame(size), ExpectedAck::Entry { path: "unit" })
                .unwrap();
        }
        window.finish().unwrap();
        // The incumbent drains all three earlier controls in both cases.
        // A sliding window must keep the still-charged suffix in flight.
        assert_eq!(peer.reads_at_send, [0, 0, 0, expected_reads]);
        assert!(peer.peak <= MAX_IN_FLIGHT_BYTES);
        assert_eq!((peer.writes, peer.reads, peer.bytes), (4, 4, 0));
        assert!(peer.replies.is_empty());
    }
}

#[test]
fn a_full_byte_window_preserves_its_exact_newline_inclusive_limit() {
    let overhead = serde_json::to_vec(&metadata_frame(0)).unwrap().len() + 1;
    let large = metadata_frame(MAX_IN_FLIGHT_BYTES - overhead);
    let small = metadata_frame(1);
    assert_eq!(
        serde_json::to_vec(&large).unwrap().len() + 1,
        MAX_IN_FLIGHT_BYTES
    );
    let mut peer = EchoPeer::default();
    let mut window = UploadWindow::new(&mut peer, 0, [0x11; 32]);
    for frame in [&large, &small, &large] {
        window
            .queue(frame, ExpectedAck::Entry { path: "unit" })
            .unwrap();
    }
    window.finish().unwrap();
    assert_eq!(peer.reads_at_send, [0, 1, 2]);
    assert_eq!(peer.peak, MAX_IN_FLIGHT_BYTES);
    assert_eq!((peer.writes, peer.reads, peer.bytes), (3, 3, 0));
}

#[test]
fn every_sliding_ack_failure_stops_credit_and_the_final_drain() {
    const CONTROLS: usize = 13;
    for failed_ack in 1..=CONTROLS {
        let mut peer = EchoPeer {
            corrupt_ack: Some(failed_ack),
            ..EchoPeer::default()
        };
        let mut window = Some(UploadWindow::new(&mut peer, 0, [0x11; 32]));
        for _ in 0..CONTROLS {
            if window
                .as_mut()
                .unwrap()
                .queue(&metadata_frame(1), ExpectedAck::Entry { path: "unit" })
                .is_err()
            {
                assert!(
                    window
                        .as_mut()
                        .unwrap()
                        .queue(&metadata_frame(1), ExpectedAck::Entry { path: "unit" })
                        .is_err()
                );
                assert!(window.take().unwrap().finish().is_err());
                break;
            }
        }
        if let Some(window) = window {
            // Exercise errors in the tail as well as while refilling. A
            // complete set of sent controls is not a completed transfer.
            assert!(window.finish().is_err());
        }
        assert_eq!(peer.reads, failed_ack);
        assert_eq!(
            peer.writes,
            (CHUNK_WINDOW + failed_ack - 1).min(CONTROLS),
            "a failed ACK cannot replenish a slot or restart I/O"
        );
        assert!(peer.peak <= MAX_IN_FLIGHT_BYTES);
    }
}

#[test]
fn dropping_an_unfinished_window_neither_accepts_nor_retries_its_tail() {
    for controls in 0..CHUNK_WINDOW {
        let mut peer = EchoPeer::default();
        {
            let mut window = UploadWindow::new(&mut peer, 0, [0x11; 32]);
            for _ in 0..controls {
                window
                    .queue(&metadata_frame(1), ExpectedAck::Entry { path: "unit" })
                    .unwrap();
            }
        }
        assert_eq!((peer.writes, peer.reads), (controls, 0));
        assert_eq!(peer.replies.len(), controls);
    }
    let mut peer = EchoPeer::default();
    UploadWindow::new(&mut peer, 0, [0x11; 32])
        .finish()
        .unwrap();
    assert_eq!((peer.writes, peer.reads, peer.bytes), (0, 0, 0));
}
