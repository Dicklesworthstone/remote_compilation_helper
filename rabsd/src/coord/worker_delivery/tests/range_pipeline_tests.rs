//! Exercise the actual result receiver with a queued, instrumented peer.
//! The peer supplies fixture ranges, not compiler output or TLS authentication.

use super::*;

#[derive(Debug, Clone, PartialEq, Eq)]
enum Event {
    Send(u64),
    Receive(u64),
}

struct RangePeer {
    inner: Script,
    bytes: Vec<u8>,
    artifact: bool,
    sha256: String,
    manifest_sha256: String,
    pending: VecDeque<Value>,
    events: Vec<Event>,
    received: usize,
    sent: usize,
    peak: usize,
    corrupt: Option<(usize, &'static str, Value)>,
    fail_read: Option<usize>,
    fail_write: Option<usize>,
}

impl RangePeer {
    fn new(destination: &Path, bytes: Vec<u8>, artifact: bool, mode: DeliveryMode) -> Self {
        let mut inner = match mode {
            DeliveryMode::Execute => fixture(destination),
            DeliveryMode::Resume => resumable(destination),
        };
        let sha256 = hash(&bytes);
        let manifest_sha256 = if artifact {
            let mut hasher = Sha256::new();
            field(&mut hasher, b"rabs.worker-artifact-manifest.v1");
            field(&mut hasher, b"dep");
            hasher.update(1_u64.to_be_bytes());
            field(&mut hasher, b"a");
            hasher.update([0_u8]);
            hasher.update((bytes.len() as u64).to_be_bytes());
            field(&mut hasher, sha256.as_bytes());
            let digest: String = hasher.finalize().iter().map(|b| format!("{b:02x}")).collect();
            let manifest = &mut inner.replies[1]["artifact_manifest"];
            manifest["files"][0]["bytes"] = json!(bytes.len());
            manifest["files"][0]["sha256"] = json!(sha256);
            manifest["total_bytes"] = json!(bytes.len());
            manifest["manifest_sha256"] = json!(digest);
            inner.replies.remove(4);
            digest
        } else {
            inner.expected_stdout = bytes.clone();
            inner.replies[1]["stdout_bytes"] = json!(bytes.len());
            inner.replies[1]["stdout_sha256"] = json!(sha256);
            inner.replies.remove(2);
            String::new()
        };
        Self {
            inner,
            bytes,
            artifact,
            sha256,
            manifest_sha256,
            pending: VecDeque::new(),
            events: Vec::new(),
            received: 0,
            sent: 0,
            peak: 0,
            corrupt: None,
            fail_read: None,
            fail_write: None,
        }
    }

    fn path(&self, destination: &Path) -> PathBuf {
        destination.join(if self.artifact { "artifacts/a" } else { "diagnostics/stdout" })
    }

    fn target(&self, frame: &Value) -> bool {
        if self.artifact {
            frame["kind"] == "artifact-read" && frame["name"] == "a"
        } else {
            frame["kind"] == "output-read" && frame["stream"] == "stdout"
        }
    }

    fn assert_no_release(&self, destination: &Path) {
        assert!(no_ack(&self.inner));
        assert!(!destination.join("delivery.json").exists());
        assert!(!destination.join("delivery.pending").exists());
        assert!(self.peak <= 4);
        assert_eq!(
            self.inner.sent.iter().filter(|frame| {
                matches!(frame["kind"].as_str(), Some("canonical-exec" | "result-resume"))
            }).count(),
            1,
            "no failure may retry the operation"
        );
    }
}

impl WorkerPeer for RangePeer {
    fn send(&mut self, frame: &Value) -> io::Result<()> {
        self.inner.send(frame)?;
        if !self.target(frame) {
            return Ok(());
        }
        assert_eq!(frame["request_id"], 7);
        assert_eq!(frame["max_bytes"], CHUNK_BYTES);
        assert!(self.pending.len() < 4, "bounded response window exceeded");
        let offset = frame["offset"].as_u64().unwrap();
        self.events.push(Event::Send(offset));
        self.pending.push_back(frame.clone());
        self.peak = self.peak.max(self.pending.len());
        let index = self.sent;
        self.sent += 1;
        if self.fail_write == Some(index) {
            // The peer may have accepted the control even though its writer
            // reports failure. Retain the queue; no caller may drain or retry it.
            return Err(worker_transport_error(io::Error::new(
                io::ErrorKind::BrokenPipe, "injected partial range request",
            )));
        }
        Ok(())
    }

    fn receive(&mut self) -> io::Result<Value> {
        let Some(frame) = self.pending.pop_front() else {
            return self.inner.receive();
        };
        let offset = frame["offset"].as_u64().unwrap();
        self.events.push(Event::Receive(offset));
        let index = self.received;
        self.received += 1;
        if self.fail_read == Some(index) {
            return Err(worker_transport_error(io::Error::new(
                io::ErrorKind::TimedOut, "injected absolute transfer deadline",
            )));
        }
        let start = usize::try_from(offset).unwrap();
        let end = (start + CHUNK_BYTES).min(self.bytes.len());
        let mut reply = chunk(
            if self.artifact { "a" } else { "stdout" },
            &self.bytes[start..end],
            self.artifact,
        );
        reply["offset"] = json!(offset);
        reply["next_offset"] = json!(end);
        reply["total_bytes"] = json!(self.bytes.len());
        reply["sha256"] = json!(self.sha256);
        reply["eof"] = json!(end == self.bytes.len());
        if self.artifact {
            reply["manifest_sha256"] = json!(self.manifest_sha256);
        }
        if let Some((at, field, value)) = &self.corrupt
            && *at == index
        {
            reply[*field] = value.clone();
        }
        Ok(reply)
    }
}

fn data(length: usize) -> Vec<u8> {
    (0..length).map(|index| ((index * 17 + index / CHUNK_BYTES) % 251) as u8).collect()
}

fn expected_trace(length: usize, prefix: usize) -> Vec<Event> {
    let mut offsets: VecDeque<_> = (prefix..length).step_by(CHUNK_BYTES).map(|n| n as u64).collect();
    if length == 0 {
        offsets.push_back(0);
    }
    let mut in_flight = VecDeque::new();
    let mut events = Vec::new();
    // Independent FIFO oracle: one successful oldest response permits exactly
    // one replacement request, unless all remaining ranges have been sent.
    for _ in 0..4 {
        if let Some(offset) = offsets.pop_front() {
            in_flight.push_back(offset);
            events.push(Event::Send(offset));
        }
    }
    while let Some(offset) = in_flight.pop_front() {
        events.push(Event::Receive(offset));
        if let Some(next) = offsets.pop_front() {
            in_flight.push_back(next);
            events.push(Event::Send(next));
        }
    }
    events
}

#[test]
fn result_ranges_refill_after_each_verified_chunk_without_draining_the_window() {
    for artifact in [false, true] {
        for length in [0, 1, CHUNK_BYTES - 1, CHUNK_BYTES, CHUNK_BYTES + 1,
            3 * CHUNK_BYTES + 7, 4 * CHUNK_BYTES, 4 * CHUNK_BYTES + 1,
            8 * CHUNK_BYTES + 23] {
            let parent = tempfile::tempdir().unwrap();
            let destination = parent.path().join("delivery");
            let bytes = data(length);
            let mut peer = RangePeer::new(&destination, bytes.clone(), artifact, DeliveryMode::Execute);
            let delivery = receive_execution(&mut peer, &request(), "worker", &destination).unwrap();
            assert!(delivery.acknowledgments_confirmed);
            assert_eq!(std::fs::read(peer.path(&destination)).unwrap(), bytes);
            assert_eq!(peer.events, expected_trace(length, 0), "length={length}, artifact={artifact}");
            assert!(peer.pending.is_empty());
            assert!(peer.inner.replies.is_empty());
            assert!(peer.peak <= 4);
            assert_eq!(delivery.receipt["publication_authorized"], false);
            assert_eq!(delivery.receipt["transport_authenticated"], false);
        }
    }
}

#[test]
fn every_malformed_reply_stops_refill_and_preserves_only_the_validated_prefix() {
    let bytes = data(8 * CHUNK_BYTES + 19);
    for artifact in [false, true] {
        let name = if artifact { "name" } else { "stream" };
        let mut changes = vec![
            ("kind", json!("error")), ("request_id", json!(8)),
            ("offset", json!(u64::MAX)), ("next_offset", json!(u64::MAX)),
            ("total_bytes", json!(bytes.len() + 1)), (name, json!("foreign")),
            ("sha256", json!("00".repeat(32))), ("chunk_sha256", json!("00".repeat(32))),
            ("data_hex", json!("00")), ("eof", json!(true)),
        ];
        if artifact {
            changes.push(("manifest_sha256", json!("00".repeat(32))));
            changes.push(("executable", json!(true)));
        }
        for at in 0..6 {
            for (field, value) in &changes {
                let parent = tempfile::tempdir().unwrap();
                let destination = parent.path().join("delivery");
                let mut peer = RangePeer::new(&destination, bytes.clone(), artifact, DeliveryMode::Execute);
                peer.corrupt = Some((at, field, value.clone()));
                let error = receive_execution(&mut peer, &request(), "worker", &destination).unwrap_err();
                assert!(error.execution_may_have_run);
                assert!(!error.transport_interrupted, "bad protocol is not network evidence");
                assert_eq!(peer.received, at + 1);
                assert_eq!(peer.sent, (at + 4).min(9));
                assert_eq!(std::fs::read(peer.path(&destination)).unwrap(), bytes[..at * CHUNK_BYTES]);
                peer.assert_no_release(&destination);
            }
        }
    }
}

#[test]
fn transport_loss_and_partially_accepted_refill_stop_without_tail_drain_or_retry() {
    let bytes = data(8 * CHUNK_BYTES + 19);
    for artifact in [false, true] {
        for at in 0..9 {
            for write in [false, true] {
                let parent = tempfile::tempdir().unwrap();
                let destination = parent.path().join("delivery");
                let mut peer = RangePeer::new(&destination, bytes.clone(), artifact, DeliveryMode::Execute);
                if write { peer.fail_write = Some(at); } else { peer.fail_read = Some(at); }
                let error = receive_execution(&mut peer, &request(), "worker", &destination).unwrap_err();
                assert!(error.execution_may_have_run);
                assert!(error.transport_interrupted);
                let verified = if write { (at + 1).saturating_sub(4) } else { at };
                assert_eq!(peer.received, if write { verified } else { at + 1 });
                assert_eq!(peer.sent, if write { at + 1 } else { (at + 4).min(9) });
                assert_eq!(std::fs::read(peer.path(&destination)).unwrap(), bytes[..verified * CHUNK_BYTES]);
                peer.assert_no_release(&destination);
            }
        }
    }
}

#[test]
fn valid_per_chunk_hashes_still_require_the_declared_complete_result_digest() {
    for artifact in [false, true] {
        let parent = tempfile::tempdir().unwrap();
        let destination = parent.path().join("delivery");
        let mut peer = RangePeer::new(&destination, data(6 * CHUNK_BYTES + 7), artifact, DeliveryMode::Execute);
        peer.bytes[CHUNK_BYTES + 3] ^= 1; // advertised full digest remains unchanged
        let error = receive_execution(&mut peer, &request(), "worker", &destination).unwrap_err();
        assert!(error.detail.contains("complete file digest mismatch"));
        assert!(!error.transport_interrupted);
        assert!(peer.pending.is_empty());
        peer.assert_no_release(&destination);
    }
}

#[test]
fn result_only_resume_refills_unaligned_tails_and_reverifies_complete_local_hints() {
    let bytes = data(8 * CHUNK_BYTES + 19);
    for artifact in [false, true] {
        for length in [0, 1, CHUNK_BYTES - 1, CHUNK_BYTES, CHUNK_BYTES + 1,
            4 * CHUNK_BYTES + 3, bytes.len() - 1, bytes.len()] {
            let parent = tempfile::tempdir().unwrap();
            let previous = parent.path().join("previous");
            let old_file = previous.join(if artifact { "artifacts/a" } else { "diagnostics/stdout" });
            std::fs::create_dir_all(old_file.parent().unwrap()).unwrap();
            std::fs::write(&old_file, &bytes[..length]).unwrap();
            let source = ResumeSource::open(&previous).unwrap();
            let destination = parent.path().join("resumed");
            let mut peer = RangePeer::new(&destination, bytes.clone(), artifact, DeliveryMode::Resume);
            let delivery = receive_operation(
                &mut ResumePeer::new(&mut peer, &source), &request(), "worker",
                &destination, DeliveryMode::Resume,
            ).unwrap();
            assert!(delivery.acknowledgments_confirmed);
            assert_eq!(std::fs::read(peer.path(&destination)).unwrap(), bytes);
            assert_eq!(std::fs::read(&old_file).unwrap(), bytes[..length]);
            assert_eq!(peer.events, expected_trace(bytes.len(), length));
            assert_eq!(delivery.receipt["resumed"], true);
            assert_eq!(delivery.receipt["worker_identity_scope"], "delivery-session");
            assert!(!peer.inner.sent.iter().any(|frame| frame["kind"] == "canonical-exec"));
            assert!(peer.pending.is_empty());
        }
    }
}

#[test]
fn corrupt_partial_and_complete_resume_hints_never_ack_or_reexecute() {
    let bytes = data(6 * CHUNK_BYTES + 17);
    for artifact in [false, true] {
        for length in [CHUNK_BYTES + 7, bytes.len()] {
            let parent = tempfile::tempdir().unwrap();
            let previous = parent.path().join("previous");
            let old_file = previous.join(if artifact { "artifacts/a" } else { "diagnostics/stdout" });
            let mut old = bytes[..length].to_vec();
            old[0] ^= 1;
            std::fs::create_dir_all(old_file.parent().unwrap()).unwrap();
            std::fs::write(&old_file, &old).unwrap();
            let source = ResumeSource::open(&previous).unwrap();
            let destination = parent.path().join("resumed");
            let mut peer = RangePeer::new(&destination, bytes.clone(), artifact, DeliveryMode::Resume);
            let error = receive_operation(
                &mut ResumePeer::new(&mut peer, &source), &request(), "worker",
                &destination, DeliveryMode::Resume,
            ).unwrap_err();
            assert!(error.execution_may_have_run);
            assert!(error.detail.contains("complete file digest mismatch"));
            assert_eq!(std::fs::read(&old_file).unwrap(), old);
            assert_eq!(peer.events, expected_trace(bytes.len(), length));
            assert!(!peer.inner.sent.iter().any(|frame| frame["kind"] == "canonical-exec"));
            peer.assert_no_release(&destination);
        }
    }
}
