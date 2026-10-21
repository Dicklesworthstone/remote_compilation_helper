//! Full receiver coverage with an explicitly scripted worker, not TLS or rustc.
//! Controls are queued so a per-file stop-and-wait receiver fails the trace check.
use super::*;

struct FilesPeer {
    inner: Script,
    files: Vec<(String, Vec<u8>, bool)>,
    manifest: Value,
    pending: VecDeque<Value>,
    trace: Vec<(bool, String, u64)>,
    sent: usize,
    received: usize,
    peak: usize,
    corrupt: Option<(usize, &'static str, Value)>,
    fail_send: Option<usize>,
    fail_read: Option<usize>,
    obstruct_next: Option<&'static str>,
}

impl FilesPeer {
    fn new(destination: &Path, lengths: &[usize], mode: DeliveryMode) -> Self {
        let mut inner = if mode == DeliveryMode::Resume {
            resumable(destination)
        } else {
            fixture(destination)
        };
        let files: Vec<(String, Vec<u8>, bool)> = lengths.iter().enumerate().map(|(index, length)| {
            let name = format!("tree/{index:03}.rmeta");
            let bytes: Vec<u8> = (0..*length).map(|at| ((index + at * 17) % 251) as u8).collect();
            (name, bytes, index % 2 == 0)
        }).collect();
        let mut hasher = Sha256::new();
        field(&mut hasher, b"rabs.worker-artifact-manifest.v1");
        field(&mut hasher, b"dep");
        hasher.update((files.len() as u64).to_be_bytes());
        let mut total = 0_u64;
        let rows: Vec<_> = files.iter().map(|(name, bytes, executable)| {
            let digest = hash(bytes);
            field(&mut hasher, name.as_bytes());
            hasher.update([u8::from(*executable)]);
            hasher.update((bytes.len() as u64).to_be_bytes());
            field(&mut hasher, digest.as_bytes());
            total += bytes.len() as u64;
            json!({"name":name,"bytes":bytes.len(),"sha256":digest,"executable":executable})
        }).collect();
        let digest: String = hasher.finalize().iter().map(|b| format!("{b:02x}")).collect();
        let manifest = json!({"unit":"dep","files":rows,"total_bytes":total,"manifest_sha256":digest});
        inner.replies[1]["artifact_manifest"] = manifest.clone();
        inner.replies.remove(4);
        Self {
            inner, files, manifest, pending: VecDeque::new(), trace: Vec::new(),
            sent: 0, received: 0, peak: 0, corrupt: None, fail_send: None, fail_read: None,
            obstruct_next: None,
        }
    }

    fn request(&self) -> Value {
        let mut value = request();
        value["artifacts"]["files"] = json!(self.files.iter().map(|file| &file.0).collect::<Vec<_>>());
        value
    }

    fn no_release(&self, destination: &Path) {
        assert!(no_ack(&self.inner));
        assert!(!destination.join("delivery.json").exists());
        assert!(!destination.join("delivery.pending").exists());
        assert!(self.peak <= 4);
        assert_eq!(self.inner.sent.iter().filter(|frame| {
            matches!(frame["kind"].as_str(), Some("canonical-exec" | "result-resume"))
        }).count(), 1);
    }

    fn check_files(&self, destination: &Path) {
        use std::os::unix::fs::PermissionsExt;
        for (name, bytes, executable) in &self.files {
            let path = destination.join("artifacts").join(name);
            assert_eq!(std::fs::read(&path).unwrap(), *bytes);
            assert_eq!(std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
                if *executable { 0o700 } else { 0o600 });
        }
    }
}

impl WorkerPeer for FilesPeer {
    fn send(&mut self, frame: &Value) -> io::Result<()> {
        if matches!(frame["kind"].as_str(), Some("output-ack" | "artifact-ack")) {
            assert!(self.pending.is_empty(), "no release while file responses remain");
            self.check_files(&self.inner.destination);
        }
        self.inner.send(frame)?;
        if frame["kind"] != "artifact-read" {
            return Ok(());
        }
        assert_eq!(frame["request_id"], 7);
        assert_eq!(frame["max_bytes"], CHUNK_BYTES);
        assert!(self.pending.len() < 4, "window must be shared across files");
        self.trace.push((true, frame["name"].as_str().unwrap().into(), frame["offset"].as_u64().unwrap()));
        self.pending.push_back(frame.clone());
        self.peak = self.peak.max(self.pending.len());
        let index = self.sent;
        self.sent += 1;
        if index == 0 && let Some(kind) = self.obstruct_next {
            // Install a conflicting destination after one range is in flight.
            // This is a real create-new refusal, not a forged network error.
            let next = self.inner.destination.join("artifacts").join(&self.files[1].0);
            match kind {
                "file" => std::fs::write(next, b"preexisting output")?,
                "directory" => std::fs::create_dir(next)?,
                "symlink" => std::os::unix::fs::symlink(
                    self.inner.destination.join("diagnostics/stdout"), next,
                )?,
                _ => panic!("unknown destination obstruction"),
            }
        }
        if self.fail_send == Some(index) {
            return Err(worker_transport_error(io::Error::new(io::ErrorKind::BrokenPipe, "partly accepted range")));
        }
        Ok(())
    }

    fn receive(&mut self) -> io::Result<Value> {
        let Some(frame) = self.pending.pop_front() else {
            return self.inner.receive();
        };
        let name = frame["name"].as_str().unwrap();
        let offset = frame["offset"].as_u64().unwrap();
        self.trace.push((false, name.into(), offset));
        let index = self.received;
        self.received += 1;
        if self.fail_read == Some(index) {
            return Err(worker_transport_error(io::Error::new(io::ErrorKind::TimedOut, "absolute transfer deadline")));
        }
        let file_index = self.files.iter().position(|file| file.0 == name).unwrap();
        let (_, bytes, executable) = &self.files[file_index];
        let start = usize::try_from(offset).unwrap();
        let end = (start + CHUNK_BYTES).min(bytes.len());
        let mut reply = chunk(name, &bytes[start..end], true);
        reply["offset"] = json!(offset);
        reply["next_offset"] = json!(end);
        reply["eof"] = json!(end == bytes.len());
        reply["total_bytes"] = json!(bytes.len());
        reply["sha256"] = self.manifest["files"][file_index]["sha256"].clone();
        reply["manifest_sha256"] = self.manifest["manifest_sha256"].clone();
        reply["executable"] = json!(executable);
        if let Some((at, field, value)) = &self.corrupt
            && *at == index
        {
            reply[*field] = value.clone();
        }
        Ok(reply)
    }
}

fn trace_for(files: &[(String, Vec<u8>, bool)], prefixes: &[usize]) -> Vec<(bool, String, u64)> {
    let mut ranges = VecDeque::new();
    for ((name, bytes, _), prefix) in files.iter().zip(prefixes) {
        if bytes.is_empty() {
            ranges.push_back((name.clone(), 0));
        } else {
            ranges.extend((*prefix..bytes.len()).step_by(CHUNK_BYTES).map(|offset| (name.clone(), offset as u64)));
        }
    }
    let mut in_flight = VecDeque::new();
    let mut events = Vec::new();
    for _ in 0..4 {
        if let Some((name, offset)) = ranges.pop_front() {
            events.push((true, name.clone(), offset));
            in_flight.push_back((name, offset));
        }
    }
    while let Some((name, offset)) = in_flight.pop_front() {
        events.push((false, name, offset));
        if let Some((name, offset)) = ranges.pop_front() {
            events.push((true, name.clone(), offset));
            in_flight.push_back((name, offset));
        }
    }
    events
}

#[test]
fn one_window_spans_small_empty_and_multichunk_files_in_manifest_order() {
    for lengths in [
        vec![1; 9], vec![0; 9], vec![0, 1, CHUNK_BYTES, 0, CHUNK_BYTES + 1, 3],
        vec![5 * CHUNK_BYTES + 7, 1, 0, 6 * CHUNK_BYTES, 3],
    ] {
        let owner = tempfile::tempdir().unwrap();
        let destination = owner.path().join("delivery");
        let mut peer = FilesPeer::new(&destination, &lengths, DeliveryMode::Execute);
        let request = peer.request();
        let result = receive_execution(&mut peer, &request, "worker", &destination).unwrap();
        assert!(result.acknowledgments_confirmed);
        peer.check_files(&destination);
        assert_eq!(peer.trace, trace_for(&peer.files, &vec![0; lengths.len()]));
        assert!(peer.pending.is_empty());
        assert!(peer.inner.replies.is_empty());
        assert_eq!(peer.peak, 4);
        assert_eq!(result.receipt["publication_authorized"], false);
        assert_eq!(result.receipt["transport_authenticated"], false);
        super::super::super::delivery_recovery::recover_existing_delivery(
            &request, "worker", &destination,
            super::super::super::delivery_recovery::DeliveryTrust::Loopback,
        ).unwrap().unwrap();
    }
}

#[test]
fn foreign_file_identity_or_mode_cannot_consume_a_different_files_credit() {
    for at in 0..7 {
        for (field, value) in [
            ("name", json!("tree/999.rmeta")), ("request_id", json!(8)),
            ("offset", json!(1)), ("manifest_sha256", json!("00".repeat(32))),
            ("executable", json!(at % 2 != 0)), ("chunk_sha256", json!("00".repeat(32))),
        ] {
            let owner = tempfile::tempdir().unwrap();
            let destination = owner.path().join("delivery");
            let mut peer = FilesPeer::new(&destination, &[17; 9], DeliveryMode::Execute);
            let request = peer.request();
            peer.corrupt = Some((at, field, value));
            let failure = receive_execution(&mut peer, &request, "worker", &destination).unwrap_err();
            assert!(failure.execution_may_have_run);
            assert!(!failure.transport_interrupted);
            assert_eq!(peer.received, at + 1);
            assert_eq!(peer.sent, (at + 4).min(9));
            for (index, (name, bytes, _)) in peer.files.iter().enumerate().take(peer.sent) {
                assert_eq!(std::fs::read(destination.join("artifacts").join(name)).unwrap(),
                    if index < at { bytes.as_slice() } else { &[] });
            }
            peer.no_release(&destination);
        }
    }
}

#[test]
fn lost_cross_file_controls_stop_without_tail_drain_or_reexecution() {
    for at in 0..9 {
        for writing in [false, true] {
            let owner = tempfile::tempdir().unwrap();
            let destination = owner.path().join("delivery");
            let mut peer = FilesPeer::new(&destination, &[7; 9], DeliveryMode::Execute);
            let request = peer.request();
            if writing { peer.fail_send = Some(at); } else { peer.fail_read = Some(at); }
            let failure = receive_execution(&mut peer, &request, "worker", &destination).unwrap_err();
            assert!(failure.execution_may_have_run && failure.transport_interrupted);
            assert_eq!(peer.sent, if writing { at + 1 } else { (at + 4).min(9) });
            assert_eq!(peer.received, if writing { (at + 1).saturating_sub(4) } else { at + 1 });
            peer.no_release(&destination);
        }
    }
}

#[test]
fn complete_file_hash_failure_stops_before_receiving_the_next_file() {
    for at in 0..6 {
        let owner = tempfile::tempdir().unwrap();
        let destination = owner.path().join("delivery");
        let mut peer = FilesPeer::new(&destination, &[17; 9], DeliveryMode::Execute);
        let request = peer.request();
        // Each reply has a valid chunk hash, but this file differs from its manifest.
        peer.files[at].1[0] ^= 1;
        let failure = receive_execution(&mut peer, &request, "worker", &destination).unwrap_err();
        assert!(failure.detail.contains("complete file digest mismatch"));
        assert_eq!(peer.received, at + 1);
        assert_eq!(peer.sent, (at + 4).min(9));
        assert!(!peer.pending.is_empty());
        peer.no_release(&destination);
    }
}

#[test]
fn result_resume_shares_the_window_across_complete_unaligned_and_missing_hints() {
    let lengths = [17, 3 * CHUNK_BYTES + 13, 0, 1, 2 * CHUNK_BYTES + 7, 19];
    let prefixes = [17, CHUNK_BYTES + 1, 0, 0, CHUNK_BYTES - 1, 19];
    let owner = tempfile::tempdir().unwrap();
    let previous = owner.path().join("previous");
    let destination = owner.path().join("resumed");
    let mut peer = FilesPeer::new(&destination, &lengths, DeliveryMode::Resume);
    for ((name, bytes, _), length) in peer.files.iter().zip(prefixes) {
        let path = previous.join("artifacts").join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        if length != 0 {
            std::fs::write(&path, &bytes[..length]).unwrap();
        }
    }
    let source = ResumeSource::open(&previous).unwrap();
    let request = peer.request();
    let result = receive_operation(&mut ResumePeer::new(&mut peer, &source),
        &request, "worker", &destination, DeliveryMode::Resume).unwrap();
    assert!(result.acknowledgments_confirmed);
    peer.check_files(&destination);
    assert_eq!(peer.trace, trace_for(&peer.files, &prefixes));
    assert_eq!(result.receipt["worker_identity_scope"], "delivery-session");
    assert!(!peer.inner.sent.iter().any(|frame| frame["kind"] == "canonical-exec"));
    for ((name, bytes, _), length) in peer.files.iter().zip(prefixes) {
        let old = previous.join("artifacts").join(name);
        if length != 0 { assert_eq!(std::fs::read(old).unwrap(), bytes[..length]); }
        else { assert!(!old.exists()); }
    }
}

#[test]
fn local_destination_refusal_does_not_drain_or_overwrite_pending_files() {
    for obstruction in ["file", "directory", "symlink"] {
        let owner = tempfile::tempdir().unwrap();
        let destination = owner.path().join("delivery");
        let mut peer = FilesPeer::new(&destination, &[17; 6], DeliveryMode::Execute);
        peer.obstruct_next = Some(obstruction);
        let request = peer.request();
        let failure = receive_execution(&mut peer, &request, "worker", &destination).unwrap_err();
        assert!(failure.execution_may_have_run);
        assert!(!failure.transport_interrupted, "local failure cannot penalize transport");
        assert_eq!(peer.sent, 1);
        assert_eq!(peer.received, 0);
        assert_eq!(peer.pending.len(), 1);
        let artifacts = destination.join("artifacts");
        assert_eq!(std::fs::read(artifacts.join(&peer.files[0].0)).unwrap(), b"");
        assert!(!artifacts.join(&peer.files[2].0).exists());
        let blocked = artifacts.join(&peer.files[1].0);
        match obstruction {
            "file" => assert_eq!(std::fs::read(blocked).unwrap(), b"preexisting output"),
            "directory" => assert!(std::fs::symlink_metadata(blocked).unwrap().is_dir()),
            "symlink" => assert!(std::fs::symlink_metadata(blocked).unwrap().file_type().is_symlink()),
            _ => unreachable!(),
        }
        assert_eq!(std::fs::read(destination.join("diagnostics/stdout")).unwrap(), peer.inner.expected_stdout);
        peer.no_release(&destination);
    }
}

#[test]
fn complete_bad_resume_hint_stops_before_consuming_earlier_queued_ranges() {
    for at in 1..4 {
        let owner = tempfile::tempdir().unwrap();
        let previous = owner.path().join("previous");
        let destination = owner.path().join("resumed");
        let mut peer = FilesPeer::new(&destination, &[17; 6], DeliveryMode::Resume);
        let bad_file = previous.join("artifacts").join(&peer.files[at].0);
        std::fs::create_dir_all(bad_file.parent().unwrap()).unwrap();
        let mut bad_bytes = peer.files[at].1.clone();
        bad_bytes[0] ^= 1;
        std::fs::write(&bad_file, &bad_bytes).unwrap();
        let source = ResumeSource::open(&previous).unwrap();
        let request = peer.request();
        let failure = receive_operation(
            &mut ResumePeer::new(&mut peer, &source), &request, "worker",
            &destination, DeliveryMode::Resume,
        ).unwrap_err();
        assert!(failure.execution_may_have_run);
        assert!(failure.detail.contains("complete file digest mismatch"));
        assert!(!failure.transport_interrupted);
        assert_eq!(peer.sent, at);
        assert_eq!(peer.received, 0);
        assert_eq!(peer.pending.len(), at);
        assert_eq!(std::fs::read(&bad_file).unwrap(), bad_bytes);
        assert!(!peer.inner.sent.iter().any(|frame| frame["kind"] == "canonical-exec"));
        peer.no_release(&destination);
    }
}

#[test]
fn lost_release_ack_keeps_the_whole_verified_pipelined_delivery_recoverable() {
    use crate::coord::delivery_recovery::{DeliveryTrust, recover_existing_delivery};

    for lost in ["output-ack", "artifact-ack", "artifact-reply"] {
        let owner = tempfile::tempdir().unwrap();
        let destination = owner.path().join("delivery");
        let mut peer = FilesPeer::new(&destination, &[0, 1, CHUNK_BYTES + 7, 2, 17], DeliveryMode::Execute);
        let request = peer.request();
        match lost {
            "artifact-reply" => { peer.inner.replies.pop_back(); }
            _ => peer.inner.fail_send = Some(lost),
        }
        let result = receive_execution(&mut peer, &request, "worker", &destination).unwrap();
        assert!(!result.acknowledgments_confirmed);
        assert!(result.acknowledgment_error.is_some());
        assert!(peer.pending.is_empty());
        assert_eq!(peer.trace, trace_for(&peer.files, &[0; 5]));
        peer.check_files(&destination);
        let marker = std::fs::read(destination.join("delivery.json")).unwrap();
        assert!(!destination.join("delivery.pending").exists());
        let recovered = recover_existing_delivery(&request, "worker", &destination, DeliveryTrust::Loopback)
            .unwrap().unwrap();
        assert_eq!(recovered.receipt, result.receipt);
        assert_eq!(std::fs::read(destination.join("delivery.json")).unwrap(), marker);
        peer.check_files(&destination);
        assert_eq!(peer.inner.sent.iter().filter(|frame| frame["kind"] == "canonical-exec").count(), 1);
        assert_eq!(result.receipt["publication_authorized"], false);
    }
}
