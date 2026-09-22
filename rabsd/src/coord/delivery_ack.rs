//! Reconcile lost worker acceptance AFTER a complete durable local delivery.
//!
//! Offline recovery intentionally never contacts a worker. This separate,
//! explicit operation frees its retained-result capacity without downloading
//! the same bytes or running the compiler again. The existing result-resume,
//! request-status and identity-bound ACK messages are the only wire operations.
//! A local receipt is not permission to discard a DIFFERENT remote result.

use super::delivery_recovery::{DeliveryTrust, recover_existing_delivery};
use super::worker_delivery::{Delivery, DeliveryFailure, DeliveryMode, MAX_FRAME_BYTES, WorkerPeer};
use serde_json::{Value, json};
use std::io;
use std::path::Path;

const RETENTION: &str = "durable-result-v1";
// No compiler runs during reconciliation. Bound telemetry while the transport
// enforces the absolute restoration/ACK deadline; heartbeats grant no new time.
const MAX_RECONCILIATION_HEARTBEATS: usize = 1024;

fn require(condition: bool, message: &str) -> io::Result<()> {
    if condition { Ok(()) } else { Err(io::Error::new(io::ErrorKind::InvalidData, message)) }
}
fn canonical_hex(value: &Value, digits: usize) -> bool {
    value.as_str().is_some_and(|value| value.len() == digits
        && value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
}
fn advertised(hello: &Value, field: &str, value: &str) -> bool {
    hello[field].as_array().is_some_and(|items| items.iter().any(|item| item == value))
}
fn response(peer: &mut impl WorkerPeer, worker: &str) -> io::Result<Value> {
    for _ in 0..=MAX_RECONCILIATION_HEARTBEATS {
        let value = peer.receive()?;
        require(serde_json::to_vec(&value)?.len() <= MAX_FRAME_BYTES, "oversized acknowledgment response")?;
        if value["kind"] != "heartbeat" { return Ok(value); }
        require(value["worker_id"] == worker, "foreign heartbeat during acknowledgment")?;
    }
    Err(io::Error::new(io::ErrorKind::InvalidData, "excess telemetry during acknowledgment"))
}

/// A request-bound, byte-verified local result. Only filesystem recovery can
/// construct this proof; callers cannot substitute a peer's claimed receipt.
/// It is consumed by one reconciliation attempt, never retried on its connection.
pub struct PendingAcknowledgment {
    request: Value,
    worker: String,
    trust: DeliveryTrust,
    delivery: Delivery,
}

impl std::fmt::Debug for PendingAcknowledgment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingAcknowledgment")
            .field("directory", &self.delivery.directory)
            .field("worker", &self.worker)
            .finish_non_exhaustive() // Never dump command/environment/source data.
    }
}

impl PendingAcknowledgment {
    /// Verify complete local bytes, exact request, historical transport and a
    /// canonical durable-result seal BEFORE binding or contacting any worker.
    /// Missing, partial, legacy digest-only and corrupt deliveries all refuse.
    pub fn verify(
        request: &Value, worker: &str, directory: &Path, trust: DeliveryTrust,
    ) -> Result<Self, DeliveryFailure> {
        let failure = |detail: &str| DeliveryFailure {
            directory: directory.to_path_buf(), execution_may_have_run: true,
            detail: detail.to_owned(),
        };
        let delivery = recover_existing_delivery(request, worker, directory, trust)?
            .ok_or_else(|| failure("acknowledgment requires an existing verified delivery; never execute or download"))?;
        if delivery.receipt["result_retention"] != RETENTION
            || !canonical_hex(&delivery.receipt["retained_result_sha256"], 64)
        {
            return Err(failure("delivery lacks a durable result seal; remote copies cannot be released"));
        }
        Ok(Self { request: request.clone(), worker: worker.to_owned(), trust, delivery })
    }

    /// Original request, for narrowing the authenticated recovery adapter.
    #[must_use]
    pub fn request(&self) -> &Value { &self.request }

    /// Historical worker label. This is NOT transport-authentication evidence.
    #[must_use]
    pub fn worker(&self) -> &str { &self.worker }

    /// Existing private directory; this operation never creates or replaces it.
    #[must_use]
    pub fn directory(&self) -> &Path { &self.delivery.directory }

    fn failure(&self, error: impl std::fmt::Display) -> DeliveryFailure {
        DeliveryFailure {
            directory: self.delivery.directory.clone(), execution_may_have_run: true,
            detail: format!("worker acknowledgment unconfirmed; local delivery retained; do not reexecute: {error}"),
        }
    }

    fn verify_unchanged(&self) -> io::Result<()> {
        let current = recover_existing_delivery(
            &self.request, &self.worker, &self.delivery.directory, self.trust,
        ).map_err(io::Error::other)?;
        require(current.is_some_and(|current| current.receipt == self.delivery.receipt),
            "local delivery changed during acknowledgment admission")
    }

    fn check_session(&self, peer: &impl WorkerPeer) -> io::Result<()> {
        let proof = peer.authentication();
        require(match (self.trust, proof) {
            (DeliveryTrust::Loopback, None) => true,
            (DeliveryTrust::PinnedWorker(pin), Some(proof)) => pin != [0; 32]
                && proof.spki_sha256 == pin && proof.session_id > 0 && proof.identity_generation > 0,
            _ => false,
        }, "acknowledgment transport differs from the verified delivery trust")
    }

    fn check_outcome(&self, result: &Value) -> io::Result<()> {
        require(result["kind"] == "exec-result"
            && result["request_id"] == self.request["request_id"]
            && result["executed"] == true
            && result["residual_group_members"].as_u64() == Some(0)
            && result["retained_result_sha256"] == self.delivery.receipt["retained_result_sha256"],
            "remote result seal or execution identity differs from local delivery")?;
        for field in ["exit_code", "stop_reason", "stdout_sha256", "stderr_sha256"] {
            require(result.get(field).is_some() && result.get(field) == self.delivery.receipt.get(field),
                "remote execution outcome differs from local delivery")?;
        }
        Ok(())
    }

    fn confirm(&self, peer: &mut impl WorkerPeer) -> io::Result<()> {
        let hello = peer.receive()?;
        require(serde_json::to_vec(&hello)?.len() <= MAX_FRAME_BYTES, "oversized worker hello")?;
        require(hello["kind"] == "worker-hello" && hello["worker_id"] == self.worker,
            "acknowledgment connected to an unexpected worker")?;
        require(hello["request_high_water"] == self.request["request_id"],
            "worker no longer retains this exact admission; do not infer acceptance from high-water")?;
        let original_boot = self.delivery.receipt["boot_generation"].as_u64().unwrap_or(u64::MAX);
        require(hello["boot_generation"].as_u64().is_some_and(|boot| boot > 0 && boot >= original_boot)
            && canonical_hex(&hello["incarnation"], 32)
            && hello["incarnation"].as_str().is_some_and(|value| value.bytes().any(|byte| byte != b'0')),
            "worker acknowledgment incarnation is invalid or stale")?;
        require(advertised(&hello, "recovery_protocols", "request-journal-v1")
            && advertised(&hello, "result_retentions", RETENTION)
            && advertised(&hello, "output_transfers", "ranges-v1"),
            "worker lacks durable acknowledgment recovery capabilities")?;
        let mut grant = json!({"kind":"session-ok", "output_transfer":"ranges-v1",
            "recovery_protocol":"request-journal-v1", "result_retention":RETENTION});
        if self.request.get("artifacts").is_some() {
            require(advertised(&hello, "artifact_transfers", "files-v1"), "worker lacks artifact recovery")?;
            grant["artifact_transfer"] = json!("files-v1");
        }
        peer.negotiate(&hello, &grant)?;
        self.check_session(peer)?;
        // This only reinstates delivery ownership. It cannot admit a compiler
        // and includes the entire original request for the worker journal fence.
        peer.send(&DeliveryMode::Resume.frame(&self.request))?;
        let result = response(peer, &self.worker)?;
        if result["kind"] == "error" {
            require(result["request_id"] == self.request["request_id"], "foreign resume refusal")?;
            // Both ACKs may have committed and their final reply been lost.
            // Only an exact terminal seal marked RELEASED can confirm that;
            // an error, absent spool, label or high-water alone cannot.
            peer.send(&json!({"kind":"request-status", "request_id":self.request["request_id"]}))?;
            let status = response(peer, &self.worker)?;
            require(status["kind"] == "request-status"
                && status["request_id"] == self.request["request_id"]
                && status["high_water"] == self.request["request_id"]
                && status["status"] == "terminal-observed"
                && status["output_recovery"] == "unavailable"
                && status["replay_authorized"] == false
                && status["publication_authorized"] == false
                && status["receipt"]["retained_result_released"] == true,
                "worker has not durably confirmed acceptance of this result")?;
            self.check_outcome(&status["receipt"])?;
            return self.verify_unchanged();
        }
        self.check_outcome(&result)?;
        require(result["resumed"] == true && result["result_retention"] == RETENTION
            && result["output_transfer"] == "ranges-v1" && result["output_ack_required"] == true,
            "worker did not resume the sealed delivery for acknowledgment")?;
        for field in ["stdout_bytes", "stderr_bytes", "artifact_manifest"] {
            require(result.get(field).is_some() && result.get(field) == self.delivery.receipt.get(field),
                "resumed output manifest differs from local delivery")?;
        }
        let artifacts = !self.delivery.receipt["artifact_manifest"].is_null();
        require(result["artifact_ack_required"].as_bool() == Some(artifacts)
            && (!artifacts || result["artifact_transfer"] == "files-v1"),
            "resumed artifact acknowledgment policy mismatch")?;
        // Rehash after the network round trip, before giving up the remote
        // copies. Callers must exclude concurrent same-credential modification,
        // as for normal delivery/recovery; no advisory lock asserts otherwise.
        self.verify_unchanged()?;
        let receipt = &self.delivery.receipt;
        self.ack(peer, json!({"kind":"output-ack", "request_id":self.request["request_id"],
            "stdout_bytes":receipt["stdout_bytes"], "stdout_sha256":receipt["stdout_sha256"],
            "stderr_bytes":receipt["stderr_bytes"], "stderr_sha256":receipt["stderr_sha256"]}),
            "output-acknowledged")?;
        if artifacts {
            self.ack(peer, json!({"kind":"artifact-ack", "request_id":self.request["request_id"],
                "manifest_sha256":receipt["artifact_manifest"]["manifest_sha256"],
                "total_bytes":receipt["artifact_manifest"]["total_bytes"]}), "artifact-acknowledged")?;
        }
        Ok(())
    }

    fn ack(&self, peer: &mut impl WorkerPeer, frame: Value, kind: &str) -> io::Result<()> {
        peer.send(&frame)?;
        let reply = response(peer, &self.worker)?;
        require(reply["kind"] == kind && reply["request_id"] == self.request["request_id"]
            && reply["already_released"].as_bool().is_some(), "worker acceptance response mismatch")
    }

    /// Consume one proof on one admitted transport. Only metadata/resume/ACKs
    /// are sent, never source bytes, byte-range reads or canonical-exec. Errors
    /// leave the local tree and receipt unchanged and never retry on this peer.
    pub fn acknowledge(mut self, peer: &mut impl WorkerPeer) -> Result<Delivery, DeliveryFailure> {
        self.confirm(peer).map_err(|error| self.failure(error))?;
        self.delivery.acknowledgments_confirmed = true;
        self.delivery.acknowledgment_error = None;
        Ok(self.delivery)
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use super::super::worker_delivery::WorkerAuthentication;
    use sha2::{Digest, Sha256};
    use std::collections::VecDeque;
    use std::fs;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::path::PathBuf;

    fn hash(bytes: &[u8]) -> String { Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect() }
    fn field(hash: &mut Sha256, bytes: &[u8]) { hash.update((bytes.len() as u64).to_be_bytes()); hash.update(bytes); }

    struct Fixture {
        owner: tempfile::TempDir,
        request: Value,
        receipt: Value,
    }
    impl Fixture {
        fn new(artifacts: bool, pinned: bool) -> Self {
            let owner = tempfile::tempdir().unwrap();
            let directory = owner.path().join("delivery");
            fs::create_dir(&directory).unwrap();
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
            for name in ["diagnostics", "artifacts"] { fs::create_dir(directory.join(name)).unwrap(); }
            let mut request = json!({"kind":"canonical-exec", "request_id":7, "program":"rustc",
                "args":["private.rs"], "workspace_backing":"/ws", "toolchain_backing":"/tc"});
            let mut manifest = Value::Null;
            if artifacts {
                request["artifacts"] = json!({"unit":"dep", "files":["a"], "tree":"tree-files-v1"});
                let mut h = Sha256::new();
                field(&mut h, b"rabs.worker-artifact-manifest.v1"); field(&mut h, b"dep");
                h.update(2_u64.to_be_bytes());
                for name in ["a", "intermediate"] {
                    fs::write(directory.join("artifacts").join(name), b"obj").unwrap();
                    field(&mut h, name.as_bytes()); h.update([0]); h.update(3_u64.to_be_bytes());
                    field(&mut h, hash(b"obj").as_bytes());
                }
                manifest = json!({"unit":"dep", "total_bytes":6,
                    "manifest_sha256":h.finalize().iter().map(|b| format!("{b:02x}")).collect::<String>(),
                    "files":[{"name":"a", "bytes":3, "sha256":hash(b"obj"), "executable":false},
                        {"name":"intermediate", "bytes":3, "sha256":hash(b"obj"), "executable":false}]});
            }
            fs::write(directory.join("diagnostics/stdout"), b"ok\0\xff").unwrap();
            fs::write(directory.join("diagnostics/stderr"), b"").unwrap();
            let receipt = json!({"version":1, "kind":"verified-worker-delivery", "request_id":7,
                "worker_id":"worker", "boot_generation":1, "incarnation":"01".repeat(16),
                "request_sha256":hash(&serde_json::to_vec(&request).unwrap()),
                "exit_code":if artifacts {0} else {1}, "stop_reason":null,
                "stdout_bytes":4, "stdout_sha256":hash(b"ok\0\xff"), "stderr_bytes":0, "stderr_sha256":hash(b""),
                "artifact_manifest":manifest, "total_bytes":if artifacts {10} else {4},
                "result_retention":RETENTION, "retained_result_sha256":"07".repeat(32),
                "transport_authenticated":pinned,
                "worker_spki_sha256":if pinned {json!("01".repeat(32))} else {Value::Null},
                "authenticated_session_id":if pinned {json!(11)} else {Value::Null},
                "identity_generation":if pinned {json!(1)} else {Value::Null},
                "publication_authorized":false, "reexecute":false});
            fs::write(directory.join("delivery.json"), serde_json::to_vec(&receipt).unwrap()).unwrap();
            for path in ["delivery.json", "diagnostics/stdout", "diagnostics/stderr"] {
                fs::set_permissions(directory.join(path), fs::Permissions::from_mode(0o600)).unwrap();
            }
            if artifacts {
                for name in ["a", "intermediate"] {
                    fs::set_permissions(directory.join("artifacts").join(name), fs::Permissions::from_mode(0o600)).unwrap();
                }
            }
            Self { owner, request, receipt }
        }
        fn directory(&self) -> PathBuf { self.owner.path().join("delivery") }
        fn trust(&self) -> DeliveryTrust {
            if self.receipt["transport_authenticated"] == true { DeliveryTrust::PinnedWorker([1; 32]) }
            else { DeliveryTrust::Loopback }
        }
        fn pending(&self) -> PendingAcknowledgment {
            PendingAcknowledgment::verify(&self.request, "worker", &self.directory(), self.trust()).unwrap()
        }
        fn peer(&self) -> Script {
            let mut result = self.receipt.clone();
            result["kind"] = json!("exec-result");
            result["executed"] = json!(true);
            result["resumed"] = json!(true);
            result["residual_group_members"] = json!(0);
            result["output_transfer"] = json!("ranges-v1");
            result["output_ack_required"] = json!(true);
            result["artifact_transfer"] = json!("files-v1");
            let artifacts = !result["artifact_manifest"].is_null();
            result["artifact_ack_required"] = json!(artifacts);
            let mut replies = VecDeque::from([
                json!({"kind":"worker-hello", "worker_id":"worker", "boot_generation":2,
                    "incarnation":"02".repeat(16), "request_high_water":7,
                    "recovery_protocols":["request-journal-v1"], "result_retentions":[RETENTION],
                    "output_transfers":["ranges-v1"], "artifact_transfers":["files-v1"]}), result,
                json!({"kind":"output-acknowledged", "request_id":7, "already_released":false}),
            ]);
            if artifacts { replies.push_back(json!({"kind":"artifact-acknowledged", "request_id":7, "already_released":false})); }
            Script { replies, sent:Vec::new(), corrupt_on_result:None,
                proof:if self.receipt["transport_authenticated"] == true {
                    Some(WorkerAuthentication { spki_sha256:[1;32], session_id:22, identity_generation:1 })
                } else { None } }
        }
    }
    struct Script {
        replies: VecDeque<Value>,
        sent: Vec<Value>,
        proof: Option<WorkerAuthentication>,
        corrupt_on_result: Option<PathBuf>,
    }
    impl WorkerPeer for Script {
        fn send(&mut self, value: &Value) -> io::Result<()> {
            assert!(!matches!(value["kind"].as_str(), Some("canonical-exec" | "output-read" | "artifact-read" | "source-begin" | "source-chunk")));
            self.sent.push(value.clone()); Ok(())
        }
        fn receive(&mut self) -> io::Result<Value> {
            let value = self.replies.pop_front().ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "lost reply"))?;
            if value["kind"] == "exec-result" && let Some(path) = self.corrupt_on_result.take() { fs::write(path, b"bad")?; }
            Ok(value)
        }
        fn authentication(&self) -> Option<WorkerAuthentication> { self.proof }
    }
    fn no_ack(peer: &Script) -> bool {
        !peer.sent.iter().any(|value| matches!(value["kind"].as_str(), Some("output-ack" | "artifact-ack")))
    }

    #[test]
    fn verified_delivery_releases_remote_copies_without_reading_ranges_or_changing_local_files() {
        for artifacts in [false, true] {
            for pinned in [false, true] {
                let f = Fixture::new(artifacts, pinned);
                let marker = fs::read(f.directory().join("delivery.json")).unwrap();
                let inode = fs::metadata(f.directory().join("diagnostics/stdout")).unwrap().ino();
                let mut peer = f.peer();
                let delivered = f.pending().acknowledge(&mut peer).unwrap();
                assert!(delivered.acknowledgments_confirmed);
                assert!(delivered.acknowledgment_error.is_none());
                assert_eq!(delivered.receipt, f.receipt);
                assert_eq!(fs::read(f.directory().join("delivery.json")).unwrap(), marker);
                assert_eq!(fs::metadata(f.directory().join("diagnostics/stdout")).unwrap().ino(), inode);
                assert_eq!(peer.sent[1], DeliveryMode::Resume.frame(&f.request));
                assert_eq!(peer.sent.len(), if artifacts {4} else {3});
                assert!(peer.replies.is_empty());
            }
        }
    }

    #[test]
    fn changed_remote_outcome_or_seal_never_releases_either_capture() {
        for (field, value) in [("retained_result_sha256", json!("08".repeat(32))),
            ("request_id", json!(8)), ("exit_code", json!(1)), ("stop_reason", json!("cancelled")),
            ("stdout_bytes", json!(5)), ("stdout_sha256", json!("09".repeat(32))),
            ("artifact_manifest", Value::Null), ("resumed", json!(false)),
            ("artifact_ack_required", json!(false)), ("residual_group_members", json!(1))] {
            let f = Fixture::new(true, false);
            let mut peer = f.peer(); peer.replies[1][field] = value;
            assert!(f.pending().acknowledge(&mut peer).unwrap_err().execution_may_have_run, "{field}");
            assert!(no_ack(&peer), "{field}");
            f.pending();
        }
    }

    #[test]
    fn wrong_worker_capability_high_water_or_transport_never_receives_acceptance() {
        for case in 0..6 {
            let f = Fixture::new(true, true);
            let mut peer = f.peer();
            match case {
                0 => peer.replies[0]["worker_id"] = json!("other"),
                1 => peer.replies[0]["request_high_water"] = json!(8),
                2 => peer.replies[0]["boot_generation"] = json!(0),
                3 => peer.replies[0]["result_retentions"] = json!([]),
                4 => peer.proof = None,
                _ => peer.proof.as_mut().unwrap().spki_sha256 = [2;32],
            }
            assert!(f.pending().acknowledge(&mut peer).is_err());
            assert!(no_ack(&peer));
            assert!(!peer.sent.iter().any(|value| value["kind"] == "result-resume"));
        }
    }

    #[test]
    fn partial_or_corrupt_local_delivery_cannot_mint_an_acknowledgment_proof() {
        for case in 0..5 {
            let f = Fixture::new(true, false);
            match case {
                0 => fs::write(f.directory().join("artifacts/intermediate"), b"bad").unwrap(),
                1 => fs::rename(f.directory().join("delivery.json"), f.directory().join("delivery.pending")).unwrap(),
                2 => fs::write(f.directory().join("unexpected"), b"bad").unwrap(),
                _ => {
                    let mut receipt = f.receipt.clone();
                    if case == 3 { receipt.as_object_mut().unwrap().remove("result_retention"); }
                    else { receipt["retained_result_sha256"] = json!("not-a-seal"); }
                    fs::write(f.directory().join("delivery.json"), serde_json::to_vec(&receipt).unwrap()).unwrap();
                }
            }
            assert!(PendingAcknowledgment::verify(&f.request, "worker", &f.directory(), f.trust()).is_err());
        }
    }

    #[test]
    fn local_bytes_are_reverified_after_network_admission_before_any_ack() {
        let f = Fixture::new(true, false);
        let pending = f.pending();
        let mut peer = f.peer();
        peer.corrupt_on_result = Some(f.directory().join("artifacts/intermediate"));
        assert!(pending.acknowledge(&mut peer).is_err());
        assert!(no_ack(&peer));
    }

    #[test]
    fn lost_acceptance_reply_keeps_local_result_and_can_retry_only_on_a_new_session() {
        let f = Fixture::new(true, false);
        for replies in [2, 3] {
            let mut peer = f.peer(); peer.replies.truncate(replies);
            assert!(f.pending().acknowledge(&mut peer).is_err());
            assert_eq!(peer.sent.iter().filter(|value| value["kind"] == "result-resume").count(), 1);
        }
        assert!(f.pending().acknowledge(&mut f.peer()).unwrap().acknowledgments_confirmed);
    }

    #[test]
    fn lost_final_reply_is_confirmed_only_by_the_exact_durably_released_seal() {
        for case in 0..6 {
            let f = Fixture::new(true, false);
            let mut peer = f.peer();
            let mut receipt = peer.replies[1].clone();
            receipt["retained_result_released"] = json!(true);
            let mut status = json!({"kind":"request-status", "request_id":7, "high_water":7,
                "status":"terminal-observed", "output_recovery":"unavailable", "receipt":receipt,
                "replay_authorized":false, "publication_authorized":false});
            match case {
                0 => {}
                1 => status["receipt"]["retained_result_released"] = json!(false),
                2 => status["receipt"]["retained_result_sha256"] = json!("09".repeat(32)),
                3 => status["status"] = json!("retired"),
                4 => status["high_water"] = json!(8),
                _ => status["receipt"]["stdout_sha256"] = json!("09".repeat(32)),
            }
            peer.replies.truncate(1);
            peer.replies.push_back(json!({"kind":"error", "request_id":7, "reason":"no retained result"}));
            peer.replies.push_back(status);
            let result = f.pending().acknowledge(&mut peer);
            assert_eq!(result.is_ok(), case == 0);
            assert!(no_ack(&peer));
            assert_eq!(peer.sent.last().unwrap()["kind"], "request-status");
        }
    }
}
