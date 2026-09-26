//! Recover an owned, complete LOCAL delivery without opening a worker connection.
//!
//! A receiver may have acknowledged the worker before output installation or
//! daemon completion persistence fails. Downloading again then cannot recover
//! the only remaining bytes. This path reuses the ordinary verifier/installer,
//! but never calls a transport, reads the old bundle, or queues an execution.
//! A durable linear claim excludes concurrent recovery and reserves uncertainty
//! across crashes. Offline verification does not manufacture a remote release ACK.

use super::{
    OperationClaim, OperationOutcome, OperationState, OperationStatus, PreparedOperationStore,
    Record, State, StoredMode, MAX_RUNNING, invalid, ordinary_directory, overlap, path_shape,
    require, valid_id,
};
use crate::coord::delivery_recovery::{DeliveryTrust, install_delivery_outputs, recover_existing_delivery};
use crate::coord::secure_worker_delivery::{OperationCancellation, parse_worker_pin};
use serde_json::{Value, json};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

impl PreparedOperationStore {
    /// Make one offline recovery attempt for an uncertain network operation.
    /// The daemon calls this on its existing bounded executor threads. No
    /// listener, worker request, bundle read or compiler execution is involved.
    ///
    /// Selecting and claiming share the ownership mutex. Persisting LocalRecovery
    /// BEFORE verification also consumes this automatic attempt: absent/corrupt
    /// bytes, a panic or another daemon loss cannot create an endless scan/retry
    /// loop. An explicit operator recovery remains available afterwards.
    ///
    /// A rejected delivery returns its persisted Uncertain status, not an error
    /// that would stop unrelated jobs. Store/ownership failures still propagate.
    pub fn recover_next_local(self: &Arc<Self>) -> io::Result<Option<OperationStatus>> {
        let (claim, acceptance_confirmed) = {
            let mut state = self.lock_state()?;
            if !state.accepting || state.active.len() >= MAX_RUNNING {
                return Ok(None);
            }
            let next = state.records.values()
                .filter(|record| {
                    record.state == OperationState::Uncertain
                        && record.execution_may_have_run
                        && !record.cancel_requested
                        && record.mode != StoredMode::LocalRecovery
                        && !state.active.contains_key(&record.spec.id)
                        && local_paths_available(&state, record, &record.delivery)
                })
                .min_by_key(|record| record.order)
                .cloned();
            let Some(record) = next else { return Ok(None); };
            let delivery = record.delivery.clone();
            self.claim_local_record(&mut state, record, delivery)?
        };
        let outcome = match local_result(&claim, acceptance_confirmed) {
            Ok(result) => OperationOutcome::Completed { result },
            Err(error) => OperationOutcome::Failed {
                detail: format!("automatic local recovery: {error}; explicit recovery required"),
                execution_may_have_run: true,
            },
        };
        claim.finish(outcome).map(Some)
    }

    /// Reverify a delivery already owned by this job and finish its installation.
    /// Run on the bounded filesystem lane, never the reactor or control lane.
    /// The saved request/pin and output destination remain fixed. No fallback
    /// exists when local bytes are absent, corrupt, or conflict with the output.
    pub fn recover_local(self: &Arc<Self>, id: &str, delivery: PathBuf) -> io::Result<OperationStatus> {
        let (claim, acceptance_confirmed) = self.claim_local(id, delivery)?;
        match local_result(&claim, acceptance_confirmed) {
            Ok(result) => claim.finish(OperationOutcome::Completed { result }),
            Err(error) => {
                // Persist the failed local attempt before reporting it. This
                // failure says nothing new about the original compiler's run.
                claim.finish(OperationOutcome::Failed {
                    detail: format!("local recovery: {error}"),
                    execution_may_have_run: true,
                })?;
                Err(error)
            }
        }
    }

    /// Mark Running BEFORE any filesystem access or installation. Unlike a
    /// resume, local recovery is never Queued: no daemon executor may interpret
    /// it as permission to contact a worker. The same linear owner/Drop path
    /// used by network operations fences panic, cancellation and daemon loss.
    pub(super) fn claim_local(
        self: &Arc<Self>, id: &str, delivery: PathBuf,
    ) -> io::Result<(OperationClaim, bool)> {
        require(valid_id(id) && path_shape(&delivery), "invalid local recovery identity or path")?;
        let mut state = self.lock_state()?;
        let record = self.read_record(&state, id)?
            .ok_or_else(|| invalid("unknown prepared operation"))?;
        self.claim_local_record(&mut state, record, delivery)
    }

    /// The caller holds the ownership lock from selection through persistence.
    /// Both explicit and automatic recovery use the identical claim boundary.
    fn claim_local_record(
        self: &Arc<Self>, state: &mut State, mut record: Record, delivery: PathBuf,
    ) -> io::Result<(OperationClaim, bool)> {
        let id = record.spec.id.clone();
        require(state.accepting, "prepared operation service is stopping")?;
        require(state.active.len() < MAX_RUNNING, "prepared operation capacity exhausted")?;
        require(!state.active.contains_key(&id), "operation already has an active owner")?;
        require(record.execution_may_have_run && matches!(record.state,
            OperationState::Uncertain | OperationState::Completed | OperationState::Cancelled),
            "local recovery requires a previously dispatched execution")?;
        require(delivery == record.delivery || record.prior_deliveries.contains(&delivery),
            "local recovery requires a delivery already owned by this job")?;
        // Membership is checked before traversing a caller-supplied path.
        // A bad preflight cannot turn this API into arbitrary file inspection.
        require(local_paths_available(state, &record, &delivery),
            "local recovery paths overlap an active operation")?;
        // An archived record owns the same paths but no live memory slot.
        // Restore only after all eligibility checks, under this same lock, and
        // before either Running persistence or an installation can occur.
        self.restore_record(state, &record)?;
        // Keep proven acceptance only for this exact recorded delivery. A local
        // receipt by itself cannot prove the worker received its release ACKs.
        let acceptance_confirmed = record.delivery == delivery
            && record.acknowledgments_confirmed == Some(true);
        if record.delivery != delivery {
            record.prior_deliveries.retain(|path| path != &delivery);
            record.prior_deliveries.push(record.delivery.clone());
            record.delivery = delivery;
        }
        record.attempt = record.attempt.checked_add(1)
            .ok_or_else(|| invalid("operation attempts exhausted"))?;
        record.state = OperationState::Running;
        record.mode = StoredMode::LocalRecovery;
        record.recovery_origin_attempt = None;
        record.resume_from = None;
        record.listen_address = None;
        record.cancel_requested = false;
        record.detail = None;
        // A different owned directory does not inherit the current one's ACK.
        if !acceptance_confirmed { record.acknowledgments_confirmed = None; }
        let cancellation = OperationCancellation::default();
        let mut spec = record.spec.clone();
        spec.delivery = record.delivery.clone();
        self.replace(state, record.clone())?;
        state.active.insert(id, cancellation.clone());
        Ok((OperationClaim {
            store: Arc::clone(self), spec, request: record.request,
            mode: StoredMode::LocalRecovery, resume_from: None,
            attempt: record.attempt, cancellation, finished: false,
            preview: None,
        }, acceptance_confirmed))
    }
}

fn local_paths_available(state: &State, record: &Record, delivery: &Path) -> bool {
    state.records.values().all(|other| {
        other.spec.id == record.spec.id
            || !state.active.contains_key(&other.spec.id)
            || other.paths().iter().all(|path| {
                !overlap(delivery, path) && !overlap(&record.spec.output, path)
            })
    })
}

fn checkpoint(claim: &OperationClaim) -> io::Result<()> {
    if claim.cancellation().is_cancelled() {
        Err(io::Error::new(io::ErrorKind::Interrupted, "local recovery cancelled; original execution remains unchanged"))
    } else {
        Ok(())
    }
}

fn local_result(claim: &OperationClaim, acceptance_confirmed: bool) -> io::Result<Value> {
    checkpoint(claim)?;
    let spec = claim.spec();
    ordinary_directory(&spec.delivery, false)?;
    ordinary_directory(&spec.output, true)?;
    let trust = DeliveryTrust::PinnedWorker(parse_worker_pin(&spec.worker_spki_sha256)?);
    let mut delivery = recover_existing_delivery(claim.request(), &spec.worker, &spec.delivery, trust)
        .map_err(io::Error::other)?
        .ok_or_else(|| invalid("owned delivery is missing; local recovery never downloads or executes"))?;
    {
        let state = claim.store.lock_state()?;
        let recorded = claim.current(&state)?;
        if let Some(exit_code) = recorded.exit_code {
            require(delivery.receipt["exit_code"].as_i64() == Some(i64::from(exit_code))
                && delivery.receipt["stop_reason"].as_str() == recorded.stop_reason.as_deref(),
                "local delivery contradicts the previously recorded compiler outcome")?;
        }
    }
    checkpoint(claim)?;
    let installed = if delivery.receipt["exit_code"] == 0 && delivery.receipt["stop_reason"].is_null() {
        Some(install_delivery_outputs(claim.request(), &spec.worker, &spec.delivery, &spec.output, trust)
            .map_err(io::Error::other)?.to_json())
    } else {
        None
    };
    // Do not turn cancellation arriving AFTER successful installation into an
    // invented cancelled compiler. Return the observed original result. Kernel
    // filesystem calls are not claimed interruptible; accepted writers drain.
    delivery.acknowledgments_confirmed = acceptance_confirmed;
    delivery.acknowledgment_error = if acceptance_confirmed {
        None
    } else {
        Some("local recovery did not contact the worker; release acceptance remains unconfirmed".to_owned())
    };
    Ok(json!({
        "kind":"worker-build", "operation":"recover-local", "bundle":spec.bundle,
        "delivery":delivery.to_json(), "installed_outputs":installed,
        "publication_authorized":false, "reexecute":false,
    }))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::coord::prepared_operation::PreparedOperationSpec;
    use crate::coord::worker_delivery::{
        WorkerAuthentication, WorkerPeer, receive_execution,
    };
    use rabs_sandbox::source_transfer::{SourceFile, SourceManifest};
    use sha2::{Digest, Sha256};
    use std::collections::VecDeque;
    use std::fs;
    use std::time::{Duration, Instant};

    const ID: &str = "0123456789abcdef0123456789abcdef";
    const STDOUT: &[u8] = b"compiler output\0\xff\n";
    const STDERR: &[u8] = b"compiler warning\0\xfe\n";
    const ARTIFACT: &[u8] = b"compiled\0\xff";

    fn hash(bytes: &[u8]) -> String {
        Sha256::digest(bytes).iter().map(|byte| format!("{byte:02x}")).collect()
    }

    // Only the transport/result producer is scripted. Admission, byte reception,
    // durable receipts, restart, verifier and output installation are production
    // code. These tests do not claim native TLS or actual compiler execution.
    struct Peer {
        result: Value,
        replies: VecDeque<Value>,
    }

    impl WorkerPeer for Peer {
        fn authentication(&self) -> Option<WorkerAuthentication> {
            Some(WorkerAuthentication {
                spki_sha256: [1; 32], session_id: 42, identity_generation: 1,
            })
        }

        fn send(&mut self, frame: &Value) -> io::Result<()> {
            match frame["kind"].as_str().unwrap() {
                "session-ok" => {}
                "canonical-exec" => self.replies.push_back(self.result.clone()),
                "output-read" | "artifact-read" => {
                    let artifact = frame["kind"] == "artifact-read";
                    let field = if artifact { "name" } else { "stream" };
                    let name = frame[field].as_str().unwrap();
                    let bytes = match name {
                        "stdout" => STDOUT,
                        "stderr" => STDERR,
                        "app" => ARTIFACT,
                        _ => panic!("unexpected member"),
                    };
                    assert_eq!(frame["offset"], 0);
                    let mut reply = json!({
                        "kind": if artifact { "artifact-chunk" } else { "output-chunk" },
                        "request_id": 7, "offset": 0, "next_offset": bytes.len(),
                        "total_bytes": bytes.len(), "sha256": hash(bytes),
                        "chunk_sha256": hash(bytes), "eof": true,
                        "data_hex": bytes.iter().map(|byte| format!("{byte:02x}")).collect::<String>(),
                    });
                    reply[field] = json!(name);
                    if artifact {
                        reply["executable"] = json!(true);
                        reply["manifest_sha256"] = self.result["artifact_manifest"]["manifest_sha256"].clone();
                    }
                    self.replies.push_back(reply);
                }
                "output-ack" | "artifact-ack" => self.replies.push_back(json!({
                    "kind": if frame["kind"] == "output-ack" { "output-acknowledged" } else { "artifact-acknowledged" },
                    "request_id": 7, "already_released": false,
                })),
                _ => panic!("unexpected worker operation"),
            }
            Ok(())
        }

        fn receive(&mut self) -> io::Result<Value> {
            self.replies.pop_front().ok_or_else(|| io::Error::other("missing scripted frame"))
        }
    }

    fn peer(exit: u8, stop: Option<&str>) -> Peer {
        let mut digest = Sha256::new();
        let field = |digest: &mut Sha256, bytes: &[u8]| {
            digest.update((bytes.len() as u64).to_be_bytes());
            digest.update(bytes);
        };
        field(&mut digest, b"rabs.worker-artifact-manifest.v1");
        field(&mut digest, b"build");
        digest.update(1_u64.to_be_bytes());
        field(&mut digest, b"app");
        digest.update([1]);
        digest.update((ARTIFACT.len() as u64).to_be_bytes());
        field(&mut digest, hash(ARTIFACT).as_bytes());
        let manifest = json!({
            "unit": "build", "files": [{"name": "app", "bytes": ARTIFACT.len(),
                "sha256": hash(ARTIFACT), "executable": true}],
            "total_bytes": ARTIFACT.len(),
            "manifest_sha256": digest.finalize().iter().map(|byte| format!("{byte:02x}")).collect::<String>(),
        });
        let success = exit == 0 && stop.is_none();
        Peer {
            result: json!({
                "kind": "exec-result", "request_id": 7, "executed": true,
                "exit_code": exit, "stop_reason": stop, "residual_group_members": 0,
                "output_transfer": "ranges-v1", "output_ack_required": true,
                "stdout_bytes": STDOUT.len(), "stdout_sha256": hash(STDOUT),
                "stderr_bytes": STDERR.len(), "stderr_sha256": hash(STDERR),
                "artifact_transfer": "files-v1", "artifact_ack_required": success,
                "artifact_manifest": if success { manifest } else { Value::Null },
                "result_retention": "durable-result-v1",
                "retained_result_sha256": hash(b"scripted retained result"),
            }),
            replies: VecDeque::from([json!({
                "kind": "worker-hello", "worker_id": "worker", "canonical": true, "slots": 1,
                "boot_generation": 1, "incarnation": "00000000000000000000000000000001",
                "request_high_water": null, "recovery_protocols": ["request-journal-v1"],
                "output_transfers": ["ranges-v1"], "artifact_transfers": ["files-v1"],
                "command_contexts": ["env-cwd-v1"], "toolchain_datasets": ["toolchain-dataset-v1"],
                "result_retentions": ["durable-result-v1"],
            })]),
        }
    }

    struct Fixture {
        _owner: tempfile::TempDir,
        root: PathBuf,
        store: Arc<PreparedOperationStore>,
        spec: PreparedOperationSpec,
        request: Value,
        fingerprint: String,
    }

    impl Fixture {
        fn new() -> Self {
            let owner = tempfile::tempdir().unwrap();
            let root = owner.path().canonicalize().unwrap();
            let store = PreparedOperationStore::open(&root.join("state")).unwrap();
            let spec = PreparedOperationSpec {
                id: ID.into(), address: "127.0.0.1:7001".into(), worker: "worker".into(),
                worker_spki_sha256: "01".repeat(32), bundle: root.join("bundle"),
                delivery: root.join("delivery"), output: root.join("installed"),
            };
            fs::create_dir(&spec.bundle).unwrap();
            let manifest = SourceManifest::new(vec![SourceFile {
                path: "lib.rs".into(), len: 1, sha256: Sha256::digest(b"x").into(), executable: false,
            }]).unwrap();
            let request = json!({
                "kind": "canonical-exec", "request_id": 7, "program": "rustc", "args": ["lib.rs"],
                "toolchain_backing": "/tc", "toolchain_identity": {
                    "version": "toolchain-dataset-v1", "sha256": "ab".repeat(32), "files": 1, "bytes": 1,
                },
                "source_manifest": {
                    "manifest_sha256": manifest.digest().iter().map(|byte| format!("{byte:02x}")).collect::<String>(),
                    "files": [{"path": "lib.rs", "bytes": 1, "sha256": hash(b"x"), "executable": false}],
                },
                "command_context": {"version": "env-cwd-v1", "cwd": "/__rabs/workspace", "env": {}},
                "artifacts": {"unit": "build", "files": ["app"]},
            });
            fs::write(spec.bundle.join("request.json"), serde_json::to_vec(&request).unwrap()).unwrap();
            let fingerprint = store.submit(spec.clone()).unwrap().request_sha256;
            Self { _owner: owner, root, store, spec, request, fingerprint }
        }

        fn strand(&self, exit: u8, stop: Option<&str>) {
            let claim = self.store.claim_next().unwrap().unwrap();
            let mut peer = peer(exit, stop);
            receive_execution(&mut peer, &self.request, "worker", &self.spec.delivery).unwrap();
            assert!(peer.replies.is_empty());
            drop(claim);
        }
    }

    #[test]
    fn automatic_local_recovery_finishes_verified_outputs_and_diagnostics_without_bundle() {
        use std::os::unix::fs::MetadataExt;
        let fixture = Fixture::new();
        fixture.strand(0, None);
        let retained = fixture.spec.delivery.join("artifacts/app");
        let receipt = fs::read(fixture.spec.delivery.join("delivery.json")).unwrap();
        fs::rename(&fixture.spec.bundle, fixture.root.join("retired-bundle")).unwrap();
        let status = fixture.store.recover_next_local().unwrap().unwrap();
        assert!(status.succeeded && status.outputs_installed);
        assert_eq!(status.attempt, 2);
        assert_eq!(status.mode, "recover-local");
        assert_eq!(status.request_sha256, fixture.fingerprint);
        assert_eq!(status.acknowledgments_confirmed, Some(false));
        assert!(status.listen_address.is_none());
        assert_eq!(fs::read(fixture.spec.output.join("app")).unwrap(), ARTIFACT);
        assert_ne!(fs::metadata(&retained).unwrap().ino(), fs::metadata(fixture.spec.output.join("app")).unwrap().ino());
        assert_eq!(fs::read(fixture.spec.delivery.join("delivery.json")).unwrap(), receipt);
        let proof = fixture.store.completion(ID, &fixture.fingerprint).unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
        proof.snapshot(deadline).unwrap().emit(&mut stdout, &mut stderr, deadline).unwrap();
        assert_eq!(stdout, STDOUT);
        assert_eq!(stderr, STDERR);
        assert!(fixture.store.recover_next_local().unwrap().is_none());
        assert!(fixture.store.claim_next().unwrap().is_none());
    }

    #[test]
    fn recovered_failure_retains_the_real_exit_and_never_installs_outputs() {
        for (exit, stop) in [(17, None), (130, Some("cancelled")), (125, Some("lease-expired"))] {
            let fixture = Fixture::new();
            fixture.strand(exit, stop);
            let status = fixture.store.recover_next_local().unwrap().unwrap();
            assert_eq!(status.exit_code, Some(i32::from(exit)));
            assert_eq!(status.stop_reason.as_deref(), stop);
            assert!(!status.succeeded && !status.outputs_installed);
            assert!(!fixture.spec.output.exists());
            assert!(fixture.store.completion(ID, &fixture.fingerprint).is_ok());
            assert!(fixture.store.recover_next_local().unwrap().is_none());
        }
    }

    #[test]
    fn missing_corrupt_and_conflicting_deliveries_are_attempted_once_even_across_restart() {
        for case in 0..6 {
            let fixture = Fixture::new();
            fixture.strand(0, None);
            match case {
                0 => fs::rename(&fixture.spec.delivery, fixture.root.join("removed-delivery")).unwrap(),
                1 => fs::write(fixture.spec.delivery.join("artifacts/app"), b"corrupt").unwrap(),
                2 => fs::write(fixture.spec.delivery.join("diagnostics/stderr"), b"corrupt").unwrap(),
                3 => fs::rename(fixture.spec.delivery.join("delivery.json"), fixture.root.join("removed-receipt")).unwrap(),
                4 => {
                    let path = fixture.spec.delivery.join("delivery.json");
                    let mut value: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
                    value["worker_spki_sha256"] = json!("02".repeat(32));
                    fs::write(path, serde_json::to_vec(&value).unwrap()).unwrap();
                }
                _ => {
                    fs::create_dir(&fixture.spec.output).unwrap();
                    fs::write(fixture.spec.output.join("app"), b"keep user output").unwrap();
                }
            }
            let status = fixture.store.recover_next_local().unwrap().unwrap();
            assert_eq!(status.state, OperationState::Uncertain, "case {case}");
            assert_eq!(status.mode, "recover-local");
            assert!(status.execution_may_have_run && !status.succeeded);
            let journal = fixture.root.join(format!("state/{ID}.json"));
            let before = fs::read(&journal).unwrap();
            assert!(fixture.store.recover_next_local().unwrap().is_none());
            assert_eq!(fs::read(&journal).unwrap(), before);
            if case == 5 {
                assert_eq!(fs::read(fixture.spec.output.join("app")).unwrap(), b"keep user output");
            } else {
                assert!(!fixture.spec.output.exists());
            }
            drop(fixture.store);
            let store = PreparedOperationStore::open(&fixture.root.join("state")).unwrap();
            assert!(store.recover_next_local().unwrap().is_none());
            assert!(store.claim_next().unwrap().is_none());
        }
    }

    #[test]
    fn simultaneous_automatic_recovery_has_one_durable_owner() {
        let fixture = Fixture::new();
        fixture.strand(0, None);
        let results = std::thread::scope(|scope| {
            let threads: Vec<_> = (0..4).map(|_| {
                scope.spawn(|| fixture.store.recover_next_local().unwrap())
            }).collect();
            threads.into_iter().map(|thread| thread.join().unwrap()).collect::<Vec<_>>()
        });
        assert_eq!(results.iter().filter(|result| result.is_some()).count(), 1);
        assert_eq!(fixture.store.status(ID).unwrap().unwrap().attempt, 2);
        assert_eq!(fs::read(fixture.spec.output.join("app")).unwrap(), ARTIFACT);
    }

    #[test]
    fn pending_active_cancelled_and_stopping_jobs_are_not_automatically_claimed() {
        let fixture = Fixture::new();
        assert!(fixture.store.recover_next_local().unwrap().is_none());
        let claim = fixture.store.claim_next().unwrap().unwrap();
        assert!(fixture.store.recover_next_local().unwrap().is_none());
        fixture.store.cancel(ID).unwrap();
        drop(claim);
        let before = fixture.store.status(ID).unwrap().unwrap();
        assert!(before.cancel_requested);
        assert!(fixture.store.recover_next_local().unwrap().is_none());
        assert_eq!(fixture.store.status(ID).unwrap().unwrap().attempt, before.attempt);
        let fixture = Fixture::new();
        fixture.strand(0, None);
        fixture.store.stop().unwrap();
        assert!(fixture.store.recover_next_local().unwrap().is_none());
        assert!(!fixture.spec.output.exists());
    }

    #[test]
    fn interrupted_owner_is_recovered_after_reopening_the_durable_store() {
        let fixture = Fixture::new();
        fixture.strand(0, None);
        drop(fixture.store);
        let store = PreparedOperationStore::open(&fixture.root.join("state")).unwrap();
        assert!(store.recover_next_local().unwrap().unwrap().succeeded);
        drop(store);
        let store = PreparedOperationStore::open(&fixture.root.join("state")).unwrap();
        assert!(store.status(ID).unwrap().unwrap().succeeded);
        assert!(store.recover_next_local().unwrap().is_none());
        assert!(store.claim_next().unwrap().is_none());
    }

    #[test]
    fn lost_acceptance_keeps_the_original_worker_reserved() {
        let fixture = Fixture::new();
        fixture.strand(0, None);
        assert!(fixture.store.recover_next_local().unwrap().unwrap().succeeded);
        let mut next = fixture.spec.clone();
        next.id = "ab".repeat(16);
        next.delivery = fixture.root.join("next-delivery");
        next.output = fixture.root.join("next-output");
        fixture.store.submit(next).unwrap();
        assert!(fixture.store.claim_next().unwrap().is_none());
    }

    #[test]
    fn uncertain_claim_persistence_never_installs_or_requeues_a_compiler() {
        let fixture = Fixture::new();
        fixture.strand(0, None);
        fixture.store.fail_after_rename.store(true, std::sync::atomic::Ordering::SeqCst);
        assert!(fixture.store.recover_next_local().is_err());
        assert!(!fixture.spec.output.exists());
        assert!(fixture.store.claim_next().is_err());
        drop(fixture.store);
        let store = PreparedOperationStore::open(&fixture.root.join("state")).unwrap();
        assert_eq!(store.status(ID).unwrap().unwrap().state, OperationState::Uncertain);
        assert!(store.recover_next_local().unwrap().is_none());
        assert!(store.claim_next().unwrap().is_none());
        assert!(!fixture.spec.output.exists());
    }
}
