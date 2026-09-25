//! Read-only completion delivery for a daemon-owned prepared operation.
//!
//! A terminal status is not permission to print arbitrary files. The daemon
//! first revalidates the entire delivery against its saved request and worker
//! pin. The local client then snapshots and hashes BOTH diagnostic streams
//! before exposing either. This grants no execution, release or cache authority.
//! Directories remain exclusively operator-owned; this is not a hostile
//! same-credential, race-proof filesystem API.

use super::{OperationState, PreparedOperationStore, invalid, ordinary_directory, read_bounded, require, valid_id};
use crate::coord::delivery_recovery::{DeliveryTrust, recover_existing_delivery};
use crate::coord::secure_worker_delivery::parse_worker_pin;
use crate::coord::worker_delivery::{MAX_DELIVERY_BYTES, MAX_FRAME_BYTES};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs::{self, File, Metadata};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

const COPY_BYTES: usize = 64 * 1024;

fn hash(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|byte| format!("{byte:02x}")).collect()
}
fn canonical_hash(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn checkpoint(until: Instant) -> io::Result<()> {
    if Instant::now() >= until {
        Err(io::Error::new(io::ErrorKind::TimedOut, "job completion deadline exceeded"))
    } else {
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticStream {
    pub bytes: u64,
    pub sha256: String,
}

/// Bounded metadata from the trusted local daemon, not a cache admission proof.
/// The request fingerprints have DIFFERENT domains and are never interchangeable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedCompletion {
    pub version: u32,
    pub operation_id: String,
    /// Domain-separated durable job request fingerprint (same as job status).
    pub request_sha256: String,
    /// SHA-256 of original request JSON (same as the delivery receipt).
    pub delivery_request_sha256: String,
    /// SHA-256 of the receipt's compact JSON value, not its pretty-printing.
    pub receipt_sha256: String,
    pub request_id: u64,
    pub worker: String,
    pub worker_spki_sha256: String,
    pub delivery: PathBuf,
    pub exit_code: u8,
    pub stop_reason: Option<String>,
    pub outputs_installed: bool,
    pub stdout: DiagnosticStream,
    pub stderr: DiagnosticStream,
}

impl PreparedOperationStore {
    /// Revalidate the whole local result using the saved request, without a
    /// worker connection or a bundle read. Call on a bounded filesystem lane,
    /// never the control reactor. The store mutex is NOT held during hashing.
    pub fn completion(&self, id: &str, request_sha256: &str) -> io::Result<PreparedCompletion> {
        require(valid_id(id) && canonical_hash(request_sha256), "invalid completion identity")?;
        let record = {
            let state = self.lock_state()?;
            let record = self.read_record(&state, id)?
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "prepared operation not found"))?;
            require(record.request_sha256 == request_sha256, "completion request identity changed")?;
            require(matches!(record.state, OperationState::Completed | OperationState::Cancelled)
                && record.execution_may_have_run && !state.active.contains_key(id),
                "prepared operation has no terminal delivered execution")?;
            record
        };
        let pin = parse_worker_pin(&record.spec.worker_spki_sha256)?;
        ordinary_directory(&record.delivery, false)?;
        let delivered = recover_existing_delivery(&record.request, &record.spec.worker,
            &record.delivery, DeliveryTrust::PinnedWorker(pin))
            .map_err(io::Error::other)?
            .ok_or_else(|| invalid("completed operation has no verified local delivery"))?;
        let receipt = &delivered.receipt;
        require(receipt["exit_code"].as_i64() == record.exit_code.map(i64::from)
            && receipt["stop_reason"].as_str() == record.stop_reason.as_deref(),
            "local delivery outcome differs from the terminal job")?;
        let stream = |name: &str| -> io::Result<DiagnosticStream> {
            Ok(DiagnosticStream {
                bytes: receipt[format!("{name}_bytes")].as_u64().ok_or_else(|| invalid("missing diagnostic length"))?,
                sha256: receipt[format!("{name}_sha256")].as_str().ok_or_else(|| invalid("missing diagnostic digest"))?.to_owned(),
            })
        };
        let completion = PreparedCompletion {
            version: 1, operation_id: id.to_owned(), request_sha256: record.request_sha256.clone(),
            delivery_request_sha256: receipt["request_sha256"].as_str()
                .ok_or_else(|| invalid("missing delivery request fingerprint"))?.to_owned(),
            receipt_sha256: hash(&serde_json::to_vec(receipt)?),
            request_id: record.request["request_id"].as_u64().ok_or_else(|| invalid("missing request id"))?,
            worker: record.spec.worker.clone(), worker_spki_sha256: record.spec.worker_spki_sha256.clone(),
            delivery: record.delivery.clone(),
            exit_code: record.exit_code.and_then(|code| u8::try_from(code).ok())
                .ok_or_else(|| invalid("missing bounded compiler exit"))?,
            stop_reason: record.stop_reason.clone(), outputs_installed: record.outputs_installed,
            stdout: stream("stdout")?, stderr: stream("stderr")?,
        };
        completion.validate()?;
        // Explicit recovery can start while files are being checked. Do not
        // label that newer attempt with a previous terminal completion snapshot.
        let state = self.lock_state()?;
        let current = self.read_record(&state, id)?.ok_or_else(|| invalid("completion owner disappeared"))?;
        require(current.attempt == record.attempt && current.state == record.state
            && current.delivery == record.delivery && current.mode == record.mode
            && current.outputs_installed == record.outputs_installed
            && current.exit_code == record.exit_code && current.stop_reason == record.stop_reason
            && !state.active.contains_key(id), "operation changed during completion verification")?;
        Ok(completion)
    }
}

impl PreparedCompletion {
    fn validate(&self) -> io::Result<()> {
        require(self.version == 1 && valid_id(&self.operation_id), "invalid completion version or job id")?;
        for digest in [&self.request_sha256, &self.delivery_request_sha256, &self.receipt_sha256,
            &self.stdout.sha256, &self.stderr.sha256] {
            require(canonical_hash(digest), "noncanonical completion digest")?;
        }
        parse_worker_pin(&self.worker_spki_sha256)?;
        require(!self.worker.is_empty() && self.worker.len() <= 1024
            && !self.worker.chars().any(char::is_control), "invalid completion worker")?;
        require(self.stdout.bytes.checked_add(self.stderr.bytes)
            .is_some_and(|bytes| bytes <= MAX_DELIVERY_BYTES), "diagnostics exceed delivery budget")?;
        require(self.stop_reason.as_deref().is_none_or(|reason|
            matches!(reason, "cancelled" | "deadline-exceeded" | "session-lost" | "lease-expired")), "unknown completion stop reason")?;
        require(self.stop_reason.is_none() || self.exit_code != 0, "interrupted success contradiction")?;
        require(self.exit_code != 0 || self.outputs_installed,
            "successful compiler outcome has no verified output installation")?;
        Ok(())
    }

    fn check_receipt(&self) -> io::Result<()> {
        ordinary_directory(&self.delivery, false)?;
        let bytes = read_bounded(&self.delivery.join("delivery.json"), MAX_FRAME_BYTES, true)?;
        let receipt: Value = serde_json::from_slice(&bytes)?;
        require(hash(&serde_json::to_vec(&receipt)?) == self.receipt_sha256
            && receipt["kind"] == "verified-worker-delivery"
            && receipt["request_id"].as_u64() == Some(self.request_id)
            && receipt["request_sha256"].as_str() == Some(self.delivery_request_sha256.as_str())
            && receipt["worker_id"].as_str() == Some(self.worker.as_str())
            && receipt["worker_spki_sha256"].as_str() == Some(self.worker_spki_sha256.as_str())
            && receipt["transport_authenticated"] == true
            && receipt["publication_authorized"] == false
            && receipt["reexecute"] == false
            && receipt["exit_code"].as_u64() == Some(u64::from(self.exit_code))
            && receipt["stop_reason"].as_str() == self.stop_reason.as_deref(),
            "completion receipt does not match daemon evidence")?;
        for (name, stream) in [("stdout", &self.stdout), ("stderr", &self.stderr)] {
            require(receipt[format!("{name}_bytes")].as_u64() == Some(stream.bytes)
                && receipt[format!("{name}_sha256")].as_str() == Some(stream.sha256.as_str()),
                "completion diagnostic descriptor differs from receipt")?;
        }
        Ok(())
    }

    /// Snapshot BOTH streams before exposing either. A changed second stream
    /// must not leak a valid first stream followed by an apparent compiler retry.
    /// Copies are bounded, independent private files; originals are never edited.
    pub fn snapshot(&self, until: Instant) -> io::Result<DiagnosticSnapshot> {
        self.validate()?;
        checkpoint(until)?;
        self.check_receipt()?;
        let directory = self.delivery.join("diagnostics");
        ordinary_directory(&directory, false)?;
        let before = fs::symlink_metadata(&directory)?;
        let stdout = capture(&directory.join("stdout"), &self.stdout, until)?;
        let stderr = capture(&directory.join("stderr"), &self.stderr, until)?;
        ordinary_directory(&directory, false)?;
        require(same_identity(&before, &fs::symlink_metadata(&directory)?), "diagnostic directory changed")?;
        self.check_receipt()?;
        checkpoint(until)?;
        Ok(DiagnosticSnapshot { stdout, stderr })
    }
}

fn same_identity(before: &Metadata, after: &Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        before.dev() == after.dev() && before.ino() == after.ino() && before.file_type() == after.file_type()
    }
    #[cfg(not(unix))]
    {
        before.file_type() == after.file_type()
            && before.created().ok().zip(after.created().ok()).is_some_and(|(a, b)| a == b)
    }
}
fn same_file(before: &Metadata, after: &Metadata) -> bool {
    if !same_identity(before, after) || before.len() != after.len() { return false; }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        before.mode() == after.mode() && before.nlink() == after.nlink()
            && before.mtime() == after.mtime() && before.mtime_nsec() == after.mtime_nsec()
            && before.ctime() == after.ctime() && before.ctime_nsec() == after.ctime_nsec()
    }
    #[cfg(not(unix))]
    {
        before.modified().ok().zip(after.modified().ok()).is_some_and(|(a, b)| a == b)
    }
}
fn capture(path: &Path, expected: &DiagnosticStream, until: Instant) -> io::Result<File> {
    checkpoint(until)?;
    let before = fs::symlink_metadata(path)?;
    require(before.is_file() && before.len() == expected.bytes, "diagnostic file type or length changed")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        require(before.nlink() == 1 && before.permissions().mode() & 0o7777 == 0o600,
            "diagnostics must be private, nonexecutable files with one link")?;
    }
    let mut input = File::open(path)?;
    require(same_file(&before, &input.metadata()?), "diagnostic file changed during open")?;
    let mut output = tempfile::tempfile()?;
    let mut hasher = Sha256::new();
    let mut remaining = expected.bytes;
    let mut bytes = [0_u8; COPY_BYTES];
    while remaining != 0 {
        checkpoint(until)?;
        let count = remaining.min(COPY_BYTES as u64) as usize;
        input.read_exact(&mut bytes[..count])?;
        output.write_all(&bytes[..count])?;
        hasher.update(&bytes[..count]);
        remaining -= count as u64;
    }
    require(input.read(&mut bytes[..1])? == 0 && same_file(&before, &input.metadata()?)
        && same_file(&before, &fs::symlink_metadata(path)?), "diagnostic file changed during capture")?;
    let digest: String = hasher.finalize().iter().map(|byte| format!("{byte:02x}")).collect();
    require(digest == expected.sha256, "diagnostic bytes fail complete-file digest")?;
    output.seek(SeekFrom::Start(0))?;
    checkpoint(until)?;
    Ok(output)
}

/// Independent, already verified bytes. Emission is never retried implicitly.
/// Per-stream order is preserved; historical stdout/stderr interleaving is not
/// available from the retained result and is not reconstructed or invented.
#[derive(Debug)]
pub struct DiagnosticSnapshot {
    stdout: File,
    stderr: File,
}
impl DiagnosticSnapshot {
    pub fn emit(mut self, stdout: &mut impl Write, stderr: &mut impl Write, until: Instant) -> io::Result<()> {
        let copy = |input: &mut File, output: &mut dyn Write| -> io::Result<()> {
            let mut bytes = [0_u8; COPY_BYTES];
            loop {
                checkpoint(until)?;
                let count = input.read(&mut bytes)?;
                if count == 0 { return output.flush(); }
                output.write_all(&bytes[..count])?;
            }
        };
        copy(&mut self.stdout, stdout)?;
        copy(&mut self.stderr, stderr)?;
        checkpoint(until)
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::coord::prepared_operation::{OperationOutcome, PreparedOperationSpec};
    use crate::coord::delivery_recovery::install_delivery_outputs;
    use crate::coord::worker_delivery::{WorkerAuthentication, WorkerPeer, receive_execution};
    use rabs_sandbox::source_transfer::{SourceFile, SourceManifest};
    use serde_json::json;
    use std::collections::VecDeque;
    use std::sync::Arc;
    use std::time::Duration;

    const ID: &str = "0123456789abcdef0123456789abcdef";
    const STDOUT: &[u8] = b"compiler output\0\xff\n";
    const STDERR: &[u8] = b"warning: binary\0\xfe\n";
    const ARTIFACT: &[u8] = b"compiled\0\xff";

    // This is an injected trusted transport boundary and scripted execution
    // result, NOT native TLS or compiler proof. The receiver, files, installer,
    // durable operation store and completion verification are all production.
    struct Peer { result: Value, replies: VecDeque<Value> }
    impl WorkerPeer for Peer {
        fn authentication(&self) -> Option<WorkerAuthentication> {
            Some(WorkerAuthentication { spki_sha256:[1; 32], session_id:42, identity_generation:1 })
        }
        fn send(&mut self, frame: &Value) -> io::Result<()> {
            match frame["kind"].as_str().unwrap() {
                "session-ok" => {},
                "canonical-exec" => self.replies.push_back(self.result.clone()),
                "output-read" | "artifact-read" => {
                    let artifact = frame["kind"] == "artifact-read";
                    let name = frame[if artifact {"name"} else {"stream"}].as_str().unwrap();
                    let bytes = match name { "stdout" => STDOUT, "stderr" => STDERR, "app" => ARTIFACT, _ => panic!("unexpected member") };
                    assert_eq!(frame["offset"], 0);
                    let mut reply = json!({"kind":if artifact {"artifact-chunk"} else {"output-chunk"},
                        "request_id":7,"offset":0,"next_offset":bytes.len(),"total_bytes":bytes.len(),
                        "sha256":hash(bytes),"chunk_sha256":hash(bytes),"eof":true,
                        "data_hex":bytes.iter().map(|byte| format!("{byte:02x}")).collect::<String>()});
                    reply[if artifact {"name"} else {"stream"}] = json!(name);
                    if artifact {
                        reply["executable"] = json!(true);
                        reply["manifest_sha256"] = self.result["artifact_manifest"]["manifest_sha256"].clone();
                    }
                    self.replies.push_back(reply);
                }
                "output-ack" | "artifact-ack" => self.replies.push_back(json!({
                    "kind":if frame["kind"] == "output-ack" {"output-acknowledged"} else {"artifact-acknowledged"},
                    "request_id":7,"already_released":false})),
                _ => panic!("unexpected protocol operation"),
            }
            Ok(())
        }
        fn receive(&mut self) -> io::Result<Value> {
            self.replies.pop_front().ok_or_else(|| io::Error::other("missing fixture reply"))
        }
    }
    fn peer(exit: u8, stop: Option<&str>) -> Peer {
        let mut hasher = Sha256::new();
        let field = |hash: &mut Sha256, bytes: &[u8]| { hash.update((bytes.len() as u64).to_be_bytes()); hash.update(bytes); };
        field(&mut hasher, b"rabs.worker-artifact-manifest.v1"); field(&mut hasher, b"build");
        hasher.update(1_u64.to_be_bytes()); field(&mut hasher, b"app"); hasher.update([1]);
        hasher.update((ARTIFACT.len() as u64).to_be_bytes()); field(&mut hasher, hash(ARTIFACT).as_bytes());
        let manifest = json!({"unit":"build","files":[{"name":"app","bytes":ARTIFACT.len(),
            "sha256":hash(ARTIFACT),"executable":true}],"total_bytes":ARTIFACT.len(),
            "manifest_sha256":hasher.finalize().iter().map(|byte| format!("{byte:02x}")).collect::<String>()});
        let success = exit == 0 && stop.is_none();
        Peer {
            result:json!({"kind":"exec-result","request_id":7,"executed":true,"exit_code":exit,
                "stop_reason":stop,"residual_group_members":0,"output_transfer":"ranges-v1","output_ack_required":true,
                "stdout_bytes":STDOUT.len(),"stdout_sha256":hash(STDOUT),"stderr_bytes":STDERR.len(),"stderr_sha256":hash(STDERR),
                "artifact_transfer":"files-v1","artifact_ack_required":success,"artifact_manifest":if success {manifest} else {Value::Null},
                "result_retention":"durable-result-v1","retained_result_sha256":hash(b"scripted retained result")}),
            replies:VecDeque::from([json!({"kind":"worker-hello","worker_id":"worker","canonical":true,"slots":1,
                "boot_generation":1,"incarnation":"00000000000000000000000000000001","request_high_water":null,
                "recovery_protocols":["request-journal-v1"],"output_transfers":["ranges-v1"],"artifact_transfers":["files-v1"],
                "command_contexts":["env-cwd-v1"],"toolchain_datasets":["toolchain-dataset-v1"],
                "result_retentions":["durable-result-v1"]})]),
        }
    }
    struct Fixture {
        _owner: tempfile::TempDir, root: PathBuf, store: Arc<PreparedOperationStore>,
        spec: PreparedOperationSpec, request: Value, digest: String,
    }
    impl Fixture {
        fn new() -> Self {
            let owner = tempfile::tempdir().unwrap();
            let root = owner.path().canonicalize().unwrap();
            let store = PreparedOperationStore::open(&root.join("state")).unwrap();
            let spec = PreparedOperationSpec { id:ID.into(),address:"127.0.0.1:7001".into(),
                worker:"worker".into(),worker_spki_sha256:"01".repeat(32),
                bundle:root.join("bundle"),delivery:root.join("delivery"),output:root.join("installed") };
            fs::create_dir(&spec.bundle).unwrap();
            let manifest = SourceManifest::new(vec![SourceFile { path:"lib.rs".into(),len:1,
                sha256:Sha256::digest(b"x").into(),executable:false }]).unwrap();
            let request = json!({"kind":"canonical-exec","request_id":7,"program":"rustc","args":["lib.rs"],
                "toolchain_backing":"/tc","toolchain_identity":{"version":"toolchain-dataset-v1","sha256":"ab".repeat(32),"files":1,"bytes":1},
                "source_manifest":{"manifest_sha256":manifest.digest().iter().map(|byte| format!("{byte:02x}")).collect::<String>(),
                    "files":[{"path":"lib.rs","bytes":1,"sha256":hash(b"x"),"executable":false}]},
                "command_context":{"version":"env-cwd-v1","cwd":"/__rabs/workspace","env":{"PRIVATE_INPUT":"do-not-return-this-value"}},
                "artifacts":{"unit":"build","files":["app"]}});
            fs::write(spec.bundle.join("request.json"), serde_json::to_vec(&request).unwrap()).unwrap();
            let digest = store.submit(spec.clone()).unwrap().request_sha256;
            Self { _owner:owner,root,store,spec,request,digest }
        }
        fn complete(&self, exit: u8, stop: Option<&str>) {
            let claim = self.store.claim_next().unwrap().unwrap();
            let mut peer = peer(exit, stop);
            let delivery = receive_execution(&mut peer, &self.request, "worker", &self.spec.delivery).unwrap();
            assert!(peer.replies.is_empty());
            let installed = if exit == 0 {
                Some(install_delivery_outputs(&self.request, "worker", &self.spec.delivery,
                    &self.spec.output, DeliveryTrust::PinnedWorker([1;32])).unwrap().to_json())
            } else { None };
            claim.finish(OperationOutcome::Completed { result:json!({"kind":"worker-build","delivery":delivery.to_json(),
                "installed_outputs":installed,"publication_authorized":false,"reexecute":false}) }).unwrap();
        }
        fn proof(&self) -> PreparedCompletion { self.store.completion(ID, &self.digest).unwrap() }

        // The receiver has durable files and may even have sent both ACKs, but
        // the daemon owner dies before installation/completion persistence.
        fn strand(&self, exit: u8, stop: Option<&str>) {
            let claim = self.store.claim_next().unwrap().unwrap();
            let mut peer = peer(exit, stop);
            receive_execution(&mut peer, &self.request, "worker", &self.spec.delivery).unwrap();
            assert!(peer.replies.is_empty());
            drop(claim);
            assert_eq!(self.store.status(ID).unwrap().unwrap().state, OperationState::Uncertain);
            assert!(!self.spec.output.exists());
        }
    }
    fn deadline() -> Instant { Instant::now() + Duration::from_secs(10) }

    #[test]
    fn complete_success_failure_and_cancellation_replay_exact_binary_streams() {
        for (exit, stop) in [(0,None),(1,None),(130,Some("cancelled")),(125,Some("lease-expired"))] {
            let fixture = Fixture::new(); fixture.complete(exit, stop);
            let proof = fixture.proof();
            assert_eq!(proof.exit_code, exit);
            assert_eq!(proof.request_sha256, fixture.digest);
            assert_eq!(proof.delivery_request_sha256, hash(&serde_json::to_vec(&fixture.request).unwrap()));
            assert_ne!(proof.request_sha256, proof.delivery_request_sha256, "different hash domains must not be substituted");
            assert!(!serde_json::to_string(&proof).unwrap().contains("do-not-return-this-value"));
            let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
            proof.snapshot(deadline()).unwrap().emit(&mut stdout, &mut stderr, deadline()).unwrap();
            assert_eq!(stdout, STDOUT); assert_eq!(stderr, STDERR);
            assert_eq!(fixture.store.status(ID).unwrap().unwrap().request_sha256, fixture.digest);
        }
    }

    #[test]
    fn status_and_diagnostic_files_alone_cannot_hide_a_corrupt_artifact() {
        let fixture = Fixture::new(); fixture.complete(0,None);
        fs::write(fixture.spec.delivery.join("artifacts/app"), b"wrong artifact").unwrap();
        assert!(fixture.store.completion(ID, &fixture.digest).is_err());
        assert_eq!(fs::read(fixture.spec.delivery.join("diagnostics/stdout")).unwrap(), STDOUT);
        assert_eq!(fixture.store.status(ID).unwrap().unwrap().state, OperationState::Completed);
    }

    #[test]
    fn both_streams_must_be_verified_and_snapshots_are_independent_of_original_files() {
        let fixture = Fixture::new(); fixture.complete(1,None);
        let proof = fixture.proof();
        let snapshot = proof.snapshot(deadline()).unwrap();
        fs::write(fixture.spec.delivery.join("diagnostics/stderr"), b"corrupted second stream").unwrap();
        assert!(proof.snapshot(deadline()).is_err());
        fs::write(fixture.spec.delivery.join("diagnostics/stdout"), b"changed after snapshot").unwrap();
        let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
        snapshot.emit(&mut stdout, &mut stderr, deadline()).unwrap();
        assert_eq!(stdout, STDOUT); assert_eq!(stderr, STDERR);
    }

    #[test]
    fn nonterminal_cancelled_before_spawn_and_wrong_identity_never_authorize_output() {
        let fixture = Fixture::new();
        assert!(fixture.store.completion(ID, &fixture.digest).is_err());
        fixture.store.cancel(ID).unwrap();
        assert!(fixture.store.completion(ID, &fixture.digest).is_err());
        let active = Fixture::new();
        let claim = active.store.claim_next().unwrap().unwrap();
        assert!(active.store.completion(ID, &active.digest).is_err());
        drop(claim);
        assert_eq!(
            active.store.status(ID).unwrap().unwrap().state,
            OperationState::Uncertain
        );
        assert!(active.store.completion(ID, &active.digest).is_err());
        let completed = Fixture::new();
        completed.complete(1, None);
        assert!(completed.store.completion(ID, &"00".repeat(32)).is_err());
        assert!(
            completed
                .store
                .completion(&"00".repeat(16), &completed.digest)
                .is_err()
        );
    }

    #[test]
    fn receipt_substitution_links_and_expired_snapshot_refuse_before_replay() {
        for case in 0..4 {
            let fixture = Fixture::new();
            fixture.complete(1, None);
            let proof = fixture.proof();
            let stdout = fixture.spec.delivery.join("diagnostics/stdout");
            match case {
                0 => {
                    fs::write(fixture.spec.delivery.join("delivery.json"), b"{}").unwrap();
                }
                1 => {
                    fs::hard_link(&stdout, fixture.root.join("alias")).unwrap();
                }
                2 => {
                    let retained = fixture.root.join("retained-stdout");
                    fs::rename(&stdout, &retained).unwrap();
                    std::os::unix::fs::symlink(&retained, &stdout).unwrap();
                }
                _ => {}
            }
            assert!(
                proof
                    .snapshot(if case == 3 {
                        Instant::now()
                    } else {
                        deadline()
                    })
                    .is_err()
            );
        }
    }

    #[test]
    fn completion_survives_store_restart_without_the_original_bundle() {
        let fixture = Fixture::new();
        fixture.complete(1, None);
        let proof = fixture.proof();
        fs::rename(&fixture.spec.bundle, fixture.root.join("retired-bundle")).unwrap();
        drop(fixture.store);
        let reopened = PreparedOperationStore::open(&fixture.root.join("state")).unwrap();
        assert_eq!(reopened.completion(ID, &fixture.digest).unwrap(), proof);
        let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
        proof
            .snapshot(deadline())
            .unwrap()
            .emit(&mut stdout, &mut stderr, deadline())
            .unwrap();
        assert_eq!(stdout, STDOUT);
        assert_eq!(stderr, STDERR);
        assert!(
            reopened.claim_next().unwrap().is_none(),
            "replay must never enqueue a compiler"
        );
    }

    #[test]
    fn broken_stdout_aborts_replay_without_retrying_or_printing_stderr() {
        struct Broken(usize);
        impl Write for Broken {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                self.0 += 1;
                Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed console"))
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let fixture = Fixture::new();
        fixture.complete(1, None);
        let snapshot = fixture.proof().snapshot(deadline()).unwrap();
        let (mut stdout, mut stderr) = (Broken(0), Vec::new());
        assert_eq!(
            snapshot
                .emit(&mut stdout, &mut stderr, deadline())
                .unwrap_err()
                .kind(),
            io::ErrorKind::BrokenPipe
        );
        assert_eq!(stdout.0, 1);
        assert!(stderr.is_empty());
        assert_eq!(
            fixture.store.status(ID).unwrap().unwrap().state,
            OperationState::Completed
        );
    }

    #[test]
    fn local_recovery_installs_stranded_outputs_without_the_bundle_and_retains_uncertainty_about_acks()
     {
        use std::os::unix::fs::MetadataExt;
        let fixture = Fixture::new();
        fixture.strand(0, None);
        let receipt = fs::read(fixture.spec.delivery.join("delivery.json")).unwrap();
        let source_inode = fs::metadata(fixture.spec.delivery.join("artifacts/app"))
            .unwrap()
            .ino();
        fs::rename(&fixture.spec.bundle, fixture.root.join("retired-bundle")).unwrap();
        let status = fixture
            .store
            .recover_local(ID, fixture.spec.delivery.clone())
            .unwrap();
        assert!(status.succeeded && status.outputs_installed);
        assert_eq!(status.mode, "recover-local");
        assert_eq!(status.request_sha256, fixture.digest);
        assert!(status.listen_address.is_none());
        assert_eq!(status.acknowledgments_confirmed, Some(false));
        assert!(
            status
                .detail
                .unwrap()
                .contains("did not contact the worker")
        );
        assert_eq!(fs::read(fixture.spec.output.join("app")).unwrap(), ARTIFACT);
        assert_ne!(
            source_inode,
            fs::metadata(fixture.spec.output.join("app")).unwrap().ino()
        );
        assert_eq!(
            fs::read(fixture.spec.delivery.join("delivery.json")).unwrap(),
            receipt
        );
        let proof = fixture.proof();
        let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
        proof
            .snapshot(deadline())
            .unwrap()
            .emit(&mut stdout, &mut stderr, deadline())
            .unwrap();
        assert_eq!(stdout, STDOUT);
        assert_eq!(stderr, STDERR);

        // Local completion does not free an uncertain remote reservation.
        let mut next = fixture.spec.clone();
        next.id = "ab".repeat(16);
        next.bundle = fixture.root.join("next-bundle");
        next.delivery = fixture.root.join("next-delivery");
        next.output = fixture.root.join("next-output");
        fs::create_dir(&next.bundle).unwrap();
        let mut request = fixture.request.clone();
        request["request_id"] = json!(8);
        fs::write(
            next.bundle.join("request.json"),
            serde_json::to_vec(&request).unwrap(),
        )
        .unwrap();
        fixture.store.submit(next).unwrap();
        assert!(fixture.store.claim_next().unwrap().is_none());
    }

    #[test]
    fn local_recovery_preserves_failed_or_cancelled_compiler_diagnostics_without_installation() {
        for (exit, stop) in [
            (17, None),
            (130, Some("cancelled")),
            (125, Some("lease-expired")),
        ] {
            let fixture = Fixture::new();
            fixture.strand(exit, stop);
            let status = fixture
                .store
                .recover_local(ID, fixture.spec.delivery.clone())
                .unwrap();
            assert_eq!(status.exit_code, Some(i32::from(exit)));
            assert_eq!(status.stop_reason.as_deref(), stop);
            assert!(!status.succeeded && !status.outputs_installed);
            assert_eq!(
                status.state,
                if stop.is_some() {
                    OperationState::Cancelled
                } else {
                    OperationState::Completed
                }
            );
            assert!(!fixture.spec.output.exists());
            assert_eq!(fixture.proof().exit_code, exit);
            assert!(fixture.store.claim_next().unwrap().is_none());
        }
    }

    #[test]
    fn local_recovery_never_repairs_corrupt_deliveries_or_overwrites_conflicting_outputs() {
        for case in 0..5 {
            let fixture = Fixture::new();
            fixture.strand(0, None);
            match case {
                0 => fs::write(
                    fixture.spec.delivery.join("artifacts/app"),
                    b"corrupt artifact",
                )
                .unwrap(),
                1 => fs::write(
                    fixture.spec.delivery.join("diagnostics/stderr"),
                    b"corrupt diagnostics",
                )
                .unwrap(),
                2 => fs::rename(
                    fixture.spec.delivery.join("delivery.json"),
                    fixture.root.join("saved-receipt"),
                )
                .unwrap(),
                3 => {
                    let path = fixture.spec.delivery.join("delivery.json");
                    let mut receipt: Value =
                        serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
                    receipt["worker_spki_sha256"] = json!("02".repeat(32));
                    fs::write(path, serde_json::to_vec(&receipt).unwrap()).unwrap();
                }
                _ => {
                    fs::create_dir(&fixture.spec.output).unwrap();
                    fs::write(
                        fixture.spec.output.join("app"),
                        b"operator-owned different output",
                    )
                    .unwrap();
                }
            }
            let artifact_before = fs::read(fixture.spec.delivery.join("artifacts/app")).unwrap();
            assert!(
                fixture
                    .store
                    .recover_local(ID, fixture.spec.delivery.clone())
                    .is_err(),
                "case {case}"
            );
            assert_eq!(
                fs::read(fixture.spec.delivery.join("artifacts/app")).unwrap(),
                artifact_before
            );
            if case == 4 {
                assert_eq!(
                    fs::read(fixture.spec.output.join("app")).unwrap(),
                    b"operator-owned different output"
                );
            } else {
                assert!(!fixture.spec.output.exists());
            }
            let status = fixture.store.status(ID).unwrap().unwrap();
            assert_eq!(status.state, OperationState::Uncertain);
            assert!(status.execution_may_have_run);
            assert!(status.listen_address.is_none());
            assert!(fixture.store.claim_next().unwrap().is_none());
        }
    }

    #[test]
    fn local_recovery_refuses_unowned_active_or_never_dispatched_jobs_without_mutation() {
        for case in 0..4 {
            let fixture = Fixture::new();
            let claim = if case == 0 {
                fixture.store.claim_next().unwrap()
            } else {
                None
            };
            if case == 2 {
                fixture.store.cancel(ID).unwrap();
            }
            if case == 3 {
                fixture.strand(0, None);
            }
            let record = fixture.root.join(format!("state/{ID}.json"));
            let before = fs::read(&record).unwrap();
            let path = if case == 3 {
                fixture.root.join("unowned")
            } else {
                fixture.spec.delivery.clone()
            };
            assert!(fixture.store.recover_local(ID, path).is_err());
            assert_eq!(fs::read(record).unwrap(), before);
            assert!(!fixture.spec.output.exists());
            drop(claim);
        }
    }

    #[test]
    fn local_recovery_can_select_an_earlier_owned_delivery_after_failed_remote_resume() {
        let fixture = Fixture::new();
        fixture.strand(0, None);
        let later = fixture.root.join("later-delivery");
        fixture.store.resume(ID, later.clone(), None).unwrap();
        drop(fixture.store.claim_next().unwrap().unwrap());
        let status = fixture
            .store
            .recover_local(ID, fixture.spec.delivery.clone())
            .unwrap();
        assert!(status.succeeded);
        assert_eq!(status.delivery, fixture.spec.delivery);
        let record: Value = serde_json::from_slice(
            &fs::read(fixture.root.join(format!("state/{ID}.json"))).unwrap(),
        )
        .unwrap();
        assert!(
            record["prior_deliveries"]
                .as_array()
                .unwrap()
                .contains(&json!(later))
        );
        assert!(!later.exists());
    }

    #[test]
    fn local_recovery_preserves_previously_confirmed_acceptance_and_reuses_exact_installations() {
        use std::os::unix::fs::MetadataExt;
        let fixture = Fixture::new(); fixture.complete(0, None);
        let receipt = fs::read(fixture.spec.delivery.join("delivery.json")).unwrap();
        let inode = fs::metadata(fixture.spec.output.join("app")).unwrap().ino();
        let status = fixture.store.recover_local(ID, fixture.spec.delivery.clone()).unwrap();
        assert!(status.succeeded);
        assert_eq!(status.acknowledgments_confirmed, Some(true));
        assert!(status.detail.is_none());
        assert_eq!(fs::metadata(fixture.spec.output.join("app")).unwrap().ino(), inode);
        assert_eq!(fs::read(fixture.spec.delivery.join("delivery.json")).unwrap(), receipt);
        assert!(fixture.store.claim_next().unwrap().is_none());
    }

    #[test]
    fn local_recovery_cannot_substitute_a_different_recorded_compiler_outcome() {
        let fixture = Fixture::new(); fixture.complete(0, None);
        let other = Fixture::new(); other.complete(17, None);
        // Both trees passed the real receiver, for the same request identity,
        // but their compiler outcomes differ. Preserve the original tree under
        // another name rather than deleting its files in this fixture.
        fs::rename(&fixture.spec.delivery, fixture.root.join("original-delivery")).unwrap();
        fs::rename(&other.spec.delivery, &fixture.spec.delivery).unwrap();
        assert!(fixture.store.recover_local(ID, fixture.spec.delivery.clone()).unwrap_err()
            .to_string().contains("previously recorded compiler outcome"));
        assert_eq!(fs::read(fixture.spec.output.join("app")).unwrap(), ARTIFACT);
        let status = fixture.store.status(ID).unwrap().unwrap();
        assert_eq!(status.state, OperationState::Uncertain);
        assert_eq!(status.exit_code, Some(0));
    }

    #[test]
    fn cancelled_or_lost_local_owner_remains_uncertain_across_store_restart() {
        let fixture = Fixture::new(); fixture.strand(0, None);
        let (claim, accepted) = fixture.store.claim_local(ID, fixture.spec.delivery.clone()).unwrap();
        assert!(!accepted);
        assert!(fixture.store.claim_next().unwrap().is_none());
        assert!(fixture.store.recover_local(ID, fixture.spec.delivery.clone()).is_err());
        fixture.store.cancel(ID).unwrap();
        assert!(claim.cancellation().is_cancelled());
        drop(claim);
        assert!(!fixture.spec.output.exists());
        assert_eq!(fixture.store.status(ID).unwrap().unwrap().state, OperationState::Uncertain);
        drop(fixture.store);
        let reopened = PreparedOperationStore::open(&fixture.root.join("state")).unwrap();
        assert!(reopened.claim_next().unwrap().is_none());
        assert_eq!(reopened.status(ID).unwrap().unwrap().mode, "recover-local");
        assert!(reopened.recover_local(ID, fixture.spec.delivery).unwrap().succeeded);
    }

    #[test]
    fn uncertain_local_claim_persistence_never_installs_or_enqueues_after_restart() {
        use std::sync::atomic::Ordering;
        let fixture = Fixture::new(); fixture.strand(0, None);
        fixture.store.fail_after_rename.store(true, Ordering::SeqCst);
        assert!(fixture.store.recover_local(ID, fixture.spec.delivery.clone()).is_err());
        assert!(!fixture.spec.output.exists());
        assert!(fixture.store.claim_next().is_err(), "uncertain store must remain fenced");
        drop(fixture.store);
        let reopened = PreparedOperationStore::open(&fixture.root.join("state")).unwrap();
        let status = reopened.status(ID).unwrap().unwrap();
        assert_eq!(status.state, OperationState::Uncertain);
        assert_eq!(status.mode, "recover-local");
        assert!(status.execution_may_have_run);
        assert!(reopened.claim_next().unwrap().is_none());
        assert!(reopened.recover_local(ID, fixture.spec.delivery).unwrap().succeeded);
    }

    #[test]
    fn archived_completion_replays_and_local_recovery_restores_without_source_or_execution() {
        use crate::coord::prepared_operation::MAX_RETAINED_BYTES;
        use std::os::unix::fs::MetadataExt;
        let fixture = Fixture::new();
        fixture.complete(0, None);
        let proof = fixture.proof();
        let inode = fs::metadata(fixture.spec.output.join("app")).unwrap().ino();
        let receipt = fs::read(fixture.spec.delivery.join("delivery.json")).unwrap();
        let archive = fixture.root.join(format!("state/archive/{ID}.json"));
        {
            let mut state = fixture.store.lock_state().unwrap();
            fixture
                .store
                .make_room(&mut state, MAX_RETAINED_BYTES)
                .unwrap();
            assert!(state.records.is_empty());
        }
        fs::rename(&fixture.spec.bundle, fixture.root.join("retired-bundle")).unwrap();
        assert_eq!(
            fixture.proof(),
            proof,
            "archival preserves the complete delivery proof"
        );
        let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
        fixture
            .proof()
            .snapshot(deadline())
            .unwrap()
            .emit(&mut stdout, &mut stderr, deadline())
            .unwrap();
        assert_eq!(stdout, STDOUT);
        assert_eq!(stderr, STDERR);
        assert!(archive.is_file());
        assert!(fixture.store.claim_next().unwrap().is_none());
        drop(fixture.store);

        let reopened = PreparedOperationStore::open(&fixture.root.join("state")).unwrap();
        assert_eq!(reopened.completion(ID, &fixture.digest).unwrap(), proof);
        let status = reopened
            .recover_local(ID, fixture.spec.delivery.clone())
            .unwrap();
        assert!(status.succeeded && status.outputs_installed);
        assert_eq!(status.acknowledgments_confirmed, Some(true));
        assert_eq!(status.mode, "recover-local");
        assert_eq!(status.attempt, 2);
        assert!(reopened.lock_state().unwrap().records.contains_key(ID));
        assert!(
            !archive.exists(),
            "one durable record moves back to live ownership"
        );
        assert_eq!(
            fs::metadata(fixture.spec.output.join("app")).unwrap().ino(),
            inode
        );
        assert_eq!(
            fs::read(fixture.spec.delivery.join("delivery.json")).unwrap(),
            receipt
        );
        assert!(reopened.claim_next().unwrap().is_none());
        {
            let mut state = reopened.lock_state().unwrap();
            reopened.make_room(&mut state, MAX_RETAINED_BYTES).unwrap();
        }
        let archived: Value = serde_json::from_slice(&fs::read(&archive).unwrap()).unwrap();
        assert_eq!(archived["attempt"], 2);
        assert_eq!(archived["mode"], "local_recovery");
        assert_eq!(reopened.completion(ID, &fixture.digest).unwrap(), proof);
        assert!(reopened.claim_next().unwrap().is_none());
    }

    #[test]
    fn archival_restore_crashes_never_queue_an_execution_or_replace_installed_outputs() {
        use crate::coord::prepared_operation::MAX_RETAINED_BYTES;
        use std::os::unix::fs::MetadataExt;
        use std::sync::atomic::Ordering;
        for after_running in [false, true] {
            let fixture = Fixture::new();
            fixture.complete(0, None);
            let inode = fs::metadata(fixture.spec.output.join("app")).unwrap().ino();
            {
                let mut state = fixture.store.lock_state().unwrap();
                fixture
                    .store
                    .make_room(&mut state, MAX_RETAINED_BYTES)
                    .unwrap();
            }
            // These are distinct durable boundaries: the terminal record moves
            // back first; only then can the local owner persist Running.
            if after_running {
                fixture
                    .store
                    .fail_after_rename
                    .store(true, Ordering::SeqCst);
            } else {
                fixture
                    .store
                    .fail_after_archive_rename
                    .store(true, Ordering::SeqCst);
            }
            assert!(
                fixture
                    .store
                    .recover_local(ID, fixture.spec.delivery.clone())
                    .is_err()
            );
            assert!(fixture.store.claim_next().is_err());
            assert_eq!(
                fs::metadata(fixture.spec.output.join("app")).unwrap().ino(),
                inode
            );
            assert_eq!(fs::read(fixture.spec.output.join("app")).unwrap(), ARTIFACT);
            drop(fixture.store);

            let reopened = PreparedOperationStore::open(&fixture.root.join("state")).unwrap();
            let status = reopened.status(ID).unwrap().unwrap();
            assert_eq!(
                status.state,
                if after_running {
                    OperationState::Uncertain
                } else {
                    OperationState::Completed
                }
            );
            assert_eq!(status.attempt, if after_running { 2 } else { 1 });
            assert!(reopened.claim_next().unwrap().is_none());
            assert!(
                reopened
                    .recover_local(ID, fixture.spec.delivery.clone())
                    .unwrap()
                    .succeeded
            );
            assert_eq!(
                fs::metadata(fixture.spec.output.join("app")).unwrap().ino(),
                inode
            );
            assert!(reopened.claim_next().unwrap().is_none());
        }
    }
}
