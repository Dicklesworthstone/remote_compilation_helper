//! Durable, request-bound retention of one completed worker result.
//!
//! The execution owner seals immutable captures before announcing completion.
//! The journal commits the seal's digest before any network result. Reopening
//! verifies the seal and every byte off the reactor; only then can the ordinary
//! range handlers deliver the original result without launching an executor.
//! These files are transport retention, never CAS publication or cache authority.

use crate::artifacts::{ArtifactPlan, PreparedArtifacts};
use crate::execution::{ExecutionCompletion, StopReason};
use crate::output::{CapturedOutputs, CapturedStream, MAX_OUTPUT_CHUNK_BYTES};
use crate::session::{ExecResult, sha256_hex};
use rabs_sandbox::artifact_tree::{MAX_TREE_FILES, MAX_TREE_MANIFEST_BYTES};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

pub const RESULT_RETENTION: &str = "durable-result-v1";
pub const MAX_RESULT_BYTES: u64 = 1024 * 1024 * 1024;
// A tree's bounded complete manifest plus diagnostic and recipient metadata.
const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
const DIRECTORY: &str = "retained-result";
const MANIFEST: &str = "manifest.json";

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}
fn require(condition: bool, message: &str) -> io::Result<()> {
    if condition { Ok(()) } else { Err(invalid(message)) }
}
fn text<'a>(value: &'a Value, key: &str) -> io::Result<&'a str> {
    value.get(key).and_then(Value::as_str).ok_or_else(|| invalid(key))
}
fn number(value: &Value, key: &str) -> io::Result<u64> {
    value.get(key).and_then(Value::as_u64).ok_or_else(|| invalid(key))
}
fn canonical_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// The destination authenticated on the actual connection, not a hello claim.
/// Endpoint binding is additionally supplied by the enclosing worker journal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResultRecipient {
    TlsSpki([u8; 32]),
    LoopbackFixture,
}
impl ResultRecipient {
    fn encode(&self) -> String {
        match self {
            Self::TlsSpki(pin) => format!("tls-spki:{}", pin.iter().map(|b| format!("{b:02x}")).collect::<String>()),
            Self::LoopbackFixture => "loopback-fixture".to_owned(),
        }
    }
    fn decode(value: &str) -> io::Result<Self> {
        if value == "loopback-fixture" { return Ok(Self::LoopbackFixture); }
        let pin = value.strip_prefix("tls-spki:").ok_or_else(|| invalid("unknown result recipient"))?;
        require(canonical_digest(pin), "invalid result recipient key")?;
        let mut bytes = [0_u8; 32];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&pin[index * 2..index * 2 + 2], 16).map_err(|_| invalid("recipient key"))?;
        }
        require(bytes != [0; 32], "zero result recipient key")?;
        Ok(Self::TlsSpki(bytes))
    }
}

fn private_path(path: &Path, directory: bool) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    require(if directory { metadata.is_dir() } else { metadata.is_file() }, "spool path is a link or special file")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        require(metadata.permissions().mode() & 0o077 == 0, "spool path is not private")?;
        if !directory { require(metadata.nlink() == 1, "spool file has another hard link")?; }
    }
    #[cfg(not(unix))]
    return Err(io::Error::new(io::ErrorKind::Unsupported, "durable result storage requires Unix"));
    #[cfg(unix)]
    Ok(())
}
fn create_file(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}
fn data_path(root: &Path, index: usize) -> PathBuf { root.join(format!("file-{index:03}")) }

#[derive(Debug, Clone)]
struct Item { name: String, len: u64, digest: String, executable: bool }

/// Bounded interpretation of the sealed result. Names are validated as an exact
/// artifact plan before they can ever be used to reconstruct a directory. The
/// complete tree set may exceed the original request's required-file count;
/// rehydration never treats that minimum as the complete output manifest.
fn describe(result: &Value) -> io::Result<(Vec<Item>, Option<ArtifactPlan>, Option<StopReason>)> {
    require(text(result, "kind")? == "exec-result" && result["executed"] == true
        && number(result, "residual_group_members")? == 0, "result is not fully cleaned")?;
    number(result, "request_id")?;
    let exit = result["exit_code"].as_i64().filter(|code| (0..=255).contains(code))
        .ok_or_else(|| invalid("invalid retained exit"))?;
    let stop = match result.get("stop_reason") {
        Some(Value::Null) => None,
        Some(value) => Some(match value.as_str() {
            Some("cancelled") => StopReason::Cancelled,
            Some("deadline-exceeded") => StopReason::DeadlineExceeded,
            Some("session-lost") => StopReason::SessionLost,
            _ => return Err(invalid("invalid retained stop reason")),
        }),
        None => return Err(invalid("missing retained stop reason")),
    };
    require(stop.is_none_or(|reason| exit == i64::from(reason.exit_code())), "retained interruption contradicts exit")?;
    let mut items = Vec::new();
    for name in ["stdout", "stderr"] {
        items.push(Item { name: name.to_owned(), len: number(result, &format!("{name}_bytes"))?,
            digest: text(result, &format!("{name}_sha256"))?.to_owned(), executable: false });
    }
    let plan = match result.get("artifact_manifest") {
        Some(Value::Null) => None,
        Some(manifest) if exit == 0 && stop.is_none() => {
            require(serde_json::to_vec(manifest)?.len() <= MAX_TREE_MANIFEST_BYTES,
                "retained artifact manifest exceeds its byte bound")?;
            let rows = manifest["files"].as_array().filter(|rows| rows.len() <= MAX_TREE_FILES)
                .ok_or_else(|| invalid("invalid retained artifact manifest"))?;
            let mut names = Vec::new();
            for row in rows {
                let name = text(row, "name")?.to_owned();
                names.push(name.clone());
                items.push(Item { name, len: number(row, "bytes")?, digest: text(row, "sha256")?.to_owned(),
                    executable: row["executable"].as_bool().ok_or_else(|| invalid("artifact mode"))? });
            }
            let plan = ArtifactPlan::from_retained(text(manifest, "unit")?.to_owned(), names.clone())?;
            require(plan.files().eq(names.iter().map(String::as_str)), "retained manifest is not canonically ordered")?;
            Some(plan)
        }
        _ => return Err(invalid("unexpected retained artifacts")),
    };
    let mut total = 0_u64;
    for item in &items {
        require(canonical_digest(&item.digest), "invalid retained file digest")?;
        total = total.checked_add(item.len).filter(|size| *size <= MAX_RESULT_BYTES)
            .ok_or_else(|| invalid("combined result retention budget exceeded"))?;
    }
    Ok((items, plan, stop))
}

/// Prepared from the already-durable admission, on the worker thread-launch path.
/// No wire field can nominate the spool directory or substitute a fingerprint.
#[derive(Debug, Clone)]
pub struct RetentionTarget { root: PathBuf, request_id: u64, fingerprint: String, recipient: ResultRecipient }
impl RetentionTarget {
    pub fn from_admitted(journal_root: &Path, request_id: u64, recipient: ResultRecipient) -> io::Result<Self> {
        private_path(journal_root, true)?;
        private_path(&journal_root.join("requests.json"), false)?;
        let mut bytes = Vec::new();
        File::open(journal_root.join("requests.json"))?.take(65_537).read_to_end(&mut bytes)?;
        require(bytes.len() <= 65_536, "journal exceeds bound")?;
        let state: Value = serde_json::from_slice(&bytes)?;
        let last = &state["last"];
        require(state["version"] == 1 && number(&state, "boot_generation")? > 0
            && last["request_id"].as_u64() == Some(request_id)
            && last["boot_generation"] == state["boot_generation"]
            && last["resolved"] == false && last["receipt"].is_null(), "retention does not own current admission")?;
        let fingerprint = text(last, "fingerprint")?.to_owned();
        require(canonical_digest(&fingerprint), "invalid admission fingerprint")?;
        ResultRecipient::decode(&recipient.encode())?;
        let root = journal_root.join(DIRECTORY);
        match fs::symlink_metadata(&root) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
            Ok(_) => return Err(invalid("prior retained result has not been released")),
        }
        Ok(Self { root, request_id, fingerprint, recipient })
    }

    /// Seal on the blocking execution owner, before making completion observable.
    /// Every file and the containing directory are synced before returning a root.
    /// Partial failures retain evidence; they never advertise resumable output.
    pub fn seal(&self, completion: &mut ExecutionCompletion) -> io::Result<String> {
        let result = &completion.result;
        require(result.request_id == self.request_id, "retained result has a foreign request identity")?;
        let outputs = completion.outputs.as_mut().ok_or_else(|| invalid("durable results require complete diagnostics"))?;
        let record = json!({"kind":"exec-result", "request_id":result.request_id,
            "exit_code":result.exit_code,"executed":result.executed,
            "residual_group_members":result.residual_group_members,
            "stop_reason":completion.stop_reason.map(StopReason::label),
            "stdout_bytes":outputs.stdout.len(),"stderr_bytes":outputs.stderr.len(),
            "stdout_sha256":outputs.stdout.sha256(),"stderr_sha256":outputs.stderr.sha256(),
            "artifact_manifest":completion.artifacts.as_ref().map(|bundle| bundle.manifest())});
        require(record["stdout_sha256"] == result.stdout_sha256 && record["stderr_sha256"] == result.stderr_sha256,
            "capture/result digest disagreement")?;
        let (items, _, _) = describe(&record)?;
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(&self.root)?;
        for (index, item) in items.iter().enumerate() {
            let mut file = create_file(&data_path(&self.root, index))?;
            let mut hasher = Sha256::new();
            let mut offset = 0_u64;
            while offset < item.len {
                let bytes = match index {
                    0 => outputs.stdout.read_chunk(offset, MAX_OUTPUT_CHUNK_BYTES)?,
                    1 => outputs.stderr.read_chunk(offset, MAX_OUTPUT_CHUNK_BYTES)?,
                    _ => completion.artifacts.as_mut().ok_or_else(|| invalid("missing artifact owner"))?
                        .read_chunk(&item.name, offset, MAX_OUTPUT_CHUNK_BYTES)?,
                };
                require(!bytes.is_empty() && bytes.len() as u64 <= item.len - offset, "capture range length changed")?;
                file.write_all(&bytes)?;
                hasher.update(&bytes);
                offset += bytes.len() as u64;
            }
            let actual: String = hasher.finalize().iter().map(|byte| format!("{byte:02x}")).collect();
            require(actual == item.digest, "retained bytes differ from capture digest")?;
            file.sync_all()?;
        }
        let manifest = json!({"version":1,"request_id":self.request_id,
            "request_fingerprint":self.fingerprint,"recipient":self.recipient.encode(),"result":record});
        let bytes = serde_json::to_vec(&manifest)?;
        require(bytes.len() as u64 <= MAX_MANIFEST_BYTES, "result manifest too large")?;
        let mut file = create_file(&self.root.join(MANIFEST))?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        File::open(&self.root)?.sync_all()?;
        File::open(self.root.parent().ok_or_else(|| invalid("spool parent"))?)?.sync_all()?;
        Ok(sha256_hex(&bytes))
    }
}

fn read_manifest(root: &Path, expected_digest: &str) -> io::Result<Value> {
    private_path(root, true)?;
    private_path(&root.join(MANIFEST), false)?;
    require(canonical_digest(expected_digest), "invalid retained manifest identity")?;
    let mut bytes = Vec::new();
    File::open(root.join(MANIFEST))?.take(MAX_MANIFEST_BYTES + 1).read_to_end(&mut bytes)?;
    require(bytes.len() as u64 <= MAX_MANIFEST_BYTES && sha256_hex(&bytes) == expected_digest,
        "retained manifest digest mismatch")?;
    let manifest: Value = serde_json::from_slice(&bytes)?;
    require(manifest["version"] == 1 && manifest.as_object().is_some_and(|map| map.len() == 5), "retained manifest schema")?;
    Ok(manifest)
}

#[derive(Debug)]
pub struct RecoveredResult {
    pub recipient: ResultRecipient,
    pub completion: ExecutionCompletion,
}

/// Refuse an unexplained leftover rather than overwrite or silently discard it.
pub fn exists(journal_root: &Path) -> io::Result<bool> {
    match fs::symlink_metadata(journal_root.join(DIRECTORY)) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

/// The small durable journal receipt must identify the same completed outcome
/// as the seal. This bounded metadata check never rereads all output on the reactor.
pub fn validate_receipt(
    journal_root: &Path, request_id: u64, fingerprint: &str, digest: &str, receipt: &Value,
) -> io::Result<()> {
    let manifest = read_manifest(&journal_root.join(DIRECTORY), digest)?;
    require(manifest["request_id"].as_u64() == Some(request_id)
        && text(&manifest, "request_fingerprint")? == fingerprint, "retention/admission mismatch")?;
    describe(&manifest["result"])?;
    for field in ["kind", "request_id", "exit_code", "executed", "residual_group_members",
        "stop_reason", "stdout_sha256", "stderr_sha256"] {
        require(receipt.get(field).is_some() && receipt.get(field) == manifest["result"].get(field),
            "journal outcome disagrees with retained result")?;
    }
    Ok(())
}

/// Rehydrate off the reactor, while the exclusive worker journal lock is held.
/// Private snapshots are recreated, so later reads do not reopen mutable names.
pub fn load(journal_root: &Path, request_id: u64, fingerprint: &str, digest: &str) -> io::Result<RecoveredResult> {
    let root = journal_root.join(DIRECTORY);
    let manifest = read_manifest(&root, digest)?;
    require(manifest["request_id"].as_u64() == Some(request_id)
        && text(&manifest, "request_fingerprint")? == fingerprint, "retained result/admission binding mismatch")?;
    let recipient = ResultRecipient::decode(text(&manifest, "recipient")?)?;
    let result = &manifest["result"];
    require(number(result, "request_id")? == request_id, "retained result request mismatch")?;
    let (items, plan, stop_reason) = describe(result)?;
    let expected: BTreeSet<_> = std::iter::once(MANIFEST.to_owned())
        .chain((0..items.len()).map(|index| format!("file-{index:03}"))).collect();
    for entry in fs::read_dir(&root)? {
        let entry = entry?;
        require(entry.file_name().to_str().is_some_and(|name| expected.contains(name)), "unknown spool entry")?;
    }
    let mut captured = Vec::new();
    for (index, item) in items.iter().enumerate() {
        let path = data_path(&root, index);
        private_path(&path, false)?;
        let file = File::open(&path)?;
        require(file.metadata()?.is_file() && file.metadata()?.len() == item.len, "retained file type/size mismatch")?;
        let snapshot = CapturedStream::from_reader(file, item.len)?;
        require(snapshot.sha256() == item.digest, "retained file content mismatch")?;
        captured.push(snapshot);
    }
    let mut streams = captured.into_iter();
    let stdout = streams.next().ok_or_else(|| invalid("missing stdout"))?;
    let stderr = streams.next().ok_or_else(|| invalid("missing stderr"))?;
    let artifacts = match plan {
        None => None,
        Some(plan) => {
            let prepared = PreparedArtifacts::new(plan)?;
            for (item, mut snapshot) in items.iter().skip(2).zip(streams) {
                let mut file = create_file(&prepared.backing().join(&item.name))?;
                let mut offset = 0;
                while offset < item.len {
                    let bytes = snapshot.read_chunk(offset, MAX_OUTPUT_CHUNK_BYTES)?;
                    require(!bytes.is_empty(), "empty artifact restore range")?;
                    file.write_all(&bytes)?;
                    offset += bytes.len() as u64;
                }
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    file.set_permissions(fs::Permissions::from_mode(if item.executable {0o700} else {0o600}))?;
                }
            }
            let bundle = prepared.capture(|| false)?;
            require(bundle.manifest() == result["artifact_manifest"], "retained artifact manifest disagreement")?;
            Some(bundle)
        }
    };
    Ok(RecoveredResult { recipient, completion: ExecutionCompletion {
        result: ExecResult { request_id, exit_code: result["exit_code"].as_i64().ok_or_else(|| invalid("exit"))? as i32,
            stdout_sha256: stdout.sha256().to_owned(), stderr_sha256: stderr.sha256().to_owned(),
            executed: true, residual_group_members: 0,
            stdout_spill_bytes: 0, stderr_spill_bytes: 0, stdout_spill_path: None, stderr_spill_path: None },
        stop_reason, outputs: Some(CapturedOutputs { stdout, stderr }), artifacts,
    } })
}

/// Called ONLY after the journal durably records complete receiver acceptance.
/// Fixed owned names, never a recursive deletion or a peer-supplied path. Partial
/// cleanup can be retried after restart; unexpected entries stop reclamation.
pub fn purge_accepted(journal_root: &Path, digest: &str) -> io::Result<()> {
    let root = journal_root.join(DIRECTORY);
    match fs::symlink_metadata(&root) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
        Ok(_) => private_path(&root, true)?,
    }
    if fs::read_dir(&root)?.next().is_none() {
        fs::remove_dir(&root)?;
        File::open(journal_root)?.sync_all()?;
        return Ok(());
    }
    let manifest = read_manifest(&root, digest)?;
    let (items, _, _) = describe(&manifest["result"])?;
    let expected: BTreeSet<_> = std::iter::once(MANIFEST.to_owned())
        .chain((0..items.len()).map(|index| format!("file-{index:03}"))).collect();
    for entry in fs::read_dir(&root)? {
        let entry = entry?;
        require(entry.file_name().to_str().is_some_and(|name| expected.contains(name)), "unknown spool entry prevents cleanup")?;
        private_path(&entry.path(), false)?;
    }
    for index in 0..items.len() {
        match fs::remove_file(data_path(&root, index)) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    // Persist data-file removal before removing the only cleanup manifest.
    File::open(&root)?.sync_all()?;
    fs::remove_file(root.join(MANIFEST))?;
    File::open(&root)?.sync_all()?;
    fs::remove_dir(&root)?;
    File::open(journal_root)?.sync_all()
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::execution::ExecutionTask;
    use crate::request_journal::{WorkerJournal, request_fingerprint};
    use std::future::Future;
    use std::pin::pin;
    use std::sync::Arc;
    use std::task::{Context, Poll, Wake, Waker};
    use std::time::{Duration, Instant};

    fn target(root: &Path, id: u64) -> (WorkerJournal, RetentionTarget, String) {
        let mut journal = WorkerJournal::open(root, "worker", "coord").unwrap();
        let request = json!({"kind":"canonical-exec","request_id":id,"program":"rustc","args":[]});
        let timeout = Duration::from_secs(5);
        assert_eq!(journal.admit(&request, timeout).unwrap(), None);
        let fingerprint = request_fingerprint(&request, timeout);
        let target = RetentionTarget::from_admitted(root, id, ResultRecipient::TlsSpki([7; 32])).unwrap();
        (journal, target, fingerprint)
    }
    fn completion(id: u64, with_artifact: bool) -> ExecutionCompletion {
        let outputs = CapturedOutputs {
            stdout: CapturedStream::from_reader(&b"A\0\xffB"[..], 4).unwrap(),
            stderr: CapturedStream::from_reader(&b""[..], 0).unwrap(),
        };
        let artifacts = with_artifact.then(|| {
            use std::os::unix::fs::PermissionsExt;
            let prepared = PreparedArtifacts::new(ArtifactPlan::new("dep".into(), vec!["nested/a".into()]).unwrap()).unwrap();
            fs::write(prepared.backing().join("nested/a"), b"compiled\0\xff").unwrap();
            fs::set_permissions(prepared.backing().join("nested/a"), fs::Permissions::from_mode(0o700)).unwrap();
            prepared.capture(|| false).unwrap()
        });
        ExecutionCompletion { result: ExecResult { request_id: id, exit_code: 0,
            stdout_sha256: outputs.stdout.sha256().to_owned(), stderr_sha256: outputs.stderr.sha256().to_owned(),
            executed: true, residual_group_members: 0, stdout_spill_bytes: 0, stderr_spill_bytes: 0,
            stdout_spill_path: None, stderr_spill_path: None }, stop_reason: None, outputs: Some(outputs), artifacts }
    }
    struct ThreadWake(std::thread::Thread);
    impl Wake for ThreadWake { fn wake(self: Arc<Self>) { self.0.unpark(); } }
    fn wait<F: Future>(future: F) -> F::Output {
        let mut future = pin!(future);
        let waker = Waker::from(Arc::new(ThreadWake(std::thread::current())));
        let mut cx = Context::from_waker(&waker);
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Poll::Ready(result) = future.as_mut().poll(&mut cx) { return result; }
            assert!(Instant::now() < deadline, "result retention timed out");
            std::thread::park_timeout(Duration::from_millis(10));
        }
    }

    #[test]
    fn sealed_binary_result_reopens_with_exact_artifacts_and_recipient() {
        let root = tempfile::tempdir().unwrap();
        let (_journal, target, fingerprint) = target(root.path(), 1);
        let mut original = completion(1, true);
        let manifest = original.artifacts.as_ref().unwrap().manifest();
        let digest = target.seal(&mut original).unwrap();
        drop(original);
        let mut recovered = load(root.path(), 1, &fingerprint, &digest).unwrap();
        assert_eq!(recovered.recipient, ResultRecipient::TlsSpki([7; 32]));
        assert_eq!(recovered.completion.outputs.as_mut().unwrap().stdout.read_chunk(0, 64).unwrap(), b"A\0\xffB");
        let artifacts = recovered.completion.artifacts.as_mut().unwrap();
        assert_eq!(artifacts.manifest(), manifest);
        assert_eq!(artifacts.read_chunk("nested/a", 0, 64).unwrap(), b"compiled\0\xff");
        assert!(artifacts.file_identity("nested/a").unwrap().2);
        assert!(load(root.path(), 2, &fingerprint, &digest).is_err());
        assert!(load(root.path(), 1, &"0".repeat(64), &digest).is_err());
    }

    #[test]
    fn failed_and_cancelled_results_recover_diagnostics_without_fake_artifacts() {
        for stop in [None, Some(StopReason::Cancelled), Some(StopReason::SessionLost)] {
            let root = tempfile::tempdir().unwrap();
            let (_journal, target, fingerprint) = target(root.path(), 1);
            let mut original = completion(1, false);
            original.stop_reason = stop;
            original.result.exit_code = stop.map_or(1, StopReason::exit_code);
            let digest = target.seal(&mut original).unwrap();
            let recovered = load(root.path(), 1, &fingerprint, &digest).unwrap();
            assert_eq!(recovered.completion.stop_reason, stop);
            assert_eq!(recovered.completion.result.exit_code, original.result.exit_code);
            assert!(recovered.completion.artifacts.is_none());
        }
    }

    #[test]
    fn corruption_and_foreign_entries_never_become_recovered_results() {
        for case in 0..5 {
            let root = tempfile::tempdir().unwrap();
            let (_journal, target, fingerprint) = target(root.path(), 1);
            let digest = target.seal(&mut completion(1, true)).unwrap();
            let spool = root.path().join(DIRECTORY);
            match case {
                0 => fs::write(data_path(&spool, 0), b"bad!").unwrap(),
                1 => fs::write(spool.join(MANIFEST), b"{}").unwrap(),
                2 => { let _ = create_file(&spool.join("unexpected")).unwrap(); }
                3 => fs::rename(data_path(&spool, 0), spool.join("missing")).unwrap(),
                _ => {
                    fs::rename(data_path(&spool, 0), root.path().join("outside")).unwrap();
                    std::os::unix::fs::symlink(root.path().join("outside"), data_path(&spool, 0)).unwrap();
                }
            }
            assert!(load(root.path(), 1, &fingerprint, &digest).is_err());
        }
    }

    #[test]
    fn missing_capture_and_residual_writers_are_refused_before_spool_creation() {
        for case in 0..3 {
            let root = tempfile::tempdir().unwrap();
            let (_journal, target, _) = target(root.path(), 1);
            let mut original = completion(1, false);
            match case {
                0 => original.outputs = None,
                1 => original.result.residual_group_members = 1,
                _ => original.result.request_id = 2,
            }
            assert!(target.seal(&mut original).is_err());
            assert!(!root.path().join(DIRECTORY).exists());
        }
    }

    #[test]
    fn declared_byte_limits_and_metadata_paths_fail_closed() {
        let mut value = json!({"kind":"exec-result","request_id":1,"executed":true,
            "exit_code":0,"stop_reason":null,"residual_group_members":0,
            "stdout_bytes":MAX_RESULT_BYTES,"stderr_bytes":0,
            "stdout_sha256":sha256_hex(b""),"stderr_sha256":sha256_hex(b""),"artifact_manifest":null});
        assert!(describe(&value).is_ok());
        value["stderr_bytes"] = json!(1);
        assert!(describe(&value).is_err());
        value["stdout_bytes"] = json!(u64::MAX);
        assert!(describe(&value).is_err());
        value["stdout_bytes"] = json!(0);
        value["artifact_manifest"] = json!({"unit":"dep","files":[
            {"name":"../host-file","bytes":1,"sha256":sha256_hex(b"x"),"executable":false}]});
        assert!(describe(&value).is_err());
        assert!(ResultRecipient::decode(&format!("tls-spki:{}", "0".repeat(64))).is_err());
        assert!(ResultRecipient::decode("tls-spki:not-hex").is_err());
    }

    #[test]
    fn acceptance_cleanup_is_repeatable_and_cannot_follow_unknown_paths() {
        let root = tempfile::tempdir().unwrap();
        let (_journal, target, _) = target(root.path(), 1);
        let digest = target.seal(&mut completion(1, true)).unwrap();
        let unknown = root.path().join(DIRECTORY).join("foreign");
        let _ = create_file(&unknown).unwrap();
        assert!(purge_accepted(root.path(), &digest).is_err());
        assert!(root.path().join(DIRECTORY).join(MANIFEST).exists());
        fs::rename(&unknown, root.path().join("saved-foreign")).unwrap();
        // A previous cleanup may have removed some data files before crashing.
        fs::remove_file(data_path(&root.path().join(DIRECTORY), 0)).unwrap();
        purge_accepted(root.path(), &digest).unwrap();
        purge_accepted(root.path(), &digest).unwrap();
        assert!(!root.path().join(DIRECTORY).exists());
        assert!(root.path().join("saved-foreign").exists());
    }

    #[test]
    fn execution_owner_seals_before_completion_and_reports_persistence_failure() {
        for fail in [false, true] {
            let root = tempfile::tempdir().unwrap();
            let (_journal, target, fingerprint) = target(root.path(), 1);
            if fail { fs::create_dir(root.path().join(DIRECTORY)).unwrap(); }
            let mut task = ExecutionTask::spawn_for_delivery(1, Duration::from_secs(5), None, Some(target), |control| {
                let mut completion = completion(1, false);
                control.retain_outputs(Ok(completion.outputs.take().unwrap())).unwrap();
                completion.result
            }).unwrap();
            let completed = wait(task.wait());
            if fail {
                assert!(completed.unwrap_err().contains("retention"));
                assert!(task.retained_result_digest().is_none());
            } else {
                completed.unwrap();
                let digest = task.retained_result_digest().unwrap();
                assert!(load(root.path(), 1, &fingerprint, &digest).is_ok());
            }
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn tree_results_rehydrate_every_file_beyond_the_exact_declaration_limit() {
        use rabs_sandbox::artifact_tree::TREE_FILES_VERSION;
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let mut journal = WorkerJournal::open(root.path(), "worker", "coord").unwrap();
        let request = json!({"kind":"canonical-exec", "request_id":23, "program":"cargo",
            "artifacts":{"unit":"build", "files":["debug/app"], "tree":TREE_FILES_VERSION}});
        let timeout = Duration::from_secs(5);
        assert_eq!(journal.admit(&request, timeout).unwrap(), None);
        let fingerprint = request_fingerprint(&request, timeout);
        let target = RetentionTarget::from_admitted(root.path(), 23, ResultRecipient::TlsSpki([7; 32])).unwrap();
        let plan = crate::artifacts::parse_plan(&request).unwrap().unwrap();
        let prepared = PreparedArtifacts::new(plan).unwrap();
        fs::create_dir_all(prepared.backing().join("debug/deps")).unwrap();
        for index in 0..130 {
            fs::write(prepared.backing().join(format!("debug/deps/file-{index:04}")), format!("payload-{index}")).unwrap();
        }
        fs::set_permissions(prepared.backing().join("debug/deps/file-0000"), fs::Permissions::from_mode(0o755)).unwrap();
        fs::hard_link(prepared.backing().join("debug/deps/file-0000"), prepared.backing().join("debug/app")).unwrap();
        let mut original = completion(23, false);
        original.artifacts = Some(prepared.capture(|| false).unwrap());
        let manifest = original.artifacts.as_ref().unwrap().manifest();
        assert_eq!(manifest["files"].as_array().unwrap().len(), 131);
        let digest = target.seal(&mut original).unwrap();
        drop(original);
        let mut recovered = load(root.path(), 23, &fingerprint, &digest).unwrap();
        let artifacts = recovered.completion.artifacts.as_mut().unwrap();
        assert_eq!(artifacts.manifest(), manifest);
        assert_eq!(artifacts.read_chunk("debug/app", 0, 64).unwrap(), b"payload-0");
        assert_eq!(artifacts.read_chunk("debug/deps/file-0129", 0, 64).unwrap(), b"payload-129");
        assert!(artifacts.file_identity("debug/app").unwrap().2);
        let mut changed = request;
        changed["artifacts"].as_object_mut().unwrap().remove("tree");
        assert!(load(root.path(), 23, &request_fingerprint(&changed, timeout), &digest).is_err());
    }

    #[test]
    fn retained_tree_count_is_bounded_independently_of_request_minimum() {
        let rows: Vec<_> = (0..MAX_TREE_FILES).map(|index| json!({
            "name":format!("f{index:04}"), "bytes":0, "sha256":sha256_hex(b""), "executable":false,
        })).collect();
        let mut result = json!({"kind":"exec-result", "request_id":1, "executed":true,
            "exit_code":0, "stop_reason":null, "residual_group_members":0,
            "stdout_bytes":0, "stderr_bytes":0, "stdout_sha256":sha256_hex(b""),
            "stderr_sha256":sha256_hex(b""), "artifact_manifest":{"unit":"build", "files":rows}});
        assert_eq!(describe(&result).unwrap().0.len(), MAX_TREE_FILES + 2);
        result["artifact_manifest"]["files"].as_array_mut().unwrap().push(json!({
            "name":"overflow", "bytes":0, "sha256":sha256_hex(b""), "executable":false,
        }));
        assert!(describe(&result).is_err());
    }
}
