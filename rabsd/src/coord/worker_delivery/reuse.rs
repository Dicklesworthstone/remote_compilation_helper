//! Local byte hints for an explicitly resumed, still-retained worker result.
//!
//! An abandoned directory is never promoted to a delivery and is never edited.
//! Its ordinary files may supply prefixes in a NEW private staging directory.
//! The current remote result supplies the complete lengths and SHA-256 values;
//! the delivery engine hashes local prefixes plus downloaded tails together.
//! No prefix, file length, old marker or local timestamp authorizes an ACK.
//!
//! Like the existing delivery/recovery API, the operator exclusively owns these
//! directories for the invocation. Component checks detect ordinary substitutions;
//! this is not a race-proof shared-directory filesystem API. No tree is enumerated
//! and only names in the newly validated result are considered for reuse.

use super::{CHUNK_BYTES, MAX_DELIVERY_BYTES, WorkerAuthentication, WorkerPeer, invalid, require, safe_name};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs::{self, File, Metadata};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};

/// An operator-selected, read-only source of candidate prefixes. This is NOT a
/// verified delivery, retained-result identity, or permission to execute work.
#[derive(Debug)]
pub struct ResumeSource {
    root: PathBuf,
    identity: Metadata,
}

fn ordinary_path(path: &Path, allow_missing_leaf: bool) -> io::Result<()> {
    require(path.is_absolute() && path.file_name().is_some()
        && path.components().all(|part| matches!(part, Component::RootDir | Component::Normal(_))),
        "resume paths must be named absolute paths without traversal")?;
    let mut prefix = PathBuf::new();
    for part in path.components() {
        prefix.push(part.as_os_str());
        match fs::symlink_metadata(&prefix) {
            Ok(metadata) => require(metadata.is_dir(), "resume path contains a link or non-directory")?,
            Err(error) if allow_missing_leaf && prefix == path && error.kind() == io::ErrorKind::NotFound => {},
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn same_identity(before: &Metadata, after: &Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        before.dev() == after.dev() && before.ino() == after.ino()
            && before.file_type() == after.file_type()
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
        before.nlink() == after.nlink() && before.mode() == after.mode()
            && before.mtime() == after.mtime() && before.mtime_nsec() == after.mtime_nsec()
            && before.ctime() == after.ctime() && before.ctime_nsec() == after.ctime_nsec()
    }
    #[cfg(not(unix))]
    {
        before.modified().ok().zip(after.modified().ok()).is_some_and(|(a, b)| a == b)
    }
}

impl ResumeSource {
    /// Inspect local intent before opening a listener. A missing candidate FILE
    /// is a cache miss later; a missing/linked source ROOT is a preflight error.
    pub fn open(root: &Path) -> io::Result<Self> {
        ordinary_path(root, false)?;
        let root = fs::canonicalize(root)?;
        let identity = fs::symlink_metadata(&root)?;
        require(identity.is_dir(), "resume source is not an ordinary directory")?;
        Ok(Self { root, identity })
    }

    /// The previous directory is informational only; it is never sent to a peer.
    pub fn root(&self) -> &Path { &self.root }

    /// Refuse in-place repair and aliases in either direction before dispatch.
    /// The ordinary receiver still exclusively creates the destination itself.
    pub fn validate_destination(&self, destination: &Path) -> io::Result<()> {
        self.check_root()?;
        ordinary_path(destination, true)?;
        let parent = destination.parent().ok_or_else(|| invalid("resume destination parent"))?;
        let name = destination.file_name().ok_or_else(|| invalid("resume destination name"))?;
        let destination = fs::canonicalize(parent)?.join(name);
        require(!destination.starts_with(&self.root) && !self.root.starts_with(&destination),
            "resume source and new delivery must not overlap")
    }

    fn check_root(&self) -> io::Result<()> {
        ordinary_path(&self.root, false)?;
        let current = fs::symlink_metadata(&self.root)?;
        require(current.is_dir() && same_identity(&self.identity, &current), "resume source root changed")
    }

    /// Copy a bounded prefix and advance the SAME complete-file hash used for
    /// network ranges. Even a complete local file is not trusted until that hash
    /// matches the freshly received result. Corruption fails the whole delivery;
    /// it does not cause a second execution or silent repair of the old tree.
    pub(super) fn copy_prefix(
        &self, group: &str, name: &str, expected_length: u64,
        target: &mut File, hasher: &mut Sha256,
    ) -> io::Result<u64> {
        require(matches!(group, "artifacts" | "diagnostics") && safe_name(name)
            && (group == "artifacts" || matches!(name, "stdout" | "stderr")),
            "invalid resume member")?;
        require(expected_length <= MAX_DELIVERY_BYTES, "resume file exceeds delivery budget")?;
        self.check_root()?;
        let mut path = self.root.clone();
        let mut directories = Vec::new();
        let mut components = std::iter::once(group).chain(name.split('/')).peekable();
        while let Some(component) = components.next() {
            path.push(component);
            let before = match fs::symlink_metadata(&path) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(0),
                Err(error) => return Err(error),
            };
            if components.peek().is_some() {
                require(before.is_dir(), "resume member parent is a link or non-directory")?;
                directories.push((path.clone(), before));
                continue;
            }
            require(before.is_file() && before.len() <= expected_length,
                "resume member is nonregular or longer than the retained result")?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                require(before.nlink() == 1, "resume member has another hard link")?;
            }
            let mut source = File::open(&path)?;
            require(same_file(&before, &source.metadata()?), "resume member changed while opening")?;
            let mut remaining = before.len();
            let mut bytes = [0_u8; CHUNK_BYTES];
            while remaining != 0 {
                let count = remaining.min(CHUNK_BYTES as u64) as usize;
                source.read_exact(&mut bytes[..count])?;
                target.write_all(&bytes[..count])?;
                hasher.update(&bytes[..count]);
                remaining -= count as u64;
            }
            require(source.read(&mut bytes[..1])? == 0
                && same_file(&before, &source.metadata()?)
                && same_file(&before, &fs::symlink_metadata(&path)?),
                "resume member changed while copying")?;
            for (directory, before) in directories {
                let after = fs::symlink_metadata(directory)?;
                require(after.is_dir() && same_identity(&before, &after), "resume member parent changed")?;
            }
            self.check_root()?;
            return Ok(before.len());
        }
        Err(invalid("missing resume member"))
    }
}

/// Add local byte hints without changing authentication, negotiation, operation
/// identity or the transport's deadlines. The shared receiver rejects this
/// adapter in Execute mode before contacting the worker or creating storage.
pub struct ResumePeer<'a, P: ?Sized> {
    inner: &'a mut P,
    source: &'a ResumeSource,
}

impl<'a, P: WorkerPeer + ?Sized> ResumePeer<'a, P> {
    pub fn new(inner: &'a mut P, source: &'a ResumeSource) -> Self { Self { inner, source } }
}

impl<P: WorkerPeer + ?Sized> WorkerPeer for ResumePeer<'_, P> {
    fn send(&mut self, value: &Value) -> io::Result<()> { self.inner.send(value) }
    fn receive(&mut self) -> io::Result<Value> { self.inner.receive() }
    fn negotiate(&mut self, hello: &Value, grant: &Value) -> io::Result<()> { self.inner.negotiate(hello, grant) }
    fn authentication(&self) -> Option<WorkerAuthentication> { self.inner.authentication() }
    fn resume_source(&self) -> Option<&ResumeSource> { Some(self.source) }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt, symlink};

    fn prefix(source: &ResumeSource, owner: &Path, group: &str, name: &str, len: u64)
        -> io::Result<(u64, Vec<u8>, String)>
    {
        let output = tempfile::NamedTempFile::new_in(owner)?;
        let mut hash = Sha256::new();
        let copied = source.copy_prefix(group, name, len, &mut output.reopen()?, &mut hash)?;
        let digest = hash.finalize().iter().map(|byte| format!("{byte:02x}")).collect();
        Ok((copied, fs::read(output.path())?, digest))
    }

    #[test]
    fn binary_unaligned_prefixes_are_copied_without_changing_the_old_tree() {
        let owner = tempfile::tempdir().unwrap();
        let root = owner.path().join("old");
        fs::create_dir_all(root.join("artifacts/nested")).unwrap();
        let bytes: Vec<u8> = (0..CHUNK_BYTES + 17).map(|n| (n % 251) as u8).collect();
        let path = root.join("artifacts/nested/a");
        fs::write(&path, &bytes).unwrap();
        let before = fs::metadata(&path).unwrap();
        let source = ResumeSource::open(&root).unwrap();
        let (copied, actual, digest) = prefix(&source, owner.path(), "artifacts", "nested/a", bytes.len() as u64 + 20).unwrap();
        assert_eq!(copied, bytes.len() as u64);
        assert_eq!(actual, bytes);
        assert_eq!(digest, super::super::hash(&bytes));
        assert_eq!(fs::read(&path).unwrap(), bytes);
        assert!(same_file(&before, &fs::metadata(&path).unwrap()));
        assert_eq!(fs::metadata(&path).unwrap().nlink(), 1);
    }

    #[test]
    fn absent_members_are_misses_but_nonregular_oversized_and_linked_members_refuse() {
        let owner = tempfile::tempdir().unwrap();
        let root = owner.path().join("old");
        fs::create_dir_all(root.join("artifacts")).unwrap();
        fs::write(root.join("artifacts/large"), b"AB").unwrap();
        fs::create_dir(root.join("artifacts/directory")).unwrap();
        symlink("large", root.join("artifacts/alias")).unwrap();
        fs::hard_link(root.join("artifacts/large"), root.join("artifacts/hard")).unwrap();
        let socket = std::os::unix::net::UnixListener::bind(root.join("artifacts/socket")).unwrap();
        let source = ResumeSource::open(&root).unwrap();
        assert_eq!(prefix(&source, owner.path(), "diagnostics", "stdout", 8).unwrap().0, 0);
        assert_eq!(prefix(&source, owner.path(), "artifacts", "missing/a", 8).unwrap().0, 0);
        for name in ["large", "hard", "directory", "alias", "socket"] {
            assert!(prefix(&source, owner.path(), "artifacts", name, 1).is_err(), "{name}");
        }
        assert!(prefix(&source, owner.path(), "artifacts", "hard", 8).is_err());
        assert!(prefix(&source, owner.path(), "artifacts", "../outside", 8).is_err());
        assert!(prefix(&source, owner.path(), "diagnostics", "other", 8).is_err());
        drop(socket);
    }

    #[test]
    fn roots_and_destinations_cannot_alias_or_overlap() {
        let owner = tempfile::tempdir().unwrap();
        let root = owner.path().join("old");
        fs::create_dir(&root).unwrap();
        let source = ResumeSource::open(&root).unwrap();
        source.validate_destination(&owner.path().join("new")).unwrap();
        assert!(source.validate_destination(&root).is_err());
        assert!(source.validate_destination(&root.join("new")).is_err());
        assert!(source.validate_destination(owner.path()).is_err());
        assert!(source.validate_destination(Path::new("relative")).is_err());
        let alias = owner.path().join("alias");
        symlink(&root, &alias).unwrap();
        assert!(ResumeSource::open(&alias).is_err());
        assert!(source.validate_destination(&alias.join("new")).is_err());
        fs::rename(&root, owner.path().join("retired")).unwrap();
        fs::create_dir(&root).unwrap();
        assert!(source.validate_destination(&owner.path().join("new")).is_err());
    }
}

#[cfg(all(test, unix))]
mod delivery_tests {
    use super::*;
    use super::super::{DeliveryMode, field, hash, receive_operation};
    use serde_json::json;
    use std::collections::VecDeque;
    use std::os::unix::fs::MetadataExt;

    fn request() -> Value {
        json!({"kind":"canonical-exec", "request_id":7, "program":"rustc", "args":["lib.rs"],
            "toolchain_backing":"/tc", "workspace_backing":"/ws",
            "artifacts":{"unit":"build", "files":["a"]}})
    }

    struct Peer {
        replies: VecDeque<Value>,
        sent: Vec<Value>,
        result: Value,
        stdout: Vec<u8>,
        artifact: Vec<u8>,
        destination: PathBuf,
        fail_artifact_at: Option<u64>,
        receive_count: usize,
    }
    impl Peer {
        fn new(destination: &Path, mode: DeliveryMode) -> Self {
            let stdout: Vec<u8> = (0..CHUNK_BYTES + 19).map(|n| (n % 256) as u8).collect();
            let artifact: Vec<u8> = (0..2 * CHUNK_BYTES + 37).map(|n| (n % 251) as u8).collect();
            let mut manifest_hash = Sha256::new();
            field(&mut manifest_hash, b"rabs.worker-artifact-manifest.v1");
            field(&mut manifest_hash, b"build");
            manifest_hash.update(1_u64.to_be_bytes());
            field(&mut manifest_hash, b"a");
            manifest_hash.update([0]);
            manifest_hash.update((artifact.len() as u64).to_be_bytes());
            field(&mut manifest_hash, hash(&artifact).as_bytes());
            let identity: String = manifest_hash.finalize().iter().map(|b| format!("{b:02x}")).collect();
            let manifest = json!({"unit":"build", "files":[{"name":"a", "bytes":artifact.len(),
                "sha256":hash(&artifact), "executable":false}], "total_bytes":artifact.len(), "manifest_sha256":identity});
            let result = json!({"kind":"exec-result", "request_id":7, "executed":true, "exit_code":0,
                "resumed":mode == DeliveryMode::Resume, "residual_group_members":0, "stop_reason":null,
                "result_retention":"durable-result-v1", "retained_result_sha256":hash(b"retained fixture result"),
                "output_transfer":"ranges-v1", "output_ack_required":true,
                "stdout_bytes":stdout.len(), "stdout_sha256":hash(&stdout), "stderr_bytes":0, "stderr_sha256":hash(b""),
                "artifact_transfer":"files-v1", "artifact_ack_required":true, "artifact_manifest":manifest});
            let mut hello = json!({"kind":"worker-hello", "worker_id":"worker", "canonical":true, "slots":1,
                "boot_generation":1, "incarnation":"00000000000000000000000000000001", "request_high_water":null,
                "result_retentions":["durable-result-v1"], "recovery_protocols":["request-journal-v1"],
                "output_transfers":["ranges-v1"], "artifact_transfers":["files-v1"]});
            if mode == DeliveryMode::Resume { hello["request_high_water"] = json!(7); }
            Self { replies:VecDeque::from([hello]), sent:Vec::new(), result, stdout, artifact,
                destination:destination.to_path_buf(), fail_artifact_at:None, receive_count:0 }
        }
        fn no_ack(&self) -> bool {
            self.sent.iter().all(|frame| !matches!(frame["kind"].as_str(), Some("output-ack" | "artifact-ack")))
        }
    }
    impl WorkerPeer for Peer {
        fn send(&mut self, frame: &Value) -> io::Result<()> {
            self.sent.push(frame.clone());
            match frame["kind"].as_str() {
                Some("session-ok") => {},
                Some("canonical-exec") => {
                    assert_eq!(frame, &request());
                    self.replies.push_back(self.result.clone());
                }
                Some("result-resume") => {
                    assert_eq!(frame, &DeliveryMode::Resume.frame(&request()));
                    self.replies.push_back(self.result.clone());
                }
                Some("output-read" | "artifact-read") => {
                    assert_eq!(frame["request_id"], 7);
                    assert_eq!(frame["max_bytes"], CHUNK_BYTES);
                    let artifact = frame["kind"] == "artifact-read";
                    let name = frame[if artifact { "name" } else { "stream" }].as_str().unwrap();
                    let offset = frame["offset"].as_u64().unwrap();
                    if artifact && self.fail_artifact_at.is_some_and(|limit| offset >= limit) {
                        return Err(io::Error::new(io::ErrorKind::ConnectionReset, "injected interrupted artifact"));
                    }
                    let bytes: &[u8] = match (artifact, name) {
                        (true, "a") => &self.artifact,
                        (false, "stdout") => &self.stdout,
                        (false, "stderr") => b"",
                        _ => panic!("unexpected requested output"),
                    };
                    assert!(offset <= bytes.len() as u64);
                    let end = (offset as usize + CHUNK_BYTES).min(bytes.len());
                    let part = &bytes[offset as usize..end];
                    let mut reply = json!({"kind":if artifact {"artifact-chunk"} else {"output-chunk"},
                        "request_id":7, "offset":offset, "next_offset":end, "total_bytes":bytes.len(),
                        "sha256":hash(bytes), "chunk_sha256":hash(part), "eof":end == bytes.len(),
                        "data_hex":part.iter().map(|b| format!("{b:02x}")).collect::<String>()});
                    reply[if artifact {"name"} else {"stream"}] = json!(name);
                    if artifact {
                        reply["manifest_sha256"] = self.result["artifact_manifest"]["manifest_sha256"].clone();
                        reply["executable"] = json!(false);
                    }
                    self.replies.push_back(reply);
                }
                Some("output-ack" | "artifact-ack") => {
                    let receipt: Value = serde_json::from_slice(&fs::read(self.destination.join("delivery.json"))?)?;
                    assert_eq!(receipt["request_sha256"], hash(&serde_json::to_vec(&request()).unwrap()));
                    assert_eq!(fs::read(self.destination.join("diagnostics/stdout"))?, self.stdout);
                    assert_eq!(fs::read(self.destination.join("artifacts/a"))?, self.artifact);
                    assert_eq!(receipt["publication_authorized"], false);
                    self.replies.push_back(json!({"kind":if frame["kind"] == "output-ack" {
                        "output-acknowledged"} else {"artifact-acknowledged"}, "request_id":7, "already_released":false}));
                }
                _ => panic!("resume must not upload sources, retry execution or invent protocol messages"),
            }
            Ok(())
        }
        fn receive(&mut self) -> io::Result<Value> {
            self.receive_count += 1;
            self.replies.pop_front().ok_or_else(|| invalid("missing fixture reply"))
        }
    }

    #[test]
    fn interrupted_real_receiver_reuses_complete_diagnostics_and_partial_artifact() {
        let owner = tempfile::tempdir().unwrap();
        let old = owner.path().join("interrupted");
        let mut first = Peer::new(&old, DeliveryMode::Execute);
        first.fail_artifact_at = Some(CHUNK_BYTES as u64);
        let failure = receive_operation(&mut first, &request(), "worker", &old, DeliveryMode::Execute).unwrap_err();
        assert!(failure.execution_may_have_run);
        assert!(first.no_ack());
        assert!(!old.join("delivery.json").exists());
        let prefix = fs::read(old.join("artifacts/a")).unwrap();
        assert_eq!(prefix, first.artifact[..CHUNK_BYTES]);
        let before = fs::metadata(old.join("artifacts/a")).unwrap();
        let source = ResumeSource::open(&old).unwrap();
        let destination = owner.path().join("recovered");
        let mut peer = Peer::new(&destination, DeliveryMode::Resume);
        let delivery = receive_operation(&mut ResumePeer::new(&mut peer, &source),
            &request(), "worker", &destination, DeliveryMode::Resume).unwrap();
        assert!(delivery.acknowledgments_confirmed);
        let artifacts: Vec<_> = peer.sent.iter().filter(|q| q["kind"] == "artifact-read").collect();
        assert_eq!(artifacts.len(), 2);
        assert_eq!(artifacts[0]["offset"], CHUNK_BYTES);
        assert_eq!(artifacts[1]["offset"], 2 * CHUNK_BYTES);
        assert!(peer.sent.iter().all(|q| !(q["kind"] == "output-read" && q["stream"] == "stdout")));
        assert!(peer.sent.iter().all(|q| q["kind"] != "canonical-exec"));
        assert_eq!(fs::read(old.join("artifacts/a")).unwrap(), prefix);
        assert!(same_file(&before, &fs::metadata(old.join("artifacts/a")).unwrap()));
        assert_ne!(before.ino(), fs::metadata(destination.join("artifacts/a")).unwrap().ino());
        assert_eq!(delivery.receipt["resumed"], true);
        super::super::super::delivery_recovery::recover_existing_delivery(
            &request(), "worker", &destination,
            super::super::super::delivery_recovery::DeliveryTrust::Loopback,
        ).unwrap().unwrap();
    }

    #[test]
    fn complete_and_unaligned_prefixes_use_exact_remaining_ranges() {
        let owner = tempfile::tempdir().unwrap();
        for length in [17, CHUNK_BYTES + 7, 2 * CHUNK_BYTES + 37] {
            let old = owner.path().join(format!("old-{length}"));
            fs::create_dir_all(old.join("artifacts")).unwrap();
            let destination = owner.path().join(format!("new-{length}"));
            let mut peer = Peer::new(&destination, DeliveryMode::Resume);
            fs::write(old.join("artifacts/a"), &peer.artifact[..length]).unwrap();
            let source = ResumeSource::open(&old).unwrap();
            let delivery = receive_operation(&mut ResumePeer::new(&mut peer, &source),
                &request(), "worker", &destination, DeliveryMode::Resume).unwrap();
            assert!(delivery.acknowledgments_confirmed);
            let reads: Vec<_> = peer.sent.iter().filter(|q| q["kind"] == "artifact-read").collect();
            if length == peer.artifact.len() { assert!(reads.is_empty()); }
            else { assert_eq!(reads[0]["offset"], length); }
        }
    }

    #[test]
    fn corrupt_prefix_cannot_be_blessed_by_valid_network_tail_hashes() {
        let owner = tempfile::tempdir().unwrap();
        let old = owner.path().join("corrupt");
        fs::create_dir_all(old.join("artifacts")).unwrap();
        fs::write(old.join("artifacts/a"), b"corrupt-prefix").unwrap();
        let source = ResumeSource::open(&old).unwrap();
        let destination = owner.path().join("refused");
        let mut peer = Peer::new(&destination, DeliveryMode::Resume);
        let error = receive_operation(&mut ResumePeer::new(&mut peer, &source),
            &request(), "worker", &destination, DeliveryMode::Resume).unwrap_err();
        assert!(error.execution_may_have_run);
        assert!(error.detail.contains("complete file digest"));
        assert!(peer.no_ack());
        assert!(!destination.join("delivery.json").exists());
        assert_eq!(fs::read(old.join("artifacts/a")).unwrap(), b"corrupt-prefix");
        assert!(peer.sent.iter().all(|q| q["kind"] != "canonical-exec"));
    }

    #[test]
    fn resume_sources_never_authorize_execution_or_in_place_repair() {
        let owner = tempfile::tempdir().unwrap();
        let old = owner.path().join("old");
        fs::create_dir(&old).unwrap();
        let source = ResumeSource::open(&old).unwrap();
        for mode in [DeliveryMode::Execute, DeliveryMode::Resume] {
            let destination = if mode == DeliveryMode::Execute { owner.path().join("new") } else { old.clone() };
            let mut peer = Peer::new(&destination, mode);
            let failure = receive_operation(&mut ResumePeer::new(&mut peer, &source),
                &request(), "worker", &destination, mode).unwrap_err();
            assert_eq!(failure.execution_may_have_run, mode == DeliveryMode::Resume);
            assert!(peer.sent.is_empty());
            assert_eq!(peer.receive_count, 0);
        }
        assert!(fs::read_dir(&old).unwrap().next().is_none());
    }

    #[test]
    fn local_bytes_cannot_replace_missing_remote_result_or_retention_identity() {
        let owner = tempfile::tempdir().unwrap();
        let old = owner.path().join("old");
        fs::create_dir(&old).unwrap();
        let source = ResumeSource::open(&old).unwrap();
        for case in 0..3 {
            let destination = owner.path().join(format!("new-{case}"));
            let mut peer = Peer::new(&destination, DeliveryMode::Resume);
            match case {
                0 => peer.result = json!({"kind":"error", "request_id":7, "reason":"result unavailable"}),
                1 => peer.result["resumed"] = json!(false),
                _ => peer.result["retained_result_sha256"] = json!("invalid"),
            }
            assert!(receive_operation(&mut ResumePeer::new(&mut peer, &source),
                &request(), "worker", &destination, DeliveryMode::Resume).is_err());
            assert_eq!(peer.sent.len(), 2); // grant and exact result-resume only.
            assert!(peer.no_ack());
            assert!(!destination.join("delivery.json").exists());
        }
    }
}
