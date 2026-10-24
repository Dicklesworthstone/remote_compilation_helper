//! Production receiver coverage with a scripted authenticated transport adapter.
//! These tests exercise real files and delivery controls, not TLS or execution.

use super::*;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};

#[derive(Clone)]
struct Artifact {
    name: String,
    bytes: Vec<u8>,
    executable: bool,
}

impl Artifact {
    fn new(name: &str, bytes: &[u8], executable: bool) -> Self {
        Self {
            name: name.to_owned(),
            bytes: bytes.to_vec(),
            executable,
        }
    }
}

struct BytePeer {
    inner: Script,
    id: u64,
    worker: String,
    authentication: Option<WorkerAuthentication>,
    files: Vec<Artifact>,
    manifest: Value,
    pending: VecDeque<Value>,
    ranges: Vec<(String, u64)>,
    peak: usize,
    successful: bool,
    interrupt_after_bytes: Option<u64>,
    checkpoint_error: io::ErrorKind,
    checkpoints: usize,
}

impl BytePeer {
    fn new(destination: &Path, id: u64, files: Vec<Artifact>) -> Self {
        let mut inner = fixture(destination);
        inner.replies.remove(4);
        for frame in &mut inner.replies {
            if frame.get("request_id").is_some() {
                frame["request_id"] = json!(id);
            }
        }
        let mut peer = Self {
            inner,
            id,
            worker: "worker".to_owned(),
            authentication: Some(WorkerAuthentication {
                spki_sha256: [7; 32],
                session_id: id,
                identity_generation: 1,
            }),
            files,
            manifest: Value::Null,
            pending: VecDeque::new(),
            ranges: Vec::new(),
            peak: 0,
            successful: true,
            interrupt_after_bytes: None,
            checkpoint_error: io::ErrorKind::Interrupted,
            checkpoints: 0,
        };
        peer.set_diagnostics(
            format!("stdout for request {id}\n").as_bytes(),
            format!("stderr for request {id}\n").as_bytes(),
        );
        peer.set_manifest("dep");
        peer
    }

    fn set_diagnostics(&mut self, stdout: &[u8], stderr: &[u8]) {
        self.inner.expected_stdout = stdout.to_vec();
        for (index, stream, bytes) in [(2, "stdout", stdout), (3, "stderr", stderr)] {
            self.inner.replies[1][format!("{stream}_bytes")] = json!(bytes.len());
            self.inner.replies[1][format!("{stream}_sha256")] = json!(hash(bytes));
            let mut frame = chunk(stream, bytes, false);
            frame["request_id"] = json!(self.id);
            self.inner.replies[index] = frame;
        }
    }

    fn set_manifest(&mut self, unit: &str) {
        let mut hasher = Sha256::new();
        field(&mut hasher, b"rabs.worker-artifact-manifest.v1");
        field(&mut hasher, unit.as_bytes());
        hasher.update((self.files.len() as u64).to_be_bytes());
        let mut total = 0_u64;
        let rows: Vec<_> = self
            .files
            .iter()
            .map(|file| {
                let digest = hash(&file.bytes);
                field(&mut hasher, file.name.as_bytes());
                hasher.update([u8::from(file.executable)]);
                hasher.update((file.bytes.len() as u64).to_be_bytes());
                field(&mut hasher, digest.as_bytes());
                total += file.bytes.len() as u64;
                json!({"name":file.name,"bytes":file.bytes.len(),"sha256":digest,
                    "executable":file.executable})
            })
            .collect();
        let digest: String = hasher
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        self.manifest = json!({"unit":unit,"files":rows,"total_bytes":total,
            "manifest_sha256":digest});
        self.inner.replies[1]["artifact_manifest"] = self.manifest.clone();
    }

    fn request(&self) -> Value {
        let mut request = request();
        request["request_id"] = json!(self.id);
        request["artifacts"]["files"] =
            json!(self.files.iter().map(|file| &file.name).collect::<Vec<_>>());
        request
    }

    fn deliver(&mut self, cache: &ArtifactByteCache) -> Delivery {
        let request = self.request();
        let destination = self.inner.destination.clone();
        let worker = self.worker.clone();
        receive_execution(
            &mut ArtifactCachePeer::new(self, cache),
            &request,
            &worker,
            &destination,
        )
        .unwrap()
    }

    fn assert_complete(&self) {
        assert!(self.pending.is_empty());
        assert!(self.inner.replies.is_empty());
        assert!(self.peak <= 4);
        assert_eq!(
            self.inner
                .sent
                .iter()
                .filter(|frame| frame["kind"] == "canonical-exec")
                .count(),
            1
        );
        assert_eq!(
            self.inner
                .sent
                .iter()
                .filter(|frame| frame["kind"] == "output-read")
                .count(),
            2,
            "both current diagnostic streams must still be fetched"
        );
        self.assert_files();
    }

    fn assert_files(&self) {
        if !self.successful {
            assert!(
                fs::read_dir(self.inner.destination.join("artifacts"))
                    .unwrap()
                    .next()
                    .is_none()
            );
            return;
        }
        for file in &self.files {
            let path = self.inner.destination.join("artifacts").join(&file.name);
            assert_eq!(fs::read(&path).unwrap(), file.bytes);
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                if file.executable { 0o700 } else { 0o600 }
            );
            assert_eq!(fs::metadata(path).unwrap().nlink(), 1);
        }
    }

    fn assert_unreleased(&self) {
        assert!(no_ack(&self.inner));
        assert!(!self.inner.destination.join("delivery.json").exists());
        assert!(!self.inner.destination.join("delivery.pending").exists());
        assert_eq!(
            self.inner
                .sent
                .iter()
                .filter(|frame| matches!(
                    frame["kind"].as_str(),
                    Some("canonical-exec" | "result-resume")
                ))
                .count(),
            1
        );
    }
}

impl WorkerPeer for BytePeer {
    fn send(&mut self, frame: &Value) -> io::Result<()> {
        if frame.get("request_id").is_some() {
            assert_eq!(frame["request_id"], self.id);
        }
        if matches!(frame["kind"].as_str(), Some("output-ack" | "artifact-ack")) {
            assert!(
                self.pending.is_empty(),
                "ACK before all current ranges finish"
            );
            self.assert_files();
        }
        self.inner.send(frame)?;
        if frame["kind"] == "artifact-read" {
            assert!(self.pending.len() < 4, "one window must cover all files");
            assert_eq!(frame["max_bytes"], CHUNK_BYTES);
            self.ranges.push((
                frame["name"].as_str().unwrap().to_owned(),
                frame["offset"].as_u64().unwrap(),
            ));
            self.pending.push_back(frame.clone());
            self.peak = self.peak.max(self.pending.len());
        }
        Ok(())
    }

    fn receive(&mut self) -> io::Result<Value> {
        let Some(frame) = self.pending.pop_front() else {
            return self.inner.receive();
        };
        let name = frame["name"].as_str().unwrap();
        let index = self
            .files
            .iter()
            .position(|file| file.name == name)
            .unwrap();
        let file = &self.files[index];
        let offset = frame["offset"].as_u64().unwrap() as usize;
        let end = (offset + CHUNK_BYTES).min(file.bytes.len());
        let mut reply = chunk(name, &file.bytes[offset..end], true);
        reply["request_id"] = json!(self.id);
        reply["offset"] = json!(offset);
        reply["next_offset"] = json!(end);
        reply["total_bytes"] = json!(file.bytes.len());
        reply["sha256"] = self.manifest["files"][index]["sha256"].clone();
        reply["manifest_sha256"] = self.manifest["manifest_sha256"].clone();
        reply["executable"] = json!(file.executable);
        reply["eof"] = json!(end == file.bytes.len());
        Ok(reply)
    }

    fn authentication(&self) -> Option<WorkerAuthentication> {
        self.authentication
    }

    fn checkpoint(&mut self) -> io::Result<()> {
        self.checkpoints += 1;
        if self.interrupt_after_bytes.is_some_and(|limit| {
            self.files.iter().any(|file| {
                fs::metadata(self.inner.destination.join("artifacts").join(&file.name))
                    .is_ok_and(|metadata| metadata.len() >= limit)
            })
        }) {
            return Err(io::Error::new(
                self.checkpoint_error,
                "current delivery interrupted during bounded local copy",
            ));
        }
        Ok(())
    }
}

fn cache(owner: &Path) -> ArtifactByteCache {
    fs::set_permissions(owner, fs::Permissions::from_mode(0o700)).unwrap();
    ArtifactByteCache::open(owner, 8 * CHUNK_BYTES as u64, 32).unwrap()
}

fn objects(cache: &ArtifactByteCache) -> Vec<PathBuf> {
    let mut paths: Vec<_> = fs::read_dir(cache.root())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "artifact")
        })
        .collect();
    paths.sort();
    paths
}

#[test]
fn fresh_executions_reuse_bytes_with_current_diagnostics_manifest_and_mode() {
    let owner = tempfile::tempdir().unwrap();
    let cache = cache(owner.path());
    let bytes: Vec<_> = (0..2 * CHUNK_BYTES + 17)
        .map(|index| (index % 251) as u8)
        .collect();
    let first_path = owner.path().join("first");
    let mut first = BytePeer::new(
        &first_path,
        7,
        vec![Artifact::new("deps/old", &bytes, false)],
    );
    let first_delivery = first.deliver(&cache);
    first.assert_complete();
    assert_eq!(first.ranges.len(), 3);
    assert_eq!(objects(&cache).len(), 1);

    let second_path = owner.path().join("second");
    let mut second = BytePeer::new(
        &second_path,
        8,
        vec![Artifact::new("bin/current", &bytes, true)],
    );
    second.authentication.as_mut().unwrap().identity_generation = 2;
    let second_delivery = second.deliver(&cache);
    second.assert_complete();
    assert!(
        second.ranges.is_empty(),
        "verified bytes should avoid all artifact ranges"
    );
    assert!(second_delivery.acknowledgments_confirmed);
    assert_eq!(second_delivery.receipt["request_id"], 8);
    assert_eq!(second_delivery.receipt["authenticated_session_id"], 8);
    assert_eq!(second_delivery.receipt["identity_generation"], 2);
    assert_eq!(
        second_delivery.receipt["artifact_manifest"],
        second.manifest
    );
    assert_eq!(second_delivery.receipt["publication_authorized"], false);
    assert_ne!(
        first_delivery.receipt["request_sha256"],
        second_delivery.receipt["request_sha256"]
    );
    assert_ne!(
        first_delivery.receipt["stdout_sha256"],
        second_delivery.receipt["stdout_sha256"]
    );
    assert_ne!(
        first_delivery.receipt["stderr_sha256"],
        second_delivery.receipt["stderr_sha256"]
    );

    let cached = objects(&cache).pop().unwrap();
    let first_file = first_path.join("artifacts/deps/old");
    let second_file = second_path.join("artifacts/bin/current");
    let identity = |path: &Path| {
        let metadata = fs::metadata(path).unwrap();
        (metadata.dev(), metadata.ino())
    };
    assert_ne!(identity(&cached), identity(&first_file));
    assert_ne!(identity(&cached), identity(&second_file));
    assert_ne!(identity(&first_file), identity(&second_file));
    fs::write(&second_file, b"subscriber-owned mutation").unwrap();
    assert_eq!(fs::read(&first_file).unwrap(), bytes);
    assert_eq!(fs::read(&cached).unwrap(), bytes);
}

#[test]
fn reopening_private_cache_retains_only_content_reuse() {
    let owner = tempfile::tempdir().unwrap();
    let files = vec![Artifact::new("a", b"persistent bytes", false)];
    {
        let cache = cache(owner.path());
        BytePeer::new(&owner.path().join("first"), 7, files.clone()).deliver(&cache);
    }
    let reopened = cache(owner.path());
    let mut second = BytePeer::new(&owner.path().join("second"), 99, files);
    let delivery = second.deliver(&reopened);
    second.assert_complete();
    assert!(second.ranges.is_empty());
    assert_eq!(delivery.receipt["request_id"], 99);
    assert_eq!(delivery.receipt["publication_authorized"], false);
}

#[test]
fn corrupt_cached_content_falls_back_without_reexecution_or_early_ack() {
    for truncate in [false, true] {
        let owner = tempfile::tempdir().unwrap();
        let cache = cache(owner.path());
        let bytes = vec![0x5a; 2 * CHUNK_BYTES + 13];
        let files = vec![Artifact::new("a", &bytes, false)];
        BytePeer::new(&owner.path().join("first"), 7, files.clone()).deliver(&cache);
        let object = objects(&cache).pop().unwrap();
        let corrupt = if truncate {
            vec![0x5a; CHUNK_BYTES]
        } else {
            vec![0xa5; bytes.len()]
        };
        let permissions = fs::metadata(&object).unwrap().permissions();
        fs::set_permissions(&object, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&object, corrupt).unwrap();
        fs::set_permissions(&object, permissions).unwrap();
        let mut second = BytePeer::new(&owner.path().join("second"), 8, files);
        let delivery = second.deliver(&cache);
        second.assert_complete();
        assert!(delivery.acknowledgments_confirmed);
        assert_eq!(
            second.ranges,
            vec![
                ("a".to_owned(), 0),
                ("a".to_owned(), CHUNK_BYTES as u64),
                ("a".to_owned(), 2 * CHUNK_BYTES as u64)
            ]
        );
    }
}

#[test]
fn worker_identity_and_authenticated_spki_scope_byte_reuse() {
    let owner = tempfile::tempdir().unwrap();
    let cache = cache(owner.path());
    let files = vec![Artifact::new("a", b"scope bytes", false)];
    BytePeer::new(&owner.path().join("first"), 7, files.clone()).deliver(&cache);
    for case in 0..3 {
        let mut second = BytePeer::new(
            &owner.path().join(format!("second-{case}")),
            8 + case,
            files.clone(),
        );
        match case {
            0 => second.authentication.as_mut().unwrap().spki_sha256 = [8; 32],
            1 => {
                second.worker = "another-worker".to_owned();
                second.inner.replies[0]["worker_id"] = json!(second.worker);
            }
            _ => second.authentication = None,
        }
        second.deliver(&cache);
        second.assert_complete();
        assert_eq!(
            second.ranges,
            vec![("a".to_owned(), 0)],
            "scope case {case}"
        );
    }
    assert_eq!(
        objects(&cache).len(),
        3,
        "unauthenticated delivery must not publish bytes"
    );
}

#[test]
fn mixed_cached_and_network_files_keep_one_bounded_range_window() {
    let owner = tempfile::tempdir().unwrap();
    let cache = cache(owner.path());
    let files = vec![
        Artifact::new("a", b"cached a", false),
        Artifact::new("b", b"cached b", true),
        Artifact::new("c", b"cached c", false),
    ];
    BytePeer::new(&owner.path().join("first"), 7, files.clone()).deliver(&cache);
    let mut mixed = files;
    mixed[1].bytes = vec![0x6d; 5 * CHUNK_BYTES + 1];
    mixed.extend([
        Artifact::new("d", b"new file", true),
        Artifact::new("e", b"", false),
    ]);
    let mut second = BytePeer::new(&owner.path().join("second"), 8, mixed);
    second.deliver(&cache);
    second.assert_complete();
    assert_eq!(second.peak, 4);
    assert_eq!(second.ranges.len(), 8);
    assert!(
        second
            .ranges
            .iter()
            .all(|(name, _)| matches!(name.as_str(), "b" | "d" | "e"))
    );
    assert_eq!(
        second.ranges.last(),
        Some(&("e".to_owned(), 0)),
        "empty files keep their ordinary verified reply"
    );
}

#[test]
fn interruption_during_cached_copy_cannot_be_downgraded_to_a_cache_miss() {
    for error_kind in [io::ErrorKind::Interrupted, io::ErrorKind::TimedOut] {
        let owner = tempfile::tempdir().unwrap();
        let cache = cache(owner.path());
        let bytes = vec![0x42; 3 * CHUNK_BYTES + 1];
        let files = vec![Artifact::new("a", &bytes, false)];
        BytePeer::new(&owner.path().join("first"), 7, files.clone()).deliver(&cache);
        let destination = owner.path().join("interrupted");
        let mut second = BytePeer::new(&destination, 8, files);
        second.interrupt_after_bytes = Some(CHUNK_BYTES as u64);
        second.checkpoint_error = error_kind;
        let request = second.request();
        let failure = receive_execution(
            &mut ArtifactCachePeer::new(&mut second, &cache),
            &request,
            "worker",
            &destination,
        )
        .unwrap_err();
        assert!(failure.execution_may_have_run);
        assert!(
            !failure.transport_interrupted,
            "local error kinds alone are not socket evidence"
        );
        assert!(failure.detail.contains("bounded local copy"));
        assert!(
            second.ranges.is_empty(),
            "interruption must never trigger cold fallback"
        );
        assert!(second.checkpoints > 1);
        second.assert_unreleased();
        let partial = fs::read(destination.join("artifacts/a")).unwrap();
        assert!(partial.len() >= CHUNK_BYTES && partial.len() <= 2 * CHUNK_BYTES);
        assert_eq!(partial, bytes[..partial.len()]);
        assert_eq!(fs::read(objects(&cache).pop().unwrap()).unwrap(), bytes);
    }
}

#[test]
fn cached_bytes_cannot_bypass_current_cargo_artifact_report_validation() {
    let owner = tempfile::tempdir().unwrap();
    let cache = cache(owner.path());
    let files = vec![Artifact::new("deps/a.rmeta", b"compiled bytes", false)];
    BytePeer::new(&owner.path().join("first"), 7, files.clone()).deliver(&cache);
    let destination = owner.path().join("cargo");
    let mut second = BytePeer::new(&destination, 8, files);
    second.set_manifest("cargo");
    second.set_diagnostics(
        b"{\"reason\":\"build-finished\",\"success\":true}\n",
        b"current warning\n",
    );
    let mut request = second.request();
    request["program"] = json!("/__rabs/toolchain/bin/cargo");
    request["args"] = json!([
        "check",
        "--workspace",
        "--message-format=json",
        "--target-dir",
        "/__rabs/out/cargo"
    ]);
    request["artifacts"] =
        json!({"unit":"cargo", "tree":TREE_FILES_VERSION, "files":[], "cargo":"cargo-json-v1"});
    let failure = receive_execution(
        &mut ArtifactCachePeer::new(&mut second, &cache),
        &request,
        "worker",
        &destination,
    )
    .unwrap_err();
    assert!(failure.detail.contains("real non-build-script target"));
    assert!(second.ranges.is_empty());
    assert!(!destination.join("artifacts/deps/a.rmeta").exists());
    second.assert_unreleased();
}

#[test]
fn explicit_resume_prefix_retains_its_existing_verification_contract() {
    let owner = tempfile::tempdir().unwrap();
    let cache = cache(owner.path());
    let files = vec![Artifact::new("a", b"good bytes", false)];
    BytePeer::new(&owner.path().join("first"), 7, files.clone()).deliver(&cache);
    let abandoned = owner.path().join("abandoned");
    fs::create_dir_all(abandoned.join("artifacts")).unwrap();
    fs::write(abandoned.join("artifacts/a"), b"bad! bytes").unwrap();
    let source = ResumeSource::open(&abandoned).unwrap();
    let destination = owner.path().join("resumed");
    let mut second = BytePeer::new(&destination, 8, files);
    second.inner.replies[0]["request_high_water"] = json!(8);
    second.inner.replies[0]["result_retentions"] = json!([RESULT_RETENTION]);
    second.inner.replies[1]["resumed"] = json!(true);
    second.inner.replies[1]["result_retention"] = json!(RESULT_RETENTION);
    second.inner.replies[1]["retained_result_sha256"] = json!("ab".repeat(32));
    let request = second.request();
    let failure = receive_operation(
        &mut ArtifactCachePeer::new(&mut ResumePeer::new(&mut second, &source), &cache),
        &request,
        "worker",
        &destination,
        DeliveryMode::Resume,
    )
    .unwrap_err();
    assert!(failure.detail.contains("complete file digest"));
    assert!(second.ranges.is_empty());
    assert_eq!(
        fs::read(destination.join("artifacts/a")).unwrap(),
        b"bad! bytes"
    );
    second.assert_unreleased();
}

#[test]
fn a_current_failed_execution_keeps_its_diagnostics_without_prior_artifacts() {
    let owner = tempfile::tempdir().unwrap();
    let cache = cache(owner.path());
    let files = vec![Artifact::new("a", b"earlier successful artifact", true)];
    BytePeer::new(&owner.path().join("first"), 7, files.clone()).deliver(&cache);
    let mut second = BytePeer::new(&owner.path().join("failed"), 8, files);
    second.successful = false;
    second.inner.replies[1]["exit_code"] = json!(101);
    second.inner.replies[1]["artifact_manifest"] = Value::Null;
    second.inner.replies[1]["artifact_ack_required"] = json!(false);
    second.inner.replies.pop_back();
    let delivery = second.deliver(&cache);
    second.assert_complete();
    assert_eq!(delivery.receipt["exit_code"], 101);
    assert_eq!(delivery.receipt["artifact_manifest"], Value::Null);
    assert!(delivery.acknowledgments_confirmed);
    assert!(second.ranges.is_empty());
    assert!(
        !second
            .inner
            .sent
            .iter()
            .any(|frame| frame["kind"] == "artifact-ack")
    );
    assert_eq!(objects(&cache).len(), 1);
}

#[test]
fn linked_cache_objects_fall_back_without_touching_external_files() {
    for hard_link in [false, true] {
        let owner = tempfile::tempdir().unwrap();
        let cache = cache(owner.path());
        let bytes = b"private artifact bytes";
        let files = vec![Artifact::new("a", bytes, false)];
        BytePeer::new(&owner.path().join("first"), 7, files.clone()).deliver(&cache);
        let object = objects(&cache).pop().unwrap();
        let external = owner.path().join("outside-cache");
        if hard_link {
            fs::hard_link(&object, &external).unwrap();
        } else {
            fs::rename(&object, &external).unwrap();
            std::os::unix::fs::symlink(&external, &object).unwrap();
        }
        let external_before = fs::metadata(&external).unwrap();
        let mut second = BytePeer::new(&owner.path().join("second"), 8, files);
        second.deliver(&cache);
        second.assert_complete();
        assert_eq!(second.ranges, vec![("a".to_owned(), 0)]);
        assert_eq!(fs::read(&external).unwrap(), bytes);
        let external_after = fs::metadata(&external).unwrap();
        assert_eq!(external_after.ino(), external_before.ino());
        assert_eq!(
            external_after.permissions().mode(),
            external_before.permissions().mode()
        );
    }
}
