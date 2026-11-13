//! Real filesystem and owned-I/O-task recovery tests; no simulated cache hits.

#[path = "prefix_tests.rs"]
mod prefix_tests;

use super::*;
use rabs_sandbox::toolchain_dataset::capture_toolchain;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::task::Wake;
use std::time::Duration;

const REQUEST_ID: u64 = 71;

fn private() -> tempfile::TempDir {
    tempfile::Builder::new()
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap()
}

fn fixture(files: &[(&str, &[u8], bool)]) -> (tempfile::TempDir, PreparedToolchain) {
    let owner = private();
    let source = owner.path().join("source");
    fs::create_dir(&source).unwrap();
    for (path, bytes, executable) in files {
        let path = source.join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, bytes).unwrap();
        fs::set_permissions(
            &path,
            fs::Permissions::from_mode(if *executable { 0o700 } else { 0o600 }),
        )
        .unwrap();
    }
    let sdk = capture_toolchain(
        &source,
        &owner.path().join("retained"),
        None,
        &ToolchainLimits::default(),
        || false,
    )
    .unwrap();
    (owner, sdk)
}

fn identity(sdk: &PreparedToolchain) -> Value {
    let identity = sdk.identity();
    json!({"version":rabs_sandbox::toolchain_dataset::TOOLCHAIN_DATASET_VERSION,
        "sha256":hex(&identity.sha256), "files":identity.files, "bytes":identity.bytes})
}

fn request(sdk: &PreparedToolchain) -> Value {
    json!({"kind":"canonical-exec", "request_id":REQUEST_ID,
        "toolchain_transfer":TOOLCHAIN_TRANSFER_VERSION,
        "toolchain_identity":identity(sdk), "source_manifest":{"files":[]}})
}

fn operation(sdk: &PreparedToolchain, kind: &str) -> Value {
    json!({"kind":kind, "request_id":REQUEST_ID, "sha256":hex(&sdk.identity().sha256)})
}

struct ThreadWake(std::thread::Thread);
impl Wake for ThreadWake {
    fn wake(self: Arc<Self>) {
        self.0.unpark();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.0.unpark();
    }
}

fn exchange(task: &mut ToolchainTransferTask, frame: Value) -> Result<Value, String> {
    task.submit_owned(frame, true, false)?;
    let waker = Waker::from(Arc::new(ThreadWake(std::thread::current())));
    let mut context = Context::from_waker(&waker);
    let until = Instant::now() + Duration::from_secs(10);
    loop {
        if let Poll::Ready(reply) = task.poll_completion(&mut context) {
            return reply?.response;
        }
        assert!(
            Instant::now() < until,
            "toolchain filesystem operation did not finish"
        );
        std::thread::park_timeout(Duration::from_millis(5));
    }
}

fn begin(task: &mut ToolchainTransferTask, sdk: &PreparedToolchain) {
    let ready = exchange(
        task,
        json!({"kind":"toolchain-begin", "request_id":REQUEST_ID,
        "identity":identity(sdk), "entries":sdk.entries().unwrap().len()}),
    )
    .unwrap();
    assert_eq!(ready["sealed"], false);
    if let ToolchainBacking::Uploaded(upload) =
        &task.state.as_ref().unwrap().owner.as_ref().unwrap().backing
        && let Some(reuse) = &upload.file_reuse
    {
        assert!(
            reuse.snapshots.is_some(),
            "configured cache must own its private anonymous spool"
        );
    }
    assert!(task.prepared_path(&request(sdk), true).is_err());
}

fn file_record(file: &ToolchainFile) -> Value {
    json!({"path":file.path, "bytes":file.bytes, "executable":file.executable, "sha256":hex(&file.sha256)})
}

fn page(sdk: &PreparedToolchain, offset: usize, files: &[ToolchainFile]) -> Value {
    let mut frame = operation(sdk, "toolchain-file-manifest");
    frame["offset"] = json!(offset);
    frame["files"] = json!(files.iter().map(file_record).collect::<Vec<_>>());
    frame
}

fn negotiate(task: &mut ToolchainTransferTask, sdk: &PreparedToolchain) -> BTreeSet<String> {
    let files = sdk.files().unwrap();
    let mut missing = BTreeSet::new();
    // Multiple pages exercise the actual across-page cursor and snapshots.
    for (index, file) in files.iter().enumerate() {
        let accepted = exchange(task, page(sdk, index, std::slice::from_ref(file))).unwrap();
        assert_eq!(accepted["kind"], "toolchain-file-manifest-accepted");
        assert_eq!(accepted["next_offset"], index + 1);
        for path in accepted["missing"].as_array().unwrap() {
            assert!(missing.insert(path.as_str().unwrap().to_owned()));
        }
    }
    let ready = exchange(task, operation(sdk, "toolchain-file-manifest-seal")).unwrap();
    assert_eq!(ready["kind"], "toolchain-file-manifest-ready");
    assert_eq!(ready["files"], sdk.identity().files);
    assert_eq!(ready["bytes"], sdk.identity().bytes);
    assert!(task.prepared_path(&request(sdk), true).is_err());
    missing
}

fn entry_frame(sdk: &PreparedToolchain, entry: &ToolchainEntry) -> Value {
    let mut frame = operation(sdk, "toolchain-entry");
    frame["path"] = json!(entry.path);
    frame["entry"] = match &entry.kind {
        ToolchainEntryKind::Directory => json!({"kind":"directory"}),
        ToolchainEntryKind::Symlink { target } => json!({"kind":"symlink", "target":target}),
        ToolchainEntryKind::File { bytes, executable } => {
            json!({"kind":"file", "bytes":bytes, "executable":executable})
        }
    };
    frame
}

fn chunk_frame(sdk: &PreparedToolchain, path: &str, offset: u64, bytes: &[u8]) -> Value {
    let mut frame = operation(sdk, "toolchain-chunk");
    frame["path"] = json!(path);
    frame["offset"] = json!(offset);
    frame["data_hex"] = json!(hex(bytes));
    frame["chunk_sha256"] = json!(hex(&Sha256::digest(bytes)));
    frame
}

fn upload(
    task: &mut ToolchainTransferTask,
    sdk: &PreparedToolchain,
    missing: &BTreeSet<String>,
    stop_after: Option<&str>,
) -> u64 {
    let mut transmitted = 0;
    for entry in sdk.entries().unwrap() {
        let reply = exchange(task, entry_frame(sdk, &entry)).unwrap();
        assert_eq!(reply["kind"], "toolchain-entry-accepted");
        if let ToolchainEntryKind::File { bytes, .. } = entry.kind
            && missing.contains(&entry.path)
        {
            let mut offset = 0;
            while offset < bytes {
                let chunk = sdk
                    .read_chunk(&entry.path, offset, MAX_TOOLCHAIN_CHUNK, || false)
                    .unwrap();
                let reply = exchange(task, chunk_frame(sdk, &entry.path, offset, &chunk)).unwrap();
                offset += chunk.len() as u64;
                transmitted += chunk.len() as u64;
                assert_eq!(reply["next_offset"], offset);
            }
        }
        if stop_after == Some(entry.path.as_str()) {
            return transmitted;
        }
    }
    let ready = exchange(task, operation(sdk, "toolchain-seal")).unwrap();
    assert_eq!(ready["sealed"], true);
    assert!(task.prepared_path(&request(sdk), true).unwrap().is_some());
    transmitted
}

fn object(root: &Path, file: &ToolchainFile) -> std::path::PathBuf {
    root.join("toolchain-files-v1")
        .join(format!("{}.sdk", hex(&file.sha256)))
}

fn seed(root: &Path, sdk: &PreparedToolchain, budget: u64) {
    let cache = ToolchainFileCache::open(root, budget).unwrap();
    let mut task = ToolchainTransferTask::with_configuration(false, Some(cache));
    begin(&mut task, sdk);
    let missing = negotiate(&mut task, sdk);
    upload(&mut task, sdk, &missing, None);
}

#[test]
fn interrupted_sdk_reuses_only_completed_files_after_fresh_cache_and_task_open() {
    let (_sdk_owner, sdk) = fixture(&[
        ("bin/rustc", b"completed compiler", true),
        ("libstd", b"unfinished library body", false),
    ]);
    let root = private();
    let files = sdk.files().unwrap();
    let cache = ToolchainFileCache::open(root.path(), 1024).unwrap();
    let mut first = ToolchainTransferTask::with_configuration(false, Some(cache));
    begin(&mut first, &sdk);
    let missing = negotiate(&mut first, &sdk);
    assert_eq!(
        missing,
        BTreeSet::from(["bin/rustc".to_owned(), "libstd".to_owned()])
    );
    assert_eq!(
        upload(&mut first, &sdk, &missing, Some("bin/rustc")),
        files[0].bytes
    );
    let unfinished = sdk
        .entries()
        .unwrap()
        .into_iter()
        .find(|entry| entry.path == "libstd")
        .unwrap();
    exchange(&mut first, entry_frame(&sdk, &unfinished)).unwrap();
    exchange(&mut first, chunk_frame(&sdk, "libstd", 0, b"unfi")).unwrap();
    assert!(
        object(root.path(), &files[0]).is_file(),
        "checkpoint must precede complete SDK seal"
    );
    assert!(
        !object(root.path(), &files[1]).exists(),
        "partial files are never reusable"
    );
    assert!(first.prepared_path(&request(&sdk), true).is_err());
    drop(first);

    let reopened = ToolchainFileCache::open(root.path(), 1024).unwrap();
    let mut resumed = ToolchainTransferTask::with_configuration(false, Some(reopened));
    begin(&mut resumed, &sdk);
    let missing = negotiate(&mut resumed, &sdk);
    assert_eq!(missing, BTreeSet::from(["libstd".to_owned()]));
    assert_eq!(upload(&mut resumed, &sdk, &missing, None), files[1].bytes);
    let uploaded = resumed
        .prepared_path(&request(&sdk), true)
        .unwrap()
        .unwrap();
    let compiler = Path::new(&uploaded).join("bin/rustc");
    assert_eq!(fs::read(&compiler).unwrap(), b"completed compiler");
    assert_ne!(
        fs::metadata(&compiler).unwrap().ino(),
        fs::metadata(object(root.path(), &files[0])).unwrap().ino()
    );
    assert_eq!(fs::metadata(&compiler).unwrap().mode() & 0o777, 0o555);
}

#[test]
fn different_sdk_identity_and_executable_mode_reuse_unchanged_bytes_but_still_seal() {
    let root = private();
    let (_old_owner, old) = fixture(&[("a", b"same bytes", false), ("b", b"old SDK data", false)]);
    seed(root.path(), &old, 1024);
    let (_new_owner, new) = fixture(&[("a", b"same bytes", true), ("b", b"new SDK data", false)]);
    assert_ne!(old.identity(), new.identity());
    let mut task = ToolchainTransferTask::with_configuration(
        false,
        Some(ToolchainFileCache::open(root.path(), 1024).unwrap()),
    );
    begin(&mut task, &new);
    let missing = negotiate(&mut task, &new);
    assert_eq!(missing, BTreeSet::from(["b".to_owned()]));
    assert_eq!(
        upload(&mut task, &new, &missing, None),
        b"new SDK data".len() as u64
    );
    let root_path = task.prepared_path(&request(&new), true).unwrap().unwrap();
    assert_eq!(
        fs::metadata(Path::new(&root_path).join("a"))
            .unwrap()
            .mode()
            & 0o777,
        0o555
    );
    drop(task);

    let mut all_hits = ToolchainTransferTask::with_configuration(
        false,
        Some(ToolchainFileCache::open(root.path(), 1024).unwrap()),
    );
    begin(&mut all_hits, &new);
    let missing = negotiate(&mut all_hits, &new);
    assert!(missing.is_empty());
    assert!(all_hits.prepared_path(&request(&new), true).is_err());
    assert_eq!(upload(&mut all_hits, &new, &missing, None), 0);
}

fn corrupt(path: &Path, bytes: u64) {
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(path, vec![0xa5; bytes as usize]).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o400)).unwrap();
}

#[test]
fn corrupt_objects_refetch_and_advertised_hits_survive_later_cache_corruption() {
    let root = private();
    let (_owner, sdk) = fixture(&[
        ("a", b"first SDK file", false),
        ("b", b"second SDK file", false),
    ]);
    let files = sdk.files().unwrap();
    seed(root.path(), &sdk, 1024);
    corrupt(&object(root.path(), &files[0]), files[0].bytes);
    let mut task = ToolchainTransferTask::with_configuration(
        false,
        Some(ToolchainFileCache::open(root.path(), 1024).unwrap()),
    );
    begin(&mut task, &sdk);
    let missing = negotiate(&mut task, &sdk);
    assert_eq!(missing, BTreeSet::from(["a".to_owned()]));
    corrupt(&object(root.path(), &files[1]), files[1].bytes);
    assert_eq!(upload(&mut task, &sdk, &missing, None), files[0].bytes);
    let uploaded = task.prepared_path(&request(&sdk), true).unwrap().unwrap();
    assert_eq!(
        fs::read(Path::new(&uploaded).join("b")).unwrap(),
        b"second SDK file"
    );
    assert_ne!(
        fs::read(object(root.path(), &files[1])).unwrap(),
        b"second SDK file"
    );
}

#[test]
fn bounded_retention_protects_hits_and_newly_checkpointed_files_without_churning() {
    let root = private();
    let (_owner, sdk) = fixture(&[("a", b"aaaa", false), ("b", b"bbbb", false)]);
    let files = sdk.files().unwrap();
    seed(root.path(), &sdk, 4);
    assert_eq!(
        fs::metadata(object(root.path(), &files[0])).unwrap().len(),
        4
    );
    assert!(!object(root.path(), &files[1]).exists());
    let mut task = ToolchainTransferTask::with_configuration(
        false,
        Some(ToolchainFileCache::open(root.path(), 4).unwrap()),
    );
    begin(&mut task, &sdk);
    let missing = negotiate(&mut task, &sdk);
    assert_eq!(missing, BTreeSet::from(["b".to_owned()]));
    assert_eq!(upload(&mut task, &sdk, &missing, None), 4);
    assert!(object(root.path(), &files[0]).exists());
    assert!(!object(root.path(), &files[1]).exists());
    drop(task);
    let (_other_owner, other) = fixture(&[("c", b"cccc", false)]);
    seed(root.path(), &other, 4);
    assert!(!object(root.path(), &files[0]).exists());
    assert!(object(root.path(), &other.files().unwrap()[0]).exists());
    let bytes: u64 = fs::read_dir(root.path().join("toolchain-files-v1"))
        .unwrap()
        .map(|entry| entry.unwrap().metadata().unwrap().len())
        .sum();
    assert_eq!(bytes, 4);
}

#[test]
fn contended_writer_still_allows_verified_hits_and_complete_upload() {
    let root = private();
    let (_owner, sdk) = fixture(&[("a", b"cached", false), ("empty", b"", false)]);
    seed(root.path(), &sdk, 1024);
    let cache = ToolchainFileCache::open(root.path(), 1024).unwrap();
    let mut first = ToolchainTransferTask::with_configuration(false, Some(cache.clone()));
    begin(&mut first, &sdk);
    assert!(first.state.as_ref().unwrap().owner.as_ref().is_some());
    assert!(cache.writer(&|| false).unwrap().is_none());
    let mut second = ToolchainTransferTask::with_configuration(false, Some(cache.clone()));
    begin(&mut second, &sdk);
    let ToolchainBacking::Uploaded(uploaded) = &second
        .state
        .as_ref()
        .unwrap()
        .owner
        .as_ref()
        .unwrap()
        .backing
    else {
        panic!("new upload")
    };
    assert!(uploaded.file_reuse.as_ref().unwrap().writer.is_none());
    let missing = negotiate(&mut second, &sdk);
    assert!(missing.is_empty());
    assert_eq!(upload(&mut second, &sdk, &missing, None), 0);
    drop(first);
    assert!(cache.writer(&|| false).unwrap().is_some());
}

#[test]
fn incorrect_completed_file_digest_revokes_ack_and_never_creates_reusable_object() {
    let root = private();
    let (_owner, sdk) = fixture(&[("a", b"actual SDK file", false)]);
    let cache = ToolchainFileCache::open(root.path(), 1024).unwrap();
    let mut task = ToolchainTransferTask::with_configuration(false, Some(cache));
    begin(&mut task, &sdk);
    let mut files = sdk.files().unwrap();
    files[0].sha256 = [0x55; 32];
    exchange(&mut task, page(&sdk, 0, &files)).unwrap();
    exchange(&mut task, operation(&sdk, "toolchain-file-manifest-seal")).unwrap();
    for entry in sdk.entries().unwrap() {
        exchange(&mut task, entry_frame(&sdk, &entry)).unwrap();
    }
    let failure = exchange(&mut task, chunk_frame(&sdk, "a", 0, b"actual SDK file")).unwrap_err();
    assert!(
        failure.contains("generation") || failure.contains("bytes"),
        "{failure}"
    );
    assert!(!object(root.path(), &files[0]).exists());
    assert!(task.prepared_path(&request(&sdk), true).is_err());
    assert!(exchange(&mut task, operation(&sdk, "toolchain-seal")).is_err());
}

#[test]
fn failed_optional_checkpoint_destination_keeps_valid_sdk_upload_usable() {
    let root = private();
    let (_owner, sdk) = fixture(&[("a", b"valid SDK file", false)]);
    let cache = ToolchainFileCache::open(root.path(), 1024).unwrap();
    let mut task = ToolchainTransferTask::with_configuration(false, Some(cache));
    begin(&mut task, &sdk);
    let missing = negotiate(&mut task, &sdk);
    fs::create_dir(root.path().join("toolchain-files-v1/incoming")).unwrap();
    assert_eq!(
        upload(&mut task, &sdk, &missing, None),
        sdk.identity().bytes
    );
    assert!(
        root.path().join("toolchain-files-v1/incoming").is_dir(),
        "unknown state is not deleted"
    );
}

#[test]
fn malformed_pages_and_missing_file_declarations_fail_before_upload() {
    let root = private();
    let (_owner, sdk) = fixture(&[("a", b"a", false), ("b", b"b", false)]);
    let cache = ToolchainFileCache::open(root.path(), 1024).unwrap();
    let files = sdk.files().unwrap();
    let good = page(&sdk, 0, &files);
    let mut malformed = Vec::new();
    for path in [
        "../a".to_owned(),
        "/a".to_owned(),
        "a//x".to_owned(),
        "a\\x".to_owned(),
        "a:x".to_owned(),
        "a\n".to_owned(),
        "a\u{0085}".to_owned(),
        "x".repeat(256),
    ] {
        let mut frame = good.clone();
        frame["files"][0]["path"] = json!(path);
        malformed.push(frame);
    }
    let mut wrong_offset = good.clone();
    wrong_offset["offset"] = json!(1);
    malformed.push(wrong_offset);
    let mut duplicate = good.clone();
    duplicate["files"][1] = duplicate["files"][0].clone();
    malformed.push(duplicate);
    let mut unordered = good.clone();
    unordered["files"].as_array_mut().unwrap().reverse();
    malformed.push(unordered);
    let mut count = good.clone();
    count["files"] = json!(vec![
        file_record(&files[0]);
        MAX_TOOLCHAIN_FILE_PAGE_ENTRIES + 1
    ]);
    malformed.push(count);
    let mut bytes = good.clone();
    bytes["files"][0]["path"] = json!("x".repeat(MAX_TOOLCHAIN_FILE_PAGE_BYTES));
    malformed.push(bytes);
    for frame in malformed {
        let mut task = ToolchainTransferTask::with_configuration(false, Some(cache.clone()));
        begin(&mut task, &sdk);
        assert!(exchange(&mut task, frame).is_err());
        assert!(task.prepared_path(&request(&sdk), true).is_err());
    }
    let mut incomplete = ToolchainTransferTask::with_configuration(false, Some(cache.clone()));
    begin(&mut incomplete, &sdk);
    exchange(&mut incomplete, page(&sdk, 0, &files[..1])).unwrap();
    assert!(
        exchange(
            &mut incomplete,
            operation(&sdk, "toolchain-file-manifest-seal")
        )
        .is_err()
    );
    drop(incomplete);
    let mut premature = ToolchainTransferTask::with_configuration(false, Some(cache));
    begin(&mut premature, &sdk);
    assert!(
        exchange(
            &mut premature,
            entry_frame(&sdk, &sdk.entries().unwrap()[0])
        )
        .is_err()
    );
}

#[test]
fn unnegotiated_file_manifests_and_expired_or_cancelled_uploads_are_refused() {
    let root = private();
    let (_owner, sdk) = fixture(&[("a", b"data", false)]);
    let mut old_protocol = ToolchainTransferTask::default();
    begin(&mut old_protocol, &sdk);
    assert!(
        exchange(&mut old_protocol, page(&sdk, 0, &sdk.files().unwrap()))
            .unwrap_err()
            .contains("not negotiated")
    );
    let cache = ToolchainFileCache::open(root.path(), 1024).unwrap();
    let mut expired = ToolchainTransferTask::with_configuration(false, Some(cache.clone()));
    begin(&mut expired, &sdk);
    expired
        .state
        .as_mut()
        .unwrap()
        .owner
        .as_mut()
        .unwrap()
        .deadline = Instant::now() - Duration::from_secs(1);
    assert!(
        exchange(&mut expired, page(&sdk, 0, &sdk.files().unwrap()))
            .unwrap_err()
            .contains("deadline")
    );
    let mut cancelled = ToolchainTransferTask::with_configuration(false, Some(cache));
    begin(&mut cancelled, &sdk);
    cancelled.cancelled.store(true, Ordering::Release);
    assert!(
        exchange(&mut cancelled, page(&sdk, 0, &sdk.files().unwrap()))
            .unwrap_err()
            .contains("cancelled")
    );
    assert!(cancelled.prepared_path(&request(&sdk), true).is_err());
}

#[test]
fn io_task_panic_releases_writer_and_completed_checkpoint_remains_verifiable() {
    let root = private();
    let (_owner, sdk) = fixture(&[("a", b"checkpoint before panic", false)]);
    let cache = ToolchainFileCache::open(root.path(), 1024).unwrap();
    let mut task = ToolchainTransferTask::with_configuration(false, Some(cache.clone()));
    task.start_worker(|state, frame, cancelled| {
        let response = state.handle(frame, cancelled);
        if frame["kind"] == "toolchain-chunk" && response.is_ok() {
            panic!("injected failure after completed checkpoint");
        }
        response
    })
    .unwrap();
    begin(&mut task, &sdk);
    negotiate(&mut task, &sdk);
    for entry in sdk.entries().unwrap() {
        exchange(&mut task, entry_frame(&sdk, &entry)).unwrap();
    }
    assert!(
        exchange(
            &mut task,
            chunk_frame(&sdk, "a", 0, b"checkpoint before panic")
        )
        .unwrap_err()
        .contains("panicked")
    );
    assert!(cache.writer(&|| false).unwrap().is_some());
    drop(task);
    let mut resumed = ToolchainTransferTask::with_configuration(false, Some(cache));
    begin(&mut resumed, &sdk);
    let missing = negotiate(&mut resumed, &sdk);
    assert!(missing.is_empty());
    assert_eq!(upload(&mut resumed, &sdk, &missing, None), 0);
}

#[test]
fn private_cache_storage_cannot_alias_writable_runtime_roots() {
    let root = private();
    let cache = ToolchainFileCache::open(root.path(), 1024).unwrap();
    let runtime = private();
    cache.validate_runtime_root(runtime.path()).unwrap();
    cache
        .validate_runtime_root(&runtime.path().join("new"))
        .unwrap();
    assert!(cache.validate_runtime_root(root.path()).is_err());
    assert!(
        cache
            .validate_runtime_root(&root.path().join("toolchain-files-v1/new"))
            .is_err()
    );
    let alias = runtime.path().join("cache-alias");
    symlink(root.path().join("toolchain-files-v1"), &alias).unwrap();
    assert!(cache.validate_runtime_root(&alias).is_err());
}

#[test]
fn directory_only_sdk_uses_empty_manifest_then_the_complete_normal_seal() {
    let root = private();
    let (_owner, sdk) = fixture(&[]);
    assert_eq!(sdk.identity().files, 0);
    let mut task = ToolchainTransferTask::with_configuration(
        false,
        Some(ToolchainFileCache::open(root.path(), 1024).unwrap()),
    );
    begin(&mut task, &sdk);
    let missing = negotiate(&mut task, &sdk);
    assert!(missing.is_empty());
    assert_eq!(upload(&mut task, &sdk, &missing, None), 0);
}
