use super::*;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::sync::atomic::AtomicUsize;
use std::sync::{Barrier, mpsc};

fn private() -> tempfile::TempDir {
    let directory = tempfile::tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    directory
}

fn staged(files: &[(&str, &[u8], bool)]) -> (tempfile::TempDir, SourceReceiver) {
    let directory = private();
    let manifest = SourceManifest::new(
        files
            .iter()
            .map(|(path, bytes, executable)| SourceFile {
                path: (*path).to_owned(),
                len: bytes.len() as u64,
                sha256: Sha256::digest(bytes).into(),
                executable: *executable,
            })
            .collect(),
    )
    .unwrap();
    let mut receiver = SourceReceiver::create(&directory.path().join("bundle"), manifest).unwrap();
    for (path, bytes, _) in files {
        for (index, chunk) in bytes.chunks(MAX_SOURCE_CHUNK).enumerate() {
            receiver
                .write_chunk(
                    path,
                    (index * MAX_SOURCE_CHUNK) as u64,
                    chunk,
                    Sha256::digest(chunk).into(),
                )
                .unwrap();
        }
    }
    receiver.seal().unwrap();
    (directory, receiver)
}

fn acquire(pool: &SourceProjectionPool, source: &SourceReceiver) -> SourceProjectionLease {
    pool.acquire(source, "package/", &[], || false)
        .unwrap()
        .unwrap()
}

#[test]
fn warm_projection_reuses_owned_inodes_across_different_transport_manifests() {
    let parent = private();
    let pool = SourceProjectionPool::new(parent.path(), 1024, 4, 64).unwrap();
    let (first_directory, first_source) = staged(&[
        ("package/lib.rs", b"source", false),
        ("package/generate", b"script", true),
        ("dependencies/0000/libone.rmeta", b"artifact one", false),
    ]);
    let (_second_directory, second_source) = staged(&[
        ("package/lib.rs", b"source", false),
        ("package/generate", b"script", true),
        (
            "dependencies/0000/libtwo.rmeta",
            b"different artifact",
            false,
        ),
    ]);
    let directories = vec!["empty".into(), "empty/child".into()];
    assert_ne!(
        first_source.manifest().digest(),
        second_source.manifest().digest()
    );
    let first = pool
        .acquire(&first_source, "package/", &directories, || false)
        .unwrap()
        .unwrap();
    let file = first.root().join("lib.rs");
    let original =
        fs::metadata(first_source.sealed_root().unwrap().join("package/lib.rs")).unwrap();
    let retained = fs::metadata(&file).unwrap();
    assert_ne!(
        (original.dev(), original.ino()),
        (retained.dev(), retained.ino())
    );
    assert_eq!(retained.nlink(), 1);
    assert_eq!(retained.mode() & 0o777, 0o444);
    assert_eq!(
        fs::metadata(first.root().join("generate")).unwrap().mode() & 0o777,
        0o555
    );
    assert!(first.root().join("empty/child").is_dir());
    assert!(!first.root().join("dependencies").exists());
    drop(first_source);
    drop(first_directory);
    let second = pool
        .acquire(&second_source, "package/", &directories, || false)
        .unwrap()
        .unwrap();
    assert!(Arc::ptr_eq(&first.0, &second.0));
    assert_eq!(retained.ino(), fs::metadata(&file).unwrap().ino());
    assert_eq!(lock(&pool.quota.used).unwrap().images, 1);
    drop(pool);
    drop(first);
    second.verify(|| false).unwrap();
    assert_eq!(fs::read(&file).unwrap(), b"source");
    drop(second);
    assert!(!file.exists());
}

#[test]
fn corrupted_live_generation_is_rebuilt_without_refunding_its_lease() {
    let parent = private();
    let pool = SourceProjectionPool::new(parent.path(), 16, 2, 16).unwrap();
    let (_directory, source) = staged(&[("package/lib.rs", b"good", false)]);
    let old = acquire(&pool, &source);
    let path = old.root().join("lib.rs");
    let original = fs::metadata(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&path, b"evil").unwrap();
    File::open(&path)
        .unwrap()
        .set_times(fs::FileTimes::new().set_modified(original.modified().unwrap()))
        .unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o444)).unwrap();
    assert!(old.verify(|| false).is_err());
    let repaired = acquire(&pool, &source);
    assert_ne!(old.root(), repaired.root());
    assert_eq!(fs::read(repaired.root().join("lib.rs")).unwrap(), b"good");
    assert_eq!(lock(&pool.quota.used).unwrap().bytes, 8);
    let (_next_directory, next) = staged(&[("package/lib.rs", b"newbytes", false)]);
    assert!(
        pool.acquire(&next, "package/", &[], || false)
            .unwrap()
            .is_none()
    );
    drop(old);
    assert_eq!(lock(&pool.quota.used).unwrap().images, 1);
    acquire(&pool, &next).verify(|| false).unwrap();
    repaired.verify(|| false).unwrap();
}

#[test]
fn active_leases_prevent_eviction_but_idle_images_return_all_capacity() {
    let parent = private();
    let pool = SourceProjectionPool::new(parent.path(), 4, 1, 3).unwrap();
    let (_a_directory, a) = staged(&[("package/a", b"aaaa", false)]);
    let (_b_directory, b) = staged(&[("package/b", b"bbbb", false)]);
    let lease = acquire(&pool, &a);
    let path = lease.root().to_path_buf();
    assert!(
        pool.acquire(&b, "package/", &[], || false)
            .unwrap()
            .is_none()
    );
    assert!(path.join("a").is_file());
    drop(lease);
    let replacement = acquire(&pool, &b);
    assert!(!path.exists());
    assert_eq!(fs::read(replacement.root().join("b")).unwrap(), b"bbbb");
    let used = lock(&pool.quota.used).unwrap();
    assert_eq!((used.bytes, used.images, used.members), (4, 1, 3));
}

#[test]
fn independent_callers_coalesce_one_actual_capture() {
    let parent = private();
    let pool = SourceProjectionPool::new(parent.path(), 1024, 4, 64).unwrap();
    let (_directory, source) = staged(&[("package/lib.rs", b"shared", false)]);
    let start = Barrier::new(4);
    let leases = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..4)
            .map(|_| {
                scope.spawn(|| {
                    start.wait();
                    acquire(&pool, &source)
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert!(
        leases
            .iter()
            .all(|lease| Arc::ptr_eq(&lease.0, &leases[0].0))
    );
    assert_eq!(lock(&pool.quota.used).unwrap().images, 1);
}

#[test]
fn pending_capture_is_charged_and_a_cancelled_waiter_cannot_cancel_it() {
    let parent = private();
    let pool = SourceProjectionPool::new(parent.path(), 4, 1, 3).unwrap();
    let (_directory, source) = staged(&[
        ("package/a", b"aaaa", false),
        ("generated/b", b"bbbb", false),
    ]);
    let (started_tx, started_rx) = mpsc::sync_channel(1);
    let (resume_tx, resume_rx) = mpsc::sync_channel(1);
    std::thread::scope(|scope| {
        let pool_ref = &pool;
        let source_ref = &source;
        let capture = scope.spawn(move || {
            let paused = AtomicBool::new(false);
            pool_ref
                .acquire(source_ref, "package/", &[], || {
                    if lock(&pool_ref.quota.used).unwrap().images == 1
                        && !paused.swap(true, Ordering::AcqRel)
                    {
                        started_tx.send(()).unwrap();
                        resume_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                    }
                    false
                })
                .unwrap()
                .unwrap()
        });
        started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(lock(&pool.quota.used).unwrap().bytes, 4);
        assert!(
            pool.acquire(&source, "generated/", &[], || false)
                .unwrap()
                .is_none()
        );
        let checks = AtomicUsize::new(0);
        let error = pool
            .acquire(&source, "package/", &[], || {
                checks.fetch_add(1, Ordering::AcqRel) != 0
            })
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
        assert_eq!(lock(&pool.quota.used).unwrap().images, 1);
        resume_tx.send(()).unwrap();
        capture.join().unwrap().verify(|| false).unwrap();
    });
}

#[test]
fn replaced_image_is_not_removed_by_its_owner_or_final_pool_cleanup() {
    let parent = private();
    let pool = SourceProjectionPool::new(parent.path(), 4, 1, 3).unwrap();
    let (_directory, source) = staged(&[("package/lib.rs", b"good", false)]);
    let lease = acquire(&pool, &source);
    let container = lease.root().parent().unwrap().to_path_buf();
    let moved = pool.parent.path.join("moved-original");
    fs::rename(&container, &moved).unwrap();
    fs::create_dir(&container).unwrap();
    fs::set_permissions(&container, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(container.join("foreign"), b"keep me").unwrap();
    assert!(lease.verify(|| false).is_err());
    assert!(
        pool.acquire(&source, "package/", &[], || false)
            .unwrap()
            .is_none()
    );
    drop(lease);
    assert_eq!(lock(&pool.quota.used).unwrap().images, 1);
    drop(pool);
    assert_eq!(fs::read(container.join("foreign")).unwrap(), b"keep me");
    assert_eq!(fs::read(moved.join("package/lib.rs")).unwrap(), b"good");
}

#[test]
fn exact_modes_paths_bytes_and_empty_directories_select_distinct_images() {
    let parent = private();
    let pool = SourceProjectionPool::new(parent.path(), 1024, 8, 64).unwrap();
    let (_directory, original) = staged(&[("package/a", b"same", false)]);
    let first = acquire(&pool, &original);
    let mut leases = vec![first];
    for (path, bytes, mode, directories) in [
        ("package/a", b"next".as_slice(), false, vec![]),
        ("package/b", b"same".as_slice(), false, vec![]),
        ("package/a", b"same".as_slice(), true, vec![]),
        ("package/a", b"same".as_slice(), false, vec!["empty".into()]),
    ] {
        let (_directory, changed) = staged(&[(path, bytes, mode)]);
        let lease = pool
            .acquire(&changed, "package/", &directories, || false)
            .unwrap()
            .unwrap();
        assert!(leases.iter().all(|other| other.root() != lease.root()));
        assert!(
            !leases[0]
                .matches(&changed, "package/", &directories)
                .unwrap()
        );
        leases.push(lease);
    }
    let empty = pool
        .acquire(&original, "generated/", &["empty".into()], || false)
        .unwrap()
        .unwrap();
    assert_eq!(empty.file_count(), 0);
    assert!(empty.root().join("empty").is_dir());
    let unsealed_parent = private();
    let unsealed = SourceReceiver::create(
        &unsealed_parent.path().join("unsealed"),
        original.manifest().clone(),
    )
    .unwrap();
    assert!(pool.acquire(&unsealed, "package/", &[], || false).is_err());
    assert!(
        pool.acquire(&original, "../package/", &[], || false)
            .is_err()
    );
    assert!(
        pool.acquire(&original, "package/", &["missing/parent".into()], || false)
            .is_err()
    );
    assert!(
        pool.acquire(&original, "package/", &["a".into()], || false)
            .is_err()
    );
    assert_eq!(lock(&pool.quota.used).unwrap().images, 6);
}

#[test]
fn cancellation_during_copy_releases_only_its_pending_image() {
    let parent = private();
    let pool = SourceProjectionPool::new(parent.path(), 1024 * 1024, 2, 16).unwrap();
    let (_old_directory, old_source) = staged(&[("package/old", b"old", false)]);
    let old = acquire(&pool, &old_source);
    let bytes = vec![7_u8; MAX_SOURCE_CHUNK * 3];
    let (_new_directory, new_source) = staged(&[("package/new", &bytes, false)]);
    let checks = AtomicUsize::new(0);
    let error = pool
        .acquire(&new_source, "package/", &[], || {
            lock(&pool.quota.used).unwrap().images == 2
                && checks.fetch_add(1, Ordering::AcqRel) >= 3
        })
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::Interrupted);
    assert_eq!(lock(&pool.quota.used).unwrap().images, 1);
    assert_eq!(lock(&pool.quota.used).unwrap().bytes, 3);
    old.verify(|| false).unwrap();
    let next = acquire(&pool, &new_source);
    assert_eq!(fs::read(next.root().join("new")).unwrap(), bytes);
    old.verify(|| false).unwrap();
}
