//! Filesystem evidence for incomplete input retention. Every positive prefix is
//! first accepted by the real SourceReceiver; cache ownership, reopening and
//! replacement are exercised with actual files rather than saved cursors.

use super::*;
use std::os::unix::fs::{MetadataExt, PermissionsExt};

fn private() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("rabs-source-prefix-")
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap()
}

fn expected(path: &str, bytes: &[u8]) -> SourceFile {
    SourceFile {
        path: path.to_owned(),
        len: bytes.len() as u64,
        sha256: Sha256::digest(bytes).into(),
        executable: false,
    }
}

fn empty() -> SourcePrefix {
    SourcePrefix {
        offset: 0,
        sha256: Sha256::digest([]).into(),
    }
}

fn receiver(parent: &Path, manifest: &SourceManifest) -> SourceReceiver {
    SourceReceiver::create(&parent.join("workspace"), manifest.clone()).unwrap()
}

fn accept(
    receiver: &mut SourceReceiver,
    checkpoints: &mut SourceCheckpoints,
    path: &str,
    offset: u64,
    bytes: &[u8],
) {
    receiver
        .write_chunk(path, offset, bytes, Sha256::digest(bytes).into())
        .unwrap();
    checkpoints.append_prefix(path, offset, bytes).unwrap();
}

fn retain_prefix(cache: &SourceCache, receiver: &mut SourceReceiver, path: &str, bytes: &[u8]) {
    let mut checkpoints = cache.checkpoints(receiver.manifest()).unwrap().unwrap();
    checkpoints
        .begin_prefix(receiver, path, empty(), |_, _| {
            panic!("an empty selection has no seed bytes")
        })
        .unwrap();
    for (index, chunk) in bytes.chunks(MAX_SOURCE_CHUNK).enumerate() {
        accept(
            receiver,
            &mut checkpoints,
            path,
            (index * MAX_SOURCE_CHUNK) as u64,
            chunk,
        );
    }
    // Deliberately drop an unfinished writer, as on a session disconnect.
}

#[test]
fn retained_prefix_survives_new_cache_and_session_and_finishes_exact_source() {
    let parent = private();
    let first_input = private();
    let bytes: Vec<_> = (0..MAX_SOURCE_CHUNK * 4 + 37)
        .map(|index| (index % 251) as u8)
        .collect();
    let file = expected("dependencies/lib.rlib", &bytes);
    let manifest = SourceManifest::new(vec![file.clone()]).unwrap();
    let offset = MAX_SOURCE_CHUNK + 19;
    let cache = SourceCache::open_byte_only(parent.path(), bytes.len() as u64 * 2).unwrap();
    let mut first = receiver(first_input.path(), &manifest);
    retain_prefix(&cache, &mut first, &file.path, &bytes[..offset]);
    assert!(first.sealed_root().is_none());
    assert!(
        cache.load(&file).is_none(),
        "a prefix is never a complete-file hit"
    );
    let cached = cache.object_path(&file.sha256);
    assert_eq!(fs::read(&cached).unwrap(), bytes[..offset]);
    assert_eq!(fs::metadata(&cached).unwrap().mode() & 0o222, 0);
    drop(cache);
    drop(first);

    let reopened = SourceCache::open_byte_only(parent.path(), bytes.len() as u64 * 2).unwrap();
    let mut snapshots = SourcePrefixSnapshots::new(reopened.clone(), &manifest).unwrap();
    let offer = snapshots.capture(&file).unwrap().unwrap();
    assert_eq!(offer.offset, offset as u64);
    assert_eq!(
        offer.sha256,
        <[u8; 32]>::from(Sha256::digest(&bytes[..offset]))
    );
    assert!(snapshots.read_chunk(&file.path, 0, 1).is_err());
    snapshots.seal().unwrap();
    assert_eq!(snapshots.spool.metadata().unwrap().nlink(), 0);
    assert_eq!(snapshots.spool.metadata().unwrap().mode() & 0o222, 0);
    assert!(snapshots.capture(&file).is_err());

    // A later change to the optional cache object cannot alter already frozen
    // snapshot bytes. The next checkpoint replaces that changed generation.
    fs::set_permissions(&cached, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&cached, b"changed cache bytes").unwrap();
    let second_input = private();
    let mut second = receiver(second_input.path(), &manifest);
    let mut copied = 0;
    while copied < offer.offset {
        let chunk = snapshots
            .read_chunk(&file.path, copied, MAX_SOURCE_CHUNK)
            .unwrap();
        second
            .write_chunk(&file.path, copied, &chunk, Sha256::digest(&chunk).into())
            .unwrap();
        copied += chunk.len() as u64;
    }
    let mut checkpoints = reopened.checkpoints(&manifest).unwrap().unwrap();
    checkpoints
        .begin_prefix(&second, &file.path, offer, |offset, count| {
            snapshots.read_chunk(&file.path, offset, count)
        })
        .unwrap();
    for (index, chunk) in bytes[offset..].chunks(MAX_SOURCE_CHUNK).enumerate() {
        accept(
            &mut second,
            &mut checkpoints,
            &file.path,
            (offset + index * MAX_SOURCE_CHUNK) as u64,
            chunk,
        );
    }
    checkpoints.remember_file(&mut second, &file.path).unwrap();
    second.seal().unwrap();
    let source = second.sealed_root().unwrap().join(&file.path);
    assert_eq!(fs::read(&source).unwrap(), bytes);
    assert_eq!(reopened.load(&file).unwrap().bytes(), bytes);
    assert_ne!(
        fs::metadata(&source).unwrap().ino(),
        fs::metadata(&cached).unwrap().ino()
    );
}

#[test]
fn cancelled_seed_copy_preserves_the_previous_published_generation() {
    let parent = private();
    let input = private();
    let bytes = vec![0x7b; MAX_SOURCE_CHUNK * 4 + 31];
    let file = expected("input.rs", &bytes);
    let manifest = SourceManifest::new(vec![file.clone()]).unwrap();
    let cache = SourceCache::open_byte_only(parent.path(), bytes.len() as u64 * 2).unwrap();
    let mut first = receiver(input.path(), &manifest);
    let old_length = MAX_SOURCE_CHUNK + 13;
    retain_prefix(&cache, &mut first, &file.path, &bytes[..old_length]);
    let path = cache.object_path(&file.sha256);
    let original = fs::metadata(&path).unwrap();

    let cancelled = Arc::new(AtomicBool::new(false));
    let stopped = cache.clone().with_cancellation(Arc::clone(&cancelled));
    let mut checkpoints = stopped.checkpoints(&manifest).unwrap().unwrap();
    let mut reads = 0;
    let result = checkpoints.begin_prefix(
        &first,
        &file.path,
        SourcePrefix {
            offset: old_length as u64,
            sha256: Sha256::digest(&bytes[..old_length]).into(),
        },
        |offset, count| {
            reads += 1;
            cancelled.store(true, Ordering::Release);
            Ok(bytes[offset as usize..offset as usize + count].to_vec())
        },
    );
    assert!(
        matches!(result, Err(RememberError::Cache(error)) if error.kind() == io::ErrorKind::Interrupted)
    );
    assert_eq!(reads, 1);
    assert!(same_state(&original, &fs::metadata(&path).unwrap()));
    assert_eq!(fs::read(&path).unwrap(), bytes[..old_length]);
    assert_eq!(
        fs::metadata(cache.root.join(INCOMING)).unwrap().len(),
        MAX_SOURCE_CHUNK as u64
    );
    drop(checkpoints);

    // A new owner cleans only the incomplete scratch object; the old published
    // prefix remains available and cancellation does not infect this session.
    let next = cache.checkpoints(&manifest).unwrap().unwrap();
    assert!(!cache.root.join(INCOMING).exists());
    assert!(same_state(&original, &fs::metadata(&path).unwrap()));
    drop(next);
    let mut snapshots = SourcePrefixSnapshots::new(cache, &manifest).unwrap();
    assert_eq!(
        snapshots.capture(&file).unwrap().unwrap().offset,
        old_length as u64
    );
}

#[test]
fn destination_replacement_during_seed_copy_is_not_overwritten() {
    let parent = private();
    let input = private();
    let bytes = b"original selected input bytes";
    let file = expected("input.rs", bytes);
    let manifest = SourceManifest::new(vec![file.clone()]).unwrap();
    let cache = SourceCache::open_byte_only(parent.path(), 128).unwrap();
    let mut source = receiver(input.path(), &manifest);
    retain_prefix(&cache, &mut source, &file.path, &bytes[..12]);
    let path = cache.object_path(&file.sha256);
    let replacement = parent.path().join("replacement-fixture");
    fs::write(&replacement, b"external replacement").unwrap();
    let replacement_identity = fs::metadata(&replacement).unwrap();
    let mut checkpoints = cache.checkpoints(&manifest).unwrap().unwrap();
    let result = checkpoints.begin_prefix(
        &source,
        &file.path,
        SourcePrefix {
            offset: 12,
            sha256: Sha256::digest(&bytes[..12]).into(),
        },
        |offset, count| {
            fs::rename(&replacement, &path)?;
            Ok(bytes[offset as usize..offset as usize + count].to_vec())
        },
    );
    assert!(matches!(result, Err(RememberError::Cache(_))));
    assert_eq!(
        fs::metadata(&path).unwrap().ino(),
        replacement_identity.ino()
    );
    assert_eq!(fs::read(&path).unwrap(), b"external replacement");
}

#[test]
fn quota_stops_prefix_growth_and_spool_bounds_duplicate_aliases() {
    let parent = private();
    let input = private();
    let bytes = b"abcdefghijkl";
    let file = expected("a", bytes);
    let manifest = SourceManifest::new(vec![file.clone()]).unwrap();
    let mut cache = SourceCache::open_byte_only(parent.path(), 8).unwrap();
    cache.max_files = 1;
    let mut source = receiver(input.path(), &manifest);
    let mut checkpoints = cache.checkpoints(&manifest).unwrap().unwrap();
    checkpoints
        .begin_prefix(&source, "a", empty(), |_, _| unreachable!())
        .unwrap();
    accept(&mut source, &mut checkpoints, "a", 0, &bytes[..4]);
    accept(&mut source, &mut checkpoints, "a", 4, &bytes[4..10]);
    assert!(!checkpoints.active_prefix.as_ref().unwrap().writable);
    accept(&mut source, &mut checkpoints, "a", 10, &bytes[10..]);
    checkpoints.remember_file(&mut source, "a").unwrap();
    source.seal().unwrap();
    assert_eq!(checkpoints.total, 4);
    assert_eq!(checkpoints.entries.len(), 1);
    assert_eq!(
        fs::read(cache.object_path(&file.sha256)).unwrap(),
        &bytes[..4]
    );
    drop(checkpoints);

    let aliases =
        SourceManifest::new(["a", "b", "c"].map(|path| expected(path, bytes)).into()).unwrap();
    let mut snapshots = SourcePrefixSnapshots::new(cache.clone(), &aliases).unwrap();
    assert_eq!(snapshots.max_bytes, 8);
    for file in &aliases.files()[..2] {
        assert_eq!(snapshots.capture(file).unwrap().unwrap().offset, 4);
    }
    assert!(snapshots.capture(&aliases.files()[2]).unwrap().is_none());
    assert_eq!(snapshots.bytes, 8);
    assert_eq!(snapshots.ranges.len(), 2);
    assert_eq!(snapshots.spool.metadata().unwrap().len(), 8);
    snapshots.seal().unwrap();
    assert_eq!(
        snapshots.read_chunk("b", 0, MAX_SOURCE_CHUNK).unwrap(),
        &bytes[..4]
    );
    assert!(snapshots.read_chunk("c", 0, 1).is_err());
    assert!(snapshots.read_chunk("a", 4, 1).is_err());
    assert!(snapshots.read_chunk("a", 0, MAX_SOURCE_CHUNK + 1).is_err());

    let other_input = private();
    let other_file = expected("other", b"different source bytes");
    let other_manifest = SourceManifest::new(vec![other_file.clone()]).unwrap();
    let mut other_source = receiver(other_input.path(), &other_manifest);
    retain_prefix(&cache, &mut other_source, "other", b"diff");
    assert!(!cache.object_path(&file.sha256).exists());
    assert_eq!(
        fs::read(cache.object_path(&other_file.sha256)).unwrap(),
        b"diff"
    );
    // Evicting the underlying cache object does not invalidate the frozen spool.
    assert_eq!(snapshots.read_chunk("a", 0, 4).unwrap(), b"abcd");
}

#[test]
fn separate_busy_writer_skips_checkpoint_but_allows_frozen_prefix_reads() {
    let parent = private();
    let input = private();
    let file = expected("input.rs", b"abcdefgh");
    let manifest = SourceManifest::new(vec![file.clone()]).unwrap();
    let first = SourceCache::open_byte_only(parent.path(), 128).unwrap();
    let second = SourceCache::open_byte_only(parent.path(), 128).unwrap();
    let mut source = receiver(input.path(), &manifest);
    let mut checkpoints = first.checkpoints(&manifest).unwrap().unwrap();
    checkpoints
        .begin_prefix(&source, &file.path, empty(), |_, _| unreachable!())
        .unwrap();
    accept(&mut source, &mut checkpoints, &file.path, 0, b"abcd");
    assert!(second.checkpoints(&manifest).unwrap().is_none());
    let mut snapshots = SourcePrefixSnapshots::new(second.clone(), &manifest).unwrap();
    assert_eq!(snapshots.capture(&file).unwrap().unwrap().offset, 4);
    snapshots.seal().unwrap();
    assert_eq!(snapshots.read_chunk(&file.path, 0, 4).unwrap(), b"abcd");
    drop(checkpoints);
    assert!(second.checkpoints(&manifest).unwrap().is_some());
}

#[test]
fn corrupt_completed_source_is_strict_failure_and_preserves_old_cache_prefix() {
    let parent = private();
    let input = private();
    let bytes = b"authenticated source body";
    let file = expected("input.rs", bytes);
    let manifest = SourceManifest::new(vec![file.clone()]).unwrap();
    let cache = SourceCache::open_byte_only(parent.path(), 128).unwrap();
    let mut source = receiver(input.path(), &manifest);
    retain_prefix(&cache, &mut source, &file.path, &bytes[..7]);
    source
        .write_chunk(
            &file.path,
            7,
            &bytes[7..],
            Sha256::digest(&bytes[7..]).into(),
        )
        .unwrap();
    let path = cache.object_path(&file.sha256);
    let original = fs::metadata(&path).unwrap();
    let mut checkpoints = cache.checkpoints(&manifest).unwrap().unwrap();
    fs::write(
        input.path().join("workspace").join(&file.path),
        vec![b'x'; bytes.len()],
    )
    .unwrap();
    assert!(matches!(
        checkpoints.remember_file(&mut source, &file.path),
        Err(RememberError::Source(_))
    ));
    assert!(
        source.seal().is_err(),
        "changed source cannot become execution custody"
    );
    assert!(source.sealed_root().is_none());
    assert!(same_state(&original, &fs::metadata(&path).unwrap()));
    assert_eq!(fs::read(&path).unwrap(), &bytes[..7]);
}

#[test]
fn frozen_spool_mutation_and_cancelled_reads_are_refused() {
    let parent = private();
    let input = private();
    let file = expected("input.rs", b"abcdefgh");
    let manifest = SourceManifest::new(vec![file.clone()]).unwrap();
    let cache = SourceCache::open_byte_only(parent.path(), 128).unwrap();
    let mut source = receiver(input.path(), &manifest);
    retain_prefix(&cache, &mut source, &file.path, b"abcd");
    let cancelled = Arc::new(AtomicBool::new(false));
    let mut snapshots =
        SourcePrefixSnapshots::new(cache.with_cancellation(Arc::clone(&cancelled)), &manifest)
            .unwrap();
    snapshots.capture(&file).unwrap().unwrap();
    snapshots.seal().unwrap();
    cancelled.store(true, Ordering::Release);
    assert_eq!(
        snapshots.read_chunk(&file.path, 0, 4).unwrap_err().kind(),
        io::ErrorKind::Interrupted
    );
    cancelled.store(false, Ordering::Release);
    snapshots.spool.set_len(1).unwrap();
    assert!(snapshots.read_chunk(&file.path, 0, 1).is_err());
}
