//! Real filesystem, dataset verifier and pool tests. Reopening models restart;
//! these fixtures are not power-loss, TLS, compiler-execution or speedup proof.
use super::*;
use super::super::ToolchainPool;
use rabs_sandbox::canonical_namespace::{Bind, CanonicalNamespaceSpec};
use rabs_sandbox::toolchain_dataset::fingerprint_toolchain;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};

const BYTES: &[u8] = b"compiler\0\xff";

struct Fixture {
    _owner: tempfile::TempDir,
    source: PathBuf,
    cache: PathBuf,
    identity: ToolchainIdentity,
}

impl Fixture {
    fn new() -> Self {
        let owner = tempfile::tempdir().unwrap();
        let root = owner.path().canonicalize().unwrap();
        let source = root.join("installation");
        fs::create_dir_all(source.join("bin")).unwrap();
        fs::create_dir_all(source.join("lib/empty")).unwrap();
        fs::write(source.join("bin/compiler"), BYTES).unwrap();
        fs::set_permissions(source.join("bin/compiler"), fs::Permissions::from_mode(0o755)).unwrap();
        symlink("compiler", source.join("bin/rustc")).unwrap();
        let identity = fingerprint_toolchain(&source, &ToolchainLimits::default(), || false).unwrap();
        Self { _owner: owner, source, cache: root.join("cache"), identity }
    }

    fn pool(&self) -> ToolchainPool {
        ToolchainPool::with_directory(1024, 8, Some(&self.cache)).unwrap()
    }

    fn entry(&self) -> PathBuf { self.cache.join(OBJECTS).join(name(&self.identity)) }

    fn objects(&self) -> Vec<PathBuf> {
        let mut paths: Vec<_> = fs::read_dir(self.cache.join(OBJECTS)).unwrap()
            .map(|entry| entry.unwrap().path()).collect();
        paths.sort();
        paths
    }
}

#[test]
fn durable_pool_reopens_exact_inodes_without_the_original_installation() {
    let f = Fixture::new();
    let pool = f.pool();
    let first = pool.acquire(&f.source, Some(&f.identity), || false).unwrap();
    let root = first.root().to_path_buf();
    assert_eq!(root, f.entry().join("tree"));
    let inode = fs::metadata(root.join("bin/compiler")).unwrap().ino();
    assert_ne!(inode, fs::metadata(f.source.join("bin/compiler")).unwrap().ino());
    assert_eq!(first.entry_count().unwrap(), 6);
    drop(first);
    drop(pool);
    fs::rename(&f.source, f.source.with_file_name("unavailable-installation")).unwrap();
    let pool = f.pool();
    assert!(pool.lock().unwrap().entries.is_empty(), "startup must not fabricate verified in-memory hits");
    let lease = pool.lookup(&f.identity, || false).unwrap().unwrap();
    assert_eq!(lease.root(), root);
    assert_eq!(lease.disposition(), "reused");
    assert_eq!(fs::metadata(root.join("bin/compiler")).unwrap().ino(), inode);
    assert_eq!(fs::read(root.join("bin/compiler")).unwrap(), BYTES);
    assert_eq!(fs::read_link(root.join("bin/rustc")).unwrap(), Path::new("compiler"));
    assert!(root.join("lib/empty").is_dir());
    assert_eq!(f.objects(), vec![f.entry()]);
    assert_eq!(fs::read_dir(pool.directory.0.path()).unwrap().count(), 0);
    // Actual execution acquisition also finds the retained tree without having
    // to trust or reopen the vanished installation path supplied by a caller.
    let execution = pool.acquire(&f.source, Some(&f.identity), || false).unwrap();
    assert_eq!(execution.root(), root);
    assert_eq!(fs::metadata(execution.root().join("bin/compiler")).unwrap().ino(), inode);
    execution.verify(|| false).unwrap();
}

#[test]
fn the_last_execution_lease_keeps_the_durable_store_exclusively_owned() {
    let f = Fixture::new();
    let pool = f.pool();
    let lease = pool.acquire(&f.source, Some(&f.identity), || false).unwrap();
    drop(pool);
    assert!(ToolchainPool::with_directory(1024, 8, Some(&f.cache)).is_err());
    lease.verify(|| false).unwrap();
    let root = lease.root().to_path_buf();
    drop(lease);
    assert!(root.exists(), "a persistent tree is not TempDir-owned execution scratch");
    let reopened = f.pool();
    assert!(reopened.lookup(&f.identity, || false).unwrap().is_some());
}

#[test]
fn mismatching_identity_hints_never_select_or_rename_a_retained_dataset() {
    let f = Fixture::new();
    let pool = f.pool();
    drop(pool.acquire(&f.source, Some(&f.identity), || false).unwrap());
    drop(pool);
    let pool = f.pool();
    let before = f.objects();
    for identity in [
        ToolchainIdentity { sha256: [0; 32], ..f.identity },
        ToolchainIdentity { files: f.identity.files + 1, ..f.identity },
        ToolchainIdentity { bytes: f.identity.bytes + 1, ..f.identity },
    ] {
        assert!(pool.lookup(&identity, || false).unwrap().is_none());
    }
    assert_eq!(f.objects(), before);
    assert!(pool.lock().unwrap().entries.is_empty());
    drop(pool);
    let foreign = ToolchainIdentity { sha256: [0x33; 32], ..f.identity };
    let renamed = f.cache.join(OBJECTS).join(name(&foreign));
    fs::rename(f.entry(), &renamed).unwrap();
    let pool = f.pool();
    assert!(pool.lookup(&foreign, || false).is_err(), "a valid-looking filename is not content evidence");
    assert_eq!(fs::read(renamed.join("tree/bin/compiler")).unwrap(), BYTES);
}

#[test]
fn reopen_rejects_corruption_writable_files_aliases_and_extra_namespace() {
    for fault in 0..4 {
        let f = Fixture::new();
        let pool = f.pool();
        drop(pool.acquire(&f.source, Some(&f.identity), || false).unwrap());
        drop(pool);
        let file = f.entry().join("tree/bin/compiler");
        match fault {
            0 => {
                fs::set_permissions(&file, fs::Permissions::from_mode(0o755)).unwrap();
                fs::write(&file, vec![b'x'; BYTES.len()]).unwrap();
                fs::set_permissions(&file, fs::Permissions::from_mode(0o555)).unwrap();
            }
            1 => fs::set_permissions(&file, fs::Permissions::from_mode(0o755)).unwrap(),
            2 => fs::hard_link(&file, f.cache.parent().unwrap().join("writable-alias")).unwrap(),
            _ => fs::write(f.entry().join("unexpected"), b"not a dataset member").unwrap(),
        }
        let before = fs::read(&file).unwrap();
        let pool = f.pool();
        assert!(pool.lookup(&f.identity, || false).is_err(), "fault {fault}");
        assert!(pool.acquire(&f.source, Some(&f.identity), || false).is_err(),
            "configured persistence must not replace corrupt evidence with the original source");
        assert_eq!(fs::read(&file).unwrap(), before);
        assert_eq!(f.objects(), vec![f.entry()]);
    }
}

#[test]
fn disk_capacity_keeps_old_datasets_and_uses_verified_private_overflow() {
    for by_bytes in [false, true] {
        let f = Fixture::new();
        let budget = if by_bytes { f.identity.bytes } else { 1024 };
        let entries = if by_bytes { 8 } else { 1 };
        let pool = ToolchainPool::with_directory(budget, entries, Some(&f.cache)).unwrap();
        let first = pool.acquire(&f.source, Some(&f.identity), || false).unwrap();
        let root = first.root().to_path_buf();
        drop(first);
        fs::write(f.source.join("bin/compiler"), b"other!").unwrap();
        let second_id = fingerprint_toolchain(&f.source, &ToolchainLimits::default(), || false).unwrap();
        let second = pool.acquire(&f.source, Some(&second_id), || false).unwrap();
        assert!(!second.root().starts_with(&f.cache));
        assert_eq!(fs::read(second.root().join("bin/compiler")).unwrap(), b"other!");
        assert!(root.exists(), "in-memory LRU eviction must never delete durable input");
        assert_eq!(f.objects(), vec![f.entry()]);
        second.verify(|| false).unwrap();
        drop(second);
        drop(pool);
        let pool = ToolchainPool::with_directory(budget, entries, Some(&f.cache)).unwrap();
        assert!(pool.lookup(&f.identity, || false).unwrap().is_some());
        assert!(pool.lookup(&second_id, || false).unwrap().is_none());
    }
}

#[test]
fn interrupted_reservations_remain_charged_and_are_never_adopted_on_restart() {
    let f = Fixture::new();
    let cache = DurableCache::open(&f.cache, f.identity.bytes, 1).unwrap();
    let error = cache.capture(&f.source, &f.identity, &|| !f.objects().is_empty()).err().unwrap();
    assert_eq!(error.kind(), io::ErrorKind::Interrupted);
    assert!(!f.entry().exists());
    let retained = f.objects();
    assert_eq!(retained.len(), 1);
    assert_eq!(cache.catalogue(&|| false).unwrap().bytes, f.identity.bytes);
    assert_eq!(cache.catalogue(&|| false).unwrap().entries, 1);
    drop(cache);
    let cache = DurableCache::open(&f.cache, f.identity.bytes, 1).unwrap();
    assert!(cache.load(&f.identity, &|| false).unwrap().is_none());
    assert!(cache.capture(&f.source, &f.identity, &|| false).unwrap().is_none());
    assert_eq!(f.objects(), retained);
    drop(cache);
    let pool = ToolchainPool::with_directory(f.identity.bytes, 1, Some(&f.cache)).unwrap();
    let lease = pool.acquire(&f.source, Some(&f.identity), || false).unwrap();
    assert!(!lease.root().starts_with(&f.cache));
    lease.verify(|| false).unwrap();
    assert_eq!(f.objects(), retained, "private overflow cannot erase or reset a pending reservation");
}

#[test]
fn a_complete_unpublished_tree_is_not_a_hit_but_post_publish_cancellation_is_recoverable() {
    let f = Fixture::new();
    let cache = DurableCache::open(&f.cache, 1024, 8).unwrap();
    let error = cache.capture(&f.source, &f.identity, &|| f.entry().exists()).err().unwrap();
    assert_eq!(error.kind(), io::ErrorKind::Interrupted);
    assert!(f.entry().exists());
    let verified = cache.load(&f.identity, &|| false).unwrap().unwrap();
    verified.verify(|| false).unwrap();
    drop(verified);
    drop(cache);
    let pending = f.cache.join(OBJECTS).join(format!("{PENDING}{}-Crash7", name(&f.identity)));
    fs::rename(f.entry(), &pending).unwrap();
    let cache = DurableCache::open(&f.cache, 1024, 8).unwrap();
    assert!(cache.load(&f.identity, &|| false).unwrap().is_none());
    assert_eq!(cache.catalogue(&|| false).unwrap().entries, 1);
    let recaptured = cache.capture(&f.source, &f.identity, &|| false).unwrap().unwrap();
    assert_eq!(recaptured.root(), f.entry().join("tree"));
    assert!(pending.join("tree/bin/compiler").exists());
    assert_eq!(cache.catalogue(&|| false).unwrap().entries, 2);
}

#[test]
fn optional_writer_contention_never_blocks_verified_lookup_or_creates_a_reservation() {
    let f = Fixture::new();
    let cache = DurableCache::open(&f.cache, 1024, 8).unwrap();
    drop(cache.capture(&f.source, &f.identity, &|| false).unwrap().unwrap());
    let before = f.objects();
    let writer = cache.writer.lock().unwrap();
    assert!(cache.capture(Path::new("/absent"), &f.identity, &|| false).unwrap().is_none());
    assert!(cache.load(&f.identity, &|| false).unwrap().is_some());
    assert_eq!(f.objects(), before);
    drop(writer);
}

#[test]
fn persistent_storage_is_protected_even_for_an_unpinned_private_execution() {
    let f = Fixture::new();
    let pool = f.pool();
    let pinned = pool.acquire(&f.source, Some(&f.identity), || false).unwrap();
    let private = pool.acquire(&f.source, None, || false).unwrap();
    let writable = f.cache.parent().unwrap().join("writable");
    fs::create_dir(&writable).unwrap();
    let alias = writable.join("alias");
    symlink(&f.cache, &alias).unwrap();
    let objects = f.cache.join(OBJECTS);
    for lease in [&pinned, &private] {
        let mut valid = CanonicalNamespaceSpec::new();
        valid.ro_binds.push(Bind::new(lease.root(), rabs_sandbox::layout::TOOLCHAIN));
        valid.rw_binds.push(Bind::new(&writable, rabs_sandbox::layout::WORKSPACE));
        lease.validate_namespace(&valid).unwrap();
        for path in [f.cache.as_path(), objects.as_path(), alias.as_path(), f.cache.parent().unwrap()] {
            let mut bad = valid.clone();
            bad.rw_binds[0].backing = path.to_path_buf();
            let before = bad.clone();
            assert!(lease.validate_namespace(&bad).is_err());
            assert_eq!(bad, before, "validation cannot partially rewrite the sandbox");
        }
    }
}

#[test]
fn configuration_lock_and_directory_identity_fail_closed_without_erasing_files() {
    let f = Fixture::new();
    assert!(ToolchainPool::with_directory(0, 8, Some(&f.cache)).is_err());
    assert!(!f.cache.exists());
    assert!(ToolchainPool::with_directory(1024, 8, Some(Path::new("relative"))).is_err());
    let cache = DurableCache::open(&f.cache, 1024, 8).unwrap();
    assert!(DurableCache::open(&f.cache, 1024, 8).is_err());
    fs::rename(f.cache.join(OBJECTS), f.cache.join("old-objects")).unwrap();
    make_directory(&f.cache.join(OBJECTS)).unwrap();
    assert!(cache.load(&f.identity, &|| false).is_err(), "an open cache cannot follow a replaced directory");
    assert!(f.cache.join("old-objects").exists());
    drop(cache);
    assert!(DurableCache::open(&f.cache, 1024, 8).is_err(), "unrelated retained data is not silently removed");
}

#[test]
fn cache_paths_links_modes_and_quota_downgrades_are_never_silently_fixed() {
    let f = Fixture::new();
    let pool = f.pool();
    drop(pool.acquire(&f.source, Some(&f.identity), || false).unwrap());
    drop(pool);
    let alias = f.cache.with_file_name("cache-alias");
    symlink(&f.cache, &alias).unwrap();
    assert!(DurableCache::open(&alias, 1024, 8).is_err());
    assert!(DurableCache::open(&f.cache, f.identity.bytes - 1, 8).is_err());
    fs::set_permissions(&f.cache, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(DurableCache::open(&f.cache, 1024, 8).is_err());
    assert_eq!(fs::metadata(&f.cache).unwrap().mode() & 0o7777, 0o755);
    fs::set_permissions(&f.cache, fs::Permissions::from_mode(0o700)).unwrap();
    fs::hard_link(f.cache.join(LOCK), f.cache.with_file_name("lock-alias")).unwrap();
    assert!(DurableCache::open(&f.cache, 1024, 8).is_err());
    assert_eq!(fs::metadata(f.cache.join(LOCK)).unwrap().nlink(), 2);
    assert_eq!(fs::read(f.entry().join("tree/bin/compiler")).unwrap(), BYTES);
}

#[test]
fn persistent_reservation_names_use_complete_canonical_bounded_identity() {
    let id = ToolchainIdentity { sha256: [0xab; 32], files: 1, bytes: 11 };
    let good = name(&id);
    assert_eq!(identity_from_name(&good).unwrap(), id);
    assert_eq!(catalogue_identity(&format!("{PENDING}{good}-Ab1234")).unwrap(), id);
    for bad in [
        String::new(), good.replace("v1-", "v2-"), good.to_uppercase(),
        format!("v1-{}-01-11", "ab".repeat(32)),
        format!("v1-{}-1-18446744073709551616", "ab".repeat(32)),
        format!("v1-{}-100001-11", "ab".repeat(32)),
        format!("v1-{}-1-8589934593", "ab".repeat(32)),
        format!("{good}-extra"), format!("{PENDING}{good}-"),
        format!("{PENDING}{good}-../../outside"),
    ] {
        assert!(catalogue_identity(&bad).is_err(), "{bad}");
    }
}
