//! Verified source-byte reuse for the authenticated remote Cargo frontend.
//!
//! The cache owns only disposable byte objects. Each operation imports selected
//! hits into its fresh receiver, advertises a bounded missing-file plan, and
//! seals the complete manifest before execution. A hit never grants source-tree
//! or publication authority, and no shared file is mounted writable.

use super::private_directory;
use super::wire::{SourcePlan, invalid, require};
use rabs_sandbox::source_cache::{RememberError, SourceCache, SourceCheckpoints};
use rabs_sandbox::source_transfer::SourceReceiver;
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Instant;

/// One service-wide budget and private parent. Scoped sessions clone the same
/// writer/inventory state; enrolled peers do not receive independent quotas.
pub(super) struct RemoteSourceCache {
    cache: SourceCache,
    owner: Arc<tempfile::TempDir>,
}

impl RemoteSourceCache {
    pub(super) fn new(parent: &Path, max_bytes: u64) -> io::Result<Self> {
        private_directory(parent)?;
        let owner = Arc::new(
            tempfile::Builder::new()
                .prefix("canonical-remote-source-cache-")
                .permissions(fs::Permissions::from_mode(0o700))
                .tempdir_in(parent)?,
        );
        let cache = SourceCache::open_byte_only(owner.path(), max_bytes)?;
        Ok(Self { cache, owner })
    }

    /// The caller supplies the identity actually authenticated by TLS. Logical
    /// Cargo settings and the source manifest cannot choose this namespace.
    pub(super) fn for_peer(
        &self,
        peer: [u8; 32],
        stopped: Arc<AtomicBool>,
        deadline: Instant,
    ) -> io::Result<SourceCacheLease> {
        Ok(SourceCacheLease {
            cache: self
                .cache
                .clone()
                .for_peer(peer)?
                .with_cancellation(stopped)
                .before(deadline),
            _owner: Arc::clone(&self.owner),
        })
    }
}

/// Keep cache storage alive through any anonymous hit snapshot or checkpoint
/// writer, even if the service's original pool handle has already been dropped.
pub(super) struct SourceCacheLease {
    cache: SourceCache,
    _owner: Arc<tempfile::TempDir>,
}

fn checkpoint(cancelled: &impl Fn() -> bool) -> io::Result<()> {
    if cancelled() {
        Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "remote source preparation or transfer cancelled",
        ))
    } else {
        Ok(())
    }
}

fn cache_warning(stage: &str, error: &io::Error) {
    eprintln!(
        "{}",
        serde_json::json!({
            "kind":"canonical-remote-source-cache-warning",
            "stage":stage,
            "message":error.to_string().chars().take(1024).collect::<String>(),
        })
    );
}

/// Exact missing-file decision and the original fresh source receiver. Writer
/// handles close before cache ownership. An uncertain write or source error
/// makes this wrapper terminal even when the underlying receiver was sealed.
pub(super) struct SourceInput {
    receiver: SourceReceiver,
    checkpoints: Option<SourceCheckpoints>,
    cache: Option<SourceCacheLease>,
    plan: SourcePlan,
    checkpoint_attempted: bool,
    transfer_started: bool,
    failed: bool,
    sealed: bool,
}

impl SourceInput {
    pub(super) fn uncached(receiver: SourceReceiver) -> io::Result<Self> {
        require(
            receiver.sealed_root().is_none(),
            "remote source admission requires a fresh receiver",
        )?;
        let plan = SourcePlan::all(receiver.manifest())?;
        Ok(Self {
            receiver,
            checkpoints: None,
            cache: None,
            plan,
            checkpoint_attempted: false,
            transfer_started: false,
            failed: false,
            sealed: false,
        })
    }

    pub(super) fn prepare(
        receiver: SourceReceiver,
        cache: Option<SourceCacheLease>,
        cancelled: impl Fn() -> bool,
    ) -> io::Result<Self> {
        checkpoint(&cancelled)?;
        let mut input = Self::uncached(receiver)?;
        input.cache = cache;
        if let Some(cache) = &input.cache {
            let files = input.receiver.manifest().files().to_vec();
            let mut missing = Vec::with_capacity(files.len());
            for (index, file) in files.iter().enumerate() {
                checkpoint(&cancelled)?;
                if file.len == 0 {
                    continue;
                }
                let snapshot = cache
                    .cache
                    .load_with_cloner(file, rabs_cas::materialization::try_verified_reflink);
                // load intentionally treats unavailable/corrupt objects as
                // misses, including a spent cache control budget. Recheck the
                // operation budget before interpreting absence as upload work.
                checkpoint(&cancelled)?;
                if let Some(snapshot) = snapshot {
                    snapshot.install_with_cloner(
                        &mut input.receiver,
                        rabs_cas::materialization::try_verified_reflink,
                    )?;
                    // Import failure poisons the receiver: never request an
                    // upload to repair a partly populated operation in place.
                    checkpoint(&cancelled)?;
                } else {
                    missing.push(
                        u16::try_from(index)
                            .map_err(|_| invalid("remote source index exceeds its bound"))?,
                    );
                }
            }
            input.plan = SourcePlan::new(input.receiver.manifest(), missing)?;
        }
        checkpoint(&cancelled)?;
        Ok(input)
    }

    pub(super) fn plan(&self) -> &SourcePlan {
        &self.plan
    }

    /// Readiness grants one new input budget. No frame, checkpoint or retry can
    /// renew it again, and preparation must already have finished successfully.
    pub(super) fn begin_transfer(&mut self, deadline: Instant) -> io::Result<()> {
        require(
            !self.transfer_started && !self.failed && !self.sealed,
            "remote source transfer was already started or refused",
        )?;
        self.plan.validate(self.receiver.manifest())?;
        if let Some(cache) = &mut self.cache {
            cache.cache = cache.cache.clone().before(deadline);
        }
        self.transfer_started = true;
        Ok(())
    }

    pub(super) fn write_chunk(
        &mut self,
        path: &str,
        offset: u64,
        bytes: &[u8],
        sha256: [u8; 32],
        cancelled: impl Fn() -> bool,
    ) -> io::Result<()> {
        require(
            self.transfer_started && !self.failed && !self.sealed,
            "remote source transfer is unavailable or already sealed",
        )?;
        self.failed = true;
        checkpoint(&cancelled)?;
        let files = self.receiver.manifest().files();
        let index = files
            .binary_search_by(|file| file.path.as_str().cmp(path))
            .map_err(|_| invalid("remote source chunk names an undeclared file"))?;
        let index_u16 =
            u16::try_from(index).map_err(|_| invalid("remote source index exceeds its bound"))?;
        require(
            self.plan.missing_files.binary_search(&index_u16).is_ok(),
            "remote source chunk was not requested by the admitted missing-file plan",
        )?;
        let expected_len = files[index].len;
        let received = self.receiver.write_chunk(path, offset, bytes, sha256)?;
        if received == expected_len {
            self.remember_completed_file(path)?;
        }
        checkpoint(&cancelled)?;
        self.failed = false;
        Ok(())
    }

    fn remember_completed_file(&mut self, path: &str) -> io::Result<()> {
        let Some(cache) = &self.cache else {
            return Ok(());
        };
        if !self.checkpoint_attempted {
            self.checkpoint_attempted = true;
            match cache.cache.checkpoints(self.receiver.manifest()) {
                Ok(writer) => self.checkpoints = writer,
                Err(RememberError::Cache(error)) => cache_warning("checkpoint", &error),
                Err(RememberError::Source(error)) => return Err(error),
            }
        }
        if let Some(writer) = &mut self.checkpoints {
            match writer.remember_file(&mut self.receiver, path) {
                Ok(()) => {}
                Err(RememberError::Cache(error)) => {
                    cache_warning("checkpoint", &error);
                    self.checkpoints = None;
                }
                Err(RememberError::Source(error)) => return Err(error),
            }
        }
        Ok(())
    }

    pub(super) fn seal(&mut self, cancelled: impl Fn() -> bool) -> io::Result<()> {
        require(
            self.transfer_started && !self.failed,
            "remote source transfer was not started or has failed",
        )?;
        checkpoint(&cancelled)?;
        if self.sealed {
            return Ok(());
        }
        self.failed = true;
        // Do not hold a shared writer while the receiver performs its mandatory
        // complete-tree verification. Remember can retry optional admission.
        self.checkpoints = None;
        self.receiver.seal_cancellable(&cancelled)?;
        if let Some(cache) = &self.cache {
            match cache.cache.remember(&self.receiver) {
                Ok(_) => {}
                Err(RememberError::Cache(error)) => cache_warning("retain", &error),
                Err(RememberError::Source(error)) => return Err(error),
            }
        }
        checkpoint(&cancelled)?;
        self.sealed = true;
        self.failed = false;
        Ok(())
    }

    pub(super) fn finish(mut self, cancelled: impl Fn() -> bool) -> io::Result<SourceReceiver> {
        self.seal(cancelled)?;
        Ok(self.receiver)
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use rabs_sandbox::source_transfer::{SourceFile, SourceManifest};
    use sha2::{Digest, Sha256};
    use std::os::unix::fs::MetadataExt;
    use std::path::PathBuf;
    use std::sync::atomic::Ordering;
    use std::time::Duration;

    const EDGE: [u8; 32] = [17; 32];

    fn private() -> tempfile::TempDir {
        tempfile::Builder::new()
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap()
    }

    fn manifest(files: &[(&str, &[u8])]) -> SourceManifest {
        SourceManifest::new(
            files
                .iter()
                .map(|(path, bytes)| SourceFile {
                    path: (*path).into(),
                    len: bytes.len() as u64,
                    sha256: Sha256::digest(bytes).into(),
                    executable: false,
                })
                .collect(),
        )
        .unwrap()
    }

    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(30)
    }

    fn prepared(
        pool: &RemoteSourceCache,
        manifest: &SourceManifest,
    ) -> (tempfile::TempDir, SourceInput) {
        let owner = private();
        let receiver =
            SourceReceiver::create(&owner.path().join("source"), manifest.clone()).unwrap();
        let deadline = deadline();
        let cache = pool
            .for_peer(EDGE, Arc::new(AtomicBool::new(false)), deadline)
            .unwrap();
        let input =
            SourceInput::prepare(receiver, Some(cache), || Instant::now() >= deadline).unwrap();
        (owner, input)
    }

    fn send(input: &mut SourceInput, path: &str, bytes: &[u8]) {
        input
            .write_chunk(path, 0, bytes, Sha256::digest(bytes).into(), || false)
            .unwrap();
    }

    fn seed(pool: &RemoteSourceCache, files: &[(&str, &[u8])]) -> SourceManifest {
        let manifest = manifest(files);
        let (_owner, mut input) = prepared(pool, &manifest);
        assert_eq!(input.plan(), &SourcePlan::all(&manifest).unwrap());
        input.begin_transfer(deadline()).unwrap();
        for (path, bytes) in files {
            if !bytes.is_empty() {
                send(&mut input, path, bytes);
            }
        }
        let sealed = input.finish(|| false).unwrap();
        assert!(sealed.sealed_root().is_some());
        manifest
    }

    fn objects(pool: &RemoteSourceCache) -> Vec<PathBuf> {
        fs::read_dir(pool.owner.path().join("source-files-v1"))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| path.extension().is_some_and(|extension| extension == "src"))
            .collect()
    }

    #[test]
    fn completed_members_survive_incomplete_upload_and_reconstruct_a_fresh_source_tree() {
        let parent = private();
        let pool = RemoteSourceCache::new(parent.path(), 1024).unwrap();
        let first_bytes = b"complete input";
        let second_bytes = b"remaining input";
        let manifest = manifest(&[("a.rs", first_bytes), ("b.rs", second_bytes)]);
        let (first_owner, mut first) = prepared(&pool, &manifest);
        assert_eq!(first.plan().missing_files, vec![0, 1]);
        first.begin_transfer(deadline()).unwrap();
        send(&mut first, "a.rs", first_bytes);
        send(&mut first, "b.rs", &second_bytes[..3]);
        assert!(first.receiver.sealed_root().is_none());
        let retained = objects(&pool);
        assert_eq!(
            retained.len(),
            1,
            "an incomplete member must not enter reuse"
        );
        drop(first);

        let (next_owner, mut next) = prepared(&pool, &manifest);
        assert_eq!(next.plan().missing_files, vec![1]);
        let restored = next_owner.path().join("source/a.rs");
        assert_eq!(fs::read(&restored).unwrap(), first_bytes);
        assert_ne!(
            fs::metadata(&restored).unwrap().ino(),
            fs::metadata(&retained[0]).unwrap().ino()
        );
        assert_ne!(
            fs::metadata(&restored).unwrap().ino(),
            fs::metadata(first_owner.path().join("source/a.rs"))
                .unwrap()
                .ino()
        );
        next.begin_transfer(deadline()).unwrap();
        send(&mut next, "b.rs", second_bytes);
        let sealed = next.finish(|| false).unwrap();
        let root = sealed.sealed_root().unwrap();
        assert_eq!(fs::read(root.join("a.rs")).unwrap(), first_bytes);
        assert_eq!(fs::read(root.join("b.rs")).unwrap(), second_bytes);
        assert_eq!(objects(&pool).len(), 2);
    }

    #[test]
    fn corrupt_cache_is_a_miss_but_failed_import_and_changed_source_are_terminal() {
        let parent = private();
        let pool = RemoteSourceCache::new(parent.path(), 1024).unwrap();
        let bytes = b"verified input";
        let manifest = seed(&pool, &[("input.rs", bytes)]);
        let cached = objects(&pool);
        assert_eq!(cached.len(), 1);
        fs::set_permissions(&cached[0], fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&cached[0], b"corrupted data").unwrap();

        let (_repair_owner, mut repair) = prepared(&pool, &manifest);
        assert_eq!(repair.plan().missing_files, vec![0]);
        repair.begin_transfer(deadline()).unwrap();
        send(&mut repair, "input.rs", bytes);
        repair.finish(|| false).unwrap();

        // A valid cached object does not authorize repairing a receiver after
        // installation has begun. An unexpected destination type must refuse.
        let broken = private();
        let receiver =
            SourceReceiver::create(&broken.path().join("source"), manifest.clone()).unwrap();
        fs::rename(
            broken.path().join("source/input.rs"),
            broken.path().join("original-empty-file"),
        )
        .unwrap();
        fs::create_dir(broken.path().join("source/input.rs")).unwrap();
        let cache = pool
            .for_peer(EDGE, Arc::new(AtomicBool::new(false)), deadline())
            .unwrap();
        assert!(SourceInput::prepare(receiver, Some(cache), || false).is_err());

        let (owner, mut input) = prepared(&pool, &manifest);
        assert!(input.plan().missing_files.is_empty());
        input.begin_transfer(deadline()).unwrap();
        let source = owner.path().join("source/input.rs");
        fs::set_permissions(&source, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&source, b"mutated input").unwrap();
        assert!(input.seal(|| false).is_err());
        assert!(input.failed);
        assert!(input.receiver.sealed_root().is_none());
        assert!(
            input
                .write_chunk("input.rs", 0, bytes, Sha256::digest(bytes).into(), || false)
                .is_err()
        );
        assert!(input.finish(|| false).is_err());

        let (_valid_owner, valid) = prepared(&pool, &manifest);
        assert!(
            valid.plan().missing_files.is_empty(),
            "source failure must not revoke intact cache bytes"
        );
    }

    #[test]
    fn cache_storage_failure_does_not_hide_a_verified_source_or_authorize_invalid_bytes() {
        let parent = private();
        let pool = RemoteSourceCache::new(parent.path(), 1024).unwrap();
        let unexpected = pool.owner.path().join("source-files-v1/foreign-entry");
        fs::write(&unexpected, b"unrecognized optional storage").unwrap();
        let bytes = b"ordinary verified source";
        let manifest = manifest(&[("input.rs", bytes)]);
        let (_owner, mut input) = prepared(&pool, &manifest);
        input.begin_transfer(deadline()).unwrap();
        send(&mut input, "input.rs", bytes);
        assert!(input.checkpoint_attempted);
        assert!(input.checkpoints.is_none());
        assert!(!input.failed);
        let sealed = input.finish(|| false).unwrap();
        assert_eq!(
            fs::read(sealed.sealed_root().unwrap().join("input.rs")).unwrap(),
            bytes
        );
        assert!(
            unexpected.is_file(),
            "uncertain cache storage must be preserved"
        );

        let (_owner, mut changed) = prepared(&pool, &manifest);
        changed.begin_transfer(deadline()).unwrap();
        assert!(
            changed
                .write_chunk(
                    "input.rs",
                    0,
                    b"wrong",
                    Sha256::digest(b"wrong").into(),
                    || false
                )
                .is_ok()
        );
        // The cache warning path cannot convert an incomplete/incorrect
        // execution source into a sealed receiver.
        assert!(changed.finish(|| false).is_err());
    }

    #[test]
    fn cache_owner_outlives_its_pool_and_disappears_after_private_source_handoff() {
        let parent = private();
        let pool = RemoteSourceCache::new(parent.path(), 1024).unwrap();
        let cache_root = pool.owner.path().to_path_buf();
        let bytes = b"source survives cache release";
        let manifest = manifest(&[("input.rs", bytes)]);
        let (_source_owner, mut input) = prepared(&pool, &manifest);
        input.begin_transfer(deadline()).unwrap();
        drop(pool);
        assert!(cache_root.is_dir());
        send(&mut input, "input.rs", bytes);
        assert!(input.checkpoints.is_some());
        assert!(cache_root.is_dir());
        let source = input.finish(|| false).unwrap();
        assert!(
            !cache_root.exists(),
            "a completed handoff must release its cache owner"
        );
        assert_eq!(
            fs::read(source.sealed_root().unwrap().join("input.rs")).unwrap(),
            bytes
        );
    }

    #[test]
    fn preparation_and_transfer_keep_independent_fixed_cancellation_budgets() {
        let parent = private();
        let pool = RemoteSourceCache::new(parent.path(), 1024).unwrap();
        let bytes = b"cached input";
        let manifest = seed(&pool, &[("input.rs", bytes)]);

        // Cancel after a real cache import changed the fresh receiver. The
        // post-I/O check must refuse readiness and leave the pool usable.
        let owner = private();
        let path = owner.path().join("source/input.rs");
        let receiver =
            SourceReceiver::create(&owner.path().join("source"), manifest.clone()).unwrap();
        let stopped = Arc::new(AtomicBool::new(false));
        let cache = pool
            .for_peer(EDGE, Arc::clone(&stopped), deadline())
            .unwrap();
        let refused = SourceInput::prepare(receiver, Some(cache), || {
            if fs::metadata(&path).unwrap().len() == bytes.len() as u64 {
                stopped.store(true, Ordering::Release);
            }
            stopped.load(Ordering::Acquire)
        });
        assert_eq!(
            refused.err().expect("late cancellation must refuse").kind(),
            io::ErrorKind::Interrupted
        );
        assert_eq!(fs::read(&path).unwrap(), bytes);

        let (_owner, mut input) = prepared(&pool, &manifest);
        assert!(input.plan().missing_files.is_empty());
        let expired = Instant::now();
        input.begin_transfer(expired).unwrap();
        assert!(input.begin_transfer(deadline()).is_err());
        assert!(
            input
                .cache
                .as_ref()
                .unwrap()
                .cache
                .load(&manifest.files()[0])
                .is_none(),
            "a repeated begin must not renew the cache's expired input budget"
        );
        let error = input
            .write_chunk("input.rs", 0, bytes, Sha256::digest(bytes).into(), || {
                Instant::now() >= expired
            })
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
        assert!(input.failed);
        assert!(
            input
                .write_chunk("input.rs", 0, bytes, Sha256::digest(bytes).into(), || false)
                .is_err()
        );
        assert!(input.finish(|| false).is_err());

        let (_owner, live) = prepared(&pool, &manifest);
        assert!(live.plan().missing_files.is_empty());
        assert!(live.receiver.sealed_root().is_none());
    }
}
