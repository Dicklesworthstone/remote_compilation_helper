//! Verified source-byte reuse for the authenticated remote Cargo frontend.
//!
//! The cache owns only disposable byte objects. Each operation imports selected
//! hits into its fresh receiver, advertises a bounded missing-file plan, and
//! seals the complete manifest before execution. A hit never grants source-tree
//! or publication authority, and no shared file is mounted writable.

use super::private_directory;
use super::wire::{SourcePlan, SourcePrefixOffer, digest, invalid, require};
use rabs_protocol::raw_bytes::encode_hex;
use rabs_sandbox::source_cache::{
    RememberError, SourceCache, SourceCheckpoints, SourcePrefix, SourcePrefixSnapshots,
};
use rabs_sandbox::source_transfer::{
    MAX_SOURCE_CHUNK, MAX_SOURCE_PREFIX_HINT_BYTES, SourceReceiver,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
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
    prefixes: Option<SourcePrefixSnapshots>,
    cache: Option<SourceCacheLease>,
    plan: SourcePlan,
    selected: BTreeSet<usize>,
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
            prefixes: None,
            cache: None,
            plan,
            selected: BTreeSet::new(),
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
            let mut prefixes = Vec::new();
            let mut hint_bytes = 2;
            input.prefixes =
                match SourcePrefixSnapshots::new(cache.cache.clone(), input.receiver.manifest()) {
                    Ok(snapshots) => Some(snapshots),
                    Err(error) => {
                        cache_warning("prefix-snapshot", &error);
                        None
                    }
                };
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
                    let index = u16::try_from(index)
                        .map_err(|_| invalid("remote source index exceeds its bound"))?;
                    missing.push(index);
                    if let Some(snapshots) = &mut input.prefixes {
                        match snapshots.capture(file) {
                            Ok(Some(prefix)) => {
                                let offer = SourcePrefixOffer {
                                    index,
                                    offset: prefix.offset,
                                    sha256: encode_hex(&prefix.sha256),
                                };
                                let bytes = serde_json::to_vec(&offer)?.len()
                                    + usize::from(!prefixes.is_empty());
                                if hint_bytes + bytes <= MAX_SOURCE_PREFIX_HINT_BYTES {
                                    hint_bytes += bytes;
                                    prefixes.push(offer);
                                }
                            }
                            Ok(None) => {}
                            Err(error) => {
                                cache_warning("prefix-snapshot", &error);
                                input.prefixes = None;
                                prefixes.clear();
                            }
                        }
                    }
                }
            }
            if let Some(snapshots) = &mut input.prefixes
                && let Err(error) = snapshots.seal()
            {
                cache_warning("prefix-snapshot", &error);
                input.prefixes = None;
                prefixes.clear();
            }
            input.plan = SourcePlan::with_prefixes(input.receiver.manifest(), missing, prefixes)?;
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
        self.prefixes = self
            .prefixes
            .take()
            .map(|snapshots| snapshots.before(deadline));
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
        if !self.selected.contains(&index) {
            let selected = self.select_prefix(index, path, offset, &cancelled)?;
            self.selected.insert(index);
            self.begin_prefix_checkpoint(path, selected)?;
        }
        let received = self.receiver.write_chunk(path, offset, bytes, sha256)?;
        if let Some(writer) = &mut self.checkpoints
            && let Err(error) = writer.append_prefix(path, offset, bytes)
        {
            cache_warning("prefix-checkpoint", &error);
            self.checkpoints = None;
        }
        if received == expected_len {
            self.remember_completed_file(path)?;
        }
        checkpoint(&cancelled)?;
        self.failed = false;
        Ok(())
    }

    /// The first ordinary chunk selects either zero or exactly the offered
    /// range. Subsequent chunks and exact retries use the receiver's existing
    /// offset/hash checks and can never import the frozen bytes a second time.
    fn select_prefix(
        &mut self,
        index: usize,
        path: &str,
        offset: u64,
        cancelled: &impl Fn() -> bool,
    ) -> io::Result<SourcePrefix> {
        if offset == 0 {
            return Ok(SourcePrefix {
                offset: 0,
                sha256: Sha256::digest([]).into(),
            });
        }
        let offer = self
            .plan
            .prefix_for(index)
            .ok_or_else(|| invalid("remote source chunk selected an unoffered prefix"))?;
        require(
            offset == offer.offset,
            "remote source chunk differs from the offered prefix offset",
        )?;
        let selected = SourcePrefix {
            offset,
            sha256: digest(&offer.sha256)?,
        };
        let snapshots = self
            .prefixes
            .as_mut()
            .ok_or_else(|| invalid("remote source prefix has no snapshot owner"))?;
        let mut imported = 0;
        let mut hash = Sha256::new();
        while imported < offset {
            checkpoint(cancelled)?;
            let bytes = snapshots.read_chunk(path, imported, MAX_SOURCE_CHUNK)?;
            hash.update(&bytes);
            self.receiver
                .write_chunk(path, imported, &bytes, Sha256::digest(&bytes).into())?;
            imported += bytes.len() as u64;
        }
        checkpoint(cancelled)?;
        require(
            imported == offset && <[u8; 32]>::from(hash.finalize()) == selected.sha256,
            "remote source prefix snapshot differs from its offer",
        )?;
        Ok(selected)
    }

    fn ensure_checkpoints(&mut self) -> io::Result<()> {
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
        Ok(())
    }

    fn begin_prefix_checkpoint(&mut self, path: &str, selected: SourcePrefix) -> io::Result<()> {
        self.ensure_checkpoints()?;
        if let Some(writer) = &mut self.checkpoints {
            let snapshots = &mut self.prefixes;
            match writer.begin_prefix(&self.receiver, path, selected, |offset, count| {
                snapshots
                    .as_mut()
                    .ok_or_else(|| invalid("remote source prefix has no snapshot owner"))?
                    .read_chunk(path, offset, count)
            }) {
                Ok(()) => {}
                Err(RememberError::Cache(error)) => {
                    cache_warning("prefix-checkpoint", &error);
                    self.checkpoints = None;
                }
                Err(RememberError::Source(error)) => return Err(error),
            }
        }
        Ok(())
    }

    fn remember_completed_file(&mut self, path: &str) -> io::Result<()> {
        self.ensure_checkpoints()?;
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
            2,
            "complete objects and optional partial bytes share the same bounded cache"
        );
        drop(first);

        let (next_owner, mut next) = prepared(&pool, &manifest);
        assert_eq!(next.plan().missing_files, vec![1]);
        assert_eq!(next.plan().prefix_for(1).unwrap().offset, 3);
        assert_eq!(
            fs::metadata(next_owner.path().join("source/b.rs"))
                .unwrap()
                .len(),
            0,
            "an offered prefix cannot populate execution inputs before selection"
        );
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

    fn retain_prefix(
        pool: &RemoteSourceCache,
        manifest: &SourceManifest,
        path: &str,
        bytes: &[u8],
    ) {
        let (_owner, mut input) = prepared(pool, manifest);
        input.begin_transfer(deadline()).unwrap();
        let mut offset = 0;
        for chunk in bytes.chunks(MAX_SOURCE_CHUNK) {
            input
                .write_chunk(path, offset, chunk, Sha256::digest(chunk).into(), || false)
                .unwrap();
            offset += chunk.len() as u64;
        }
        assert!(input.receiver.sealed_root().is_none());
    }

    #[test]
    fn partial_upload_reopens_with_unaligned_tail_only_transfer_and_exact_retries() {
        let parent = private();
        let bytes = vec![17_u8; MAX_SOURCE_CHUNK + 131];
        let offset = MAX_SOURCE_CHUNK + 37;
        let pool = RemoteSourceCache::new(parent.path(), (bytes.len() * 2) as u64).unwrap();
        let manifest = manifest(&[("registry/cache/dependency.crate", &bytes)]);
        let path = &manifest.files()[0].path;
        retain_prefix(&pool, &manifest, path, &bytes[..offset]);

        let (owner, mut next) = prepared(&pool, &manifest);
        let offer = next.plan().prefix_for(0).unwrap();
        assert_eq!(offer.offset, offset as u64);
        assert_eq!(offer.sha256, encode_hex(&Sha256::digest(&bytes[..offset])));
        assert_eq!(
            fs::metadata(owner.path().join("source").join(path))
                .unwrap()
                .len(),
            0
        );
        next.begin_transfer(deadline()).unwrap();
        let tail = &bytes[offset..];
        for _ in 0..2 {
            next.write_chunk(
                path,
                offset as u64,
                tail,
                Sha256::digest(tail).into(),
                || false,
            )
            .unwrap();
        }
        assert_eq!(next.selected.len(), 1);
        assert!(next.receiver.sealed_root().is_none());
        let objects = objects(&pool);
        assert_eq!(objects.len(), 1);
        assert_eq!(fs::metadata(&objects[0]).unwrap().len(), bytes.len() as u64);
        let sealed = next.finish(|| false).unwrap();
        assert_eq!(
            fs::read(sealed.sealed_root().unwrap().join(path)).unwrap(),
            bytes
        );
    }

    #[test]
    fn frozen_prefix_survives_cache_replacement_between_readiness_and_selection() {
        let parent = private();
        let pool = RemoteSourceCache::new(parent.path(), 1024).unwrap();
        let bytes = b"a complete independently verified dependency";
        let manifest = manifest(&[("dependency", bytes)]);
        retain_prefix(&pool, &manifest, "dependency", &bytes[..9]);
        let (_owner, mut input) = prepared(&pool, &manifest);
        assert_eq!(input.plan().prefix_for(0).unwrap().offset, 9);
        let cached = objects(&pool).pop().unwrap();
        fs::set_permissions(&cached, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&cached, b"different").unwrap();

        input.begin_transfer(deadline()).unwrap();
        let tail = &bytes[9..];
        input
            .write_chunk("dependency", 9, tail, Sha256::digest(tail).into(), || false)
            .unwrap();
        let sealed = input.finish(|| false).unwrap();
        assert_eq!(
            fs::read(sealed.sealed_root().unwrap().join("dependency")).unwrap(),
            bytes
        );
        assert_eq!(fs::read(cached).unwrap(), bytes);
    }

    #[test]
    fn mismatching_prefix_can_restart_at_zero_but_cannot_bypass_the_full_digest() {
        let parent = private();
        let pool = RemoteSourceCache::new(parent.path(), 1024).unwrap();
        let bytes = b"complete current input";
        let manifest = manifest(&[("input.rs", bytes)]);
        retain_prefix(&pool, &manifest, "input.rs", &bytes[..7]);
        let cached = objects(&pool).pop().unwrap();
        fs::set_permissions(&cached, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&cached, b"corrupt").unwrap();

        let (_owner, mut dishonest) = prepared(&pool, &manifest);
        assert_eq!(dishonest.plan().prefix_for(0).unwrap().offset, 7);
        dishonest.begin_transfer(deadline()).unwrap();
        let tail = &bytes[7..];
        assert!(
            dishonest
                .write_chunk("input.rs", 7, tail, Sha256::digest(tail).into(), || false)
                .is_err()
        );
        assert!(dishonest.receiver.sealed_root().is_none());
        assert!(dishonest.finish(|| false).is_err());

        let (_owner, mut repair) = prepared(&pool, &manifest);
        repair.begin_transfer(deadline()).unwrap();
        send(&mut repair, "input.rs", bytes);
        let sealed = repair.finish(|| false).unwrap();
        assert_eq!(
            fs::read(sealed.sealed_root().unwrap().join("input.rs")).unwrap(),
            bytes
        );
        assert_eq!(fs::read(cached).unwrap(), bytes);
    }

    #[test]
    fn unoffered_offsets_and_other_peer_prefixes_never_select_source_bytes() {
        let parent = private();
        let pool = RemoteSourceCache::new(parent.path(), 1024).unwrap();
        let bytes = b"input with retained prefix";
        let manifest = manifest(&[("input.rs", bytes)]);
        retain_prefix(&pool, &manifest, "input.rs", &bytes[..8]);
        for offset in [3, 9] {
            let (owner, mut input) = prepared(&pool, &manifest);
            input.begin_transfer(deadline()).unwrap();
            let tail = &bytes[offset..];
            assert!(
                input
                    .write_chunk(
                        "input.rs",
                        offset as u64,
                        tail,
                        Sha256::digest(tail).into(),
                        || false
                    )
                    .is_err()
            );
            assert_eq!(
                fs::metadata(owner.path().join("source/input.rs"))
                    .unwrap()
                    .len(),
                0
            );
            assert!(input.finish(|| false).is_err());
        }

        let owner = private();
        let receiver =
            SourceReceiver::create(&owner.path().join("source"), manifest.clone()).unwrap();
        let cache = pool
            .for_peer([18; 32], Arc::new(AtomicBool::new(false)), deadline())
            .unwrap();
        let mut other = SourceInput::prepare(receiver, Some(cache), || false).unwrap();
        assert!(other.plan().prefixes.is_empty());
        other.begin_transfer(deadline()).unwrap();
        assert!(
            other
                .write_chunk(
                    "input.rs",
                    8,
                    &bytes[8..],
                    Sha256::digest(&bytes[8..]).into(),
                    || false
                )
                .is_err()
        );
        assert!(other.finish(|| false).is_err());
    }

    #[test]
    fn cancellation_during_prefix_import_poison_fences_the_operation_and_keeps_recovery_bytes() {
        let parent = private();
        let bytes = vec![29_u8; MAX_SOURCE_CHUNK * 2 + 19];
        let offset = MAX_SOURCE_CHUNK + 7;
        let pool = RemoteSourceCache::new(parent.path(), (bytes.len() * 2) as u64).unwrap();
        let manifest = manifest(&[("input", &bytes)]);
        retain_prefix(&pool, &manifest, "input", &bytes[..offset]);
        let (owner, mut input) = prepared(&pool, &manifest);
        input.begin_transfer(deadline()).unwrap();
        let path = owner.path().join("source/input");
        let tail = &bytes[offset..];
        let error = input
            .write_chunk(
                "input",
                offset as u64,
                tail,
                Sha256::digest(tail).into(),
                || fs::metadata(&path).unwrap().len() >= MAX_SOURCE_CHUNK as u64,
            )
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
        assert_eq!(fs::metadata(path).unwrap().len(), MAX_SOURCE_CHUNK as u64);
        assert!(input.failed);
        assert!(input.finish(|| false).is_err());
        let (_owner, recovered) = prepared(&pool, &manifest);
        assert_eq!(
            recovered.plan().prefix_for(0).unwrap().offset,
            offset as u64
        );
    }

    #[test]
    fn frozen_prefix_gets_one_input_budget_and_retains_shared_cancellation() {
        let parent = private();
        let pool = RemoteSourceCache::new(parent.path(), 1024).unwrap();
        let bytes = b"phase budgets protect this upload";
        let first_manifest = manifest(&[("input", bytes)]);
        retain_prefix(&pool, &first_manifest, "input", &bytes[..5]);

        let (_owner, mut input) = prepared(&pool, &first_manifest);
        // Preparation completed. Its budget can now expire while readiness
        // hands the frozen ranges to the separate fixed input phase.
        input.prefixes = input
            .prefixes
            .take()
            .map(|snapshot| snapshot.before(Instant::now()));
        let cache = input.cache.as_mut().unwrap();
        cache.cache = cache.cache.clone().before(Instant::now());
        input.begin_transfer(deadline()).unwrap();
        let tail = &bytes[5..];
        input
            .write_chunk("input", 5, tail, Sha256::digest(tail).into(), || false)
            .unwrap();
        input.finish(|| false).unwrap();

        // Use a distinct full digest so the earlier complete hit cannot hide
        // expiry or cancellation of an actually offered partial range.
        let bytes = b"other input with retained prefix";
        let manifest = manifest(&[("input", bytes)]);
        retain_prefix(&pool, &manifest, "input", &bytes[..5]);
        let (_owner, mut expired) = prepared(&pool, &manifest);
        expired.begin_transfer(Instant::now()).unwrap();
        assert!(expired.begin_transfer(deadline()).is_err());
        let tail = &bytes[5..];
        assert!(
            expired
                .write_chunk("input", 5, tail, Sha256::digest(tail).into(), || false)
                .is_err()
        );
        assert!(expired.finish(|| false).is_err());

        let owner = private();
        let receiver = SourceReceiver::create(&owner.path().join("source"), manifest).unwrap();
        let stopped = Arc::new(AtomicBool::new(false));
        let cache = pool
            .for_peer(EDGE, Arc::clone(&stopped), deadline())
            .unwrap();
        let mut cancelled = SourceInput::prepare(receiver, Some(cache), || false).unwrap();
        cancelled.begin_transfer(deadline()).unwrap();
        stopped.store(true, Ordering::Release);
        assert!(
            cancelled
                .write_chunk("input", 5, tail, Sha256::digest(tail).into(), || false)
                .is_err()
        );
        stopped.store(false, Ordering::Release);
        assert!(cancelled.finish(|| false).is_err());
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
