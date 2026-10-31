//! Verified, coordinator-local artifact bytes across distinct executions.
//!
//! These objects are transport hints, never execution results or publication
//! authority. A new authenticated result and Cargo report select every file;
//! each hit is copied into a new inode and hashed against that current manifest.
//! Cache failures are misses. Cancellation and writes to the real delivery are
//! not cache failures and must stop delivery before its receipt and ACKs.

use super::{
    CHUNK_BYTES, Item, MAX_DELIVERY_BYTES, Manifest, ResumeSource, WorkerAuthentication,
    WorkerPeer, field, invalid, is_hex, require,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

/// Default disk budget, including the one bounded incoming object.
pub const DEFAULT_ARTIFACT_CACHE_BYTES: u64 = MAX_DELIVERY_BYTES;
/// Default number of byte objects, including an incoming object during a write.
pub const DEFAULT_ARTIFACT_CACHE_ENTRIES: usize = 4096;
/// Hard bound on optional artifact byte storage across all worker scopes.
pub const MAX_ARTIFACT_CACHE_BYTES: u64 = 16 * MAX_DELIVERY_BYTES;
/// Hard bound on the inventory scanned by one optional cache writer.
pub const MAX_ARTIFACT_CACHE_ENTRIES: usize = 65_536;
const DIRECTORY: &str = "artifact-bytes-v1";
const INCOMING: &str = "incoming";

/// An optional uid-private, process-shared byte cache. Its namespace is separate
/// from action-result CAS admission. Atomic objects survive ordinary restarts;
/// missing or torn bytes after a crash always require complete cold delivery.
#[derive(Debug, Clone)]
pub struct ArtifactByteCache {
    root: PathBuf,
    max_bytes: u64,
    max_entries: usize,
    #[cfg(unix)]
    directory: std::sync::Arc<File>,
    #[cfg(unix)]
    uid: u32,
}

impl ArtifactByteCache {
    /// `parent` must already be an ordinary absolute directory owned by this uid
    /// with no group/other access. Only the dedicated child is managed/evicted.
    /// Limits are global across all worker scopes sharing this directory.
    pub fn open(parent: &Path, max_bytes: u64, max_entries: usize) -> io::Result<Self> {
        require(
            (1..=MAX_ARTIFACT_CACHE_BYTES).contains(&max_bytes)
                && (1..=MAX_ARTIFACT_CACHE_ENTRIES).contains(&max_entries),
            "artifact byte cache limits are outside their bounded range",
        )?;
        #[cfg(unix)]
        {
            use rustix::fs::{Mode, OFlags, mkdirat, open, openat};
            use std::path::Component;
            require(
                parent.is_absolute()
                    && parent.file_name().is_some()
                    && parent
                        .components()
                        .all(|part| matches!(part, Component::RootDir | Component::Normal(_))),
                "artifact byte cache parent must be a named absolute path",
            )?;
            let mut prefix = PathBuf::new();
            for part in parent.components() {
                prefix.push(part.as_os_str());
                require(
                    std::fs::symlink_metadata(&prefix)?.is_dir(),
                    "artifact byte cache path contains a link or non-directory",
                )?;
            }
            let uid = rustix::process::geteuid().as_raw();
            let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
            let parent_file = File::from(open(parent, flags, Mode::empty())?);
            unix::private_directory(&parent_file.metadata()?, uid)?;
            match mkdirat(&parent_file, DIRECTORY, Mode::from_raw_mode(0o700)) {
                Ok(()) => {}
                Err(rustix::io::Errno::EXIST) => {}
                Err(error) => return Err(error.into()),
            }
            let directory = File::from(openat(&parent_file, DIRECTORY, flags, Mode::empty())?);
            unix::private_directory(&directory.metadata()?, uid)?;
            let cache = Self {
                root: parent.join(DIRECTORY),
                max_bytes,
                max_entries,
                directory: std::sync::Arc::new(directory),
                uid,
            };
            cache.check_root()?;
            Ok(cache)
        }
        #[cfg(not(unix))]
        {
            let _ = parent;
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "artifact byte cache requires uid-private Unix storage",
            ))
        }
    }

    /// The managed namespace, not the caller's parent directory.
    pub fn root(&self) -> &Path {
        &self.root
    }
}

/// Supply local optimization policy without changing authenticated provenance,
/// operation identity, deadlines, diagnostics, or the final receipt/ACK path.
pub struct ArtifactCachePeer<'a, P: ?Sized> {
    inner: &'a mut P,
    cache: &'a ArtifactByteCache,
}

impl<'a, P: WorkerPeer + ?Sized> ArtifactCachePeer<'a, P> {
    pub fn new(inner: &'a mut P, cache: &'a ArtifactByteCache) -> Self {
        Self { inner, cache }
    }
}

impl<P: WorkerPeer + ?Sized> WorkerPeer for ArtifactCachePeer<'_, P> {
    fn send(&mut self, frame: &Value) -> io::Result<()> {
        self.inner.send(frame)
    }
    fn receive(&mut self) -> io::Result<Value> {
        self.inner.receive()
    }
    fn negotiate(&mut self, hello: &Value, grant: &Value) -> io::Result<()> {
        self.inner.negotiate(hello, grant)
    }
    fn authentication(&self) -> Option<WorkerAuthentication> {
        self.inner.authentication()
    }
    fn resume_source(&self) -> Option<&ResumeSource> {
        self.inner.resume_source()
    }
    fn artifact_byte_cache(&self) -> Option<&ArtifactByteCache> {
        Some(self.cache)
    }
    fn transfer_deadline(&self) -> Option<std::time::Instant> {
        self.inner.transfer_deadline()
    }
    fn live_continuation(&self) -> Option<&super::SealedResult> {
        self.inner.live_continuation()
    }
    fn checkpoint(&mut self) -> io::Result<()> {
        self.inner.checkpoint()
    }
}

/// A current admitted worker's stable identity, not its claimed JSON peer ID.
/// Session/generation changes do not change byte identity, but SPKI rotation and
/// worker labels isolate caches. Paths and executable modes are current policy.
pub(super) fn scope(worker: &str, authentication: WorkerAuthentication) -> String {
    let mut hasher = Sha256::new();
    field(&mut hasher, b"rabs.coordinator-artifact-byte-scope.v1");
    field(&mut hasher, worker.as_bytes());
    field(&mut hasher, &authentication.spki_sha256);
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn object_name(scope: &str, item: &Item) -> String {
    format!("{scope}-{}-{}.artifact", item.sha256, item.len)
}

/// One inventory per delivery, rather than one directory scan per Cargo file.
/// A reader or writer never waits for another process; warm readers share a
/// lease and an active writer causes a cold miss. Current manifest members are
/// eviction preferences only: names do not prove bytes and every actual hit
/// still undergoes a complete hash.
pub(super) struct CacheSession {
    cache: ArtifactByteCache,
    scope: String,
    protected: BTreeSet<String>,
    pending: PendingDelivery,
    #[cfg(unix)]
    writer: unix::WriterState,
}

#[derive(Clone, Copy, Default)]
struct PendingDelivery {
    bytes: u64,
    files: usize,
}

impl CacheSession {
    pub(super) fn new(
        cache: ArtifactByteCache,
        worker: &str,
        authentication: WorkerAuthentication,
        manifest: &Manifest,
    ) -> Self {
        let scope = scope(worker, authentication);
        let protected = manifest
            .files
            .iter()
            .map(|item| object_name(&scope, item))
            .collect();
        Self {
            cache,
            scope,
            protected,
            pending: PendingDelivery {
                bytes: manifest.total,
                files: manifest.files.len(),
            },
            #[cfg(unix)]
            writer: unix::WriterState::Unopened,
        }
    }

    /// Reserve storage for every real artifact not yet verified. Counting an
    /// in-flight partially written file in full is deliberately conservative.
    pub(super) fn completed(&mut self, item: &Item) -> io::Result<()> {
        self.pending.bytes = self
            .pending
            .bytes
            .checked_sub(item.len)
            .ok_or_else(|| invalid("artifact cache delivery byte accounting"))?;
        self.pending.files = self
            .pending
            .files
            .checked_sub(1)
            .ok_or_else(|| invalid("artifact cache delivery file accounting"))?;
        Ok(())
    }

    /// Return the hash state for a fully verified copy. An optional-cache fault
    /// rewinds only this newly created destination before cold network ranges.
    /// A checkpoint or destination-write failure never takes that fallback.
    pub(super) fn copy(
        &self,
        item: &Item,
        target: &mut File,
        mut checkpoint: impl FnMut() -> io::Result<()>,
    ) -> io::Result<Option<Sha256>> {
        checkpoint()?;
        if item.len == 0 || item.len > self.cache.max_bytes {
            return Ok(None);
        }
        #[cfg(unix)]
        {
            let name = object_name(&self.scope, item);
            let copied = (|| -> Result<Sha256, unix::HintError> {
                // Keep the object charged in the writer's namespace inventory
                // for the ENTIRE read. A writer cannot unlink leased bytes and
                // admit replacements while their old inode still consumes disk.
                // This same session's live exclusive writer is already a lease.
                let _lease = if matches!(self.writer, unix::WriterState::Open(_)) {
                    None
                } else {
                    Some(self.cache.reader()?)
                };
                let mut input = self.cache.open_object(&name)?;
                let metadata = input.metadata()?;
                require(
                    metadata.len() == item.len,
                    "artifact byte cache length mismatch",
                )?;
                let mut hasher = Sha256::new();
                let mut left = item.len;
                let mut buffer = [0_u8; CHUNK_BYTES];
                while left != 0 {
                    checkpoint().map_err(unix::HintError::Stop)?;
                    let count = usize::try_from(left.min(CHUNK_BYTES as u64))
                        .map_err(|_| invalid("artifact byte cache chunk length"))?;
                    input.read_exact(&mut buffer[..count])?;
                    target
                        .write_all(&buffer[..count])
                        .map_err(unix::HintError::Stop)?;
                    hasher.update(&buffer[..count]);
                    left -= count as u64;
                }
                checkpoint().map_err(unix::HintError::Stop)?;
                require(
                    input.read(&mut buffer[..1])? == 0
                        && input.metadata()?.len() == item.len
                        && hash_state(&hasher) == item.sha256,
                    "artifact byte cache complete digest mismatch",
                )?;
                self.cache.check_root()?;
                // Recency is only an eviction preference; never integrity proof.
                let _ = input.set_modified(std::time::SystemTime::now());
                Ok(hasher)
            })();
            match copied {
                Ok(hasher) => Ok(Some(hasher)),
                Err(unix::HintError::Stop(error)) => Err(error),
                Err(unix::HintError::Cache) => {
                    target.set_len(0)?;
                    target.seek(SeekFrom::Start(0))?;
                    Ok(None)
                }
            }
        }
        #[cfg(not(unix))]
        {
            let _ = target;
            Ok(None)
        }
    }

    /// Seed only from a file whose current full manifest digest, mode and fsync
    /// already passed. The readable handle is the receiver's original inode,
    /// never a pathname re-open or a writable hardlink into this cache.
    pub(super) fn remember(
        &mut self,
        item: &Item,
        source: &mut File,
        mut checkpoint: impl FnMut() -> io::Result<()>,
    ) -> io::Result<()> {
        checkpoint()?;
        if item.len == 0 || item.len > self.cache.max_bytes {
            return Ok(());
        }
        #[cfg(unix)]
        {
            if matches!(self.writer, unix::WriterState::Unopened) {
                self.writer =
                    match self
                        .cache
                        .writer(&self.protected, self.pending, &mut checkpoint)
                    {
                        Ok(Some(writer)) => unix::WriterState::Open(writer),
                        Ok(None) | Err(unix::HintError::Cache) => unix::WriterState::Unavailable,
                        Err(unix::HintError::Stop(error)) => return Err(error),
                    };
            }
            let unix::WriterState::Open(writer) = &mut self.writer else {
                return Ok(());
            };
            let result = self.cache.remember(
                writer,
                &object_name(&self.scope, item),
                item,
                source,
                self.pending,
                &mut checkpoint,
            );
            match result {
                Ok(()) => Ok(()),
                Err(unix::HintError::Stop(error)) => Err(error),
                Err(unix::HintError::Cache) => {
                    // Optional ENOSPC must not retain a partial cache copy that
                    // crowds out the real delivery receipt. Reclaim only the
                    // inode this writer created, while still holding its lock.
                    self.cache.discard_incoming(writer);
                    self.writer = unix::WriterState::Unavailable;
                    Ok(())
                }
            }
        }
        #[cfg(not(unix))]
        {
            let _ = source;
            Ok(())
        }
    }
}

fn hash_state(hasher: &Sha256) -> String {
    hasher
        .clone()
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(unix)]
mod unix {
    use super::*;
    use rustix::fs::{AtFlags, Mode, OFlags, fstatvfs, openat, renameat, unlinkat};
    use std::collections::BTreeMap;
    use std::fs::{Metadata, Permissions, TryLockError};
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::time::SystemTime;

    pub(super) enum HintError {
        Cache,
        Stop(io::Error),
    }
    impl From<io::Error> for HintError {
        fn from(_error: io::Error) -> Self {
            Self::Cache
        }
    }

    pub(super) fn private_directory(metadata: &Metadata, uid: u32) -> io::Result<()> {
        require(
            metadata.is_dir() && metadata.uid() == uid && metadata.mode() & 0o077 == 0,
            "artifact byte cache directory is not uid-private",
        )
    }

    fn private_file(metadata: &Metadata, uid: u32) -> io::Result<()> {
        require(
            metadata.is_file()
                && metadata.uid() == uid
                && metadata.nlink() == 1
                && metadata.mode() & 0o077 == 0,
            "artifact byte cache member is not an ordinary uid-private file",
        )
    }

    fn owned_name(name: &str) -> bool {
        let mut pieces = name.split('-');
        let Some(scope) = pieces.next() else {
            return false;
        };
        let Some(sha256) = pieces.next() else {
            return false;
        };
        let Some(length) = pieces
            .next()
            .and_then(|value| value.strip_suffix(".artifact"))
        else {
            return false;
        };
        is_hex(scope, 64)
            && is_hex(sha256, 64)
            && pieces.next().is_none()
            && length.parse::<u64>().is_ok_and(|length_value| {
                (1..=MAX_DELIVERY_BYTES).contains(&length_value)
                    && length_value.to_string() == length
            })
    }

    pub(super) struct Lock(File);
    impl Drop for Lock {
        fn drop(&mut self) {
            // Explicit unlock also releases the lease if an unrelated forked
            // child temporarily retains a copy of the underlying descriptor.
            let _ = self.0.unlock();
        }
    }

    struct Entry {
        bytes: u64,
        used: SystemTime,
        protected: bool,
        admitted: bool,
    }

    pub(super) struct Writer {
        _lock: Lock,
        entries: BTreeMap<String, Entry>,
        total: u64,
        incoming: Option<(u64, u64)>,
        protected_bytes: u64,
        protected_entries: usize,
        evictable: BTreeSet<(SystemTime, String)>,
    }

    pub(super) enum WriterState {
        Unopened,
        Unavailable,
        Open(Writer),
    }

    /// Reserve a fully rounded receipt and an extra directory block before an
    /// optional copy. Otherwise a successful cache write could exhaust space
    /// immediately before delivery.json. Unknown/overflowing geometry skips the
    /// optimization; unrelated concurrent disk users are outside this lock.
    pub(super) fn has_copy_space(
        blocks: u64,
        block_bytes: u64,
        bytes: u64,
        pending: PendingDelivery,
    ) -> bool {
        if block_bytes == 0 {
            return false;
        }
        let available = blocks.checked_mul(block_bytes);
        let rounded = |bytes: u64| {
            bytes
                .checked_add(block_bytes - 1)
                .and_then(|bytes| (bytes / block_bytes).checked_mul(block_bytes))
        };
        // Bound the sum of per-file allocation rounding without rescanning the
        // manifest for every admission. Empty/pending files also retain credit.
        let pending = (block_bytes - 1)
            .checked_mul(pending.files as u64)
            .and_then(|rounding| pending.bytes.checked_add(rounding))
            .and_then(rounded);
        let required = rounded(bytes)
            .zip(rounded(super::super::MAX_FRAME_BYTES as u64))
            .and_then(|(object, receipt)| object.checked_add(receipt))
            .zip(pending)
            .and_then(|(bytes, pending)| bytes.checked_add(pending))
            .and_then(|bytes| bytes.checked_add(block_bytes));
        available
            .zip(required)
            .is_some_and(|(available, required)| available >= required)
    }

    /// Fixed inode pools need room for pending outputs, the cache's incoming
    /// file, and delivery.json. Some filesystems report no fixed pool at all;
    /// in that case byte headroom remains the available capacity constraint.
    pub(super) fn has_copy_inodes(total: u64, free: u64, available: u64, pending: u64) -> bool {
        let Some(required) = pending.checked_add(2) else {
            return false;
        };
        if total == 0 {
            return true;
        }
        let available = free.min(available);
        available <= total && available >= required
    }

    impl ArtifactByteCache {
        pub(super) fn check_root(&self) -> io::Result<()> {
            let named = std::fs::symlink_metadata(&self.root)?;
            let held = self.directory.metadata()?;
            private_directory(&named, self.uid)?;
            require(
                (named.dev(), named.ino()) == (held.dev(), held.ino()),
                "artifact byte cache root changed",
            )
        }

        fn open_file(&self, name: &str, flags: OFlags) -> io::Result<File> {
            let file = File::from(openat(
                self.directory.as_ref(),
                name,
                flags | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                Mode::from_raw_mode(0o600),
            )?);
            private_file(&file.metadata()?, self.uid)?;
            Ok(file)
        }

        pub(super) fn open_object(&self, name: &str) -> io::Result<File> {
            self.check_root()?;
            self.open_file(name, OFlags::RDONLY)
        }

        /// Concurrent warm readers share one nonblocking lease. An active
        /// writer causes a cold miss instead of waiting for its network phase.
        pub(super) fn reader(&self) -> Result<Lock, HintError> {
            self.check_root()?;
            // A populated cache already has its stable lock. An empty-cache
            // lookup must not allocate the receipt's last available inode.
            let file = self.open_file("lock", OFlags::RDWR)?;
            require(
                file.metadata()?.len() == 0,
                "artifact byte cache lock is not empty",
            )?;
            match file.try_lock_shared() {
                Ok(()) => Ok(Lock(file)),
                Err(TryLockError::WouldBlock) => Err(HintError::Cache),
                Err(TryLockError::Error(error)) => Err(error.into()),
            }
        }

        fn unlink(&self, name: &str) -> io::Result<()> {
            unlinkat(self.directory.as_ref(), name, AtFlags::empty()).map_err(Into::into)
        }

        pub(super) fn writer(
            &self,
            protected: &BTreeSet<String>,
            pending: PendingDelivery,
            checkpoint: &mut impl FnMut() -> io::Result<()>,
        ) -> Result<Option<Writer>, HintError> {
            self.check_root()?;
            let file = match self.open_file("lock", OFlags::RDWR) {
                Ok(file) => file,
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    let capacity = fstatvfs(self.directory.as_ref()).map_err(io::Error::from)?;
                    let pending_with_lock = (pending.files as u64)
                        .checked_add(1)
                        .ok_or_else(|| invalid("artifact cache lock inode accounting"))?;
                    if !has_copy_space(capacity.f_bavail, capacity.f_frsize, 0, pending)
                        || !has_copy_inodes(
                            capacity.f_files,
                            capacity.f_ffree,
                            capacity.f_favail,
                            pending_with_lock,
                        )
                    {
                        return Ok(None);
                    }
                    self.open_file("lock", OFlags::RDWR | OFlags::CREATE)?
                }
                Err(error) => return Err(error.into()),
            };
            require(
                file.metadata()?.len() == 0,
                "artifact byte cache lock is not empty",
            )?;
            let lock = match file.try_lock() {
                Ok(()) => Lock(file),
                Err(TryLockError::WouldBlock) => return Ok(None),
                Err(TryLockError::Error(error)) => return Err(error.into()),
            };
            checkpoint().map_err(HintError::Stop)?;
            // Only this namespace's one ordinary scratch inode is reclaimable.
            // A failed cache write never creates another incoming filename.
            match self.open_file(INCOMING, OFlags::RDONLY) {
                Ok(file) => {
                    require(
                        file.metadata()?.len() <= MAX_DELIVERY_BYTES,
                        "artifact cache incoming file exceeds its bound",
                    )?;
                    self.unlink(INCOMING)?;
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
            let mut entries = BTreeMap::new();
            let mut total = 0_u64;
            let mut protected_bytes = 0_u64;
            let mut protected_entries = 0_usize;
            let mut evictable = BTreeSet::new();
            for entry in std::fs::read_dir(&self.root)? {
                checkpoint().map_err(HintError::Stop)?;
                let entry = entry?;
                let name = entry.file_name();
                if name == "lock" {
                    continue;
                }
                let name = name
                    .to_str()
                    .ok_or_else(|| invalid("non-UTF8 artifact cache member"))?;
                require(
                    entries.len() < MAX_ARTIFACT_CACHE_ENTRIES && owned_name(name),
                    "artifact byte cache inventory is not an owned bounded set",
                )?;
                let metadata = self.open_file(name, OFlags::RDONLY)?.metadata()?;
                require(
                    metadata.len() <= MAX_DELIVERY_BYTES,
                    "oversized artifact byte cache object",
                )?;
                total = total
                    .checked_add(metadata.len())
                    .filter(|total| *total <= MAX_ARTIFACT_CACHE_BYTES)
                    .ok_or_else(|| {
                        invalid("artifact byte cache inventory exceeds its byte bound")
                    })?;
                let keep = protected.contains(name);
                let used = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH);
                if keep {
                    protected_bytes += metadata.len();
                    protected_entries += 1;
                } else {
                    evictable.insert((used, name.to_owned()));
                }
                entries.insert(
                    name.to_owned(),
                    Entry {
                        bytes: metadata.len(),
                        used,
                        protected: keep,
                        admitted: false,
                    },
                );
            }
            self.check_root()?;
            Ok(Some(Writer {
                _lock: lock,
                entries,
                total,
                incoming: None,
                protected_bytes,
                protected_entries,
                evictable,
            }))
        }

        pub(super) fn discard_incoming(&self, writer: &mut Writer) {
            let Some(identity) = writer.incoming else {
                return;
            };
            let reclaim = (|| -> io::Result<()> {
                let file = self.open_file(INCOMING, OFlags::RDONLY)?;
                let metadata = file.metadata()?;
                require(
                    (metadata.dev(), metadata.ino()) == identity
                        && metadata.len() <= MAX_DELIVERY_BYTES,
                    "artifact cache incoming inode changed",
                )?;
                self.unlink(INCOMING)
            })();
            if reclaim.is_ok() {
                writer.incoming = None;
            }
        }

        fn evict(&self, writer: &mut Writer, name: &str) -> io::Result<()> {
            self.unlink(name)?;
            let entry = writer
                .entries
                .remove(name)
                .ok_or_else(|| invalid("artifact cache inventory changed"))?;
            writer.total -= entry.bytes;
            if entry.protected {
                writer.protected_bytes -= entry.bytes;
                writer.protected_entries -= 1;
            } else {
                writer.evictable.remove(&(entry.used, name.to_owned()));
            }
            Ok(())
        }

        pub(super) fn remember(
            &self,
            writer: &mut Writer,
            name: &str,
            item: &Item,
            source: &mut File,
            pending: PendingDelivery,
            checkpoint: &mut impl FnMut() -> io::Result<()>,
        ) -> Result<(), HintError> {
            self.check_root()?;
            // Two paths may name one object while both cold ranges are already
            // in flight. A verified admission by THIS held writer need not copy
            // the same bytes again. Existing filenames alone never count here.
            if writer.entries.get(name).is_some_and(|entry| entry.admitted) {
                return Ok(());
            }
            // Avoid sacrificing later hits or this delivery's earlier admissions
            // for a projection that cannot fit. A useful subset remains warm.
            // Maintain these totals with the single bounded inventory; scanning
            // all cached files for EVERY Cargo output would make seeding quadratic.
            let replaced = writer.entries.get(name).filter(|entry| entry.protected);
            let protected_bytes = writer.protected_bytes - replaced.map_or(0, |entry| entry.bytes);
            let protected_entries = writer.protected_entries - usize::from(replaced.is_some());
            if protected_entries >= self.max_entries
                || protected_bytes
                    .checked_add(item.len)
                    .is_none_or(|sum| sum > self.max_bytes)
            {
                return Ok(());
            }
            let capacity = fstatvfs(self.directory.as_ref()).map_err(io::Error::from)?;
            if !has_copy_space(capacity.f_bavail, capacity.f_frsize, item.len, pending)
                || !has_copy_inodes(
                    capacity.f_files,
                    capacity.f_ffree,
                    capacity.f_favail,
                    pending.files as u64,
                )
            {
                return Ok(());
            }
            // A corrupt same-key object must be repairable after a cold fetch.
            if writer.entries.contains_key(name) {
                self.evict(writer, name)?;
            }
            while writer.entries.len() >= self.max_entries
                || writer
                    .total
                    .checked_add(item.len)
                    .is_none_or(|sum| sum > self.max_bytes)
            {
                checkpoint().map_err(HintError::Stop)?;
                let victim = writer
                    .evictable
                    .first()
                    .map(|(_, name)| name.clone())
                    .ok_or_else(|| invalid("artifact byte cache has no eviction credit"))?;
                self.evict(writer, &victim)?;
            }
            let before = source.metadata().map_err(HintError::Stop)?;
            private_file(&before, self.uid).map_err(HintError::Stop)?;
            require(before.len() == item.len, "verified delivery length changed")
                .map_err(HintError::Stop)?;
            source.seek(SeekFrom::Start(0)).map_err(HintError::Stop)?;
            let mut target =
                self.open_file(INCOMING, OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL)?;
            let incoming = target.metadata()?;
            writer.incoming = Some((incoming.dev(), incoming.ino()));
            let mut hasher = Sha256::new();
            let mut left = item.len;
            let mut buffer = [0_u8; CHUNK_BYTES];
            while left != 0 {
                checkpoint().map_err(HintError::Stop)?;
                let count = usize::try_from(left.min(CHUNK_BYTES as u64))
                    .map_err(|_| invalid("artifact cache seed chunk length"))?;
                source
                    .read_exact(&mut buffer[..count])
                    .map_err(HintError::Stop)?;
                target.write_all(&buffer[..count])?;
                hasher.update(&buffer[..count]);
                left -= count as u64;
            }
            checkpoint().map_err(HintError::Stop)?;
            let after = source.metadata().map_err(HintError::Stop)?;
            require(
                source.read(&mut buffer[..1]).map_err(HintError::Stop)? == 0
                    && (
                        before.dev(),
                        before.ino(),
                        before.len(),
                        before.mtime(),
                        before.mtime_nsec(),
                        before.ctime(),
                        before.ctime_nsec(),
                        before.nlink(),
                        before.mode(),
                    ) == (
                        after.dev(),
                        after.ino(),
                        after.len(),
                        after.mtime(),
                        after.mtime_nsec(),
                        after.ctime(),
                        after.ctime_nsec(),
                        after.nlink(),
                        after.mode(),
                    )
                    && hash_state(&hasher) == item.sha256,
                "verified delivery changed while seeding artifact bytes",
            )
            .map_err(HintError::Stop)?;
            target.set_permissions(Permissions::from_mode(0o400))?;
            drop(target);
            // Cache persistence is optional. No fsync here is a result receipt
            // or ACK frontier; a crash-torn object is rejected by copy's hash.
            renameat(
                self.directory.as_ref(),
                INCOMING,
                self.directory.as_ref(),
                name,
            )
            .map_err(io::Error::from)?;
            writer.incoming = None;
            writer.total += item.len;
            writer.protected_bytes += item.len;
            writer.protected_entries += 1;
            writer.entries.insert(
                name.to_owned(),
                Entry {
                    bytes: item.len,
                    used: SystemTime::now(),
                    protected: true,
                    admitted: true,
                },
            );
            Ok(())
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    // Storage-layer tests; the receiver tests independently exercise current
    // execution/report/ACK admission through actual files and scripted peers.
    fn fixture(bytes: u64, entries: usize) -> (tempfile::TempDir, ArtifactByteCache) {
        let parent = tempfile::tempdir().unwrap();
        fs::set_permissions(parent.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let cache = ArtifactByteCache::open(parent.path(), bytes, entries).unwrap();
        (parent, cache)
    }

    fn item(bytes: &[u8]) -> Item {
        Item {
            name: "current-output".into(),
            len: bytes.len() as u64,
            sha256: super::super::hash(bytes),
            executable: false,
        }
    }

    fn session(cache: &ArtifactByteCache, items: &[Item]) -> CacheSession {
        CacheSession::new(
            cache.clone(),
            "worker",
            WorkerAuthentication {
                spki_sha256: [11; 32],
                session_id: 1,
                identity_generation: 1,
            },
            &Manifest {
                files: items.to_vec(),
                sha256: String::new(),
                total: items.iter().map(|item| item.len).sum(),
            },
        )
    }

    fn source(bytes: &[u8]) -> tempfile::NamedTempFile {
        let mut source = tempfile::NamedTempFile::new().unwrap();
        source.write_all(bytes).unwrap();
        source
    }

    fn seed(cache: &ArtifactByteCache, bytes: &[u8]) {
        let item = item(bytes);
        let mut source = source(bytes);
        session(cache, std::slice::from_ref(&item))
            .remember(&item, source.as_file_mut(), || Ok(()))
            .unwrap();
    }

    fn load(cache: &ArtifactByteCache, bytes: &[u8]) -> Option<Vec<u8>> {
        let item = item(bytes);
        let mut target = tempfile::NamedTempFile::new().unwrap();
        session(cache, std::slice::from_ref(&item))
            .copy(&item, target.as_file_mut(), || Ok(()))
            .unwrap()?;
        target.seek(SeekFrom::Start(0)).unwrap();
        let mut actual = Vec::new();
        target.read_to_end(&mut actual).unwrap();
        Some(actual)
    }

    fn inventory(cache: &ArtifactByteCache) -> (u64, usize) {
        let entries: Vec<_> = fs::read_dir(cache.root())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                path.extension()
                    .is_some_and(|extension| extension == "artifact")
            })
            .collect();
        (
            entries
                .iter()
                .map(|path| fs::metadata(path).unwrap().len())
                .sum(),
            entries.len(),
        )
    }

    #[test]
    fn byte_and_entry_budgets_evict_only_owned_objects() {
        let (_parent, cache) = fixture(9, 2);
        seed(&cache, b"aaaa");
        seed(&cache, b"bbbb");
        assert_eq!(inventory(&cache), (8, 2));
        seed(&cache, b"cccccccc");
        assert_eq!(inventory(&cache), (8, 1));
        assert_eq!(load(&cache, b"cccccccc"), Some(b"cccccccc".to_vec()));
        assert_eq!(load(&cache, b"aaaa"), None);
        assert_eq!(load(&cache, b"bbbb"), None);
        let (_parent, cache) = fixture(1024, 1);
        seed(&cache, b"aaaa");
        seed(&cache, b"bbbbb");
        assert_eq!(inventory(&cache), (5, 1));
        assert_eq!(load(&cache, b"aaaa"), None);
        assert_eq!(load(&cache, b"bbbbb"), Some(b"bbbbb".to_vec()));
    }

    #[test]
    fn optional_copies_leave_rounded_receipt_space() {
        // A 4097-byte object occupies two allocation blocks; the full receipt
        // needs 256 and its directory entry gets one conservative extra block.
        let complete = PendingDelivery::default();
        assert!(!unix::has_copy_space(258, 4096, 4097, complete));
        assert!(unix::has_copy_space(259, 4096, 4097, complete));
        assert!(!unix::has_copy_space(257, 4096, 1, complete));
        assert!(unix::has_copy_space(258, 4096, 1, complete));
        assert!(!unix::has_copy_space(u64::MAX, 4096, 1, complete));
        assert!(!unix::has_copy_space(u64::MAX, 1, u64::MAX, complete));
        assert!(!unix::has_copy_space(u64::MAX, 0, 1, complete));
        let pending = PendingDelivery {
            bytes: 4097,
            files: 1,
        };
        assert!(!unix::has_copy_space(260, 4096, 4097, pending));
        assert!(unix::has_copy_space(261, 4096, 4097, pending));
    }

    #[test]
    fn optional_copies_reserve_inodes_for_pending_outputs_and_receipt() {
        assert!(!unix::has_copy_inodes(100, 1, 1, 0));
        assert!(unix::has_copy_inodes(100, 2, 2, 0));
        // The first writer also reserves the stable lock's new inode.
        assert!(!unix::has_copy_inodes(100, 2, 2, 1));
        assert!(unix::has_copy_inodes(100, 3, 3, 1));
        assert!(!unix::has_copy_inodes(100, 5, 4, 3));
        assert!(unix::has_copy_inodes(100, 5, 5, 3));
        assert!(!unix::has_copy_inodes(100, 0, 0, 0));
        assert!(!unix::has_copy_inodes(100, 5, 5, u64::MAX));
        assert!(!unix::has_copy_inodes(100, u64::MAX, u64::MAX, 0));
        assert!(unix::has_copy_inodes(0, 0, 0, 3));
    }

    #[test]
    fn one_inventory_tracks_replacement_eviction_and_same_delivery_admissions() {
        let (_parent, cache) = fixture(8, 2);
        seed(&cache, b"aaaa");
        seed(&cache, b"bbbb");
        let a = item(b"aaaa");
        let c = item(b"cccc");
        let d = item(b"dddd");
        let mut session = session(&cache, &[a.clone(), c.clone(), d.clone()]);
        let a_path = cache.root().join(object_name(&session.scope, &a));
        fs::set_permissions(&a_path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&a_path, b"bad!").unwrap();
        let mut a_source = source(b"aaaa");
        session
            .remember(&a, a_source.as_file_mut(), || Ok(()))
            .unwrap();
        let held = File::open(&a_path).unwrap();
        let admitted = held.metadata().unwrap();
        let mut duplicate = source(b"aaaa");
        session
            .remember(&a, duplicate.as_file_mut(), || Ok(()))
            .unwrap();
        let same = fs::metadata(&a_path).unwrap();
        assert_eq!((admitted.dev(), admitted.ino()), (same.dev(), same.ino()));
        let mut c_source = source(b"cccc");
        session
            .remember(&c, c_source.as_file_mut(), || Ok(()))
            .unwrap();
        let mut d_source = source(b"dddd");
        session
            .remember(&d, d_source.as_file_mut(), || Ok(()))
            .unwrap();
        let mut target = tempfile::NamedTempFile::new().unwrap();
        assert!(
            session
                .copy(&a, target.as_file_mut(), || Ok(()))
                .unwrap()
                .is_some()
        );
        drop(session); // other sessions may now acquire shared reader leases
        assert_eq!(inventory(&cache), (8, 2));
        assert_eq!(load(&cache, b"aaaa"), Some(b"aaaa".to_vec()));
        assert_eq!(load(&cache, b"cccc"), Some(b"cccc".to_vec()));
        assert_eq!(load(&cache, b"bbbb"), None);
        assert_eq!(load(&cache, b"dddd"), None);
    }

    #[test]
    fn oversized_projection_preserves_later_hits_and_unrelated_entries() {
        let (_parent, cache) = fixture(8, 2);
        seed(&cache, b"aaaa");
        seed(&cache, b"zzzz");
        let large = item(b"bbbbbbbb");
        let later_hit = item(b"aaaa");
        let mut source = source(b"bbbbbbbb");
        session(&cache, &[large.clone(), later_hit])
            .remember(&large, source.as_file_mut(), || Ok(()))
            .unwrap();
        assert_eq!(inventory(&cache), (8, 2));
        assert_eq!(load(&cache, b"aaaa"), Some(b"aaaa".to_vec()));
        assert_eq!(load(&cache, b"zzzz"), Some(b"zzzz".to_vec()));
        assert_eq!(load(&cache, b"bbbbbbbb"), None);
    }

    #[test]
    fn contended_writer_skips_admission_and_uses_cold_reads_without_waiting() {
        let (_parent, cache) = fixture(1024, 4);
        seed(&cache, b"aaaa");
        let lock = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(cache.root().join("lock"))
            .unwrap();
        lock.try_lock().unwrap();
        seed(&cache, b"bbbb");
        assert_eq!(inventory(&cache), (4, 1));
        assert_eq!(load(&cache, b"aaaa"), None);
        assert_eq!(load(&cache, b"bbbb"), None);
        lock.unlock().unwrap();
        assert_eq!(load(&cache, b"aaaa"), Some(b"aaaa".to_vec()));
        seed(&cache, b"bbbb");
        assert_eq!(load(&cache, b"bbbb"), Some(b"bbbb".to_vec()));
    }

    #[test]
    fn active_reader_keeps_its_inode_charged_and_other_readers_can_share() {
        use std::sync::mpsc;
        use std::time::Duration;

        let old = vec![17; CHUNK_BYTES * 2 + 7];
        let new = vec![29; old.len()];
        let (_parent, cache) = fixture(old.len() as u64, 1);
        seed(&cache, &old);
        let (paused_tx, paused_rx) = mpsc::sync_channel(1);
        let (release_tx, release_rx) = mpsc::sync_channel(1);
        std::thread::scope(|threads| {
            let held_cache = cache.clone();
            let expected = item(&old);
            let reader = threads.spawn(move || {
                let session = session(&held_cache, std::slice::from_ref(&expected));
                let mut target = tempfile::NamedTempFile::new().unwrap();
                let target_path = target.path().to_path_buf();
                let mut paused = false;
                assert!(
                    session
                        .copy(&expected, target.as_file_mut(), || {
                            if !paused && fs::metadata(&target_path)?.len() >= CHUNK_BYTES as u64 {
                                paused = true;
                                paused_tx.send(()).unwrap();
                                release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                            }
                            Ok(())
                        })
                        .unwrap()
                        .is_some()
                );
                fs::read(target_path).unwrap()
            });
            paused_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            // This is another cache session/open file description. Its writer
            // cannot unlink the paused reader's inode and consume its credit.
            seed(&cache, &new);
            assert_eq!(inventory(&cache), (old.len() as u64, 1));
            assert_eq!(load(&cache, &new), None);
            assert_eq!(load(&cache, &old), Some(old.clone()));
            release_tx.send(()).unwrap();
            assert_eq!(reader.join().unwrap(), old);
        });
        seed(&cache, &new);
        assert_eq!(inventory(&cache), (new.len() as u64, 1));
        assert_eq!(load(&cache, &old), None);
        assert_eq!(load(&cache, &new), Some(new));
    }

    #[test]
    fn interrupted_cache_population_stops_and_leaves_only_one_reclaimable_partial() {
        let bytes = vec![37; CHUNK_BYTES * 2 + 17];
        let (_parent, cache) = fixture(bytes.len() as u64, 1);
        let item = item(&bytes);
        let mut source = source(&bytes);
        let error = session(&cache, std::slice::from_ref(&item))
            .remember(&item, source.as_file_mut(), || {
                if fs::metadata(cache.root().join(INCOMING))
                    .is_ok_and(|metadata| metadata.len() >= CHUNK_BYTES as u64)
                {
                    Err(io::Error::new(
                        io::ErrorKind::Interrupted,
                        "cancelled during cache write",
                    ))
                } else {
                    Ok(())
                }
            })
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
        assert_eq!(inventory(&cache), (0, 0));
        assert_eq!(
            fs::metadata(cache.root().join(INCOMING)).unwrap().len(),
            CHUNK_BYTES as u64
        );
        seed(&cache, &bytes);
        assert_eq!(inventory(&cache), (bytes.len() as u64, 1));
        assert!(!cache.root().join(INCOMING).exists());
        assert_eq!(load(&cache, &bytes), Some(bytes));
    }

    #[test]
    fn unknown_namespace_member_refuses_writes_without_evicting_healthy_bytes() {
        let (_parent, cache) = fixture(4, 1);
        seed(&cache, b"aaaa");
        let unknown = cache.root().join("operator-notes");
        fs::write(&unknown, b"retain").unwrap();
        seed(&cache, b"bbbb");
        assert_eq!(inventory(&cache), (4, 1));
        assert_eq!(fs::read(&unknown).unwrap(), b"retain");
        assert_eq!(load(&cache, b"aaaa"), Some(b"aaaa".to_vec()));
        assert_eq!(load(&cache, b"bbbb"), None);
    }

    #[test]
    fn optional_publish_failure_reclaims_only_its_own_partial_cache_inode() {
        let (_parent, cache) = fixture(1024, 4);
        seed(&cache, b"aaaa");
        let expected = item(b"bbbb");
        let mut session = session(&cache, std::slice::from_ref(&expected));
        let obstruction = cache.root().join(object_name(&session.scope, &expected));
        let mut source = source(b"bbbb");
        let mut obstructed = false;
        session
            .remember(&expected, source.as_file_mut(), || {
                if !obstructed && cache.root().join(INCOMING).exists() {
                    fs::create_dir(&obstruction)?;
                    obstructed = true;
                }
                Ok(())
            })
            .unwrap();
        assert!(obstructed);
        assert!(
            obstruction.is_dir(),
            "unknown namespace entries must be retained"
        );
        assert!(
            !cache.root().join(INCOMING).exists(),
            "optional failure retained disk pressure"
        );
        assert_eq!(load(&cache, b"aaaa"), Some(b"aaaa".to_vec()));
        assert_eq!(load(&cache, b"bbbb"), None);
    }

    #[test]
    fn changed_verified_delivery_is_a_failure_not_an_optional_cache_fault() {
        let (_parent, cache) = fixture(1024, 4);
        let expected = item(b"good");
        let mut source = source(b"evil");
        let error = session(&cache, std::slice::from_ref(&expected))
            .remember(&expected, source.as_file_mut(), || Ok(()))
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(inventory(&cache), (0, 0));
        assert_eq!(load(&cache, b"good"), None);
    }

    #[test]
    fn cache_objects_are_private_distinct_inodes_and_invalid_roots_are_refused() {
        let (parent, cache) = fixture(1024, 4);
        let bytes = b"private independent bytes";
        let expected = item(bytes);
        let mut source = source(bytes);
        let original = source.as_file().metadata().unwrap();
        session(&cache, std::slice::from_ref(&expected))
            .remember(&expected, source.as_file_mut(), || Ok(()))
            .unwrap();
        let object = fs::read_dir(cache.root())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| {
                path.extension()
                    .is_some_and(|extension| extension == "artifact")
            })
            .unwrap();
        let cached = fs::metadata(object).unwrap();
        assert_ne!(
            (original.dev(), original.ino()),
            (cached.dev(), cached.ino())
        );
        assert_eq!(cached.nlink(), 1);
        assert_eq!(cached.mode() & 0o777, 0o400);
        assert_eq!(cached.uid(), rustix::process::geteuid().as_raw());
        assert!(ArtifactByteCache::open(parent.path(), 0, 1).is_err());
        assert!(ArtifactByteCache::open(parent.path(), 1, 0).is_err());
        fs::set_permissions(parent.path(), fs::Permissions::from_mode(0o755)).unwrap();
        assert!(ArtifactByteCache::open(parent.path(), 1, 1).is_err());
    }
}
