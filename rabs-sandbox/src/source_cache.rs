//! Private, bounded reuse of uploaded and produced bytes, not action-cache authority.
//!
//! Every hit is read and SHA-256 verified before it can populate a fresh source
//! receiver. Executions never share writable inodes with this cache. Cache loss,
//! eviction, corruption, and a busy writer only cost another source upload.
//! Worker caches retain their existing trusted-domain namespace and optional
//! execution projection pool. A byte-only owner may additionally derive scoped
//! views from an authenticated peer key: those views share one inventory, writer
//! and aggregate budget while never reading another peer's objects.

use crate::source_transfer::{
    MAX_SOURCE_BYTES, MAX_SOURCE_CHUNK, SOURCE_PROJECTION_PREFIX, SourceCheckpointError,
    SourceFile, SourceManifest, SourceProjectionPool, SourceReceiver,
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Read, Seek, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

/// Retain one maximum-size source/dependency projection by default.
pub const DEFAULT_SOURCE_CACHE_BYTES: u64 = MAX_SOURCE_BYTES;
/// Explicit disk bound, independent of the maximum size of one input object.
pub const MAX_SOURCE_CACHE_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const MAX_FILES: usize = 4096;
const MAX_FILE_BYTES: u64 = MAX_SOURCE_BYTES;
const INCOMING: &str = "incoming";
const MIN_PROJECTION_CACHE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_PROJECTION_IMAGES: usize = 64;
const MAX_PROJECTION_MEMBERS: usize = 4 * MAX_FILES;
const WRITER_FREE: u8 = 0;
const WRITER_HELD: u8 = 1;
const WRITER_POISONED: u8 = 2;
// Post-completion optimization must not spend the executor's potentially
// minutes-long remaining allowance before delivering its captured result.
const PRODUCED_INPUT_BUDGET: Duration = Duration::from_millis(250);

#[derive(Clone, Copy, PartialEq, Eq)]
enum RememberSource {
    SealedUpload,
    CapturedOutput,
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(unix)]
fn private_directory(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let meta = fs::symlink_metadata(path)?;
    if !meta.is_dir() || meta.permissions().mode() & 0o077 != 0 {
        return Err(invalid("source cache must be a private ordinary directory"));
    }
    Ok(())
}

#[cfg(not(unix))]
fn private_directory(_path: &Path) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "source reuse requires Unix",
    ))
}

fn ordinary(meta: &Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        meta.is_file() && meta.nlink() == 1
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        false
    }
}

fn same_inode(a: &Metadata, b: &Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        a.dev() == b.dev() && a.ino() == b.ino()
    }
    #[cfg(not(unix))]
    {
        let _ = (a, b);
        false
    }
}

fn same_state(a: &Metadata, b: &Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        same_inode(a, b)
            && a.len() == b.len()
            && a.mode() == b.mode()
            && a.nlink() == b.nlink()
            && a.mtime() == b.mtime()
            && a.mtime_nsec() == b.mtime_nsec()
            && a.ctime() == b.ctime()
            && a.ctime_nsec() == b.ctime_nsec()
    }
    #[cfg(not(unix))]
    {
        let _ = (a, b);
        false
    }
}

/// Only a complete, unchanged bounded inventory can rule out retained images.
/// Names suffice to refuse reuse; uncertain storage is never traversed/deleted.
fn projection_residue(parent: &Path) -> io::Result<bool> {
    private_directory(parent)?;
    let before = fs::symlink_metadata(parent)?;
    for (index, entry) in fs::read_dir(parent)?.enumerate() {
        if index >= MAX_FILES {
            return Err(invalid("source cache parent inventory exceeds its bound"));
        }
        if entry?
            .file_name()
            .as_encoded_bytes()
            .starts_with(SOURCE_PROJECTION_PREFIX.as_bytes())
        {
            return Ok(true);
        }
    }
    if !same_state(&before, &fs::symlink_metadata(parent)?) {
        return Err(invalid("source cache parent changed during inspection"));
    }
    Ok(false)
}

#[derive(Debug, Clone, Default)]
struct CacheControl {
    deadline: Option<Instant>,
    cancelled: Option<Arc<AtomicBool>>,
}

impl CacheControl {
    fn check(&self) -> io::Result<()> {
        if self
            .cancelled
            .as_ref()
            .is_some_and(|cancelled| cancelled.load(Ordering::Acquire))
        {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "source upload cancelled during cache I/O",
            ));
        }
        if self
            .deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "source upload deadline exceeded during cache I/O",
            ));
        }
        Ok(())
    }

    fn stopped(&self) -> bool {
        self.check().is_err()
    }
}

fn object_name(digest: &[u8; 32]) -> String {
    format!("{}.src", rabs_protocol::raw_bytes::encode_hex(digest))
}

fn owned_name(name: &str) -> bool {
    name.len() == 68
        && name.ends_with(".src")
        && name.as_bytes()[..64]
            .iter()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
}

/// Stream exactly the declared bytes plus one bounded EOF check. The destination
/// is private scratch, never an execution receiver. Source and storage failures
/// remain distinct so optional cache writes cannot hide a changed sealed input.
fn copy_verified(
    path: &Path,
    expected: &SourceFile,
    control: &CacheControl,
    output: &mut (impl Write + ?Sized),
) -> Result<File, RememberError> {
    control.check()?;
    if expected.len > MAX_FILE_BYTES {
        return Err(RememberError::Source(invalid(
            "source object exceeds the per-file reuse bound",
        )));
    }
    let named = fs::symlink_metadata(path).map_err(RememberError::Source)?;
    if !ordinary(&named) || named.len() != expected.len {
        return Err(RememberError::Source(invalid(
            "source object has an unexpected type or length",
        )));
    }
    #[cfg(target_os = "linux")]
    let mut input = File::from(
        rustix::fs::open(
            path,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::NONBLOCK
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(|error| RememberError::Source(error.into()))?,
    );
    #[cfg(not(target_os = "linux"))]
    let mut input = File::open(path).map_err(RememberError::Source)?;
    let before = input.metadata().map_err(RememberError::Source)?;
    if !ordinary(&before) || !same_state(&named, &before) {
        return Err(RememberError::Source(invalid(
            "source object changed while opening",
        )));
    }
    let mut hash = Sha256::new();
    let mut buffer = [0_u8; MAX_SOURCE_CHUNK];
    let mut remaining = expected.len;
    while remaining != 0 {
        control.check()?;
        let count = remaining.min(buffer.len() as u64) as usize;
        input
            .read_exact(&mut buffer[..count])
            .map_err(RememberError::Source)?;
        hash.update(&buffer[..count]);
        output.write_all(&buffer[..count])?;
        remaining -= count as u64;
    }
    control.check()?;
    if input
        .read(&mut buffer[..1])
        .map_err(RememberError::Source)?
        != 0
        || !same_state(&before, &input.metadata().map_err(RememberError::Source)?)
        || !same_state(
            &before,
            &fs::symlink_metadata(path).map_err(RememberError::Source)?,
        )
        || <[u8; 32]>::from(hash.finalize()) != expected.sha256
    {
        return Err(RememberError::Source(invalid(
            "source object content verification failed",
        )));
    }
    Ok(input)
}

/// Read an immutable captured stream through its bounded range interface. The
/// caller supplies no filesystem path to reopen. A digest/name claim cannot
/// seed the cache without independently checking every byte and exact EOF.
fn copy_verified_ranges(
    expected: &SourceFile,
    control: &CacheControl,
    read: &mut impl FnMut(&str, u64, usize) -> io::Result<Vec<u8>>,
    output: &mut dyn Write,
) -> Result<(), RememberError> {
    control.check()?;
    let mut hash = Sha256::new();
    let mut offset = 0;
    while offset < expected.len {
        control.check()?;
        let count = (expected.len - offset).min(MAX_SOURCE_CHUNK as u64) as usize;
        let bytes = read(&expected.path, offset, count).map_err(RememberError::Source)?;
        if bytes.len() != count {
            return Err(RememberError::Source(invalid(
                "captured input range differs from its declared length",
            )));
        }
        hash.update(&bytes);
        output.write_all(&bytes)?;
        offset += count as u64;
    }
    control.check()?;
    if !read(&expected.path, expected.len, 1)
        .map_err(RememberError::Source)?
        .is_empty()
        || <[u8; 32]>::from(hash.finalize()) != expected.sha256
    {
        return Err(RememberError::Source(invalid(
            "captured input content verification failed",
        )));
    }
    control.check().map_err(RememberError::Cache)
}

/// An anonymous, independently owned snapshot of a completely verified object.
/// Cache replacement after lookup cannot change these bytes. Only this type can
/// begin populating the receiver, and it never allocates an object-sized buffer.
#[derive(Debug)]
pub struct VerifiedSource {
    file: File,
    expected: SourceFile,
    control: CacheControl,
}

impl VerifiedSource {
    /// Install through the bounded private-copy path without requiring a
    /// platform clone implementation from this crate.
    pub fn install(self, receiver: &mut SourceReceiver) -> io::Result<()> {
        self.install_with_cloner(receiver, |_, _, _| false)
            .map(|_| ())
    }

    /// The optional callback may create only an independent CoW clone, never a
    /// hardlink. The receiver verifies actual destination bytes and still needs
    /// its complete final seal. Returns whether a verified clone was used.
    pub fn install_with_cloner(
        mut self,
        receiver: &mut SourceReceiver,
        cloner: impl FnOnce(&File, &File, &Path) -> bool,
    ) -> io::Result<bool> {
        self.control.check()?;
        let result = receiver.import_file_with_cloner(
            &self.expected.path,
            &mut self.file,
            || self.control.stopped(),
            cloner,
        );
        // Preserve the fixed upload timeout separately from cancellation;
        // either condition has already poisoned a partially imported receiver.
        self.control.check()?;
        result
    }

    #[cfg(test)]
    fn bytes(mut self) -> Vec<u8> {
        let mut bytes = Vec::new();
        self.file.read_to_end(&mut bytes).unwrap();
        bytes
    }
}

struct Entry {
    path: PathBuf,
    bytes: u64,
    used: SystemTime,
}

#[derive(Debug)]
struct ProjectionWriter {
    file: Arc<File>,
    local: AtomicU8,
}

/// An owned nonblocking guard can move with the source I/O task between frames.
/// It retains the process lock and preserves the previous mutex's panic poison.
struct LocalCacheWriter {
    owner: Arc<ProjectionWriter>,
}

impl Drop for LocalCacheWriter {
    fn drop(&mut self) {
        self.owner.local.store(
            if std::thread::panicking() {
                WRITER_POISONED
            } else {
                WRITER_FREE
            },
            Ordering::Release,
        );
    }
}

enum CacheWriter {
    Process { file: File },
    Local { guard: LocalCacheWriter },
}

impl CacheWriter {
    fn verify(&self, root: &Path) -> io::Result<()> {
        let file = match self {
            Self::Process { file } => file,
            Self::Local { guard } => &guard.owner.file,
        };
        let metadata = file.metadata()?;
        if !ordinary(&metadata) || !same_inode(&metadata, &fs::symlink_metadata(root.join("lock"))?)
        {
            return Err(invalid("retained source cache writer identity changed"));
        }
        Ok(())
    }
}

/// A path is only configuration, never an input capability. The cache owns a
/// dedicated namespace below an explicitly configured private directory.
#[derive(Debug, Clone)]
pub struct SourceCache {
    root: PathBuf,
    max_bytes: u64,
    max_files: usize,
    byte_only: bool,
    peer: Option<[u8; 32]>,
    control: CacheControl,
    projections: Option<Arc<SourceProjectionPool>>,
    projection_writer: Option<Arc<ProjectionWriter>>,
    quarantine: Arc<Mutex<Option<File>>>,
}

#[derive(Debug)]
pub enum RememberError {
    /// A known-invalid execution source must not be treated as optional cache I/O.
    Source(io::Error),
    Cache(io::Error),
}

/// One upload's optional writer admission. Inventory and protection are built
/// once, then each completed file is visited once. The owned nonblocking lock
/// serializes capacity accounting through seal/drop; other uploads can still
/// read verified snapshots and skip optional writes without waiting.
pub struct SourceCheckpoints {
    cache: SourceCache,
    writer: CacheWriter,
    root_identity: Metadata,
    manifest_digest: [u8; 32],
    entries: BTreeMap<PathBuf, Entry>,
    evictable: BTreeSet<(SystemTime, PathBuf)>,
    protected: BTreeMap<PathBuf, u64>,
    protected_bytes: u64,
    total: u64,
    visited: BTreeSet<String>,
}

impl SourceCheckpoints {
    fn check_owner(&self) -> io::Result<()> {
        self.cache.control.check()?;
        private_directory(&self.cache.root)?;
        if !same_inode(
            &self.root_identity,
            &fs::symlink_metadata(&self.cache.root)?,
        ) {
            return Err(invalid("source checkpoint cache directory was replaced"));
        }
        self.writer.verify(&self.cache.root)
    }

    fn remove(&mut self, path: &Path) -> io::Result<()> {
        self.check_owner()?;
        let entry = self
            .entries
            .get(path)
            .ok_or_else(|| invalid("source checkpoint inventory changed"))?;
        fs::remove_file(&entry.path)?;
        let entry = self
            .entries
            .remove(path)
            .ok_or_else(|| invalid("source checkpoint inventory changed"))?;
        self.evictable.remove(&(entry.used, entry.path));
        self.total -= entry.bytes;
        Ok(())
    }

    pub fn remember_file(
        &mut self,
        receiver: &mut SourceReceiver,
        path: &str,
    ) -> Result<(), RememberError> {
        self.check_owner()?;
        if receiver.manifest().digest() != self.manifest_digest {
            return Err(RememberError::Source(invalid(
                "source checkpoint manifest changed",
            )));
        }
        let files = receiver.manifest().files();
        let index = files
            .binary_search_by(|file| file.path.as_str().cmp(path))
            .map_err(|_| RememberError::Source(invalid("undeclared source checkpoint member")))?;
        let expected = files[index].clone();
        if !self.visited.insert(path.to_owned())
            || expected.len == 0
            || expected.len > self.cache.max_bytes
            || expected.len > MAX_FILE_BYTES
        {
            return Ok(());
        }
        let destination = self.cache.object_path(&expected.sha256);
        if let Some(bytes) = self.protected.get(&destination) {
            if *bytes != expected.len {
                return Err(RememberError::Source(invalid(
                    "one source digest has conflicting declared lengths",
                )));
            }
            return Ok(());
        }
        let Some(next_protected_bytes) =
            self.protected_bytes
                .checked_add(expected.len)
                .filter(|sum| {
                    *sum <= self.cache.max_bytes && self.protected.len() < self.cache.max_files
                })
        else {
            // The complete-tree seal still verifies this member. An unfittable
            // optional checkpoint must not evict another useful object.
            return Ok(());
        };
        let scratch = self.cache.root.join(INCOMING);
        let mut options = OpenOptions::new();
        options.read(true).write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(&scratch)?;
        let snapshot = receiver.checkpoint_file(path, file, || self.cache.control.stopped());
        // Cancellation/deadline is never made into a usable cache miss or a
        // late successful chunk ACK, even if the filesystem call also failed.
        self.cache.control.check()?;
        let snapshot = snapshot.map_err(|error| match error {
            SourceCheckpointError::Source(error) => RememberError::Source(error),
            SourceCheckpointError::Destination(error) => RememberError::Cache(error),
        })?;
        if snapshot.expected() != &expected {
            return Err(RememberError::Source(invalid(
                "source checkpoint returned a different member",
            )));
        }
        let file = snapshot.into_file();
        let mut permissions = file.metadata()?.permissions();
        permissions.set_readonly(true);
        file.set_permissions(permissions)?;
        drop(file);
        self.check_owner()?;
        if self.entries.contains_key(&destination) {
            self.remove(&destination)?;
        }
        while self.entries.len() >= self.cache.max_files
            || self
                .total
                .checked_add(expected.len)
                .is_none_or(|sum| sum > self.cache.max_bytes)
        {
            let path = self
                .evictable
                .first()
                .map(|(_, path)| path.clone())
                .ok_or_else(|| invalid("source checkpoint eviction credit is inconsistent"))?;
            self.remove(&path)?;
        }
        self.check_owner()?;
        fs::rename(&scratch, &destination)?;
        self.total += expected.len;
        self.protected_bytes = next_protected_bytes;
        self.protected.insert(destination.clone(), expected.len);
        self.entries.insert(
            destination.clone(),
            Entry {
                path: destination,
                bytes: expected.len,
                used: SystemTime::now(),
            },
        );
        Ok(())
    }
}

impl From<io::Error> for RememberError {
    fn from(error: io::Error) -> Self {
        Self::Cache(error)
    }
}

impl SourceCache {
    /// Open a private, disposable input cache below an existing worker-owned
    /// directory. A zero capacity is configured by omitting this cache entirely.
    pub fn open(parent: &Path, max_bytes: u64) -> io::Result<Self> {
        Self::open_with_mode(parent, max_bytes, false)
    }

    /// Open only bounded file reuse, without reserving storage for execution
    /// projections. The caller retains this private parent through every view
    /// and active checkpoint writer; the cache does not own or delete it.
    pub fn open_byte_only(parent: &Path, max_bytes: u64) -> io::Result<Self> {
        Self::open_with_mode(parent, max_bytes, true)
    }

    fn open_with_mode(parent: &Path, max_bytes: u64, byte_only: bool) -> io::Result<Self> {
        if !parent.is_absolute() {
            return Err(invalid("source cache directory must be absolute"));
        }
        if max_bytes == 0 || max_bytes > MAX_SOURCE_CACHE_BYTES {
            return Err(invalid(
                "source cache capacity must be between 1 and 8589934592 bytes",
            ));
        }
        private_directory(parent)?;
        let root = fs::canonicalize(parent)?.join("source-files-v1");
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        match builder.create(&root) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
        private_directory(&root)?;
        // Keep the existing configured retained-byte budget: larger caches
        // reserve one quarter for complete read-only execution projections.
        // Tiny caches remain byte-only, and zero still omits SourceCache.
        let projection_bytes = if !byte_only && max_bytes >= MIN_PROJECTION_CACHE_BYTES {
            max_bytes / 4
        } else {
            0
        };
        let mut cache = Self {
            root,
            max_bytes: max_bytes - projection_bytes,
            max_files: MAX_FILES,
            byte_only,
            peer: None,
            control: CacheControl::default(),
            projections: None,
            projection_writer: None,
            quarantine: Arc::new(Mutex::new(None)),
        };
        let retained_writer = cache.reserve_projection_budget(projection_bytes != 0)?;
        if let Some(file) = retained_writer {
            // Hold the existing process-shared writer lock through the final
            // retained image lease. Independent cache opens can still read
            // snapshots, but cannot grow raw storage or create a second pool.
            // Clones of this owner serialize their own writes locally.
            let pool = SourceProjectionPool::new(
                parent,
                projection_bytes,
                MAX_PROJECTION_IMAGES,
                MAX_PROJECTION_MEMBERS,
            )?
            .with_retention_lock(Arc::clone(&file))?;
            cache.projections = Some(Arc::new(pool));
            cache.projection_writer = Some(Arc::new(ProjectionWriter {
                file,
                local: AtomicU8::new(WRITER_FREE),
            }));
        } else {
            // An existing writer may still be using the old raw-file budget.
            // Skip the optional pool instead of oversubscribing that budget.
            cache.max_bytes = max_bytes;
        }
        Ok(cache)
    }

    /// Select a byte-object namespace using identity authenticated by the
    /// caller. Never derive this key from an untrusted source manifest. Views
    /// keep the same root, lock and retention limits; peer count cannot multiply
    /// the disk budget. Execution projection pools are deliberately excluded.
    pub fn for_peer(mut self, peer: [u8; 32]) -> io::Result<Self> {
        if !self.byte_only || peer == [0; 32] {
            return Err(invalid(
                "peer-scoped source reuse requires a byte-only cache and a nonzero identity",
            ));
        }
        self.peer = Some(peer);
        Ok(self)
    }

    fn object_path(&self, digest: &[u8; 32]) -> PathBuf {
        let identity = match self.peer {
            Some(peer) => {
                let mut hash = Sha256::new();
                hash.update(b"rabs.source-cache.peer.v1\0");
                hash.update(peer);
                hash.update(digest);
                <[u8; 32]>::from(hash.finalize())
            }
            None => *digest,
        };
        self.root.join(object_name(&identity))
    }

    pub fn projections(&self) -> Option<Arc<SourceProjectionPool>> {
        self.projections.as_ref().map(Arc::clone)
    }

    /// Refuse writable runtime aliases, including legacy commands without uploads.
    pub fn validate_runtime_root(&self, path: &Path) -> io::Result<()> {
        let path = fs::canonicalize(path).or_else(|error| {
            if error.kind() != io::ErrorKind::NotFound {
                return Err(error);
            }
            let (parent, name) = path
                .parent()
                .zip(path.file_name())
                .ok_or_else(|| invalid("invalid runtime root"))?;
            Ok(fs::canonicalize(parent)?.join(name))
        })?;
        let parent = self
            .root
            .parent()
            .ok_or_else(|| invalid("source cache parent missing"))?;
        if let Some(pool) = &self.projections {
            pool.protected_parent()?;
        }
        if parent.starts_with(&path) || path.starts_with(parent) {
            return Err(invalid("runtime root aliases retained source storage"));
        }
        Ok(())
    }

    fn reserve_projection_budget(&self, enabled: bool) -> io::Result<Option<Arc<File>>> {
        let Some(_writer) = self.writer()? else {
            return Ok(None);
        };
        if !enabled {
            return Ok(None);
        }
        let mut entries = self.inventory()?;
        let mut total = entries.iter().try_fold(0_u64, |sum, entry| {
            sum.checked_add(entry.bytes)
                .ok_or_else(|| invalid("source cache size overflow"))
        })?;
        while total > self.max_bytes || entries.len() > self.max_files {
            let entry = entries
                .pop_front()
                .ok_or_else(|| invalid("source cache capacity accounting is inconsistent"))?;
            fs::remove_file(&entry.path)?;
            total -= entry.bytes;
        }
        match _writer {
            CacheWriter::Process { file } => Ok(Some(Arc::new(file))),
            CacheWriter::Local { .. } => {
                Err(invalid("source cache projection budget already owned"))
            }
        }
    }

    pub fn before(mut self, deadline: Instant) -> Self {
        self.control.deadline = Some(deadline);
        self
    }

    pub fn with_cancellation(mut self, cancelled: Arc<AtomicBool>) -> Self {
        self.control.cancelled = Some(cancelled);
        self
    }

    /// An unavailable or corrupt object is a MISS before any staging write.
    /// Recency is eviction policy only; it never establishes content identity.
    pub fn load(&self, expected: &SourceFile) -> Option<VerifiedSource> {
        if expected.len > self.max_bytes || expected.len > MAX_FILE_BYTES {
            return None;
        }
        self.control.check().ok()?;
        private_directory(&self.root).ok()?;
        let mut snapshot = tempfile::tempfile_in(&self.root).ok()?;
        let file = copy_verified(
            &self.object_path(&expected.sha256),
            expected,
            &self.control,
            &mut snapshot,
        )
        .ok()?;
        snapshot.rewind().ok()?;
        self.control.check().ok()?;
        let _ = file.set_modified(SystemTime::now());
        Some(VerifiedSource {
            file: snapshot,
            expected: expected.clone(),
            control: self.control.clone(),
        })
    }

    fn contains_verified(&self, expected: &SourceFile) -> bool {
        let Ok(file) = copy_verified(
            &self.object_path(&expected.sha256),
            expected,
            &self.control,
            &mut io::sink(),
        ) else {
            return false;
        };
        let _ = file.set_modified(SystemTime::now());
        true
    }

    fn writer(&self) -> io::Result<Option<CacheWriter>> {
        self.control.check()?;
        private_directory(&self.root)?;
        let path = self.root.join("lock");
        if let Some(owner) = &self.projection_writer {
            let metadata = owner.file.metadata()?;
            if !ordinary(&metadata) || !same_inode(&metadata, &fs::symlink_metadata(&path)?) {
                return Err(invalid("retained source cache writer identity changed"));
            }
            return match owner.local.compare_exchange(
                WRITER_FREE,
                WRITER_HELD,
                Ordering::Acquire,
                Ordering::Relaxed,
            ) {
                Ok(_) => Ok(Some(CacheWriter::Local {
                    guard: LocalCacheWriter {
                        owner: Arc::clone(owner),
                    },
                })),
                Err(WRITER_HELD) => Ok(None),
                Err(_) => Err(invalid("source cache writer poisoned")),
            };
        }
        let mut quarantine = match self.quarantine.try_lock() {
            Ok(guard) => guard,
            Err(std::sync::TryLockError::WouldBlock) => return Ok(None),
            Err(std::sync::TryLockError::Poisoned(_)) => {
                return Err(invalid("source cache quarantine poisoned"));
            }
        };
        if quarantine.is_some() {
            return Ok(None);
        }
        match fs::symlink_metadata(&path) {
            Ok(meta) if !ordinary(&meta) => return Err(invalid("invalid source cache lock")),
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(&path)?;
        let meta = file.metadata()?;
        if !ordinary(&meta) || !same_inode(&meta, &fs::symlink_metadata(&path)?) {
            return Err(invalid("source cache lock identity changed"));
        }
        match file.try_lock() {
            Ok(()) => {
                let parent = self
                    .root
                    .parent()
                    .ok_or_else(|| invalid("source cache parent missing"))?;
                let residue = projection_residue(parent);
                self.control.check()?;
                if !matches!(residue, Ok(false)) {
                    // A crashed predecessor released flock without freeing its
                    // images. Retain this lock even for tiny/lowered budgets;
                    // old passive handles must pass the same check on writing.
                    eprintln!(
                        "{}",
                        serde_json::json!({
                            "kind": "worker-source-cache-read-only",
                            "reason": "retained projection residue or incomplete parent inspection",
                            "preserved_bytes": null,
                        })
                    );
                    *quarantine = Some(file);
                    return Ok(None);
                }
                Ok(Some(CacheWriter::Process { file }))
            }
            Err(fs::TryLockError::WouldBlock) => Ok(None),
            Err(fs::TryLockError::Error(error)) => Err(error),
        }
    }

    /// Called with the exclusive cache lock held. A dead writer leaves at most
    /// one bounded scratch file. It is never read as a reusable object.
    fn inventory(&self) -> io::Result<VecDeque<Entry>> {
        let scratch = self.root.join(INCOMING);
        match fs::symlink_metadata(&scratch) {
            Ok(meta) if ordinary(&meta) && meta.len() <= MAX_FILE_BYTES => {
                fs::remove_file(&scratch)?
            }
            Ok(_) => return Err(invalid("invalid source cache scratch file")),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let mut entries = Vec::new();
        for item in fs::read_dir(&self.root)? {
            self.control.check()?;
            let item = item?;
            let name = item.file_name();
            if name == "lock" {
                continue;
            }
            if entries.len() >= MAX_FILES
                || !name.to_str().is_some_and(owned_name)
                || !ordinary(&fs::symlink_metadata(item.path())?)
            {
                return Err(invalid(
                    "source cache inventory is not an owned bounded file set",
                ));
            }
            let meta = fs::symlink_metadata(item.path())?;
            entries.push(Entry {
                path: item.path(),
                bytes: meta.len(),
                used: meta.modified().unwrap_or(SystemTime::UNIX_EPOCH),
            });
        }
        entries.sort_by(|a, b| a.used.cmp(&b.used).then_with(|| a.path.cmp(&b.path)));
        Ok(entries.into())
    }

    /// Acquire once at the first completed member, not on every chunk. A busy
    /// writer skips this upload's checkpoints; the final seal can still attempt
    /// ordinary optional cache admission after the upload is complete.
    pub fn checkpoints(
        &self,
        manifest: &SourceManifest,
    ) -> Result<Option<SourceCheckpoints>, RememberError> {
        let Some(writer) = self.writer()? else {
            return Ok(None);
        };
        let root_identity = fs::symlink_metadata(&self.root)?;
        let mut entries = self.inventory()?;
        let mut total = entries.iter().try_fold(0_u64, |sum, entry| {
            sum.checked_add(entry.bytes)
                .ok_or_else(|| invalid("source cache size overflow"))
        })?;
        while total > self.max_bytes || entries.len() > self.max_files {
            self.control.check()?;
            let entry = entries
                .pop_front()
                .ok_or_else(|| invalid("source cache capacity accounting is inconsistent"))?;
            fs::remove_file(&entry.path)?;
            total -= entry.bytes;
        }
        let mut protected = BTreeMap::new();
        for expected in manifest.files() {
            self.control.check()?;
            if expected.len == 0 || expected.len > MAX_FILE_BYTES || expected.len > self.max_bytes {
                continue;
            }
            let path = self.object_path(&expected.sha256);
            if !protected.contains_key(&path) && self.contains_verified(expected) {
                protected.insert(path, expected.len);
            }
        }
        let protected_bytes = protected.values().try_fold(0_u64, |sum, bytes| {
            sum.checked_add(*bytes)
                .ok_or_else(|| invalid("source cache protected size overflow"))
        })?;
        let evictable = entries
            .iter()
            .filter(|entry| !protected.contains_key(&entry.path))
            .map(|entry| (entry.used, entry.path.clone()))
            .collect();
        self.control.check()?;
        let checkpoint = SourceCheckpoints {
            cache: self.clone(),
            writer,
            root_identity,
            manifest_digest: manifest.digest(),
            entries: entries
                .into_iter()
                .map(|entry| (entry.path.clone(), entry))
                .collect(),
            evictable,
            protected,
            protected_bytes,
            total,
            visited: BTreeSet::new(),
        };
        checkpoint.check_owner()?;
        Ok(Some(checkpoint))
    }

    /// Seed only from a completed source receiver, never an arbitrary upload
    /// claim. Cache I/O is optional; the caller must retain the sealed receiver
    /// regardless. Lock contention skips writes instead of delaying execution.
    ///
    /// File and directory fsync are deliberately not publication frontiers:
    /// after a crash a missing/torn object simply fails load's full verification.
    /// Protect this projection's verified hits before admitting any misses, and
    /// protect each new admission for the rest of this call. A projection larger
    /// than the cache retains a useful subset instead of rewriting/evicting its
    /// own inputs on every transfer. These are local eviction preferences, not
    /// execution pins: another projection may evict them under the same lock.
    pub fn remember(&self, receiver: &SourceReceiver) -> Result<u64, RememberError> {
        let root = receiver
            .sealed_root()
            .ok_or_else(|| RememberError::Source(invalid("cannot cache unsealed source")))?;
        self.remember_files(
            receiver.manifest(),
            RememberSource::SealedUpload,
            |expected, output| {
                copy_verified(&root.join(&expected.path), expected, &self.control, output).map(drop)
            },
        )
    }

    /// Reuse bytes already produced on this worker as a later request's inputs.
    /// Only immutable captured-artifact readers call this production entry.
    /// Existing source upload negotiation still selects the exact bytes, reads
    /// them into a private receiver and requires its complete final seal.
    ///
    /// This is optional storage work on the blocking execution owner, after
    /// successful completion. It shares the source cache's writer, capacity,
    /// corruption handling and atomic admission. A short optional-I/O allowance
    /// is additionally capped by the original execution deadline. It cannot
    /// acquire compiler/publication authority or delay output delivery for the
    /// execution owner's potentially much longer remaining allowance.
    pub fn remember_streamed(
        &self,
        manifest: &SourceManifest,
        deadline: Instant,
        mut read: impl FnMut(&str, u64, usize) -> io::Result<Vec<u8>>,
    ) -> io::Result<u64> {
        let deadline = deadline.min(Instant::now() + PRODUCED_INPUT_BUDGET);
        let cache = self.clone().before(deadline);
        cache
            .remember_files(
                manifest,
                RememberSource::CapturedOutput,
                |expected, output| {
                    copy_verified_ranges(expected, &cache.control, &mut read, output)
                },
            )
            .map_err(|error| match error {
                RememberError::Source(error) | RememberError::Cache(error) => error,
            })
    }

    /// Both upload and captured-output admission use this one eviction and
    /// publication path. The copy callback must verify its complete source;
    /// no candidate becomes readable under its digest before that succeeds.
    fn remember_files(
        &self,
        manifest: &SourceManifest,
        source: RememberSource,
        mut copy: impl FnMut(&SourceFile, &mut dyn Write) -> Result<(), RememberError>,
    ) -> Result<u64, RememberError> {
        let Some(_lock) = self.writer()? else {
            return Ok(0);
        };
        let mut entries = self.inventory()?;
        let mut total = entries.iter().try_fold(0_u64, |sum, entry| {
            sum.checked_add(entry.bytes)
                .ok_or_else(|| invalid("source cache size overflow"))
        })?;
        // A restarted worker may deliberately lower its disk allowance. Apply
        // that limit before protecting this projection's hits, including when
        // every requested object was already present in the older cache.
        while total > self.max_bytes || entries.len() > self.max_files {
            self.control.check()?;
            let entry = entries
                .pop_front()
                .ok_or_else(|| invalid("source cache capacity accounting is inconsistent"))?;
            fs::remove_file(&entry.path)?;
            total -= entry.bytes;
        }
        let mut protected = BTreeMap::new();
        let mut missing = Vec::new();
        // Decide the whole projection's existing-hit set before any eviction.
        // Otherwise an early miss can evict a later hit just because source
        // paths sort that way. A filename alone is never protection evidence:
        // corrupt objects must remain evictable/repairable, not occupy credit.
        for expected in manifest.files() {
            self.control.check()?;
            if expected.len == 0 || expected.len > MAX_FILE_BYTES || expected.len > self.max_bytes {
                continue;
            }
            if self.contains_verified(expected) {
                protected.insert(self.object_path(&expected.sha256), expected.len);
            } else {
                missing.push(expected);
            }
        }
        let mut protected_bytes = protected.values().try_fold(0_u64, |sum, bytes| {
            sum.checked_add(*bytes)
                .ok_or_else(|| invalid("source cache protected size overflow"))
        })?;
        if source == RememberSource::CapturedOutput {
            // SourceManifest canonicalizes path order. Restore metadata-first
            // admission here, after existing hits have all been protected.
            missing.sort_by_key(|expected| !expected.path.ends_with(".rmeta"));
        }
        let mut stored = 0;
        for expected in missing {
            self.control.check()?;
            let destination = self.object_path(&expected.sha256);
            if let Some(bytes) = protected.get(&destination) {
                if *bytes != expected.len {
                    return Err(RememberError::Source(invalid(
                        "one source digest has conflicting declared lengths",
                    )));
                }
                // Different source paths can name the same content. A byte
                // object admitted earlier in this call consumes only one slot.
                continue;
            }
            let next_protected_bytes = protected_bytes
                .checked_add(expected.len)
                .filter(|sum| *sum <= self.max_bytes && protected.len() < self.max_files);
            let Some(next_protected_bytes) = next_protected_bytes else {
                if source == RememberSource::SealedUpload {
                    // Capacity pressure must not hide mutation of a sealed
                    // execution input. Preserve original upload verification.
                    copy(expected, &mut io::sink())?;
                }
                // Produced bytes are independently captured already. If this
                // optional cache cannot retain them, do not reread a potentially
                // large archive for no benefit before result delivery.
                continue;
            };
            // One fixed scratch name plus the held process-shared lock bounds
            // crash debris and serializes capacity accounting across workers.
            // Verify the complete source before evicting useful cache objects.
            let scratch = self.root.join(INCOMING);
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(&scratch)?;
            copy(expected, &mut file)?;
            let mut permissions = file.metadata()?.permissions();
            permissions.set_readonly(true);
            file.set_permissions(permissions)?;
            drop(file);
            // Establish that this object can fit WITHOUT sacrificing this
            // projection's useful bytes before removing any cache entry. If
            // it cannot, even unrelated LRU entries should remain untouched.
            // A corrupted object with this name must not make future uploads
            // permanently miss. Only our ordinary, inventoried cache file moves.
            if let Some(index) = entries.iter().position(|entry| entry.path == destination) {
                let entry = entries
                    .remove(index)
                    .ok_or_else(|| invalid("source cache inventory changed"))?;
                fs::remove_file(&entry.path)?;
                total -= entry.bytes;
            }
            while entries.len() >= self.max_files
                || total
                    .checked_add(expected.len)
                    .is_none_or(|sum| sum > self.max_bytes)
            {
                self.control.check()?;
                let index = entries
                    .iter()
                    .position(|entry| !protected.contains_key(&entry.path))
                    .ok_or_else(|| invalid("source cache eviction credit is inconsistent"))?;
                let entry = entries
                    .remove(index)
                    .ok_or_else(|| invalid("source cache inventory changed"))?;
                fs::remove_file(&entry.path)?;
                total -= entry.bytes;
            }
            self.control.check()?;
            fs::rename(&scratch, &destination)?;
            total += expected.len;
            protected_bytes = next_protected_bytes;
            protected.insert(destination.clone(), expected.len);
            entries.push_back(Entry {
                path: destination,
                bytes: expected.len,
                used: SystemTime::now(),
            });
            stored += 1;
        }
        Ok(stored)
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::source_transfer::SourceManifest;
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};

    fn entry(path: &str, bytes: &[u8]) -> SourceFile {
        SourceFile {
            path: path.into(),
            len: bytes.len() as u64,
            sha256: Sha256::digest(bytes).into(),
            executable: false,
        }
    }

    fn staged(parent: &Path, files: &[(&str, &[u8])]) -> SourceReceiver {
        let manifest = SourceManifest::new(
            files
                .iter()
                .map(|(path, bytes)| entry(path, bytes))
                .collect(),
        )
        .unwrap();
        let mut receiver = SourceReceiver::create(&parent.join("workspace"), manifest).unwrap();
        for (path, bytes) in files {
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
        receiver
    }

    fn range(bytes: &[u8], offset: u64, count: usize) -> Vec<u8> {
        let offset = usize::try_from(offset).unwrap();
        bytes[offset..bytes.len().min(offset + count)].to_vec()
    }

    fn remember_output(cache: &SourceCache, name: &str, bytes: &[u8]) -> io::Result<u64> {
        let manifest = SourceManifest::new(vec![entry(name, bytes)]).unwrap();
        cache.remember_streamed(
            &manifest,
            Instant::now() + std::time::Duration::from_secs(30),
            |requested, offset, count| {
                assert_eq!(requested, name);
                assert!(count <= MAX_SOURCE_CHUNK);
                Ok(range(bytes, offset, count))
            },
        )
    }

    #[test]
    fn byte_only_cache_keeps_its_whole_budget_and_requires_explicit_peer_scope() {
        let parent = private();
        let cache = SourceCache::open_byte_only(parent.path(), DEFAULT_SOURCE_CACHE_BYTES).unwrap();
        assert_eq!(cache.max_bytes, DEFAULT_SOURCE_CACHE_BYTES);
        assert!(cache.projections().is_none());
        assert!(cache.projection_writer.is_none());
        assert!(fs::read_dir(parent.path()).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .as_encoded_bytes()
                .starts_with(SOURCE_PROJECTION_PREFIX.as_bytes())
        }));
        assert!(cache.clone().for_peer([0; 32]).is_err());
        let peer = cache.clone().for_peer([1; 32]).unwrap();
        assert_eq!(peer.root, cache.root);
        assert_eq!(peer.max_bytes, cache.max_bytes);
        assert!(Arc::ptr_eq(&peer.quarantine, &cache.quarantine));
        let legacy_parent = private();
        let legacy = SourceCache::open(legacy_parent.path(), 1).unwrap();
        assert!(legacy.projections().is_none());
        assert!(
            legacy.for_peer([1; 32]).is_err(),
            "a worker cache without a projection pool is not a byte-only peer cache"
        );
        for capacity in [0, MAX_SOURCE_CACHE_BYTES + 1] {
            assert!(SourceCache::open_byte_only(parent.path(), capacity).is_err());
        }
    }

    #[test]
    fn peer_scoped_bytes_require_an_independent_upload_and_allow_private_rename_and_mode_changes() {
        let parent = private();
        let input = private();
        let bytes = b"compiler input\0\xff";
        let source = staged(input.path(), &[("original.rs", bytes)]);
        let expected = &source.manifest().files()[0];
        let cache = SourceCache::open_byte_only(parent.path(), 1024).unwrap();
        let first = cache.clone().for_peer([1; 32]).unwrap();
        let second = cache.clone().for_peer([2; 32]).unwrap();
        assert_eq!(first.remember(&source).unwrap(), 1);
        assert!(first.load(expected).is_some());
        assert!(second.load(expected).is_none());
        assert!(cache.load(expected).is_none());
        assert_ne!(
            first.object_path(&expected.sha256),
            second.object_path(&expected.sha256)
        );
        assert_ne!(
            first.object_path(&expected.sha256),
            cache.object_path(&expected.sha256)
        );

        let mut renamed = expected.clone();
        renamed.path = "renamed/tool".into();
        renamed.executable = true;
        let output = private();
        let mut receiver = SourceReceiver::create(
            &output.path().join("workspace"),
            SourceManifest::new(vec![renamed.clone()]).unwrap(),
        )
        .unwrap();
        first
            .load(&renamed)
            .unwrap()
            .install(&mut receiver)
            .unwrap();
        assert!(receiver.sealed_root().is_none());
        let installed = receiver.seal().unwrap().join(&renamed.path);
        assert_eq!(fs::read(&installed).unwrap(), bytes);
        assert_ne!(fs::metadata(&installed).unwrap().mode() & 0o111, 0);
        assert_ne!(
            fs::metadata(&installed).unwrap().ino(),
            fs::metadata(first.object_path(&expected.sha256))
                .unwrap()
                .ino()
        );
        fs::set_permissions(&installed, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&installed, b"private execution edit").unwrap();
        assert_eq!(first.load(expected).unwrap().bytes(), bytes);
        assert!(second.load(expected).is_none());
        assert_eq!(second.remember(&source).unwrap(), 1);
        assert_eq!(second.load(expected).unwrap().bytes(), bytes);
        assert_eq!(cache_inodes(&cache).len(), 2);

        // Reopening byte-only storage preserves namespaces without relying on
        // a process-local declaration or sharing another principal's key.
        let reopened = SourceCache::open_byte_only(parent.path(), 1024).unwrap();
        assert_eq!(
            reopened
                .clone()
                .for_peer([1; 32])
                .unwrap()
                .load(expected)
                .unwrap()
                .bytes(),
            bytes
        );
        assert!(reopened.for_peer([3; 32]).unwrap().load(expected).is_none());
    }

    #[test]
    fn peer_scoped_objects_share_one_aggregate_byte_and_entry_budget() {
        for (capacity, max_files) in [(8, MAX_FILES), (16, 2)] {
            let parent = private();
            let input = private();
            let source = staged(input.path(), &[("input.rs", b"same")]);
            let expected = &source.manifest().files()[0];
            let mut cache = SourceCache::open_byte_only(parent.path(), capacity).unwrap();
            cache.max_files = max_files;
            let first = cache.clone().for_peer([1; 32]).unwrap();
            let second = cache.clone().for_peer([2; 32]).unwrap();
            let third = cache.clone().for_peer([3; 32]).unwrap();
            assert_eq!(first.remember(&source).unwrap(), 1);
            assert_eq!(second.remember(&source).unwrap(), 1);
            File::open(first.object_path(&expected.sha256))
                .unwrap()
                .set_modified(SystemTime::UNIX_EPOCH + Duration::from_secs(1))
                .unwrap();
            File::open(second.object_path(&expected.sha256))
                .unwrap()
                .set_modified(SystemTime::UNIX_EPOCH + Duration::from_secs(2))
                .unwrap();
            assert_eq!(third.remember(&source).unwrap(), 1);
            assert!(first.load(expected).is_none());
            assert_eq!(second.load(expected).unwrap().bytes(), b"same");
            assert_eq!(third.load(expected).unwrap().bytes(), b"same");
            let objects = cache_inodes(&cache);
            assert_eq!(objects.len(), 2);
            let retained_bytes: u64 = objects
                .keys()
                .map(|path| fs::metadata(path).unwrap().len())
                .sum();
            assert_eq!(retained_bytes, 8);
            assert!(retained_bytes <= capacity);
        }
    }

    #[test]
    fn peer_scoped_checkpoints_share_writer_admission_and_keep_cancellation_and_repair_local() {
        let parent = private();
        let input = private();
        let source_manifest =
            SourceManifest::new(vec![entry("first.rs", b"first"), entry("last.rs", b"last")])
                .unwrap();
        let first_file = source_manifest.files()[0].clone();
        let mut source =
            SourceReceiver::create(&input.path().join("workspace"), source_manifest.clone())
                .unwrap();
        source
            .write_chunk("first.rs", 0, b"first", Sha256::digest(b"first").into())
            .unwrap();
        let cache = SourceCache::open_byte_only(parent.path(), 16).unwrap();
        let first = cache.clone().for_peer([1; 32]).unwrap();
        let second = cache.clone().for_peer([2; 32]).unwrap();
        let mut checkpoints = first.checkpoints(&source_manifest).unwrap().unwrap();
        checkpoints.remember_file(&mut source, "first.rs").unwrap();
        assert!(source.sealed_root().is_none());
        assert_eq!(first.load(&first_file).unwrap().bytes(), b"first");
        assert!(second.load(&first_file).is_none());

        let other_input = private();
        let other = staged(other_input.path(), &[("first.rs", b"first")]);
        assert_eq!(
            second.remember(&other).unwrap(),
            0,
            "another peer cannot obtain an independent writer allowance"
        );
        drop(checkpoints);
        assert_eq!(second.remember(&other).unwrap(), 1);
        let other_path = second.object_path(&first_file.sha256);
        let other_inode = fs::metadata(&other_path).unwrap().ino();
        source
            .write_chunk("last.rs", 0, b"last", Sha256::digest(b"last").into())
            .unwrap();
        source.seal().unwrap();
        assert_eq!(first.remember(&source).unwrap(), 1);

        let cancelled = Arc::new(AtomicBool::new(true));
        let stopped = first.clone().with_cancellation(cancelled);
        assert!(stopped.load(&first_file).is_none());
        assert!(matches!(stopped.remember(&source),
            Err(RememberError::Cache(error)) if error.kind() == io::ErrorKind::Interrupted));
        let expired = first.clone().before(Instant::now());
        assert!(expired.load(&first_file).is_none());
        assert!(matches!(expired.remember(&source),
            Err(RememberError::Cache(error)) if error.kind() == io::ErrorKind::TimedOut));
        assert_eq!(first.load(&first_file).unwrap().bytes(), b"first");
        assert_eq!(second.load(&first_file).unwrap().bytes(), b"first");

        let corrupt = first.object_path(&first_file.sha256);
        fs::set_permissions(&corrupt, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&corrupt, b"wrong").unwrap();
        assert!(first.load(&first_file).is_none());
        assert_eq!(second.load(&first_file).unwrap().bytes(), b"first");
        assert_eq!(first.remember(&source).unwrap(), 1);
        assert_eq!(first.load(&first_file).unwrap().bytes(), b"first");
        assert_eq!(fs::metadata(other_path).unwrap().ino(), other_inode);
        assert_eq!(cache_inodes(&cache).len(), 3);
    }

    #[test]
    fn produced_library_bytes_reopen_as_renamed_private_inputs_without_upload() {
        let parent = private();
        let bytes = (0..MAX_SOURCE_CHUNK * 3 + 17)
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>();
        let output = entry("libleaf.rlib", &bytes);
        let mut cache = SourceCache::open(parent.path(), 1024 * 1024).unwrap();
        assert!(
            cache.load(&output).is_none(),
            "cold producer output is not an uploaded input"
        );
        assert_eq!(remember_output(&cache, &output.path, &bytes).unwrap(), 1);
        let original = cache_inodes(&cache);
        assert_eq!(remember_output(&cache, &output.path, &bytes).unwrap(), 0);
        assert_eq!(
            cache_inodes(&cache),
            original,
            "duplicate output rewrote the cache inode"
        );
        drop(cache);
        cache = SourceCache::open(parent.path(), 1024 * 1024).unwrap();

        let mut input = output.clone();
        input.path = "dependencies/0003/libleaf-renamed.rlib".into();
        let destination = private();
        let mut receiver = SourceReceiver::create(
            &destination.path().join("workspace"),
            SourceManifest::new(vec![input.clone()]).unwrap(),
        )
        .unwrap();
        cache.load(&input).unwrap().install(&mut receiver).unwrap();
        assert!(
            receiver.sealed_root().is_none(),
            "byte reuse cannot skip the final seal"
        );
        let installed = receiver.seal().unwrap().join(&input.path);
        assert_eq!(fs::read(&installed).unwrap(), bytes);
        assert_ne!(
            fs::metadata(&installed).unwrap().ino(),
            fs::metadata(cache.root.join(object_name(&output.sha256)))
                .unwrap()
                .ino(),
            "consumer input aliases the retained byte object"
        );
        fs::set_permissions(&installed, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&installed, b"changed consumer").unwrap();
        assert_eq!(cache.load(&output).unwrap().bytes(), bytes);
    }

    #[test]
    fn malformed_output_ranges_never_publish_or_evict_verified_input_bytes() {
        let bytes = vec![37; MAX_SOURCE_CHUNK + 19];
        for case in 0..5 {
            let parent = private();
            let cache = SourceCache::open(parent.path(), bytes.len() as u64).unwrap();
            let old = entry("old.rs", b"keep");
            assert_eq!(remember_output(&cache, &old.path, b"keep").unwrap(), 1);
            let before = cache_inodes(&cache);
            let output = entry("libnew.rlib", &bytes);
            let manifest = SourceManifest::new(vec![output.clone()]).unwrap();
            let error = cache
                .remember_streamed(
                    &manifest,
                    Instant::now() + std::time::Duration::from_secs(30),
                    |_, offset, count| {
                        let mut result = range(&bytes, offset, count);
                        match case {
                            0 if offset == 0 => result[0] ^= 1,
                            1 if offset == 0 => {
                                result.pop();
                            }
                            2 if offset == 0 => result.push(0),
                            3 if offset == bytes.len() as u64 => result.push(0),
                            4 if offset != 0 => {
                                return Err(io::Error::other("captured range unavailable"));
                            }
                            _ => {}
                        }
                        Ok(result)
                    },
                )
                .unwrap_err();
            assert!(matches!(
                error.kind(),
                io::ErrorKind::InvalidData | io::ErrorKind::Other
            ));
            assert!(!cache.root.join(object_name(&output.sha256)).exists());
            assert_eq!(cache.load(&old).unwrap().bytes(), b"keep");
            assert_eq!(
                cache_inodes(&cache),
                before,
                "invalid output evicted an existing input"
            );
            // A private partial scratch object cannot poison a subsequent
            // complete import or permanently consume the bounded writer.
            assert_eq!(remember_output(&cache, &output.path, &bytes).unwrap(), 1);
            assert_eq!(cache.load(&output).unwrap().bytes(), bytes);
        }
    }

    #[test]
    fn produced_outputs_share_upload_capacity_and_skip_contended_writers() {
        let parent = private();
        let mut cache = SourceCache::open(parent.path(), 8).unwrap();
        cache.max_files = 2;
        let source = private();
        let uploaded = staged(source.path(), &[("input.rs", b"aaaa")]);
        assert_eq!(cache.remember(&uploaded).unwrap(), 1);
        let output = entry("libone.rmeta", b"bbbb");
        let manifest = SourceManifest::new(vec![output.clone()]).unwrap();
        let writer = cache.writer().unwrap().unwrap();
        assert_eq!(
            cache
                .remember_streamed(
                    &manifest,
                    Instant::now() + std::time::Duration::from_secs(30),
                    |_, _, _| panic!("contended cache read produced bytes")
                )
                .unwrap(),
            0
        );
        drop(writer);
        assert_eq!(remember_output(&cache, &output.path, b"bbbb").unwrap(), 1);
        assert_eq!(
            cache
                .inventory()
                .unwrap()
                .iter()
                .map(|entry| entry.bytes)
                .sum::<u64>(),
            8
        );

        let oversized = entry("liblarge.rlib", b"cccccccc");
        let mixed = SourceManifest::new(vec![oversized.clone(), output.clone()]).unwrap();
        let before = cache_inodes(&cache);
        assert_eq!(
            cache
                .remember_streamed(
                    &mixed,
                    Instant::now() + std::time::Duration::from_secs(30),
                    |_, _, _| panic!("capacity-ineligible output was read without retaining it")
                )
                .unwrap(),
            0,
            "an oversized projection evicted its protected useful output"
        );
        assert_eq!(cache_inodes(&cache), before);
        assert_eq!(
            cache.load(&uploaded.manifest().files()[0]).unwrap().bytes(),
            b"aaaa"
        );
        assert_eq!(cache.load(&output).unwrap().bytes(), b"bbbb");
        assert!(cache.load(&oversized).is_none());
    }

    #[test]
    fn produced_metadata_wins_bounded_admission_after_manifest_path_sorting() {
        let parent = private();
        let cache = SourceCache::open(parent.path(), 8).unwrap();
        let archive = entry("libleaf.rlib", b"archive!");
        let metadata = entry("libleaf.rmeta", b"meta");
        let manifest = SourceManifest::new(vec![metadata.clone(), archive.clone()]).unwrap();
        assert_eq!(manifest.files()[0].path, archive.path);
        assert_eq!(
            cache
                .remember_streamed(
                    &manifest,
                    Instant::now() + Duration::from_secs(30),
                    |name, offset, count| {
                        assert_eq!(
                            name, metadata.path,
                            "archive consumed metadata admission credit"
                        );
                        Ok(range(b"meta", offset, count))
                    },
                )
                .unwrap(),
            1
        );
        assert_eq!(cache.load(&metadata).unwrap().bytes(), b"meta");
        assert!(cache.load(&archive).is_none());
    }

    #[test]
    fn produced_retention_cannot_spend_the_remaining_execution_allowance() {
        let parent = private();
        let cache = SourceCache::open(parent.path(), 1024 * 1024).unwrap();
        let bytes = vec![23; MAX_SOURCE_CHUNK + 1];
        let output = entry("libslow.rlib", &bytes);
        let manifest = SourceManifest::new(vec![output.clone()]).unwrap();
        let error = cache
            .remember_streamed(
                &manifest,
                Instant::now() + Duration::from_secs(30),
                |_, offset, count| {
                    assert_eq!(
                        offset, 0,
                        "optional budget expiration permitted another range"
                    );
                    std::thread::sleep(PRODUCED_INPUT_BUDGET + Duration::from_millis(10));
                    Ok(range(&bytes, offset, count))
                },
            )
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(!cache.root.join(object_name(&output.sha256)).exists());
        assert!(cache.load(&output).is_none());
    }

    #[test]
    fn streamed_input_cache_checks_cancellation_and_deadline_before_publication() {
        let bytes = vec![19; MAX_SOURCE_CHUNK + 1];
        let output = entry("libcancel.rlib", &bytes);
        let manifest = SourceManifest::new(vec![output.clone()]).unwrap();
        let parent = private();
        let cache = SourceCache::open(parent.path(), 1024 * 1024).unwrap();
        assert_eq!(
            cache
                .remember_streamed(&manifest, Instant::now(), |_, _, _| panic!(
                    "expired optional retention read bytes"
                ))
                .unwrap_err()
                .kind(),
            io::ErrorKind::TimedOut
        );
        assert!(!cache.root.join(INCOMING).exists());
        let cancelled = Arc::new(AtomicBool::new(false));
        let controlled = cache.clone().with_cancellation(Arc::clone(&cancelled));
        assert_eq!(
            controlled
                .remember_streamed(
                    &manifest,
                    Instant::now() + std::time::Duration::from_secs(30),
                    |_, offset, count| {
                        assert_eq!(offset, 0, "cancellation permitted another output read");
                        cancelled.store(true, Ordering::Release);
                        Ok(range(&bytes, offset, count))
                    }
                )
                .unwrap_err()
                .kind(),
            io::ErrorKind::Interrupted
        );
        assert!(!cache.root.join(object_name(&output.sha256)).exists());
        assert!(cache.load(&output).is_none());
        assert_eq!(remember_output(&cache, &output.path, &bytes).unwrap(), 1);
        assert_eq!(cache.load(&output).unwrap().bytes(), bytes);
    }

    fn private() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }

    #[test]
    fn incomplete_parent_inventory_retains_a_read_only_domain_lock() {
        let parent = private();
        for index in 0..=MAX_FILES {
            File::create(parent.path().join(format!("entry-{index}"))).unwrap();
        }
        let cache = SourceCache::open(parent.path(), 1).unwrap();
        let input = private();
        let source = staged(input.path(), &[("new", b"x")]);
        assert!(cache.projections().is_none());
        assert!(cache.quarantine.try_lock().unwrap().is_some());
        assert_eq!(cache.remember(&source).unwrap(), 0);
        let other = File::open(cache.root.join("lock")).unwrap();
        assert!(matches!(
            other.try_lock(),
            Err(fs::TryLockError::WouldBlock)
        ));
        assert_eq!(fs::read_dir(&cache.root).unwrap().count(), 1);
    }

    #[test]
    fn reuse_survives_reopen_and_never_aliases_a_staging_inode() {
        let parent = private();
        let input = private();
        let source = staged(input.path(), &[("lib.rs", b"A\0\xffB")]);
        let expected = source.manifest().files()[0].clone();
        let cache = SourceCache::open(parent.path(), DEFAULT_SOURCE_CACHE_BYTES).unwrap();
        assert_eq!(cache.remember(&source).unwrap(), 1);
        let cache = SourceCache::open(parent.path(), DEFAULT_SOURCE_CACHE_BYTES).unwrap();
        let mut projected = expected.clone();
        projected.path = "different/name.rs".into();
        projected.executable = true;
        let bytes = cache.load(&projected).unwrap().bytes();
        assert_eq!(bytes, b"A\0\xffB");
        let next = private();
        let mut receiver = SourceReceiver::create(
            &next.path().join("workspace"),
            SourceManifest::new(vec![projected.clone()]).unwrap(),
        )
        .unwrap();
        receiver
            .write_chunk(&projected.path, 0, &bytes, Sha256::digest(&bytes).into())
            .unwrap();
        let installed = receiver.seal().unwrap().join(&projected.path);
        assert_ne!(
            fs::metadata(&installed).unwrap().ino(),
            fs::metadata(cache.root.join(object_name(&expected.sha256)))
                .unwrap()
                .ino()
        );
        fs::set_permissions(&installed, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&installed, b"changed").unwrap();
        assert_eq!(cache.load(&expected).unwrap().bytes(), b"A\0\xffB");
    }

    #[test]
    fn corruption_and_wrong_length_miss_and_a_verified_upload_repairs_the_object() {
        let parent = private();
        let input = private();
        let source = staged(input.path(), &[("lib.rs", b"good")]);
        let expected = &source.manifest().files()[0];
        let cache = SourceCache::open(parent.path(), DEFAULT_SOURCE_CACHE_BYTES).unwrap();
        cache.remember(&source).unwrap();
        let path = cache.root.join(object_name(&expected.sha256));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&path, b"evil").unwrap();
        assert!(cache.load(expected).is_none());
        assert_eq!(cache.remember(&source).unwrap(), 1);
        assert_eq!(cache.load(expected).unwrap().bytes(), b"good");
        let mut wrong = expected.clone();
        wrong.len += 1;
        assert!(cache.load(&wrong).is_none());
        wrong.len = MAX_FILE_BYTES + 1;
        assert!(cache.load(&wrong).is_none());
    }

    #[test]
    fn symlinks_and_hardlinks_are_not_reusable_source_objects() {
        for hardlink in [false, true] {
            let parent = private();
            let input = private();
            let source = staged(input.path(), &[("lib.rs", b"good")]);
            let expected = &source.manifest().files()[0];
            let cache = SourceCache::open(parent.path(), DEFAULT_SOURCE_CACHE_BYTES).unwrap();
            let path = cache.root.join(object_name(&expected.sha256));
            let original = source.sealed_root().unwrap().join("lib.rs");
            if hardlink {
                fs::hard_link(original, path).unwrap();
            } else {
                symlink(original, path).unwrap();
            }
            assert!(cache.load(expected).is_none());
            assert!(cache.remember(&source).is_err());
        }
    }

    #[test]
    fn byte_and_entry_limits_evict_cache_objects_not_source_files() {
        let parent = private();
        let input = private();
        let source = staged(
            input.path(),
            &[("a", b"aaaa"), ("b", b"bbbb"), ("c", b"cccc")],
        );
        let mut cache = SourceCache::open(parent.path(), DEFAULT_SOURCE_CACHE_BYTES).unwrap();
        cache.max_bytes = 8;
        cache.max_files = 2;
        let prior = private();
        let old = staged(prior.path(), &[("old", b"old!")]);
        assert_eq!(cache.remember(&old).unwrap(), 1);
        assert_eq!(cache.remember(&source).unwrap(), 2);
        let entries = cache.inventory().unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries.iter().map(|entry| entry.bytes).sum::<u64>(), 8);
        assert_eq!(
            cache.load(&source.manifest().files()[0]).unwrap().bytes(),
            b"aaaa"
        );
        assert_eq!(
            cache.load(&source.manifest().files()[1]).unwrap().bytes(),
            b"bbbb"
        );
        assert!(cache.load(&source.manifest().files()[2]).is_none());
        assert!(cache.load(&old.manifest().files()[0]).is_none());
        assert_eq!(
            fs::read(source.sealed_root().unwrap().join("a")).unwrap(),
            b"aaaa"
        );
    }

    #[test]
    fn writer_contention_does_not_block_and_abandoned_scratch_is_never_a_hit() {
        let parent = private();
        let input = private();
        let source = staged(input.path(), &[("lib.rs", b"good")]);
        let expected = &source.manifest().files()[0];
        let cache = SourceCache::open(parent.path(), DEFAULT_SOURCE_CACHE_BYTES).unwrap();
        let lock = cache.writer().unwrap().unwrap();
        assert_eq!(cache.remember(&source).unwrap(), 0);
        fs::write(cache.root.join(INCOMING), b"torn").unwrap();
        assert!(cache.load(expected).is_none());
        drop(lock);
        assert_eq!(cache.remember(&source).unwrap(), 1);
        assert!(!cache.root.join(INCOMING).exists());
        assert_eq!(cache.load(expected).unwrap().bytes(), b"good");
    }

    #[test]
    fn unsealed_source_and_nonprivate_configuration_refuse() {
        let parent = private();
        let input = private();
        let cache = SourceCache::open(parent.path(), DEFAULT_SOURCE_CACHE_BYTES).unwrap();
        let source = SourceReceiver::create(
            &input.path().join("workspace"),
            SourceManifest::new(vec![entry("lib.rs", b"good")]).unwrap(),
        )
        .unwrap();
        assert!(cache.remember(&source).is_err());
        assert!(SourceCache::open(Path::new("relative"), DEFAULT_SOURCE_CACHE_BYTES).is_err());
        fs::set_permissions(parent.path(), fs::Permissions::from_mode(0o755)).unwrap();
        assert!(SourceCache::open(parent.path(), DEFAULT_SOURCE_CACHE_BYTES).is_err());
    }

    fn bounded_cache(parent: &Path, bytes: u64, files: usize) -> SourceCache {
        let mut cache = SourceCache::open(parent, bytes.max(1)).unwrap();
        cache.max_bytes = bytes;
        cache.max_files = files;
        cache
    }

    fn cache_inodes(cache: &SourceCache) -> BTreeMap<PathBuf, u64> {
        cache
            .inventory()
            .unwrap()
            .into_iter()
            .map(|entry| {
                let inode = fs::metadata(&entry.path).unwrap().ino();
                (entry.path, inode)
            })
            .collect()
    }

    #[test]
    fn checkpoints_preserve_byte_and_entry_quotas_without_republishing_duplicate_objects() {
        for (bytes, files) in [(8, 8), (16, 2), (8, 2)] {
            let parent = private();
            let input = private();
            let mut source = staged(
                input.path(),
                &[
                    ("a", b"aaaa"),
                    ("b", b"aaaa"),
                    ("c", b"cccc"),
                    ("d", b"dddd"),
                ],
            );
            let cache = bounded_cache(parent.path(), bytes, files);
            let mut checkpoints = cache.checkpoints(source.manifest()).unwrap().unwrap();
            checkpoints.remember_file(&mut source, "a").unwrap();
            let original = cache_inodes(&cache);
            checkpoints.remember_file(&mut source, "a").unwrap();
            checkpoints.remember_file(&mut source, "b").unwrap();
            assert_eq!(cache_inodes(&cache), original);
            checkpoints.remember_file(&mut source, "c").unwrap();
            checkpoints.remember_file(&mut source, "d").unwrap();
            assert_eq!(checkpoints.total, 8);
            assert_eq!(checkpoints.entries.len(), 2);
            assert_eq!(checkpoints.protected.len(), 2);
            let admitted = cache_inodes(&cache);
            drop(checkpoints);
            assert_eq!(cache.remember(&source).unwrap(), 0);
            assert_eq!(cache_inodes(&cache), admitted);
            assert_eq!(cache.load(&entry("a", b"aaaa")).unwrap().bytes(), b"aaaa");
            assert_eq!(cache.load(&entry("c", b"cccc")).unwrap().bytes(), b"cccc");
            assert!(cache.load(&entry("d", b"dddd")).is_none());
        }
    }

    #[test]
    fn checkpoints_protect_later_warm_members_before_admitting_an_early_miss() {
        let parent = private();
        let seed = private();
        let input = private();
        let cache = bounded_cache(parent.path(), 4, 1);
        let old = staged(seed.path(), &[("hot", b"warm")]);
        cache.remember(&old).unwrap();
        let original = cache_inodes(&cache);
        let mut source = staged(input.path(), &[("a-cold", b"cold"), ("z-hot", b"warm")]);
        let mut checkpoints = cache.checkpoints(source.manifest()).unwrap().unwrap();
        checkpoints.remember_file(&mut source, "a-cold").unwrap();
        assert_eq!(cache_inodes(&cache), original);
        checkpoints.remember_file(&mut source, "z-hot").unwrap();
        assert_eq!(cache_inodes(&cache), original);
        assert!(cache.load(&entry("a-cold", b"cold")).is_none());
        assert_eq!(
            cache.load(&entry("z-hot", b"warm")).unwrap().bytes(),
            b"warm"
        );
    }

    #[test]
    fn checkpoint_writer_contention_skips_writes_but_keeps_verified_reads_available() {
        let parent = private();
        let first = private();
        let second = private();
        let cache = SourceCache::open(parent.path(), DEFAULT_SOURCE_CACHE_BYTES).unwrap();
        let mut source = staged(first.path(), &[("a", b"first")]);
        let other = staged(second.path(), &[("b", b"other")]);
        let mut checkpoints = cache.checkpoints(source.manifest()).unwrap().unwrap();
        checkpoints.remember_file(&mut source, "a").unwrap();
        assert!(cache.checkpoints(other.manifest()).unwrap().is_none());
        assert_eq!(cache.remember(&other).unwrap(), 0);
        assert_eq!(cache.load(&entry("a", b"first")).unwrap().bytes(), b"first");
        drop(checkpoints);
        assert_eq!(cache.remember(&other).unwrap(), 1);
        assert_eq!(cache.load(&entry("b", b"other")).unwrap().bytes(), b"other");
    }

    #[test]
    fn checkpoint_writer_preserves_panic_poison_and_rejects_a_replaced_lock_inode() {
        for panic_writer in [false, true] {
            let parent = private();
            let input = private();
            let cache = SourceCache::open(parent.path(), DEFAULT_SOURCE_CACHE_BYTES).unwrap();
            let mut source = staged(input.path(), &[("a", b"first"), ("b", b"other")]);
            let mut checkpoints = cache.checkpoints(source.manifest()).unwrap().unwrap();
            checkpoints.remember_file(&mut source, "a").unwrap();
            if panic_writer {
                assert!(
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                        let _owned = checkpoints;
                        panic!("exercise owned source writer poisoning");
                    }))
                    .is_err()
                );
                assert!(cache.writer().is_err());
            } else {
                fs::rename(cache.root.join("lock"), cache.root.join("preserved-lock")).unwrap();
                drop(File::create(cache.root.join("lock")).unwrap());
                assert!(matches!(
                    checkpoints.remember_file(&mut source, "b"),
                    Err(RememberError::Cache(_))
                ));
                assert!(
                    !cache
                        .root
                        .join(object_name(&Sha256::digest(b"other").into()))
                        .exists()
                );
            }
            assert_eq!(cache.load(&entry("a", b"first")).unwrap().bytes(), b"first");
        }
    }

    #[test]
    fn checkpoint_storage_failure_and_expiry_do_not_hide_or_poison_valid_source_bytes() {
        for expire in [false, true] {
            let parent = private();
            let input = private();
            let cache = SourceCache::open(parent.path(), DEFAULT_SOURCE_CACHE_BYTES).unwrap();
            let expected = entry("file", b"good");
            let mut source = SourceReceiver::create(
                &input.path().join("source"),
                SourceManifest::new(vec![expected.clone()]).unwrap(),
            )
            .unwrap();
            source
                .write_chunk("file", 0, b"good", expected.sha256)
                .unwrap();
            let mut checkpoints = cache.checkpoints(source.manifest()).unwrap().unwrap();
            if expire {
                checkpoints.cache.control.deadline = Some(Instant::now());
            } else {
                fs::create_dir(cache.root.join(INCOMING)).unwrap();
            }
            assert!(matches!(
                checkpoints.remember_file(&mut source, "file"),
                Err(RememberError::Cache(_))
            ));
            assert!(!cache.root.join(object_name(&expected.sha256)).exists());
            assert!(source.sealed_root().is_none());
            source.seal().unwrap();
            assert_eq!(
                fs::read(source.sealed_root().unwrap().join("file")).unwrap(),
                b"good"
            );
        }
    }

    #[test]
    fn oversized_projection_keeps_a_stable_reusable_subset_across_reopens() {
        let parent = private();
        let input = private();
        let source = staged(
            input.path(),
            &[
                ("a", b"aaaa"),
                ("b", b"bbbb"),
                ("c", b"cccc"),
                ("d", b"dddd"),
            ],
        );
        // Exercise the byte and object ceilings independently, then together.
        for (bytes, files) in [(8, 4), (16, 2), (8, 2)] {
            let directory = private();
            let cache = bounded_cache(directory.path(), bytes, files);
            assert_eq!(cache.remember(&source).unwrap(), 2);
            let original = cache_inodes(&cache);
            for _ in 0..4 {
                let reopened = bounded_cache(directory.path(), bytes, files);
                assert_eq!(reopened.remember(&source).unwrap(), 0);
                assert_eq!(cache_inodes(&reopened), original);
                assert_eq!(
                    reopened.load(&entry("any", b"aaaa")).unwrap().bytes(),
                    b"aaaa"
                );
                assert_eq!(
                    reopened.load(&entry("any", b"bbbb")).unwrap().bytes(),
                    b"bbbb"
                );
                assert!(reopened.load(&entry("any", b"cccc")).is_none());
                assert!(reopened.load(&entry("any", b"dddd")).is_none());
                assert!(!reopened.root.join(INCOMING).exists());
            }
        }
        // An empty capacity is a refused cache admission, not a source error.
        let cache = bounded_cache(parent.path(), 0, 0);
        assert_eq!(cache.remember(&source).unwrap(), 0);
        assert!(cache_inodes(&cache).is_empty());
    }

    #[test]
    fn a_sorted_early_miss_cannot_evict_a_later_verified_hit() {
        let parent = private();
        let seed = private();
        let cached = staged(seed.path(), &[("hot", b"warm")]);
        let cache = bounded_cache(parent.path(), 4, 1);
        assert_eq!(cache.remember(&cached).unwrap(), 1);
        let original = cache_inodes(&cache);
        let input = private();
        let source = staged(input.path(), &[("a-cold", b"cold"), ("z-hot", b"warm")]);
        assert_eq!(cache.remember(&source).unwrap(), 0);
        assert_eq!(cache_inodes(&cache), original);
        assert_eq!(
            cache.load(&entry("z-hot", b"warm")).unwrap().bytes(),
            b"warm"
        );
        assert!(cache.load(&entry("a-cold", b"cold")).is_none());
    }

    #[test]
    fn an_unfittable_miss_does_not_evict_unrelated_cache_entries_either() {
        let parent = private();
        let seed = private();
        let cached = staged(seed.path(), &[("hot", b"abcdef"), ("other", b"xy")]);
        let cache = bounded_cache(parent.path(), 8, 3);
        assert_eq!(cache.remember(&cached).unwrap(), 2);
        let original = cache_inodes(&cache);
        let input = private();
        let source = staged(input.path(), &[("a-new", b"12345"), ("z-hot", b"abcdef")]);
        assert_eq!(cache.remember(&source).unwrap(), 0);
        assert_eq!(cache_inodes(&cache), original);
        assert_eq!(cache.load(&entry("other", b"xy")).unwrap().bytes(), b"xy");
        assert_eq!(
            cache.load(&entry("z-hot", b"abcdef")).unwrap().bytes(),
            b"abcdef"
        );
        assert!(cache.load(&entry("a-new", b"12345")).is_none());
    }

    #[test]
    fn lru_eviction_still_reclaims_objects_outside_the_current_projection() {
        let parent = private();
        let seed = private();
        let cached = staged(
            seed.path(),
            &[("a", b"aaaa"), ("b", b"bbbb"), ("c", b"cccc")],
        );
        let cache = bounded_cache(parent.path(), 12, 3);
        assert_eq!(cache.remember(&cached).unwrap(), 3);
        // Deliberate timestamps, not sleeps or filesystem timestamp resolution.
        for (file, seconds) in cached.manifest().files().iter().zip([30, 10, 20]) {
            File::open(cache.root.join(object_name(&file.sha256)))
                .unwrap()
                .set_modified(SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(seconds))
                .unwrap();
        }
        let input = private();
        let source = staged(input.path(), &[("a-new", b"NEW!"), ("z-hot", b"aaaa")]);
        assert_eq!(cache.remember(&source).unwrap(), 1);
        assert!(cache.load(&entry("b", b"bbbb")).is_none());
        for bytes in [b"aaaa", b"cccc", b"NEW!"] {
            assert_eq!(cache.load(&entry("any", bytes)).unwrap().bytes(), bytes);
        }
        let entries = cache.inventory().unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries.iter().map(|entry| entry.bytes).sum::<u64>(), 12);
        assert_eq!(
            fs::read(cached.sealed_root().unwrap().join("b")).unwrap(),
            b"bbbb"
        );
    }

    #[test]
    fn duplicate_contents_consume_one_object_and_one_byte_allowance() {
        let parent = private();
        let input = private();
        let source = staged(
            input.path(),
            &[
                ("a", b"same"),
                ("b", b"diff"),
                ("c", b"same"),
                ("d", b"tail"),
            ],
        );
        let cache = bounded_cache(parent.path(), 8, 2);
        assert_eq!(cache.remember(&source).unwrap(), 2);
        assert_eq!(cache.remember(&source).unwrap(), 0);
        let entries = cache.inventory().unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries.iter().map(|entry| entry.bytes).sum::<u64>(), 8);
        assert_eq!(cache.load(&entry("c", b"same")).unwrap().bytes(), b"same");
        assert!(cache.load(&entry("d", b"tail")).is_none());
    }

    #[test]
    fn corrupted_requested_objects_are_not_protected_from_repair_or_eviction() {
        let parent = private();
        let input = private();
        let source = staged(input.path(), &[("a", b"aaaa"), ("b", b"bbbb")]);
        let cache = bounded_cache(parent.path(), 8, 2);
        assert_eq!(cache.remember(&source).unwrap(), 2);
        for file in source.manifest().files() {
            let path = cache.root.join(object_name(&file.sha256));
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            fs::write(&path, b"oversized-corrupt").unwrap();
            assert!(cache.load(file).is_none());
        }
        // Names alone cannot pin oversized corrupt objects and deadlock repair.
        assert_eq!(cache.remember(&source).unwrap(), 2);
        for file in source.manifest().files() {
            assert_eq!(
                cache.load(file).unwrap().bytes(),
                fs::read(source.sealed_root().unwrap().join(&file.path)).unwrap()
            );
        }
        assert_eq!(
            cache
                .inventory()
                .unwrap()
                .iter()
                .map(|entry| entry.bytes)
                .sum::<u64>(),
            8
        );
        assert_eq!(cache.remember(&source).unwrap(), 0);
    }

    #[test]
    fn cache_pressure_does_not_hide_a_changed_sealed_source() {
        let parent = private();
        let seed = private();
        let cached = staged(seed.path(), &[("hot", b"warm")]);
        let cache = bounded_cache(parent.path(), 4, 1);
        cache.remember(&cached).unwrap();
        let input = private();
        let source = staged(input.path(), &[("a-cold", b"cold"), ("z-hot", b"warm")]);
        let path = source.sealed_root().unwrap().join("a-cold");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&path, b"evil").unwrap();
        assert!(matches!(
            cache.remember(&source),
            Err(RememberError::Source(_))
        ));
        assert_eq!(cache.load(&entry("hot", b"warm")).unwrap().bytes(), b"warm");
        assert!(cache.load(&entry("a-cold", b"cold")).is_none());
        assert!(!cache.root.join(INCOMING).exists());
    }

    #[test]
    fn protection_ends_with_the_projection_and_does_not_pin_the_cache_forever() {
        let parent = private();
        let first = private();
        let second = private();
        let old = staged(first.path(), &[("old", b"aaaa")]);
        let new = staged(second.path(), &[("new", b"bbbb")]);
        let cache = bounded_cache(parent.path(), 4, 1);
        assert_eq!(cache.remember(&old).unwrap(), 1);
        assert_eq!(cache.remember(&new).unwrap(), 1);
        assert!(cache.load(&entry("old", b"aaaa")).is_none());
        assert_eq!(cache.load(&entry("new", b"bbbb")).unwrap().bytes(), b"bbbb");
        assert_eq!(cache.remember(&old).unwrap(), 1);
        assert!(cache.load(&entry("new", b"bbbb")).is_none());
        assert_eq!(cache.load(&entry("old", b"aaaa")).unwrap().bytes(), b"aaaa");
    }

    #[test]
    fn large_verified_spool_is_independent_of_later_cache_mutation() {
        let parent = private();
        let input = private();
        let bytes = vec![b'A'; 5 * 1024 * 1024 + 13];
        let source = staged(input.path(), &[("liblarge.rlib", &bytes)]);
        let expected = &source.manifest().files()[0];
        let cache = SourceCache::open(parent.path(), DEFAULT_SOURCE_CACHE_BYTES).unwrap();
        assert_eq!(cache.remember(&source).unwrap(), 1);
        let snapshot = cache.load(expected).unwrap();
        let cached = cache.root.join(object_name(&expected.sha256));
        assert_ne!(
            snapshot.file.metadata().unwrap().ino(),
            fs::metadata(&cached).unwrap().ino()
        );
        fs::set_permissions(&cached, fs::Permissions::from_mode(0o600)).unwrap();
        fs::OpenOptions::new()
            .write(true)
            .open(&cached)
            .unwrap()
            .write_all(b"B")
            .unwrap();
        assert!(cache.load(expected).is_none());

        let next = private();
        let mut receiver =
            SourceReceiver::create(&next.path().join("workspace"), source.manifest().clone())
                .unwrap();
        snapshot.install(&mut receiver).unwrap();
        let installed = receiver.seal().unwrap().join(&expected.path);
        assert_eq!(fs::read(&installed).unwrap(), bytes);
        assert_ne!(
            fs::metadata(installed).unwrap().ino(),
            fs::metadata(cached).unwrap().ino()
        );
    }

    #[test]
    fn retained_readers_have_independent_positions_and_survive_eviction() {
        let parent = private();
        let input = private();
        let source = staged(input.path(), &[("lib.rmeta", b"ABCD")]);
        let expected = &source.manifest().files()[0];
        let cache = SourceCache::open(parent.path(), 4).unwrap();
        cache.remember(&source).unwrap();
        let mut first = cache.load(expected).unwrap();
        let mut second = cache.load(expected).unwrap();
        let mut prefix = [0_u8; 2];
        first.file.read_exact(&mut prefix).unwrap();
        assert_eq!(&prefix, b"AB");
        assert_eq!(second.file.stream_position().unwrap(), 0);
        second.file.read_exact(&mut prefix).unwrap();
        assert_eq!(&prefix, b"AB");
        assert_eq!(first.file.stream_position().unwrap(), 2);
        first.file.rewind().unwrap();
        second.file.rewind().unwrap();
        let replacement = private();
        let next = staged(replacement.path(), &[("next.rmeta", b"WXYZ")]);
        cache.remember(&next).unwrap();
        assert!(cache.load(expected).is_none());
        for snapshot in [first, second] {
            let destination = private();
            let mut receiver = SourceReceiver::create(
                &destination.path().join("workspace"),
                source.manifest().clone(),
            )
            .unwrap();
            snapshot.install(&mut receiver).unwrap();
            assert_eq!(
                fs::read(receiver.seal().unwrap().join("lib.rmeta")).unwrap(),
                b"ABCD"
            );
        }
    }

    #[test]
    fn large_objects_obey_capacity_and_a_lowered_budget_after_reopen() {
        let parent = private();
        let input = private();
        let first = vec![b'A'; 5 * 1024 * 1024 + 17];
        let second = vec![b'B'; first.len()];
        let source = staged(input.path(), &[("a.rlib", &first), ("b.rlib", &second)]);
        // Three quarters remain available to byte objects after the retained
        // projection reservation; enough for one of these actual large files.
        let capacity = 8 * 1024 * 1024;
        let cache = SourceCache::open(parent.path(), capacity).unwrap();
        assert_eq!(cache.remember(&source).unwrap(), 1);
        let inodes = cache_inodes(&cache);
        assert_eq!(
            cache
                .inventory()
                .unwrap()
                .iter()
                .map(|entry| entry.bytes)
                .sum::<u64>(),
            first.len() as u64
        );
        let reopened = SourceCache::open(parent.path(), capacity).unwrap();
        assert_eq!(reopened.remember(&source).unwrap(), 0);
        assert_eq!(cache_inodes(&reopened), inodes);
        assert_eq!(
            reopened
                .load(&source.manifest().files()[0])
                .unwrap()
                .bytes(),
            first
        );
        assert!(reopened.load(&source.manifest().files()[1]).is_none());

        drop(reopened);
        drop(cache);
        let smaller = SourceCache::open(parent.path(), 4 * 1024 * 1024).unwrap();
        assert!(smaller.load(&source.manifest().files()[0]).is_none());
        assert_eq!(smaller.remember(&source).unwrap(), 0);
        assert!(smaller.inventory().unwrap().is_empty());
        assert_eq!(
            fs::metadata(source.sealed_root().unwrap().join("a.rlib"))
                .unwrap()
                .len(),
            first.len() as u64
        );
    }

    #[test]
    fn streaming_verification_detects_mutation_after_the_modified_bytes_were_read() {
        struct MutatingSink<'a> {
            path: &'a Path,
            changed: bool,
        }
        impl Write for MutatingSink<'_> {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                if !self.changed {
                    self.changed = true;
                    fs::set_permissions(self.path, fs::Permissions::from_mode(0o600))?;
                    fs::OpenOptions::new()
                        .write(true)
                        .open(self.path)?
                        .write_all(b"B")?;
                }
                Ok(bytes.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let input = private();
        let bytes = vec![b'A'; MAX_SOURCE_CHUNK * 3 + 7];
        let source = staged(input.path(), &[("lib.rlib", &bytes)]);
        let path = source.sealed_root().unwrap().join("lib.rlib");
        let mut sink = MutatingSink {
            path: &path,
            changed: false,
        };
        assert!(matches!(
            copy_verified(
                &path,
                &source.manifest().files()[0],
                &CacheControl::default(),
                &mut sink,
            ),
            Err(RememberError::Source(_))
        ));
        assert!(sink.changed);
    }

    #[test]
    fn cache_verification_stops_after_a_real_copy_chunk_when_session_is_cancelled() {
        struct CancellingOutput {
            file: File,
            cancelled: Arc<AtomicBool>,
        }
        impl Write for CancellingOutput {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.file.write_all(bytes)?;
                self.cancelled.store(true, Ordering::Release);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                self.file.flush()
            }
        }
        let input = private();
        let bytes = vec![b'A'; MAX_SOURCE_CHUNK * 3 + 7];
        let source = staged(input.path(), &[("lib.rlib", &bytes)]);
        let cancelled = Arc::new(AtomicBool::new(false));
        let control = CacheControl {
            cancelled: Some(Arc::clone(&cancelled)),
            ..CacheControl::default()
        };
        let mut output = CancellingOutput {
            file: tempfile::tempfile_in(input.path()).unwrap(),
            cancelled,
        };
        let result = copy_verified(
            &source.sealed_root().unwrap().join("lib.rlib"),
            &source.manifest().files()[0],
            &control,
            &mut output,
        );
        assert!(matches!(result,
            Err(RememberError::Cache(error)) if error.kind() == io::ErrorKind::Interrupted));
        assert_eq!(
            output.file.metadata().unwrap().len(),
            MAX_SOURCE_CHUNK as u64
        );
        output.file.rewind().unwrap();
        let mut copied = Vec::new();
        output.file.read_to_end(&mut copied).unwrap();
        assert_eq!(copied, bytes[..MAX_SOURCE_CHUNK]);
    }

    #[test]
    fn cancelled_cache_session_does_not_modify_receiver_or_revoke_other_sessions() {
        let parent = private();
        let input = private();
        let bytes = vec![0x81; MAX_SOURCE_CHUNK * 2 + 1];
        let source = staged(input.path(), &[("lib.rlib", &bytes)]);
        let expected = &source.manifest().files()[0];
        let cache = SourceCache::open(parent.path(), DEFAULT_SOURCE_CACHE_BYTES).unwrap();
        cache.remember(&source).unwrap();
        let cancelled = Arc::new(AtomicBool::new(false));
        let session = cache.clone().with_cancellation(Arc::clone(&cancelled));
        let snapshot = session.load(expected).unwrap();
        let original = cache_inodes(&cache);
        cancelled.store(true, Ordering::Release);
        assert!(session.load(expected).is_none());
        assert!(matches!(session.remember(&source),
            Err(RememberError::Cache(error)) if error.kind() == io::ErrorKind::Interrupted));
        let next = private();
        let mut receiver =
            SourceReceiver::create(&next.path().join("workspace"), source.manifest().clone())
                .unwrap();
        assert_eq!(
            snapshot.install(&mut receiver).unwrap_err().kind(),
            io::ErrorKind::Interrupted
        );
        assert_eq!(
            fs::metadata(next.path().join("workspace/lib.rlib"))
                .unwrap()
                .len(),
            0
        );
        assert!(receiver.sealed_root().is_none());
        assert_eq!(cache_inodes(&cache), original);
        // A new session keeps the same reusable bytes but has independent
        // cancellation custody; cancelled consumers cannot poison the cache.
        cache
            .load(expected)
            .unwrap()
            .install(&mut receiver)
            .unwrap();
        let installed = receiver.seal().unwrap().join("lib.rlib");
        assert_eq!(fs::read(&installed).unwrap(), bytes);
        assert_ne!(
            fs::metadata(installed).unwrap().ino(),
            fs::metadata(cache.root.join(object_name(&expected.sha256)))
                .unwrap()
                .ino()
        );
    }

    #[test]
    fn expired_cache_work_neither_modifies_receiver_nor_publishes_cache_bytes() {
        let parent = private();
        let input = private();
        let source = staged(input.path(), &[("lib.rs", b"good")]);
        let expected = &source.manifest().files()[0];
        let cache = SourceCache::open(parent.path(), DEFAULT_SOURCE_CACHE_BYTES).unwrap();
        cache.remember(&source).unwrap();
        let original = cache_inodes(&cache);
        let expired = cache.clone().before(Instant::now());
        assert!(expired.load(expected).is_none());
        assert!(
            matches!(expired.remember(&source), Err(RememberError::Cache(error)) if error.kind() == io::ErrorKind::TimedOut)
        );
        assert_eq!(cache_inodes(&cache), original);
        assert!(!cache.root.join(INCOMING).exists());

        let mut snapshot = cache.load(expected).unwrap();
        snapshot.control.deadline = Some(Instant::now());
        let next = private();
        let mut receiver =
            SourceReceiver::create(&next.path().join("workspace"), source.manifest().clone())
                .unwrap();
        assert_eq!(
            snapshot.install(&mut receiver).unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(
            fs::metadata(next.path().join("workspace/lib.rs"))
                .unwrap()
                .len(),
            0
        );
        receiver
            .write_chunk("lib.rs", 0, b"good", Sha256::digest(b"good").into())
            .unwrap();
        assert!(receiver.seal().is_ok());
    }
}
