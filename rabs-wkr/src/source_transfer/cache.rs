//! Private, bounded reuse of uploaded source bytes, not action-cache authority.
//!
//! Every hit is read and SHA-256 verified before it can populate a fresh source
//! receiver. Executions never share writable inodes with this cache. Cache loss,
//! eviction, corruption, and a busy writer only cost another source upload.
//! The directory is scoped to one trusted worker administrative domain.

use rabs_sandbox::source_transfer::{
    MAX_SOURCE_BYTES, MAX_SOURCE_CHUNK, SOURCE_PROJECTION_PREFIX, SourceFile, SourceProjectionPool,
    SourceReceiver,
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, VecDeque};
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Read, Seek, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Instant, SystemTime};

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
    format!("{}.src", super::hex(digest))
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
    output: &mut impl Write,
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

/// An anonymous, independently owned snapshot of a completely verified object.
/// Cache replacement after lookup cannot change these bytes. Only this type can
/// begin populating the receiver, and it never allocates an object-sized buffer.
#[derive(Debug)]
pub(super) struct VerifiedSource {
    file: File,
    expected: SourceFile,
    control: CacheControl,
}

impl VerifiedSource {
    pub(super) fn install(mut self, receiver: &mut SourceReceiver) -> io::Result<()> {
        self.control.check()?;
        let result = receiver.import_file_with_cloner(
            &self.expected.path,
            &mut self.file,
            || self.control.stopped(),
            rabs_cas::materialization::try_verified_reflink,
        );
        // Preserve the fixed upload timeout separately from cancellation;
        // either condition has already poisoned a partially imported receiver.
        self.control.check()?;
        result.map(|_| ())
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
    local: Mutex<()>,
}

enum CacheWriter<'a> {
    Process { file: File },
    Local { _guard: MutexGuard<'a, ()> },
}

/// A path is only configuration, never an input capability. The cache owns a
/// dedicated namespace below an explicitly configured private directory.
#[derive(Debug, Clone)]
pub struct SourceCache {
    root: PathBuf,
    max_bytes: u64,
    max_files: usize,
    control: CacheControl,
    projections: Option<Arc<SourceProjectionPool>>,
    projection_writer: Option<Arc<ProjectionWriter>>,
    quarantine: Arc<Mutex<Option<File>>>,
}

#[derive(Debug)]
pub(super) enum RememberError {
    /// A known-invalid execution source must not be treated as optional cache I/O.
    Source(io::Error),
    Cache(io::Error),
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
        let projection_bytes = if max_bytes >= MIN_PROJECTION_CACHE_BYTES {
            max_bytes / 4
        } else {
            0
        };
        let mut cache = Self {
            root,
            max_bytes: max_bytes - projection_bytes,
            max_files: MAX_FILES,
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
                local: Mutex::new(()),
            }));
        } else {
            // An existing writer may still be using the old raw-file budget.
            // Skip the optional pool instead of oversubscribing that budget.
            cache.max_bytes = max_bytes;
        }
        Ok(cache)
    }

    pub(super) fn projections(&self) -> Option<Arc<SourceProjectionPool>> {
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

    pub(super) fn before(mut self, deadline: Instant) -> Self {
        self.control.deadline = Some(deadline);
        self
    }

    pub(super) fn with_cancellation(mut self, cancelled: Arc<AtomicBool>) -> Self {
        self.control.cancelled = Some(cancelled);
        self
    }

    /// An unavailable or corrupt object is a MISS before any staging write.
    /// Recency is eviction policy only; it never establishes content identity.
    pub(super) fn load(&self, expected: &SourceFile) -> Option<VerifiedSource> {
        if expected.len > self.max_bytes || expected.len > MAX_FILE_BYTES {
            return None;
        }
        self.control.check().ok()?;
        private_directory(&self.root).ok()?;
        let mut snapshot = tempfile::tempfile_in(&self.root).ok()?;
        let file = copy_verified(
            &self.root.join(object_name(&expected.sha256)),
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
            &self.root.join(object_name(&expected.sha256)),
            expected,
            &self.control,
            &mut io::sink(),
        ) else {
            return false;
        };
        let _ = file.set_modified(SystemTime::now());
        true
    }

    fn writer(&self) -> io::Result<Option<CacheWriter<'_>>> {
        self.control.check()?;
        private_directory(&self.root)?;
        let path = self.root.join("lock");
        if let Some(owner) = &self.projection_writer {
            let metadata = owner.file.metadata()?;
            if !ordinary(&metadata) || !same_inode(&metadata, &fs::symlink_metadata(&path)?) {
                return Err(invalid("retained source cache writer identity changed"));
            }
            return match owner.local.try_lock() {
                Ok(guard) => Ok(Some(CacheWriter::Local { _guard: guard })),
                Err(std::sync::TryLockError::WouldBlock) => Ok(None),
                Err(std::sync::TryLockError::Poisoned(_)) => {
                    Err(invalid("source cache writer poisoned"))
                }
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
    pub(super) fn remember(&self, receiver: &SourceReceiver) -> Result<u64, RememberError> {
        let root = receiver
            .sealed_root()
            .ok_or_else(|| RememberError::Source(invalid("cannot cache unsealed source")))?;
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
        for expected in receiver.manifest().files() {
            self.control.check()?;
            if expected.len == 0 || expected.len > MAX_FILE_BYTES || expected.len > self.max_bytes {
                continue;
            }
            if self.contains_verified(expected) {
                protected.insert(self.root.join(object_name(&expected.sha256)), expected.len);
            } else {
                missing.push(expected);
            }
        }
        let mut protected_bytes = protected.values().try_fold(0_u64, |sum, bytes| {
            sum.checked_add(*bytes)
                .ok_or_else(|| invalid("source cache protected size overflow"))
        })?;
        let mut stored = 0;
        for expected in missing {
            self.control.check()?;
            let destination = self.root.join(object_name(&expected.sha256));
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
                // Capacity pressure must not hide mutation of a sealed source.
                // Verify without allocating or writing an unnecessary spool.
                copy_verified(
                    &root.join(&expected.path),
                    expected,
                    &self.control,
                    &mut io::sink(),
                )?;
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
            copy_verified(
                &root.join(&expected.path),
                expected,
                &self.control,
                &mut file,
            )?;
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
    use rabs_sandbox::source_transfer::SourceManifest;
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

    #[cfg(all(
        target_os = "linux",
        not(any(target_arch = "sparc", target_arch = "sparc64"))
    ))]
    #[test]
    #[ignore = "requires RABS_REFLINK_TEST_ROOT on a real reflink-capable filesystem"]
    fn cached_snapshot_import_requires_real_verified_reflink_and_independent_seal() {
        let root = std::env::var_os("RABS_REFLINK_TEST_ROOT").expect("explicit capable filesystem");
        let parent = tempfile::tempdir_in(root).unwrap();
        let input = tempfile::tempdir_in(parent.path()).unwrap();
        let bytes = vec![0x29; MAX_SOURCE_CHUNK * 4 + 3];
        let source = staged(input.path(), &[("lib.rlib", &bytes)]);
        let cache = SourceCache::open(parent.path(), DEFAULT_SOURCE_CACHE_BYTES).unwrap();
        cache.remember(&source).unwrap();
        let expected = &source.manifest().files()[0];
        let mut snapshot = cache.load(expected).unwrap();
        let next = tempfile::tempdir_in(parent.path()).unwrap();
        let mut receiver =
            SourceReceiver::create(&next.path().join("workspace"), source.manifest().clone())
                .unwrap();
        assert!(
            receiver
                .import_file_with_cloner(
                    &expected.path,
                    &mut snapshot.file,
                    || snapshot.control.stopped(),
                    rabs_cas::materialization::try_verified_reflink,
                )
                .unwrap(),
            "a private-copy fallback does not satisfy this real CoW fixture"
        );
        assert!(receiver.sealed_root().is_none());
        snapshot.file.rewind().unwrap();
        snapshot.file.write_all(b"changed private spool").unwrap();
        let installed = receiver.seal().unwrap().join("lib.rlib");
        assert_eq!(fs::read(&installed).unwrap(), bytes);
        assert_ne!(
            snapshot.file.metadata().unwrap().ino(),
            fs::metadata(&installed).unwrap().ino()
        );
        fs::set_permissions(&installed, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&installed, b"changed private receiver").unwrap();
        assert_eq!(cache.load(expected).unwrap().bytes(), bytes);
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
