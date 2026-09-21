//! Private, bounded reuse of uploaded source bytes, not action-cache authority.
//!
//! Every hit is read and SHA-256 verified before it can populate a fresh source
//! receiver. Executions never share writable inodes with this cache. Cache loss,
//! eviction, corruption, and a busy writer only cost another source upload.
//! The directory is scoped to one trusted worker administrative domain.

use rabs_sandbox::source_transfer::{SourceFile, SourceReceiver};
use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

const MAX_BYTES: u64 = 256 * 1024 * 1024;
const MAX_FILES: usize = 4096;
const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024;
const INCOMING: &str = "incoming";

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
    Err(io::Error::new(io::ErrorKind::Unsupported, "source reuse requires Unix"))
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

fn object_name(digest: &[u8; 32]) -> String {
    format!("{}.src", super::hex(digest))
}

fn owned_name(name: &str) -> bool {
    name.len() == 68
        && name.ends_with(".src")
        && name.as_bytes()[..64].iter().all(|b| {
            b.is_ascii_digit() || (b'a'..=b'f').contains(b)
        })
}

/// The bound is checked before allocating, and the descriptor is checked against
/// the named inode. No mtime, filename, or former successful upload is a hit.
fn read_verified(path: &Path, expected: &SourceFile) -> io::Result<(File, Vec<u8>)> {
    if expected.len > MAX_FILE_BYTES {
        return Err(invalid("source object exceeds the per-file reuse bound"));
    }
    let named = fs::symlink_metadata(path)?;
    if !ordinary(&named) || named.len() != expected.len {
        return Err(invalid("source object has an unexpected type or length"));
    }
    let mut input = File::open(path)?;
    let before = input.metadata()?;
    if !ordinary(&before) || !same_inode(&named, &before) || before.len() != expected.len {
        return Err(invalid("source object changed while opening"));
    }
    let mut bytes = Vec::new();
    (&mut input).take(expected.len + 1).read_to_end(&mut bytes)?;
    let after = input.metadata()?;
    if !ordinary(&after)
        || after.len() != expected.len
        || bytes.len() as u64 != expected.len
        || <[u8; 32]>::from(Sha256::digest(&bytes)) != expected.sha256
    {
        return Err(invalid("source object content verification failed"));
    }
    Ok((input, bytes))
}

struct Entry {
    path: PathBuf,
    bytes: u64,
    used: SystemTime,
}

/// A path is only configuration, never an input capability. The cache owns a
/// dedicated namespace below an explicitly configured private directory.
#[derive(Debug, Clone)]
pub(super) struct SourceCache {
    root: PathBuf,
    max_bytes: u64,
    max_files: usize,
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
    pub(super) fn configured() -> io::Result<Option<Self>> {
        std::env::var_os("RABS_SOURCE_CACHE_DIR")
            .map(|root| Self::open(Path::new(&root)))
            .transpose()
    }

    pub(super) fn open(parent: &Path) -> io::Result<Self> {
        if !parent.is_absolute() {
            return Err(invalid("RABS_SOURCE_CACHE_DIR must be absolute"));
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
        Ok(Self { root, max_bytes: MAX_BYTES, max_files: MAX_FILES })
    }

    /// An unavailable or corrupt object is a MISS before any staging write.
    /// Recency is eviction policy only; it never establishes content identity.
    pub(super) fn load(&self, expected: &SourceFile) -> Option<Vec<u8>> {
        private_directory(&self.root).ok()?;
        let (file, bytes) = read_verified(&self.root.join(object_name(&expected.sha256)), expected).ok()?;
        let _ = file.set_modified(SystemTime::now());
        Some(bytes)
    }

    fn writer(&self) -> io::Result<Option<File>> {
        private_directory(&self.root)?;
        let path = self.root.join("lock");
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
            Ok(()) => Ok(Some(file)),
            Err(fs::TryLockError::WouldBlock) => Ok(None),
            Err(fs::TryLockError::Error(error)) => Err(error),
        }
    }

    /// Called with the exclusive cache lock held. A dead writer leaves at most
    /// one bounded scratch file. It is never read as a reusable object.
    fn inventory(&self) -> io::Result<VecDeque<Entry>> {
        let scratch = self.root.join(INCOMING);
        match fs::symlink_metadata(&scratch) {
            Ok(meta) if ordinary(&meta) && meta.len() <= MAX_FILE_BYTES => fs::remove_file(&scratch)?,
            Ok(_) => return Err(invalid("invalid source cache scratch file")),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let mut entries = Vec::new();
        for item in fs::read_dir(&self.root)? {
            let item = item?;
            let name = item.file_name();
            if name == "lock" { continue; }
            if entries.len() >= self.max_files
                || !name.to_str().is_some_and(owned_name)
                || !ordinary(&fs::symlink_metadata(item.path())?)
            {
                return Err(invalid("source cache inventory is not an owned bounded file set"));
            }
            let meta = fs::symlink_metadata(item.path())?;
            entries.push(Entry {
                path: item.path(), bytes: meta.len(),
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
    pub(super) fn remember(&self, receiver: &SourceReceiver) -> Result<u64, RememberError> {
        let root = receiver.sealed_root().ok_or_else(|| {
            RememberError::Source(invalid("cannot cache unsealed source"))
        })?;
        let Some(_lock) = self.writer()? else { return Ok(0); };
        let mut entries = self.inventory()?;
        let mut total = entries.iter().try_fold(0_u64, |sum, entry| {
            sum.checked_add(entry.bytes).ok_or_else(|| invalid("source cache size overflow"))
        })?;
        let mut stored = 0;
        for expected in receiver.manifest().files() {
            if expected.len == 0 || expected.len > MAX_FILE_BYTES || expected.len > self.max_bytes {
                continue;
            }
            if self.load(expected).is_some() { continue; }
            let (_, bytes) = read_verified(&root.join(&expected.path), expected)
                .map_err(RememberError::Source)?;
            let destination = self.root.join(object_name(&expected.sha256));
            // A corrupted object with this name must not make future uploads
            // permanently miss. Only our ordinary, inventoried cache file moves.
            if let Some(index) = entries.iter().position(|entry| entry.path == destination) {
                let entry = entries.remove(index).ok_or_else(|| invalid("source cache inventory changed"))?;
                fs::remove_file(&entry.path)?;
                total -= entry.bytes;
            }
            while entries.len() >= self.max_files
                || total.checked_add(expected.len).is_none_or(|sum| sum > self.max_bytes)
            {
                let Some(entry) = entries.pop_front() else { break; };
                fs::remove_file(&entry.path)?;
                total -= entry.bytes;
            }
            if entries.len() >= self.max_files || total + expected.len > self.max_bytes {
                continue;
            }
            // One fixed scratch name plus the held process-shared lock bounds
            // crash debris and serializes capacity accounting across workers.
            let scratch = self.root.join(INCOMING);
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(&scratch)?;
            file.write_all(&bytes)?;
            let mut permissions = file.metadata()?.permissions();
            permissions.set_readonly(true);
            file.set_permissions(permissions)?;
            drop(file);
            fs::rename(&scratch, &destination)?;
            total += expected.len;
            entries.push_back(Entry { path: destination, bytes: expected.len, used: SystemTime::now() });
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
        SourceFile { path: path.into(), len: bytes.len() as u64,
            sha256: Sha256::digest(bytes).into(), executable: false }
    }

    fn staged(parent: &Path, files: &[(&str, &[u8])]) -> SourceReceiver {
        let manifest = SourceManifest::new(files.iter().map(|(path, bytes)| entry(path, bytes)).collect()).unwrap();
        let mut receiver = SourceReceiver::create(&parent.join("workspace"), manifest).unwrap();
        for (path, bytes) in files {
            if !bytes.is_empty() {
                receiver.write_chunk(path, 0, bytes, Sha256::digest(bytes).into()).unwrap();
            }
        }
        receiver.seal().unwrap();
        receiver
    }

    #[test]
    fn reuse_survives_reopen_and_never_aliases_a_staging_inode() {
        let parent = tempfile::tempdir().unwrap();
        let input = tempfile::tempdir().unwrap();
        let source = staged(input.path(), &[("lib.rs", b"A\0\xffB")]);
        let expected = source.manifest().files()[0].clone();
        let cache = SourceCache::open(parent.path()).unwrap();
        assert_eq!(cache.remember(&source).unwrap(), 1);
        let cache = SourceCache::open(parent.path()).unwrap();
        let mut projected = expected.clone();
        projected.path = "different/name.rs".into();
        projected.executable = true;
        let bytes = cache.load(&projected).unwrap();
        assert_eq!(bytes, b"A\0\xffB");
        let next = tempfile::tempdir().unwrap();
        let mut receiver = SourceReceiver::create(&next.path().join("workspace"),
            SourceManifest::new(vec![projected.clone()]).unwrap()).unwrap();
        receiver.write_chunk(&projected.path, 0, &bytes, Sha256::digest(&bytes).into()).unwrap();
        let installed = receiver.seal().unwrap().join(&projected.path);
        assert_ne!(fs::metadata(&installed).unwrap().ino(),
            fs::metadata(cache.root.join(object_name(&expected.sha256))).unwrap().ino());
        fs::set_permissions(&installed, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&installed, b"changed").unwrap();
        assert_eq!(cache.load(&expected).unwrap(), b"A\0\xffB");
    }

    #[test]
    fn corruption_and_wrong_length_miss_and_a_verified_upload_repairs_the_object() {
        let parent = tempfile::tempdir().unwrap();
        let input = tempfile::tempdir().unwrap();
        let source = staged(input.path(), &[("lib.rs", b"good")]);
        let expected = &source.manifest().files()[0];
        let cache = SourceCache::open(parent.path()).unwrap();
        cache.remember(&source).unwrap();
        let path = cache.root.join(object_name(&expected.sha256));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&path, b"evil").unwrap();
        assert!(cache.load(expected).is_none());
        assert_eq!(cache.remember(&source).unwrap(), 1);
        assert_eq!(cache.load(expected).unwrap(), b"good");
        let mut wrong = expected.clone();
        wrong.len += 1;
        assert!(cache.load(&wrong).is_none());
        wrong.len = MAX_FILE_BYTES + 1;
        assert!(cache.load(&wrong).is_none());
    }

    #[test]
    fn symlinks_and_hardlinks_are_not_reusable_source_objects() {
        for hardlink in [false, true] {
            let parent = tempfile::tempdir().unwrap();
            let input = tempfile::tempdir().unwrap();
            let source = staged(input.path(), &[("lib.rs", b"good")]);
            let expected = &source.manifest().files()[0];
            let cache = SourceCache::open(parent.path()).unwrap();
            let path = cache.root.join(object_name(&expected.sha256));
            let original = source.sealed_root().unwrap().join("lib.rs");
            if hardlink { fs::hard_link(original, path).unwrap(); }
            else { symlink(original, path).unwrap(); }
            assert!(cache.load(expected).is_none());
            assert!(cache.remember(&source).is_err());
        }
    }

    #[test]
    fn byte_and_entry_limits_evict_cache_objects_not_source_files() {
        let parent = tempfile::tempdir().unwrap();
        let input = tempfile::tempdir().unwrap();
        let source = staged(input.path(), &[("a", b"aaaa"), ("b", b"bbbb"), ("c", b"cccc")]);
        let mut cache = SourceCache::open(parent.path()).unwrap();
        cache.max_bytes = 8;
        cache.max_files = 2;
        assert_eq!(cache.remember(&source).unwrap(), 3);
        let entries = cache.inventory().unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries.iter().map(|entry| entry.bytes).sum::<u64>(), 8);
        assert_eq!(cache.load(&source.manifest().files()[2]).unwrap(), b"cccc");
        assert_eq!(fs::read(source.sealed_root().unwrap().join("a")).unwrap(), b"aaaa");
    }

    #[test]
    fn writer_contention_does_not_block_and_abandoned_scratch_is_never_a_hit() {
        let parent = tempfile::tempdir().unwrap();
        let input = tempfile::tempdir().unwrap();
        let source = staged(input.path(), &[("lib.rs", b"good")]);
        let expected = &source.manifest().files()[0];
        let cache = SourceCache::open(parent.path()).unwrap();
        let lock = cache.writer().unwrap().unwrap();
        assert_eq!(cache.remember(&source).unwrap(), 0);
        fs::write(cache.root.join(INCOMING), b"torn").unwrap();
        assert!(cache.load(expected).is_none());
        drop(lock);
        assert_eq!(cache.remember(&source).unwrap(), 1);
        assert!(!cache.root.join(INCOMING).exists());
        assert_eq!(cache.load(expected).unwrap(), b"good");
    }

    #[test]
    fn unsealed_source_and_nonprivate_configuration_refuse() {
        let parent = tempfile::tempdir().unwrap();
        let input = tempfile::tempdir().unwrap();
        let cache = SourceCache::open(parent.path()).unwrap();
        let source = SourceReceiver::create(&input.path().join("workspace"),
            SourceManifest::new(vec![entry("lib.rs", b"good")]).unwrap()).unwrap();
        assert!(cache.remember(&source).is_err());
        assert!(SourceCache::open(Path::new("relative")).is_err());
        fs::set_permissions(parent.path(), fs::Permissions::from_mode(0o755)).unwrap();
        assert!(SourceCache::open(parent.path()).is_err());
    }
}
