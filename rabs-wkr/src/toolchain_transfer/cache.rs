//! Bounded, optional reuse of SDK bytes across interrupted uploads.
//!
//! Byte objects carry no SDK or execution authority. Every lookup verifies the
//! actual file into a private upload snapshot, and the ordinary receiver still
//! seals the complete SDK. A single nonblocking writer inventories once per
//! upload, protects its hits, and checkpoints completed files before their ACK.
//! Negotiated prefix recovery uses the same object names and capacity. A short
//! object is only a hint until its independently copied hash is checked by the
//! sender; old completed-file readers continue to treat short objects as misses.

use rabs_sandbox::toolchain_transfer::{
    MAX_TOOLCHAIN_CHUNK, ToolchainCheckpointError, ToolchainFile, ToolchainReceiver,
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, Metadata};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

pub const MAX_TOOLCHAIN_FILE_CACHE_BYTES: u64 = 64 * 1024 * 1024 * 1024;
const MAX_OBJECTS: usize = 100_000;
const INCOMING: &str = "incoming";
const LOCK: &str = "lock";

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn checkpoint(stopped: &impl Fn() -> bool) -> io::Result<()> {
    if stopped() {
        Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "toolchain file reuse stopped",
        ))
    } else {
        Ok(())
    }
}

#[cfg(unix)]
fn same_inode(a: &Metadata, b: &Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    a.dev() == b.dev() && a.ino() == b.ino()
}

#[cfg(not(unix))]
fn same_inode(_a: &Metadata, _b: &Metadata) -> bool {
    false
}

#[cfg(unix)]
pub(super) fn same_state(a: &Metadata, b: &Metadata) -> bool {
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
pub(super) fn same_state(_a: &Metadata, _b: &Metadata) -> bool {
    false
}

#[cfg(unix)]
fn private_file(metadata: &Metadata, links: u64, writable: bool) -> bool {
    use std::os::unix::fs::MetadataExt;
    metadata.is_file()
        && metadata.nlink() == links
        && metadata.mode() & 0o077 == 0
        && (writable || metadata.mode() & 0o222 == 0)
}

#[cfg(not(unix))]
fn private_file(_metadata: &Metadata, _links: u64, _writable: bool) -> bool {
    false
}

#[cfg(unix)]
fn private_directory(path: &Path) -> io::Result<Metadata> {
    use std::os::unix::fs::MetadataExt;
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.mode() & 0o077 != 0 {
        return Err(invalid(
            "toolchain file cache requires a private ordinary directory",
        ));
    }
    Ok(metadata)
}

#[cfg(not(unix))]
fn private_directory(_path: &Path) -> io::Result<Metadata> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "toolchain file reuse requires Linux",
    ))
}

fn object_name(digest: &[u8; 32]) -> String {
    format!("{}.sdk", crate::source_transfer::hex(digest))
}

fn owned_name(name: &str) -> bool {
    name.len() == 68
        && name.ends_with(".sdk")
        && name.as_bytes()[..64]
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
}

#[derive(Debug)]
struct CacheRoot {
    path: PathBuf,
    directory: File,
    identity: Metadata,
}

/// Retained byte capacity is independent of source and whole-SDK retention.
/// Zero is configured by omitting this owner; the default worker budget is zero.
#[derive(Debug, Clone)]
pub struct ToolchainFileCache {
    root: Arc<CacheRoot>,
    max_bytes: u64,
}

impl ToolchainFileCache {
    pub fn open(parent: &Path, max_bytes: u64) -> io::Result<Self> {
        if !parent.is_absolute() || !(1..=MAX_TOOLCHAIN_FILE_CACHE_BYTES).contains(&max_bytes) {
            return Err(invalid(
                "invalid toolchain file cache directory or byte budget",
            ));
        }
        private_directory(parent)?;
        let path = fs::canonicalize(parent)?.join("toolchain-files-v1");
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        match builder.create(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
        let identity = private_directory(&path)?;
        #[cfg(target_os = "linux")]
        let directory = File::from(rustix::fs::open(
            &path,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )?);
        #[cfg(not(target_os = "linux"))]
        let directory = File::open(&path)?;
        if !same_inode(&identity, &directory.metadata()?) {
            return Err(invalid(
                "toolchain file cache directory changed while opening",
            ));
        }
        let cache = Self {
            root: Arc::new(CacheRoot {
                path,
                directory,
                identity,
            }),
            max_bytes,
        };
        // Reduce an older larger budget before advertising this cache. A busy
        // owner retains its own bound; this worker never waits for its writer.
        let _writer = cache.writer(&|| false)?;
        Ok(cache)
    }

    fn check(&self) -> io::Result<()> {
        if !same_inode(&self.root.identity, &private_directory(&self.root.path)?)
            || !same_inode(&self.root.identity, &self.root.directory.metadata()?)
        {
            return Err(invalid("toolchain file cache directory was replaced"));
        }
        Ok(())
    }

    /// Persistent byte objects must never appear beneath a writable sandbox bind.
    pub fn validate_runtime_root(&self, path: &Path) -> io::Result<()> {
        self.check()?;
        let resolved = fs::canonicalize(path).or_else(|error| {
            if error.kind() != io::ErrorKind::NotFound {
                return Err(error);
            }
            let (parent, name) = path
                .parent()
                .zip(path.file_name())
                .ok_or_else(|| invalid("invalid runtime root"))?;
            Ok(fs::canonicalize(parent)?.join(name))
        })?;
        if resolved.starts_with(&self.root.path) || self.root.path.starts_with(&resolved) {
            return Err(invalid("runtime root aliases retained toolchain files"));
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn open_child(&self, name: &str, create: bool) -> io::Result<File> {
        use rustix::fs::{Mode, OFlags};
        self.check()?;
        let access = if create {
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL
        } else {
            OFlags::RDONLY
        };
        Ok(File::from(rustix::fs::openat(
            &self.root.directory,
            name,
            access | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )?))
    }

    #[cfg(not(target_os = "linux"))]
    fn open_child(&self, _name: &str, _create: bool) -> io::Result<File> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "toolchain file reuse requires Linux",
        ))
    }

    fn anonymous(&self) -> io::Result<File> {
        self.check()?;
        let file = tempfile::tempfile_in(&self.root.path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // tempfile's Linux O_TMPFILE path inherits OpenOptions' default
            // mode. Set our owned anonymous descriptor's permissions before
            // applying the same private-file check as the named fallback.
            file.set_permissions(fs::Permissions::from_mode(0o600))?;
        }
        self.check()?;
        if !private_file(&file.metadata()?, 0, true) {
            return Err(invalid(
                "toolchain snapshot is not an anonymous private file",
            ));
        }
        Ok(file)
    }

    #[cfg(target_os = "linux")]
    fn remove(&self, name: &str) -> io::Result<()> {
        self.check()?;
        rustix::fs::unlinkat(&self.root.directory, name, rustix::fs::AtFlags::empty())?;
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    fn remove(&self, _name: &str) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "toolchain file reuse requires Linux",
        ))
    }

    pub(super) fn writer(&self, stopped: &impl Fn() -> bool) -> io::Result<Option<CacheWriter>> {
        checkpoint(stopped)?;
        let lock = match self.open_child(LOCK, true) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                self.open_child(LOCK, false)?
            }
            Err(error) => return Err(error),
        };
        if !private_file(&lock.metadata()?, 1, true) || lock.metadata()?.len() != 0 {
            return Err(invalid("invalid toolchain file cache lock"));
        }
        match lock.try_lock() {
            Ok(()) => {}
            Err(std::fs::TryLockError::WouldBlock) => return Ok(None),
            Err(std::fs::TryLockError::Error(error)) => return Err(error),
        }
        let mut writer = CacheWriter {
            cache: self.clone(),
            lock,
            entries: BTreeMap::new(),
            evictable: BTreeSet::new(),
            protected: BTreeSet::new(),
            total: 0,
            active: None,
        };
        for (index, entry) in fs::read_dir(&self.root.path)?.enumerate() {
            checkpoint(stopped)?;
            if index >= MAX_OBJECTS + 2 {
                return Err(invalid("toolchain file cache inventory exceeds its bound"));
            }
            let entry = entry?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| invalid("unrecognized toolchain file cache entry"))?;
            if name == LOCK {
                continue;
            }
            let file = self.open_child(&name, false)?;
            let metadata = file.metadata()?;
            if name == INCOMING
                && private_file(&metadata, 1, true)
                && metadata.len() <= self.max_bytes
            {
                self.remove(INCOMING)?;
                continue;
            }
            if !owned_name(&name) || !private_file(&metadata, 1, false) {
                return Err(invalid("unrecognized toolchain file cache entry"));
            }
            let used = metadata.modified()?;
            writer.total = writer
                .total
                .checked_add(metadata.len())
                .ok_or_else(|| invalid("toolchain file cache byte overflow"))?;
            writer.evictable.insert((used, name.clone()));
            writer.entries.insert(
                name,
                Entry {
                    bytes: metadata.len(),
                    used,
                    metadata,
                },
            );
        }
        writer.check(stopped)?;
        writer.reserve(0, false, stopped)?;
        Ok(Some(writer))
    }

    fn copy_verified(
        &self,
        expected: &ToolchainFile,
        output: &mut File,
        allow_prefix: bool,
        capacity: u64,
        stopped: &impl Fn() -> bool,
    ) -> io::Result<(u64, [u8; 32])> {
        checkpoint(stopped)?;
        let name = object_name(&expected.sha256);
        let mut input = self.open_child(&name, false)?;
        let before = input.metadata()?;
        let bytes = before.len();
        if !private_file(&before, 1, false)
            || bytes > capacity
            || !(bytes == expected.bytes || allow_prefix && bytes > 0 && bytes < expected.bytes)
        {
            return Err(invalid(
                "toolchain cache object has an unexpected type or length",
            ));
        }
        let mut remaining = bytes;
        let mut hash = Sha256::new();
        let mut buffer = [0_u8; MAX_TOOLCHAIN_CHUNK];
        while remaining != 0 {
            checkpoint(stopped)?;
            let count = remaining.min(buffer.len() as u64) as usize;
            input.read_exact(&mut buffer[..count])?;
            hash.update(&buffer[..count]);
            output.write_all(&buffer[..count])?;
            remaining -= count as u64;
        }
        checkpoint(stopped)?;
        let actual: [u8; 32] = hash.finalize().into();
        if input.read(&mut buffer[..1])? != 0
            || !same_state(&before, &input.metadata()?)
            || !same_state(&before, &self.open_child(&name, false)?.metadata()?)
            || bytes == expected.bytes && actual != expected.sha256
        {
            return Err(invalid(
                "toolchain cache object changed or failed its digest",
            ));
        }
        Ok((bytes, actual))
    }
}

struct Entry {
    bytes: u64,
    used: SystemTime,
    metadata: Metadata,
}

pub(super) struct CacheWriter {
    cache: ToolchainFileCache,
    lock: File,
    entries: BTreeMap<String, Entry>,
    evictable: BTreeSet<(SystemTime, String)>,
    protected: BTreeSet<String>,
    total: u64,
    active: Option<ActivePrefix>,
}

struct ActivePrefix {
    expected: ToolchainFile,
    file: File,
    offset: u64,
    writable: bool,
}

impl CacheWriter {
    fn check(&self, stopped: &impl Fn() -> bool) -> io::Result<()> {
        checkpoint(stopped)?;
        self.cache.check()?;
        if !same_inode(
            &self.lock.metadata()?,
            &self.cache.open_child(LOCK, false)?.metadata()?,
        ) {
            return Err(invalid("toolchain file cache writer was replaced"));
        }
        Ok(())
    }

    pub(super) fn protect(&mut self, digest: &[u8; 32]) {
        let name = object_name(digest);
        if let Some(entry) = self.entries.get(&name) {
            self.evictable.remove(&(entry.used, name.clone()));
        }
        self.protected.insert(name);
    }

    fn remove(&mut self, name: &str, stopped: &impl Fn() -> bool) -> io::Result<()> {
        self.check(stopped)?;
        let entry = self
            .entries
            .get(name)
            .ok_or_else(|| invalid("toolchain cache inventory changed"))?;
        if !same_state(
            &entry.metadata,
            &self.cache.open_child(name, false)?.metadata()?,
        ) {
            return Err(invalid("toolchain cache object changed before eviction"));
        }
        self.cache.remove(name)?;
        let entry = self
            .entries
            .remove(name)
            .ok_or_else(|| invalid("toolchain cache inventory changed"))?;
        self.evictable.remove(&(entry.used, name.to_owned()));
        self.total -= entry.bytes;
        Ok(())
    }

    fn reserve(
        &mut self,
        bytes: u64,
        new_object: bool,
        stopped: &impl Fn() -> bool,
    ) -> io::Result<bool> {
        if bytes > self.cache.max_bytes {
            return Ok(false);
        }
        while self.total > self.cache.max_bytes - bytes
            || self.entries.len() + usize::from(new_object) > MAX_OBJECTS
        {
            let Some((_, name)) = self.evictable.first().cloned() else {
                return Ok(false);
            };
            self.remove(&name, stopped)?;
        }
        Ok(true)
    }

    /// The retained bytes are hints, never a completed-file assertion. Publish
    /// the ordinary read-only object name with a held writable descriptor, then
    /// grow it only while this same nonblocking writer owns the cache lock.
    /// A crash can leave any shorter length; a later sender must hash-agree on
    /// the independently snapshotted range before those bytes may be skipped.
    pub(super) fn begin_prefix(
        &mut self,
        expected: &ToolchainFile,
        mut seed: Option<&mut File>,
        offset: u64,
        sha256: [u8; 32],
        stopped: &impl Fn() -> bool,
    ) -> io::Result<()> {
        self.check(stopped)?;
        if self.active.is_some() {
            return Err(invalid("another toolchain prefix owns the cache writer"));
        }
        if expected.bytes == 0 || offset >= expected.bytes {
            return Err(invalid("toolchain prefix requires an unfinished file"));
        }
        let name = object_name(&expected.sha256);
        // A duplicate content identity may already have completed earlier in
        // this same upload. Preserve that protected complete object.
        if self.protected.contains(&name) || offset > self.cache.max_bytes {
            return Ok(());
        }
        if self.entries.contains_key(&name) {
            self.remove(&name, stopped)?;
        }
        if !self.reserve(offset, true, stopped)? {
            return Ok(());
        }
        let mut file = self.cache.open_child(INCOMING, true)?;
        let mut permissions = file.metadata()?.permissions();
        permissions.set_readonly(true);
        file.set_permissions(permissions)?;
        let mut hash = Sha256::new();
        if offset != 0 {
            let input = seed
                .as_mut()
                .ok_or_else(|| invalid("toolchain prefix seed is missing"))?;
            let before = input.metadata()?;
            if !private_file(&before, 0, false) || before.len() != offset {
                return Err(invalid("toolchain prefix seed is not an owned snapshot"));
            }
            input.rewind()?;
            let mut remaining = offset;
            let mut buffer = [0_u8; MAX_TOOLCHAIN_CHUNK];
            while remaining != 0 {
                checkpoint(stopped)?;
                let count = remaining.min(buffer.len() as u64) as usize;
                input.read_exact(&mut buffer[..count])?;
                hash.update(&buffer[..count]);
                file.write_all(&buffer[..count])?;
                remaining -= count as u64;
            }
            if input.read(&mut buffer[..1])? != 0 || !same_state(&before, &input.metadata()?) {
                return Err(invalid("toolchain prefix seed changed during copying"));
            }
        }
        if <[u8; 32]>::from(hash.finalize()) != sha256 {
            return Err(invalid(
                "toolchain prefix seed digest differs from selection",
            ));
        }
        self.check(stopped)?;
        let metadata = file.metadata()?;
        if !private_file(&metadata, 1, false)
            || metadata.len() != offset
            || !same_state(
                &metadata,
                &self.cache.open_child(INCOMING, false)?.metadata()?,
            )
        {
            return Err(invalid(
                "toolchain prefix destination changed before publication",
            ));
        }
        #[cfg(target_os = "linux")]
        rustix::fs::renameat(
            &self.cache.root.directory,
            INCOMING,
            &self.cache.root.directory,
            name.as_str(),
        )?;
        #[cfg(not(target_os = "linux"))]
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "toolchain prefix reuse requires Linux",
        ));
        let metadata = file.metadata()?;
        let used = metadata.modified()?;
        self.total += offset;
        self.entries.insert(
            name.clone(),
            Entry {
                bytes: offset,
                used,
                metadata,
            },
        );
        self.protected.insert(name);
        self.active = Some(ActivePrefix {
            expected: expected.clone(),
            file,
            offset,
            writable: true,
        });
        checkpoint(stopped)
    }

    /// Called only after the ordinary receiver accepts these exact contiguous
    /// bytes. A failed or partial optional append cannot authorize a hit: fresh
    /// lookup rehashes its actual length and the sender checks that prefix.
    pub(super) fn append_prefix(
        &mut self,
        expected: &ToolchainFile,
        offset: u64,
        bytes: &[u8],
        stopped: &impl Fn() -> bool,
    ) -> io::Result<()> {
        self.check(stopped)?;
        let Some(active) = &self.active else {
            return Ok(());
        };
        if &active.expected != expected {
            return Err(invalid("toolchain prefix content identity changed"));
        }
        if !active.writable {
            return Ok(());
        }
        let next = offset
            .checked_add(bytes.len() as u64)
            .filter(|next| *next <= expected.bytes)
            .ok_or_else(|| invalid("toolchain prefix exceeds its file"))?;
        let name = object_name(&expected.sha256);
        let stored = self
            .entries
            .get(&name)
            .ok_or_else(|| invalid("toolchain prefix inventory disappeared"))?;
        if offset != active.offset
            || bytes.is_empty()
            || bytes.len() > MAX_TOOLCHAIN_CHUNK
            || !same_state(&stored.metadata, &active.file.metadata()?)
            || !same_state(
                &stored.metadata,
                &self.cache.open_child(&name, false)?.metadata()?,
            )
        {
            return Err(invalid(
                "toolchain prefix offset or owned generation changed",
            ));
        }
        if !self.reserve(bytes.len() as u64, false, stopped)? {
            // Keep the largest retained prefix within the same total capacity.
            // Stop growing it, but retain ownership until ordinary completion.
            self.active.as_mut().unwrap().writable = false;
            return Ok(());
        }
        let active = self.active.as_mut().unwrap();
        if active.file.stream_position()? != offset {
            return Err(invalid("toolchain prefix writer cursor changed"));
        }
        active.file.write_all(bytes)?;
        let metadata = active.file.metadata()?;
        if !private_file(&metadata, 1, false)
            || metadata.len() != next
            || !same_state(&metadata, &self.cache.open_child(&name, false)?.metadata()?)
        {
            return Err(invalid("toolchain prefix changed during append"));
        }
        active.offset = next;
        self.total += bytes.len() as u64;
        let used = metadata.modified()?;
        self.entries.insert(
            name,
            Entry {
                bytes: next,
                used,
                metadata,
            },
        );
        self.check(stopped)
    }

    pub(super) fn finish_prefix(
        &mut self,
        expected: &ToolchainFile,
        stopped: &impl Fn() -> bool,
    ) -> io::Result<()> {
        self.check(stopped)?;
        if let Some(active) = self.active.take() {
            if &active.expected != expected {
                return Err(invalid("another toolchain prefix was completed"));
            }
            let name = object_name(&expected.sha256);
            let entry = self
                .entries
                .get(&name)
                .ok_or_else(|| invalid("completed toolchain prefix disappeared"))?;
            if !same_state(&entry.metadata, &active.file.metadata()?)
                || !same_state(
                    &entry.metadata,
                    &self.cache.open_child(&name, false)?.metadata()?,
                )
            {
                return Err(invalid("completed toolchain prefix generation changed"));
            }
            self.protected.remove(&name);
            self.evictable.insert((entry.used, name));
        }
        Ok(())
    }

    /// Destination errors merely disable optional checkpoints. Source errors
    /// revoke this upload; they are never translated into cache misses.
    pub(super) fn remember(
        &mut self,
        receiver: &mut ToolchainReceiver,
        expected: &ToolchainFile,
        stopped: &impl Fn() -> bool,
    ) -> Result<(), ToolchainCheckpointError> {
        use ToolchainCheckpointError::Destination;
        self.check(stopped).map_err(Destination)?;
        let name = object_name(&expected.sha256);
        if self.protected.contains(&name) || expected.bytes > self.cache.max_bytes {
            return Ok(());
        }
        if self.entries.contains_key(&name) {
            // This name was reported missing, so it failed verified lookup.
            // It may now be a useful short prefix. Reserve its growth before
            // replacing it, so a complete object which cannot fit does not
            // discard the bounded recovery bytes already retained.
            let previous = self.entries[&name].bytes;
            self.protect(&expected.sha256);
            let fits = self
                .reserve(expected.bytes.saturating_sub(previous), false, stopped)
                .map_err(Destination)?;
            self.protected.remove(&name);
            self.evictable
                .insert((self.entries[&name].used, name.clone()));
            if !fits {
                return Ok(());
            }
            // Replace only the inventoried ordinary object, never unknown state.
            self.remove(&name, stopped).map_err(Destination)?;
        }
        if !self
            .reserve(expected.bytes, true, stopped)
            .map_err(Destination)?
        {
            return Ok(());
        }
        let destination = self.cache.open_child(INCOMING, true).map_err(Destination)?;
        let verified = receiver.checkpoint_file(expected, destination, stopped)?;
        if verified.expected() != expected {
            return Err(Destination(invalid(
                "toolchain checkpoint identity changed",
            )));
        }
        let file = verified.into_file();
        let mut permissions = file.metadata().map_err(Destination)?.permissions();
        permissions.set_readonly(true);
        file.set_permissions(permissions).map_err(Destination)?;
        let metadata = file.metadata().map_err(Destination)?;
        self.check(stopped).map_err(Destination)?;
        if !same_state(
            &metadata,
            &self
                .cache
                .open_child(INCOMING, false)
                .map_err(Destination)?
                .metadata()
                .map_err(Destination)?,
        ) {
            return Err(Destination(invalid(
                "toolchain checkpoint destination was replaced",
            )));
        }
        #[cfg(target_os = "linux")]
        rustix::fs::renameat(
            &self.cache.root.directory,
            INCOMING,
            &self.cache.root.directory,
            name.as_str(),
        )
        .map_err(|error| Destination(error.into()))?;
        #[cfg(not(target_os = "linux"))]
        return Err(Destination(io::Error::new(
            io::ErrorKind::Unsupported,
            "toolchain file reuse requires Linux",
        )));
        let metadata = file.metadata().map_err(Destination)?;
        let used = metadata.modified().map_err(Destination)?;
        self.total += expected.bytes;
        self.entries.insert(
            name.clone(),
            Entry {
                bytes: expected.bytes,
                used,
                metadata,
            },
        );
        self.protected.insert(name);
        checkpoint(stopped).map_err(Destination)
    }
}

#[derive(Clone, Copy)]
pub(super) struct SnapshotRange {
    offset: u64,
    pub(super) bytes: u64,
    pub(super) sha256: [u8; 32],
}

/// One anonymous spool bounds file descriptors independently of SDK file count.
/// Its bytes are temporary upload storage, bounded separately by both the
/// declared SDK size and configured retained-byte capacity. Only one current
/// file snapshot is materialized while importing into the independent receiver.
pub(super) struct Snapshots {
    cache: ToolchainFileCache,
    spool: File,
    max_bytes: u64,
    bytes: u64,
    frozen: Option<Metadata>,
    writable: bool,
}

impl Snapshots {
    pub(super) fn new(cache: ToolchainFileCache, sdk_bytes: u64) -> io::Result<Self> {
        Ok(Self {
            spool: cache.anonymous()?,
            max_bytes: sdk_bytes.min(cache.max_bytes),
            cache,
            bytes: 0,
            frozen: None,
            writable: true,
        })
    }

    pub(super) fn append(
        &mut self,
        expected: &ToolchainFile,
        allow_prefix: bool,
        stopped: &impl Fn() -> bool,
    ) -> io::Result<Option<SnapshotRange>> {
        checkpoint(stopped)?;
        if !self.writable || self.frozen.is_some() {
            return Ok(None);
        }
        let offset = self.bytes;
        if self.spool.seek(SeekFrom::Start(offset)).is_err() {
            self.writable = false;
            return Ok(None);
        }
        let (bytes, sha256) = match self.cache.copy_verified(
            expected,
            &mut self.spool,
            allow_prefix,
            self.max_bytes - self.bytes,
            stopped,
        ) {
            Ok(verified) => verified,
            Err(_) => {
                checkpoint(stopped)?;
                // Existing advertised ranges remain independent and intact. A
                // failed optional append cannot turn them into a later miss.
                if self.spool.set_len(offset).is_err() {
                    self.writable = false;
                }
                return Ok(None);
            }
        };
        self.bytes += bytes;
        Ok(Some(SnapshotRange {
            offset,
            bytes,
            sha256,
        }))
    }

    pub(super) fn seal(&mut self, stopped: &impl Fn() -> bool) -> io::Result<()> {
        checkpoint(stopped)?;
        self.spool.set_len(self.bytes)?;
        let mut permissions = self.spool.metadata()?.permissions();
        permissions.set_readonly(true);
        self.spool.set_permissions(permissions)?;
        self.frozen = Some(self.spool.metadata()?);
        checkpoint(stopped)
    }

    pub(super) fn materialize(
        &mut self,
        range: SnapshotRange,
        stopped: &impl Fn() -> bool,
    ) -> io::Result<File> {
        checkpoint(stopped)?;
        let before = self
            .frozen
            .as_ref()
            .ok_or_else(|| invalid("toolchain snapshots are not sealed"))?;
        if !same_state(before, &self.spool.metadata()?)
            || range
                .offset
                .checked_add(range.bytes)
                .is_none_or(|end| end > self.bytes)
        {
            return Err(invalid("toolchain snapshot generation or range changed"));
        }
        let mut file = self.cache.anonymous()?;
        self.spool.seek(SeekFrom::Start(range.offset))?;
        let mut remaining = range.bytes;
        let mut buffer = [0_u8; MAX_TOOLCHAIN_CHUNK];
        while remaining != 0 {
            checkpoint(stopped)?;
            let count = remaining.min(buffer.len() as u64) as usize;
            self.spool.read_exact(&mut buffer[..count])?;
            file.write_all(&buffer[..count])?;
            remaining -= count as u64;
        }
        if !same_state(before, &self.spool.metadata()?) {
            return Err(invalid("toolchain snapshot changed during import"));
        }
        let mut permissions = file.metadata()?.permissions();
        permissions.set_readonly(true);
        file.set_permissions(permissions)?;
        file.rewind()?;
        checkpoint(stopped)?;
        Ok(file)
    }

    #[cfg(test)]
    pub(super) fn corrupt_owned_snapshot_for_test(&mut self) {
        assert!(self.bytes > 0 && self.frozen.is_some());
        self.spool.rewind().unwrap();
        self.spool.write_all(&[0x99]).unwrap();
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    #[test]
    fn anonymous_snapshots_have_private_unlinked_descriptors() {
        let owner = tempfile::Builder::new()
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let cache = ToolchainFileCache::open(owner.path(), 1024).unwrap();
        let snapshots = Snapshots::new(cache, 1024).unwrap();
        let metadata = snapshots.spool.metadata().unwrap();
        assert!(metadata.is_file());
        assert_eq!(metadata.mode() & 0o777, 0o600);
        assert_eq!(metadata.nlink(), 0);
        assert_eq!(
            metadata.len(),
            0,
            "privacy precedes copying any cached bytes"
        );
    }
}
