//! Owned, content-identified toolchain copies for canonical worker execution.
//!
//! Capture includes the whole explicitly selected tree, without source-file
//! exclusions. Regular files are streamed into independent files, directories
//! (including empty ones) and contained relative symlinks retain their layout,
//! and executable bits are preserved. Hard-link topology, timestamps, ownership,
//! ACLs and extended attributes are not part of this execution-only identity.
//! This is not a complete ToolchainContract: host runtime and native tools outside
//! this tree remain separate inputs, and this identity grants no cache authority.
//!
//! The caller owns the private destination parent through execution and cleanup.
//! Read-only files and a read-only namespace mount prevent compiler writes; they
//! are not protection against another process with the owner's credentials.
//! `verify` checks retained bytes and inode/mutation stamps before/after execution.
//! Callers must reject outputs if verification fails. Failed new directories are
//! retained for inspection, never overwritten or silently reused.

use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};

#[cfg(target_os = "linux")]
use crate::toolchain_transfer::ToolchainEntryKind;
use crate::toolchain_transfer::{ToolchainEntry, ToolchainFile};

pub const TOOLCHAIN_DATASET_VERSION: &str = "toolchain-dataset-v1";

/// Portable content identity, independent of host backing paths and inode IDs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ToolchainIdentity {
    pub sha256: [u8; 32],
    pub files: u64,
    pub bytes: u64,
}

/// Aggregate bounds apply to the complete tree, counting hard-link aliases as
/// separate files because captured files never share an inode with their source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ToolchainLimits {
    pub max_bytes: u64,
    pub max_entries: usize,
    pub max_depth: usize,
}

impl Default for ToolchainLimits {
    fn default() -> Self {
        Self {
            max_bytes: 8 * 1024 * 1024 * 1024,
            max_entries: 100_000,
            max_depth: 64,
        }
    }
}

/// An independently copied toolchain and its retained verification boundary.
#[derive(Debug)]
pub struct PreparedToolchain {
    root: PathBuf,
    identity: ToolchainIdentity,
    #[cfg(target_os = "linux")]
    inventory: linux::Inventory,
    #[cfg(target_os = "linux")]
    source_inventory: Option<linux::Inventory>,
    #[cfg(target_os = "linux")]
    file_hashes: Vec<[u8; 32]>,
}

impl PreparedToolchain {
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    #[must_use]
    pub const fn identity(&self) -> &ToolchainIdentity {
        &self.identity
    }

    /// Rebind the same retained image after its enclosing owned directory moves.
    ///
    /// This performs no filesystem move and refreshes no inode or mutation
    /// stamp. The new ordinary absolute path must name the original anchored
    /// root, and every original file, directory and alias generation must still
    /// match. Moving the dataset root itself can change its generation and is
    /// deliberately not repaired here; move its enclosing owner instead.
    ///
    /// The caller retains ownership of the backing directory on both success
    /// and error. Its content identity and original-source witness are unchanged.
    /// Rebinding is not a byte verification or permission to publish a result;
    /// consumers must still perform their normal full verification and sync.
    pub fn rebind_root(self, new_root: &Path, stopped: impl Fn() -> bool) -> io::Result<Self> {
        #[cfg(target_os = "linux")]
        {
            let mut rebound = self;
            rebound.inventory.rebind_root(new_root, &stopped)?;
            rebound.root = new_root.to_path_buf();
            Ok(rebound)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (self, new_root, stopped);
            Err(unsupported())
        }
    }

    /// Validate the complete original source generation without rereading bytes.
    ///
    /// A captured toolchain retains the source inventory that produced its
    /// identity. This checks every original file, directory and symlink through
    /// anchored descriptors, including entries outside rustc's selected sysroot
    /// inventory. Added members, replaced inodes, rewritten bytes, mode changes
    /// and retargeted aliases invalidate the witness; a later capture never
    /// refreshes this one. Cost is proportional to entries, not toolchain bytes.
    ///
    /// This is a mutation witness, not a filesystem lock. Callers retaining a
    /// source-to-dataset memo must check it before keying and again before using
    /// a result. The exact source path is required. An open_toolchain owner
    /// has no original-source witness and cannot establish this correspondence.
    pub fn verify_source_unchanged(
        &self,
        source: &Path,
        stopped: impl Fn() -> bool,
    ) -> io::Result<()> {
        #[cfg(target_os = "linux")]
        {
            self.source_inventory
                .as_ref()
                .ok_or_else(|| invalid("toolchain has no retained original-source witness"))?
                .verify_source(source, &stopped)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (source, stopped);
            Err(unsupported())
        }
    }

    /// Export the retained namespace in the same order used by its identity.
    /// File contents remain on disk and are read through [`Self::read_chunk`].
    pub fn entries(&self) -> io::Result<Vec<ToolchainEntry>> {
        #[cfg(target_os = "linux")]
        {
            self.inventory.transfer_entries()
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(unsupported())
        }
    }

    /// Export regular-file identities from the original complete byte scan.
    /// These are bound to the retained generation, not a refreshed observation
    /// of mutable paths. A receiver may reuse matching independent bytes, but
    /// must still verify the complete namespace and dataset identity at seal.
    pub fn files(&self) -> io::Result<Vec<ToolchainFile>> {
        #[cfg(target_os = "linux")]
        {
            self.inventory.transfer_files(&self.file_hashes)
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(unsupported())
        }
    }

    /// Read a bounded range through the retained, descriptor-anchored inventory.
    /// A mutation or replacement of a selected file invalidates that read. The
    /// receiver must verify its complete reconstructed tree against the retained
    /// identity before accepting the seal; no second sender-wide hash is needed.
    pub fn read_chunk(
        &self,
        path: &str,
        offset: u64,
        maximum: usize,
        stopped: impl Fn() -> bool,
    ) -> io::Result<Vec<u8>> {
        #[cfg(target_os = "linux")]
        {
            self.inventory.read_chunk(path, offset, maximum, &stopped)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (path, offset, maximum, stopped);
            Err(unsupported())
        }
    }

    /// Make the retained files and namespace durable before publishing a local
    /// bundle's readiness marker. Descriptors stay anchored to this inventory;
    /// directory syncs run after file syncs and from children to parents.
    pub fn sync(&self, stopped: impl Fn() -> bool) -> io::Result<()> {
        #[cfg(target_os = "linux")]
        {
            self.inventory.sync(&stopped)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = stopped;
            Err(unsupported())
        }
    }

    /// Rehash the retained bytes through anchored descriptors and reject any
    /// content, mode, namespace, inode or mutation-stamp change since capture.
    pub fn verify(&self, stopped: impl Fn() -> bool) -> io::Result<()> {
        #[cfg(target_os = "linux")]
        {
            self.inventory.verify(&stopped)?;
            let current = self.rehash_retained_bytes(&stopped)?;
            self.inventory.verify(&stopped)?;
            require(
                current == self.identity,
                "retained toolchain content changed",
            )
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = stopped;
            Err(unsupported())
        }
    }

    /// Compute the retained inventory's current content identity by reading
    /// every regular byte with the original before/after file-stamp checks.
    ///
    /// This is not namespace authority: directory membership and alias closure
    /// need separate validation. A caller authorizing use must bracket this
    /// scan with [`Self::verify_retained_generation`], or use [`Self::verify`].
    /// This split lets an existing verification owner supply those barriers
    /// without walking every entry twice again inside the byte scan.
    pub fn rehash_retained_bytes(
        &self,
        stopped: impl Fn() -> bool,
    ) -> io::Result<ToolchainIdentity> {
        #[cfg(target_os = "linux")]
        {
            self.inventory.stream(None, &stopped)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = stopped;
            Err(unsupported())
        }
    }

    /// Revalidate the exact retained generation without rehashing its bytes.
    ///
    /// Initial capture/open already verified every retained byte against the
    /// content identity. This checks the same anchored file, directory and
    /// alias generations, including a final directory-membership barrier.
    /// Replaced inodes, writes, mode changes, added members and retargeted
    /// aliases invalidate this owner; this call never refreshes its witness.
    /// The original mutable source is checked separately by
    /// [`Self::verify_source_unchanged`].
    pub fn verify_retained_generation(&self, stopped: impl Fn() -> bool) -> io::Result<()> {
        #[cfg(target_os = "linux")]
        {
            self.inventory.verify_source(&self.root, &stopped)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = stopped;
            Err(unsupported())
        }
    }
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn require(condition: bool, message: &str) -> io::Result<()> {
    if condition {
        Ok(())
    } else {
        Err(invalid(message))
    }
}
fn checkpoint(stopped: &impl Fn() -> bool) -> io::Result<()> {
    if stopped() {
        Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "toolchain capture interrupted",
        ))
    } else {
        Ok(())
    }
}
#[cfg(not(target_os = "linux"))]
fn unsupported() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "anchored toolchain capture requires Linux openat2",
    )
}

/// Fingerprint a complete local toolchain with streamed content reads and a
/// final source mutation barrier. A later capture must independently match this
/// identity; this function does not retain or freeze the mutable source tree.
pub fn fingerprint_toolchain(
    root: &Path,
    limits: &ToolchainLimits,
    stopped: impl Fn() -> bool,
) -> io::Result<ToolchainIdentity> {
    #[cfg(target_os = "linux")]
    {
        let inventory = linux::Inventory::scan(root, limits, &stopped)?;
        let identity = inventory.stream(None, &stopped)?;
        inventory.verify(&stopped)?;
        Ok(identity)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (root, limits, stopped);
        Err(unsupported())
    }
}

/// Copy a complete coherent toolchain into a NEW destination beneath a private
/// caller-owned parent, optionally requiring a coordinator-selected identity.
/// All bytes are verified again from the retained copy before ownership returns.
pub fn capture_toolchain(
    source: &Path,
    destination: &Path,
    expected: Option<&ToolchainIdentity>,
    limits: &ToolchainLimits,
    stopped: impl Fn() -> bool,
) -> io::Result<PreparedToolchain> {
    capture_toolchain_with_cloner(source, destination, expected, limits, stopped, |_, _, _| {
        false
    })
}

/// Capture using an optional verified private copy-on-write primitive supplied
/// by the effects-owning caller. The callback must never alias source inodes or
/// mutate source bytes. It is tried only for files larger than one copy buffer.
/// A false result falls back to a complete byte copy, resetting both cursors and
/// truncating any partial destination left by the attempt.
///
/// Cloning replaces only writes: source bytes still determine the identity,
/// source mutation barriers remain in force, and the complete actual destination
/// is independently rehashed before ownership returns. A successful callback is
/// never content evidence. Keeping the primitive here as a callback preserves
/// the sandbox's dependency direction and its prohibition on unsafe code.
pub fn capture_toolchain_with_cloner(
    source: &Path,
    destination: &Path,
    expected: Option<&ToolchainIdentity>,
    limits: &ToolchainLimits,
    stopped: impl Fn() -> bool,
    cloner: impl Fn(&File, &File, &Path) -> bool,
) -> io::Result<PreparedToolchain> {
    #[cfg(target_os = "linux")]
    {
        linux::capture(source, destination, expected, limits, &stopped, &cloner)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (source, destination, expected, limits, stopped, cloner);
        Err(unsupported())
    }
}

/// Open an already retained tree without copying it, requiring the exact
/// selected identity. This performs the same complete scan, byte hashing and
/// mutation barrier as capture. The caller owns the root and its private parent
/// for the returned object's lifetime; this does not make arbitrary host paths
/// immutable or grant action-cache authority.
pub fn open_toolchain(
    root: &Path,
    expected: &ToolchainIdentity,
    limits: &ToolchainLimits,
    stopped: impl Fn() -> bool,
) -> io::Result<PreparedToolchain> {
    #[cfg(target_os = "linux")]
    {
        let inventory = linux::Inventory::scan(root, limits, &stopped)?;
        let (identity, file_hashes) = inventory.stream_with_file_hashes(&stopped)?;
        inventory.verify(&stopped)?;
        require(
            identity == *expected,
            "retained toolchain identity mismatch",
        )?;
        Ok(PreparedToolchain {
            root: root.to_owned(),
            identity,
            inventory,
            source_inventory: None,
            file_hashes,
        })
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (root, expected, limits, stopped);
        Err(unsupported())
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use rustix::fs::{Advice, CWD, Dir, Mode, OFlags, ResolveFlags, fadvise, openat2, readlinkat};
    use sha2::{Digest, Sha256};
    use std::collections::{BTreeMap, VecDeque};
    use std::fs::{self, Metadata, OpenOptions};
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt, symlink};
    use std::path::Component;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    // A successful clone may still wait for filesystem writeback. Stop trying
    // this optional optimization after one slow call rather than multiplying
    // that wait by every large SDK file. Ordinary copies keep all verification.
    const MAX_USEFUL_CLONE_LATENCY: Duration = Duration::from_millis(50);

    // One optional reader is shared by ALL dataset scans in this process.
    // Small datasets and contended callers keep the original sequential path;
    // there is no thread pool, queue, detached reader or cached byte digest.
    const PARALLEL_READ_BYTES: u64 = 4 * 1024 * 1024;
    const READ_BUFFER_BYTES: usize = 64 * 1024;
    static READ_HELPER_BUSY: AtomicBool = AtomicBool::new(false);

    struct ReadHelperPermit<'a>(&'a AtomicBool);

    impl<'a> ReadHelperPermit<'a> {
        fn acquire(busy: &'a AtomicBool) -> Option<Self> {
            busy.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
                .ok()
                .map(|_| Self(busy))
        }
    }

    impl Drop for ReadHelperPermit<'_> {
        fn drop(&mut self) {
            self.0.store(false, Ordering::Release);
        }
    }

    struct StopReaders<'a> {
        stopped: &'a AtomicBool,
        armed: bool,
    }

    impl Drop for StopReaders<'_> {
        fn drop(&mut self) {
            if self.armed {
                self.stopped.store(true, Ordering::Release);
            }
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Stamp {
        device: u64,
        inode: u64,
        size: u64,
        links: u64,
        mode: u32,
        uid: u32,
        gid: u32,
        modified: (i64, i64),
        changed: (i64, i64),
    }
    impl Stamp {
        fn of(metadata: &Metadata) -> Self {
            Self {
                device: metadata.dev(),
                inode: metadata.ino(),
                size: metadata.len(),
                links: metadata.nlink(),
                mode: metadata.mode(),
                uid: metadata.uid(),
                gid: metadata.gid(),
                modified: (metadata.mtime(), metadata.mtime_nsec()),
                changed: (metadata.ctime(), metadata.ctime_nsec()),
            }
        }
    }
    #[derive(Debug, Clone)]
    enum Kind {
        Directory,
        File,
        Link(String),
    }
    #[derive(Debug, Clone)]
    struct Entry {
        stamp: Stamp,
        kind: Kind,
    }

    #[derive(Debug)]
    pub(super) struct Inventory {
        root: File,
        root_path: PathBuf,
        entries: BTreeMap<String, Entry>,
        bytes: u64,
        files: u64,
    }

    fn absolute(path: &Path) -> io::Result<()> {
        require(
            path.is_absolute()
                && path
                    .components()
                    .all(|part| matches!(part, Component::RootDir | Component::Normal(_))),
            "toolchain root/destination must be absolute without traversal",
        )
    }
    fn name_valid(name: &str) -> bool {
        !name.is_empty()
            && name.len() <= 255
            && !matches!(name, "." | "..")
            && !name.contains(['/', '\\', ':'])
            && !name.chars().any(char::is_control)
    }

    impl Inventory {
        pub(super) fn rebind_root(
            &mut self,
            new_root: &Path,
            stopped: &impl Fn() -> bool,
        ) -> io::Result<()> {
            checkpoint(stopped)?;
            absolute(new_root)?;
            let original = &self
                .entries
                .get("")
                .ok_or_else(|| invalid("missing toolchain root stamp"))?
                .stamp;
            let open_root = || -> io::Result<File> {
                Ok(File::from(openat2(
                    CWD,
                    new_root,
                    OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                    ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
                )?))
            };
            require(
                Stamp::of(&self.root.metadata()?) == *original
                    && Stamp::of(&open_root()?.metadata()?) == *original,
                "rebound toolchain root differs from its retained generation",
            )?;
            // Only the pathname changes. All original descriptors, stamps,
            // contents and alias text remain the verification authority.
            self.root_path = new_root.to_path_buf();
            self.verify_source(new_root, stopped)?;
            // Do not admit a final or ancestor symlink introduced during the
            // complete generation walk, even when it resolves to the same inode.
            require(
                Stamp::of(&open_root()?.metadata()?) == *original,
                "rebound toolchain path changed during verification",
            )?;
            checkpoint(stopped)
        }

        pub(super) fn sync(&self, stopped: &impl Fn() -> bool) -> io::Result<()> {
            self.verify(stopped)?;
            for (path, entry) in &self.entries {
                checkpoint(stopped)?;
                if matches!(entry.kind, Kind::File) {
                    self.open(path, OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOCTTY)?
                        .sync_all()?;
                }
            }
            for (path, entry) in self.entries.iter().rev() {
                checkpoint(stopped)?;
                if matches!(entry.kind, Kind::Directory) {
                    if path.is_empty() {
                        self.root.sync_all()?;
                    } else {
                        self.open(path, OFlags::RDONLY | OFlags::DIRECTORY)?
                            .sync_all()?;
                    }
                }
            }
            self.verify(stopped)
        }

        pub(super) fn transfer_entries(&self) -> io::Result<Vec<ToolchainEntry>> {
            let mut metadata_bytes = 0_usize;
            let mut entries = Vec::with_capacity(self.entries.len());
            for (path, entry) in &self.entries {
                let kind = match &entry.kind {
                    Kind::Directory => ToolchainEntryKind::Directory,
                    Kind::Link(target) => ToolchainEntryKind::Symlink {
                        target: target.clone(),
                    },
                    Kind::File => ToolchainEntryKind::File {
                        bytes: entry.stamp.size,
                        executable: entry.stamp.mode & 0o111 != 0,
                    },
                };
                let transfer = ToolchainEntry {
                    path: path.clone(),
                    kind,
                };
                metadata_bytes = metadata_bytes
                    .checked_add(transfer.metadata_bytes())
                    .filter(|bytes| {
                        *bytes <= crate::toolchain_transfer::MAX_TOOLCHAIN_METADATA_BYTES
                    })
                    .ok_or_else(|| invalid("toolchain transfer metadata limit exceeded"))?;
                entries.push(transfer);
            }
            Ok(entries)
        }

        pub(super) fn transfer_files(&self, hashes: &[[u8; 32]]) -> io::Result<Vec<ToolchainFile>> {
            require(
                hashes.len() as u64 == self.files,
                "toolchain retained file hash count differs from its inventory",
            )?;
            let mut metadata_bytes = 0_usize;
            let mut files = Vec::with_capacity(hashes.len());
            for ((path, entry), sha256) in self
                .entries
                .iter()
                .filter(|(_, entry)| matches!(entry.kind, Kind::File))
                .zip(hashes)
            {
                let file = ToolchainFile {
                    path: path.clone(),
                    bytes: entry.stamp.size,
                    executable: entry.stamp.mode & 0o111 != 0,
                    sha256: *sha256,
                };
                metadata_bytes = metadata_bytes
                    .checked_add(file.metadata_bytes())
                    .filter(|bytes| {
                        *bytes <= crate::toolchain_transfer::MAX_TOOLCHAIN_METADATA_BYTES
                    })
                    .ok_or_else(|| invalid("toolchain file metadata limit exceeded"))?;
                files.push(file);
            }
            Ok(files)
        }

        pub(super) fn read_chunk(
            &self,
            path: &str,
            offset: u64,
            maximum: usize,
            stopped: &impl Fn() -> bool,
        ) -> io::Result<Vec<u8>> {
            checkpoint(stopped)?;
            require(
                maximum > 0 && maximum <= crate::toolchain_transfer::MAX_TOOLCHAIN_CHUNK,
                "toolchain chunk size outside its bound",
            )?;
            let entry = self
                .entries
                .get(path)
                .filter(|entry| matches!(entry.kind, Kind::File))
                .ok_or_else(|| invalid("toolchain chunk must name an inventoried regular file"))?;
            require(
                offset <= entry.stamp.size,
                "toolchain chunk offset exceeds file",
            )?;
            let root = self
                .entries
                .get("")
                .ok_or_else(|| invalid("missing toolchain root"))?;
            require(
                Stamp::of(&fs::symlink_metadata(&self.root_path)?) == root.stamp,
                "toolchain root changed during export",
            )?;
            let mut source = self.open(path, OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOCTTY)?;
            require(
                Stamp::of(&source.metadata()?) == entry.stamp,
                "toolchain file changed before export",
            )?;
            source.seek(SeekFrom::Start(offset))?;
            let length = usize::try_from((entry.stamp.size - offset).min(maximum as u64))
                .map_err(|_| invalid("toolchain chunk length overflow"))?;
            let mut bytes = vec![0; length];
            source.read_exact(&mut bytes)?;
            checkpoint(stopped)?;
            require(
                Stamp::of(&source.metadata()?) == entry.stamp
                    && Stamp::of(&self.open(path, OFlags::PATH)?.metadata()?) == entry.stamp,
                "toolchain file changed during export",
            )?;
            Ok(bytes)
        }

        pub(super) fn scan(
            root: &Path,
            limits: &ToolchainLimits,
            stopped: &impl Fn() -> bool,
        ) -> io::Result<Self> {
            checkpoint(stopped)?;
            absolute(root)?;
            require(
                limits.max_entries > 0 && limits.max_depth > 0 && limits.max_depth <= 256,
                "invalid toolchain capture limits",
            )?;
            let directory = File::from(openat2(
                CWD,
                root,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
                ResolveFlags::NO_MAGICLINKS,
            )?);
            let mut inventory = Self {
                root: directory.try_clone()?,
                root_path: root.to_owned(),
                entries: BTreeMap::new(),
                bytes: 0,
                files: 0,
            };
            inventory.visit(&directory, "", 0, limits, stopped)?;
            for (path, entry) in &inventory.entries {
                checkpoint(stopped)?;
                if let Kind::Link(target) = &entry.kind {
                    inventory.validate_link(path, target)?;
                }
            }
            inventory.verify(stopped)?;
            Ok(inventory)
        }

        fn open(&self, path: &str, flags: OFlags) -> io::Result<File> {
            Ok(File::from(openat2(
                &self.root,
                path,
                flags | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
                ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_XDEV,
            )?))
        }

        fn visit(
            &mut self,
            directory: &File,
            relative: &str,
            depth: usize,
            limits: &ToolchainLimits,
            stopped: &impl Fn() -> bool,
        ) -> io::Result<()> {
            checkpoint(stopped)?;
            let before = Stamp::of(&directory.metadata()?);
            // Reserve the directory before recursion, so every node consumes the
            // same aggregate budget and deep/wide trees cannot bypass limits.
            require(
                self.entries.len() < limits.max_entries,
                "toolchain entry limit exceeded",
            )?;
            self.entries.insert(
                relative.to_owned(),
                Entry {
                    stamp: before.clone(),
                    kind: Kind::Directory,
                },
            );
            let mut entries = Dir::read_from(directory)?;
            while let Some(entry) = entries.read() {
                checkpoint(stopped)?;
                let entry = entry?;
                if matches!(entry.file_name().to_bytes(), b"." | b"..") {
                    continue;
                }
                let name = entry
                    .file_name()
                    .to_str()
                    .map_err(|_| invalid("non-UTF-8 toolchain entry"))?;
                require(
                    name_valid(name) && depth < limits.max_depth,
                    "unsafe or overly deep toolchain entry",
                )?;
                let path = if relative.is_empty() {
                    name.to_owned()
                } else {
                    format!("{relative}/{name}")
                };
                require(path.len() <= 4096, "toolchain path exceeds its bound")?;
                let observed = self.open(&path, OFlags::PATH)?;
                let metadata = observed.metadata()?;
                let stamp = Stamp::of(&metadata);
                if metadata.is_dir() {
                    let child = self.open(&path, OFlags::RDONLY | OFlags::DIRECTORY)?;
                    require(
                        Stamp::of(&child.metadata()?) == stamp,
                        "toolchain directory changed during inventory",
                    )?;
                    self.visit(&child, &path, depth + 1, limits, stopped)?;
                } else {
                    require(
                        self.entries.len() < limits.max_entries,
                        "toolchain entry limit exceeded",
                    )?;
                    let kind = if metadata.is_file() {
                        self.bytes = self
                            .bytes
                            .checked_add(metadata.len())
                            .filter(|bytes| *bytes <= limits.max_bytes)
                            .ok_or_else(|| invalid("toolchain byte limit exceeded"))?;
                        self.files += 1;
                        Kind::File
                    } else if metadata.file_type().is_symlink() {
                        let target = readlinkat(&observed, "", Vec::new())?;
                        let target = target
                            .to_str()
                            .map_err(|_| invalid("non-UTF-8 toolchain symlink"))?;
                        require(
                            !target.is_empty()
                                && target.len() <= 4096
                                && !target.starts_with('/')
                                && !target.contains(['\\', ':'])
                                && !target.chars().any(char::is_control),
                            "toolchain symlinks must have bounded relative targets",
                        )?;
                        Kind::Link(target.to_owned())
                    } else {
                        return Err(invalid("toolchain contains a special file"));
                    };
                    require(
                        self.entries
                            .insert(
                                path.clone(),
                                Entry {
                                    stamp: stamp.clone(),
                                    kind,
                                },
                            )
                            .is_none(),
                        "duplicate toolchain directory entry",
                    )?;
                }
                require(
                    Stamp::of(&self.open(&path, OFlags::PATH)?.metadata()?) == stamp,
                    "toolchain entry changed during inventory",
                )?;
            }
            require(
                Stamp::of(&directory.metadata()?) == before,
                "toolchain directory changed during inventory",
            )
        }

        fn validate_link(&self, path: &str, target: &str) -> io::Result<()> {
            use crate::toolchain_transfer::{LinkNode, validate_link};
            validate_link(path, target, |name| {
                self.entries.get(name).map(|entry| match &entry.kind {
                    Kind::Directory => LinkNode::Directory,
                    Kind::File => LinkNode::File,
                    Kind::Link(target) => LinkNode::Symlink(target),
                })
            })
        }

        pub(super) fn verify(&self, stopped: &impl Fn() -> bool) -> io::Result<()> {
            checkpoint(stopped)?;
            let original = self
                .entries
                .get("")
                .ok_or_else(|| invalid("missing toolchain root stamp"))?;
            require(
                Stamp::of(&fs::symlink_metadata(&self.root_path)?) == original.stamp,
                "toolchain root changed during capture or execution",
            )?;
            for (path, entry) in &self.entries {
                checkpoint(stopped)?;
                let metadata = if path.is_empty() {
                    self.root.metadata()?
                } else {
                    self.open(path, OFlags::PATH)?.metadata()?
                };
                require(
                    Stamp::of(&metadata) == entry.stamp,
                    "toolchain entry changed during capture or execution",
                )?;
            }
            Ok(())
        }

        pub(super) fn verify_source(
            &self,
            source: &Path,
            stopped: &impl Fn() -> bool,
        ) -> io::Result<()> {
            require(
                source == self.root_path,
                "toolchain source witness names another root",
            )?;
            self.verify(stopped)?;
            // Stamp checks cover all regular bytes without reading them again.
            // Keep link text explicit because it defines the exported alias
            // closure, and finish with directory generations to cover negative
            // membership observed before the file/link pass.
            for (path, entry) in &self.entries {
                if let Kind::Link(expected) = &entry.kind {
                    checkpoint(stopped)?;
                    let held = self.open(path, OFlags::PATH)?;
                    require(
                        Stamp::of(&held.metadata()?) == entry.stamp,
                        "toolchain source alias changed before validation",
                    )?;
                    let target = readlinkat(&held, "", Vec::new())?;
                    require(
                        target.to_bytes() == expected.as_bytes()
                            && Stamp::of(&held.metadata()?) == entry.stamp
                            && Stamp::of(&self.open(path, OFlags::PATH)?.metadata()?)
                                == entry.stamp,
                        "toolchain source alias changed during validation",
                    )?;
                }
            }
            for (path, entry) in self.entries.iter().rev() {
                if matches!(entry.kind, Kind::Directory) {
                    checkpoint(stopped)?;
                    let metadata = if path.is_empty() {
                        self.root.metadata()?
                    } else {
                        self.open(path, OFlags::PATH)?.metadata()?
                    };
                    require(
                        Stamp::of(&metadata) == entry.stamp,
                        "toolchain source membership changed during validation",
                    )?;
                }
            }
            checkpoint(stopped)?;
            let original = self
                .entries
                .get("")
                .ok_or_else(|| invalid("missing toolchain root stamp"))?;
            require(
                Stamp::of(&fs::symlink_metadata(source)?) == original.stamp,
                "toolchain source root changed during validation",
            )
        }

        pub(super) fn stream(
            &self,
            destination: Option<&Path>,
            stopped: &impl Fn() -> bool,
        ) -> io::Result<ToolchainIdentity> {
            if destination.is_none()
                && let Some((identity, _)) = self.parallel_read(stopped, &READ_HELPER_BUSY)?
            {
                return Ok(identity);
            }
            self.stream_with_cloner(destination, stopped, &|_, _, _| false, None)
        }

        pub(super) fn stream_with_file_hashes(
            &self,
            stopped: &impl Fn() -> bool,
        ) -> io::Result<(ToolchainIdentity, Vec<[u8; 32]>)> {
            if let Some(result) = self.parallel_read(stopped, &READ_HELPER_BUSY)? {
                return Ok(result);
            }
            // Retain only digests in the inventory's immutable canonical order.
            // At most 100,000 hashes are stored; paths are cloned only when a
            // bounded file-transfer manifest is actually requested.
            let mut hashes = Vec::with_capacity(self.files as usize);
            let identity =
                self.stream_with_cloner(None, stopped, &|_, _, _| false, Some(&mut hashes))?;
            Ok((identity, hashes))
        }

        /// Independently read every selected file, then fold its digest in the
        /// original canonical order. Namespace barriers still belong to the
        /// caller, exactly as for the sequential byte scan below.
        fn parallel_read(
            &self,
            stopped: &impl Fn() -> bool,
            helper_busy: &AtomicBool,
        ) -> io::Result<Option<(ToolchainIdentity, Vec<[u8; 32]>)>> {
            if self.bytes < PARALLEL_READ_BYTES
                || self
                    .entries
                    .values()
                    .filter(|entry| {
                        matches!(entry.kind, Kind::File)
                            && entry.stamp.size >= READ_BUFFER_BYTES as u64
                    })
                    .take(2)
                    .count()
                    < 2
            {
                return Ok(None);
            }
            checkpoint(stopped)?;
            let Some(permit) = ReadHelperPermit::acquire(helper_busy) else {
                return Ok(None);
            };
            let jobs: Vec<_> = self
                .entries
                .iter()
                .filter(|(_, entry)| matches!(entry.kind, Kind::File))
                .collect();
            let mut order: Vec<_> = (0..jobs.len()).collect();
            order.sort_unstable_by_key(|&index| {
                (std::cmp::Reverse(jobs[index].1.stamp.size), index)
            });
            let next = AtomicUsize::new(0);
            let abort = AtomicBool::new(false);
            let hashes: Option<Vec<[u8; 32]>> = std::thread::scope(|scope| {
                // This guard runs before scope's mandatory join on unwinding,
                // including a panic in the caller's non-Sync stop callback.
                let _owner = StopReaders {
                    stopped: &abort,
                    armed: true,
                };
                let (jobs, order, next, abort) = (&jobs, &order, &next, &abort);
                let helper = std::thread::Builder::new()
                    .name("rabs-dataset-read".into())
                    .spawn_scoped(scope, move || {
                        let _permit = permit;
                        let mut failure = StopReaders {
                            stopped: abort,
                            armed: true,
                        };
                        let result =
                            self.read_jobs(jobs, order, next, &|| abort.load(Ordering::Acquire));
                        failure.armed = result.is_err();
                        result
                    });
                let Ok(helper) = helper else {
                    // A refused thread start drops its permit and closure.
                    // No reads have started; use the ordinary scanner in full.
                    return Ok(None);
                };
                let mut owner = self.read_jobs(jobs, order, next, &|| {
                    abort.load(Ordering::Acquire) || stopped()
                });
                if owner.is_err() {
                    abort.store(true, Ordering::Release);
                }
                // The helper may own the last large file. Keep evaluating the
                // original callback on its owner's thread while awaiting it;
                // neither deadlines nor cancellation require Fn: Sync/Send.
                while !helper.is_finished() {
                    if !abort.load(Ordering::Acquire) && stopped() {
                        abort.store(true, Ordering::Release);
                        owner = Err(io::Error::new(
                            io::ErrorKind::Interrupted,
                            "toolchain capture interrupted",
                        ));
                    }
                    std::thread::sleep(Duration::from_millis(1));
                }
                let other = helper
                    .join()
                    .unwrap_or_else(|_| Err(io::Error::other("toolchain dataset reader panicked")));
                // A helper I/O/integrity failure may have interrupted its owner.
                // Preserve that cause rather than reporting only its abort.
                let mut complete = match (owner, other) {
                    (Ok(mut owner), Ok(other)) => {
                        owner.extend(other);
                        owner
                    }
                    (Err(error), _) if error.kind() != io::ErrorKind::Interrupted => {
                        return Err(error);
                    }
                    (_, Err(error)) | (Err(error), _) => return Err(error),
                };
                complete.sort_unstable_by_key(|(index, _)| *index);
                require(
                    complete.len() == jobs.len()
                        && complete
                            .iter()
                            .enumerate()
                            .all(|(position, (index, _))| position == *index),
                    "toolchain dataset read lost a selected file",
                )?;
                Ok(Some(
                    complete.into_iter().map(|(_, digest)| digest).collect(),
                ))
            })?;
            let Some(hashes) = hashes else {
                return Ok(None);
            };
            let mut digest = Sha256::new();
            digest.update(TOOLCHAIN_DATASET_VERSION.as_bytes());
            let mut files = hashes.iter();
            for (path, entry) in &self.entries {
                checkpoint(stopped)?;
                digest.update((path.len() as u64).to_be_bytes());
                digest.update(path.as_bytes());
                match &entry.kind {
                    Kind::Directory => digest.update([0]),
                    Kind::Link(target) => {
                        digest.update([1]);
                        digest.update((target.len() as u64).to_be_bytes());
                        digest.update(target.as_bytes());
                    }
                    Kind::File => {
                        digest.update([2, u8::from(entry.stamp.mode & 0o111 != 0)]);
                        digest.update(entry.stamp.size.to_be_bytes());
                        digest.update(
                            files
                                .next()
                                .ok_or_else(|| invalid("toolchain file digest absent"))?,
                        );
                    }
                }
            }
            Ok(Some((
                ToolchainIdentity {
                    sha256: digest.finalize().into(),
                    files: self.files,
                    bytes: self.bytes,
                },
                hashes,
            )))
        }

        fn read_jobs(
            &self,
            jobs: &[(&String, &Entry)],
            order: &[usize],
            next: &AtomicUsize,
            stopped: &impl Fn() -> bool,
        ) -> io::Result<Vec<(usize, [u8; 32])>> {
            let mut complete = Vec::new();
            let mut buffer = [0_u8; READ_BUFFER_BYTES];
            loop {
                checkpoint(stopped)?;
                let Some(&index) = order.get(next.fetch_add(1, Ordering::Relaxed)) else {
                    return Ok(complete);
                };
                let (path, entry) = jobs[index];
                let mut source =
                    self.open(path, OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOCTTY)?;
                require(
                    Stamp::of(&source.metadata()?) == entry.stamp,
                    "toolchain changed before read",
                )?;
                if let Some(bytes) = std::num::NonZeroU64::new(entry.stamp.size.min(1024 * 1024)) {
                    let _ = fadvise(&source, 0, Some(bytes), Advice::WillNeed);
                }
                let mut digest = Sha256::new();
                let mut copied = 0_u64;
                loop {
                    checkpoint(stopped)?;
                    let read = source.read(&mut buffer)?;
                    if read == 0 {
                        break;
                    }
                    copied = copied
                        .checked_add(read as u64)
                        .filter(|bytes| *bytes <= entry.stamp.size)
                        .ok_or_else(|| invalid("toolchain file grew during capture"))?;
                    digest.update(&buffer[..read]);
                }
                require(
                    copied == entry.stamp.size && Stamp::of(&source.metadata()?) == entry.stamp,
                    "toolchain file changed during capture",
                )?;
                complete.push((index, digest.finalize().into()));
            }
        }

        fn stream_with_cloner(
            &self,
            destination: Option<&Path>,
            stopped: &impl Fn() -> bool,
            cloner: &impl Fn(&File, &File, &Path) -> bool,
            mut file_hashes: Option<&mut Vec<[u8; 32]>>,
        ) -> io::Result<ToolchainIdentity> {
            let mut digest = Sha256::new();
            digest.update(TOOLCHAIN_DATASET_VERSION.as_bytes());
            let mut buffer = [0_u8; 64 * 1024];
            let mut try_cloning = true;
            // A complete installed toolchain contains many small files. Keep
            // only eight anchored descriptors ahead of the reader, with at
            // most 1 MiB of advice per file, so filesystem reads can overlap.
            // Advice supplies no content evidence: every selected file still
            // passes the original read, stamp and independent-copy checks.
            let mut ahead = self
                .entries
                .iter()
                .filter(|(_, entry)| matches!(entry.kind, Kind::File));
            let mut pending = VecDeque::with_capacity(8);
            for (path, entry) in &self.entries {
                checkpoint(stopped)?;
                digest.update((path.len() as u64).to_be_bytes());
                digest.update(path.as_bytes());
                match &entry.kind {
                    Kind::Directory => {
                        digest.update([0]);
                        if let Some(destination) = destination.filter(|_| !path.is_empty()) {
                            fs::DirBuilder::new()
                                .mode(0o700)
                                .create(destination.join(path))?;
                        }
                    }
                    Kind::Link(target) => {
                        digest.update([1]);
                        digest.update((target.len() as u64).to_be_bytes());
                        digest.update(target.as_bytes());
                        // Install links after all regular writes, so a link can
                        // never redirect a destination file creation.
                    }
                    Kind::File => {
                        digest.update([2, u8::from(entry.stamp.mode & 0o111 != 0)]);
                        digest.update(entry.stamp.size.to_be_bytes());
                        while pending.len() < 8 {
                            let Some((next, observed)) = ahead.next() else {
                                break;
                            };
                            checkpoint(stopped)?;
                            let source = self
                                .open(next, OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOCTTY)?;
                            require(
                                Stamp::of(&source.metadata()?) == observed.stamp,
                                "toolchain changed before read-ahead",
                            )?;
                            if let Some(bytes) =
                                std::num::NonZeroU64::new(observed.stamp.size.min(1024 * 1024))
                            {
                                // Unsupported advice falls back to the same
                                // ordinary verified read; it never admits a file.
                                let _ = fadvise(&source, 0, Some(bytes), Advice::WillNeed);
                            }
                            pending.push_back((next, source));
                        }
                        let (next, mut source) = pending
                            .pop_front()
                            .ok_or_else(|| invalid("toolchain read-ahead lost a selected file"))?;
                        require(next == path, "toolchain read-ahead changed file order")?;
                        require(
                            Stamp::of(&source.metadata()?) == entry.stamp,
                            "toolchain changed before read",
                        )?;
                        let mut output = destination
                            .map(|root| {
                                OpenOptions::new()
                                    .write(true)
                                    .create_new(true)
                                    .mode(0o600)
                                    .open(root.join(path))
                            })
                            .transpose()?;
                        let cloned = if let (Some(parent), Some(output)) =
                            (destination, &mut output)
                        {
                            // The caller supplies the already-audited primitive;
                            // small files avoid its filesystem isolation probe.
                            let attempted = try_cloning && entry.stamp.size > buffer.len() as u64;
                            let cloned = if attempted {
                                let started = Instant::now();
                                let cloned = cloner(&source, output, parent);
                                try_cloning = started.elapsed() <= MAX_USEFUL_CLONE_LATENCY;
                                cloned
                            } else {
                                false
                            };
                            checkpoint(stopped)?;
                            if cloned {
                                let metadata = output.metadata()?;
                                require(
                                    metadata.is_file()
                                        && metadata.len() == entry.stamp.size
                                        && (metadata.dev(), metadata.ino())
                                            != (entry.stamp.device, entry.stamp.inode),
                                    "toolchain clone is not an independent complete file",
                                )?;
                            } else if attempted {
                                // Failed primitives may leave both a partial
                                // suffix and moved file offsets. Neither may
                                // leak into the verified fallback copy.
                                output.set_len(0)?;
                                output.rewind()?;
                            }
                            if attempted {
                                source.rewind()?;
                            }
                            cloned
                        } else {
                            false
                        };
                        let mut file_digest = Sha256::new();
                        let mut copied = 0_u64;
                        loop {
                            checkpoint(stopped)?;
                            let read = source.read(&mut buffer)?;
                            if read == 0 {
                                break;
                            }
                            copied = copied
                                .checked_add(read as u64)
                                .filter(|bytes| *bytes <= entry.stamp.size)
                                .ok_or_else(|| invalid("toolchain file grew during capture"))?;
                            file_digest.update(&buffer[..read]);
                            if !cloned && let Some(output) = &mut output {
                                output.write_all(&buffer[..read])?;
                            }
                        }
                        require(
                            copied == entry.stamp.size
                                && Stamp::of(&source.metadata()?) == entry.stamp,
                            "toolchain file changed during capture",
                        )?;
                        let sha256: [u8; 32] = file_digest.finalize().into();
                        digest.update(sha256);
                        if let Some(hashes) = &mut file_hashes {
                            hashes.push(sha256);
                        }
                        if let Some(output) = output {
                            output.set_permissions(fs::Permissions::from_mode(
                                if entry.stamp.mode & 0o111 != 0 {
                                    0o555
                                } else {
                                    0o444
                                },
                            ))?;
                        }
                    }
                }
            }
            if let Some(destination) = destination {
                for (path, entry) in &self.entries {
                    checkpoint(stopped)?;
                    if let Kind::Link(target) = &entry.kind {
                        symlink(target, destination.join(path))?;
                    }
                }
                for (path, entry) in self.entries.iter().rev() {
                    checkpoint(stopped)?;
                    if matches!(entry.kind, Kind::Directory) {
                        let directory = File::open(destination.join(path))?;
                        // Keep directory ownership writable so the caller's
                        // private staging owner can clean up after use. The
                        // execution namespace must mount this tree read-only.
                        directory.set_permissions(fs::Permissions::from_mode(0o700))?;
                    }
                }
            }
            Ok(ToolchainIdentity {
                sha256: digest.finalize().into(),
                files: self.files,
                bytes: self.bytes,
            })
        }
    }

    pub(super) fn capture(
        source: &Path,
        destination: &Path,
        expected: Option<&ToolchainIdentity>,
        limits: &ToolchainLimits,
        stopped: &impl Fn() -> bool,
        cloner: &impl Fn(&File, &File, &Path) -> bool,
    ) -> io::Result<PreparedToolchain> {
        absolute(destination)?;
        let parent = fs::canonicalize(
            destination
                .parent()
                .ok_or_else(|| invalid("toolchain destination parent missing"))?,
        )?;
        let parent_file = File::open(&parent)?;
        require(
            parent_file.metadata()?.is_dir() && parent_file.metadata()?.mode() & 0o077 == 0,
            "toolchain destination parent must be private",
        )?;
        let destination = parent.join(
            destination
                .file_name()
                .ok_or_else(|| invalid("toolchain destination name missing"))?,
        );
        let source_root = fs::canonicalize(source)?;
        require(
            !source_root.starts_with(&destination) && !destination.starts_with(&source_root),
            "toolchain source and destination cannot overlap",
        )?;
        let inventory = Inventory::scan(source, limits, stopped)?;
        checkpoint(stopped)?;
        fs::DirBuilder::new().mode(0o700).create(&destination)?;
        let identity = inventory.stream_with_cloner(Some(&destination), stopped, cloner, None)?;
        inventory.verify(stopped)?;
        require(
            expected.is_none_or(|expected| *expected == identity),
            "toolchain identity does not match expected dataset",
        )?;
        let retained = Inventory::scan(&destination, limits, stopped)?;
        let (retained_identity, file_hashes) = retained.stream_with_file_hashes(stopped)?;
        require(
            retained_identity == identity,
            "retained toolchain bytes differ from captured dataset",
        )?;
        retained.verify(stopped)?;
        inventory.verify_source(source, stopped)?;
        Ok(PreparedToolchain {
            root: destination,
            identity,
            inventory: retained,
            source_inventory: Some(inventory),
            file_hashes,
        })
    }

    #[cfg(test)]
    mod scan_tests {
        use super::*;
        use std::cell::Cell;

        fn fixture() -> (tempfile::TempDir, Inventory) {
            let root = tempfile::tempdir().unwrap();
            fs::create_dir(root.path().join("lib")).unwrap();
            fs::create_dir(root.path().join("empty")).unwrap();
            fs::write(root.path().join("compiler"), vec![43; 3 * 1024 * 1024 + 17]).unwrap();
            fs::set_permissions(
                root.path().join("compiler"),
                fs::Permissions::from_mode(0o755),
            )
            .unwrap();
            fs::write(
                root.path().join("lib/runtime"),
                vec![71; 2 * 1024 * 1024 + 3],
            )
            .unwrap();
            fs::write(root.path().join("lib/zero"), b"").unwrap();
            fs::write(root.path().join("lib/small"), b"small\0\xff").unwrap();
            symlink("lib/runtime", root.path().join("alias")).unwrap();
            let inventory =
                Inventory::scan(root.path(), &ToolchainLimits::default(), &|| false).unwrap();
            (root, inventory)
        }

        fn sequential(inventory: &Inventory) -> (ToolchainIdentity, Vec<[u8; 32]>) {
            let mut hashes = Vec::new();
            let identity = inventory
                .stream_with_cloner(None, &|| false, &|_, _, _| false, Some(&mut hashes))
                .unwrap();
            (identity, hashes)
        }

        #[test]
        fn parallel_reads_match_original_ordered_identity_and_file_hashes() {
            let (root, inventory) = fixture();
            let expected = sequential(&inventory);
            let busy = AtomicBool::new(false);
            let owner = std::thread::current().id();
            let checks = Cell::new(0);
            let actual = inventory
                .parallel_read(
                    &|| {
                        assert_eq!(std::thread::current().id(), owner);
                        checks.set(checks.get() + 1);
                        false
                    },
                    &busy,
                )
                .unwrap()
                .expect("the fixture must exercise the actual helper");
            assert_eq!(actual, expected);
            assert!(checks.get() > 1);
            assert!(!busy.load(Ordering::Acquire));
            inventory.verify_source(root.path(), &|| false).unwrap();
        }

        #[test]
        fn occupied_read_capacity_and_small_datasets_keep_the_serial_path() {
            let (_root, inventory) = fixture();
            let busy = AtomicBool::new(true);
            assert!(inventory.parallel_read(&|| false, &busy).unwrap().is_none());
            assert!(busy.load(Ordering::Acquire));
            // Losing the optional permit does not prevent a complete scan.
            assert_eq!(sequential(&inventory).0.bytes, inventory.bytes);

            let small = tempfile::tempdir().unwrap();
            fs::write(small.path().join("small"), b"ordinary input").unwrap();
            let small =
                Inventory::scan(small.path(), &ToolchainLimits::default(), &|| false).unwrap();
            let available = AtomicBool::new(false);
            assert!(
                small
                    .parallel_read(&|| false, &available)
                    .unwrap()
                    .is_none()
            );
            assert!(!available.load(Ordering::Acquire));
        }

        #[test]
        fn mutation_during_parallel_reads_cannot_refresh_the_original_inventory() {
            for replacement in [false, true] {
                let (root, inventory) = fixture();
                let replacement_root = tempfile::tempdir().unwrap();
                fs::write(
                    replacement_root.path().join("runtime"),
                    vec![71; 2 * 1024 * 1024 + 3],
                )
                .unwrap();
                let busy = AtomicBool::new(false);
                let checks = Cell::new(0);
                let changed = Cell::new(false);
                let result = inventory
                    .parallel_read(
                        &|| {
                            checks.set(checks.get() + 1);
                            if checks.get() == 2 {
                                if replacement {
                                    fs::rename(
                                        replacement_root.path().join("runtime"),
                                        root.path().join("lib/runtime"),
                                    )
                                    .unwrap();
                                } else {
                                    fs::write(
                                        root.path().join("lib/runtime"),
                                        vec![72; 2 * 1024 * 1024 + 3],
                                    )
                                    .unwrap();
                                }
                                changed.set(true);
                            }
                            false
                        },
                        &busy,
                    )
                    .and_then(|value| {
                        inventory.verify_source(root.path(), &|| false)?;
                        Ok(value)
                    });
                assert!(changed.get(), "mutation must occur after helper start");
                assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
                assert!(!busy.load(Ordering::Acquire));
            }
        }

        #[test]
        fn failed_cancelled_and_panicking_read_owners_join_and_release_the_helper() {
            let (root, inventory) = fixture();
            let busy = AtomicBool::new(false);
            let checks = Cell::new(0);
            let error = inventory
                .parallel_read(
                    &|| {
                        let count = checks.get() + 1;
                        checks.set(count);
                        count >= 8
                    },
                    &busy,
                )
                .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::Interrupted);
            assert!(!busy.load(Ordering::Acquire));
            inventory.verify_source(root.path(), &|| false).unwrap();

            let checks = Cell::new(0);
            let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _ = inventory.parallel_read(
                    &|| {
                        checks.set(checks.get() + 1);
                        assert!(checks.get() != 2, "owner callback panic after helper start");
                        false
                    },
                    &busy,
                );
            }));
            assert!(panic.is_err());
            assert!(!busy.load(Ordering::Acquire));
            assert_eq!(
                inventory.parallel_read(&|| false, &busy).unwrap().unwrap(),
                sequential(&inventory)
            );

            fs::write(root.path().join("lib/runtime"), b"changed generation").unwrap();
            let error = inventory.parallel_read(&|| false, &busy).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            assert!(!busy.load(Ordering::Acquire));
        }

        #[test]
        #[ignore = "reads a complete installed SDK; run explicitly with RABS_TEST_TOOLCHAIN_ROOT"]
        fn installed_toolchain_serial_and_parallel_read_comparison() {
            let root = std::env::var_os("RABS_TEST_TOOLCHAIN_ROOT")
                .expect("set RABS_TEST_TOOLCHAIN_ROOT to an actual installed Rust toolchain");
            let root = Path::new(&root);
            let inventory = Inventory::scan(root, &ToolchainLimits::default(), &|| false).unwrap();
            let busy = AtomicBool::new(false);
            let read = |parallel| {
                let started = Instant::now();
                inventory.verify_source(root, &|| false).unwrap();
                let observed = if parallel {
                    inventory
                        .parallel_read(&|| false, &busy)
                        .unwrap()
                        .expect("installed SDK must exercise the actual helper")
                } else {
                    sequential(&inventory)
                };
                inventory.verify_source(root, &|| false).unwrap();
                (observed, started.elapsed())
            };
            // The unchanged serial scanner is live in this SAME invocation.
            // Alternate order; compare every file digest as well as the final
            // dataset identity. Timing is evidence, never a correctness gate.
            for pair in 0..4 {
                let (serial, parallel) = if pair % 2 == 0 {
                    (read(false), read(true))
                } else {
                    let parallel = read(true);
                    (read(false), parallel)
                };
                assert_eq!(serial.0, parallel.0);
                assert!(!busy.load(Ordering::Acquire));
                eprintln!(
                    "{}",
                    serde_json::json!({
                        "kind": "toolchain-dataset-read-comparison",
                        "pair": pair,
                        "first": if pair % 2 == 0 { "serial" } else { "parallel" },
                        "files": inventory.files,
                        "bytes": inventory.bytes,
                        "entries": inventory.entries.len(),
                        "sha256": rabs_protocol::raw_bytes::encode_hex(&serial.0.0.sha256),
                        "serial_seconds": serial.1.as_secs_f64(),
                        "parallel_seconds": parallel.1.as_secs_f64(),
                    })
                );
            }
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::{ToolchainLimits, capture_toolchain};
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn rehash_reads_the_bytes_instead_of_returning_the_saved_identity() {
        let parent = tempfile::tempdir().unwrap();
        fs::set_permissions(parent.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let source = parent.path().join("source");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("compiler"), b"independently retained bytes").unwrap();
        let mut retained = capture_toolchain(
            &source,
            &parent.path().join("retained"),
            None,
            &ToolchainLimits::default(),
            || false,
        )
        .unwrap();
        let actual = *retained.identity();
        retained.identity.sha256[0] ^= 1;
        assert_eq!(retained.rehash_retained_bytes(|| false).unwrap(), actual);
        assert_ne!(retained.identity(), &actual);
        assert!(retained.verify(|| false).is_err());
    }
}
