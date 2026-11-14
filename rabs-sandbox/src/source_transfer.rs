//! Request-scoped source-file transfer into a fresh worker-owned execroot.
//!
//! A manifest binds relative paths, exact lengths, SHA-256 bytes and executable
//! bits. It describes an already-approved projection, NOT permission to crawl a
//! checkout or upload secrets. Senders must supply coherent captured bytes.
//! This transport identity is not an action key or cache-publication authority.
//!
//! The caller owns the private parent directory and its lifetime. The receiver
//! never reuses a directory, follows a peer-selected host path, or exposes a
//! usable root before every declared byte is verified. Filesystem work is
//! synchronous; orchestration must keep the owner alive through process cleanup.

mod projection;

pub use crate::artifact_tree::{
    MAX_ARTIFACT_BYTES, MAX_ARTIFACT_ENTRIES, MAX_ARTIFACT_FILES, MAX_ARTIFACT_MANIFEST_BYTES,
};
pub use projection::{SourceProjectionLease, SourceProjectionPool};

use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

/// Version negotiated independently of output/artifact transfer.
pub const SOURCE_TRANSFER: &str = "source-files-v1";
/// Optional source-begin negotiation for sender-verified incomplete-file reuse.
pub const SOURCE_PREFIX_REUSE_VERSION: &str = "source-file-prefix-v1";
/// Optional hints never enlarge the ordinary source frame or manifest bounds.
pub const MAX_SOURCE_PREFIX_HINT_BYTES: usize = 256 * 1024;
/// Retained image parents. A leftover name must not be credited as free cache space.
pub const SOURCE_PROJECTION_PREFIX: &str = "source-projections-";
/// Bounded decoded bytes in one chunk, before hexadecimal wire expansion.
pub const MAX_SOURCE_CHUNK: usize = 64 * 1024;
/// Maximum number of regular files in one projected source tree.
pub const MAX_SOURCE_FILES: usize = 4096;
/// Aggregate source bytes retained by one session. Oversize refuses, not truncates.
pub const MAX_SOURCE_BYTES: u64 = 512 * 1024 * 1024;

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn checkpoint(stopped: &impl Fn() -> bool) -> io::Result<()> {
    if stopped() {
        Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "source sealing cancelled",
        ))
    } else {
        Ok(())
    }
}

/// A regular input file. Directories are implicit; symlink semantics need a
/// separate versioned contract and are deliberately not approximated here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceFile {
    pub path: String,
    pub len: u64,
    pub sha256: [u8; 32],
    pub executable: bool,
}

/// A validated source projection with the source-only byte and file limits.
pub type SourceManifest = FileManifest<false>;

/// A validated complete artifact tree, with its own bounded transport contract.
/// This type cannot be supplied to a [`SourceReceiver`]. Output capacity never
/// enlarges the input-upload contract or changes an existing source identity.
pub type ArtifactManifest = FileManifest<true>;

/// The shared exact file-set implementation. The const parameter is a protocol
/// type boundary, not a caller-selected numeric limit. Source and artifact
/// senders/receivers share validation and hashing, with distinct digest domains.
/// Caller-supplied ordering never changes the selected protocol's digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileManifest<const ARTIFACT: bool> {
    files: Vec<SourceFile>,
    digest: [u8; 32],
    total: u64,
    metadata: u64,
}

impl<const ARTIFACT: bool> FileManifest<ARTIFACT> {
    pub fn new(mut files: Vec<SourceFile>) -> io::Result<Self> {
        let max_files = if ARTIFACT {
            MAX_ARTIFACT_FILES
        } else {
            MAX_SOURCE_FILES
        };
        let max_bytes = if ARTIFACT {
            MAX_ARTIFACT_BYTES
        } else {
            MAX_SOURCE_BYTES
        };
        let domain: &[u8] = if ARTIFACT {
            b"rabs.artifact-files.v1\0"
        } else {
            b"rabs.source-files.v1\0"
        };
        if files.is_empty() || files.len() > max_files {
            return Err(invalid("transfer file count outside its bound"));
        }
        files.sort_by(|a, b| a.path.cmp(&b.path));
        let mut names = BTreeSet::new();
        let mut directories = BTreeSet::new();
        let mut total = 0_u64;
        let mut metadata = domain.len() as u64 + 8;
        for file in &files {
            if file.path.len() > 1024
                || file.path.contains(['\\', ':'])
                || file.path.chars().any(char::is_control)
                || file.path.split('/').count() > 32
                || file
                    .path
                    .split('/')
                    .any(|part| part.is_empty() || matches!(part, "." | ".."))
                || !names.insert(file.path.as_str())
            {
                return Err(invalid("unsafe or duplicate source path"));
            }
            for (offset, _) in file.path.match_indices('/') {
                directories.insert(&file.path[..offset]);
            }
            if ARTIFACT && names.len().saturating_add(directories.len()) > MAX_ARTIFACT_ENTRIES {
                return Err(invalid(
                    "artifact directory and file count exceeds its bound",
                ));
            }
            metadata = metadata
                .checked_add(8 + file.path.len() as u64 + 8 + 1 + 32)
                .ok_or_else(|| invalid("transfer manifest byte count overflow"))?;
            if ARTIFACT && metadata > MAX_ARTIFACT_MANIFEST_BYTES as u64 {
                return Err(invalid("artifact manifest byte budget exceeded"));
            }
            total = total
                .checked_add(file.len)
                .filter(|size| *size <= max_bytes)
                .ok_or_else(|| invalid("transfer byte budget exceeded"))?;
            if file.len == 0 && file.sha256 != <[u8; 32]>::from(Sha256::digest([])) {
                return Err(invalid("empty source file has a nonempty digest"));
            }
        }
        if names.iter().any(|name| directories.contains(name)) {
            return Err(invalid("source file is also an input directory"));
        }
        if ARTIFACT {
            // Output trees are portable to the receiving filesystem. Reject
            // component-level case aliases before any receiver creates paths;
            // source projections retain their existing path contract.
            crate::artifact_tree::validate_artifact_names(
                files.iter().map(|file| file.path.as_str()),
            )?;
        }
        let mut hash = Sha256::new();
        hash.update(domain);
        hash.update((files.len() as u64).to_be_bytes());
        for file in &files {
            hash.update((file.path.len() as u64).to_be_bytes());
            hash.update(file.path.as_bytes());
            hash.update(file.len.to_be_bytes());
            hash.update([u8::from(file.executable)]);
            hash.update(file.sha256);
        }
        Ok(Self {
            files,
            digest: hash.finalize().into(),
            total,
            metadata,
        })
    }

    #[must_use]
    pub fn files(&self) -> &[SourceFile] {
        &self.files
    }

    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }

    #[must_use]
    pub const fn total_bytes(&self) -> u64 {
        self.total
    }

    /// Canonical manifest bytes, including the domain and fixed-width framing.
    /// This bounds declaration memory independently of the streamed file bytes.
    #[must_use]
    pub const fn metadata_bytes(&self) -> u64 {
        self.metadata
    }
}

struct PendingFile {
    expected: SourceFile,
    received: u64,
    hash: Sha256,
}

/// An input receiver whose constructor accepts only source-bounded manifests.
pub type SourceReceiver = FileReceiver<false>;

/// An output receiver whose constructor requires the distinct artifact contract.
pub type ArtifactReceiver = FileReceiver<true>;

/// One private staging operation. A malformed range leaves it unchanged; an
/// uncertain filesystem write or complete-file digest mismatch poisons it.
/// Retrying an already-written exact range is idempotent and does not rehash it.
pub struct FileReceiver<const ARTIFACT: bool> {
    root: PathBuf,
    // Keep the created directory alive and bind all Linux member opens to it.
    // A replacement at the public path must never become the execution root.
    root_directory: File,
    manifest: FileManifest<ARTIFACT>,
    files: BTreeMap<String, PendingFile>,
    poisoned: bool,
    sealed: bool,
}

/// An independent, fully hashed copy of one completed manifest member. This
/// carries byte identity only: it is not a sealed source tree or an execution
/// capability. Only a receiver can construct it after checking its retained
/// directory and the exact file generation around the copy.
#[derive(Debug)]
pub struct VerifiedSourceFile {
    file: File,
    expected: SourceFile,
}

impl VerifiedSourceFile {
    #[must_use]
    pub fn expected(&self) -> &SourceFile {
        &self.expected
    }

    #[must_use]
    pub fn into_file(self) -> File {
        self.file
    }
}

/// Invalid source bytes revoke this receiver; an unavailable optional byte
/// cache does not. Cancellation is reported separately by the caller's fixed
/// deadline/cancellation check and follows the destination-error branch here.
#[derive(Debug)]
pub enum SourceCheckpointError {
    Source(io::Error),
    Destination(io::Error),
}

#[cfg(unix)]
fn private_directory(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let meta = fs::symlink_metadata(path)?;
    if !meta.is_dir() || meta.permissions().mode() & 0o077 != 0 {
        return Err(invalid(
            "source staging parent must be a private ordinary directory",
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn private_directory(_path: &Path) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "source staging requires Unix",
    ))
}

fn same_identity(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        left.dev() == right.dev() && left.ino() == right.ino()
    }
    #[cfg(not(unix))]
    {
        // SourceReceiver::create refuses these platforms before opening a root.
        let _ = (left, right);
        false
    }
}

fn same_state(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        same_identity(left, right)
            && left.len() == right.len()
            && left.mode() == right.mode()
            && left.nlink() == right.nlink()
            && left.mtime() == right.mtime()
            && left.mtime_nsec() == right.mtime_nsec()
            && left.ctime() == right.ctime()
            && left.ctime_nsec() == right.ctime_nsec()
    }
    #[cfg(not(unix))]
    {
        let _ = (left, right);
        false
    }
}

fn ordinary_file(meta: &fs::Metadata, len: u64) -> io::Result<()> {
    if !meta.is_file() || meta.len() != len {
        return Err(invalid("source staging file type or length changed"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if meta.nlink() != 1 {
            return Err(invalid("source staging file has another link"));
        }
    }
    Ok(())
}

fn open_root(path: &Path) -> io::Result<File> {
    #[cfg(target_os = "linux")]
    {
        use rustix::fs::{Mode, OFlags, open};
        Ok(File::from(open(
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?))
    }
    #[cfg(not(target_os = "linux"))]
    {
        if !fs::symlink_metadata(path)?.is_dir() {
            return Err(invalid("source root is not an ordinary directory"));
        }
        File::open(path)
    }
}

/// Create one exclusive regular file under a retained private directory.
/// Every parent is traversed through directory descriptors; substituted
/// symlinks and mount crossings cannot redirect creation outside this root.
/// Callers must separately retain and check the root's public-name identity.
/// Cancellation leaves any new directories or empty file in owned staging.
pub fn create_staging_file(
    root: &File,
    relative: &str,
    stopped: &impl Fn() -> bool,
) -> io::Result<File> {
    #[cfg(unix)]
    {
        use rustix::fs::{Mode, mkdirat};
        checkpoint(stopped)?;
        if relative.is_empty()
            || relative.len() > 1024
            || relative.contains(['\\', ':'])
            || relative.chars().any(char::is_control)
            || relative.split('/').count() > 32
            || relative
                .split('/')
                .any(|part| part.is_empty() || matches!(part, "." | ".."))
        {
            return Err(invalid("unsafe staging file path"));
        }
        check_staging_directory(root, root)?;
        let mut directory = root.try_clone()?;
        let mut parent = String::new();
        let mut parts = relative.split('/').peekable();
        while let Some(part) = parts.next() {
            checkpoint(stopped)?;
            verify_staging_parent(root, &parent, &directory)?;
            if parts.peek().is_none() {
                let file = open_staging_member(&directory, OsStr::new(part), false, true)?;
                checkpoint(stopped)?;
                verify_staging_parent(root, &parent, &directory)?;
                let named = open_staging_member(&directory, OsStr::new(part), false, false)?;
                if !same_identity(&file.metadata()?, &named.metadata()?) {
                    return Err(invalid("staging file was replaced during creation"));
                }
                return Ok(file);
            }
            match mkdirat(&directory, part, Mode::RWXU) {
                Ok(()) => {}
                Err(error) if error == rustix::io::Errno::EXIST => {}
                Err(error) => return Err(error.into()),
            }
            let child = open_staging_member(&directory, OsStr::new(part), true, false)?;
            check_staging_directory(root, &child)?;
            if !parent.is_empty() {
                parent.push('/');
            }
            parent.push_str(part);
            directory = child;
        }
        Err(invalid("staging file path has no filename"))
    }
    #[cfg(not(unix))]
    {
        let _ = (root, relative, stopped);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "staging requires Unix",
        ))
    }
}

#[cfg(unix)]
fn check_staging_directory(root: &File, directory: &File) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    let metadata = directory.metadata()?;
    if !metadata.is_dir()
        || metadata.dev() != root.metadata()?.dev()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o077 != 0
    {
        return Err(invalid(
            "staging directory is not private, owned and on the retained filesystem",
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn open_staging_member(
    directory: &File,
    name: &OsStr,
    is_directory: bool,
    create: bool,
) -> io::Result<File> {
    use rustix::fs::{Mode, OFlags};
    let flags = OFlags::CLOEXEC
        | OFlags::NOFOLLOW
        | OFlags::NONBLOCK
        | if is_directory {
            OFlags::RDONLY | OFlags::DIRECTORY
        } else if create {
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL
        } else {
            OFlags::RDONLY
        };
    let mode = if create {
        Mode::RUSR | Mode::WUSR
    } else {
        Mode::empty()
    };
    #[cfg(target_os = "linux")]
    let opened = rustix::fs::openat2(
        directory,
        name,
        flags,
        mode,
        rustix::fs::ResolveFlags::BENEATH
            | rustix::fs::ResolveFlags::NO_SYMLINKS
            | rustix::fs::ResolveFlags::NO_MAGICLINKS
            | rustix::fs::ResolveFlags::NO_XDEV,
    )?;
    #[cfg(not(target_os = "linux"))]
    let opened = rustix::fs::openat(directory, name, flags, mode)?;
    Ok(File::from(opened))
}

#[cfg(unix)]
fn verify_staging_parent(root: &File, relative: &str, expected: &File) -> io::Result<()> {
    let mut current = root.try_clone()?;
    for part in relative.split('/').filter(|part| !part.is_empty()) {
        current = open_staging_member(&current, OsStr::new(part), true, false)?;
        check_staging_directory(root, &current)?;
    }
    if !same_identity(&current.metadata()?, &expected.metadata()?) {
        return Err(invalid("staging parent was replaced during creation"));
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum FileAccess {
    Read,
    Append,
    Import,
}

/// Every component is opened separately: NOFOLLOW on the final pathname alone
/// does not protect a file whose parent was replaced with a symlink. NONBLOCK
/// prevents a substituted FIFO from wedging the execution control reactor.
fn open_member(
    directory: &File,
    parent: &Path,
    name: &OsStr,
    is_directory: bool,
    access: FileAccess,
) -> io::Result<File> {
    #[cfg(target_os = "linux")]
    {
        use rustix::fs::{Mode, OFlags, openat};
        let _ = parent;
        let mut flags = OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK;
        flags |= match access {
            FileAccess::Read => OFlags::RDONLY,
            FileAccess::Append => OFlags::WRONLY | OFlags::APPEND,
            FileAccess::Import => OFlags::WRONLY,
        };
        if is_directory {
            flags |= OFlags::DIRECTORY;
        }
        Ok(File::from(openat(directory, name, flags, Mode::empty())?))
    }
    #[cfg(not(target_os = "linux"))]
    {
        // The portable lane retains the private-owner exclusion contract. It
        // checks each component but does not claim Linux's openat race boundary.
        let _ = directory;
        let path = parent.join(name);
        let before = fs::symlink_metadata(&path)?;
        if (is_directory && !before.is_dir()) || (!is_directory && !before.is_file()) {
            return Err(invalid(
                "source member is not an ordinary file or directory",
            ));
        }
        let file = OpenOptions::new()
            .read(matches!(access, FileAccess::Read))
            .write(matches!(access, FileAccess::Import))
            .append(matches!(access, FileAccess::Append))
            .open(&path)?;
        if !same_identity(&before, &file.metadata()?) {
            return Err(invalid("source member changed while opening"));
        }
        Ok(file)
    }
}

fn check_root(root: &Path, directory: &File) -> io::Result<()> {
    let current = fs::symlink_metadata(root)?;
    if !current.is_dir() || !same_identity(&current, &directory.metadata()?) {
        return Err(invalid("source staging root was replaced"));
    }
    Ok(())
}

/// The relative name has already passed SourceManifest validation. At most one
/// parent descriptor is retained while walking to the requested regular file.
fn open_source(
    root: &Path,
    directory: &File,
    relative: &str,
    access: FileAccess,
) -> io::Result<File> {
    check_root(root, directory)?;
    let mut directory = directory.try_clone()?;
    let mut parent = root.to_path_buf();
    let mut parts = relative.split('/').peekable();
    while let Some(part) = parts.next() {
        let is_directory = parts.peek().is_some();
        let member = open_member(
            &directory,
            &parent,
            OsStr::new(part),
            is_directory,
            if is_directory {
                FileAccess::Read
            } else {
                access
            },
        )?;
        if !is_directory {
            return Ok(member);
        }
        directory = member;
        parent.push(part);
    }
    Err(invalid("empty source member"))
}

/// Enumerate incrementally, refusing undeclared entries before descending or
/// opening them. Directory depth and total accepted membership come only from
/// the bounded manifest, never from untrusted read_dir output.
fn each_child(
    directory: &File,
    path: &Path,
    mut visit: impl FnMut(&OsStr) -> io::Result<()>,
) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::ffi::OsStrExt;
        let _ = path;
        let mut entries = rustix::fs::Dir::read_from(directory)?;
        while let Some(entry) = entries.read() {
            let entry = entry?;
            let name = entry.file_name().to_bytes();
            if name != b"." && name != b".." {
                visit(OsStr::from_bytes(name))?;
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = directory;
        for entry in fs::read_dir(path)? {
            visit(&entry?.file_name())?;
        }
    }
    Ok(())
}

fn verify_file(
    file: &mut File,
    expected: &SourceFile,
    stopped: &impl Fn() -> bool,
) -> io::Result<()> {
    checkpoint(stopped)?;
    let before = file.metadata()?;
    ordinary_file(&before, expected.len)?;
    let mut hash = Sha256::new();
    let mut buffer = [0_u8; MAX_SOURCE_CHUNK];
    let mut remaining = expected.len;
    while remaining != 0 {
        checkpoint(stopped)?;
        let count = remaining.min(buffer.len() as u64) as usize;
        file.read_exact(&mut buffer[..count])?;
        hash.update(&buffer[..count]);
        remaining -= count as u64;
    }
    checkpoint(stopped)?;
    // Bounded even when a writer keeps appending. Read exactly the declaration
    // plus one byte rather than following an unbounded moving EOF.
    if file.read(&mut buffer[..1])? != 0
        || !same_state(&before, &file.metadata()?)
        || <[u8; 32]>::from(hash.finalize()) != expected.sha256
    {
        return Err(invalid("staged source bytes changed before seal"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Change the verified descriptor, never re-resolve a mutable pathname.
        file.set_permissions(fs::Permissions::from_mode(if expected.executable {
            0o555
        } else {
            0o444
        }))?;
    }
    checkpoint(stopped)?;
    Ok(())
}

impl<const ARTIFACT: bool> FileReceiver<ARTIFACT> {
    /// `root` is selected by the worker under a held private directory, not by
    /// a remote frame. Existing roots refuse even if empty. Partial failures
    /// remain under the caller's owner and never return an execution capability.
    pub fn create(root: &Path, manifest: FileManifest<ARTIFACT>) -> io::Result<Self> {
        Self::create_cancellable(root, manifest, &|| false)
    }

    /// Create bounded staging with cancellation between namespace operations.
    /// An interrupted creation retains its partial, unsealed directory under
    /// the caller's existing owner; it cannot be reused as a completed tree.
    pub fn create_cancellable(
        root: &Path,
        manifest: FileManifest<ARTIFACT>,
        stopped: &impl Fn() -> bool,
    ) -> io::Result<Self> {
        checkpoint(stopped)?;
        if !root.is_absolute() || root.file_name().is_none() {
            return Err(invalid(
                "source staging root must be an absolute new directory",
            ));
        }
        let parent = root
            .parent()
            .ok_or_else(|| invalid("source staging root has no parent"))?;
        private_directory(parent)?;
        // Freeze the caller-selected ancestry before using peer-selected relative
        // names. The private owner excludes other principals, not hostile code
        // running with the worker's own credentials.
        let name = root.file_name().ok_or_else(|| invalid("source root"))?;
        let parent = fs::canonicalize(parent)?;
        let parent_directory = open_root(&parent)?;
        check_root(&parent, &parent_directory)?;
        Self::create_cancellable_in(&parent.join(name), &parent_directory, manifest, stopped)
    }

    /// Create beneath the caller's already-retained parent generation.
    /// Neither cancellation callbacks nor a replaced public path can select a
    /// different parent between the caller's ownership check and this creation.
    pub fn create_cancellable_in(
        root: &Path,
        parent_directory: &File,
        manifest: FileManifest<ARTIFACT>,
        stopped: &impl Fn() -> bool,
    ) -> io::Result<Self> {
        checkpoint(stopped)?;
        if !root.is_absolute() || root.file_name().is_none() {
            return Err(invalid(
                "source staging root must be an absolute new directory",
            ));
        }
        let name = root.file_name().ok_or_else(|| invalid("source root"))?;
        let parent = root
            .parent()
            .ok_or_else(|| invalid("source staging root has no parent"))?;
        private_directory(parent)?;
        check_root(parent, parent_directory)?;
        let parent = fs::canonicalize(parent)?;
        check_root(&parent, parent_directory)?;
        let root = parent.join(name);
        checkpoint(stopped)?;
        check_root(&parent, parent_directory)?;
        #[cfg(unix)]
        let root_directory = {
            check_staging_directory(parent_directory, parent_directory)?;
            rustix::fs::mkdirat(parent_directory, name, rustix::fs::Mode::RWXU)?;
            open_staging_member(parent_directory, name, true, false)?
        };
        #[cfg(not(unix))]
        let root_directory = open_root(&root)?;
        check_root(&parent, parent_directory)?;
        check_root(&root, &root_directory)?;
        let mut files = BTreeMap::new();
        for expected in manifest.files() {
            checkpoint(stopped)?;
            check_root(&root, &root_directory)?;
            drop(create_staging_file(
                &root_directory,
                &expected.path,
                stopped,
            )?);
            check_root(&root, &root_directory)?;
            files.insert(
                expected.path.clone(),
                PendingFile {
                    expected: expected.clone(),
                    received: 0,
                    hash: Sha256::new(),
                },
            );
        }
        checkpoint(stopped)?;
        check_root(&root, &root_directory)?;
        Ok(Self {
            root,
            root_directory,
            manifest,
            files,
            poisoned: false,
            sealed: false,
        })
    }

    #[must_use]
    pub fn manifest(&self) -> &FileManifest<ARTIFACT> {
        &self.manifest
    }

    /// Accept a contiguous new range or verify an exact retransmission. Only one
    /// chunk is allocated at a time; claimed sizes cannot allocate source-sized
    /// buffers. No write occurs for a wrong digest, path, offset or size.
    pub fn write_chunk(
        &mut self,
        path: &str,
        offset: u64,
        bytes: &[u8],
        chunk_sha256: [u8; 32],
    ) -> io::Result<u64> {
        if self.poisoned || self.sealed {
            return Err(invalid("source staging is failed or already sealed"));
        }
        if bytes.is_empty()
            || bytes.len() > MAX_SOURCE_CHUNK
            || <[u8; 32]>::from(Sha256::digest(bytes)) != chunk_sha256
        {
            return Err(invalid("source chunk length or digest mismatch"));
        }
        let file = self
            .files
            .get_mut(path)
            .ok_or_else(|| invalid("undeclared source file"))?;
        let end = offset
            .checked_add(bytes.len() as u64)
            .filter(|end| *end <= file.expected.len)
            .ok_or_else(|| invalid("source range exceeds declared length"))?;
        if offset > file.received || (offset < file.received && end > file.received) {
            return Err(invalid("source range is not contiguous or an exact retry"));
        }
        let result = (|| {
            let mut target = open_source(
                &self.root,
                &self.root_directory,
                path,
                if offset == file.received {
                    FileAccess::Append
                } else {
                    FileAccess::Read
                },
            )?;
            let before = target.metadata()?;
            ordinary_file(&before, file.received)?;
            if offset < file.received {
                let mut original = vec![0; bytes.len()];
                target.seek(SeekFrom::Start(offset))?;
                target.read_exact(&mut original)?;
                if original != bytes || !same_state(&before, &target.metadata()?) {
                    return Err(invalid("source retry changes accepted bytes"));
                }
                return Ok(file.received);
            }
            target.write_all(bytes)?;
            ordinary_file(&target.metadata()?, end)?;
            file.hash.update(bytes);
            file.received = end;
            if end == file.expected.len
                && <[u8; 32]>::from(file.hash.clone().finalize()) != file.expected.sha256
            {
                return Err(invalid("complete source file digest mismatch"));
            }
            Ok(file.received)
        })();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    /// Copy one completed file into an exclusively created, empty private file.
    /// Reconnecting sessions may reuse these bytes before the whole manifest is
    /// complete, but must still build a fresh receiver and obtain its final seal.
    ///
    /// The supplied destination is checked before any write; it is never
    /// truncated, linked to a source inode, or used as source authority. Reads
    /// are anchored to the retained root, bounded by the manifest, and rehashed
    /// from disk. An input failure poisons this receiver. Destination failure
    /// and cancellation leave execution-source verification to the final seal.
    pub fn checkpoint_file(
        &mut self,
        path: &str,
        mut destination: File,
        stopped: impl Fn() -> bool,
    ) -> Result<VerifiedSourceFile, SourceCheckpointError> {
        let expected = self.verify_completed_member(path, Some(&mut destination), stopped)?;
        Ok(VerifiedSourceFile {
            file: destination,
            expected,
        })
    }

    /// Revalidate one completed member without creating or writing a copy.
    /// A remote byte-cache hit still requires this local custody check: the
    /// transfer transcript, full on-disk digest, EOF and descriptor-bound file
    /// generation are checked exactly as they are for a checkpoint copy.
    ///
    /// This neither seals the source tree nor returns an execution capability.
    /// Changed source poisons this receiver; cancellation stops the bounded
    /// read without changing its state and must still abort the caller's work.
    pub fn verify_completed_file(
        &mut self,
        path: &str,
        stopped: impl Fn() -> bool,
    ) -> io::Result<()> {
        self.verify_completed_member(path, None, stopped)
            .map(|_| ())
            .map_err(|error| match error {
                SourceCheckpointError::Source(error)
                | SourceCheckpointError::Destination(error) => error,
            })
    }

    fn verify_completed_member(
        &mut self,
        path: &str,
        mut destination: Option<&mut File>,
        stopped: impl Fn() -> bool,
    ) -> Result<SourceFile, SourceCheckpointError> {
        use SourceCheckpointError::{Destination, Source};

        if self.poisoned {
            return Err(Source(invalid("source staging is poisoned")));
        }
        let pending = self
            .files
            .get(path)
            .ok_or_else(|| Source(invalid("undeclared source checkpoint member")))?;
        if pending.received != pending.expected.len {
            return Err(Source(invalid("source checkpoint member is incomplete")));
        }
        let expected = pending.expected.clone();
        checkpoint(&stopped).map_err(Destination)?;
        let target = if let Some(destination) = destination.as_mut() {
            let target = destination.metadata().map_err(Destination)?;
            ordinary_file(&target, 0).map_err(Destination)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if target.permissions().mode() & 0o077 != 0 || target.permissions().readonly() {
                    return Err(Destination(invalid(
                        "source checkpoint destination must be a private writable file",
                    )));
                }
            }
            if destination.stream_position().map_err(Destination)? != 0 {
                return Err(Destination(invalid(
                    "source checkpoint destination must start at offset zero",
                )));
            }
            Some(target)
        } else {
            None
        };
        let result = (|| {
            if <[u8; 32]>::from(pending.hash.clone().finalize()) != expected.sha256 {
                return Err(Source(invalid("source checkpoint transcript changed")));
            }
            let mut input = open_source(&self.root, &self.root_directory, path, FileAccess::Read)
                .map_err(Source)?;
            let before = input.metadata().map_err(Source)?;
            ordinary_file(&before, expected.len).map_err(Source)?;
            if target
                .as_ref()
                .is_some_and(|target| same_identity(&before, target))
            {
                return Err(Destination(invalid(
                    "source checkpoint destination aliases its input",
                )));
            }
            let mut hash = Sha256::new();
            let mut buffer = [0_u8; MAX_SOURCE_CHUNK];
            let mut remaining = expected.len;
            while remaining != 0 {
                checkpoint(&stopped).map_err(Destination)?;
                let count = remaining.min(buffer.len() as u64) as usize;
                input.read_exact(&mut buffer[..count]).map_err(Source)?;
                hash.update(&buffer[..count]);
                if let Some(destination) = destination.as_mut() {
                    destination
                        .write_all(&buffer[..count])
                        .map_err(Destination)?;
                }
                remaining -= count as u64;
            }
            checkpoint(&stopped).map_err(Destination)?;
            if input.read(&mut buffer[..1]).map_err(Source)? != 0
                || !same_state(&before, &input.metadata().map_err(Source)?)
                || <[u8; 32]>::from(hash.finalize()) != expected.sha256
            {
                return Err(Source(invalid(
                    "completed source changed during checkpoint",
                )));
            }
            let named = open_source(&self.root, &self.root_directory, path, FileAccess::Read)
                .map_err(Source)?;
            if !same_state(&before, &named.metadata().map_err(Source)?) {
                return Err(Source(invalid("completed source generation was replaced")));
            }
            if let Some(destination) = destination {
                ordinary_file(&destination.metadata().map_err(Destination)?, expected.len)
                    .map_err(Destination)?;
            }
            checkpoint(&stopped).map_err(Destination)?;
            Ok(expected)
        })();
        if matches!(&result, Err(Source(_))) {
            self.poisoned = true;
        }
        result
    }

    /// Import one complete, previously untouched manifest member from an owned
    /// regular file. Local byte reuse needs no transport chunk hashes. Both the
    /// ordinary copy and an optional independent CoW clone verify the complete
    /// manifest digest; the clone path hashes the actual destination bytes.
    ///
    /// This does not seal the receiver or grant execution authority. The final
    /// exact-tree seal still rereads every member. Source/destination movement,
    /// partial I/O and cancellation poison this receiver, including a panicking
    /// cloning callback. A failed clone is truncated before copying normally.
    /// The callback must establish real CoW isolation, never a hardlink.
    pub fn import_file_with_cloner(
        &mut self,
        path: &str,
        input: &mut File,
        stopped: impl Fn() -> bool,
        cloner: impl FnOnce(&File, &File, &Path) -> bool,
    ) -> io::Result<bool> {
        if self.poisoned || self.sealed {
            return Err(invalid("source staging is failed or already sealed"));
        }
        let pending = self
            .files
            .get_mut(path)
            .ok_or_else(|| invalid("undeclared source file"))?;
        if pending.received != 0 {
            return Err(invalid("source import requires an untouched member"));
        }
        // Set the failure fence before invoking external code or touching the
        // destination. A panic cannot leave a partly imported reusable receiver.
        self.poisoned = true;
        let result = (|| {
            checkpoint(&stopped)?;
            let source_before = input.metadata()?;
            if !source_before.is_file() || source_before.len() != pending.expected.len {
                return Err(invalid(
                    "source import input type or length differs from manifest",
                ));
            }
            input.seek(SeekFrom::Start(0))?;
            let mut target =
                open_source(&self.root, &self.root_directory, path, FileAccess::Import)?;
            let target_before = target.metadata()?;
            ordinary_file(&target_before, 0)?;
            if same_identity(&source_before, &target_before) {
                return Err(invalid("source import input aliases its destination"));
            }
            // Both descriptors use the same anchored acquisition. A whole-file
            // clone needs a normal writer: Linux FICLONE refuses O_APPEND.
            // A separate anchored reader verifies actual cloned bytes and binds
            // both descriptors to the same initially empty private inode.
            let mut reader = open_source(&self.root, &self.root_directory, path, FileAccess::Read)?;
            if !same_state(&target_before, &reader.metadata()?) {
                return Err(invalid("source import destination changed while opening"));
            }
            let parent = self.root.join(path);
            let parent = parent
                .parent()
                .ok_or_else(|| invalid("source import parent"))?;
            let cloned = cloner(input, &target, parent);
            checkpoint(&stopped)?;
            if cloned {
                ordinary_file(&target.metadata()?, pending.expected.len)?;
            } else {
                target.set_len(0)?;
                target.rewind()?;
                ordinary_file(&target.metadata()?, 0)?;
            }
            let mut hash = Sha256::new();
            let mut buffer = [0_u8; MAX_SOURCE_CHUNK];
            let mut remaining = pending.expected.len;
            let verify = if cloned { &mut reader } else { &mut *input };
            let observed = verify.metadata()?;
            verify.seek(SeekFrom::Start(0))?;
            while remaining != 0 {
                checkpoint(&stopped)?;
                let count = remaining.min(buffer.len() as u64) as usize;
                verify.read_exact(&mut buffer[..count])?;
                hash.update(&buffer[..count]);
                if !cloned {
                    target.write_all(&buffer[..count])?;
                }
                remaining -= count as u64;
            }
            checkpoint(&stopped)?;
            if verify.read(&mut buffer[..1])? != 0
                || !same_state(&observed, &verify.metadata()?)
                || <[u8; 32]>::from(hash.clone().finalize()) != pending.expected.sha256
            {
                return Err(invalid("source import bytes differ from manifest"));
            }
            if !same_state(&source_before, &input.metadata()?) {
                return Err(invalid("source import input changed while reading"));
            }
            let completed = target.metadata()?;
            ordinary_file(&completed, pending.expected.len)?;
            let named = open_source(&self.root, &self.root_directory, path, FileAccess::Read)?;
            if !same_state(&completed, &reader.metadata()?)
                || !same_state(&completed, &named.metadata()?)
                || same_identity(&source_before, &completed)
            {
                return Err(invalid(
                    "source import destination changed while populating",
                ));
            }
            checkpoint(&stopped)?;
            pending.hash = hash;
            pending.received = pending.expected.len;
            Ok(cloned)
        })();
        if result.is_ok() {
            self.poisoned = false;
        }
        result
    }

    /// Verify the exact closure before returning a usable root. This frontier
    /// seals the bytes, not durable publication. The private owner must outlive
    /// the execution and the execroot must be mounted read-only by the sandbox.
    /// Transfer hashes prove what arrived, not what is still on disk: sealing
    /// rereads every file and rejects all undeclared files, directories and links.
    pub fn seal(&mut self) -> io::Result<&Path> {
        self.seal_cancellable(|| false)
    }

    /// Seal with cooperative cancellation between members and bounded read
    /// chunks. An interrupted verification poisons this staging operation;
    /// clearing cancellation cannot turn a partial verification into authority.
    pub fn seal_cancellable(&mut self, stopped: impl Fn() -> bool) -> io::Result<&Path> {
        if self.poisoned {
            return Err(invalid("source staging is poisoned"));
        }
        if let Err(error) = checkpoint(&stopped) {
            self.poisoned = true;
            return Err(error);
        }
        if self.sealed {
            return Ok(&self.root);
        }
        if self
            .files
            .values()
            .any(|file| file.received != file.expected.len)
        {
            return Err(invalid("source staging is incomplete"));
        }
        let result = (|| {
            for file in self.files.values() {
                checkpoint(&stopped)?;
                if <[u8; 32]>::from(file.hash.clone().finalize()) != file.expected.sha256 {
                    return Err(invalid("source digest changed before seal"));
                }
            }
            check_root(&self.root, &self.root_directory)?;
            let mut directories = BTreeSet::new();
            let mut remaining: BTreeSet<String> = self.files.keys().cloned().collect();
            for name in self.files.keys() {
                checkpoint(&stopped)?;
                for (offset, _) in name.match_indices('/') {
                    directories.insert(&name[..offset]);
                    remaining.insert(name[..offset].to_owned());
                }
            }
            self.verify_directory(
                &self.root_directory,
                &self.root,
                "",
                &directories,
                &mut remaining,
                &stopped,
            )?;
            if !remaining.is_empty() {
                return Err(invalid("source staging lost declared members"));
            }
            check_root(&self.root, &self.root_directory)?;
            checkpoint(&stopped)?;
            Ok(())
        })();
        if let Err(error) = result {
            self.poisoned = true;
            return Err(error);
        }
        self.sealed = true;
        Ok(&self.root)
    }

    fn verify_directory(
        &self,
        directory: &File,
        path: &Path,
        prefix: &str,
        directories: &BTreeSet<&str>,
        remaining: &mut BTreeSet<String>,
        stopped: &impl Fn() -> bool,
    ) -> io::Result<()> {
        checkpoint(stopped)?;
        let before = directory.metadata()?;
        each_child(directory, path, |name| {
            checkpoint(stopped)?;
            let text = name
                .to_str()
                .ok_or_else(|| invalid("non-UTF-8 source member"))?;
            let relative = if prefix.is_empty() {
                text.to_owned()
            } else {
                format!("{prefix}/{text}")
            };
            if !remaining.remove(&relative) {
                return Err(invalid("undeclared or duplicate source member before seal"));
            }
            let is_directory = directories.contains(relative.as_str());
            let mut member = open_member(directory, path, name, is_directory, FileAccess::Read)?;
            if is_directory {
                self.verify_directory(
                    &member,
                    &path.join(name),
                    &relative,
                    directories,
                    remaining,
                    stopped,
                )?;
            } else {
                let pending = self
                    .files
                    .get(&relative)
                    .ok_or_else(|| invalid("undeclared source file"))?;
                verify_file(&mut member, &pending.expected, stopped)?;
            }
            Ok(())
        })?;
        if !same_state(&before, &directory.metadata()?) {
            return Err(invalid("source directory changed during seal"));
        }
        checkpoint(stopped)?;
        Ok(())
    }

    #[must_use]
    pub fn sealed_root(&self) -> Option<&Path> {
        (self.sealed && !self.poisoned).then_some(self.root.as_path())
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    fn entry(path: &str, bytes: &[u8]) -> SourceFile {
        SourceFile {
            path: path.to_owned(),
            len: bytes.len() as u64,
            sha256: Sha256::digest(bytes).into(),
            executable: false,
        }
    }

    #[test]
    fn manifest_binds_bytes_modes_lengths_and_paths_not_order() {
        let a = entry("src/lib.rs", b"source\0\xff");
        let b = entry("Cargo.toml", b"manifest");
        let expected = SourceManifest::new(vec![a.clone(), b.clone()]).unwrap();
        assert_eq!(
            expected,
            SourceManifest::new(vec![b.clone(), a.clone()]).unwrap()
        );
        for changed in [
            SourceFile {
                executable: true,
                ..a.clone()
            },
            SourceFile {
                len: a.len + 1,
                ..a.clone()
            },
            SourceFile {
                path: "src/main.rs".to_owned(),
                ..a.clone()
            },
            entry("src/lib.rs", b"different"),
        ] {
            assert_ne!(
                expected.digest(),
                SourceManifest::new(vec![b.clone(), changed])
                    .unwrap()
                    .digest()
            );
        }
    }

    #[test]
    fn unsafe_conflicting_or_unbounded_manifests_refuse() {
        for path in [
            "",
            "/absolute",
            "../escape",
            "a/./b",
            "a//b",
            "a\\b",
            "a:b",
            "a\0b",
        ] {
            assert!(
                SourceManifest::new(vec![entry(path, b"x")]).is_err(),
                "{path:?}"
            );
        }
        assert!(SourceManifest::new(vec![]).is_err());
        assert!(SourceManifest::new(vec![entry("a", b"x"), entry("a", b"x")]).is_err());
        assert!(SourceManifest::new(vec![entry("a", b"x"), entry("a/b", b"x")]).is_err());
        assert!(
            SourceManifest::new(vec![SourceFile {
                len: MAX_SOURCE_BYTES + 1,
                ..entry("a", b"x")
            }])
            .is_err()
        );
        assert!(
            SourceManifest::new(vec![SourceFile {
                len: 0,
                ..entry("a", b"x")
            }])
            .is_err()
        );
    }

    #[test]
    fn artifact_capacity_and_identity_cannot_widen_source_uploads() {
        let file = entry("src/lib.rs", b"source\0\xff");
        let source = SourceManifest::new(vec![file.clone()]).unwrap();
        // Fixed source-files-v1 wire identity, predating artifact transport.
        assert_eq!(
            source.digest(),
            [
                0xd8, 0x76, 0xd4, 0x33, 0x59, 0x79, 0x40, 0x9a, 0x8a, 0x84, 0x8b, 0xcd, 0xbb, 0x54,
                0x8c, 0xb2, 0x40, 0xed, 0xa0, 0x83, 0x00, 0x0b, 0x62, 0x16, 0xc2, 0xd5, 0xf4, 0x9b,
                0x51, 0xc7, 0x0b, 0xf7,
            ]
        );
        let artifact = ArtifactManifest::new(vec![file.clone()]).unwrap();
        assert_ne!(source.digest(), artifact.digest());
        assert_eq!(source.files(), artifact.files());
        assert_eq!(
            artifact.metadata_bytes(),
            (b"rabs.artifact-files.v1\0".len() + 8 + 8 + file.path.len() + 8 + 1 + 32) as u64
        );

        let many = (0..=MAX_SOURCE_FILES)
            .map(|index| entry(&format!("deps/{index:05}.rmeta"), b""))
            .collect::<Vec<_>>();
        assert!(SourceManifest::new(many.clone()).is_err());
        assert_eq!(
            ArtifactManifest::new(many).unwrap().files().len(),
            MAX_SOURCE_FILES + 1
        );
        let large = SourceFile {
            len: MAX_SOURCE_BYTES + 1,
            ..file
        };
        assert!(SourceManifest::new(vec![large.clone()]).is_err());
        assert_eq!(
            ArtifactManifest::new(vec![large]).unwrap().total_bytes(),
            MAX_SOURCE_BYTES + 1
        );
    }

    #[test]
    fn artifact_manifests_bound_payload_metadata_and_implicit_directories() {
        let mut many = (0..MAX_ARTIFACT_FILES)
            .map(|index| entry(&format!("{index:05}"), b""))
            .collect::<Vec<_>>();
        ArtifactManifest::new(many.clone()).unwrap();
        many.push(entry("overflow", b""));
        assert!(ArtifactManifest::new(many).is_err());

        let maximum = SourceFile {
            len: MAX_ARTIFACT_BYTES,
            ..entry("complete-target", b"x")
        };
        ArtifactManifest::new(vec![maximum.clone()]).unwrap();
        for len in [MAX_ARTIFACT_BYTES + 1, u64::MAX] {
            assert!(
                ArtifactManifest::new(vec![SourceFile {
                    len,
                    ..maximum.clone()
                }])
                .is_err()
            );
        }
        assert!(ArtifactManifest::new(vec![maximum, entry("extra", b"x")]).is_err());

        // 2048 disjoint 32-component paths consume exactly 65536 entries,
        // well below the file-count and encoded-metadata budgets.
        let mut deep = (0..MAX_ARTIFACT_ENTRIES / 32)
            .map(|index| entry(&format!("{index:05}/{}file", "d/".repeat(30)), b""))
            .collect::<Vec<_>>();
        ArtifactManifest::new(deep.clone()).unwrap();
        deep.push(entry("extra", b""));
        assert!(ArtifactManifest::new(deep.clone()).is_err());
        SourceManifest::new(deep).unwrap();

        let prefix = format!(
            "{}/{}/{}/{}",
            "a".repeat(250),
            "b".repeat(250),
            "c".repeat(250),
            "d".repeat(242)
        );
        let per_file = 8 + prefix.len() + 5 + 8 + 1 + 32;
        let header = b"rabs.artifact-files.v1\0".len() + 8;
        let count = (MAX_ARTIFACT_MANIFEST_BYTES - header) / per_file;
        assert!(count < MAX_ARTIFACT_FILES);
        let mut large_names = (0..count)
            .map(|index| entry(&format!("{prefix}{index:05}"), b""))
            .collect::<Vec<_>>();
        let accepted = ArtifactManifest::new(large_names.clone()).unwrap();
        assert!(accepted.metadata_bytes() <= MAX_ARTIFACT_MANIFEST_BYTES as u64);
        large_names.push(entry(&format!("{prefix}{count:05}"), b""));
        assert!(ArtifactManifest::new(large_names).is_err());

        for paths in [["Deps/a.o", "deps/b.o"], ["out", "OUT/a.o"], ["a", "a/b"]] {
            assert!(
                ArtifactManifest::new(paths.into_iter().map(|path| entry(path, b"x")).collect())
                    .is_err()
            );
        }
    }

    #[test]
    fn artifact_receiver_seals_more_than_the_source_file_limit() {
        let owner = private();
        let entries = (0..=MAX_SOURCE_FILES)
            .map(|index| entry(&format!("deps/{index:05}.o"), b"x"))
            .collect::<Vec<_>>();
        let manifest = ArtifactManifest::new(entries).unwrap();
        let mut receiver =
            ArtifactReceiver::create(&owner.path().join("artifacts"), manifest.clone()).unwrap();
        for file in manifest.files() {
            assert_eq!(
                receiver
                    .write_chunk(&file.path, 0, b"x", file.sha256)
                    .unwrap(),
                1
            );
        }
        let sealed = receiver.seal_cancellable(|| false).unwrap().to_path_buf();
        assert_eq!(
            fs::read_dir(sealed.join("deps")).unwrap().count(),
            MAX_SOURCE_FILES + 1
        );
        assert_eq!(fs::read(sealed.join("deps/04096.o")).unwrap(), b"x");
        assert_eq!(receiver.manifest(), &manifest);
        assert_eq!(receiver.sealed_root(), Some(sealed.as_path()));
    }

    #[test]
    fn artifact_receiver_preserves_chunk_poison_and_cancellation_boundaries() {
        use std::cell::Cell;
        for corrupt in [false, true] {
            let owner = private();
            let bytes = vec![0x51; MAX_SOURCE_CHUNK * 3 + 7];
            let manifest = ArtifactManifest::new(vec![entry("binary", &bytes)]).unwrap();
            let root = owner.path().join("artifacts");
            let mut receiver = ArtifactReceiver::create(&root, manifest).unwrap();
            assert!(receiver.write_chunk("binary", 0, b"bad", [0; 32]).is_err());
            assert!(!receiver.poisoned, "malformed chunks cannot alter staging");
            for (index, chunk) in bytes.chunks(MAX_SOURCE_CHUNK).enumerate() {
                receiver
                    .write_chunk(
                        "binary",
                        (index * MAX_SOURCE_CHUNK) as u64,
                        chunk,
                        Sha256::digest(chunk).into(),
                    )
                    .unwrap();
            }
            if corrupt {
                fs::write(root.join("binary"), vec![0x52; bytes.len()]).unwrap();
            }
            let checks = Cell::new(0);
            assert!(
                receiver
                    .seal_cancellable(|| {
                        checks.set(checks.get() + 1);
                        !corrupt && checks.get() == 9
                    })
                    .is_err()
            );
            assert!(receiver.poisoned);
            assert!(receiver.sealed_root().is_none());
            assert!(receiver.seal().is_err());
        }
    }

    #[test]
    fn artifact_receiver_creation_stops_before_all_declared_files_are_created() {
        let owner = private();
        let root = owner.path().join("artifacts");
        let manifest = ArtifactManifest::new(
            (0..=MAX_SOURCE_FILES)
                .map(|index| entry(&format!("deps/{index:05}.o"), b""))
                .collect(),
        )
        .unwrap();
        assert!(ArtifactReceiver::create_cancellable(&root, manifest.clone(), &|| true).is_err());
        assert!(!root.exists());
        let error = ArtifactReceiver::create_cancellable(&root, manifest, &|| {
            root.join("deps/00003.o").exists()
        })
        .err()
        .expect("creation must observe cancellation between files");
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
        assert_eq!(fs::read_dir(root.join("deps")).unwrap().count(), 4);
        assert!(!root.join("deps/00004.o").exists());
    }

    #[test]
    fn cancellable_creation_never_follows_replaced_root_or_ancestry() {
        use std::cell::Cell;
        use std::os::unix::fs::{PermissionsExt, symlink};
        for replace_parent in [false, true] {
            let owner = private();
            let parent = owner.path().join("parent");
            let outside = owner.path().join("outside");
            for path in [&parent, &outside] {
                fs::create_dir(path).unwrap();
                fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
            }
            let root = parent.join("artifacts");
            let calls = Cell::new(0);
            let replaced = Cell::new(false);
            let manifest = ArtifactManifest::new(vec![entry("nested/object", b"x")]).unwrap();
            let result = ArtifactReceiver::create_cancellable(&root, manifest, &|| {
                calls.set(calls.get() + 1);
                let ready = if replace_parent {
                    calls.get() == 2
                } else {
                    root.exists()
                };
                if ready && !replaced.replace(true) {
                    let victim = if replace_parent { &parent } else { &root };
                    fs::rename(victim, owner.path().join("original")).unwrap();
                    symlink(&outside, victim).unwrap();
                }
                false
            });
            assert!(replaced.get());
            assert!(result.is_err());
            assert_eq!(fs::read_dir(&outside).unwrap().count(), 0);
        }
    }

    #[test]
    fn retained_parent_creation_refuses_an_ordinary_directory_substituted_by_a_callback() {
        use std::cell::Cell;
        use std::os::unix::fs::PermissionsExt;
        for replace_at in [1, 2] {
            let owner = private();
            let parent = owner.path().join("parent");
            let replacement = owner.path().join("replacement");
            for path in [&parent, &replacement] {
                fs::create_dir(path).unwrap();
                fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
            }
            let held = File::open(&parent).unwrap();
            let original = owner.path().join("retained-parent");
            let calls = Cell::new(0);
            let result = ArtifactReceiver::create_cancellable_in(
                &parent.join("artifacts"),
                &held,
                ArtifactManifest::new(vec![entry("object", b"x")]).unwrap(),
                &|| {
                    calls.set(calls.get() + 1);
                    if calls.get() == replace_at {
                        fs::rename(&parent, &original).unwrap();
                        fs::rename(&replacement, &parent).unwrap();
                    }
                    false
                },
            );
            assert!(calls.get() >= replace_at);
            assert!(result.is_err());
            assert_eq!(fs::read_dir(&parent).unwrap().count(), 0);
            assert_eq!(fs::read_dir(&original).unwrap().count(), 0);
        }
    }

    #[test]
    fn staging_file_creation_is_anchored_across_parent_replacement() {
        use std::cell::Cell;
        use std::os::unix::fs::{PermissionsExt, symlink};
        let owner = private();
        let root = owner.path().join("artifacts");
        let outside = owner.path().join("outside");
        for path in [&root, &outside] {
            fs::create_dir(path).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let held = File::open(&root).unwrap();
        let replaced = Cell::new(false);
        let result = create_staging_file(&held, "nested/deep/object", &|| {
            if root.join("nested").exists() && !replaced.replace(true) {
                fs::rename(root.join("nested"), root.join("retained")).unwrap();
                symlink(&outside, root.join("nested")).unwrap();
            }
            false
        });
        assert!(replaced.get());
        assert!(result.is_err());
        assert_eq!(fs::read_dir(outside).unwrap().count(), 0);
        assert_eq!(fs::read_dir(root.join("retained")).unwrap().count(), 0);
        for path in ["../escape", "/absolute", "bad//path"] {
            assert!(create_staging_file(&held, path, &|| false).is_err());
        }
    }

    fn private() -> tempfile::TempDir {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }

    fn checkpoint_destination(path: &Path) -> File {
        use std::os::unix::fs::OpenOptionsExt;
        OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .unwrap()
    }

    #[test]
    fn completed_file_verification_preserves_source_without_a_copy_or_tree_seal() {
        let owner = private();
        let root = owner.path().join("source");
        let complete = entry("complete", b"finished\0\xff");
        let partial = entry("partial", b"partial");
        let mut receiver = SourceReceiver::create(
            &root,
            SourceManifest::new(vec![complete.clone(), entry("empty", b""), partial]).unwrap(),
        )
        .unwrap();
        receiver
            .write_chunk("complete", 0, b"finished\0\xff", complete.sha256)
            .unwrap();
        receiver
            .write_chunk("partial", 0, b"part", Sha256::digest(b"part").into())
            .unwrap();
        let before = fs::metadata(root.join("complete")).unwrap();
        receiver
            .verify_completed_file("complete", || false)
            .unwrap();
        receiver.verify_completed_file("empty", || false).unwrap();
        assert!(same_state(
            &before,
            &fs::metadata(root.join("complete")).unwrap()
        ));
        assert!(receiver.sealed_root().is_none());
        for path in ["partial", "undeclared"] {
            assert_eq!(
                receiver
                    .verify_completed_file(path, || false)
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidData,
            );
        }
        assert!(!receiver.poisoned);
        assert_eq!(fs::read_dir(owner.path()).unwrap().count(), 1);
        assert_eq!(fs::read_dir(&root).unwrap().count(), 3);
        receiver
            .write_chunk("partial", 4, b"ial", Sha256::digest(b"ial").into())
            .unwrap();
        receiver.seal().unwrap();
        let sealed = fs::metadata(root.join("complete")).unwrap();
        receiver
            .verify_completed_file("complete", || false)
            .unwrap();
        assert!(same_state(
            &sealed,
            &fs::metadata(root.join("complete")).unwrap()
        ));
        assert!(receiver.sealed_root().is_some());
    }

    #[test]
    fn completed_file_verification_rejects_corruption_and_generation_changes() {
        use std::cell::Cell;
        for mutation in ["corrupt", "rewrite", "replace", "append", "truncate"] {
            let owner = private();
            let root = owner.path().join("source");
            let path = root.join("file");
            let bytes = vec![0x7b; MAX_SOURCE_CHUNK * 2 + 7];
            let mut receiver = SourceReceiver::create(
                &root,
                SourceManifest::new(vec![entry("file", &bytes)]).unwrap(),
            )
            .unwrap();
            for (index, chunk) in bytes.chunks(MAX_SOURCE_CHUNK).enumerate() {
                receiver
                    .write_chunk(
                        "file",
                        (index * MAX_SOURCE_CHUNK) as u64,
                        chunk,
                        Sha256::digest(chunk).into(),
                    )
                    .unwrap();
            }
            let mutate_at = match mutation {
                "corrupt" => 1,
                "append" => 5,
                _ => 3,
            };
            let checks = Cell::new(0);
            let result = receiver.verify_completed_file("file", || {
                checks.set(checks.get() + 1);
                if checks.get() == mutate_at {
                    match mutation {
                        "corrupt" => fs::write(&path, vec![0x42; bytes.len()]).unwrap(),
                        "rewrite" => {
                            fs::write(&path, &bytes).unwrap();
                            File::open(&path)
                                .unwrap()
                                .set_modified(std::time::SystemTime::UNIX_EPOCH)
                                .unwrap();
                        }
                        "replace" => {
                            fs::rename(&path, root.join("old-generation")).unwrap();
                            fs::write(&path, &bytes).unwrap();
                        }
                        "append" => OpenOptions::new()
                            .append(true)
                            .open(&path)
                            .unwrap()
                            .write_all(b"x")
                            .unwrap(),
                        "truncate" => OpenOptions::new()
                            .write(true)
                            .open(&path)
                            .unwrap()
                            .set_len(MAX_SOURCE_CHUNK as u64)
                            .unwrap(),
                        _ => unreachable!(),
                    }
                }
                false
            });
            assert!(result.is_err(), "changed member accepted: {mutation}");
            assert!(receiver.poisoned, "changed member must revoke custody");
            assert!(receiver.sealed_root().is_none());
            assert!(receiver.seal().is_err());
            assert!(receiver.verify_completed_file("file", || false).is_err());
        }
    }

    #[test]
    fn completed_file_verification_cancels_between_bounded_reads() {
        use std::cell::Cell;
        let owner = private();
        let bytes = vec![0x23; MAX_SOURCE_CHUNK * 3];
        let mut receiver = SourceReceiver::create(
            &owner.path().join("source"),
            SourceManifest::new(vec![entry("file", &bytes)]).unwrap(),
        )
        .unwrap();
        for (index, chunk) in bytes.chunks(MAX_SOURCE_CHUNK).enumerate() {
            receiver
                .write_chunk(
                    "file",
                    (index * MAX_SOURCE_CHUNK) as u64,
                    chunk,
                    Sha256::digest(chunk).into(),
                )
                .unwrap();
        }
        let checks = Cell::new(0);
        let error = receiver
            .verify_completed_file("file", || {
                checks.set(checks.get() + 1);
                checks.get() == 3
            })
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
        assert_eq!(checks.get(), 3);
        assert!(!receiver.poisoned);
        receiver.verify_completed_file("file", || false).unwrap();
        receiver.seal().unwrap();
    }

    #[test]
    fn completed_file_checkpoint_has_independent_bytes_without_a_source_tree_seal() {
        use std::os::unix::fs::MetadataExt;
        let owner = private();
        let root = owner.path().join("source");
        let a = entry("a", b"finished\0\xff");
        let b = entry("b", b"partial");
        let mut receiver =
            SourceReceiver::create(&root, SourceManifest::new(vec![a.clone(), b]).unwrap())
                .unwrap();
        receiver
            .write_chunk("a", 0, b"finished\0\xff", a.sha256)
            .unwrap();
        receiver
            .write_chunk("b", 0, b"part", Sha256::digest(b"part").into())
            .unwrap();
        let snapshot = receiver
            .checkpoint_file(
                "a",
                checkpoint_destination(&owner.path().join("checkpoint-a")),
                || false,
            )
            .unwrap();
        assert_eq!(snapshot.expected(), &a);
        assert_ne!(
            snapshot.file.metadata().unwrap().ino(),
            fs::metadata(root.join("a")).unwrap().ino()
        );
        assert_eq!(
            fs::read(owner.path().join("checkpoint-a")).unwrap(),
            b"finished\0\xff"
        );
        assert!(receiver.sealed_root().is_none());
        assert!(receiver.seal().is_err());
        assert!(matches!(
            receiver.checkpoint_file(
                "b",
                checkpoint_destination(&owner.path().join("checkpoint-b")),
                || false,
            ),
            Err(SourceCheckpointError::Source(_))
        ));
        // An invalid API precondition did not change the still-valid receiver.
        receiver
            .write_chunk("b", 4, b"ial", Sha256::digest(b"ial").into())
            .unwrap();
        receiver.seal().unwrap();
    }

    #[test]
    fn checkpoint_destination_failures_preserve_source_and_existing_destination_bytes() {
        use std::os::unix::fs::PermissionsExt;
        let owner = private();
        let root = owner.path().join("source");
        let expected = entry("file", b"good");
        let mut receiver =
            SourceReceiver::create(&root, SourceManifest::new(vec![expected.clone()]).unwrap())
                .unwrap();
        receiver
            .write_chunk("file", 0, b"good", expected.sha256)
            .unwrap();
        let existing = owner.path().join("existing");
        let mut file = checkpoint_destination(&existing);
        file.write_all(b"preserve").unwrap();
        assert!(matches!(
            receiver.checkpoint_file("file", file, || false),
            Err(SourceCheckpointError::Destination(_))
        ));
        assert_eq!(fs::read(&existing).unwrap(), b"preserve");
        let public = owner.path().join("public");
        let file = checkpoint_destination(&public);
        file.set_permissions(fs::Permissions::from_mode(0o644))
            .unwrap();
        assert!(matches!(
            receiver.checkpoint_file("file", file, || false),
            Err(SourceCheckpointError::Destination(_))
        ));
        assert_eq!(fs::metadata(&public).unwrap().len(), 0);
        let readonly = owner.path().join("read-only-descriptor");
        drop(checkpoint_destination(&readonly));
        assert!(matches!(
            receiver.checkpoint_file("file", File::open(readonly).unwrap(), || false),
            Err(SourceCheckpointError::Destination(_))
        ));
        receiver.seal().unwrap();
        assert_eq!(fs::read(root.join("file")).unwrap(), b"good");
    }

    #[test]
    fn checkpoint_rejects_even_an_empty_destination_that_is_the_source_inode() {
        let owner = private();
        let root = owner.path().join("source");
        let mut receiver = SourceReceiver::create(
            &root,
            SourceManifest::new(vec![entry("empty", b"")]).unwrap(),
        )
        .unwrap();
        let alias = OpenOptions::new()
            .read(true)
            .write(true)
            .open(root.join("empty"))
            .unwrap();
        assert!(matches!(
            receiver.checkpoint_file("empty", alias, || false),
            Err(SourceCheckpointError::Destination(_))
        ));
        receiver.seal().unwrap();
    }

    #[test]
    fn checkpoint_rehash_and_generation_check_poison_changed_source_members() {
        use std::cell::Cell;
        for replacement in [false, true] {
            let owner = private();
            let root = owner.path().join("source");
            let bytes = vec![0x7b; MAX_SOURCE_CHUNK * 2 + 7];
            let expected = entry("file", &bytes);
            let mut receiver =
                SourceReceiver::create(&root, SourceManifest::new(vec![expected]).unwrap())
                    .unwrap();
            for (index, chunk) in bytes.chunks(MAX_SOURCE_CHUNK).enumerate() {
                receiver
                    .write_chunk(
                        "file",
                        (index * MAX_SOURCE_CHUNK) as u64,
                        chunk,
                        Sha256::digest(chunk).into(),
                    )
                    .unwrap();
            }
            let checks = Cell::new(0);
            let result = receiver.checkpoint_file(
                "file",
                checkpoint_destination(&owner.path().join("snapshot")),
                || {
                    checks.set(checks.get() + 1);
                    if checks.get() == 3 {
                        if replacement {
                            fs::rename(root.join("file"), root.join("old-generation")).unwrap();
                            fs::write(root.join("file"), &bytes).unwrap();
                        } else {
                            fs::write(root.join("file"), &bytes).unwrap();
                            File::open(root.join("file"))
                                .unwrap()
                                .set_modified(std::time::SystemTime::UNIX_EPOCH)
                                .unwrap();
                        }
                    }
                    false
                },
            );
            assert!(matches!(result, Err(SourceCheckpointError::Source(_))));
            assert!(receiver.sealed_root().is_none());
            assert!(receiver.seal().is_err());
            assert!(receiver.poisoned);
        }
    }

    #[test]
    fn checkpoint_cancellation_stops_after_a_bounded_copy_without_returning_a_witness() {
        use std::cell::Cell;
        let owner = private();
        let root = owner.path().join("source");
        let bytes = vec![0x23; MAX_SOURCE_CHUNK * 3];
        let mut receiver = SourceReceiver::create(
            &root,
            SourceManifest::new(vec![entry("file", &bytes)]).unwrap(),
        )
        .unwrap();
        for (index, chunk) in bytes.chunks(MAX_SOURCE_CHUNK).enumerate() {
            receiver
                .write_chunk(
                    "file",
                    (index * MAX_SOURCE_CHUNK) as u64,
                    chunk,
                    Sha256::digest(chunk).into(),
                )
                .unwrap();
        }
        let checks = Cell::new(0);
        let snapshot = owner.path().join("snapshot");
        assert!(matches!(
            receiver.checkpoint_file("file", checkpoint_destination(&snapshot), || {
                checks.set(checks.get() + 1);
                checks.get() == 3
            }),
            Err(SourceCheckpointError::Destination(error)) if error.kind() == io::ErrorKind::Interrupted
        ));
        assert_eq!(
            fs::metadata(snapshot).unwrap().len(),
            MAX_SOURCE_CHUNK as u64
        );
        assert!(receiver.sealed_root().is_none());
        receiver.seal().unwrap();
    }

    #[test]
    fn exact_binary_chunks_and_empty_files_seal_only_after_complete_verification() {
        use std::os::unix::fs::PermissionsExt;
        let owner = private();
        let manifest =
            SourceManifest::new(vec![entry("src/lib.rs", b"A\0\xffB"), entry("empty", b"")])
                .unwrap();
        let root = owner.path().join("source");
        let mut receiver = SourceReceiver::create(&root, manifest.clone()).unwrap();
        assert!(SourceReceiver::create(&root, manifest).is_err());
        assert!(receiver.sealed_root().is_none());
        assert!(receiver.seal().is_err());
        assert!(
            receiver
                .write_chunk("../escape", 0, b"A", Sha256::digest(b"A").into())
                .is_err()
        );
        assert!(
            receiver
                .write_chunk("src/lib.rs", 0, b"A", [0; 32])
                .is_err()
        );
        assert_eq!(
            receiver
                .write_chunk("src/lib.rs", 0, b"A\0", Sha256::digest(b"A\0").into())
                .unwrap(),
            2
        );
        assert_eq!(
            receiver
                .write_chunk("src/lib.rs", 0, b"A\0", Sha256::digest(b"A\0").into())
                .unwrap(),
            2
        );
        assert!(
            receiver
                .write_chunk("src/lib.rs", 3, b"B", Sha256::digest(b"B").into())
                .is_err()
        );
        assert_eq!(
            receiver
                .write_chunk("src/lib.rs", 2, b"\xffB", Sha256::digest(b"\xffB").into())
                .unwrap(),
            4
        );
        assert_eq!(receiver.seal().unwrap(), root);
        assert_eq!(fs::read(root.join("src/lib.rs")).unwrap(), b"A\0\xffB");
        assert_eq!(fs::read(root.join("empty")).unwrap(), b"");
        assert_eq!(
            fs::metadata(root.join("src/lib.rs"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o444
        );
        assert!(
            receiver
                .write_chunk("src/lib.rs", 0, b"A", Sha256::digest(b"A").into())
                .is_err()
        );
    }

    #[test]
    fn whole_file_import_owns_exact_bytes_and_recovers_a_partial_clone_fallback() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let owner = private();
        let bytes = vec![0x9b; MAX_SOURCE_CHUNK * 3 + 19];
        let mut expected = entry("src/lib.rs", &bytes);
        expected.executable = true;
        let root = owner.path().join("source");
        let mut receiver =
            SourceReceiver::create(&root, SourceManifest::new(vec![expected]).unwrap()).unwrap();
        let mut input = tempfile::tempfile_in(owner.path()).unwrap();
        input.write_all(&bytes).unwrap();
        assert!(
            !receiver
                .import_file_with_cloner(
                    "src/lib.rs",
                    &mut input,
                    || false,
                    |_, mut output, _| {
                        #[cfg(target_os = "linux")]
                        assert!(
                            !rustix::fs::fcntl_getfl(output)
                                .unwrap()
                                .contains(rustix::fs::OFlags::APPEND)
                        );
                        output.write_all(b"failed clone debris").unwrap();
                        false
                    }
                )
                .unwrap()
        );
        assert!(receiver.sealed_root().is_none());
        let target = root.join("src/lib.rs");
        assert_ne!(
            input.metadata().unwrap().ino(),
            fs::metadata(&target).unwrap().ino()
        );
        // The receiver owns its bytes even if the caller changes or drops the
        // anonymous spool before the mandatory final exact-tree verification.
        input.rewind().unwrap();
        input.write_all(b"changed").unwrap();
        drop(input);
        receiver.seal().unwrap();
        assert_eq!(fs::read(&target).unwrap(), bytes);
        assert_eq!(
            fs::metadata(target).unwrap().permissions().mode() & 0o777,
            0o555
        );
    }

    #[test]
    fn whole_file_import_verifies_a_clone_candidates_actual_destination() {
        for corrupt in [false, true] {
            let owner = private();
            let bytes = vec![0x71; MAX_SOURCE_CHUNK * 2 + 3];
            let root = owner.path().join("source");
            let mut receiver = SourceReceiver::create(
                &root,
                SourceManifest::new(vec![entry("src/lib.rs", &bytes)]).unwrap(),
            )
            .unwrap();
            let mut input = tempfile::tempfile_in(owner.path()).unwrap();
            input.write_all(&bytes).unwrap();
            let result = receiver.import_file_with_cloner(
                "src/lib.rs",
                &mut input,
                || false,
                |input, mut output, _| {
                    // Exercise the candidate-verification branch with real
                    // independent bytes; this is not a filesystem CoW claim.
                    if corrupt {
                        output.write_all(&vec![0x72; bytes.len()]).unwrap();
                    } else {
                        io::copy(&mut input.try_clone().unwrap(), &mut output).unwrap();
                    }
                    true
                },
            );
            if corrupt {
                assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
                assert_poisoned(&mut receiver);
            } else {
                assert!(result.unwrap());
                receiver.seal().unwrap();
                assert_eq!(fs::read(root.join("src/lib.rs")).unwrap(), bytes);
            }
        }
    }

    #[test]
    fn whole_file_import_rejects_length_digest_and_post_read_source_mutation() {
        use std::cell::Cell;
        use std::io::Seek;
        for change in 0..3 {
            let owner = private();
            let bytes = vec![0x63; MAX_SOURCE_CHUNK * 3 + 11];
            let mut receiver = SourceReceiver::create(
                &owner.path().join("source"),
                SourceManifest::new(vec![entry("src/lib.rs", &bytes)]).unwrap(),
            )
            .unwrap();
            let mut input = tempfile::tempfile_in(owner.path()).unwrap();
            match change {
                0 => input.write_all(&bytes[..bytes.len() - 1]).unwrap(),
                1 => input.write_all(&vec![0x64; bytes.len()]).unwrap(),
                _ => input.write_all(&bytes).unwrap(),
            }
            input.rewind().unwrap();
            let observer = std::cell::RefCell::new(input.try_clone().unwrap());
            let changed = Cell::new(false);
            let result = receiver.import_file_with_cloner(
                "src/lib.rs",
                &mut input,
                || {
                    if change == 2 && !changed.get() {
                        let mut observer = observer.borrow_mut();
                        let position = observer.stream_position().unwrap();
                        if position >= MAX_SOURCE_CHUNK as u64 {
                            observer.rewind().unwrap();
                            observer.write_all(b"X").unwrap();
                            observer.seek(SeekFrom::Start(position)).unwrap();
                            changed.set(true);
                        }
                    }
                    false
                },
                |_, _, _| false,
            );
            assert!(result.is_err(), "accepted changed source case {change}");
            if change == 2 {
                assert!(changed.get(), "source mutation followed a real read");
            }
            assert_poisoned(&mut receiver);
        }
    }

    #[test]
    fn cancelling_whole_file_import_after_real_read_poisoned_partial_receiver() {
        use std::cell::RefCell;
        let owner = private();
        let bytes = vec![0x31; MAX_SOURCE_CHUNK * 3 + 17];
        let root = owner.path().join("source");
        let mut receiver = SourceReceiver::create(
            &root,
            SourceManifest::new(vec![entry("src/lib.rs", &bytes)]).unwrap(),
        )
        .unwrap();
        let mut input = tempfile::tempfile_in(owner.path()).unwrap();
        input.write_all(&bytes).unwrap();
        input.rewind().unwrap();
        let observer = RefCell::new(input.try_clone().unwrap());
        let error = receiver
            .import_file_with_cloner(
                "src/lib.rs",
                &mut input,
                || observer.borrow_mut().stream_position().unwrap() >= MAX_SOURCE_CHUNK as u64,
                |_, _, _| false,
            )
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
        assert_eq!(input.stream_position().unwrap(), MAX_SOURCE_CHUNK as u64);
        assert_eq!(
            fs::read(root.join("src/lib.rs")).unwrap(),
            bytes[..MAX_SOURCE_CHUNK]
        );
        assert_poisoned(&mut receiver);
    }

    #[test]
    fn whole_file_import_refuses_destination_links_replacements_and_callback_unwind() {
        for change in 0..4 {
            let owner = private();
            let root = owner.path().join("source");
            let mut receiver = SourceReceiver::create(
                &root,
                SourceManifest::new(vec![entry("src/lib.rs", b"AB")]).unwrap(),
            )
            .unwrap();
            let mut input = tempfile::tempfile_in(owner.path()).unwrap();
            input.write_all(b"AB").unwrap();
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                receiver.import_file_with_cloner(
                    "src/lib.rs",
                    &mut input,
                    || false,
                    |_, _, _| {
                        match change {
                            0 => fs::hard_link(root.join("src/lib.rs"), owner.path().join("alias"))
                                .unwrap(),
                            1 => {
                                fs::rename(root.join("src/lib.rs"), owner.path().join("old-file"))
                                    .unwrap();
                                fs::write(root.join("src/lib.rs"), b"").unwrap();
                            }
                            2 => {
                                fs::rename(&root, owner.path().join("old-root")).unwrap();
                                fs::create_dir(&root).unwrap();
                            }
                            _ => panic!("injected clone callback unwind"),
                        }
                        false
                    },
                )
            }));
            assert!(result.is_err() || result.unwrap().is_err());
            assert_poisoned(&mut receiver);
        }
    }

    #[test]
    fn complete_file_mismatch_and_conflicting_retries_poison_the_whole_stage() {
        for retry in [false, true] {
            let owner = private();
            let mut receiver = SourceReceiver::create(
                &owner.path().join("source"),
                SourceManifest::new(vec![entry("a", b"AB")]).unwrap(),
            )
            .unwrap();
            if retry {
                receiver
                    .write_chunk("a", 0, b"A", Sha256::digest(b"A").into())
                    .unwrap();
                assert!(
                    receiver
                        .write_chunk("a", 0, b"X", Sha256::digest(b"X").into())
                        .is_err()
                );
            } else {
                assert!(
                    receiver
                        .write_chunk("a", 0, b"XX", Sha256::digest(b"XX").into())
                        .is_err()
                );
            }
            assert!(receiver.seal().is_err());
            assert!(receiver.sealed_root().is_none());
            assert!(
                receiver
                    .write_chunk("a", 0, b"AB", Sha256::digest(b"AB").into())
                    .is_err()
            );
        }
    }

    fn completed_source(owner: &Path) -> (SourceReceiver, PathBuf) {
        let root = owner.join("source");
        let mut receiver = SourceReceiver::create(
            &root,
            SourceManifest::new(vec![entry("src/lib.rs", b"AB")]).unwrap(),
        )
        .unwrap();
        receiver
            .write_chunk("src/lib.rs", 0, b"AB", Sha256::digest(b"AB").into())
            .unwrap();
        (receiver, root)
    }

    fn assert_poisoned(receiver: &mut SourceReceiver) {
        assert!(receiver.seal().is_err());
        assert!(receiver.sealed_root().is_none());
        assert!(
            receiver
                .write_chunk("src/lib.rs", 0, b"AB", Sha256::digest(b"AB").into())
                .is_err()
        );
        assert!(
            receiver.seal().is_err(),
            "a failed seal cannot be retried into authority"
        );
    }

    fn completed_multichunk_source(owner: &Path) -> (SourceReceiver, PathBuf) {
        let root = owner.join("source");
        let bytes = vec![0x5a; MAX_SOURCE_CHUNK * 3 + 17];
        let mut receiver = SourceReceiver::create(
            &root,
            SourceManifest::new(vec![entry("src/lib.rs", &bytes)]).unwrap(),
        )
        .unwrap();
        for (index, chunk) in bytes.chunks(MAX_SOURCE_CHUNK).enumerate() {
            receiver
                .write_chunk(
                    "src/lib.rs",
                    (index * MAX_SOURCE_CHUNK) as u64,
                    chunk,
                    Sha256::digest(chunk).into(),
                )
                .unwrap();
        }
        (receiver, root)
    }

    #[test]
    fn source_rehash_observes_cancellation_between_real_read_chunks() {
        use std::cell::RefCell;
        use std::os::unix::fs::PermissionsExt;
        let owner = private();
        let (receiver, root) = completed_multichunk_source(owner.path());
        let mut file = File::open(root.join("src/lib.rs")).unwrap();
        // A cloned descriptor shares the actual cursor, so cancellation follows
        // real read progress rather than a checkpoint counter or a timing race.
        let observer = RefCell::new(file.try_clone().unwrap());
        let error = verify_file(&mut file, &receiver.manifest().files()[0], &|| {
            observer.borrow_mut().stream_position().unwrap() >= MAX_SOURCE_CHUNK as u64
        })
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
        assert_eq!(file.stream_position().unwrap(), MAX_SOURCE_CHUNK as u64);
        assert_eq!(file.metadata().unwrap().permissions().mode() & 0o777, 0o600);
        assert!(receiver.sealed_root().is_none());
    }

    #[test]
    fn cancelled_partial_seal_never_exposes_or_retries_into_sealed_authority() {
        use std::cell::Cell;
        use std::os::unix::fs::PermissionsExt;
        let owner = private();
        let (mut receiver, root) = completed_multichunk_source(owner.path());
        let verified = Cell::new(false);
        let error = receiver
            .seal_cancellable(|| {
                // Sealing has actually rehashed the received disk bytes and
                // changed this verified descriptor's mode before we cancel.
                let read_only = fs::metadata(root.join("src/lib.rs"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o222
                    == 0;
                verified.set(read_only);
                read_only
            })
            .unwrap_err();
        assert!(
            verified.get(),
            "cancellation did not reach filesystem verification"
        );
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
        assert!(receiver.seal_cancellable(|| false).is_err());
        assert_poisoned(&mut receiver);
    }

    #[test]
    fn cancelled_seal_refuses_even_an_already_sealed_receiver() {
        let owner = private();
        let (mut receiver, root) = completed_source(owner.path());
        assert_eq!(receiver.seal().unwrap(), root);
        assert_eq!(receiver.sealed_root(), Some(root.as_path()));
        assert_eq!(
            receiver.seal_cancellable(|| true).unwrap_err().kind(),
            io::ErrorKind::Interrupted
        );
        assert_poisoned(&mut receiver);
    }

    #[test]
    fn seal_rehashes_disk_bytes_not_just_the_accepted_chunk_transcript() {
        let owner = private();
        let (mut receiver, root) = completed_source(owner.path());
        fs::write(root.join("src/lib.rs"), b"XY").unwrap();
        assert_poisoned(&mut receiver);
        // Restoring the expected bytes cannot un-poison this operation.
        fs::write(root.join("src/lib.rs"), b"AB").unwrap();
        assert!(receiver.seal().is_err());
    }

    #[test]
    fn accepted_prefix_edits_cannot_hide_behind_a_valid_final_chunk_hash() {
        let owner = private();
        let root = owner.path().join("source");
        let mut receiver = SourceReceiver::create(
            &root,
            SourceManifest::new(vec![entry("src/lib.rs", b"AB")]).unwrap(),
        )
        .unwrap();
        receiver
            .write_chunk("src/lib.rs", 0, b"A", Sha256::digest(b"A").into())
            .unwrap();
        fs::write(root.join("src/lib.rs"), b"X").unwrap();
        // The received transcript still hashes to AB, but the disk now holds XB.
        receiver
            .write_chunk("src/lib.rs", 1, b"B", Sha256::digest(b"B").into())
            .unwrap();
        assert_poisoned(&mut receiver);
    }

    #[test]
    fn seal_refuses_undeclared_files_empty_directories_and_hidden_cargo_inputs() {
        for extra in [
            "extra.rs",
            ".cargo/config.toml",
            ".git/HEAD",
            "src/extra.rs",
            "empty-dir",
        ] {
            let owner = private();
            let (mut receiver, root) = completed_source(owner.path());
            let path = root.join(extra);
            if extra == "empty-dir" {
                fs::create_dir(&path).unwrap();
            } else {
                fs::create_dir_all(path.parent().unwrap()).unwrap();
                fs::write(&path, b"undeclared semantic input").unwrap();
            }
            assert_poisoned(&mut receiver);
        }
    }

    #[test]
    fn seal_refuses_missing_replaced_and_resized_members() {
        for change in 0..4 {
            let owner = private();
            let (mut receiver, root) = completed_source(owner.path());
            let path = root.join("src/lib.rs");
            match change {
                0 => fs::rename(&path, owner.path().join("moved-file")).unwrap(),
                1 => {
                    fs::rename(&path, owner.path().join("moved-file")).unwrap();
                    fs::create_dir(&path).unwrap();
                }
                2 => fs::write(&path, b"A").unwrap(),
                _ => fs::write(&path, b"ABC").unwrap(),
            }
            assert_poisoned(&mut receiver);
        }
    }

    #[test]
    fn root_replacement_never_redirects_upload_or_sealing() {
        for during_upload in [false, true] {
            let owner = private();
            let root = owner.path().join("source");
            let mut receiver = SourceReceiver::create(
                &root,
                SourceManifest::new(vec![entry("src/lib.rs", b"AB")]).unwrap(),
            )
            .unwrap();
            if !during_upload {
                receiver
                    .write_chunk("src/lib.rs", 0, b"AB", Sha256::digest(b"AB").into())
                    .unwrap();
            }
            fs::rename(&root, owner.path().join("original-root")).unwrap();
            fs::create_dir_all(root.join("src")).unwrap();
            let replacement: &[u8] = if during_upload { b"" } else { b"AB" };
            fs::write(root.join("src/lib.rs"), replacement).unwrap();
            if during_upload {
                assert!(
                    receiver
                        .write_chunk("src/lib.rs", 0, b"AB", Sha256::digest(b"AB").into())
                        .is_err()
                );
            }
            assert_poisoned(&mut receiver);
            assert_eq!(fs::read(root.join("src/lib.rs")).unwrap(), replacement);
        }
    }

    #[test]
    fn symlinked_parent_never_receives_source_bytes_or_mode_changes() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        for during_upload in [false, true] {
            let owner = private();
            let root = owner.path().join("source");
            let mut receiver = SourceReceiver::create(
                &root,
                SourceManifest::new(vec![entry("src/lib.rs", b"AB")]).unwrap(),
            )
            .unwrap();
            if !during_upload {
                receiver
                    .write_chunk("src/lib.rs", 0, b"AB", Sha256::digest(b"AB").into())
                    .unwrap();
            }
            let outside = owner.path().join("outside");
            fs::create_dir(&outside).unwrap();
            let bytes: &[u8] = if during_upload { b"" } else { b"AB" };
            let outside_file = outside.join("lib.rs");
            fs::write(&outside_file, bytes).unwrap();
            fs::set_permissions(&outside_file, fs::Permissions::from_mode(0o600)).unwrap();
            fs::rename(root.join("src"), owner.path().join("original-src")).unwrap();
            symlink(&outside, root.join("src")).unwrap();
            if during_upload {
                assert!(
                    receiver
                        .write_chunk("src/lib.rs", 0, b"AB", Sha256::digest(b"AB").into())
                        .is_err()
                );
            }
            assert_poisoned(&mut receiver);
            assert_eq!(fs::read(&outside_file).unwrap(), bytes);
            assert_eq!(
                fs::metadata(&outside_file).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn seal_rejects_final_symlinks_and_hardlinks() {
        use std::os::unix::fs::symlink;
        for change in 0..3 {
            let owner = private();
            let (mut receiver, root) = completed_source(owner.path());
            let path = root.join("src/lib.rs");
            let preserved = owner.path().join("preserved");
            match change {
                0 => fs::hard_link(&path, &preserved).unwrap(),
                1 => {
                    fs::rename(&path, &preserved).unwrap();
                    symlink(&preserved, &path).unwrap();
                }
                _ => symlink("missing", root.join("extra-link")).unwrap(),
            }
            assert_poisoned(&mut receiver);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_substituted_fifo_is_rejected_without_waiting_for_a_writer() {
        use rustix::fs::{CWD, Mode, mkfifoat};
        let owner = private();
        let (mut receiver, root) = completed_source(owner.path());
        let path = root.join("src/lib.rs");
        fs::rename(&path, owner.path().join("preserved")).unwrap();
        mkfifoat(CWD, &path, Mode::RUSR | Mode::WUSR).unwrap();
        assert_poisoned(&mut receiver);
    }

    #[test]
    fn exact_multichunk_binary_empty_and_executable_inputs_remain_usable() {
        use std::os::unix::fs::PermissionsExt;
        let owner = private();
        let bytes: Vec<_> = (0..MAX_SOURCE_CHUNK * 2 + 17)
            .map(|n| (n % 256) as u8)
            .collect();
        let mut executable = entry("tools/run", &bytes);
        executable.executable = true;
        let root = owner.path().join("source");
        let mut receiver = SourceReceiver::create(
            &root,
            SourceManifest::new(vec![executable, entry(".cargo/config.toml", b"")]).unwrap(),
        )
        .unwrap();
        for (index, chunk) in bytes.chunks(MAX_SOURCE_CHUNK).enumerate() {
            receiver
                .write_chunk(
                    "tools/run",
                    (index * MAX_SOURCE_CHUNK) as u64,
                    chunk,
                    Sha256::digest(chunk).into(),
                )
                .unwrap();
        }
        assert_eq!(receiver.seal().unwrap(), root);
        assert_eq!(
            receiver.seal().unwrap(),
            root,
            "a successful seal is idempotent"
        );
        assert_eq!(receiver.sealed_root(), Some(root.as_path()));
        assert_eq!(fs::read(root.join("tools/run")).unwrap(), bytes);
        assert_eq!(
            fs::metadata(root.join("tools/run"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o555
        );
        assert_eq!(
            fs::metadata(root.join(".cargo/config.toml")).unwrap().len(),
            0
        );
    }
}
