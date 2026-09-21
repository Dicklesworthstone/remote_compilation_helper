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

use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

/// Version negotiated independently of output/artifact transfer.
pub const SOURCE_TRANSFER: &str = "source-files-v1";
/// Bounded decoded bytes in one chunk, before hexadecimal wire expansion.
pub const MAX_SOURCE_CHUNK: usize = 64 * 1024;
/// Maximum number of regular files in one projected source tree.
pub const MAX_SOURCE_FILES: usize = 4096;
/// Aggregate source bytes retained by one session. Oversize refuses, not truncates.
pub const MAX_SOURCE_BYTES: u64 = 512 * 1024 * 1024;

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
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

/// A validated exact file set with one canonical identity implementation shared
/// by senders and receivers. Caller-supplied ordering never changes its digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceManifest {
    files: Vec<SourceFile>,
    digest: [u8; 32],
    total: u64,
}

impl SourceManifest {
    pub fn new(mut files: Vec<SourceFile>) -> io::Result<Self> {
        if files.is_empty() || files.len() > MAX_SOURCE_FILES {
            return Err(invalid("source file count outside its bound"));
        }
        files.sort_by(|a, b| a.path.cmp(&b.path));
        let mut names = BTreeSet::new();
        let mut directories = BTreeSet::new();
        let mut total = 0_u64;
        for file in &files {
            if file.path.len() > 1024
                || file.path.contains(['\\', ':'])
                || file.path.chars().any(char::is_control)
                || file.path.split('/').count() > 32
                || file.path.split('/').any(|part| part.is_empty() || matches!(part, "." | ".."))
                || !names.insert(file.path.as_str())
            {
                return Err(invalid("unsafe or duplicate source path"));
            }
            for (offset, _) in file.path.match_indices('/') {
                directories.insert(&file.path[..offset]);
            }
            total = total.checked_add(file.len).filter(|size| *size <= MAX_SOURCE_BYTES)
                .ok_or_else(|| invalid("source byte budget exceeded"))?;
            if file.len == 0 && file.sha256 != <[u8; 32]>::from(Sha256::digest([])) {
                return Err(invalid("empty source file has a nonempty digest"));
            }
        }
        if names.iter().any(|name| directories.contains(name)) {
            return Err(invalid("source file is also an input directory"));
        }
        let mut hash = Sha256::new();
        hash.update(b"rabs.source-files.v1\0");
        hash.update((files.len() as u64).to_be_bytes());
        for file in &files {
            hash.update((file.path.len() as u64).to_be_bytes());
            hash.update(file.path.as_bytes());
            hash.update(file.len.to_be_bytes());
            hash.update([u8::from(file.executable)]);
            hash.update(file.sha256);
        }
        Ok(Self { files, digest: hash.finalize().into(), total })
    }

    #[must_use]
    pub fn files(&self) -> &[SourceFile] { &self.files }

    #[must_use]
    pub const fn digest(&self) -> [u8; 32] { self.digest }

    #[must_use]
    pub const fn total_bytes(&self) -> u64 { self.total }
}

struct PendingFile {
    expected: SourceFile,
    received: u64,
    hash: Sha256,
}

/// One private staging operation. A malformed range leaves it unchanged; an
/// uncertain filesystem write or complete-file digest mismatch poisons it.
/// Retrying an already-written exact range is idempotent and does not rehash it.
pub struct SourceReceiver {
    root: PathBuf,
    // Keep the created directory alive and bind all Linux member opens to it.
    // A replacement at the public path must never become the execution root.
    root_directory: File,
    manifest: SourceManifest,
    files: BTreeMap<String, PendingFile>,
    poisoned: bool,
    sealed: bool,
}

#[cfg(unix)]
fn private_directory(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let meta = fs::symlink_metadata(path)?;
    if !meta.is_dir() || meta.permissions().mode() & 0o077 != 0 {
        return Err(invalid("source staging parent must be a private ordinary directory"));
    }
    Ok(())
}

#[cfg(not(unix))]
fn private_directory(_path: &Path) -> io::Result<()> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "source staging requires Unix"))
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

/// Every component is opened separately: NOFOLLOW on the final pathname alone
/// does not protect a file whose parent was replaced with a symlink. NONBLOCK
/// prevents a substituted FIFO from wedging the execution control reactor.
fn open_member(
    directory: &File,
    parent: &Path,
    name: &OsStr,
    is_directory: bool,
    append: bool,
) -> io::Result<File> {
    #[cfg(target_os = "linux")]
    {
        use rustix::fs::{Mode, OFlags, openat};
        let _ = parent;
        let mut flags = OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK;
        flags |= if append { OFlags::WRONLY | OFlags::APPEND } else { OFlags::RDONLY };
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
            return Err(invalid("source member is not an ordinary file or directory"));
        }
        let file = OpenOptions::new().read(!append).append(append).open(&path)?;
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
fn open_source(root: &Path, directory: &File, relative: &str, append: bool) -> io::Result<File> {
    check_root(root, directory)?;
    let mut directory = directory.try_clone()?;
    let mut parent = root.to_path_buf();
    let mut parts = relative.split('/').peekable();
    while let Some(part) = parts.next() {
        let is_directory = parts.peek().is_some();
        let member = open_member(&directory, &parent, OsStr::new(part), is_directory, append && !is_directory)?;
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

fn verify_file(file: &mut File, expected: &SourceFile) -> io::Result<()> {
    let before = file.metadata()?;
    ordinary_file(&before, expected.len)?;
    let mut hash = Sha256::new();
    let mut buffer = [0_u8; MAX_SOURCE_CHUNK];
    let mut remaining = expected.len;
    while remaining != 0 {
        let count = remaining.min(buffer.len() as u64) as usize;
        file.read_exact(&mut buffer[..count])?;
        hash.update(&buffer[..count]);
        remaining -= count as u64;
    }
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
        file.set_permissions(fs::Permissions::from_mode(if expected.executable { 0o555 } else { 0o444 }))?;
    }
    Ok(())
}

impl SourceReceiver {
    /// `root` is selected by the worker under a held private directory, not by
    /// a remote frame. Existing roots refuse even if empty. Partial failures
    /// remain under the caller's owner and never return an execution capability.
    pub fn create(root: &Path, manifest: SourceManifest) -> io::Result<Self> {
        if !root.is_absolute() || root.file_name().is_none() {
            return Err(invalid("source staging root must be an absolute new directory"));
        }
        let parent = root.parent().ok_or_else(|| invalid("source staging root has no parent"))?;
        private_directory(parent)?;
        // Freeze the caller-selected ancestry before using peer-selected relative
        // names. The private owner excludes other principals, not hostile code
        // running with the worker's own credentials.
        let root = fs::canonicalize(parent)?.join(root.file_name().ok_or_else(|| invalid("source root"))?);
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(&root)?;
        let root_directory = open_root(&root)?;
        check_root(&root, &root_directory)?;
        let mut files = BTreeMap::new();
        for expected in manifest.files() {
            let path = root.join(&expected.path);
            let parent = path.parent().ok_or_else(|| invalid("source file has no parent"))?;
            let mut directories = fs::DirBuilder::new();
            directories.recursive(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                directories.mode(0o700);
            }
            directories.create(parent)?;
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            drop(options.open(&path)?);
            files.insert(expected.path.clone(), PendingFile {
                expected: expected.clone(), received: 0, hash: Sha256::new(),
            });
        }
        Ok(Self { root, root_directory, manifest, files, poisoned: false, sealed: false })
    }

    #[must_use]
    pub fn manifest(&self) -> &SourceManifest { &self.manifest }

    /// Accept a contiguous new range or verify an exact retransmission. Only one
    /// chunk is allocated at a time; claimed sizes cannot allocate source-sized
    /// buffers. No write occurs for a wrong digest, path, offset or size.
    pub fn write_chunk(
        &mut self, path: &str, offset: u64, bytes: &[u8], chunk_sha256: [u8; 32],
    ) -> io::Result<u64> {
        if self.poisoned || self.sealed {
            return Err(invalid("source staging is failed or already sealed"));
        }
        if bytes.is_empty() || bytes.len() > MAX_SOURCE_CHUNK
            || <[u8; 32]>::from(Sha256::digest(bytes)) != chunk_sha256
        {
            return Err(invalid("source chunk length or digest mismatch"));
        }
        let file = self.files.get_mut(path).ok_or_else(|| invalid("undeclared source file"))?;
        let end = offset.checked_add(bytes.len() as u64)
            .filter(|end| *end <= file.expected.len)
            .ok_or_else(|| invalid("source range exceeds declared length"))?;
        if offset > file.received || (offset < file.received && end > file.received) {
            return Err(invalid("source range is not contiguous or an exact retry"));
        }
        let result = (|| {
            let mut target = open_source(&self.root, &self.root_directory, path, offset == file.received)?;
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
        if result.is_err() { self.poisoned = true; }
        result
    }

    /// Verify the exact closure before returning a usable root. This frontier
    /// seals the bytes, not durable publication. The private owner must outlive
    /// the execution and the execroot must be mounted read-only by the sandbox.
    /// Transfer hashes prove what arrived, not what is still on disk: sealing
    /// rereads every file and rejects all undeclared files, directories and links.
    pub fn seal(&mut self) -> io::Result<&Path> {
        if self.poisoned { return Err(invalid("source staging is poisoned")); }
        if self.sealed { return Ok(&self.root); }
        if self.files.values().any(|file| file.received != file.expected.len) {
            return Err(invalid("source staging is incomplete"));
        }
        let result = (|| {
            for file in self.files.values() {
                if <[u8; 32]>::from(file.hash.clone().finalize()) != file.expected.sha256 {
                    return Err(invalid("source digest changed before seal"));
                }
            }
            check_root(&self.root, &self.root_directory)?;
            let mut directories = BTreeSet::new();
            let mut remaining: BTreeSet<String> = self.files.keys().cloned().collect();
            for name in self.files.keys() {
                for (offset, _) in name.match_indices('/') {
                    directories.insert(&name[..offset]);
                    remaining.insert(name[..offset].to_owned());
                }
            }
            self.verify_directory(&self.root_directory, &self.root, "", &directories, &mut remaining)?;
            if !remaining.is_empty() {
                return Err(invalid("source staging lost declared members"));
            }
            check_root(&self.root, &self.root_directory)?;
            Ok(())
        })();
        if let Err(error) = result { self.poisoned = true; return Err(error); }
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
    ) -> io::Result<()> {
        let before = directory.metadata()?;
        each_child(directory, path, |name| {
            let text = name.to_str().ok_or_else(|| invalid("non-UTF-8 source member"))?;
            let relative = if prefix.is_empty() { text.to_owned() } else { format!("{prefix}/{text}") };
            if !remaining.remove(&relative) {
                return Err(invalid("undeclared or duplicate source member before seal"));
            }
            let is_directory = directories.contains(relative.as_str());
            let mut member = open_member(directory, path, name, is_directory, false)?;
            if is_directory {
                self.verify_directory(&member, &path.join(name), &relative, directories, remaining)?;
            } else {
                let pending = self.files.get(&relative).ok_or_else(|| invalid("undeclared source file"))?;
                verify_file(&mut member, &pending.expected)?;
            }
            Ok(())
        })?;
        if !same_state(&before, &directory.metadata()?) {
            return Err(invalid("source directory changed during seal"));
        }
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
        SourceFile { path: path.to_owned(), len: bytes.len() as u64,
            sha256: Sha256::digest(bytes).into(), executable: false }
    }

    #[test]
    fn manifest_binds_bytes_modes_lengths_and_paths_not_order() {
        let a = entry("src/lib.rs", b"source\0\xff");
        let b = entry("Cargo.toml", b"manifest");
        let expected = SourceManifest::new(vec![a.clone(), b.clone()]).unwrap();
        assert_eq!(expected, SourceManifest::new(vec![b.clone(), a.clone()]).unwrap());
        for changed in [
            SourceFile { executable: true, ..a.clone() },
            SourceFile { len: a.len + 1, ..a.clone() },
            SourceFile { path: "src/main.rs".to_owned(), ..a.clone() },
            entry("src/lib.rs", b"different"),
        ] {
            assert_ne!(expected.digest(), SourceManifest::new(vec![b.clone(), changed]).unwrap().digest());
        }
    }

    #[test]
    fn unsafe_conflicting_or_unbounded_manifests_refuse() {
        for path in ["", "/absolute", "../escape", "a/./b", "a//b", "a\\b", "a:b", "a\0b"] {
            assert!(SourceManifest::new(vec![entry(path, b"x")]).is_err(), "{path:?}");
        }
        assert!(SourceManifest::new(vec![]).is_err());
        assert!(SourceManifest::new(vec![entry("a", b"x"), entry("a", b"x")]).is_err());
        assert!(SourceManifest::new(vec![entry("a", b"x"), entry("a/b", b"x")]).is_err());
        assert!(SourceManifest::new(vec![SourceFile { len: MAX_SOURCE_BYTES + 1, ..entry("a", b"x") }]).is_err());
        assert!(SourceManifest::new(vec![SourceFile { len: 0, ..entry("a", b"x") }]).is_err());
    }

    #[test]
    fn exact_binary_chunks_and_empty_files_seal_only_after_complete_verification() {
        use std::os::unix::fs::PermissionsExt;
        let owner = tempfile::tempdir().unwrap();
        let manifest = SourceManifest::new(vec![entry("src/lib.rs", b"A\0\xffB"), entry("empty", b"")]).unwrap();
        let root = owner.path().join("source");
        let mut receiver = SourceReceiver::create(&root, manifest.clone()).unwrap();
        assert!(SourceReceiver::create(&root, manifest).is_err());
        assert!(receiver.sealed_root().is_none());
        assert!(receiver.seal().is_err());
        assert!(receiver.write_chunk("../escape", 0, b"A", Sha256::digest(b"A").into()).is_err());
        assert!(receiver.write_chunk("src/lib.rs", 0, b"A", [0; 32]).is_err());
        assert_eq!(receiver.write_chunk("src/lib.rs", 0, b"A\0", Sha256::digest(b"A\0").into()).unwrap(), 2);
        assert_eq!(receiver.write_chunk("src/lib.rs", 0, b"A\0", Sha256::digest(b"A\0").into()).unwrap(), 2);
        assert!(receiver.write_chunk("src/lib.rs", 3, b"B", Sha256::digest(b"B").into()).is_err());
        assert_eq!(receiver.write_chunk("src/lib.rs", 2, b"\xffB", Sha256::digest(b"\xffB").into()).unwrap(), 4);
        assert_eq!(receiver.seal().unwrap(), root);
        assert_eq!(fs::read(root.join("src/lib.rs")).unwrap(), b"A\0\xffB");
        assert_eq!(fs::read(root.join("empty")).unwrap(), b"");
        assert_eq!(fs::metadata(root.join("src/lib.rs")).unwrap().permissions().mode() & 0o777, 0o444);
        assert!(receiver.write_chunk("src/lib.rs", 0, b"A", Sha256::digest(b"A").into()).is_err());
    }

    #[test]
    fn complete_file_mismatch_and_conflicting_retries_poison_the_whole_stage() {
        for retry in [false, true] {
            let owner = tempfile::tempdir().unwrap();
            let mut receiver = SourceReceiver::create(&owner.path().join("source"),
                SourceManifest::new(vec![entry("a", b"AB")]).unwrap()).unwrap();
            if retry {
                receiver.write_chunk("a", 0, b"A", Sha256::digest(b"A").into()).unwrap();
                assert!(receiver.write_chunk("a", 0, b"X", Sha256::digest(b"X").into()).is_err());
            } else {
                assert!(receiver.write_chunk("a", 0, b"XX", Sha256::digest(b"XX").into()).is_err());
            }
            assert!(receiver.seal().is_err());
            assert!(receiver.sealed_root().is_none());
            assert!(receiver.write_chunk("a", 0, b"AB", Sha256::digest(b"AB").into()).is_err());
        }
    }

    fn completed_source(owner: &Path) -> (SourceReceiver, PathBuf) {
        let root = owner.join("source");
        let mut receiver = SourceReceiver::create(
            &root, SourceManifest::new(vec![entry("src/lib.rs", b"AB")]).unwrap(),
        ).unwrap();
        receiver.write_chunk("src/lib.rs", 0, b"AB", Sha256::digest(b"AB").into()).unwrap();
        (receiver, root)
    }

    fn assert_poisoned(receiver: &mut SourceReceiver) {
        assert!(receiver.seal().is_err());
        assert!(receiver.sealed_root().is_none());
        assert!(receiver.write_chunk("src/lib.rs", 0, b"AB", Sha256::digest(b"AB").into()).is_err());
        assert!(receiver.seal().is_err(), "a failed seal cannot be retried into authority");
    }

    #[test]
    fn seal_rehashes_disk_bytes_not_just_the_accepted_chunk_transcript() {
        let owner = tempfile::tempdir().unwrap();
        let (mut receiver, root) = completed_source(owner.path());
        fs::write(root.join("src/lib.rs"), b"XY").unwrap();
        assert_poisoned(&mut receiver);
        // Restoring the expected bytes cannot un-poison this operation.
        fs::write(root.join("src/lib.rs"), b"AB").unwrap();
        assert!(receiver.seal().is_err());
    }

    #[test]
    fn accepted_prefix_edits_cannot_hide_behind_a_valid_final_chunk_hash() {
        let owner = tempfile::tempdir().unwrap();
        let root = owner.path().join("source");
        let mut receiver = SourceReceiver::create(
            &root, SourceManifest::new(vec![entry("src/lib.rs", b"AB")]).unwrap(),
        ).unwrap();
        receiver.write_chunk("src/lib.rs", 0, b"A", Sha256::digest(b"A").into()).unwrap();
        fs::write(root.join("src/lib.rs"), b"X").unwrap();
        // The received transcript still hashes to AB, but the disk now holds XB.
        receiver.write_chunk("src/lib.rs", 1, b"B", Sha256::digest(b"B").into()).unwrap();
        assert_poisoned(&mut receiver);
    }

    #[test]
    fn seal_refuses_undeclared_files_empty_directories_and_hidden_cargo_inputs() {
        for extra in ["extra.rs", ".cargo/config.toml", ".git/HEAD", "src/extra.rs", "empty-dir"] {
            let owner = tempfile::tempdir().unwrap();
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
            let owner = tempfile::tempdir().unwrap();
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
            let owner = tempfile::tempdir().unwrap();
            let root = owner.path().join("source");
            let mut receiver = SourceReceiver::create(
                &root, SourceManifest::new(vec![entry("src/lib.rs", b"AB")]).unwrap(),
            ).unwrap();
            if !during_upload {
                receiver.write_chunk("src/lib.rs", 0, b"AB", Sha256::digest(b"AB").into()).unwrap();
            }
            fs::rename(&root, owner.path().join("original-root")).unwrap();
            fs::create_dir_all(root.join("src")).unwrap();
            let replacement: &[u8] = if during_upload { b"" } else { b"AB" };
            fs::write(root.join("src/lib.rs"), replacement).unwrap();
            if during_upload {
                assert!(receiver.write_chunk("src/lib.rs", 0, b"AB", Sha256::digest(b"AB").into()).is_err());
            }
            assert_poisoned(&mut receiver);
            assert_eq!(fs::read(root.join("src/lib.rs")).unwrap(), replacement);
        }
    }

    #[test]
    fn symlinked_parent_never_receives_source_bytes_or_mode_changes() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        for during_upload in [false, true] {
            let owner = tempfile::tempdir().unwrap();
            let root = owner.path().join("source");
            let mut receiver = SourceReceiver::create(
                &root, SourceManifest::new(vec![entry("src/lib.rs", b"AB")]).unwrap(),
            ).unwrap();
            if !during_upload {
                receiver.write_chunk("src/lib.rs", 0, b"AB", Sha256::digest(b"AB").into()).unwrap();
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
                assert!(receiver.write_chunk("src/lib.rs", 0, b"AB", Sha256::digest(b"AB").into()).is_err());
            }
            assert_poisoned(&mut receiver);
            assert_eq!(fs::read(&outside_file).unwrap(), bytes);
            assert_eq!(fs::metadata(&outside_file).unwrap().permissions().mode() & 0o777, 0o600);
        }
    }

    #[test]
    fn seal_rejects_final_symlinks_and_hardlinks() {
        use std::os::unix::fs::symlink;
        for change in 0..3 {
            let owner = tempfile::tempdir().unwrap();
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
        let owner = tempfile::tempdir().unwrap();
        let (mut receiver, root) = completed_source(owner.path());
        let path = root.join("src/lib.rs");
        fs::rename(&path, owner.path().join("preserved")).unwrap();
        mkfifoat(CWD, &path, Mode::RUSR | Mode::WUSR).unwrap();
        assert_poisoned(&mut receiver);
    }

    #[test]
    fn exact_multichunk_binary_empty_and_executable_inputs_remain_usable() {
        use std::os::unix::fs::PermissionsExt;
        let owner = tempfile::tempdir().unwrap();
        let bytes: Vec<_> = (0..MAX_SOURCE_CHUNK * 2 + 17).map(|n| (n % 256) as u8).collect();
        let mut executable = entry("tools/run", &bytes);
        executable.executable = true;
        let root = owner.path().join("source");
        let mut receiver = SourceReceiver::create(&root, SourceManifest::new(vec![
            executable, entry(".cargo/config.toml", b""),
        ]).unwrap()).unwrap();
        for (index, chunk) in bytes.chunks(MAX_SOURCE_CHUNK).enumerate() {
            receiver.write_chunk("tools/run", (index * MAX_SOURCE_CHUNK) as u64, chunk,
                Sha256::digest(chunk).into()).unwrap();
        }
        assert_eq!(receiver.seal().unwrap(), root);
        assert_eq!(receiver.seal().unwrap(), root, "a successful seal is idempotent");
        assert_eq!(receiver.sealed_root(), Some(root.as_path()));
        assert_eq!(fs::read(root.join("tools/run")).unwrap(), bytes);
        assert_eq!(fs::metadata(root.join("tools/run")).unwrap().permissions().mode() & 0o777, 0o555);
        assert_eq!(fs::metadata(root.join(".cargo/config.toml")).unwrap().len(), 0);
    }
}
