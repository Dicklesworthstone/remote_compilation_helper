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
        Ok(Self { root, manifest, files, poisoned: false, sealed: false })
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
        let target = self.root.join(path);
        let result = (|| {
            let meta = fs::symlink_metadata(&target)?;
            if !meta.is_file() || meta.len() != file.received {
                return Err(invalid("source staging file changed outside its owner"));
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if meta.nlink() != 1 { return Err(invalid("source staging file has another link")); }
            }
            if offset < file.received {
                let mut original = vec![0; bytes.len()];
                let mut input = File::open(&target)?;
                input.seek(SeekFrom::Start(offset))?;
                input.read_exact(&mut original)?;
                if original != bytes { return Err(invalid("source retry changes accepted bytes")); }
                return Ok(file.received);
            }
            let mut output = OpenOptions::new().append(true).open(&target)?;
            output.write_all(bytes)?;
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
                let path = self.root.join(&file.expected.path);
                let meta = fs::symlink_metadata(&path)?;
                if !meta.is_file() || meta.len() != file.expected.len {
                    return Err(invalid("source file changed before seal"));
                }
                #[cfg(unix)]
                {
                    use std::os::unix::fs::{MetadataExt, PermissionsExt};
                    if meta.nlink() != 1 { return Err(invalid("source file linked before seal")); }
                    fs::set_permissions(&path, fs::Permissions::from_mode(
                        if file.expected.executable { 0o555 } else { 0o444 },
                    ))?;
                }
            }
            Ok(())
        })();
        if let Err(error) = result { self.poisoned = true; return Err(error); }
        self.sealed = true;
        Ok(&self.root)
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
}
