//! Exact, bounded target-tree delivery for remote canonical operations.
//!
//! This module grants byte custody only. The operation owner must first drain
//! every writer and must recheck its producer authority after capture and before
//! reporting success. Each returned artifact is an independent regular file;
//! directories are implicit and only the executable bit is transported. Empty
//! directories, timestamps, hard-link topology and Cargo freshness are not part
//! of this first protocol. Unsupported or oversized trees refuse in full.

use rabs_sandbox::artifact_tree::{MAX_ARTIFACT_BYTES, TreeInventory, validate_artifact_names};
use rabs_sandbox::source_transfer::{
    ArtifactManifest, ArtifactReceiver, MAX_SOURCE_CHUNK, SourceFile, create_staging_file,
};
use sha2::{Digest, Sha256};
use std::fs::{self, File, Metadata};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

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
            "remote target delivery cancelled",
        ))
    } else {
        Ok(())
    }
}

fn mode(executable: bool) -> u32 {
    if executable { 0o555 } else { 0o444 }
}

fn validate_manifest(manifest: &ArtifactManifest) -> io::Result<()> {
    // The independently negotiated artifact profile bounds both data and
    // metadata. Source upload limits never authorize or restrict this tree.
    validate_artifact_names(manifest.files().iter().map(|file| file.path.as_str()))?;
    Ok(())
}

/// Retain the local parent identity across staging and final publication.
/// Other principals cannot mutate this private tree; a replacement by the
/// same user is still refused rather than redirecting the final rename.
#[derive(Debug)]
struct Parent {
    path: PathBuf,
    directory: File,
    ancestors: Vec<(PathBuf, File)>,
}

impl Parent {
    fn open(path: &Path) -> io::Result<Self> {
        use rustix::fs::{Mode, OFlags, openat};
        super::private_directory(path)?;
        let mut ancestors = Vec::new();
        let mut current = PathBuf::from("/");
        let mut directory = File::open(&current)?;
        for component in path.components().skip(1) {
            let child = File::from(openat(
                &directory,
                component.as_os_str(),
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )?);
            ancestors.push((current.clone(), directory));
            current.push(component.as_os_str());
            directory = child;
        }
        let owner = Self {
            path: path.to_path_buf(),
            directory,
            ancestors,
        };
        owner.verify()?;
        Ok(owner)
    }

    fn try_clone(&self) -> io::Result<Self> {
        Ok(Self {
            path: self.path.clone(),
            directory: self.directory.try_clone()?,
            ancestors: self
                .ancestors
                .iter()
                .map(|(path, directory)| Ok((path.clone(), directory.try_clone()?)))
                .collect::<io::Result<_>>()?,
        })
    }

    fn child(&self, path: PathBuf, directory: File) -> io::Result<Self> {
        let mut ancestors = self.try_clone()?.ancestors;
        ancestors.push((self.path.clone(), self.directory.try_clone()?));
        let child = Self {
            path,
            directory,
            ancestors,
        };
        child.verify()?;
        Ok(child)
    }

    fn verify(&self) -> io::Result<()> {
        super::private_directory(&self.path)?;
        for (path, directory) in &self.ancestors {
            let current = fs::symlink_metadata(path)?;
            let held = directory.metadata()?;
            require(
                current.is_dir() && current.dev() == held.dev() && current.ino() == held.ino(),
                "remote target parent ancestry was replaced",
            )?;
        }
        let current = fs::symlink_metadata(&self.path)?;
        let held = self.directory.metadata()?;
        require(
            current.dev() == held.dev() && current.ino() == held.ino(),
            "remote target parent was replaced",
        )
    }
}

/// The canonical operation owner retains this parent until final delivery and
/// cleans the capture together with its original target. This narrower owner
/// never removes a path on drop: a replaced name is not deletion authority.
/// Standalone callers likewise retain ownership of the parent lifecycle.
#[derive(Debug)]
struct CaptureOwner {
    parent: Parent,
    directory: Parent,
}

impl CaptureOwner {
    fn create(parent: &Parent) -> io::Result<Self> {
        use rustix::fs::{Mode, OFlags, mkdirat, openat};
        parent.verify()?;
        let created = tempfile::Builder::new()
            .prefix("rabs-target-capture-")
            .disable_cleanup(true)
            .make_in(&parent.path, |path| {
                parent.verify()?;
                let name = path
                    .file_name()
                    .ok_or_else(|| invalid("capture owner name is absent"))?;
                mkdirat(&parent.directory, name, Mode::RWXU)?;
                let directory = File::from(openat(
                    &parent.directory,
                    name,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )?);
                parent.verify()?;
                Ok(directory)
            })?;
        let (directory, path) = created.keep().map_err(|error| error.error)?;
        let owner = Self {
            parent: parent.try_clone()?,
            directory: parent.child(path, directory)?,
        };
        owner.verify()?;
        Ok(owner)
    }

    fn path(&self) -> &Path {
        &self.directory.path
    }

    fn verify(&self) -> io::Result<()> {
        use rustix::fs::{Mode, OFlags, openat};
        self.parent.verify()?;
        let name = self
            .path()
            .file_name()
            .ok_or_else(|| invalid("capture owner name is absent"))?;
        let named = File::from(openat(
            &self.parent.directory,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?);
        let named = named.metadata()?;
        let retained = self.directory.directory.metadata()?;
        require(
            named.dev() == retained.dev() && named.ino() == retained.ino(),
            "capture owner name was replaced",
        )?;
        self.directory.verify()?;
        self.parent.verify()
    }
}

fn verify_capture_root(owner: &CaptureOwner, directory: &File) -> io::Result<()> {
    use rustix::fs::{Mode, OFlags, openat};
    owner.verify()?;
    let named = File::from(openat(
        &owner.directory.directory,
        "files",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?);
    let current = named.metadata()?;
    let retained = directory.metadata()?;
    require(
        current.dev() == retained.dev()
            && current.ino() == retained.ino()
            && current.mode() & 0o077 == 0,
        "captured target root was replaced or is no longer private",
    )
}

/// Rehash the exact retained namespace, including empty files, and sync only
/// those anchored descriptors. The inventory comparison brackets all reads;
/// a valid digest alone cannot bless replaced files, extra entries or links.
fn verify_tree(
    tree: &TreeInventory,
    manifest: &ArtifactManifest,
    stopped: &impl Fn() -> bool,
    sync: bool,
) -> io::Result<()> {
    checkpoint(stopped)?;
    validate_manifest(manifest)?;
    tree.verify(stopped)?;
    verify_manifest_bytes(tree, manifest, stopped, sync)?;
    if sync {
        // Lexical order puts every child after its parent; sync children first.
        let directories: Vec<_> = tree.directory_names().collect();
        for name in directories.into_iter().rev() {
            checkpoint(stopped)?;
            tree.open_directory(name)?.sync_all()?;
        }
    }
    tree.verify(stopped)?;
    checkpoint(stopped)
}

/// Hash through the original inventory's retained root. Publication changes
/// only the root's name and ctime, so an installed receipt can retain the exact
/// same file/directory identities instead of reconstructing them from a path.
fn verify_manifest_bytes(
    tree: &TreeInventory,
    manifest: &ArtifactManifest,
    stopped: &impl Fn() -> bool,
    sync: bool,
) -> io::Result<()> {
    require(
        tree.names()
            .eq(manifest.files().iter().map(|file| file.path.as_str()))
            && tree.total_bytes() == manifest.total_bytes(),
        "remote target inventory differs from its manifest",
    )?;
    let mut buffer = [0_u8; MAX_SOURCE_CHUNK];
    for expected in manifest.files() {
        checkpoint(stopped)?;
        let mut file = tree.open_file(&expected.path)?;
        let metadata = file.metadata()?;
        require(
            metadata.len() == expected.len
                && metadata.nlink() == 1
                && metadata.mode() & 0o7777 == mode(expected.executable),
            "remote target file length, mode or link identity changed",
        )?;
        let mut hash = Sha256::new();
        let mut remaining = expected.len;
        while remaining != 0 {
            checkpoint(stopped)?;
            let count = remaining.min(buffer.len() as u64) as usize;
            file.read_exact(&mut buffer[..count])?;
            hash.update(&buffer[..count]);
            remaining -= count as u64;
        }
        require(
            file.read(&mut buffer[..1])? == 0
                && <[u8; 32]>::from(hash.finalize()) == expected.sha256,
            "remote target file bytes differ from its manifest",
        )?;
        tree.verify_file(&expected.path, &file)?;
        if sync {
            file.sync_all()?;
        }
    }
    Ok(())
}

/// Independent captured bytes, never writable links into the completed target.
/// Its parent remains under the operation owner's custody through delivery.
#[derive(Debug)]
pub(super) struct CapturedTarget {
    owner: CaptureOwner,
    tree: TreeInventory,
    manifest: ArtifactManifest,
}

impl CapturedTarget {
    /// The caller has already joined compiler/publication writers. Capture the
    /// entire ordinary-file tree or refuse; no oversized subset is exported.
    pub(super) fn capture(target: &Path, stopped: &impl Fn() -> bool) -> io::Result<Self> {
        checkpoint(stopped)?;
        super::private_directory(target)?;
        let parent = Parent::open(
            target
                .parent()
                .ok_or_else(|| invalid("remote target has no parent"))?,
        )?;
        let original = TreeInventory::scan_complete_artifacts(target, MAX_ARTIFACT_BYTES, stopped)?;
        validate_artifact_names(original.names())?;
        let owner = CaptureOwner::create(&parent)?;
        let captured_parent = &owner.directory;
        let root = owner.path().join("files");
        use rustix::fs::{Mode, OFlags, mkdirat, openat};
        mkdirat(&captured_parent.directory, "files", Mode::RWXU)?;
        let root_directory = File::from(openat(
            &captured_parent.directory,
            "files",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?);
        verify_capture_root(&owner, &root_directory)?;
        let mut files = Vec::new();
        let mut buffer = [0_u8; MAX_SOURCE_CHUNK];
        for name in original.names() {
            checkpoint(stopped)?;
            verify_capture_root(&owner, &root_directory)?;
            let mut input = original.open_file(name)?;
            let metadata = input.metadata()?;
            let mut output = create_staging_file(&root_directory, name, stopped)?;
            let executable = metadata.mode() & 0o111 != 0;
            let mut remaining = metadata.len();
            let mut hash = Sha256::new();
            while remaining != 0 {
                checkpoint(stopped)?;
                let count = remaining.min(buffer.len() as u64) as usize;
                input.read_exact(&mut buffer[..count])?;
                output.write_all(&buffer[..count])?;
                hash.update(&buffer[..count]);
                remaining -= count as u64;
            }
            require(
                input.read(&mut buffer[..1])? == 0,
                "remote target grew during capture",
            )?;
            original.verify_file(name, &input)?;
            output.set_permissions(fs::Permissions::from_mode(mode(executable)))?;
            output.sync_all()?;
            verify_capture_root(&owner, &root_directory)?;
            files.push(SourceFile {
                path: name.to_owned(),
                len: metadata.len(),
                sha256: hash.finalize().into(),
                executable,
            });
        }
        original.verify(stopped)?;
        parent.verify()?;
        verify_capture_root(&owner, &root_directory)?;
        let manifest = ArtifactManifest::new(files)?;
        validate_manifest(&manifest)?;
        let tree = TreeInventory::scan_complete_artifacts(&root, MAX_ARTIFACT_BYTES, stopped)?;
        let scanned = tree.open_directory("")?.metadata()?;
        let retained = root_directory.metadata()?;
        require(
            scanned.dev() == retained.dev() && scanned.ino() == retained.ino(),
            "captured target inventory names a different root",
        )?;
        verify_tree(&tree, &manifest, stopped, true)?;
        captured_parent.directory.sync_all()?;
        parent.directory.sync_all()?;
        original.verify(stopped)?;
        parent.verify()?;
        verify_capture_root(&owner, &root_directory)?;
        checkpoint(stopped)?;
        Ok(Self {
            owner,
            tree,
            manifest,
        })
    }

    pub(super) fn manifest(&self) -> &ArtifactManifest {
        &self.manifest
    }

    /// Read at most one protocol chunk through the retained inventory. The
    /// source generation is checked on the same descriptor after the read.
    pub(super) fn read_chunk(
        &self,
        path: &str,
        offset: u64,
        maximum: usize,
        stopped: &impl Fn() -> bool,
    ) -> io::Result<Vec<u8>> {
        checkpoint(stopped)?;
        require(
            (1..=MAX_SOURCE_CHUNK).contains(&maximum),
            "remote target chunk exceeds its byte bound",
        )?;
        let index = self
            .manifest
            .files()
            .binary_search_by(|file| file.path.as_str().cmp(path))
            .map_err(|_| invalid("undeclared remote target member"))?;
        let expected = &self.manifest.files()[index];
        let remaining = expected
            .len
            .checked_sub(offset)
            .ok_or_else(|| invalid("remote target range exceeds its file"))?;
        let count = remaining.min(maximum as u64) as usize;
        let mut file = self.tree.open_file(path)?;
        file.seek(SeekFrom::Start(offset))?;
        let mut bytes = vec![0; count];
        file.read_exact(&mut bytes)?;
        self.tree.verify_file(path, &file)?;
        checkpoint(stopped)?;
        Ok(bytes)
    }

    /// Mandatory after the last byte is sent and before terminal success.
    pub(super) fn verify(&self, stopped: &impl Fn() -> bool) -> io::Result<()> {
        self.owner.verify()?;
        verify_tree(&self.tree, &self.manifest, stopped, false)
    }
}

fn same_directory_state(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.is_dir()
        && right.is_dir()
        && left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.len() == right.len()
        && left.nlink() == right.nlink()
        && left.mode() == right.mode()
        && left.uid() == right.uid()
        && left.gid() == right.gid()
        && (left.mtime(), left.mtime_nsec()) == (right.mtime(), right.mtime_nsec())
}

/// In-process custody of the exact tree installed by this receiver. It cannot
/// be reconstructed from a destination path or an untrusted saved manifest.
/// Retain it through terminal acknowledgment and any reconnect uncertainty.
#[derive(Debug)]
pub(super) struct InstalledTarget {
    parent: Parent,
    destination: PathBuf,
    directory: File,
    installed: fs::Metadata,
    tree: TreeInventory,
    manifest: ArtifactManifest,
}

impl InstalledTarget {
    pub(super) fn manifest(&self) -> &ArtifactManifest {
        &self.manifest
    }

    fn verify_location(&self) -> io::Result<()> {
        use rustix::fs::{Mode, OFlags, openat};
        self.parent.verify()?;
        let name = self
            .destination
            .file_name()
            .ok_or_else(|| invalid("installed remote target name is absent"))?;
        let named = File::from(openat(
            &self.parent.directory,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?);
        for current in [named.metadata()?, self.directory.metadata()?] {
            require(
                same_directory_state(&current, &self.installed)
                    && (current.ctime(), current.ctime_nsec())
                        == (self.installed.ctime(), self.installed.ctime_nsec()),
                "installed remote target directory was replaced or changed",
            )?;
        }
        Ok(())
    }

    fn verify_inventory(&self, stopped: &impl Fn() -> bool) -> io::Result<()> {
        self.verify_location()?;
        // The original root's pre-rename ctime and pathname are obsolete. Its
        // children retain their exact sealed identities; the separate retained
        // root descriptor and post-rename stamp cover root membership instead.
        for name in self.tree.directory_names().filter(|name| !name.is_empty()) {
            checkpoint(stopped)?;
            self.tree.open_directory(name)?;
        }
        for name in self.tree.names() {
            checkpoint(stopped)?;
            self.tree.open_file(name)?;
        }
        self.verify_location()
    }

    pub(super) fn verify(&self, stopped: &impl Fn() -> bool) -> io::Result<()> {
        checkpoint(stopped)?;
        self.verify_inventory(stopped)?;
        verify_manifest_bytes(&self.tree, &self.manifest, stopped, false)?;
        self.verify_inventory(stopped)
    }
}

/// An untrusted old member becomes a byte hint only after a bounded, complete
/// hash. Its name is always resolved beneath the retained private root, never
/// through an old manifest or an unrelated directory enumeration.
struct ReuseFile {
    file: File,
    observed: Metadata,
}

fn same_reuse_file(before: &Metadata, after: &Metadata) -> bool {
    after.is_file()
        && after.nlink() == 1
        && before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.len() == after.len()
        && before.mode() == after.mode()
        && before.mtime() == after.mtime()
        && before.mtime_nsec() == after.mtime_nsec()
        && before.ctime() == after.ctime()
        && before.ctime_nsec() == after.ctime_nsec()
}

fn open_reuse_file(root: &Parent, path: &str) -> io::Result<File> {
    use rustix::fs::{Mode, OFlags, ResolveFlags, openat2};
    Ok(File::from(openat2(
        &root.directory,
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK | OFlags::NOCTTY,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_XDEV,
    )?))
}

impl ReuseFile {
    fn inspect(
        root: &Parent,
        expected: &SourceFile,
        buffer: &mut [u8],
        stopped: &impl Fn() -> bool,
    ) -> io::Result<Option<Self>> {
        checkpoint(stopped)?;
        root.verify()?;
        let mut file = match open_reuse_file(root, &expected.path) {
            Ok(file) => file,
            Err(_) => {
                // Missing, inaccessible and linked old members are all misses.
                // The selected root itself must nevertheless remain unchanged.
                root.verify()?;
                checkpoint(stopped)?;
                return Ok(None);
            }
        };
        let observed = match file.metadata() {
            Ok(metadata)
                if metadata.is_file()
                    && metadata.nlink() == 1
                    && metadata.len() == expected.len =>
            {
                metadata
            }
            _ => return Ok(None),
        };
        let inspected = (|| {
            let mut hash = Sha256::new();
            let mut remaining = expected.len;
            while remaining != 0 {
                checkpoint(stopped)?;
                let count = remaining.min(buffer.len() as u64) as usize;
                file.read_exact(&mut buffer[..count])?;
                hash.update(&buffer[..count]);
                remaining -= count as u64;
            }
            checkpoint(stopped)?;
            Ok::<_, io::Error>(
                file.read(&mut buffer[..1])? == 0
                    && <[u8; 32]>::from(hash.finalize()) == expected.sha256
                    && same_reuse_file(&observed, &file.metadata()?)
                    && same_reuse_file(
                        &observed,
                        &open_reuse_file(root, &expected.path)?.metadata()?,
                    ),
            )
        })();
        root.verify()?;
        match inspected {
            Ok(true) => Ok(Some(Self { file, observed })),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => Err(error),
            // No receiver bytes were touched: stale, partial, corrupt or
            // unavailable files may safely request ordinary network delivery.
            Ok(false) | Err(_) => Ok(None),
        }
    }

    fn verify(&self, root: &Parent, path: &str) -> io::Result<()> {
        root.verify()?;
        require(
            same_reuse_file(&self.observed, &self.file.metadata()?)
                && same_reuse_file(&self.observed, &open_reuse_file(root, path)?.metadata()?),
            "artifact reuse member changed after selection",
        )
    }
}

/// A fresh client-owned staging tree. Failed and interrupted transfers retain
/// their private staging paths; only an exact completed tree can be published.
pub(super) struct ReceivedTarget {
    parent: Parent,
    staging: PathBuf,
    receiver: ArtifactReceiver,
    sealed: Option<TreeInventory>,
    poisoned: bool,
    input_started: bool,
}

impl ReceivedTarget {
    #[cfg(test)]
    pub(super) fn new(private_parent: &Path, manifest: ArtifactManifest) -> io::Result<Self> {
        Self::new_cancellable(private_parent, manifest, &|| false)
    }

    pub(super) fn new_cancellable(
        private_parent: &Path,
        manifest: ArtifactManifest,
        stopped: &impl Fn() -> bool,
    ) -> io::Result<Self> {
        checkpoint(stopped)?;
        validate_manifest(&manifest)?;
        let parent = Parent::open(private_parent)?;
        // make_in chooses a fresh bounded random name; ArtifactReceiver creates
        // that directory exclusively. Keep it immediately, including on later
        // failure. Publication needs a sibling of the eventual destination.
        let staged = tempfile::Builder::new()
            .prefix(".rabs-target-staging-")
            .disable_cleanup(true)
            .make_in(&parent.path, |path| {
                ArtifactReceiver::create_cancellable_in(
                    path,
                    &parent.directory,
                    manifest.clone(),
                    stopped,
                )
            })?;
        let (receiver, staging) = staged.keep().map_err(|error| error.error)?;
        parent.verify()?;
        checkpoint(stopped)?;
        Ok(Self {
            parent,
            staging,
            receiver,
            sealed: None,
            poisoned: false,
            input_started: false,
        })
    }

    pub(super) fn manifest(&self) -> &ArtifactManifest {
        self.receiver.manifest()
    }

    /// A cursor for this live receiver only; reconnect never adopts a partial
    /// directory by its name. Full byte and namespace sealing remains mandatory.
    pub(super) fn resume_cursor(&self) -> io::Result<(usize, u64)> {
        require(!self.poisoned, "remote target receiver is failed")?;
        self.parent.verify()?;
        self.receiver.resume_cursor()
    }

    /// Reuse complete old files as untrusted byte hints before receiving any
    /// network payload. Return the strictly ordered nonempty manifest indices
    /// still requiring download. Empty files already belong to the new receiver.
    ///
    /// Only names in this newly verified manifest are inspected. Old modes and
    /// unrelated files do not affect the new tree; each selected member is
    /// copied or safely reflinked into an independent inode; the ordinary seal
    /// chooses its mode and verifies the actual destination bytes.
    /// A missing or unavailable old root/member, partial file, or hash mismatch
    /// requests ordinary transfer. Once an import is chosen, mutation, I/O
    /// failure or cancellation poisons this receiver rather than repairing it.
    pub(super) fn reuse_from(
        &mut self,
        previous: &Path,
        stopped: &impl Fn() -> bool,
    ) -> io::Result<Vec<u16>> {
        require(
            !self.poisoned && self.sealed.is_none() && !self.input_started,
            "artifact reuse must precede all other receiver input",
        )?;
        self.input_started = true;
        // Fence external cancellation callbacks and partial imports alike.
        self.poisoned = true;
        let result = (|| {
            checkpoint(stopped)?;
            self.parent.verify()?;
            require(
                super::plain_absolute(previous)
                    && !previous.starts_with(&self.staging)
                    && !self.staging.starts_with(previous),
                "artifact reuse root overlaps the new staging tree or is not an ordinary absolute path",
            )?;
            let root = match Parent::open(previous) {
                Ok(root) => Some(root),
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied
                    ) =>
                {
                    None
                }
                Err(error) => return Err(error),
            };
            let mut missing = Vec::new();
            let mut buffer = vec![0_u8; MAX_SOURCE_CHUNK];
            for index in 0..self.receiver.manifest().files().len() {
                checkpoint(stopped)?;
                // Clone one bounded path, not a second entire target manifest.
                let expected = self.receiver.manifest().files()[index].clone();
                if expected.len == 0 {
                    continue;
                }
                let hint = match &root {
                    Some(root) => ReuseFile::inspect(root, &expected, &mut buffer, stopped)?,
                    None => None,
                };
                if let (Some(root), Some(mut hint)) = (&root, hint) {
                    self.parent.verify()?;
                    hint.verify(root, &expected.path)?;
                    self.receiver.import_file_with_cloner(
                        &expected.path,
                        &mut hint.file,
                        stopped,
                        rabs_cas::materialization::try_verified_reflink,
                    )?;
                    hint.verify(root, &expected.path)?;
                    self.parent.verify()?;
                } else {
                    missing.push(
                        u16::try_from(index)
                            .map_err(|_| invalid("artifact index exceeds its wire bound"))?,
                    );
                }
            }
            if let Some(root) = &root {
                root.verify()?;
            }
            self.parent.verify()?;
            checkpoint(stopped)?;
            Ok(missing)
        })();
        if result.is_ok() {
            self.poisoned = false;
        }
        result
    }

    pub(super) fn write_chunk(
        &mut self,
        path: &str,
        offset: u64,
        bytes: &[u8],
        sha256: [u8; 32],
    ) -> io::Result<u64> {
        require(
            !self.poisoned && self.sealed.is_none(),
            "remote target receiver is failed or already sealed",
        )?;
        self.input_started = true;
        self.parent.verify()?;
        self.receiver.write_chunk(path, offset, bytes, sha256)
    }

    pub(super) fn seal(&mut self, stopped: &impl Fn() -> bool) -> io::Result<()> {
        require(!self.poisoned, "remote target receiver is failed")?;
        let result = (|| {
            checkpoint(stopped)?;
            self.parent.verify()?;
            if let Some(tree) = &self.sealed {
                // ArtifactReceiver's already-sealed path is intentionally cheap;
                // an artifact delivery must still recheck every retained byte.
                return verify_tree(tree, self.receiver.manifest(), stopped, true);
            }
            self.receiver.seal_cancellable(stopped)?;
            let tree =
                TreeInventory::scan_complete_artifacts(&self.staging, MAX_ARTIFACT_BYTES, stopped)?;
            verify_tree(&tree, self.receiver.manifest(), stopped, true)?;
            self.parent.directory.sync_all()?;
            self.parent.verify()?;
            checkpoint(stopped)?;
            self.sealed = Some(tree);
            Ok(())
        })();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    /// Publish only beside this retained parent, never merge or overwrite.
    /// A post-rename sync error can leave the destination installed; return that
    /// uncertainty without deleting it or authorizing execution to run again.
    pub(super) fn publish(
        mut self,
        destination: &Path,
        stopped: &impl Fn() -> bool,
    ) -> io::Result<InstalledTarget> {
        checkpoint(stopped)?;
        require(!self.poisoned, "remote target receiver is failed")?;
        require(
            super::plain_absolute(destination)
                && destination.parent() == Some(self.parent.path.as_path())
                && destination != self.staging,
            "remote target destination must be a distinct ordinary sibling",
        )?;
        let tree = self
            .sealed
            .as_ref()
            .ok_or_else(|| invalid("remote target is not sealed"))?;
        self.parent.verify()?;
        verify_tree(tree, self.receiver.manifest(), stopped, true)?;
        self.parent.verify()?;
        checkpoint(stopped)?;
        // The pathname-based publication helper opens its parent anew. This
        // receiver already owns that directory: keep both names relative to
        // the retained descriptor, including if an ancestor was renamed after
        // the final cancellation checkpoint. Confirm the exact sealed source
        // before the atomic rename and the installed inode afterward.
        let publication = (|| -> io::Result<(File, fs::Metadata)> {
            use rustix::fs::{Mode, OFlags, RenameFlags, openat, renameat_with};
            let source_name = self
                .staging
                .file_name()
                .ok_or_else(|| invalid("remote target staging name is absent"))?;
            let destination_name = destination
                .file_name()
                .ok_or_else(|| invalid("remote target destination name is absent"))?;
            let expected = tree.open_directory("")?.metadata()?;
            let open_named = |name: &std::ffi::OsStr| -> io::Result<File> {
                Ok(File::from(openat(
                    &self.parent.directory,
                    name,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )?))
            };
            let source = open_named(source_name)?;
            let source_metadata = source.metadata()?;
            require(
                same_directory_state(&source_metadata, &expected)
                    && (source_metadata.ctime(), source_metadata.ctime_nsec())
                        == (expected.ctime(), expected.ctime_nsec()),
                "remote target staging name no longer identifies the sealed tree",
            )?;
            renameat_with(
                &self.parent.directory,
                source_name,
                &self.parent.directory,
                destination_name,
                RenameFlags::NOREPLACE,
            )?;
            let directory = open_named(destination_name)?;
            let installed = directory.metadata()?;
            require(
                same_directory_state(&installed, &expected),
                "remote target installation identity is uncertain",
            )?;
            self.parent.directory.sync_all()?;
            self.parent.verify()?;
            Ok((directory, installed))
        })();
        let (directory, installed) = publication.map_err(|error| {
            io::Error::new(
                error.kind(),
                format!(
                    "remote target publication failed; verify destination before retrying; staging={}, destination={}: {error}",
                    self.staging.display(),
                    destination.display(),
                ),
            )
        })?;
        Ok(InstalledTarget {
            parent: self.parent,
            destination: destination.to_path_buf(),
            directory,
            installed,
            tree: self
                .sealed
                .take()
                .expect("publication requires a sealed tree"),
            manifest: self.receiver.manifest().clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::os::unix::fs::{DirBuilderExt, symlink};

    fn private() -> tempfile::TempDir {
        tempfile::Builder::new()
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap()
    }

    fn target(parent: &Path) -> PathBuf {
        let path = parent.join("target");
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        path
    }

    fn file(path: &str, bytes: &[u8], executable: bool) -> SourceFile {
        SourceFile {
            path: path.to_owned(),
            len: bytes.len() as u64,
            sha256: Sha256::digest(bytes).into(),
            executable,
        }
    }

    fn receive(parent: &Path, captured: &CapturedTarget) -> ReceivedTarget {
        let mut received = ReceivedTarget::new(parent, captured.manifest().clone()).unwrap();
        for expected in captured.manifest().files() {
            let mut offset = 0;
            while offset < expected.len {
                let bytes = captured
                    .read_chunk(&expected.path, offset, MAX_SOURCE_CHUNK, &|| false)
                    .unwrap();
                offset = received
                    .write_chunk(
                        &expected.path,
                        offset,
                        &bytes,
                        Sha256::digest(&bytes).into(),
                    )
                    .unwrap();
            }
        }
        captured.verify(&|| false).unwrap();
        received
    }

    #[test]
    fn artifact_reuse_copies_only_verified_complete_members_with_new_modes() {
        let old_parent = private();
        let old = target(old_parent.path());
        fs::create_dir(old.join("nested")).unwrap();
        let binary: Vec<_> = (0..MAX_SOURCE_CHUNK * 2 + 17)
            .map(|index| (index % 251) as u8)
            .collect();
        fs::write(old.join("nested/keep"), &binary).unwrap();
        fs::set_permissions(old.join("nested/keep"), fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(old.join("program"), b"executable bytes").unwrap();
        fs::set_permissions(old.join("program"), fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(old.join("changed"), b"wrong bytes").unwrap();
        fs::write(old.join("partial"), b"part").unwrap();
        fs::write(old.join("removed"), b"not in the new result").unwrap();
        // Unrelated unsupported old members are not traversed or interpreted.
        symlink("does-not-exist", old.join("unrelated-link")).unwrap();
        let manifest = ArtifactManifest::new(vec![
            file("changed", b"right bytes", false),
            file("empty", b"", true),
            file("missing", b"new file", false),
            file("nested/keep", &binary, true),
            file("partial", b"partial bytes", false),
            file("program", b"executable bytes", false),
        ])
        .unwrap();
        let parent = private();
        let mut received = ReceivedTarget::new(parent.path(), manifest.clone()).unwrap();
        let missing = received.reuse_from(&old, &|| false).unwrap();
        assert_eq!(missing, vec![0, 2, 4]);
        for index in missing {
            let expected = &manifest.files()[usize::from(index)];
            let bytes: &[u8] = match expected.path.as_str() {
                "changed" => b"right bytes",
                "missing" => b"new file",
                "partial" => b"partial bytes",
                _ => panic!("unexpected download"),
            };
            received
                .write_chunk(&expected.path, 0, bytes, Sha256::digest(bytes).into())
                .unwrap();
        }
        let staged = fs::metadata(received.staging.join("nested/keep")).unwrap();
        let prior = fs::metadata(old.join("nested/keep")).unwrap();
        assert_ne!((staged.dev(), staged.ino()), (prior.dev(), prior.ino()));
        assert_eq!(staged.nlink(), 1);
        // The prior tree retains no write alias into the new receiver.
        fs::write(old.join("nested/keep"), b"changed after independent import").unwrap();
        received.seal(&|| false).unwrap();
        let destination = parent.path().join("completed");
        received.publish(&destination, &|| false).unwrap();
        assert_eq!(fs::read(destination.join("nested/keep")).unwrap(), binary);
        assert_eq!(
            fs::read(destination.join("changed")).unwrap(),
            b"right bytes"
        );
        assert_eq!(
            fs::read(destination.join("partial")).unwrap(),
            b"partial bytes"
        );
        assert_eq!(fs::metadata(destination.join("empty")).unwrap().len(), 0);
        assert_eq!(
            fs::metadata(destination.join("nested/keep"))
                .unwrap()
                .mode()
                & 0o7777,
            0o555,
        );
        assert_eq!(
            fs::metadata(destination.join("program")).unwrap().mode() & 0o7777,
            0o444,
        );
        assert!(!destination.join("removed").exists());
        assert!(!destination.join("unrelated-link").exists());
        assert_eq!(fs::read(old.join("changed")).unwrap(), b"wrong bytes");
        assert_eq!(fs::read(old.join("partial")).unwrap(), b"part");
    }

    #[test]
    fn installed_receipt_keeps_reused_bytes_independent_and_revalidates_the_new_tree() {
        let old_parent = private();
        let old = target(old_parent.path());
        let retained = vec![0x4d; MAX_SOURCE_CHUNK + 19];
        fs::write(old.join("a-reused"), &retained).unwrap();
        let parent = private();
        let fresh = b"new version";
        let manifest = ArtifactManifest::new(vec![
            file("a-reused", &retained, true),
            file("z-fresh", fresh, false),
        ])
        .unwrap();
        let mut received = ReceivedTarget::new(parent.path(), manifest.clone()).unwrap();
        assert_eq!(received.reuse_from(&old, &|| false).unwrap(), vec![1]);
        assert_eq!(received.resume_cursor().unwrap(), (1, 0));
        received
            .write_chunk(
                "z-fresh",
                0,
                &fresh[..4],
                Sha256::digest(&fresh[..4]).into(),
            )
            .unwrap();
        assert_eq!(received.resume_cursor().unwrap(), (1, 4));
        received
            .write_chunk(
                "z-fresh",
                4,
                &fresh[4..],
                Sha256::digest(&fresh[4..]).into(),
            )
            .unwrap();
        received.seal(&|| false).unwrap();
        let destination = parent.path().join("completed");
        let installed = received.publish(&destination, &|| false).unwrap();
        assert_eq!(installed.manifest(), &manifest);
        let prior = fs::metadata(old.join("a-reused")).unwrap();
        let current = fs::metadata(destination.join("a-reused")).unwrap();
        assert_ne!((prior.dev(), prior.ino()), (current.dev(), current.ino()));
        assert_eq!(current.mode() & 0o7777, 0o555);

        // The source of a verified import retains no installed write authority.
        fs::write(old.join("a-reused"), b"changed old output").unwrap();
        installed.verify(&|| false).unwrap();
        assert_eq!(fs::read(destination.join("a-reused")).unwrap(), retained);

        // Even an identical-byte replacement of the installed member loses
        // the retained generation, so a resumed acknowledgment must refuse.
        fs::rename(
            destination.join("a-reused"),
            parent.path().join("original-installed-member"),
        )
        .unwrap();
        fs::write(destination.join("a-reused"), &retained).unwrap();
        fs::set_permissions(
            destination.join("a-reused"),
            fs::Permissions::from_mode(0o555),
        )
        .unwrap();
        assert!(installed.verify(&|| false).is_err());
    }

    #[test]
    fn artifact_reuse_never_reads_links_special_files_or_undeclared_names() {
        let old_parent = private();
        let old = target(old_parent.path());
        let outside = private();
        let bytes = b"complete prior artifact";
        fs::write(outside.path().join("outside"), bytes).unwrap();
        fs::hard_link(outside.path().join("outside"), old.join("hard")).unwrap();
        symlink(outside.path().join("outside"), old.join("link")).unwrap();
        symlink(outside.path(), old.join("nested")).unwrap();
        rustix::fs::mkfifoat(
            rustix::fs::CWD,
            old.join("pipe"),
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        )
        .unwrap();
        fs::create_dir(old.join("directory")).unwrap();
        let manifest = ArtifactManifest::new(vec![
            file("directory", bytes, false),
            file("hard", bytes, false),
            file("link", bytes, false),
            file("nested/outside", bytes, false),
            file("pipe", bytes, false),
        ])
        .unwrap();
        let parent = private();
        let mut received = ReceivedTarget::new(parent.path(), manifest.clone()).unwrap();
        assert_eq!(
            received.reuse_from(&old, &|| false).unwrap(),
            vec![0, 1, 2, 3, 4],
        );
        for expected in manifest.files() {
            received
                .write_chunk(&expected.path, 0, bytes, Sha256::digest(bytes).into())
                .unwrap();
        }
        received.seal(&|| false).unwrap();
        let destination = parent.path().join("completed");
        received.publish(&destination, &|| false).unwrap();
        for expected in manifest.files() {
            let output = destination.join(&expected.path);
            assert!(fs::symlink_metadata(&output).unwrap().is_file());
            assert_eq!(fs::metadata(&output).unwrap().nlink(), 1);
            assert_eq!(fs::read(output).unwrap(), bytes);
        }
        assert_eq!(fs::read(outside.path().join("outside")).unwrap(), bytes);
    }

    #[test]
    fn artifact_reuse_missing_root_downloads_every_nonempty_member() {
        let parent = private();
        let old_parent = private();
        let manifest = ArtifactManifest::new(vec![
            file("data", b"bytes", false),
            file("empty", b"", false),
        ])
        .unwrap();
        let mut received = ReceivedTarget::new(parent.path(), manifest).unwrap();
        assert_eq!(
            received
                .reuse_from(&old_parent.path().join("gone"), &|| false)
                .unwrap(),
            vec![0],
        );
        received
            .write_chunk("data", 0, b"bytes", Sha256::digest(b"bytes").into())
            .unwrap();
        received.seal(&|| false).unwrap();
    }

    #[test]
    fn artifact_reuse_refuses_unsafe_roots_and_cannot_run_after_input() {
        let old_parent = private();
        let old = target(old_parent.path());
        fs::write(old.join("data"), b"bytes").unwrap();
        symlink(&old, old_parent.path().join("linked")).unwrap();
        let public = old_parent.path().join("public");
        fs::DirBuilder::new().mode(0o700).create(&public).unwrap();
        fs::set_permissions(&public, fs::Permissions::from_mode(0o755)).unwrap();
        let manifest = ArtifactManifest::new(vec![file("data", b"bytes", false)]).unwrap();
        for kind in ["linked", "public", "overlap", "relative"] {
            let parent = private();
            let mut received = ReceivedTarget::new(parent.path(), manifest.clone()).unwrap();
            let previous = match kind {
                "overlap" => parent.path().to_path_buf(),
                "relative" => PathBuf::from("relative"),
                _ => old_parent.path().join(kind),
            };
            assert!(received.reuse_from(&previous, &|| false).is_err(), "{kind}");
            assert!(received.seal(&|| false).is_err(), "{kind}");
        }
        for network_first in [true, false] {
            let parent = private();
            let mut received = ReceivedTarget::new(parent.path(), manifest.clone()).unwrap();
            if network_first {
                received
                    .write_chunk("data", 0, b"by", Sha256::digest(b"by").into())
                    .unwrap();
            } else {
                assert!(received.reuse_from(&old, &|| false).unwrap().is_empty());
            }
            assert!(received.reuse_from(&old, &|| false).is_err());
        }
    }

    #[test]
    fn artifact_reuse_cancelled_during_inspection_never_installs_or_repairs() {
        let old_parent = private();
        let old = target(old_parent.path());
        let bytes = vec![b'x'; MAX_SOURCE_CHUNK * 3 + 1];
        fs::write(old.join("data"), &bytes).unwrap();
        let manifest = ArtifactManifest::new(vec![file("data", &bytes, false)]).unwrap();
        let parent = private();
        let mut received = ReceivedTarget::new(parent.path(), manifest).unwrap();
        let seen = Cell::new(0);
        let error = received
            .reuse_from(&old, &|| {
                seen.set(seen.get() + 1);
                seen.get() == 5
            })
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
        assert_eq!(
            fs::metadata(received.staging.join("data")).unwrap().len(),
            0
        );
        assert!(received.seal(&|| false).is_err());
        assert!(
            received
                .publish(&parent.path().join("completed"), &|| false)
                .is_err(),
        );
        assert!(!parent.path().join("completed").exists());
        assert_eq!(fs::read(old.join("data")).unwrap(), bytes);
    }

    #[test]
    fn artifact_reuse_changes_or_cancellation_during_import_poison_the_receiver() {
        for change in ["bytes", "member", "source-root", "target-parent", "cancel"] {
            let old_parent = private();
            let old = target(old_parent.path());
            let bytes = vec![b'x'; MAX_SOURCE_CHUNK * 2 + 17];
            fs::write(old.join("data"), &bytes).unwrap();
            let manifest = ArtifactManifest::new(vec![file("data", &bytes, false)]).unwrap();
            let outer = private();
            let parent = target(outer.path());
            let mut received = ReceivedTarget::new(&parent, manifest).unwrap();
            let staged_file = received.staging.join("data");
            let changed = Cell::new(false);
            let result = received.reuse_from(&old, &|| {
                // Real copy progress identifies the post-selection boundary;
                // hashing prior hints never writes to this new file.
                if !changed.get()
                    && fs::metadata(&staged_file).is_ok_and(|metadata| metadata.len() != 0)
                {
                    changed.set(true);
                    match change {
                        "bytes" => fs::write(old.join("data"), vec![b'y'; bytes.len()]).unwrap(),
                        "member" => {
                            fs::rename(old.join("data"), old.join("original-data")).unwrap();
                            fs::write(old.join("data"), &bytes).unwrap();
                        }
                        "source-root" => {
                            fs::rename(&old, old_parent.path().join("original-root")).unwrap();
                            fs::DirBuilder::new().mode(0o700).create(&old).unwrap();
                            fs::write(old.join("data"), &bytes).unwrap();
                        }
                        "target-parent" => {
                            fs::rename(&parent, outer.path().join("original-parent")).unwrap();
                            fs::DirBuilder::new().mode(0o700).create(&parent).unwrap();
                        }
                        "cancel" => return true,
                        _ => unreachable!(),
                    }
                }
                false
            });
            assert!(changed.get(), "import never started: {change}");
            assert!(result.is_err(), "{change}");
            assert!(received.seal(&|| false).is_err(), "{change}");
            let destination = parent.join("completed");
            assert!(
                received.publish(&destination, &|| false).is_err(),
                "{change}"
            );
            assert!(!destination.exists(), "{change}");
        }
    }

    #[test]
    fn independent_binary_empty_and_executable_files_roundtrip_atomically() {
        let server = private();
        let original = target(server.path());
        fs::create_dir(original.join("nested")).unwrap();
        let bytes: Vec<_> = (0..MAX_SOURCE_CHUNK * 2 + 17)
            .map(|index| (index % 251) as u8)
            .collect();
        fs::write(original.join("nested/data"), &bytes).unwrap();
        fs::write(original.join("empty"), []).unwrap();
        fs::write(original.join("program"), b"#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(original.join("program"), fs::Permissions::from_mode(0o751)).unwrap();
        fs::hard_link(original.join("nested/data"), original.join("alias")).unwrap();
        fs::create_dir(original.join("empty-directory")).unwrap();
        let captured = CapturedTarget::capture(&original, &|| false).unwrap();
        // The independent captured generation survives later original edits.
        fs::write(original.join("nested/data"), b"changed after capture").unwrap();
        captured.verify(&|| false).unwrap();
        let client = private();
        let mut received = receive(client.path(), &captured);
        let destination = client.path().join("completed");
        assert!(!destination.exists());
        received.seal(&|| false).unwrap();
        assert!(!destination.exists());
        let installed = received.publish(&destination, &|| false).unwrap();
        assert_eq!(installed.destination, destination);
        assert_eq!(installed.manifest(), captured.manifest());
        installed.verify(&|| false).unwrap();
        assert_eq!(fs::read(destination.join("nested/data")).unwrap(), bytes);
        assert_eq!(fs::read(destination.join("alias")).unwrap(), bytes);
        assert!(fs::read(destination.join("empty")).unwrap().is_empty());
        assert!(!destination.join("empty-directory").exists());
        let data = fs::metadata(destination.join("nested/data")).unwrap();
        let alias = fs::metadata(destination.join("alias")).unwrap();
        assert_eq!(data.mode() & 0o7777, 0o444);
        assert_eq!(data.nlink(), 1);
        assert_ne!((data.dev(), data.ino()), (alias.dev(), alias.ino()));
        assert_eq!(
            fs::metadata(destination.join("program")).unwrap().mode() & 0o7777,
            0o555,
        );
        assert!(original.exists());
    }

    #[test]
    fn partial_artifact_cursor_retains_the_exact_receiver_across_delivery_sessions() {
        let parent = private();
        let bytes = vec![0x63; MAX_SOURCE_CHUNK * 2 + 23];
        let manifest = ArtifactManifest::new(vec![
            file("a-empty", b"", false),
            file("bin/program", &bytes, true),
            file("version", b"v1", false),
        ])
        .unwrap();
        let mut received = ReceivedTarget::new(parent.path(), manifest.clone()).unwrap();
        assert_eq!(received.manifest(), &manifest);
        assert_eq!(received.resume_cursor().unwrap(), (1, 0));
        received
            .write_chunk(
                "bin/program",
                0,
                &bytes[..MAX_SOURCE_CHUNK],
                Sha256::digest(&bytes[..MAX_SOURCE_CHUNK]).into(),
            )
            .unwrap();
        assert_eq!(
            received.resume_cursor().unwrap(),
            (1, MAX_SOURCE_CHUNK as u64)
        );
        let staging = received.staging.clone();
        // A replacement transport keeps the same receiver and its hash state.
        // No retained pathname is reopened as a new receiver or trusted result.
        let (first, mut offset) = received.resume_cursor().unwrap();
        assert_eq!(first, 1);
        while offset < bytes.len() as u64 {
            let end = (offset as usize + MAX_SOURCE_CHUNK).min(bytes.len());
            let chunk = &bytes[offset as usize..end];
            offset = received
                .write_chunk("bin/program", offset, chunk, Sha256::digest(chunk).into())
                .unwrap();
        }
        assert_eq!(received.resume_cursor().unwrap(), (2, 0));
        received
            .write_chunk("version", 0, b"v1", Sha256::digest(b"v1").into())
            .unwrap();
        assert_eq!(received.resume_cursor().unwrap(), (3, 0));
        assert_eq!(received.staging, staging);
        received.seal(&|| false).unwrap();
        let installed = received
            .publish(&parent.path().join("completed"), &|| false)
            .unwrap();
        installed.verify(&|| false).unwrap();
        assert_eq!(
            fs::read(parent.path().join("completed/bin/program")).unwrap(),
            bytes
        );
    }

    #[test]
    fn installed_receipt_survives_a_lost_acknowledgment_without_republication() {
        let parent = private();
        let bytes = b"complete installed artifact";
        let manifest = ArtifactManifest::new(vec![file("data", bytes, false)]).unwrap();
        let mut received = ReceivedTarget::new(parent.path(), manifest.clone()).unwrap();
        received
            .write_chunk("data", 0, bytes, Sha256::digest(bytes).into())
            .unwrap();
        received.seal(&|| false).unwrap();
        let destination = parent.path().join("completed");
        let installed = received.publish(&destination, &|| false).unwrap();
        let identity = fs::metadata(&destination).unwrap();
        installed.verify(&|| false).unwrap();
        assert_eq!(
            installed.verify(&|| true).unwrap_err().kind(),
            io::ErrorKind::Interrupted
        );
        installed.verify(&|| false).unwrap();
        assert_eq!(installed.manifest(), &manifest);
        let current = fs::metadata(&destination).unwrap();
        assert_eq!(
            (identity.dev(), identity.ino()),
            (current.dev(), current.ino())
        );
        assert_eq!(fs::read(destination.join("data")).unwrap(), bytes);
    }

    #[test]
    fn installed_receipt_refuses_byte_mode_member_and_namespace_replacement() {
        for mutation in [
            "bytes",
            "mode",
            "extra",
            "empty-directory",
            "missing",
            "file-replacement",
            "directory-replacement",
            "root",
            "parent",
            "ancestor",
        ] {
            let outer = private();
            let ancestor = outer.path().join("ancestor");
            let parent = ancestor.join("parent");
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(&parent)
                .unwrap();
            let bytes = b"complete installed artifact";
            let manifest = ArtifactManifest::new(vec![file("nested/data", bytes, false)]).unwrap();
            let mut received = ReceivedTarget::new(&parent, manifest).unwrap();
            received
                .write_chunk("nested/data", 0, bytes, Sha256::digest(bytes).into())
                .unwrap();
            received.seal(&|| false).unwrap();
            let destination = parent.join("completed");
            let installed = received.publish(&destination, &|| false).unwrap();
            match mutation {
                "bytes" => {
                    fs::set_permissions(
                        destination.join("nested/data"),
                        fs::Permissions::from_mode(0o600),
                    )
                    .unwrap();
                    fs::write(
                        destination.join("nested/data"),
                        b"changed installed artifact",
                    )
                    .unwrap();
                    fs::set_permissions(
                        destination.join("nested/data"),
                        fs::Permissions::from_mode(0o444),
                    )
                    .unwrap();
                }
                "mode" => fs::set_permissions(
                    destination.join("nested/data"),
                    fs::Permissions::from_mode(0o555),
                )
                .unwrap(),
                "extra" => fs::write(destination.join("extra"), b"unexpected").unwrap(),
                "empty-directory" => fs::create_dir(destination.join("extra")).unwrap(),
                "missing" => {
                    fs::rename(
                        destination.join("nested/data"),
                        parent.join("original-file"),
                    )
                    .unwrap();
                }
                "file-replacement" => {
                    fs::rename(
                        destination.join("nested/data"),
                        parent.join("original-file"),
                    )
                    .unwrap();
                    fs::write(destination.join("nested/data"), bytes).unwrap();
                    fs::set_permissions(
                        destination.join("nested/data"),
                        fs::Permissions::from_mode(0o444),
                    )
                    .unwrap();
                }
                "directory-replacement" => {
                    fs::rename(destination.join("nested"), parent.join("original-nested")).unwrap();
                    fs::create_dir(destination.join("nested")).unwrap();
                    fs::rename(
                        parent.join("original-nested/data"),
                        destination.join("nested/data"),
                    )
                    .unwrap();
                }
                "root" => {
                    fs::rename(&destination, parent.join("original-installed")).unwrap();
                    fs::DirBuilder::new()
                        .mode(0o700)
                        .create(&destination)
                        .unwrap();
                }
                "parent" => {
                    fs::rename(&parent, ancestor.join("original-parent")).unwrap();
                    fs::DirBuilder::new().mode(0o700).create(&parent).unwrap();
                }
                "ancestor" => {
                    let old = outer.path().join("original-ancestor");
                    fs::rename(&ancestor, &old).unwrap();
                    fs::DirBuilder::new().mode(0o700).create(&ancestor).unwrap();
                    // The immediate parent and installed tree retain their
                    // inodes. Only the previously retained ancestor changes.
                    fs::rename(old.join("parent"), &parent).unwrap();
                }
                _ => unreachable!(),
            }
            assert!(installed.verify(&|| false).is_err(), "{mutation}");
        }
    }

    #[test]
    fn complete_target_above_source_file_limit_roundtrips_without_dropping_members() {
        let server = private();
        let original = target(server.path());
        for index in 0..=rabs_sandbox::source_transfer::MAX_SOURCE_FILES {
            fs::write(original.join(format!("member-{index:05}")), []).unwrap();
        }
        let captured = CapturedTarget::capture(&original, &|| false).unwrap();
        assert_eq!(captured.manifest().files().len(), 4097);
        let client = private();
        let mut received = receive(client.path(), &captured);
        received.seal(&|| false).unwrap();
        let destination = client.path().join("completed");
        received.publish(&destination, &|| false).unwrap();
        assert_eq!(fs::read_dir(destination).unwrap().count(), 4097);
        assert_eq!(fs::read_dir(original).unwrap().count(), 4097);
    }

    #[test]
    #[ignore = "streams and rehashes more than 512 MiB; needs 2 GiB of disk-backed scratch"]
    fn artifact_larger_than_source_byte_limit_streams_with_bounded_buffers() {
        let server = private();
        let original = target(server.path());
        let length = rabs_sandbox::source_transfer::MAX_SOURCE_BYTES + MAX_SOURCE_CHUNK as u64 + 17;
        let mut input = File::create(original.join("large.rlib")).unwrap();
        input.set_len(length).unwrap();
        for offset in [0, length / 2, length - 4] {
            input.seek(SeekFrom::Start(offset)).unwrap();
            input.write_all(b"RABS").unwrap();
        }
        input.sync_all().unwrap();
        drop(input);
        let captured = CapturedTarget::capture(&original, &|| false).unwrap();
        assert_eq!(captured.manifest().total_bytes(), length);
        let client = private();
        let mut received = receive(client.path(), &captured);
        received.seal(&|| false).unwrap();
        let destination = client.path().join("completed");
        received.publish(&destination, &|| false).unwrap();
        let mut output = File::open(destination.join("large.rlib")).unwrap();
        assert_eq!(output.metadata().unwrap().len(), length);
        for offset in [0, length / 2, length - 4] {
            output.seek(SeekFrom::Start(offset)).unwrap();
            let mut marker = [0; 4];
            output.read_exact(&mut marker).unwrap();
            assert_eq!(&marker, b"RABS");
        }
        let mut forbidden = [0_u8; 1];
        assert_eq!(output.read(&mut forbidden).unwrap(), 0);
    }

    #[test]
    fn receiver_creation_observes_cancellation_between_manifest_members() {
        let parent = private();
        let manifest = ArtifactManifest::new(
            (0..1024)
                .map(|index| file(&format!("member-{index:04}"), b"", false))
                .collect(),
        )
        .unwrap();
        let observed = Cell::new(false);
        let result = ReceivedTarget::new_cancellable(parent.path(), manifest, &|| {
            let created = fs::read_dir(parent.path())
                .unwrap()
                .flatten()
                .any(|entry| fs::read_dir(entry.path()).is_ok_and(|entries| entries.count() != 0));
            observed.set(observed.get() || created);
            created
        });
        assert!(
            observed.get(),
            "cancellation was never checked after the first member"
        );
        assert!(matches!(result, Err(error) if error.kind() == io::ErrorKind::Interrupted));
        let staging = fs::read_dir(parent.path())
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let created = fs::read_dir(staging).unwrap().count();
        assert!((1..1024).contains(&created));
        assert!(!parent.path().join("completed").exists());
    }

    #[test]
    fn receiver_creation_never_adopts_a_replaced_parent_after_its_callback() {
        let container = private();
        let parent = container.path().join("parent");
        fs::DirBuilder::new().mode(0o700).create(&parent).unwrap();
        let retained = container.path().join("retained-parent");
        let checkpoints = Cell::new(0);
        let replaced = Cell::new(false);
        let manifest = ArtifactManifest::new(vec![file("empty", b"", false)]).unwrap();
        let result = ReceivedTarget::new_cancellable(&parent, manifest, &|| {
            checkpoints.set(checkpoints.get() + 1);
            // The first checkpoint precedes the outer retained Parent. The
            // next belongs to the inner receiver, after that custody exists.
            if checkpoints.get() == 2 {
                fs::rename(&parent, &retained).unwrap();
                fs::DirBuilder::new().mode(0o700).create(&parent).unwrap();
                replaced.set(true);
            }
            false
        });
        assert!(replaced.get());
        assert!(result.is_err());
        assert_eq!(fs::read_dir(&parent).unwrap().count(), 0);
        assert_eq!(fs::read_dir(&retained).unwrap().count(), 0);
    }

    #[test]
    fn capture_owner_creation_never_follows_a_replaced_parent_after_inventory() {
        let container = private();
        let parent = container.path().join("parent");
        fs::DirBuilder::new().mode(0o700).create(&parent).unwrap();
        let original = target(&parent);
        fs::write(original.join("data"), b"retained input").unwrap();
        let outside = container.path().join("outside");
        fs::DirBuilder::new().mode(0o700).create(&outside).unwrap();
        let retained = container.path().join("retained-parent");
        // Count the real scanner's checkpoints instead of depending on a
        // particular read_dir order or an implementation-specific count. Its
        // last checkpoint occurs after the completed inventory verification.
        let scan_checkpoints = Cell::new(0);
        TreeInventory::scan_complete_artifacts(&original, MAX_ARTIFACT_BYTES, &|| {
            scan_checkpoints.set(scan_checkpoints.get() + 1);
            false
        })
        .unwrap();
        let checkpoints = Cell::new(0);
        let replaced = Cell::new(false);
        let outside_was_modified = Cell::new(false);
        let result = CapturedTarget::capture(&original, &|| {
            checkpoints.set(checkpoints.get() + 1);
            outside_was_modified
                .set(outside_was_modified.get() || fs::read_dir(&outside).unwrap().count() != 0);
            if checkpoints.get() == scan_checkpoints.get() + 1 {
                fs::rename(&parent, &retained).unwrap();
                symlink(&outside, &parent).unwrap();
                replaced.set(true);
            }
            false
        });
        assert!(
            replaced.get(),
            "inventory did not reach its final checkpoint"
        );
        assert!(result.is_err());
        assert!(!outside_was_modified.get());
        assert_eq!(fs::read_dir(outside).unwrap().count(), 0);
        assert_eq!(fs::read_dir(&retained).unwrap().count(), 1);
        assert_eq!(
            fs::read(retained.join("target/data")).unwrap(),
            b"retained input"
        );
    }

    #[test]
    fn capture_refuses_links_special_files_and_oversized_trees_without_a_partial_offer() {
        for kind in [
            "symlink",
            "outside-hardlink",
            "fifo",
            "too-many",
            "too-large",
        ] {
            let parent = private();
            let original = target(parent.path());
            fs::write(original.join("ordinary"), b"kept").unwrap();
            match kind {
                "symlink" => symlink("ordinary", original.join("link")).unwrap(),
                "outside-hardlink" => {
                    fs::hard_link(original.join("ordinary"), parent.path().join("external"))
                        .unwrap();
                }
                "fifo" => {
                    rustix::fs::mknodat(
                        rustix::fs::CWD,
                        original.join("pipe"),
                        rustix::fs::FileType::Fifo,
                        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
                        0,
                    )
                    .unwrap();
                }
                "too-many" => {
                    for index in 0..rabs_sandbox::artifact_tree::MAX_ARTIFACT_FILES {
                        fs::write(original.join(format!("file-{index}")), []).unwrap();
                    }
                }
                "too-large" => {
                    File::create(original.join("large"))
                        .unwrap()
                        .set_len(MAX_ARTIFACT_BYTES + 1)
                        .unwrap();
                }
                _ => unreachable!(),
            }
            assert!(
                CapturedTarget::capture(&original, &|| false).is_err(),
                "{kind}"
            );
            assert_eq!(fs::read(original.join("ordinary")).unwrap(), b"kept");
            assert!(fs::read_dir(parent.path()).unwrap().all(|entry| {
                !entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with("rabs-target-capture-")
            }));
        }
    }

    #[test]
    fn capture_rechecks_the_original_inventory_after_real_copying() {
        let parent = private();
        let original = target(parent.path());
        fs::write(original.join("data"), vec![7; MAX_SOURCE_CHUNK + 19]).unwrap();
        let changed = Cell::new(false);
        let result = CapturedTarget::capture(&original, &|| {
            let copying = fs::read_dir(parent.path()).unwrap().any(|entry| {
                let entry = entry.unwrap();
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with("rabs-target-capture-")
                    && entry.path().join("files/data").exists()
            });
            if copying && !changed.replace(true) {
                fs::write(original.join("late-member"), b"not inventoried").unwrap();
            }
            false
        });
        assert!(changed.get());
        assert!(result.is_err());
    }

    #[test]
    fn capture_does_not_follow_a_replaced_staging_parent_into_an_outside_tree() {
        let parent = private();
        let original = target(parent.path());
        fs::create_dir(original.join("nested")).unwrap();
        fs::write(original.join("nested/a"), vec![7; MAX_SOURCE_CHUNK + 19]).unwrap();
        fs::write(original.join("nested/b"), b"second member").unwrap();
        let outside = parent.path().join("outside");
        fs::DirBuilder::new().mode(0o700).create(&outside).unwrap();
        fs::write(outside.join("sentinel"), b"untouched").unwrap();
        let replaced = Cell::new(false);
        let result = CapturedTarget::capture(&original, &|| {
            if !replaced.get() {
                for entry in fs::read_dir(parent.path()).unwrap().flatten() {
                    if !entry
                        .file_name()
                        .to_string_lossy()
                        .starts_with("rabs-target-capture-")
                    {
                        continue;
                    }
                    let nested = entry.path().join("files/nested");
                    if nested.join("a").exists() {
                        fs::rename(&nested, parent.path().join("retained-original-nested"))
                            .unwrap();
                        symlink(&outside, &nested).unwrap();
                        replaced.set(true);
                        break;
                    }
                }
            }
            false
        });
        assert!(replaced.get(), "the capture never reached its first member");
        assert!(result.is_err());
        assert_eq!(fs::read(outside.join("sentinel")).unwrap(), b"untouched");
        assert_eq!(fs::read_dir(outside).unwrap().count(), 1);
        assert_eq!(
            fs::read(original.join("nested/b")).unwrap(),
            b"second member"
        );
    }

    #[test]
    fn captured_snapshot_rejects_changed_bytes_modes_and_membership() {
        for mutation in ["bytes", "mode", "extra", "replacement"] {
            let parent = private();
            let original = target(parent.path());
            fs::write(original.join("data"), b"captured bytes").unwrap();
            let captured = CapturedTarget::capture(&original, &|| false).unwrap();
            let root = captured.owner.path().join("files");
            match mutation {
                "bytes" => {
                    fs::set_permissions(root.join("data"), fs::Permissions::from_mode(0o600))
                        .unwrap();
                    fs::write(root.join("data"), b"tampered bytes").unwrap();
                    fs::set_permissions(root.join("data"), fs::Permissions::from_mode(0o444))
                        .unwrap();
                }
                "mode" => {
                    fs::set_permissions(root.join("data"), fs::Permissions::from_mode(0o555))
                        .unwrap();
                }
                "extra" => fs::write(root.join("extra"), b"unexpected").unwrap(),
                "replacement" => {
                    fs::rename(&root, captured.owner.path().join("original-files")).unwrap();
                    fs::create_dir(&root).unwrap();
                    fs::write(root.join("data"), b"captured bytes").unwrap();
                }
                _ => unreachable!(),
            }
            assert!(captured.verify(&|| false).is_err(), "{mutation}");
            if matches!(mutation, "bytes" | "mode") {
                assert!(captured.read_chunk("data", 0, 16, &|| false).is_err());
            }
        }
    }

    #[test]
    fn artifact_manifest_refuses_path_collisions_before_creating_any_receiver() {
        for names in [["Dir/a", "dir/b"], ["FILE", "file"], ["A", "a/child"]] {
            let parent = private();
            let manifest = ArtifactManifest::new(
                names
                    .into_iter()
                    .map(|name| file(name, b"", false))
                    .collect(),
            );
            assert!(manifest.is_err());
            assert_eq!(fs::read_dir(parent.path()).unwrap().count(), 0);
        }
        assert!(ArtifactManifest::new(vec![file("../outside", b"", false)]).is_err());
    }

    #[test]
    fn malformed_ranges_do_not_write_and_exact_retries_preserve_sealing() {
        let parent = private();
        let bytes = b"complete bytes";
        let manifest = ArtifactManifest::new(vec![file("data", bytes, false)]).unwrap();
        let mut received = ReceivedTarget::new(parent.path(), manifest).unwrap();
        let hash = Sha256::digest(&bytes[..4]).into();
        assert!(
            received
                .write_chunk("../outside", 0, &bytes[..4], hash)
                .is_err()
        );
        assert!(received.write_chunk("data", 1, &bytes[..4], hash).is_err());
        assert!(
            received
                .write_chunk("data", 0, &bytes[..4], [0; 32])
                .is_err()
        );
        assert_eq!(
            fs::metadata(received.staging.join("data")).unwrap().len(),
            0
        );
        assert_eq!(
            received.write_chunk("data", 0, &bytes[..4], hash).unwrap(),
            4
        );
        assert_eq!(
            received.write_chunk("data", 0, &bytes[..4], hash).unwrap(),
            4
        );
        received
            .write_chunk("data", 4, &bytes[4..], Sha256::digest(&bytes[4..]).into())
            .unwrap();
        received.seal(&|| false).unwrap();
        assert!(received.write_chunk("data", 0, &bytes[..4], hash).is_err());
        let destination = parent.path().join("completed");
        received.publish(&destination, &|| false).unwrap();
        assert_eq!(fs::read(destination.join("data")).unwrap(), bytes);
    }

    #[test]
    fn seal_rehashes_received_bytes_and_failure_cannot_be_repaired_into_success() {
        let parent = private();
        let bytes = b"complete bytes";
        let manifest = ArtifactManifest::new(vec![file("data", bytes, false)]).unwrap();
        let mut received = ReceivedTarget::new(parent.path(), manifest).unwrap();
        received
            .write_chunk("data", 0, bytes, Sha256::digest(bytes).into())
            .unwrap();
        fs::write(received.staging.join("data"), b"tampered bytes").unwrap();
        assert!(received.seal(&|| false).is_err());
        fs::write(received.staging.join("data"), bytes).unwrap();
        assert!(received.seal(&|| false).is_err());
        let destination = parent.path().join("completed");
        assert!(received.publish(&destination, &|| false).is_err());
        assert!(!destination.exists());
    }

    #[test]
    fn publication_rechecks_sealed_bytes_inventory_and_parent_identity() {
        for mutation in ["bytes", "extra", "empty-directory", "root", "parent"] {
            let outer = private();
            let parent = target(outer.path());
            let bytes = b"complete bytes";
            let manifest = ArtifactManifest::new(vec![file("data", bytes, false)]).unwrap();
            let mut received = ReceivedTarget::new(&parent, manifest).unwrap();
            received
                .write_chunk("data", 0, bytes, Sha256::digest(bytes).into())
                .unwrap();
            received.seal(&|| false).unwrap();
            match mutation {
                "bytes" => {
                    fs::set_permissions(
                        received.staging.join("data"),
                        fs::Permissions::from_mode(0o600),
                    )
                    .unwrap();
                    fs::write(received.staging.join("data"), b"tampered bytes").unwrap();
                    fs::set_permissions(
                        received.staging.join("data"),
                        fs::Permissions::from_mode(0o444),
                    )
                    .unwrap();
                }
                "extra" => fs::write(received.staging.join("extra"), b"unexpected").unwrap(),
                "empty-directory" => fs::create_dir(received.staging.join("extra")).unwrap(),
                "root" => {
                    fs::rename(&received.staging, parent.join("original-staging")).unwrap();
                    fs::create_dir(&received.staging).unwrap();
                    fs::write(received.staging.join("data"), bytes).unwrap();
                }
                "parent" => {
                    fs::rename(&parent, outer.path().join("original-parent")).unwrap();
                    fs::DirBuilder::new().mode(0o700).create(&parent).unwrap();
                }
                _ => unreachable!(),
            }
            let destination = parent.join("completed");
            assert!(
                received.publish(&destination, &|| false).is_err(),
                "{mutation}"
            );
            assert!(!destination.exists());
        }
    }

    #[test]
    fn publication_never_replaces_an_existing_directory_or_crosses_parents() {
        for existing in [true, false] {
            let parent = private();
            let manifest = ArtifactManifest::new(vec![file("empty", b"", false)]).unwrap();
            let mut received = ReceivedTarget::new(parent.path(), manifest).unwrap();
            received.seal(&|| false).unwrap();
            let destination = parent.path().join("completed");
            fs::create_dir(&destination).unwrap();
            if existing {
                fs::write(destination.join("owned"), b"do not replace").unwrap();
            }
            let before = fs::metadata(&destination).unwrap();
            assert!(received.publish(&destination, &|| false).is_err());
            let after = fs::metadata(&destination).unwrap();
            assert_eq!((before.dev(), before.ino()), (after.dev(), after.ino()));
            assert!(!destination.join("empty").exists());
            if existing {
                assert_eq!(
                    fs::read(destination.join("owned")).unwrap(),
                    b"do not replace"
                );
            }
        }
        let parent = private();
        let other = private();
        let manifest = ArtifactManifest::new(vec![file("empty", b"", false)]).unwrap();
        let mut received = ReceivedTarget::new(parent.path(), manifest).unwrap();
        received.seal(&|| false).unwrap();
        let destination = other.path().join("completed");
        assert!(received.publish(&destination, &|| false).is_err());
        assert!(!destination.exists());
    }

    #[test]
    fn final_checkpoint_namespace_swaps_cannot_publish_an_unverified_replacement() {
        let prepare = |parent: &Path| {
            let bytes = b"verified bytes";
            let manifest = ArtifactManifest::new(vec![file("data", bytes, false)]).unwrap();
            let mut received = ReceivedTarget::new(parent, manifest).unwrap();
            received
                .write_chunk("data", 0, bytes, Sha256::digest(bytes).into())
                .unwrap();
            received.seal(&|| false).unwrap();
            received
        };
        // Locate the last cooperative checkpoint using an ordinary completed
        // publication. The attack then runs at that exact boundary, after all
        // content verification and immediately before filesystem publication.
        let baseline = private();
        let checkpoints = Cell::new(0);
        prepare(baseline.path())
            .publish(&baseline.path().join("completed"), &|| {
                checkpoints.set(checkpoints.get() + 1);
                false
            })
            .unwrap();
        assert!(checkpoints.get() > 0);

        for swap_parent in [true, false] {
            let outer = private();
            let parent = target(outer.path());
            let received = prepare(&parent);
            let staging = received.staging.clone();
            let destination = parent.join("completed");
            let seen = Cell::new(0);
            let swapped = Cell::new(false);
            let result = received.publish(&destination, &|| {
                seen.set(seen.get() + 1);
                if seen.get() == checkpoints.get() {
                    if swap_parent {
                        fs::rename(&parent, outer.path().join("original-parent")).unwrap();
                        fs::DirBuilder::new().mode(0o700).create(&parent).unwrap();
                    } else {
                        fs::rename(&staging, parent.join("original-staging")).unwrap();
                    }
                    fs::DirBuilder::new().mode(0o700).create(&staging).unwrap();
                    fs::write(staging.join("data"), b"unverified replacement").unwrap();
                    swapped.set(true);
                }
                false
            });
            assert!(swapped.get());
            assert!(result.is_err());
            assert!(!destination.exists());
            assert_eq!(
                fs::read(staging.join("data")).unwrap(),
                b"unverified replacement",
            );
        }
    }

    #[test]
    fn incomplete_cancelled_and_unsealed_transfers_never_publish() {
        for stage in ["incomplete", "cancelled", "unsealed", "publish-cancelled"] {
            let parent = private();
            let bytes = b"complete bytes";
            let manifest = ArtifactManifest::new(vec![file("data", bytes, false)]).unwrap();
            let mut received = ReceivedTarget::new(parent.path(), manifest).unwrap();
            if stage != "incomplete" {
                received
                    .write_chunk("data", 0, bytes, Sha256::digest(bytes).into())
                    .unwrap();
            }
            match stage {
                "incomplete" => assert!(received.seal(&|| false).is_err()),
                "cancelled" => {
                    assert_eq!(
                        received.seal(&|| true).unwrap_err().kind(),
                        io::ErrorKind::Interrupted,
                    );
                    assert!(received.seal(&|| false).is_err());
                }
                "publish-cancelled" => received.seal(&|| false).unwrap(),
                "unsealed" => {}
                _ => unreachable!(),
            }
            let destination = parent.path().join("completed");
            assert!(
                received
                    .publish(&destination, &|| stage == "publish-cancelled")
                    .is_err()
            );
            assert!(!destination.exists());
        }
    }

    #[test]
    fn chunk_reads_are_bounded_and_never_select_unmanifested_paths() {
        let parent = private();
        let original = target(parent.path());
        fs::write(original.join("data"), b"bytes").unwrap();
        let captured = CapturedTarget::capture(&original, &|| false).unwrap();
        assert!(captured.read_chunk("data", 0, 0, &|| false).is_err());
        assert!(
            captured
                .read_chunk("data", 0, MAX_SOURCE_CHUNK + 1, &|| false)
                .is_err()
        );
        assert!(captured.read_chunk("../data", 0, 1, &|| false).is_err());
        assert!(captured.read_chunk("data", 6, 1, &|| false).is_err());
        assert_eq!(
            captured
                .read_chunk("data", 0, 1, &|| true)
                .unwrap_err()
                .kind(),
            io::ErrorKind::Interrupted,
        );
        assert_eq!(captured.read_chunk("data", 2, 2, &|| false).unwrap(), b"te");
        assert!(
            captured
                .read_chunk("data", 5, 1, &|| false)
                .unwrap()
                .is_empty()
        );
    }
}
