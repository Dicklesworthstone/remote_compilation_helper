//! Exact, bounded target-tree delivery for remote canonical operations.
//!
//! This module grants byte custody only. The operation owner must first drain
//! every writer and must recheck its producer authority after capture and before
//! reporting success. Each returned artifact is an independent regular file;
//! directories are implicit and only the executable bit is transported. Empty
//! directories, timestamps, hard-link topology and Cargo freshness are not part
//! of this first protocol. Unsupported or oversized trees refuse in full.

use rabs_sandbox::artifact_tree::{TreeInventory, validate_tree_names};
use rabs_sandbox::source_transfer::{
    MAX_SOURCE_BYTES, MAX_SOURCE_CHUNK, SourceFile, SourceManifest, SourceReceiver,
};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
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

fn validate_manifest(manifest: &SourceManifest) -> io::Result<()> {
    // SourceManifest enforces the shared 512 MiB/4096-file byte contract.
    // Artifact names additionally reject case-folded component collisions.
    validate_tree_names(manifest.files().iter().map(|file| file.path.as_str()))?;
    Ok(())
}

/// Retain the local parent identity across staging and final publication.
/// Other principals cannot mutate this private tree; a replacement by the
/// same user is still refused rather than redirecting the final rename.
#[derive(Debug)]
struct Parent {
    path: PathBuf,
    directory: File,
}

impl Parent {
    fn open(path: &Path) -> io::Result<Self> {
        super::private_directory(path)?;
        let before = fs::symlink_metadata(path)?;
        let directory = File::open(path)?;
        let opened = directory.metadata()?;
        require(
            before.dev() == opened.dev() && before.ino() == opened.ino(),
            "remote target parent changed while opening",
        )?;
        let owner = Self {
            path: path.to_path_buf(),
            directory,
        };
        owner.verify()?;
        Ok(owner)
    }

    fn verify(&self) -> io::Result<()> {
        super::private_directory(&self.path)?;
        let current = fs::symlink_metadata(&self.path)?;
        let held = self.directory.metadata()?;
        require(
            current.dev() == held.dev() && current.ino() == held.ino(),
            "remote target parent was replaced",
        )
    }
}

/// Rehash the exact retained namespace, including empty files, and sync only
/// those anchored descriptors. The inventory comparison brackets all reads;
/// a valid digest alone cannot bless replaced files, extra entries or links.
fn verify_tree(
    tree: &TreeInventory,
    manifest: &SourceManifest,
    stopped: &impl Fn() -> bool,
    sync: bool,
) -> io::Result<()> {
    checkpoint(stopped)?;
    validate_manifest(manifest)?;
    tree.verify(stopped)?;
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

/// Independent captured bytes, never writable links into the completed target.
/// Its parent remains under the operation owner's custody through delivery.
#[derive(Debug)]
pub(super) struct CapturedTarget {
    owner: tempfile::TempDir,
    tree: TreeInventory,
    manifest: SourceManifest,
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
        let original = TreeInventory::scan_complete(target, MAX_SOURCE_BYTES, stopped)?;
        validate_tree_names(original.names())?;
        let owner = tempfile::Builder::new()
            .prefix("rabs-target-capture-")
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir_in(&parent.path)?;
        let root = owner.path().join("files");
        fs::DirBuilder::new().mode(0o700).create(&root)?;
        let mut files = Vec::new();
        let mut buffer = [0_u8; MAX_SOURCE_CHUNK];
        for name in original.names() {
            checkpoint(stopped)?;
            let mut input = original.open_file(name)?;
            let metadata = input.metadata()?;
            let destination = root.join(name);
            fs::DirBuilder::new().mode(0o700).recursive(true).create(
                destination
                    .parent()
                    .ok_or_else(|| invalid("target member"))?,
            )?;
            let mut output = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&destination)?;
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
            files.push(SourceFile {
                path: name.to_owned(),
                len: metadata.len(),
                sha256: hash.finalize().into(),
                executable,
            });
        }
        original.verify(stopped)?;
        parent.verify()?;
        let manifest = SourceManifest::new(files)?;
        validate_manifest(&manifest)?;
        let tree = TreeInventory::scan_complete(&root, MAX_SOURCE_BYTES, stopped)?;
        verify_tree(&tree, &manifest, stopped, true)?;
        File::open(owner.path())?.sync_all()?;
        parent.directory.sync_all()?;
        original.verify(stopped)?;
        parent.verify()?;
        checkpoint(stopped)?;
        Ok(Self {
            owner,
            tree,
            manifest,
        })
    }

    pub(super) fn manifest(&self) -> &SourceManifest {
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
        super::private_directory(self.owner.path())?;
        verify_tree(&self.tree, &self.manifest, stopped, false)
    }
}

/// A fresh client-owned staging tree. Failed and interrupted transfers retain
/// their private staging paths; only an exact completed tree can be published.
pub(super) struct ReceivedTarget {
    parent: Parent,
    staging: PathBuf,
    receiver: SourceReceiver,
    sealed: Option<TreeInventory>,
    poisoned: bool,
}

impl ReceivedTarget {
    pub(super) fn new(private_parent: &Path, manifest: SourceManifest) -> io::Result<Self> {
        validate_manifest(&manifest)?;
        let parent = Parent::open(private_parent)?;
        // make_in chooses a fresh bounded random name; SourceReceiver creates
        // that directory exclusively. Keep it immediately, including on later
        // failure. Publication needs a sibling of the eventual destination.
        let staged = tempfile::Builder::new()
            .prefix(".rabs-target-staging-")
            .disable_cleanup(true)
            .make_in(&parent.path, |path| {
                SourceReceiver::create(path, manifest.clone())
            })?;
        let (receiver, staging) = staged.keep().map_err(|error| error.error)?;
        parent.verify()?;
        Ok(Self {
            parent,
            staging,
            receiver,
            sealed: None,
            poisoned: false,
        })
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
        self.parent.verify()?;
        self.receiver.write_chunk(path, offset, bytes, sha256)
    }

    pub(super) fn seal(&mut self, stopped: &impl Fn() -> bool) -> io::Result<()> {
        require(!self.poisoned, "remote target receiver is failed")?;
        let result = (|| {
            checkpoint(stopped)?;
            self.parent.verify()?;
            if let Some(tree) = &self.sealed {
                // SourceReceiver's already-sealed path is intentionally cheap;
                // an artifact delivery must still recheck every retained byte.
                return verify_tree(tree, self.receiver.manifest(), stopped, true);
            }
            self.receiver.seal_cancellable(stopped)?;
            let tree = TreeInventory::scan_complete(&self.staging, MAX_SOURCE_BYTES, stopped)?;
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
        self,
        destination: &Path,
        stopped: &impl Fn() -> bool,
    ) -> io::Result<PathBuf> {
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
        let publication = (|| -> io::Result<()> {
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
                source_metadata.dev() == expected.dev() && source_metadata.ino() == expected.ino(),
                "remote target staging name no longer identifies the sealed tree",
            )?;
            renameat_with(
                &self.parent.directory,
                source_name,
                &self.parent.directory,
                destination_name,
                RenameFlags::NOREPLACE,
            )?;
            let installed = open_named(destination_name)?.metadata()?;
            require(
                installed.dev() == expected.dev() && installed.ino() == expected.ino(),
                "remote target installation identity is uncertain",
            )?;
            self.parent.directory.sync_all()?;
            self.parent.verify()
        })();
        publication.map_err(|error| {
            io::Error::new(
                error.kind(),
                format!(
                    "remote target publication failed; verify destination before retrying; staging={}, destination={}: {error}",
                    self.staging.display(),
                    destination.display(),
                ),
            )
        })?;
        Ok(destination.to_path_buf())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::os::unix::fs::symlink;

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
        assert_eq!(
            received.publish(&destination, &|| false).unwrap(),
            destination
        );
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
                    for index in 0..rabs_sandbox::source_transfer::MAX_SOURCE_FILES {
                        fs::write(original.join(format!("file-{index}")), []).unwrap();
                    }
                }
                "too-large" => {
                    File::create(original.join("large"))
                        .unwrap()
                        .set_len(MAX_SOURCE_BYTES + 1)
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
    fn source_manifest_cannot_bypass_artifact_path_collision_rules() {
        for names in [["Dir/a", "dir/b"], ["FILE", "file"], ["A", "a/child"]] {
            let parent = private();
            let manifest = SourceManifest::new(
                names
                    .into_iter()
                    .map(|name| file(name, b"", false))
                    .collect(),
            )
            .unwrap();
            assert!(ReceivedTarget::new(parent.path(), manifest).is_err());
            assert_eq!(fs::read_dir(parent.path()).unwrap().count(), 0);
        }
        assert!(SourceManifest::new(vec![file("../outside", b"", false)]).is_err());
    }

    #[test]
    fn malformed_ranges_do_not_write_and_exact_retries_preserve_sealing() {
        let parent = private();
        let bytes = b"complete bytes";
        let manifest = SourceManifest::new(vec![file("data", bytes, false)]).unwrap();
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
        let manifest = SourceManifest::new(vec![file("data", bytes, false)]).unwrap();
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
            let manifest = SourceManifest::new(vec![file("data", bytes, false)]).unwrap();
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
            let manifest = SourceManifest::new(vec![file("empty", b"", false)]).unwrap();
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
        let manifest = SourceManifest::new(vec![file("empty", b"", false)]).unwrap();
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
            let manifest = SourceManifest::new(vec![file("data", bytes, false)]).unwrap();
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
            let manifest = SourceManifest::new(vec![file("data", bytes, false)]).unwrap();
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
