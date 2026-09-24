//! Bounded transfer of an exact, independently retained toolchain dataset.
//!
//! This is a streaming tree receiver, not an archive extractor. Entries arrive
//! in canonical path order, regular files finish before the next entry, and
//! symlinks are installed only after the complete namespace is validated. Every
//! write is relative to an owned directory descriptor. The final identity is
//! computed by `toolchain_dataset`, which also owns local capture identity.
//!
//! The caller retains the private parent through transfer and execution and
//! excludes concurrent writers with its credentials. Any error permanently
//! poisons the receiver; failed staging is retained for its owner to inspect.

use crate::toolchain_dataset::{PreparedToolchain, ToolchainIdentity, ToolchainLimits};
use std::collections::VecDeque;
use std::io;
use std::path::Path;
use std::time::Duration;

pub const TOOLCHAIN_TRANSFER_VERSION: &str = "toolchain-tree-v1";
pub const MAX_TOOLCHAIN_CHUNK: usize = 64 * 1024;
pub const MAX_TOOLCHAIN_METADATA_BYTES: usize = 64 * 1024 * 1024;
pub const TOOLCHAIN_UPLOAD_TIMEOUT_MS: u64 = 30 * 60 * 1000;
pub const TOOLCHAIN_UPLOAD_BUDGET: Duration = Duration::from_millis(TOOLCHAIN_UPLOAD_TIMEOUT_MS);
/// Source upload keeps its five-minute allowance before the toolchain transfer.
/// The enclosing input deadline is fixed once; neither phase renews it.
pub const TOOLCHAIN_INPUT_BUDGET: Duration = Duration::from_secs(35 * 60);

/// A single namespace entry. File bytes are supplied separately in bounded
/// chunks. Modes preserve the dataset's existing executable-bit semantics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolchainEntry {
    pub path: String,
    pub kind: ToolchainEntryKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolchainEntryKind {
    Directory,
    Symlink { target: String },
    File { bytes: u64, executable: bool },
}

impl ToolchainEntry {
    pub(crate) fn metadata_bytes(&self) -> usize {
        // Charge fixed object/index overhead as well as all variable strings.
        128 + self.path.len()
            + match &self.kind {
                ToolchainEntryKind::Symlink { target } => target.len(),
                _ => 0,
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

pub(crate) enum LinkNode<'a> {
    Directory,
    File,
    Symlink(&'a str),
}

/// Shared with local capture, so uploaded links have exactly the same bounded
/// containment, existence and cycle semantics as a locally captured dataset.
pub(crate) fn validate_link<'a>(
    path: &str,
    target: &str,
    lookup: impl Fn(&str) -> Option<LinkNode<'a>>,
) -> io::Result<()> {
    let mut resolved: Vec<String> = path.split('/').map(str::to_owned).collect();
    resolved.pop();
    let mut pending: VecDeque<String> = target.split('/').map(str::to_owned).collect();
    let mut traversals = 0;
    while let Some(component) = pending.pop_front() {
        match component.as_str() {
            "" | "." => continue,
            ".." => require(
                resolved.pop().is_some(),
                "toolchain symlink escapes its root",
            )?,
            _ => {
                resolved.push(component);
                let entry = lookup(&resolved.join("/"))
                    .ok_or_else(|| invalid("toolchain symlink target is absent"))?;
                match entry {
                    LinkNode::Symlink(target) => {
                        traversals += 1;
                        require(
                            traversals <= 40,
                            "toolchain symlink cycle or excessive chain",
                        )?;
                        resolved.pop();
                        for component in target.split('/').rev() {
                            pending.push_front(component.to_owned());
                        }
                    }
                    LinkNode::File => require(
                        pending.is_empty(),
                        "toolchain symlink traverses a regular file",
                    )?,
                    LinkNode::Directory => {}
                }
            }
        }
    }
    require(
        lookup(&resolved.join("/")).is_some(),
        "toolchain symlink target is absent",
    )
}

/// Incremental, exclusively created staging. Successful seal returns the same
/// verified object type as local capture; no path-only success is exposed.
pub struct ToolchainReceiver {
    #[cfg(target_os = "linux")]
    inner: linux::Receiver,
}

impl ToolchainReceiver {
    pub fn create(
        root: &Path,
        expected: ToolchainIdentity,
        limits: ToolchainLimits,
    ) -> io::Result<Self> {
        #[cfg(target_os = "linux")]
        {
            Ok(Self {
                inner: linux::Receiver::create(root, expected, limits)?,
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (root, expected, limits);
            Err(unsupported())
        }
    }

    pub fn entry(&mut self, entry: ToolchainEntry) -> io::Result<()> {
        #[cfg(target_os = "linux")]
        {
            self.inner.apply(|inner| inner.entry(entry))
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = entry;
            Err(unsupported())
        }
    }

    pub fn write_chunk(
        &mut self,
        path: &str,
        offset: u64,
        bytes: &[u8],
        sha256: [u8; 32],
    ) -> io::Result<()> {
        #[cfg(target_os = "linux")]
        {
            self.inner
                .apply(|inner| inner.write_chunk(path, offset, bytes, sha256))
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (path, offset, bytes, sha256);
            Err(unsupported())
        }
    }

    pub fn seal(&mut self, stopped: impl Fn() -> bool) -> io::Result<PreparedToolchain> {
        #[cfg(target_os = "linux")]
        {
            self.inner.apply(|inner| inner.seal(&stopped))
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = stopped;
            Err(unsupported())
        }
    }

    #[must_use]
    pub fn entry_count(&self) -> usize {
        #[cfg(target_os = "linux")]
        {
            self.inner.entries.len()
        }
        #[cfg(not(target_os = "linux"))]
        {
            0
        }
    }

    #[must_use]
    pub fn received_bytes(&self) -> u64 {
        #[cfg(target_os = "linux")]
        {
            self.inner.received_bytes
        }
        #[cfg(not(target_os = "linux"))]
        {
            0
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn unsupported() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "anchored toolchain transfer requires Linux openat2",
    )
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use crate::toolchain_dataset::open_toolchain;
    use rustix::fs::{CWD, Mode, OFlags, ResolveFlags, mkdirat, openat2, symlinkat};
    use sha2::{Digest, Sha256};
    use std::collections::BTreeMap;
    use std::fs::{self, File};
    use std::io::Write;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::path::{Component, PathBuf};

    struct PendingFile {
        path: String,
        file: File,
        written: u64,
        expected: u64,
        executable: bool,
    }

    pub(super) struct Receiver {
        root: PathBuf,
        directory: File,
        root_inode: (u64, u64),
        expected: ToolchainIdentity,
        limits: ToolchainLimits,
        pub(super) entries: BTreeMap<String, ToolchainEntryKind>,
        current: Option<PendingFile>,
        declared_bytes: u64,
        files: u64,
        pub(super) received_bytes: u64,
        metadata_bytes: usize,
        closed: bool,
    }

    fn component_valid(value: &str) -> bool {
        !value.is_empty()
            && value.len() <= 255
            && !matches!(value, "." | "..")
            && !value.contains(['/', '\\', ':'])
            && !value.chars().any(char::is_control)
    }

    impl Receiver {
        pub(super) fn create(
            root: &Path,
            expected: ToolchainIdentity,
            limits: ToolchainLimits,
        ) -> io::Result<Self> {
            let maximum = ToolchainLimits::default();
            require(
                limits.max_entries > 0
                    && limits.max_entries <= maximum.max_entries
                    && limits.max_depth > 0
                    && limits.max_depth <= maximum.max_depth
                    && limits.max_bytes <= maximum.max_bytes
                    && expected.bytes <= limits.max_bytes
                    && expected.files <= limits.max_entries as u64,
                "toolchain transfer limits or expected identity exceed bounds",
            )?;
            require(
                root.is_absolute()
                    && root
                        .components()
                        .all(|part| matches!(part, Component::RootDir | Component::Normal(_))),
                "toolchain transfer root must be an absolute ordinary path",
            )?;
            let name = root
                .file_name()
                .and_then(|name| name.to_str())
                .filter(|name| component_valid(name))
                .ok_or_else(|| invalid("toolchain transfer root requires an ordinary name"))?;
            let parent = fs::canonicalize(
                root.parent()
                    .ok_or_else(|| invalid("toolchain transfer parent missing"))?,
            )?;
            let parent_file = File::from(openat2(
                CWD,
                &parent,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
                ResolveFlags::NO_MAGICLINKS,
            )?);
            require(
                parent_file.metadata()?.mode() & 0o077 == 0,
                "toolchain transfer parent must be private",
            )?;
            mkdirat(&parent_file, name, Mode::from_bits_truncate(0o700))?;
            let directory = File::from(openat2(
                &parent_file,
                name,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
                ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_XDEV,
            )?);
            let metadata = directory.metadata()?;
            Ok(Self {
                root: parent.join(name),
                directory,
                root_inode: (metadata.dev(), metadata.ino()),
                expected,
                limits,
                entries: BTreeMap::new(),
                current: None,
                declared_bytes: 0,
                files: 0,
                received_bytes: 0,
                metadata_bytes: 0,
                closed: false,
            })
        }

        pub(super) fn apply<T>(
            &mut self,
            operation: impl FnOnce(&mut Self) -> io::Result<T>,
        ) -> io::Result<T> {
            require(!self.closed, "toolchain receiver is closed or poisoned")?;
            let result = operation(self);
            if result.is_err() {
                self.closed = true;
            }
            result
        }

        fn parent(&self, path: &str) -> io::Result<(File, String)> {
            let (parent, name) = path.rsplit_once('/').unwrap_or(("", path));
            require(
                matches!(
                    self.entries.get(parent),
                    Some(ToolchainEntryKind::Directory)
                ),
                "toolchain entry parent must be a declared directory",
            )?;
            let directory = if parent.is_empty() {
                self.directory.try_clone()?
            } else {
                File::from(openat2(
                    &self.directory,
                    parent,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                    ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_XDEV,
                )?)
            };
            Ok((directory, name.to_owned()))
        }

        pub(super) fn entry(&mut self, entry: ToolchainEntry) -> io::Result<()> {
            require(
                self.current.is_none(),
                "toolchain file is incomplete before next entry",
            )?;
            require(
                self.entries.len() < self.limits.max_entries,
                "toolchain entry count exceeded",
            )?;
            require(
                self.entries
                    .last_key_value()
                    .is_none_or(|(last, _)| last < &entry.path),
                "toolchain entries must be strictly ordered without duplicates",
            )?;
            self.metadata_bytes = self
                .metadata_bytes
                .checked_add(entry.metadata_bytes())
                .filter(|bytes| *bytes <= MAX_TOOLCHAIN_METADATA_BYTES)
                .ok_or_else(|| invalid("toolchain metadata limit exceeded"))?;
            if self.entries.is_empty() {
                require(
                    entry.path.is_empty() && entry.kind == ToolchainEntryKind::Directory,
                    "toolchain first entry must be its root directory",
                )?;
                self.entries.insert(entry.path, entry.kind);
                return Ok(());
            }
            require(
                !entry.path.is_empty()
                    && entry.path.len() <= 4096
                    && entry.path.split('/').count() <= self.limits.max_depth
                    && entry.path.split('/').all(component_valid),
                "unsafe toolchain entry path",
            )?;
            let (parent, name) = self.parent(&entry.path)?;
            match &entry.kind {
                ToolchainEntryKind::Directory => {
                    mkdirat(&parent, name.as_str(), Mode::from_bits_truncate(0o700))?
                }
                ToolchainEntryKind::Symlink { target } => {
                    require(
                        !target.is_empty()
                            && target.len() <= 4096
                            && !target.starts_with('/')
                            && !target.contains(['\\', ':'])
                            && !target.chars().any(char::is_control),
                        "toolchain symlinks must have bounded relative targets",
                    )?;
                }
                ToolchainEntryKind::File { bytes, executable } => {
                    self.declared_bytes = self
                        .declared_bytes
                        .checked_add(*bytes)
                        .filter(|bytes| {
                            *bytes <= self.expected.bytes && *bytes <= self.limits.max_bytes
                        })
                        .ok_or_else(|| invalid("toolchain declared byte count exceeded"))?;
                    self.files = self
                        .files
                        .checked_add(1)
                        .filter(|files| *files <= self.expected.files)
                        .ok_or_else(|| invalid("toolchain declared file count exceeded"))?;
                    let file = File::from(openat2(
                        &parent,
                        name.as_str(),
                        OFlags::WRONLY
                            | OFlags::CREATE
                            | OFlags::EXCL
                            | OFlags::NOFOLLOW
                            | OFlags::CLOEXEC,
                        Mode::from_bits_truncate(0o600),
                        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_XDEV,
                    )?);
                    self.current = Some(PendingFile {
                        path: entry.path.clone(),
                        file,
                        written: 0,
                        expected: *bytes,
                        executable: *executable,
                    });
                    self.finish_file()?;
                }
            }
            self.entries.insert(entry.path, entry.kind);
            Ok(())
        }

        fn finish_file(&mut self) -> io::Result<()> {
            if self
                .current
                .as_ref()
                .is_some_and(|file| file.written == file.expected)
            {
                let file = self
                    .current
                    .take()
                    .ok_or_else(|| invalid("toolchain file owner absent"))?;
                file.file
                    .set_permissions(fs::Permissions::from_mode(if file.executable {
                        0o555
                    } else {
                        0o444
                    }))?;
            }
            Ok(())
        }

        pub(super) fn write_chunk(
            &mut self,
            path: &str,
            offset: u64,
            bytes: &[u8],
            sha256: [u8; 32],
        ) -> io::Result<()> {
            require(
                !bytes.is_empty() && bytes.len() <= MAX_TOOLCHAIN_CHUNK,
                "toolchain chunk outside its byte bound",
            )?;
            let file = self
                .current
                .as_mut()
                .ok_or_else(|| invalid("toolchain has no incomplete file"))?;
            require(
                file.path == path && file.written == offset,
                "toolchain chunk path or offset differs from its owner",
            )?;
            let end = offset
                .checked_add(bytes.len() as u64)
                .filter(|end| *end <= file.expected)
                .ok_or_else(|| invalid("toolchain chunk exceeds declared file"))?;
            let actual: [u8; 32] = Sha256::digest(bytes).into();
            require(actual == sha256, "toolchain chunk digest mismatch")?;
            file.file.write_all(bytes)?;
            file.written = end;
            self.received_bytes = self
                .received_bytes
                .checked_add(bytes.len() as u64)
                .filter(|bytes| *bytes <= self.expected.bytes)
                .ok_or_else(|| invalid("toolchain received byte count exceeded"))?;
            self.finish_file()
        }

        pub(super) fn seal(
            &mut self,
            stopped: &impl Fn() -> bool,
        ) -> io::Result<PreparedToolchain> {
            let checkpoint = || {
                if stopped() {
                    Err(io::Error::new(
                        io::ErrorKind::Interrupted,
                        "toolchain seal interrupted",
                    ))
                } else {
                    Ok(())
                }
            };
            checkpoint()?;
            require(
                !self.entries.is_empty()
                    && self.current.is_none()
                    && self.files == self.expected.files
                    && self.declared_bytes == self.expected.bytes
                    && self.received_bytes == self.expected.bytes,
                "toolchain transfer is incomplete",
            )?;
            for (path, kind) in &self.entries {
                checkpoint()?;
                if let ToolchainEntryKind::Symlink { target } = kind {
                    validate_link(path, target, |name| {
                        self.entries.get(name).map(|kind| match kind {
                            ToolchainEntryKind::Directory => LinkNode::Directory,
                            ToolchainEntryKind::File { .. } => LinkNode::File,
                            ToolchainEntryKind::Symlink { target } => LinkNode::Symlink(target),
                        })
                    })?;
                }
            }
            for (path, kind) in &self.entries {
                checkpoint()?;
                if let ToolchainEntryKind::Symlink { target } = kind {
                    let (parent, name) = self.parent(path)?;
                    symlinkat(target.as_str(), &parent, name.as_str())?;
                }
            }
            let metadata = fs::symlink_metadata(&self.root)?;
            require(
                metadata.is_dir() && (metadata.dev(), metadata.ino()) == self.root_inode,
                "toolchain staging root was replaced",
            )?;
            let prepared = open_toolchain(&self.root, &self.expected, &self.limits, stopped)?;
            checkpoint()?;
            self.closed = true;
            Ok(prepared)
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::toolchain_dataset::{capture_toolchain, fingerprint_toolchain, open_toolchain};
    use sha2::{Digest, Sha256};
    use std::fs;
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};

    fn private() -> tempfile::TempDir {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        directory
    }

    fn directory(path: &str) -> ToolchainEntry {
        ToolchainEntry {
            path: path.to_owned(),
            kind: ToolchainEntryKind::Directory,
        }
    }
    fn file(path: &str, bytes: u64) -> ToolchainEntry {
        ToolchainEntry {
            path: path.to_owned(),
            kind: ToolchainEntryKind::File {
                bytes,
                executable: false,
            },
        }
    }
    fn link(path: &str, target: &str) -> ToolchainEntry {
        ToolchainEntry {
            path: path.to_owned(),
            kind: ToolchainEntryKind::Symlink {
                target: target.to_owned(),
            },
        }
    }
    fn selected(bytes: u64, files: u64) -> ToolchainIdentity {
        ToolchainIdentity {
            sha256: [1; 32],
            bytes,
            files,
        }
    }
    fn receiver(parent: &Path, expected: ToolchainIdentity) -> ToolchainReceiver {
        ToolchainReceiver::create(
            &parent.join("received"),
            expected,
            ToolchainLimits::default(),
        )
        .unwrap()
    }

    fn transfer(prepared: &PreparedToolchain, receiver: &mut ToolchainReceiver) {
        for entry in prepared.entries().unwrap() {
            let path = entry.path.clone();
            let bytes = match entry.kind {
                ToolchainEntryKind::File { bytes, .. } => bytes,
                _ => 0,
            };
            receiver.entry(entry).unwrap();
            let mut offset = 0;
            while offset < bytes {
                let chunk = prepared
                    .read_chunk(&path, offset, MAX_TOOLCHAIN_CHUNK, || false)
                    .unwrap();
                receiver
                    .write_chunk(&path, offset, &chunk, Sha256::digest(&chunk).into())
                    .unwrap();
                offset += chunk.len() as u64;
            }
        }
    }

    #[test]
    fn streamed_dataset_roundtrip_preserves_binary_modes_empty_directories_and_links() {
        let source = private();
        for path in ["bin", "lib", "lib/empty"] {
            fs::create_dir(source.path().join(path)).unwrap();
        }
        let payload: Vec<u8> = (0..MAX_TOOLCHAIN_CHUNK * 2 + 71)
            .map(|index| index as u8)
            .collect();
        fs::write(source.path().join("lib/runtime"), &payload).unwrap();
        fs::write(
            source.path().join("bin/compiler"),
            b"#!/bin/sh\nprintf 'toolchain\\n'\n",
        )
        .unwrap();
        fs::set_permissions(
            source.path().join("bin/compiler"),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        fs::write(source.path().join("empty-file"), []).unwrap();
        symlink("../lib/runtime", source.path().join("bin/runtime")).unwrap();
        symlink("bin/compiler", source.path().join("compiler")).unwrap();
        let parent = private();
        let prepared = capture_toolchain(
            source.path(),
            &parent.path().join("retained"),
            None,
            &ToolchainLimits::default(),
            || false,
        )
        .unwrap();
        prepared.sync(|| false).unwrap();
        fs::write(
            source.path().join("lib/runtime"),
            b"changed original after retained capture",
        )
        .unwrap();
        let reopened = open_toolchain(
            prepared.root(),
            prepared.identity(),
            &ToolchainLimits::default(),
            || false,
        )
        .unwrap();
        let mut receiver = receiver(parent.path(), *prepared.identity());
        transfer(&reopened, &mut receiver);
        assert_eq!(receiver.entry_count(), prepared.entries().unwrap().len());
        assert_eq!(receiver.received_bytes(), prepared.identity().bytes);
        assert!(
            !parent.path().join("received/compiler").exists(),
            "links must remain deferred before seal"
        );
        let received = receiver.seal(|| false).unwrap();
        assert_eq!(received.identity(), prepared.identity());
        assert_eq!(
            fs::read(received.root().join("lib/runtime")).unwrap(),
            payload
        );
        assert!(received.root().join("lib/empty").is_dir());
        assert_eq!(
            fs::metadata(received.root().join("empty-file"))
                .unwrap()
                .len(),
            0
        );
        assert_eq!(
            fs::metadata(received.root().join("bin/compiler"))
                .unwrap()
                .mode()
                & 0o777,
            0o555
        );
        assert_eq!(
            fs::metadata(received.root().join("lib/runtime"))
                .unwrap()
                .mode()
                & 0o777,
            0o444
        );
        assert_eq!(
            fs::read_link(received.root().join("bin/runtime")).unwrap(),
            Path::new("../lib/runtime")
        );
        assert_ne!(
            fs::metadata(prepared.root().join("lib/runtime"))
                .unwrap()
                .ino(),
            fs::metadata(received.root().join("lib/runtime"))
                .unwrap()
                .ino()
        );
        received.verify(|| false).unwrap();
        assert!(receiver.seal(|| false).is_err());
        assert!(receiver.entry(directory("z")).is_err());
    }

    #[test]
    fn corrupt_chunk_poisoning_prevents_repair_and_never_exposes_a_dataset() {
        let parent = private();
        let mut receiver = receiver(parent.path(), selected(3, 1));
        receiver.entry(directory("")).unwrap();
        receiver.entry(file("file", 3)).unwrap();
        assert!(receiver.write_chunk("file", 0, b"abc", [0; 32]).is_err());
        assert_eq!(
            fs::metadata(parent.path().join("received/file"))
                .unwrap()
                .len(),
            0
        );
        assert!(
            receiver
                .write_chunk("file", 0, b"abc", Sha256::digest(b"abc").into())
                .is_err()
        );
        assert!(receiver.seal(|| false).is_err());
    }

    #[test]
    fn receiver_refuses_gaps_duplicates_empty_chunks_and_incomplete_files() {
        for case in 0..5 {
            let parent = private();
            let mut receiver = receiver(parent.path(), selected(4, 1));
            receiver.entry(directory("")).unwrap();
            receiver.entry(file("file", 4)).unwrap();
            receiver
                .write_chunk("file", 0, b"ab", Sha256::digest(b"ab").into())
                .unwrap();
            let result = match case {
                0 => receiver.write_chunk("file", 3, b"d", Sha256::digest(b"d").into()),
                1 => receiver.write_chunk("file", 0, b"ab", Sha256::digest(b"ab").into()),
                2 => receiver.write_chunk("file", 2, b"", Sha256::digest([]).into()),
                3 => receiver.entry(directory("next")),
                _ => receiver.seal(|| false).map(|_| ()),
            };
            assert!(result.is_err(), "case {case}");
            assert!(
                receiver
                    .write_chunk("file", 2, b"cd", Sha256::digest(b"cd").into())
                    .is_err()
            );
            assert!(!parent.path().join("received/next").exists());
        }
    }

    #[test]
    fn namespace_requires_one_root_ordered_entries_and_directory_parents() {
        for path in [
            "/absolute",
            "../escape",
            "a/../escape",
            "a//b",
            "a\\b",
            "a:b",
            "a\n",
            "missing/child",
        ] {
            let parent = private();
            let mut receiver = receiver(parent.path(), selected(0, 0));
            receiver.entry(directory("")).unwrap();
            assert!(receiver.entry(directory(path)).is_err(), "{path:?}");
            assert!(receiver.seal(|| false).is_err());
        }
        for entries in [
            vec![directory("not-root")],
            vec![directory(""), directory("")],
            vec![directory(""), directory("z"), directory("a")],
            vec![directory(""), file("a", 0), directory("a/child")],
            vec![directory(""), link("a", "."), directory("a/child")],
        ] {
            let parent = private();
            let mut receiver = receiver(parent.path(), selected(0, 1));
            let mut refused = false;
            for entry in entries {
                if receiver.entry(entry).is_err() {
                    refused = true;
                    break;
                }
            }
            assert!(refused);
        }
    }

    #[test]
    fn symlinks_must_resolve_inside_the_complete_declared_tree_before_installation() {
        for entries in [
            vec![link("a", "../outside")],
            vec![link("a", "missing")],
            vec![link("a", "b"), link("b", "a")],
            vec![file("a", 0), link("b", "a/child")],
        ] {
            let parent = private();
            let files = entries
                .iter()
                .filter(|entry| matches!(entry.kind, ToolchainEntryKind::File { .. }))
                .count();
            let mut receiver = receiver(parent.path(), selected(0, files as u64));
            receiver.entry(directory("")).unwrap();
            for entry in entries {
                receiver.entry(entry).unwrap();
            }
            assert!(receiver.seal(|| false).is_err());
            assert!(fs::symlink_metadata(parent.path().join("received/b")).is_err());
            assert!(receiver.seal(|| false).is_err());
        }
    }

    #[test]
    fn understated_resource_counts_and_existing_destination_refuse_before_writing() {
        let parent = private();
        fs::create_dir(parent.path().join("existing")).unwrap();
        fs::write(parent.path().join("existing/keep"), b"original").unwrap();
        assert!(
            ToolchainReceiver::create(
                &parent.path().join("existing"),
                selected(0, 0),
                ToolchainLimits::default()
            )
            .is_err()
        );
        assert_eq!(
            fs::read(parent.path().join("existing/keep")).unwrap(),
            b"original"
        );
        let mut receiver = receiver(parent.path(), selected(2, 1));
        receiver.entry(directory("")).unwrap();
        assert!(receiver.entry(file("too-large", 3)).is_err());
        assert!(!parent.path().join("received/too-large").exists());
        assert!(
            ToolchainReceiver::create(
                &parent.path().join("over-budget"),
                selected(ToolchainLimits::default().max_bytes + 1, 1),
                ToolchainLimits::default()
            )
            .is_err()
        );
        assert!(!parent.path().join("over-budget").exists());
    }

    #[test]
    fn final_identity_and_cancellation_are_sticky_seal_failures() {
        for cancelled in [false, true] {
            let source = private();
            fs::write(source.path().join("file"), b"original").unwrap();
            let identity =
                fingerprint_toolchain(source.path(), &ToolchainLimits::default(), || false)
                    .unwrap();
            let prepared = open_toolchain(
                source.path(),
                &identity,
                &ToolchainLimits::default(),
                || false,
            )
            .unwrap();
            let parent = private();
            let mut expected = identity;
            if !cancelled {
                expected.sha256[0] ^= 1;
            }
            let mut receiver = receiver(parent.path(), expected);
            transfer(&prepared, &mut receiver);
            let error = receiver.seal(|| cancelled).unwrap_err();
            if cancelled {
                assert_eq!(error.kind(), io::ErrorKind::Interrupted);
            }
            assert!(receiver.seal(|| false).is_err());
        }
    }

    #[test]
    fn exporter_detects_replaced_files_and_final_namespace_drift() {
        let source = private();
        fs::create_dir(source.path().join("bin")).unwrap();
        fs::write(source.path().join("bin/compiler"), b"abcd").unwrap();
        let parent = private();
        let prepared = capture_toolchain(
            source.path(),
            &parent.path().join("retained"),
            None,
            &ToolchainLimits::default(),
            || false,
        )
        .unwrap();
        assert_eq!(
            prepared.read_chunk("bin/compiler", 1, 2, || false).unwrap(),
            b"bc"
        );
        assert!(
            prepared
                .read_chunk("bin/compiler", 0, MAX_TOOLCHAIN_CHUNK + 1, || false)
                .is_err()
        );
        assert!(prepared.read_chunk("bin/compiler", 0, 1, || true).is_err());
        fs::rename(
            prepared.root().join("bin/compiler"),
            prepared.root().join("bin/old"),
        )
        .unwrap();
        fs::write(prepared.root().join("bin/compiler"), b"abcd").unwrap();
        assert!(prepared.read_chunk("bin/compiler", 0, 4, || false).is_err());
        assert!(prepared.verify(|| false).is_err());
        assert!(prepared.sync(|| false).is_err());
    }
}
