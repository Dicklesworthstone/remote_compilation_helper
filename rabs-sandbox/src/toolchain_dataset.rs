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

#[cfg(target_os = "linux")]
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};

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

    /// Rehash the retained bytes through anchored descriptors and reject any
    /// content, mode, namespace, inode or mutation-stamp change since capture.
    pub fn verify(&self, stopped: impl Fn() -> bool) -> io::Result<()> {
        #[cfg(target_os = "linux")]
        {
            self.inventory.verify(&stopped)?;
            let current = self.inventory.stream(None, &stopped)?;
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
    #[cfg(target_os = "linux")]
    {
        linux::capture(source, destination, expected, limits, &stopped)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (source, destination, expected, limits, stopped);
        Err(unsupported())
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use rustix::fs::{CWD, Dir, Mode, OFlags, ResolveFlags, openat2, readlinkat};
    use sha2::{Digest, Sha256};
    use std::collections::{BTreeMap, VecDeque};
    use std::fs::{self, Metadata, OpenOptions};
    use std::io::{Read, Write};
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt, symlink};
    use std::path::Component;

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
            let mut resolved: Vec<String> = path.split('/').map(str::to_owned).collect();
            resolved.pop();
            let mut pending: VecDeque<String> = target.split('/').map(str::to_owned).collect();
            let mut traversals = 0;
            while let Some(component) = pending.pop_front() {
                match component.as_str() {
                    "" | "." => continue,
                    ".." => {
                        require(
                            resolved.pop().is_some(),
                            "toolchain symlink escapes its root",
                        )?;
                    }
                    _ => {
                        resolved.push(component);
                        let entry = self
                            .entries
                            .get(&resolved.join("/"))
                            .ok_or_else(|| invalid("toolchain symlink target is absent"))?;
                        match &entry.kind {
                            Kind::Link(target) => {
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
                            Kind::File => require(
                                pending.is_empty(),
                                "toolchain symlink traverses a regular file",
                            )?,
                            Kind::Directory => {}
                        }
                    }
                }
            }
            require(
                self.entries.contains_key(&resolved.join("/")),
                "toolchain symlink target is absent",
            )
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

        pub(super) fn stream(
            &self,
            destination: Option<&Path>,
            stopped: &impl Fn() -> bool,
        ) -> io::Result<ToolchainIdentity> {
            let mut digest = Sha256::new();
            digest.update(TOOLCHAIN_DATASET_VERSION.as_bytes());
            let mut buffer = [0_u8; 64 * 1024];
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
                        let mut source =
                            self.open(path, OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOCTTY)?;
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
                            if let Some(output) = &mut output {
                                output.write_all(&buffer[..read])?;
                            }
                        }
                        require(
                            copied == entry.stamp.size
                                && Stamp::of(&source.metadata()?) == entry.stamp,
                            "toolchain file changed during capture",
                        )?;
                        digest.update(file_digest.finalize());
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
        let identity = inventory.stream(Some(&destination), stopped)?;
        inventory.verify(stopped)?;
        require(
            expected.is_none_or(|expected| *expected == identity),
            "toolchain identity does not match expected dataset",
        )?;
        let retained = Inventory::scan(&destination, limits, stopped)?;
        require(
            retained.stream(None, stopped)? == identity,
            "retained toolchain bytes differ from captured dataset",
        )?;
        retained.verify(stopped)?;
        Ok(PreparedToolchain {
            root: destination,
            identity,
            inventory: retained,
        })
    }
}
