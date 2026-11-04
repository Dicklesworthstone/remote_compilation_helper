//! Verified private Cargo state, without action-cache or execution authority.
//!
//! A snapshot records the complete regular-file tree, including empty
//! directories, timestamps and internal hard-link topology. Restores read
//! through a fresh descriptor-anchored inventory and create independent files
//! in an empty, caller-owned private staging directory. The caller publishes
//! that directory atomically only after this module returns success and keeps
//! it private on error. A retained seed is never mounted writable.
//!
//! Source timestamps belong to a separately cloned execution workspace, never
//! the sealed source capture. Exact bytes are verified before and after changes;
//! edited local inputs become newer than every retained source/target timestamp.
//! Cargo still runs the original command and decides every unit's freshness.

use super::SourceEditPolicy;
use crate::artifact_tree::{
    MAX_PRIVATE_TREE_BYTES, MAX_PRIVATE_TREE_ENTRIES, MAX_PRIVATE_TREE_FILES, MAX_TREE_ENTRIES,
    TreeInventory, validate_private_tree_names,
};
use crate::source_transfer::{MAX_SOURCE_BYTES, MAX_SOURCE_FILES, SourceManifest};
use rustix::fs::{AtFlags, CWD, Dir, Mode, OFlags, ResolveFlags, linkat, mkdirat, openat2};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, FileTimes};
use std::io::{self, Read, Seek, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Component, Path};
use std::time::SystemTime;

/// Readers of persisted metadata must bound input before deserialization.
pub const MAX_SNAPSHOT_METADATA_BYTES: u64 = 16 * 1024 * 1024;

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
            "private Cargo state interrupted",
        ))
    } else {
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredFile {
    bytes: u64,
    sha256: [u8; 32],
    mode: u32,
    modified: SystemTime,
    /// First relative name in the same private tree; never a host inode ID.
    link_to: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredDirectory {
    mode: u32,
    modified: SystemTime,
}

/// Complete content and metadata of one quiescent private tree.
///
/// This serializable value is an expectation, not a filesystem capability.
/// Every restore validates its bounds and verifies the actual source bytes.
/// A persisted descriptor must be read under [`MAX_SNAPSHOT_METADATA_BYTES`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateTreeSnapshot {
    files: BTreeMap<String, StoredFile>,
    directories: BTreeMap<String, StoredDirectory>,
    bytes: u64,
}

impl PrivateTreeSnapshot {
    /// Hash and inventory every file through the existing private-tree bounds.
    pub fn capture(root: &Path, maximum: u64, stopped: &impl Fn() -> bool) -> io::Result<Self> {
        checkpoint(stopped)?;
        require(
            maximum > 0 && maximum <= MAX_PRIVATE_TREE_BYTES,
            "private tree byte limit is outside its bound",
        )?;
        let owner = PrivateDirectory::open(root)?;
        let tree = TreeInventory::scan_complete_private(root, maximum, stopped)?;
        let snapshot = Self::from_inventory(&tree, stopped)?;
        owner.verify(root)?;
        Ok(snapshot)
    }

    fn from_inventory(tree: &TreeInventory, stopped: &impl Fn() -> bool) -> io::Result<Self> {
        let directories = directory_times(tree, stopped)?;
        let mut files = BTreeMap::new();
        let mut aliases = BTreeMap::new();
        for name in tree.names() {
            checkpoint(stopped)?;
            let mut file = tree.open_file(name)?;
            let metadata = file.metadata()?;
            require(
                metadata.mode() & 0o7000 == 0,
                "special target file permissions",
            )?;
            let inode = (metadata.dev(), metadata.ino());
            let link_to = aliases.get(&inode).cloned();
            let digest = hash_copy(&mut file, &mut io::sink(), metadata.len(), stopped)?;
            tree.verify_file(name, &file)?;
            files.insert(
                name.to_owned(),
                StoredFile {
                    bytes: metadata.len(),
                    sha256: digest,
                    mode: metadata.mode() & 0o777,
                    modified: metadata.modified()?,
                    link_to,
                },
            );
            aliases.entry(inode).or_insert_with(|| name.to_owned());
        }
        tree.verify(stopped)?;
        let snapshot = Self {
            files,
            directories,
            bytes: tree.total_bytes(),
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    /// Validate a decoded descriptor before using any of its names or bounds.
    pub fn validate(&self) -> io::Result<()> {
        require(
            self.files.len() <= MAX_PRIVATE_TREE_FILES && self.bytes <= MAX_PRIVATE_TREE_BYTES,
            "private tree descriptor exceeds its bounds",
        )?;
        validate_layout(
            self.files.keys().map(String::as_str),
            &self.directories,
            MAX_PRIVATE_TREE_ENTRIES,
        )?;
        let mut bytes = 0_u64;
        for (name, file) in &self.files {
            bytes = bytes
                .checked_add(file.bytes)
                .ok_or_else(|| invalid("private tree byte overflow"))?;
            require(file.mode & !0o777 == 0, "invalid target file permissions")?;
            if file.bytes == 0 {
                require(
                    file.sha256 == <[u8; 32]>::from(Sha256::digest([])),
                    "invalid empty target digest",
                )?;
            }
            if let Some(first) = &file.link_to {
                let original = self
                    .files
                    .get(first)
                    .ok_or_else(|| invalid("missing internal target alias"))?;
                require(
                    first < name
                        && original.link_to.is_none()
                        && original.bytes == file.bytes
                        && original.sha256 == file.sha256
                        && original.mode == file.mode
                        && original.modified == file.modified,
                    "invalid internal target alias",
                )?;
            }
        }
        require(bytes == self.bytes, "private tree byte count differs")
    }

    #[must_use]
    pub const fn total_bytes(&self) -> u64 {
        self.bytes
    }

    #[must_use]
    pub fn latest_modified(&self) -> Option<SystemTime> {
        self.files
            .values()
            .map(|file| file.modified)
            .chain(
                self.directories
                    .values()
                    .map(|directory| directory.modified),
            )
            .max()
    }

    /// Restore into a fresh, empty, owned 0700 directory. An error leaves only
    /// private staging, which the caller must not expose or reuse as a seed.
    pub fn restore_into(
        &self,
        source: &Path,
        destination: &Path,
        stopped: &impl Fn() -> bool,
    ) -> io::Result<()> {
        self.restore_into_with_cloner(source, destination, stopped, |_, _, _| false)
    }

    /// As [`Self::restore_into`], optionally using a separately audited CoW
    /// primitive. The callback's signature matches the CAS verified reflink
    /// helper. Destination bytes are still hashed; failed clones are truncated
    /// and both cursors rewound before normal copying.
    pub fn restore_into_with_cloner(
        &self,
        source: &Path,
        destination: &Path,
        stopped: &impl Fn() -> bool,
        mut cloner: impl FnMut(&File, &File, &Path) -> bool,
    ) -> io::Result<()> {
        checkpoint(stopped)?;
        self.validate()?;
        require(
            !source.starts_with(destination) && !destination.starts_with(source),
            "private source and destination must be disjoint",
        )?;
        let source_owner = PrivateDirectory::open(source)?;
        let output = PrivateDirectory::open(destination)?;
        output.require_empty()?;
        require(
            !source_owner.same_inode(&output),
            "private source and destination alias",
        )?;
        let required = self.files.keys().cloned().collect();
        let tree = TreeInventory::scan_private(source, &required, self.bytes, stopped)?;
        require(
            tree.names().eq(self.files.keys().map(String::as_str))
                && directory_times(&tree, stopped)? == self.directories
                && tree.total_bytes() == self.bytes,
            "private target seed inventory changed",
        )?;
        for name in self.directories.keys().filter(|name| !name.is_empty()) {
            checkpoint(stopped)?;
            let (parent, leaf) = split_parent(name);
            mkdirat(output.directory(parent)?, leaf, Mode::RWXU)?;
        }
        let mut input_aliases = BTreeMap::new();
        for (name, expected) in &self.files {
            checkpoint(stopped)?;
            let mut input = tree.open_file(name)?;
            let metadata = input.metadata()?;
            require(
                metadata.len() == expected.bytes
                    && metadata.mode() & 0o7777 == expected.mode
                    && metadata.modified()? == expected.modified
                    && input_aliases.get(&(metadata.dev(), metadata.ino()))
                        == expected.link_to.as_ref(),
                "private target seed file metadata changed",
            )?;
            input_aliases
                .entry((metadata.dev(), metadata.ino()))
                .or_insert_with(|| name.clone());
            if let Some(first) = &expected.link_to {
                let digest = hash_copy(&mut input, &mut io::sink(), expected.bytes, stopped)?;
                require(
                    digest == expected.sha256,
                    "private target seed content changed",
                )?;
                let (first_parent, first_leaf) = split_parent(first);
                let (parent, leaf) = split_parent(name);
                linkat(
                    output.directory(first_parent)?,
                    first_leaf,
                    output.directory(parent)?,
                    leaf,
                    AtFlags::empty(),
                )?;
            } else {
                let mut file = output.file(name, true)?;
                require(
                    (metadata.dev(), metadata.ino())
                        != (file.metadata()?.dev(), file.metadata()?.ino()),
                    "private target copy shares a source inode",
                )?;
                let digest = if expected.bytes > 64 * 1024 && cloner(&input, &file, destination) {
                    file.rewind()?;
                    hash_copy(&mut file, &mut io::sink(), expected.bytes, stopped)?
                } else {
                    file.set_len(0)?;
                    file.rewind()?;
                    input.rewind()?;
                    hash_copy(&mut input, &mut file, expected.bytes, stopped)?
                };
                require(
                    digest == expected.sha256,
                    "private target seed content changed",
                )?;
                file.set_permissions(fs::Permissions::from_mode(expected.mode))?;
                file.set_times(FileTimes::new().set_modified(expected.modified))?;
                file.sync_all()?;
            }
            tree.verify_file(name, &input)?;
        }
        for (name, expected) in self.directories.iter().rev() {
            checkpoint(stopped)?;
            let directory = output.directory(name)?;
            directory.set_permissions(fs::Permissions::from_mode(expected.mode))?;
            directory.set_times(FileTimes::new().set_modified(expected.modified))?;
            directory.sync_all()?;
        }
        tree.verify(stopped)?;
        source_owner.verify(source)?;
        output.verify(destination)?;
        // Verify the actual copied bytes and aliases, not only their source.
        require(
            Self::capture(destination, self.bytes.max(1), stopped)? == *self,
            "restored private target differs from its snapshot",
        )
    }
}

/// Source times bound to an exact captured file manifest. Only a fresh private
/// execution copy may receive these timestamps; sealed source/CAS trees must
/// retain their original metadata and ownership.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceTimestamps {
    source_digest: [u8; 32],
    files: BTreeMap<String, SystemTime>,
    directories: BTreeMap<String, StoredDirectory>,
}

impl SourceTimestamps {
    pub fn capture(
        root: &Path,
        manifest: &SourceManifest,
        stopped: &impl Fn() -> bool,
    ) -> io::Result<Self> {
        checkpoint(stopped)?;
        let owner = PrivateDirectory::open(root)?;
        let required = manifest
            .files()
            .iter()
            .map(|file| file.path.clone())
            .collect();
        let tree = TreeInventory::scan(root, &required, MAX_SOURCE_BYTES, stopped)?;
        require(
            tree.names()
                .eq(manifest.files().iter().map(|file| file.path.as_str())),
            "private source differs from its exact manifest",
        )?;
        let mut files = BTreeMap::new();
        for expected in manifest.files() {
            checkpoint(stopped)?;
            let mut file = tree.open_file(&expected.path)?;
            let metadata = file.metadata()?;
            require(
                metadata.nlink() == 1
                    && metadata.len() == expected.len
                    && (metadata.mode() & 0o111 != 0) == expected.executable
                    && hash_copy(&mut file, &mut io::sink(), expected.len, stopped)?
                        == expected.sha256,
                "private source content or ownership differs",
            )?;
            tree.verify_file(&expected.path, &file)?;
            files.insert(expected.path.clone(), metadata.modified()?);
        }
        let directories = directory_times(&tree, stopped)?;
        tree.verify(stopped)?;
        owner.verify(root)?;
        let times = Self {
            source_digest: manifest.digest(),
            files,
            directories,
        };
        times.validate()?;
        Ok(times)
    }

    pub fn validate(&self) -> io::Result<()> {
        require(
            self.files.len() <= MAX_SOURCE_FILES,
            "source timestamp file bound exceeded",
        )?;
        validate_layout(
            self.files.keys().map(String::as_str),
            &self.directories,
            MAX_TREE_ENTRIES,
        )
    }

    #[must_use]
    pub fn latest_modified(&self) -> Option<SystemTime> {
        self.files
            .values()
            .copied()
            .chain(
                self.directories
                    .values()
                    .map(|directory| directory.modified),
            )
            .max()
    }

    /// Apply and read back timestamps only after exact bytes, layout and the
    /// absence of shared source inodes have been verified in a private clone.
    pub fn restore_exact(
        &self,
        root: &Path,
        manifest: &SourceManifest,
        stopped: &impl Fn() -> bool,
    ) -> io::Result<()> {
        self.validate()?;
        require(
            self.source_digest == manifest.digest(),
            "source timestamp manifest differs",
        )?;
        let current = Self::capture(root, manifest, stopped)?;
        require(
            current.files.keys().eq(self.files.keys())
                && current.directories.keys().eq(self.directories.keys())
                && current
                    .directories
                    .iter()
                    .all(|(name, directory)| self.directories[name].mode == directory.mode),
            "private source timestamp layout changed",
        )?;
        let owner = PrivateDirectory::open(root)?;
        for (name, modified) in &self.files {
            checkpoint(stopped)?;
            owner
                .file(name, false)?
                .set_times(FileTimes::new().set_modified(*modified))?;
        }
        for (name, directory) in self.directories.iter().rev() {
            checkpoint(stopped)?;
            owner
                .directory(name)?
                .set_times(FileTimes::new().set_modified(directory.modified))?;
        }
        owner.verify(root)?;
        require(
            Self::capture(root, manifest, stopped)? == *self,
            "filesystem cannot preserve Cargo source timestamps",
        )
    }

    /// Plan ordinary local/path source edits without changing action identity.
    /// The caller's compatibility key must still bind toolchain, environment,
    /// configuration and any isolated Cargo-home cache partition exactly.
    pub fn for_edits(
        &self,
        previous: &SourceManifest,
        current: &SourceManifest,
        current_times: &Self,
        target: &PrivateTreeSnapshot,
        now: SystemTime,
    ) -> io::Result<Self> {
        self.validate()?;
        current_times.validate()?;
        target.validate()?;
        require(
            self.source_digest == previous.digest()
                && current_times.source_digest == current.digest()
                && self
                    .files
                    .keys()
                    .map(String::as_str)
                    .eq(previous.files().iter().map(|file| file.path.as_str()))
                && current_times
                    .files
                    .keys()
                    .map(String::as_str)
                    .eq(current.files().iter().map(|file| file.path.as_str())),
            "source edit timestamps differ from their manifests",
        )?;
        if previous.digest() == current.digest() {
            require(
                self.files.keys().eq(current_times.files.keys())
                    && self.directories.keys().eq(current_times.directories.keys())
                    && self.directories.iter().all(|(name, directory)| {
                        current_times.directories[name].mode == directory.mode
                    }),
                "exact source timestamp layout changed",
            )?;
            return Ok(self.clone());
        }
        require(
            self.latest_modified()
                .into_iter()
                .chain(target.latest_modified())
                .all(|latest| now > latest),
            "clock cannot order edited sources after the retained target",
        )?;
        let old: BTreeMap<_, _> = previous
            .files()
            .iter()
            .map(|file| (file.path.as_str(), file))
            .collect();
        let new: BTreeMap<_, _> = current
            .files()
            .iter()
            .map(|file| (file.path.as_str(), file))
            .collect();
        let old_policy = SourceEditPolicy::new(previous);
        let policy = SourceEditPolicy::new(current);
        let mut changed = BTreeSet::new();
        for (name, file) in &old {
            if !new.contains_key(name) {
                require(
                    old_policy.is_editable(file),
                    "source edit removed an immutable Cargo input",
                )?;
                changed.insert(*name);
            }
        }
        for (name, file) in &new {
            if let Some(prior) = old.get(name) {
                require(
                    prior.executable == file.executable,
                    "source edit changed executable mode",
                )?;
                if prior.sha256 == file.sha256 && prior.len == file.len {
                    continue;
                }
            }
            require(
                policy.is_editable(file),
                "source edit changed an immutable Cargo input",
            )?;
            changed.insert(*name);
        }
        require(
            !changed.is_empty(),
            "source edit has no supported content change",
        )?;
        let mut parents = BTreeSet::new();
        for name in &changed {
            for parent in Path::new(name).ancestors().skip(1) {
                parents.insert(
                    parent
                        .to_str()
                        .ok_or_else(|| invalid("non-UTF8 source parent"))?,
                );
            }
        }
        let membership_changed = !old.keys().eq(new.keys());
        let mut wanted = current_times.clone();
        for (name, time) in &mut wanted.files {
            if let Some(prior) = self.files.get(name) {
                *time = *prior;
            }
            if changed.contains(name.as_str()) {
                *time = now;
            }
        }
        for (name, directory) in &mut wanted.directories {
            if let Some(prior) = self.directories.get(name) {
                require(
                    directory.mode == prior.mode,
                    "source edit changed directory mode",
                )?;
                directory.modified = prior.modified;
            } else {
                require(
                    parents.contains(name.as_str()),
                    "source edit added an unrelated directory",
                )?;
            }
            if parents.contains(name.as_str()) {
                directory.modified = now;
            }
        }
        for name in self.directories.keys() {
            require(
                wanted.directories.contains_key(name) || parents.contains(name.as_str()),
                "source edit removed an unrelated directory",
            )?;
        }
        if membership_changed {
            for parent in parents {
                let manifest = Path::new(parent).join("Cargo.toml");
                if let Some(name) = manifest.to_str()
                    && let Some(time) = wanted.files.get_mut(name)
                {
                    *time = now;
                }
            }
        }
        Ok(wanted)
    }
}

fn directory_times(
    tree: &TreeInventory,
    stopped: &impl Fn() -> bool,
) -> io::Result<BTreeMap<String, StoredDirectory>> {
    tree.directory_names()
        .map(|name| {
            checkpoint(stopped)?;
            let metadata = tree.open_directory(name)?.metadata()?;
            require(
                metadata.mode() & 0o7000 == 0 && metadata.mode() & 0o700 == 0o700,
                "private tree requires ordinary owner-accessible directories",
            )?;
            Ok((
                name.to_owned(),
                StoredDirectory {
                    mode: metadata.mode() & 0o777,
                    modified: metadata.modified()?,
                },
            ))
        })
        .collect()
}

fn validate_layout<'a>(
    files: impl Iterator<Item = &'a str>,
    directories: &BTreeMap<String, StoredDirectory>,
    maximum: usize,
) -> io::Result<()> {
    let files = validate_private_tree_names(files)?;
    require(
        files
            .len()
            .checked_add(directories.len())
            .is_some_and(|count| count <= maximum)
            && directories.get("").is_some_and(|root| root.mode == 0o700),
        "invalid private tree directory inventory",
    )?;
    let mut folded = BTreeMap::new();
    for name in files.iter().map(String::as_str).chain(
        directories
            .keys()
            .map(String::as_str)
            .filter(|name| !name.is_empty()),
    ) {
        require(
            !name.is_empty()
                && name.len() <= 1024
                && !name.contains(['\\', ':'])
                && !name.chars().any(char::is_control)
                && name.split('/').count() <= 32
                && name.split('/').all(|part| !matches!(part, "" | "." | ".."))
                && folded.insert(name.to_lowercase(), name).is_none()
                && directories.contains_key(split_parent(name).0),
            "invalid, aliased or incomplete private tree layout",
        )?;
    }
    for directory in directories.values() {
        require(
            directory.mode & !0o777 == 0 && directory.mode & 0o700 == 0o700,
            "invalid private directory permissions",
        )?;
    }
    Ok(())
}

fn split_parent(name: &str) -> (&str, &str) {
    name.rsplit_once('/').unwrap_or(("", name))
}

/// Descriptor-relative destination access. Only the caller's empty private
/// staging tree is writable; every component refuses symlinks and mount jumps.
struct PrivateDirectory {
    directory: File,
}

impl PrivateDirectory {
    fn open(path: &Path) -> io::Result<Self> {
        require(
            path.is_absolute()
                && path
                    .components()
                    .all(|part| matches!(part, Component::RootDir | Component::Normal(_))),
            "private directory path must be absolute and ordinary",
        )?;
        let directory = File::from(openat2(
            CWD,
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )?);
        let metadata = directory.metadata()?;
        require(
            metadata.uid() == rustix::process::geteuid().as_raw()
                && metadata.mode() & 0o7777 == 0o700,
            "private tree root must be owned and mode 0700",
        )?;
        Ok(Self { directory })
    }

    fn same_inode(&self, other: &Self) -> bool {
        self.directory
            .metadata()
            .ok()
            .zip(other.directory.metadata().ok())
            .is_some_and(|(a, b)| (a.dev(), a.ino()) == (b.dev(), b.ino()))
    }

    fn verify(&self, path: &Path) -> io::Result<()> {
        require(
            self.same_inode(&Self::open(path)?),
            "private tree root was replaced",
        )
    }

    fn require_empty(&self) -> io::Result<()> {
        let mut entries = Dir::read_from(&self.directory)?;
        while let Some(entry) = entries.read() {
            require(
                matches!(entry?.file_name().to_bytes(), b"." | b".."),
                "private restore destination must be empty",
            )?;
        }
        Ok(())
    }

    fn directory(&self, name: &str) -> io::Result<File> {
        if name.is_empty() {
            return self.directory.try_clone();
        }
        self.open_relative(name, OFlags::RDONLY | OFlags::DIRECTORY, Mode::empty())
    }

    fn file(&self, name: &str, create: bool) -> io::Result<File> {
        let flags = if create {
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL
        } else {
            OFlags::RDONLY | OFlags::NONBLOCK
        };
        self.open_relative(
            name,
            flags,
            if create {
                Mode::RUSR | Mode::WUSR
            } else {
                Mode::empty()
            },
        )
    }

    fn open_relative(&self, name: &str, flags: OFlags, mode: Mode) -> io::Result<File> {
        Ok(File::from(openat2(
            &self.directory,
            name,
            flags | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            mode,
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_XDEV,
        )?))
    }
}

fn hash_copy(
    input: &mut File,
    output: &mut impl Write,
    length: u64,
    stopped: &impl Fn() -> bool,
) -> io::Result<[u8; 32]> {
    let mut hash = Sha256::new();
    let mut remaining = length;
    let mut buffer = [0; 64 * 1024];
    loop {
        checkpoint(stopped)?;
        let count = input.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        remaining = remaining
            .checked_sub(count as u64)
            .ok_or_else(|| invalid("private state file grew during capture"))?;
        hash.update(&buffer[..count]);
        output.write_all(&buffer[..count])?;
    }
    require(remaining == 0, "private state file shrank during capture")?;
    Ok(hash.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source_transfer::SourceFile;
    use std::io::SeekFrom;
    use std::time::{Duration, UNIX_EPOCH};

    fn private() -> tempfile::TempDir {
        tempfile::Builder::new()
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap()
    }

    fn write(root: &Path, name: &str, bytes: &[u8]) {
        let path = root.join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    fn manifest(root: &Path, names: &[&str]) -> SourceManifest {
        SourceManifest::new(
            names
                .iter()
                .map(|name| {
                    let path = root.join(name);
                    let bytes = fs::read(&path).unwrap();
                    SourceFile {
                        path: (*name).to_owned(),
                        len: bytes.len() as u64,
                        sha256: Sha256::digest(&bytes).into(),
                        executable: fs::metadata(path).unwrap().mode() & 0o111 != 0,
                    }
                })
                .collect(),
        )
        .unwrap()
    }

    fn stamp(path: &Path, time: SystemTime) {
        File::open(path)
            .unwrap()
            .set_times(FileTimes::new().set_modified(time))
            .unwrap();
    }

    #[test]
    fn private_snapshot_preserves_exact_trees_without_shared_seed_inodes() {
        let source = private();
        write(source.path(), "debug/deps/library.rlib", b"archive\0bytes");
        write(source.path(), "debug/application", b"executable");
        fs::set_permissions(
            source.path().join("debug/application"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        fs::create_dir_all(source.path().join("debug/build/empty-out")).unwrap();
        fs::hard_link(
            source.path().join("debug/deps/library.rlib"),
            source.path().join("debug/library.rlib"),
        )
        .unwrap();
        let time = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        stamp(&source.path().join("debug/library.rlib"), time);
        let snapshot = PrivateTreeSnapshot::capture(source.path(), 1024, &|| false).unwrap();
        let decoded: PrivateTreeSnapshot =
            serde_json::from_slice(&serde_json::to_vec(&snapshot).unwrap()).unwrap();
        decoded.validate().unwrap();
        assert_eq!(snapshot, decoded);

        let seed = private();
        snapshot
            .restore_into(source.path(), seed.path(), &|| false)
            .unwrap();
        let execution = private();
        snapshot
            .restore_into(seed.path(), execution.path(), &|| false)
            .unwrap();
        assert_eq!(
            PrivateTreeSnapshot::capture(execution.path(), 1024, &|| false).unwrap(),
            snapshot
        );
        assert!(execution.path().join("debug/build/empty-out").is_dir());
        let source_inode = fs::metadata(source.path().join("debug/library.rlib"))
            .unwrap()
            .ino();
        let seed_inode = fs::metadata(seed.path().join("debug/library.rlib"))
            .unwrap()
            .ino();
        let execution_inode = fs::metadata(execution.path().join("debug/library.rlib"))
            .unwrap()
            .ino();
        assert_ne!(source_inode, seed_inode);
        assert_ne!(seed_inode, execution_inode);
        assert_eq!(
            execution_inode,
            fs::metadata(execution.path().join("debug/deps/library.rlib"))
                .unwrap()
                .ino()
        );
        fs::write(
            execution.path().join("debug/library.rlib"),
            b"caller changed delivered output",
        )
        .unwrap();
        let another = private();
        snapshot
            .restore_into(seed.path(), another.path(), &|| false)
            .unwrap();
        assert_eq!(
            fs::read(another.path().join("debug/library.rlib")).unwrap(),
            b"archive\0bytes"
        );
    }

    #[test]
    fn corrupted_seed_and_nonempty_destination_never_produce_a_valid_restore() {
        let source = private();
        write(source.path(), "artifact", b"original");
        let snapshot = PrivateTreeSnapshot::capture(source.path(), 1024, &|| false).unwrap();
        let occupied = private();
        write(occupied.path(), "sentinel", b"keep me");
        assert!(
            snapshot
                .restore_into(source.path(), occupied.path(), &|| false)
                .is_err()
        );
        assert_eq!(
            fs::read(occupied.path().join("sentinel")).unwrap(),
            b"keep me"
        );
        let time = fs::metadata(source.path().join("artifact"))
            .unwrap()
            .modified()
            .unwrap();
        fs::write(source.path().join("artifact"), b"tampered").unwrap();
        stamp(&source.path().join("artifact"), time);
        let output = private();
        assert!(
            snapshot
                .restore_into(source.path(), output.path(), &|| false)
                .is_err()
        );
        assert!(
            snapshot
                .restore_into(source.path(), source.path(), &|| false)
                .is_err()
        );
    }

    #[test]
    fn external_aliases_and_symlinks_are_not_snapshot_inputs() {
        let source = private();
        let external = private();
        write(source.path(), "artifact", b"owned");
        fs::hard_link(
            source.path().join("artifact"),
            external.path().join("alias"),
        )
        .unwrap();
        assert!(PrivateTreeSnapshot::capture(source.path(), 1024, &|| false).is_err());
        let linked = private();
        std::os::unix::fs::symlink(source.path().join("artifact"), linked.path().join("input"))
            .unwrap();
        assert!(PrivateTreeSnapshot::capture(linked.path(), 1024, &|| false).is_err());
    }

    #[test]
    fn failed_clone_resets_both_cursors_and_discards_partial_output() {
        let source = private();
        let bytes = vec![0x5a; 128 * 1024];
        write(source.path(), "large", &bytes);
        let snapshot = PrivateTreeSnapshot::capture(source.path(), 256 * 1024, &|| false).unwrap();
        let output = private();
        let mut attempts = 0;
        snapshot
            .restore_into_with_cloner(
                source.path(),
                output.path(),
                &|| false,
                |input, output, _| {
                    attempts += 1;
                    let mut input = input.try_clone().unwrap();
                    input.seek(SeekFrom::End(0)).unwrap();
                    let mut output = output.try_clone().unwrap();
                    output.write_all(&vec![0xcc; bytes.len() + 99]).unwrap();
                    output.seek(SeekFrom::Start(17)).unwrap();
                    false
                },
            )
            .unwrap();
        assert_eq!(attempts, 1);
        assert_eq!(fs::read(output.path().join("large")).unwrap(), bytes);
    }

    #[test]
    fn clone_success_still_verifies_actual_destination_bytes() {
        let source = private();
        write(source.path(), "large", &vec![0x5a; 128 * 1024]);
        let snapshot = PrivateTreeSnapshot::capture(source.path(), 256 * 1024, &|| false).unwrap();
        let output = private();
        assert!(
            snapshot
                .restore_into_with_cloner(
                    source.path(),
                    output.path(),
                    &|| false,
                    |_, output, _| {
                        output.set_len(128 * 1024).unwrap();
                        true
                    }
                )
                .is_err()
        );
    }

    #[test]
    fn bounds_cancellation_and_decoded_descriptor_validation_are_enforced() {
        let source = private();
        write(source.path(), "artifact", b"content");
        assert!(PrivateTreeSnapshot::capture(source.path(), 1, &|| false).is_err());
        assert_eq!(
            PrivateTreeSnapshot::capture(source.path(), 1024, &|| true)
                .unwrap_err()
                .kind(),
            io::ErrorKind::Interrupted
        );
        let snapshot = PrivateTreeSnapshot::capture(source.path(), 1024, &|| false).unwrap();
        let output = private();
        assert_eq!(
            snapshot
                .restore_into(source.path(), output.path(), &|| true)
                .unwrap_err()
                .kind(),
            io::ErrorKind::Interrupted
        );
        assert!(fs::read_dir(output.path()).unwrap().next().is_none());
        let mut corrupted = snapshot.clone();
        corrupted.bytes = MAX_PRIVATE_TREE_BYTES + 1;
        assert!(corrupted.validate().is_err());
        let mut corrupted = snapshot.clone();
        let entry = corrupted.files.remove("artifact").unwrap();
        corrupted.files.insert("../escape".into(), entry);
        assert!(corrupted.validate().is_err());
        let mut corrupted = snapshot;
        corrupted.files.get_mut("artifact").unwrap().link_to = Some("artifact".into());
        assert!(corrupted.validate().is_err());
    }

    #[test]
    fn source_timestamps_restore_only_verified_exact_private_files() {
        let source = private();
        write(source.path(), "Cargo.toml", b"manifest");
        write(source.path(), "src/lib.rs", b"original source");
        let old = UNIX_EPOCH + Duration::from_secs(1_600_000_000);
        stamp(&source.path().join("src/lib.rs"), old);
        let manifest = manifest(source.path(), &["Cargo.toml", "src/lib.rs"]);
        let times = SourceTimestamps::capture(source.path(), &manifest, &|| false).unwrap();
        let copy = private();
        PrivateTreeSnapshot::capture(source.path(), 1024, &|| false)
            .unwrap()
            .restore_into(source.path(), copy.path(), &|| false)
            .unwrap();
        stamp(&copy.path().join("src/lib.rs"), SystemTime::now());
        times
            .restore_exact(copy.path(), &manifest, &|| false)
            .unwrap();
        assert_eq!(
            fs::metadata(copy.path().join("src/lib.rs"))
                .unwrap()
                .modified()
                .unwrap(),
            old
        );
        assert_eq!(
            SourceTimestamps::capture(source.path(), &manifest, &|| false).unwrap(),
            times
        );
        fs::write(copy.path().join("src/lib.rs"), b"modified source").unwrap();
        assert!(
            times
                .restore_exact(copy.path(), &manifest, &|| false)
                .is_err()
        );
    }

    #[test]
    fn source_edits_dirty_changed_inputs_and_membership_without_touching_other_packages() {
        let original = private();
        write(original.path(), "Cargo.toml", b"manifest");
        write(original.path(), "src/lib.rs", b"old source");
        write(original.path(), "data/old.txt", b"removed input");
        write(
            original.path(),
            "dependency/lib.rs",
            b"unchanged dependency",
        );
        let names = [
            "Cargo.toml",
            "src/lib.rs",
            "data/old.txt",
            "dependency/lib.rs",
        ];
        let previous = manifest(original.path(), &names);
        let before = SourceTimestamps::capture(original.path(), &previous, &|| false).unwrap();
        let target = private();
        write(target.path(), ".fingerprint/package/stamp", b"fingerprint");
        let target = PrivateTreeSnapshot::capture(target.path(), 1024, &|| false).unwrap();

        let runtime = private();
        write(runtime.path(), "Cargo.toml", b"manifest");
        write(runtime.path(), "src/lib.rs", b"new source");
        write(runtime.path(), "src/new.rs", b"added input");
        write(runtime.path(), "dependency/lib.rs", b"unchanged dependency");
        let current = manifest(
            runtime.path(),
            &[
                "Cargo.toml",
                "src/lib.rs",
                "src/new.rs",
                "dependency/lib.rs",
            ],
        );
        let current_times = SourceTimestamps::capture(runtime.path(), &current, &|| false).unwrap();
        let now = SystemTime::now() + Duration::from_secs(2);
        let wanted = before
            .for_edits(&previous, &current, &current_times, &target, now)
            .unwrap();
        wanted
            .restore_exact(runtime.path(), &current, &|| false)
            .unwrap();
        for name in ["Cargo.toml", "src/lib.rs", "src/new.rs"] {
            assert_eq!(
                fs::metadata(runtime.path().join(name))
                    .unwrap()
                    .modified()
                    .unwrap(),
                now,
                "{name}"
            );
        }
        assert_eq!(
            fs::metadata(runtime.path().join("dependency/lib.rs"))
                .unwrap()
                .modified()
                .unwrap(),
            before.files["dependency/lib.rs"]
        );
        assert!(!runtime.path().join("data/old.txt").exists());
        assert_eq!(
            SourceTimestamps::capture(original.path(), &previous, &|| false).unwrap(),
            before
        );
        assert!(
            before
                .for_edits(
                    &previous,
                    &current,
                    &current_times,
                    &target,
                    target.latest_modified().unwrap()
                )
                .is_err()
        );

        fs::write(runtime.path().join("Cargo.toml"), b"changed manifest").unwrap();
        let changed = manifest(
            runtime.path(),
            &[
                "Cargo.toml",
                "src/lib.rs",
                "src/new.rs",
                "dependency/lib.rs",
            ],
        );
        let changed_times = SourceTimestamps::capture(runtime.path(), &changed, &|| false).unwrap();
        assert!(
            before
                .for_edits(&previous, &changed, &changed_times, &target, now)
                .is_err()
        );
    }
}
