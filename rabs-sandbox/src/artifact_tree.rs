//! Bounded regular-file closure of a quiescent, private compiler output tree.
//!
//! `tree-files-v1` exports every regular file, including Cargo's intermediate
//! artifacts, and checks a caller-declared minimum set. Directories are implicit;
//! empty directories, ownership, timestamps and hard-link topology are NOT
//! replayed. This is transport delivery, not Cargo freshness or cache authority.
//! Linux capture anchors every lookup to an open directory and rejects symlinks,
//! mount crossings and special files before reading. Hard links are accepted
//! only when ALL aliases are inside this tree; consumers copy each alias into an
//! independent immutable snapshot, never export a writable shared inode.

use std::collections::{BTreeMap, BTreeSet};
use std::io;

/// Opt-in artifact declaration contract, independent of files-v1 range framing.
pub const TREE_FILES_VERSION: &str = "tree-files-v1";
/// Maximum regular files in a complete tree offer.
pub const MAX_TREE_FILES: usize = 4096;
/// Includes directories and regular files, even empty directories.
pub const MAX_TREE_ENTRIES: usize = 16_384;
/// Maximum regular files in a worker-private compiler-state inventory. This
/// does not enlarge the artifact offer or receiver namespace limit.
pub const MAX_PRIVATE_TREE_FILES: usize = 65_536;
/// Maximum directories and regular files in a private compiler-state tree.
pub const MAX_PRIVATE_TREE_ENTRIES: usize = 131_072;
/// Independent upper bound for a complete private compiler-state generation.
/// Retention additionally reserves every byte against the worker's cache quota.
pub const MAX_PRIVATE_TREE_BYTES: u64 = 8 * 1024 * 1024 * 1024;
/// Leave room for result/retention metadata in a bounded transport record.
pub const MAX_TREE_MANIFEST_BYTES: usize = 512 * 1024;

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn valid_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 1024
        && !path.contains(['\\', ':'])
        && !path.chars().any(char::is_control)
        && path.split('/').count() <= 32
        && path
            .split('/')
            .all(|part| !part.is_empty() && !matches!(part, "." | ".."))
}

/// Validate names BEFORE a receiver creates paths. Preserve spelling and reject
/// duplicate names, traversal, file/directory overlap and case-folded aliases at
/// every directory component, not just whole-file collisions. Filesystem-specific
/// normalization collisions must additionally fail exclusive destination creation.
/// No receiver may use overwrite-on-collision semantics.
pub fn validate_tree_names<'a>(
    paths: impl IntoIterator<Item = &'a str>,
) -> io::Result<BTreeSet<String>> {
    validate_names(paths, MAX_TREE_FILES)
}

/// Validate a complete private compiler-state namespace without granting an
/// artifact offer. Exported names must separately pass [`validate_tree_names`].
pub fn validate_private_tree_names<'a>(
    paths: impl IntoIterator<Item = &'a str>,
) -> io::Result<BTreeSet<String>> {
    validate_names(paths, MAX_PRIVATE_TREE_FILES)
}

fn validate_names<'a>(
    paths: impl IntoIterator<Item = &'a str>,
    max_files: usize,
) -> io::Result<BTreeSet<String>> {
    let mut names = BTreeSet::new();
    let mut namespace: BTreeMap<String, (String, bool)> = BTreeMap::new();
    for path in paths {
        if names.len() >= max_files || !valid_path(path) || !names.insert(path.to_owned()) {
            return Err(invalid(
                "unsafe, duplicate or excessive artifact tree names",
            ));
        }
        let prefixes = path
            .match_indices('/')
            .map(|(end, _)| (&path[..end], false))
            .chain(std::iter::once((path, true)));
        for (prefix, is_file) in prefixes {
            let folded = prefix.to_lowercase();
            match namespace.get(&folded) {
                Some((prior, prior_file)) if prior != prefix || *prior_file != is_file => {
                    return Err(invalid(
                        "artifact tree contains aliased or overlapping paths",
                    ));
                }
                Some(_) => {}
                None => {
                    namespace.insert(folded, (prefix.to_owned(), is_file));
                }
            }
        }
    }
    if names.is_empty() {
        return Err(invalid("artifact tree contains no regular files"));
    }
    Ok(names)
}

#[cfg(target_os = "linux")]
pub use linux::TreeInventory;

#[cfg(target_os = "linux")]
mod linux {
    use super::{
        MAX_PRIVATE_TREE_BYTES, MAX_PRIVATE_TREE_ENTRIES, MAX_PRIVATE_TREE_FILES, MAX_TREE_ENTRIES,
        MAX_TREE_FILES, invalid, valid_path, validate_names, validate_private_tree_names,
        validate_tree_names,
    };
    use rustix::fs::{CWD, Dir, Mode, OFlags, ResolveFlags, openat2};
    use std::collections::{BTreeMap, BTreeSet};
    use std::fs::{self, File, Metadata};
    use std::io;
    use std::os::unix::fs::MetadataExt;
    use std::path::{Path, PathBuf};

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
        fn of(meta: &Metadata) -> Self {
            Self {
                device: meta.dev(),
                inode: meta.ino(),
                size: meta.len(),
                links: meta.nlink(),
                mode: meta.mode(),
                uid: meta.uid(),
                gid: meta.gid(),
                modified: (meta.mtime(), meta.mtime_nsec()),
                changed: (meta.ctime(), meta.ctime_nsec()),
            }
        }
    }

    /// Anchored inventory, never reconstructed from a remote path or manifest.
    /// The execution owner must have drained all writers before scanning, and
    /// must retain ownership through copying and the final `verify` barrier.
    #[derive(Debug)]
    pub struct TreeInventory {
        root: File,
        root_path: PathBuf,
        files: BTreeMap<String, Stamp>,
        directories: BTreeMap<String, Stamp>,
        total_bytes: u64,
        entries: usize,
    }

    #[derive(Clone, Copy)]
    struct Limits {
        files: usize,
        entries: usize,
        bytes: u64,
    }

    impl Limits {
        const fn artifacts(bytes: u64) -> Self {
            Self {
                files: MAX_TREE_FILES,
                entries: MAX_TREE_ENTRIES,
                bytes,
            }
        }

        fn private(bytes: u64) -> Self {
            Self {
                files: MAX_PRIVATE_TREE_FILES,
                entries: MAX_PRIVATE_TREE_ENTRIES,
                bytes: bytes.min(MAX_PRIVATE_TREE_BYTES),
            }
        }
    }

    fn checkpoint(stopped: &impl Fn() -> bool) -> io::Result<()> {
        if stopped() {
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "artifact tree capture interrupted",
            ))
        } else {
            Ok(())
        }
    }

    impl TreeInventory {
        /// Inventory the complete output closure under one byte/entry budget.
        /// No file content is read before the complete hard-link closure check.
        /// A missing required output refuses, rather than exporting partial work.
        pub fn scan(
            root: &Path,
            required: &BTreeSet<String>,
            max_bytes: u64,
            stopped: &impl Fn() -> bool,
        ) -> io::Result<Self> {
            checkpoint(stopped)?;
            validate_tree_names(required.iter().map(String::as_str))?;
            Self::scan_with_required(root, required, Limits::artifacts(max_bytes), stopped)
        }

        /// Inventory a complete worker-private target, including compiler state
        /// excluded from delivery by an independently validated output contract.
        /// This proves the same full filesystem closure as [`Self::scan`], with
        /// a separate bounded inventory; it does not authorize transporting its
        /// entire contents. The caller must validate the exported subset against
        /// the ordinary artifact limits before reading any payload for delivery.
        pub fn scan_private(
            root: &Path,
            required: &BTreeSet<String>,
            max_bytes: u64,
            stopped: &impl Fn() -> bool,
        ) -> io::Result<Self> {
            checkpoint(stopped)?;
            validate_private_tree_names(required.iter().map(String::as_str))?;
            Self::scan_with_required(root, required, Limits::private(max_bytes), stopped)
        }

        /// Inventory a private, quiescent tree without declaring successful
        /// compiler outputs. Cargo may retain useful completed dependencies
        /// after another unit fails; that state is only a seed for a later
        /// private Cargo execution, never a successful artifact offer.
        /// The complete nonempty tree still satisfies every ordinary path,
        /// byte, entry, hard-link and mutation check.
        pub fn scan_complete(
            root: &Path,
            max_bytes: u64,
            stopped: &impl Fn() -> bool,
        ) -> io::Result<Self> {
            Self::scan_with_required(
                root,
                &BTreeSet::new(),
                Limits::artifacts(max_bytes),
                stopped,
            )
        }

        /// Inventory bounded private state after an unsuccessful Cargo command.
        /// It may seed a later execution, but proves no successful output set.
        pub fn scan_complete_private(
            root: &Path,
            max_bytes: u64,
            stopped: &impl Fn() -> bool,
        ) -> io::Result<Self> {
            Self::scan_with_required(root, &BTreeSet::new(), Limits::private(max_bytes), stopped)
        }

        fn scan_with_required(
            root: &Path,
            required: &BTreeSet<String>,
            limits: Limits,
            stopped: &impl Fn() -> bool,
        ) -> io::Result<Self> {
            checkpoint(stopped)?;
            let directory = File::from(openat2(
                CWD,
                root,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
                ResolveFlags::NO_MAGICLINKS,
            )?);
            if directory.metadata()?.mode() & 0o077 != 0 {
                return Err(invalid("artifact tree root must be private"));
            }
            let mut tree = Self {
                root: directory.try_clone()?,
                root_path: root.to_path_buf(),
                files: BTreeMap::new(),
                directories: BTreeMap::new(),
                total_bytes: 0,
                entries: 0,
            };
            tree.visit(&directory, "", limits, stopped)?;
            let names = validate_names(tree.files.keys().map(String::as_str), limits.files)?;
            if !required.is_subset(&names) {
                return Err(invalid(
                    "compiler did not produce every required tree artifact",
                ));
            }
            let mut aliases: BTreeMap<(u64, u64), u64> = BTreeMap::new();
            for stamp in tree.files.values() {
                *aliases.entry((stamp.device, stamp.inode)).or_default() += 1;
            }
            for stamp in tree.files.values() {
                if aliases[&(stamp.device, stamp.inode)] != stamp.links {
                    return Err(invalid(
                        "artifact hard link escapes the captured output tree",
                    ));
                }
            }
            tree.verify(stopped)?;
            Ok(tree)
        }

        fn open(&self, path: &str, flags: OFlags) -> io::Result<File> {
            // No fallback to pathname traversal on older kernels or filesystems.
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
            limits: Limits,
            stopped: &impl Fn() -> bool,
        ) -> io::Result<()> {
            checkpoint(stopped)?;
            let before = Stamp::of(&directory.metadata()?);
            let mut entries = Dir::read_from(directory)?;
            while let Some(entry) = entries.read() {
                checkpoint(stopped)?;
                let entry = entry?;
                if matches!(entry.file_name().to_bytes(), b"." | b"..") {
                    continue;
                }
                self.entries += 1;
                if self.entries > limits.entries {
                    return Err(invalid("artifact tree directory entry limit exceeded"));
                }
                let name = entry
                    .file_name()
                    .to_str()
                    .map_err(|_| invalid("non-UTF-8 artifact tree path"))?;
                let path = if relative.is_empty() {
                    name.to_owned()
                } else {
                    format!("{relative}/{name}")
                };
                if !valid_path(&path) {
                    return Err(invalid("unsafe artifact tree path"));
                }
                // O_PATH classifies FIFOs/devices/symlinks without opening them
                // for I/O. Descendant directories are opened only after this.
                let observed = self.open(&path, OFlags::PATH)?;
                let metadata = observed.metadata()?;
                let stamp = Stamp::of(&metadata);
                if metadata.is_dir() {
                    let child = self.open(&path, OFlags::RDONLY | OFlags::DIRECTORY)?;
                    if Stamp::of(&child.metadata()?) != stamp {
                        return Err(invalid("artifact directory changed during inventory"));
                    }
                    self.visit(&child, &path, limits, stopped)?;
                } else if metadata.is_file() {
                    if self.files.len() >= limits.files {
                        return Err(invalid("artifact tree file count exceeded"));
                    }
                    self.total_bytes = self
                        .total_bytes
                        .checked_add(metadata.len())
                        .filter(|bytes| *bytes <= limits.bytes)
                        .ok_or_else(|| invalid("artifact tree byte limit exceeded"))?;
                    if self.files.insert(path.clone(), stamp.clone()).is_some() {
                        return Err(invalid("duplicate artifact during inventory"));
                    }
                } else {
                    return Err(invalid("artifact tree contains a symlink or special file"));
                }
                if Stamp::of(&self.open(&path, OFlags::PATH)?.metadata()?) != stamp {
                    return Err(invalid("artifact tree changed during inventory"));
                }
            }
            if Stamp::of(&directory.metadata()?) != before {
                return Err(invalid("artifact directory changed during inventory"));
            }
            self.directories.insert(relative.to_owned(), before);
            Ok(())
        }

        /// Complete file names in canonical order; empty directories are omitted.
        pub fn names(&self) -> impl Iterator<Item = &str> {
            self.files.keys().map(String::as_str)
        }

        /// Inventoried directories, including the empty name for the root.
        /// Private Cargo target clones preserve empty OUT_DIRs as well as files;
        /// the artifact transport continues to describe only regular files.
        pub fn directory_names(&self) -> impl Iterator<Item = &str> {
            self.directories.keys().map(String::as_str)
        }

        /// Open a directory through the same anchored, no-follow inventory.
        /// The descriptor may be used to preserve its original timestamp in a
        /// separate private clone, never to change an immutable shared object.
        pub fn open_directory(&self, name: &str) -> io::Result<File> {
            let expected = self
                .directories
                .get(name)
                .ok_or_else(|| invalid("unknown tree directory"))?;
            let directory = if name.is_empty() {
                self.root.try_clone()?
            } else {
                self.open(name, OFlags::RDONLY | OFlags::DIRECTORY)?
            };
            if &Stamp::of(&directory.metadata()?) != expected {
                return Err(invalid("artifact directory changed during capture"));
            }
            Ok(directory)
        }

        /// Counts each exported alias's bytes because each is copied independently.
        #[must_use]
        pub const fn total_bytes(&self) -> u64 {
            self.total_bytes
        }

        /// Open one INVENTORIED file through the anchored root and compare its
        /// inode and mutation stamp before a reader can consume any bytes.
        pub fn open_file(&self, name: &str) -> io::Result<File> {
            if !self.files.contains_key(name) {
                return Err(invalid("unknown tree artifact"));
            }
            let file = self.open(name, OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOCTTY)?;
            self.verify_file(name, &file)?;
            Ok(file)
        }

        /// Check the SAME open descriptor after its complete byte snapshot.
        pub fn verify_file(&self, name: &str, file: &File) -> io::Result<()> {
            if self.files.get(name) != Some(&Stamp::of(&file.metadata()?)) {
                return Err(invalid("artifact file changed during capture"));
            }
            Ok(())
        }

        /// Final barrier after copying: no entry replacement, directory-set
        /// change, external hard link or metadata mutation may become an offer.
        pub fn verify(&self, stopped: &impl Fn() -> bool) -> io::Result<()> {
            checkpoint(stopped)?;
            if self.directories.get("") != Some(&Stamp::of(&fs::symlink_metadata(&self.root_path)?))
            {
                return Err(invalid("artifact tree root changed during capture"));
            }
            for (path, stamp) in self.directories.iter().chain(&self.files) {
                checkpoint(stopped)?;
                let current = if path.is_empty() {
                    self.root.metadata()?
                } else {
                    self.open(path, OFlags::PATH)?.metadata()?
                };
                if Stamp::of(&current) != *stamp {
                    return Err(invalid("artifact tree changed during capture"));
                }
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_reject_aliases_traversal_and_component_collisions() {
        for paths in [
            vec!["../x"],
            vec!["/x"],
            vec!["a//b"],
            vec!["a\\b"],
            vec!["a:b"],
            vec!["a\0b"],
            vec!["a", "a"],
            vec!["a", "a/x"],
            vec!["A/x", "a/y"],
            vec!["a", "A/x"],
            vec!["a/FILE", "a/file"],
        ] {
            assert!(validate_tree_names(paths).is_err());
        }
        let names =
            validate_tree_names(["debug/app", "debug/deps/lib.rlib", "debug/.cargo-lock"]).unwrap();
        assert_eq!(names.len(), 3);
        assert!(validate_tree_names(std::iter::empty::<&str>()).is_err());
    }

    #[test]
    fn exact_tree_name_count_and_path_limits_are_bounded() {
        let mut names: Vec<_> = (0..MAX_TREE_FILES)
            .map(|index| format!("d/f{index}"))
            .collect();
        assert_eq!(
            validate_tree_names(names.iter().map(String::as_str))
                .unwrap()
                .len(),
            MAX_TREE_FILES
        );
        names.push("overflow".into());
        assert!(validate_tree_names(names.iter().map(String::as_str)).is_err());
        let deep = vec!["d"; 33].join("/");
        assert!(validate_tree_names([deep.as_str()]).is_err());
        let long = "a".repeat(1025);
        assert!(validate_tree_names([long.as_str()]).is_err());
    }

    #[test]
    fn private_names_do_not_enlarge_the_transport_namespace() {
        let names: Vec<_> = (0..MAX_PRIVATE_TREE_FILES)
            .map(|index| format!("incremental/f{index}"))
            .collect();
        assert!(validate_tree_names(names.iter().map(String::as_str)).is_err());
        assert_eq!(
            validate_private_tree_names(names.iter().map(String::as_str))
                .unwrap()
                .len(),
            MAX_PRIVATE_TREE_FILES
        );
        assert!(
            validate_private_tree_names(names.iter().map(String::as_str).chain(["overflow"]))
                .is_err()
        );
        for paths in [
            vec!["../state"],
            vec!["A/x", "a/y"],
            vec!["state", "state/x"],
        ] {
            assert!(validate_private_tree_names(paths).is_err());
        }
    }

    #[cfg(target_os = "linux")]
    fn private() -> tempfile::TempDir {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn inventory_admits_only_closed_internal_hardlinks() {
        use std::io::Read;
        let root = private();
        std::fs::create_dir(root.path().join("deps")).unwrap();
        std::fs::write(root.path().join("deps/app-hash"), b"binary\0\xff").unwrap();
        std::fs::hard_link(root.path().join("deps/app-hash"), root.path().join("app")).unwrap();
        let required = BTreeSet::from(["app".to_owned()]);
        let inventory = TreeInventory::scan(root.path(), &required, 100, &|| false).unwrap();
        assert_eq!(
            inventory.names().collect::<Vec<_>>(),
            vec!["app", "deps/app-hash"]
        );
        assert_eq!(inventory.total_bytes(), 16);
        let mut bytes = Vec::new();
        inventory
            .open_file("app")
            .unwrap()
            .read_to_end(&mut bytes)
            .unwrap();
        assert_eq!(bytes, b"binary\0\xff");
        let outside = private();
        std::fs::hard_link(root.path().join("app"), outside.path().join("alias")).unwrap();
        assert!(inventory.verify(&|| false).is_err());
        assert!(TreeInventory::scan(root.path(), &required, 100, &|| false).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn complete_private_inventory_does_not_relax_successful_artifact_requirements() {
        let root = private();
        assert!(TreeInventory::scan_complete(root.path(), 100, &|| false).is_err());
        std::fs::create_dir(root.path().join("deps")).unwrap();
        std::fs::write(root.path().join("deps/finished.rlib"), b"dependency").unwrap();
        let required = BTreeSet::from(["missing-final-binary".to_owned()]);
        assert!(TreeInventory::scan(root.path(), &required, 100, &|| false).is_err());
        assert!(TreeInventory::scan(root.path(), &BTreeSet::new(), 100, &|| false).is_err());
        let inventory = TreeInventory::scan_complete(root.path(), 100, &|| false).unwrap();
        assert_eq!(
            inventory.names().collect::<Vec<_>>(),
            ["deps/finished.rlib"]
        );
        assert!(TreeInventory::scan_complete(root.path(), 1, &|| false).is_err());
        assert!(TreeInventory::scan_complete(root.path(), 100, &|| true).is_err());
        let outside = private();
        std::fs::hard_link(
            root.path().join("deps/finished.rlib"),
            outside.path().join("alias"),
        )
        .unwrap();
        assert!(inventory.verify(&|| false).is_err());
        assert!(TreeInventory::scan_complete(root.path(), 100, &|| false).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn private_inventory_exceeds_transport_limits_with_complete_integrity_checks() {
        let root = private();
        std::fs::write(root.path().join("app"), b"app").unwrap();
        std::fs::create_dir(root.path().join("incremental")).unwrap();
        for index in 0..MAX_TREE_FILES {
            std::fs::write(root.path().join(format!("incremental/f{index}")), []).unwrap();
        }
        // Sparse file: prove the inventory's byte policy without allocating or
        // reading a large compiler-state payload in this test.
        let state = std::fs::File::create(root.path().join("incremental/query-cache.bin")).unwrap();
        let state_bytes = 1024 * 1024 * 1024 + 1;
        state.set_len(state_bytes).unwrap();
        let bytes = state_bytes + 3;
        let required = BTreeSet::from(["app".to_owned()]);
        assert!(TreeInventory::scan(root.path(), &required, bytes, &|| false).is_err());
        let inventory =
            TreeInventory::scan_private(root.path(), &required, bytes, &|| false).unwrap();
        assert_eq!(inventory.names().count(), MAX_TREE_FILES + 2);
        assert_eq!(inventory.total_bytes(), bytes);
        assert!(TreeInventory::scan_private(root.path(), &required, bytes - 1, &|| false).is_err());
        assert!(TreeInventory::scan_private(root.path(), &required, bytes, &|| true).is_err());
        let absent = BTreeSet::from(["missing".to_owned()]);
        assert!(TreeInventory::scan_private(root.path(), &absent, bytes, &|| false).is_err());
        assert!(
            TreeInventory::scan_private(root.path(), &BTreeSet::new(), bytes, &|| false).is_err()
        );
        assert!(TreeInventory::scan_complete_private(root.path(), bytes, &|| false).is_ok());

        let outside = private();
        std::fs::hard_link(
            root.path().join("incremental/f0"),
            outside.path().join("alias"),
        )
        .unwrap();
        assert!(inventory.verify(&|| false).is_err());
        assert!(TreeInventory::scan_private(root.path(), &required, bytes, &|| false).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn private_inventory_is_bounded_and_never_skips_special_files() {
        use std::os::unix::{fs::symlink, net::UnixListener};
        let required = BTreeSet::from(["app".to_owned()]);
        let large = private();
        std::fs::File::create(large.path().join("app"))
            .unwrap()
            .set_len(MAX_PRIVATE_TREE_BYTES + 1)
            .unwrap();
        assert!(TreeInventory::scan_private(large.path(), &required, u64::MAX, &|| false).is_err());
        assert!(TreeInventory::scan_complete_private(large.path(), u64::MAX, &|| false).is_err());

        let root = private();
        std::fs::write(root.path().join("app"), b"output").unwrap();
        std::fs::create_dir(root.path().join("incremental")).unwrap();
        let _socket = UnixListener::bind(root.path().join("incremental/socket")).unwrap();
        assert!(TreeInventory::scan_private(root.path(), &required, 100, &|| false).is_err());
        let links = private();
        std::fs::write(links.path().join("app"), b"output").unwrap();
        symlink(root.path(), links.path().join("incremental")).unwrap();
        assert!(TreeInventory::scan_private(links.path(), &required, 100, &|| false).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn missing_oversized_cancelled_and_nonregular_trees_refuse() {
        use std::os::unix::{fs::symlink, net::UnixListener};
        let required = BTreeSet::from(["app".to_owned()]);
        let root = private();
        assert!(TreeInventory::scan(root.path(), &required, 10, &|| false).is_err());
        std::fs::write(root.path().join("app"), b"12345").unwrap();
        assert!(TreeInventory::scan(root.path(), &required, 4, &|| false).is_err());
        assert!(TreeInventory::scan(root.path(), &required, 10, &|| true).is_err());
        let _socket = UnixListener::bind(root.path().join("socket")).unwrap();
        assert!(TreeInventory::scan(root.path(), &required, 10, &|| false).is_err());
        let links = private();
        symlink(root.path().join("app"), links.path().join("app")).unwrap();
        assert!(TreeInventory::scan(links.path(), &required, 10, &|| false).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn mutation_replacement_and_new_entries_invalidate_inventory() {
        let required = BTreeSet::from(["app".to_owned()]);
        for case in 0..3 {
            let root = private();
            std::fs::write(root.path().join("app"), b"first").unwrap();
            let inventory = TreeInventory::scan(root.path(), &required, 100, &|| false).unwrap();
            let file = inventory.open_file("app").unwrap();
            match case {
                0 => std::fs::write(root.path().join("app"), b"other").unwrap(),
                1 => {
                    std::fs::rename(root.path().join("app"), root.path().join("old")).unwrap();
                    std::fs::write(root.path().join("app"), b"first").unwrap();
                }
                _ => std::fs::create_dir(root.path().join("unexpected")).unwrap(),
            }
            assert!(inventory.verify(&|| false).is_err());
            if case == 0 {
                assert!(inventory.verify_file("app", &file).is_err());
            }
            if case < 2 {
                assert!(inventory.open_file("app").is_err());
            }
        }
    }
}
