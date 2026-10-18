//! Closed non-toolchain loader directories for path-preserving leaf rustc.
//!
//! A worker replaces these exact LD_LIBRARY_PATH entries with private empty
//! directories. The edge must first prove that this cannot hide a dynamic
//! loader candidate. Checks are fresh bounded observations, not a cache of
//! directory inode generations: ordinary Cargo .rmeta/.rlib/.d creation is
//! harmless, while any later loader candidate prevents dispatch or serving.
//! The caller must retain this witness and recheck it at each execution,
//! publication and installation boundary. It is not a filesystem lock.

use std::io;
use std::path::Path;

/// Maximum distinct non-toolchain loader roots in one compiler environment.
pub const MAX_LOADER_DIRECTORIES: usize = 64;
/// Aggregate entries examined across all roots in each fresh validation.
pub const MAX_LOADER_DIRECTORY_ENTRIES: usize = 16_384;

/// Exact original loader paths whose safe absence must continue to hold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoaderDirectoryWitness {
    directories: Vec<String>,
}

impl LoaderDirectoryWitness {
    /// Sorted, deduplicated original paths, suitable for the worker context.
    #[must_use]
    pub fn directories(&self) -> &[String] {
        &self.directories
    }

    /// Reobserve safe loader-candidate absence after possible Cargo writes.
    ///
    /// This intentionally accepts a changed directory generation if the newly
    /// observed complete contents remain safe. It never adopts changed source
    /// compiler/toolchain bytes; those have separate retained identity guards.
    pub fn verify_absence(&self, stopped: impl Fn() -> bool) -> io::Result<()> {
        observe(&self.directories, &stopped)
    }
}

/// Observe every exact non-toolchain entry before replacing it on a worker.
///
/// Only regular Cargo dependency artifacts (.rmeta, .rlib and .d) and known
/// Cargo marker files are ignored, and even those must not contain ELF magic.
/// Symlinks, special nodes, loader-looking names and unknown files refuse.
/// Ordinary Cargo structural subdirectories are ignored: glibc does not search
/// build/deps/examples/incremental/.fingerprint as hardware-capability suffixes.
/// Every other child directory refuses, including tls, glibc-hwcaps and platform
/// directories, so optimized DSOs cannot hide below a nominally empty root.
///
/// A missing path is accepted only when anchored no-symlink resolution reports
/// ENOENT. Permission errors, symlink ancestors, non-directories, mount changes,
/// cancellation and incomplete/unstable enumeration all refuse.
pub fn observe_loader_directories(
    directories: &[String],
    stopped: impl Fn() -> bool,
) -> io::Result<LoaderDirectoryWitness> {
    if directories.len() > MAX_LOADER_DIRECTORIES {
        return Err(invalid("too many private loader directories"));
    }
    let mut directories = directories.to_vec();
    for directory in &directories {
        if !normalized_absolute(directory) {
            return Err(invalid(
                "loader directory must be a normalized absolute path",
            ));
        }
    }
    directories.sort();
    directories.dedup();
    let witness = LoaderDirectoryWitness { directories };
    witness.verify_absence(stopped)?;
    Ok(witness)
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn normalized_absolute(path: &str) -> bool {
    path.starts_with('/')
        && path.len() > 1
        && path.len() <= 4096
        && !path.contains('\0')
        && path[1..]
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

fn checkpoint(stopped: &impl Fn() -> bool) -> io::Result<()> {
    if stopped() {
        Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "loader directory observation interrupted",
        ))
    } else {
        Ok(())
    }
}

#[cfg(not(target_os = "linux"))]
fn observe(directories: &[String], stopped: &impl Fn() -> bool) -> io::Result<()> {
    let _ = (directories, stopped);
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "closed loader directories require Linux openat2",
    ))
}

#[cfg(target_os = "linux")]
fn observe(directories: &[String], stopped: &impl Fn() -> bool) -> io::Result<()> {
    linux::observe(directories, stopped)
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use rustix::fs::{CWD, Dir, Mode, OFlags, ResolveFlags, openat2};
    use std::fs::{File, Metadata};
    use std::io::Read;
    use std::os::unix::fs::MetadataExt;

    #[derive(Debug, PartialEq, Eq)]
    struct Stamp {
        device: u64,
        inode: u64,
        mode: u32,
        links: u64,
        size: u64,
        modified: (i64, i64),
        changed: (i64, i64),
    }

    impl Stamp {
        fn of(metadata: &Metadata) -> Self {
            Self {
                device: metadata.dev(),
                inode: metadata.ino(),
                mode: metadata.mode(),
                links: metadata.nlink(),
                size: metadata.len(),
                modified: (metadata.mtime(), metadata.mtime_nsec()),
                changed: (metadata.ctime(), metadata.ctime_nsec()),
            }
        }
    }

    fn root(path: &Path) -> io::Result<Option<File>> {
        match openat2(
            CWD,
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_SYMLINKS,
        ) {
            Ok(file) => Ok(Some(File::from(file))),
            Err(rustix::io::Errno::NOENT) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    fn entry(directory: &File, name: &str, flags: OFlags) -> io::Result<File> {
        Ok(File::from(openat2(
            directory,
            name,
            flags | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_XDEV,
        )?))
    }

    fn loader_name(name: &str) -> bool {
        let lower = name.to_ascii_lowercase();
        lower.contains(".so") || lower.ends_with(".dylib") || lower.ends_with(".dll")
    }

    fn cargo_file(name: &str) -> bool {
        matches!(name, ".cargo-lock" | "CACHEDIR.TAG" | ".rustc_info.json")
            || [".rmeta", ".rlib", ".d"]
                .iter()
                .any(|suffix| name.ends_with(suffix))
    }

    fn cargo_directory(name: &str) -> bool {
        matches!(
            name,
            "deps" | "build" | "examples" | "incremental" | ".fingerprint"
        )
    }

    fn regular_is_safe(directory: &File, name: &str, expected: &Stamp) -> io::Result<()> {
        if !cargo_file(name) {
            return Err(invalid(
                "loader directory contains an unmodeled regular file",
            ));
        }
        let mut held = entry(
            directory,
            name,
            OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOCTTY,
        )?;
        if Stamp::of(&held.metadata()?) != *expected {
            return Err(invalid("loader entry changed before header observation"));
        }
        let mut header = [0_u8; 4];
        let mut used = 0;
        while used < header.len() {
            let count = held.read(&mut header[used..])?;
            if count == 0 {
                break;
            }
            used += count;
        }
        if header == *b"\x7fELF" {
            return Err(invalid("loader directory contains an ELF object"));
        }
        if Stamp::of(&held.metadata()?) != *expected
            || Stamp::of(&entry(directory, name, OFlags::PATH)?.metadata()?) != *expected
        {
            return Err(invalid("loader entry changed during header observation"));
        }
        Ok(())
    }

    fn one(path: &Path, remaining: &mut usize, stopped: &impl Fn() -> bool) -> io::Result<()> {
        checkpoint(stopped)?;
        let Some(directory) = root(path)? else {
            // Re-resolve once at the boundary: a just-created directory must be
            // observed, never silently accepted using an earlier absence.
            if root(path)?.is_some() {
                return Err(invalid("loader directory appeared during observation"));
            }
            return Ok(());
        };
        let before = Stamp::of(&directory.metadata()?);
        let mut entries = Dir::read_from(&directory)?;
        let mut observed = Vec::new();
        while let Some(next) = entries.read() {
            checkpoint(stopped)?;
            let next = next?;
            if matches!(next.file_name().to_bytes(), b"." | b"..") {
                continue;
            }
            *remaining = remaining
                .checked_sub(1)
                .ok_or_else(|| invalid("loader directory inventory exceeds its bound"))?;
            let name = next
                .file_name()
                .to_str()
                .map_err(|_| invalid("non-UTF-8 loader directory entry"))?;
            if loader_name(name) {
                return Err(invalid("loader directory contains a dynamic-library name"));
            }
            let held = entry(&directory, name, OFlags::PATH)?;
            let metadata = held.metadata()?;
            let stamp = Stamp::of(&metadata);
            if metadata.is_file() {
                regular_is_safe(&directory, name, &stamp)?;
            } else if !metadata.is_dir() || !cargo_directory(name) {
                // Symlinks never inherit their target's safety; any unmodeled
                // directory may be a glibc platform/hwcaps search suffix.
                return Err(invalid("loader directory contains an unmodeled node"));
            }
            observed.push((name.to_owned(), stamp));
        }
        for (name, expected) in observed {
            checkpoint(stopped)?;
            if Stamp::of(&entry(&directory, &name, OFlags::PATH)?.metadata()?) != expected {
                return Err(invalid("loader directory entry changed during enumeration"));
            }
        }
        checkpoint(stopped)?;
        let current = root(path)?.ok_or_else(|| invalid("loader directory disappeared"))?;
        if Stamp::of(&directory.metadata()?) != before || Stamp::of(&current.metadata()?) != before
        {
            return Err(invalid(
                "loader directory generation changed during enumeration",
            ));
        }
        Ok(())
    }

    pub(super) fn observe(directories: &[String], stopped: &impl Fn() -> bool) -> io::Result<()> {
        checkpoint(stopped)?;
        let mut remaining = MAX_LOADER_DIRECTORY_ENTRIES;
        for directory in directories {
            one(Path::new(directory), &mut remaining, stopped)?;
        }
        Ok(())
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::symlink;

    fn roots(path: &Path) -> Vec<String> {
        vec![path.to_str().unwrap().to_owned()]
    }

    #[test]
    fn cargo_check_layout_accepts_fresh_metadata_but_never_later_loader_candidates() {
        let root = tempfile::tempdir().unwrap();
        for directory in ["deps", "build", "examples", "incremental", ".fingerprint"] {
            fs::create_dir(root.path().join(directory)).unwrap();
        }
        // Build-script executables are under a structural directory that the
        // dynamic loader does not search as an HWCAP suffix.
        fs::write(root.path().join("build/build-script"), b"\x7fELF").unwrap();
        fs::write(root.path().join(".cargo-lock"), b"").unwrap();
        let mut selected = roots(root.path());
        selected.push(root.path().join("deps").to_str().unwrap().to_owned());
        let witness = observe_loader_directories(&selected, || false).unwrap();
        fs::write(root.path().join("deps/leaf.rmeta"), b"rust metadata").unwrap();
        fs::write(root.path().join("deps/leaf.d"), b"leaf.rmeta: src/lib.rs\n").unwrap();
        witness.verify_absence(|| false).unwrap();
        fs::write(root.path().join("deps/librustc_driver.so"), b"not even ELF").unwrap();
        assert!(witness.verify_absence(|| false).is_err());
    }

    #[test]
    fn renamed_elf_aliases_and_hwcaps_are_not_silently_treated_as_empty() {
        for mutation in 0..5 {
            let root = tempfile::tempdir().unwrap();
            let witness = observe_loader_directories(&roots(root.path()), || false).unwrap();
            match mutation {
                0 => fs::write(root.path().join("innocent.rmeta"), b"\x7fELFhidden").unwrap(),
                1 => fs::write(root.path().join("unknown-candidate"), b"not ELF").unwrap(),
                2 => {
                    fs::write(root.path().join("leaf.rmeta"), b"metadata").unwrap();
                    symlink("leaf.rmeta", root.path().join("alias.rmeta")).unwrap();
                }
                3 => {
                    fs::create_dir(root.path().join("glibc-hwcaps")).unwrap();
                    fs::create_dir(root.path().join("glibc-hwcaps/x86-64-v3")).unwrap();
                    fs::write(
                        root.path().join("glibc-hwcaps/x86-64-v3/libc.so.6"),
                        b"\x7fELF",
                    )
                    .unwrap();
                }
                _ => {
                    fs::create_dir(root.path().join("tls")).unwrap();
                }
            }
            assert!(
                witness.verify_absence(|| false).is_err(),
                "mutation {mutation}"
            );
        }
    }

    #[test]
    fn missing_roots_reobserve_creation_and_refuse_symlink_ancestors() {
        let root = tempfile::tempdir().unwrap();
        let missing = root.path().join("debug/deps");
        let witness = observe_loader_directories(&roots(&missing), || false).unwrap();
        fs::create_dir_all(&missing).unwrap();
        fs::write(missing.join("leaf.d"), b"leaf: src/lib.rs\n").unwrap();
        witness.verify_absence(|| false).unwrap();
        let alias = root.path().join("alias");
        symlink(root.path().join("debug"), &alias).unwrap();
        assert!(observe_loader_directories(&roots(&alias.join("deps")), || false).is_err());
        fs::write(missing.join("libnew.so.1"), b"loader candidate").unwrap();
        assert!(witness.verify_absence(|| false).is_err());
    }

    #[test]
    fn invalid_paths_bounds_and_cancellation_never_establish_absence() {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().to_str().unwrap().to_owned();
        assert_eq!(
            observe_loader_directories(&[directory.clone()], || true)
                .unwrap_err()
                .kind(),
            io::ErrorKind::Interrupted
        );
        for path in ["", "/", "relative", "/tmp/../other", "/tmp//other", "/tmp/"] {
            assert!(observe_loader_directories(&[path.to_owned()], || false).is_err());
        }
        assert!(
            observe_loader_directories(&vec![directory; MAX_LOADER_DIRECTORIES + 1], || false,)
                .is_err()
        );
        let witness = observe_loader_directories(&roots(root.path()), || false).unwrap();
        assert_eq!(
            witness.verify_absence(|| true).unwrap_err().kind(),
            io::ErrorKind::Interrupted
        );
    }
}
