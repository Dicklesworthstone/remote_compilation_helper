//! Descriptor-bound filesystem operation for local staging-tree collection.
//!
//! The caller holds the source registry transaction and has checked process
//! liveness. This helper does not grant that authority: it binds the claimed
//! physical candidate to the enumerated directory identities, repeats the exact
//! metadata/age check, and removes entries only through retained descriptors.
//! Source-content containers are never candidates. No file contents are read.

use std::ffi::OsString;
use std::io::{self, Write as _};

const REFUSED: i32 = 73;

/// Runs before the worker's async runtime and optional logging are started.
pub(crate) fn main(arguments: &[OsString]) -> i32 {
    #[cfg(unix)]
    let result = native::run(arguments);
    #[cfg(not(unix))]
    let result: Result<&str, ()> = {
        let _ = arguments;
        Err(())
    };
    let (verdict, status) = match result {
        Ok(verdict) => (verdict, 0),
        Err(()) => ("unavailable", REFUSED),
    };
    if writeln!(io::stdout().lock(), "{verdict}").is_err() {
        return REFUSED;
    }
    status
}

#[cfg(unix)]
mod native {
    use super::*;
    use rustix::fd::OwnedFd;
    use rustix::fs::{AtFlags, Dir, FileType, Mode, OFlags, Stat};
    use rustix::io::Errno;
    use serde::Deserialize;
    use sha2::{Digest as _, Sha256};
    use std::ffi::{CStr, CString};
    use std::os::unix::ffi::OsStrExt as _;
    use std::path::{Component, Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    const DIRECTORY_FLAGS: OFlags = OFlags::RDONLY
        .union(OFlags::DIRECTORY)
        .union(OFlags::NOFOLLOW)
        .union(OFlags::CLOEXEC);
    const MAX_WITNESS_BYTES: usize = 16 * 1024;
    // Refuse excessive traversal before any mutation. A bounded stack and
    // inventory keep an anomalous staging tree from exhausting the helper.
    const MAX_DEPTH: usize = 256;
    const MAX_ENTRIES: usize = 1_000_000;

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Identity {
        device: u64,
        inode: u64,
    }

    impl Identity {
        fn of(info: &Stat) -> Self {
            Self {
                #[cfg(target_os = "macos")]
                device: info.st_dev as u64,
                #[cfg(not(target_os = "macos"))]
                device: info.st_dev,
                inode: info.st_ino,
            }
        }
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Witness {
        canonical_base: PathBuf,
        base: Identity,
        parent: Identity,
        tree: Identity,
        metadata_digest: String,
    }

    enum Error {
        Changed,
        Unavailable,
    }

    impl From<Errno> for Error {
        fn from(error: Errno) -> Self {
            if matches!(error, Errno::NOENT | Errno::NOTDIR | Errno::LOOP) {
                Self::Changed
            } else {
                Self::Unavailable
            }
        }
    }

    impl From<io::Error> for Error {
        fn from(error: io::Error) -> Self {
            error
                .raw_os_error()
                .map(Errno::from_raw_os_error)
                .map(Self::from)
                .unwrap_or(Self::Unavailable)
        }
    }

    type Result<T> = std::result::Result<T, Error>;

    fn require(condition: bool) -> Result<()> {
        if condition {
            Ok(())
        } else {
            Err(Error::Changed)
        }
    }

    fn directory(info: &Stat) -> bool {
        FileType::from_raw_mode(info.st_mode) == FileType::Directory
    }

    // Must match rch::cache_gc::observe_tree byte-for-byte, including bytewise
    // name order, directory prefix order and signed sub-second timestamps.
    fn fields(info: &Stat) -> String {
        format!(
            "{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}\0",
            Identity::of(info).device,
            info.st_ino,
            info.st_mode,
            info.st_uid,
            info.st_gid,
            info.st_nlink,
            info.st_size as u64,
            info.st_mtime,
            info.st_mtime_nsec,
            info.st_ctime,
            info.st_ctime_nsec,
        )
    }

    fn mtime_ns(info: &Stat) -> i128 {
        i128::from(info.st_mtime) * 1_000_000_000 + i128::from(info.st_mtime_nsec)
    }

    fn record(digest: &mut Sha256, name: &[u8], info: &Stat) {
        digest.update((name.len() as u64).to_le_bytes());
        digest.update(name);
        digest.update(fields(info).as_bytes());
    }

    fn names(descriptor: &OwnedFd, remaining: &mut usize) -> Result<Vec<CString>> {
        let mut names = Vec::new();
        for entry in Dir::read_from(descriptor)? {
            let entry = entry?;
            let name = entry.file_name();
            if matches!(name.to_bytes(), b"." | b"..") {
                continue;
            }
            *remaining = remaining.checked_sub(1).ok_or(Error::Unavailable)?;
            names.push(name.to_owned());
        }
        names.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
        Ok(names)
    }

    fn named(descriptor: &OwnedFd, name: &CStr) -> Result<Stat> {
        Ok(rustix::fs::statat(
            descriptor,
            name,
            AtFlags::SYMLINK_NOFOLLOW,
        )?)
    }

    fn open_directory(parent: &OwnedFd, name: &CStr, expected: Identity) -> Result<OwnedFd> {
        let before = named(parent, name)?;
        require(directory(&before) && Identity::of(&before) == expected)?;
        let descriptor = rustix::fs::openat(parent, name, DIRECTORY_FLAGS, Mode::empty())?;
        let opened = rustix::fs::fstat(&descriptor)?;
        require(directory(&opened) && Identity::of(&opened) == expected)?;
        require(Identity::of(&named(parent, name)?) == expected)?;
        Ok(descriptor)
    }

    fn observe(
        descriptor: &OwnedFd,
        relative: &[u8],
        digest: &mut Sha256,
        remaining: &mut usize,
        depth: usize,
    ) -> Result<i128> {
        if depth > MAX_DEPTH {
            return Err(Error::Unavailable);
        }
        let before = rustix::fs::fstat(descriptor)?;
        record(digest, relative, &before);
        let mut newest = mtime_ns(&before);
        for name in names(descriptor, remaining)? {
            let current = named(descriptor, &name)?;
            let mut nested = relative.to_vec();
            if !nested.is_empty() {
                nested.push(b'/');
            }
            nested.extend_from_slice(name.as_bytes());
            if directory(&current) {
                let child = open_directory(descriptor, &name, Identity::of(&current))?;
                newest = newest.max(observe(&child, &nested, digest, remaining, depth + 1)?);
                require(fields(&named(descriptor, &name)?) == fields(&current))?;
            } else {
                record(digest, &nested, &current);
                newest = newest.max(mtime_ns(&current));
            }
        }
        require(fields(&rustix::fs::fstat(descriptor)?) == fields(&before))?;
        Ok(newest)
    }

    struct Anchor {
        name: CString,
        identity: Identity,
        descriptor: OwnedFd,
    }

    struct Tree<'a> {
        base_path: &'a Path,
        witness: &'a Witness,
        base: OwnedFd,
        chain: Vec<Anchor>,
    }

    impl Tree<'_> {
        fn descriptor(&self) -> &OwnedFd {
            self.chain
                .last()
                .map_or(&self.base, |anchor| &anchor.descriptor)
        }

        fn push(&mut self, name: CString, expected: Identity) -> Result<()> {
            let descriptor = open_directory(self.descriptor(), &name, expected)?;
            self.chain.push(Anchor {
                name,
                identity: expected,
                descriptor,
            });
            Ok(())
        }

        fn unchanged(&self) -> Result<()> {
            require(self.base_path.canonicalize()? == self.witness.canonical_base)?;
            let base = rustix::fs::stat(self.base_path)?;
            require(directory(&base) && Identity::of(&base) == self.witness.base)?;
            let mut parent = &self.base;
            for anchor in &self.chain {
                let current = named(parent, &anchor.name)?;
                require(directory(&current) && Identity::of(&current) == anchor.identity)?;
                parent = &anchor.descriptor;
            }
            Ok(())
        }

        fn remove_contents(&mut self, remaining: &mut usize, depth: usize) -> Result<()> {
            if depth > MAX_DEPTH {
                return Err(Error::Unavailable);
            }
            for name in names(self.descriptor(), remaining)? {
                self.unchanged()?;
                let info = named(self.descriptor(), &name)?;
                if directory(&info) {
                    self.push(name.clone(), Identity::of(&info))?;
                    self.remove_contents(remaining, depth + 1)?;
                    self.unchanged()?;
                    let removed = self.chain.pop().ok_or(Error::Unavailable)?;
                    rustix::fs::unlinkat(self.descriptor(), &*removed.name, AtFlags::REMOVEDIR)?;
                } else {
                    rustix::fs::unlinkat(self.descriptor(), &*name, AtFlags::empty())?;
                }
            }
            Ok(())
        }
    }

    fn absolute_clean(path: &Path) -> bool {
        path.is_absolute()
            && !path
                .as_os_str()
                .as_bytes()
                .split(|byte| *byte == b'/')
                .any(|component| matches!(component, b"." | b".."))
    }

    fn collect(
        path: &Path,
        base: &Path,
        apply: bool,
        witness: &Witness,
        minimum: u128,
        claimed: &Path,
    ) -> Result<&'static str> {
        require(absolute_clean(path) && absolute_clean(base))?;
        let relative = path.strip_prefix(base).map_err(|_| Error::Changed)?;
        let components = relative.components().collect::<Vec<_>>();
        let [Component::Normal(project), Component::Normal(hash)] = components.as_slice() else {
            return Err(Error::Changed);
        };
        require(!project.as_bytes().starts_with(b"source-content-"))?;
        require(claimed == witness.canonical_base.join(project).join(hash))?;
        require(base.canonicalize()? == witness.canonical_base)?;
        let base_descriptor =
            rustix::fs::open(&witness.canonical_base, DIRECTORY_FLAGS, Mode::empty())?;
        require(Identity::of(&rustix::fs::fstat(&base_descriptor)?) == witness.base)?;
        let mut tree = Tree {
            base_path: base,
            witness,
            base: base_descriptor,
            chain: Vec::new(),
        };
        tree.push(
            CString::new(project.as_bytes()).map_err(|_| Error::Changed)?,
            witness.parent,
        )?;
        tree.push(
            CString::new(hash.as_bytes()).map_err(|_| Error::Changed)?,
            witness.tree,
        )?;
        require(
            rustix::fs::fstat(tree.descriptor())?.st_uid == rustix::process::geteuid().as_raw(),
        )?;
        tree.unchanged()?;
        if !apply {
            return Ok("ready");
        }
        let mut digest = Sha256::new();
        digest.update(b"rch-staging-metadata-v1\0");
        let mut remaining = MAX_ENTRIES;
        let newest = observe(tree.descriptor(), b"", &mut digest, &mut remaining, 0)?;
        let observed_digest: String = digest
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        require(observed_digest == witness.metadata_digest)?;
        tree.unchanged()?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::Unavailable)?
            .as_nanos();
        let age = i128::try_from(now)
            .ok()
            .and_then(|now| now.checked_sub(newest))
            .and_then(|age| u128::try_from(age).ok());
        if age.is_none_or(|age| age < minimum) {
            return Ok("recent");
        }
        let mut remaining = MAX_ENTRIES;
        tree.remove_contents(&mut remaining, 0)?;
        tree.unchanged()?;
        let removed = tree.chain.pop().ok_or(Error::Unavailable)?;
        rustix::fs::unlinkat(tree.descriptor(), &*removed.name, AtFlags::REMOVEDIR)?;
        rustix::fs::fsync(tree.descriptor())?;
        Ok("removed")
    }

    pub(super) fn run(arguments: &[OsString]) -> std::result::Result<&'static str, ()> {
        let [
            protocol,
            version,
            path,
            base,
            mode,
            encoded,
            minimum,
            claimed,
        ] = arguments
        else {
            return Err(());
        };
        if protocol != "--protocol" || version != "v1" {
            return Err(());
        }
        let apply = match mode.to_str() {
            Some("preview") => false,
            Some("apply") => true,
            _ => return Err(()),
        };
        let encoded = encoded.as_os_str().as_bytes();
        if encoded.len() > MAX_WITNESS_BYTES {
            return Err(());
        }
        let witness: Witness = serde_json::from_slice(encoded).map_err(|_| ())?;
        let minimum = minimum.to_str().ok_or(())?;
        if minimum.is_empty() || !minimum.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(());
        }
        let minimum = minimum.parse::<u128>().map_err(|_| ())?;
        if !absolute_clean(&witness.canonical_base)
            || witness.metadata_digest.len() != 64
            || !witness
                .metadata_digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(());
        }
        Ok(
            match collect(
                Path::new(path),
                Path::new(base),
                apply,
                &witness,
                minimum,
                Path::new(claimed),
            ) {
                Ok(verdict) => verdict,
                Err(Error::Changed) => "changed",
                Err(Error::Unavailable) => "unavailable",
            },
        )
    }
}
