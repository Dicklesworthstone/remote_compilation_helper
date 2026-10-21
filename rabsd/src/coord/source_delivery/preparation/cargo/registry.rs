//! Offline crates.io archive capture from an explicitly approved Cargo home.
//!
//! A lockfile selects package identities; its SHA-256 checksums select archive
//! bytes. Cargo remains the resolver and consumes only a fresh private home.
//! Expanded user sources, credentials, Cargo configuration and unrelated
//! index entries are never opened. This supplies inputs, not cache authority.

use super::{MAX_PACKAGES, OUTPUT_LIMIT, git, invalid, require, validate_manifest_paths};
use flate2::read::MultiGzDecoder;
use rabs_sandbox::snapshot_capture::{MemberKind, SealedSourceSnapshot};
use rabs_sandbox::source_transfer::{MAX_SOURCE_BYTES, MAX_SOURCE_FILES};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};

pub(super) const CACHE_PREFIX: &str = "rabs-cargo-home";
const CRATES_IO: &str = "registry+https://github.com/rust-lang/crates.io-index";
const MAX_NAMESPACES: usize = 8;
pub(super) const MAX_ARCHIVE_MEMBERS: usize = 100_000;

type PackageIdentity = (String, String);
type LockedPackages = BTreeMap<PackageIdentity, [u8; 32]>;

fn archive_checksum(value: &str) -> io::Result<[u8; 32]> {
    require(
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "source digest must be 64 lowercase hex digits",
    )?;
    let mut digest = [0_u8; 32];
    for (slot, pair) in digest.iter_mut().zip(value.as_bytes().as_chunks::<2>().0) {
        let digit = |byte: u8| {
            if byte <= b'9' {
                byte - b'0'
            } else {
                byte - b'a' + 10
            }
        };
        *slot = (digit(pair[0]) << 4) | digit(pair[1]);
    }
    Ok(digest)
}

pub(super) fn approved_home(value: &Value) -> io::Result<PathBuf> {
    let text = value
        .as_str()
        .filter(|path| {
            !path.is_empty()
                && path.len() <= 4096
                && !path.contains(['\\', ':'])
                && !path.chars().any(char::is_control)
                && path.strip_prefix('/').is_some_and(|path| {
                    path.split('/')
                        .all(|part| !part.is_empty() && !matches!(part, "." | ".."))
                })
        })
        .ok_or_else(|| {
            invalid("cargo_home_source must be an absolute ordinary directory without traversal")
        })?;
    let path = PathBuf::from(text);
    let _directory = open_home(&path)?;
    Ok(path)
}

fn canonical_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte))
}

fn canonical_version(version: &str) -> bool {
    !version.is_empty()
        && version.len() <= 128
        && version
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b".-+".contains(&byte))
        && version.as_bytes()[0].is_ascii_digit()
}

pub(super) fn validate_lock_sources(lock: &toml::Value) -> io::Result<()> {
    locked_packages(lock).map(|_| ())
}

fn locked_packages(lock: &toml::Value) -> io::Result<LockedPackages> {
    let packages = lock
        .get("package")
        .and_then(toml::Value::as_array)
        .filter(|packages| packages.len() <= MAX_PACKAGES)
        .ok_or_else(|| {
            invalid("cached registry capture requires a bounded Cargo.lock package list")
        })?;
    let mut selected = BTreeMap::new();
    let mut identities = BTreeSet::new();
    for package in packages {
        let name = package
            .get("name")
            .and_then(toml::Value::as_str)
            .filter(|name| canonical_name(name))
            .ok_or_else(|| invalid("invalid locked package name"))?;
        let version = package
            .get("version")
            .and_then(toml::Value::as_str)
            .filter(|version| canonical_version(version))
            .ok_or_else(|| invalid("invalid locked package version"))?;
        let source = package
            .get("source")
            .map(|source| {
                source
                    .as_str()
                    .ok_or_else(|| invalid("invalid locked package source"))
            })
            .transpose()?;
        if let Some(source) = source
            && source != CRATES_IO
        {
            git::locked_revision(source)?;
            require(
                package.get("checksum").is_none(),
                "locked Git package must not carry a registry checksum",
            )?;
        }
        require(
            identities.insert((name, version, source)),
            "duplicate locked package identity",
        )?;
        if source == Some(CRATES_IO) {
            let checksum = package
                .get("checksum")
                .and_then(toml::Value::as_str)
                .ok_or_else(|| invalid("locked crates.io package requires a SHA-256 checksum"))?;
            let digest = archive_checksum(checksum)?;
            require(
                selected
                    .insert((name.to_owned(), version.to_owned()), digest)
                    .is_none(),
                "ambiguous locked crates.io package identity",
            )?;
        }
    }
    Ok(selected)
}

#[cfg(unix)]
pub(super) fn open_home(path: &Path) -> io::Result<File> {
    use rustix::fs::{Mode, OFlags, open, openat};
    require(path.is_absolute(), "Cargo cache root must be absolute")?;
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut directory = File::from(open("/", flags, Mode::empty())?);
    for part in path.components() {
        match part {
            Component::RootDir => {}
            Component::Normal(name) => {
                directory = File::from(openat(&directory, name, flags, Mode::empty())?)
            }
            _ => return Err(invalid("Cargo cache root contains traversal")),
        }
    }
    Ok(directory)
}

#[cfg(not(unix))]
pub(super) fn open_home(_path: &Path) -> io::Result<File> {
    Err(invalid(
        "cached registry capture requires descriptor-relative Unix filesystem access",
    ))
}

#[cfg(unix)]
pub(super) fn open_selected(root: &File, path: &str, directory: bool) -> io::Result<File> {
    use rustix::fs::{Mode, OFlags, openat};
    let components: Vec<_> = path.split('/').collect();
    require(
        components
            .iter()
            .all(|part| !part.is_empty() && !matches!(*part, "." | "..")),
        "invalid selected Cargo cache path",
    )?;
    let mut current = root.try_clone()?;
    for (index, name) in components.iter().enumerate() {
        let mut flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK;
        if directory || index + 1 < components.len() {
            flags |= OFlags::DIRECTORY;
        }
        current = File::from(openat(&current, *name, flags, Mode::empty())?);
    }
    Ok(current)
}

#[cfg(not(unix))]
pub(super) fn open_selected(_root: &File, _path: &str, _directory: bool) -> io::Result<File> {
    Err(invalid(
        "cached registry capture requires descriptor-relative Unix filesystem access",
    ))
}

fn read_selected(root: &File, path: &str, limit: u64) -> io::Result<Vec<u8>> {
    let mut file = open_selected(root, path, false)?;
    let before = file.metadata()?;
    require(
        before.is_file() && before.len() <= limit,
        "selected Cargo cache file is not a bounded regular file",
    )?;
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(limit.saturating_add(1))
        .read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    require(
        bytes.len() as u64 == before.len() && before.len() == after.len(),
        "selected Cargo cache file changed during capture",
    )?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        require(
            before.dev() == after.dev()
                && before.ino() == after.ino()
                && before.mtime() == after.mtime()
                && before.mtime_nsec() == after.mtime_nsec()
                && before.ctime() == after.ctime()
                && before.ctime_nsec() == after.ctime_nsec(),
            "selected Cargo cache file changed during capture",
        )?;
    }
    Ok(bytes)
}

fn index_namespaces(root: &File) -> io::Result<Vec<String>> {
    #[cfg(unix)]
    {
        let directory = open_selected(root, "registry/index", true)?;
        let mut names = BTreeSet::new();
        for (index, entry) in rustix::fs::Dir::read_from(&directory)?.enumerate() {
            require(
                index < 256,
                "Cargo registry index directory exceeds the namespace scan bound",
            )?;
            let entry = entry?;
            let Ok(name) = entry.file_name().to_str() else {
                continue;
            };
            if name.strip_prefix("index.crates.io-").is_some_and(|suffix| {
                suffix.len() == 16
                    && suffix
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            }) {
                names.insert(name.to_owned());
                require(
                    names.len() <= MAX_NAMESPACES,
                    "too many cached crates.io sparse index namespaces",
                )?;
            }
        }
        require(
            !names.is_empty(),
            "approved Cargo home has no crates.io sparse index cache",
        )?;
        Ok(names.into_iter().collect())
    }
    #[cfg(not(unix))]
    {
        let _ = root;
        Err(invalid("cached registry capture requires Unix"))
    }
}

fn index_record(name: &str) -> String {
    let name = name.to_ascii_lowercase();
    match name.len() {
        1 => format!("1/{name}"),
        2 => format!("2/{name}"),
        3 => format!("3/{}/{name}", &name[..1]),
        _ => format!("{}/{}/{name}", &name[..2], &name[2..4]),
    }
}

fn validate_index_config(bytes: &[u8]) -> io::Result<()> {
    let value: Value = serde_json::from_slice(bytes)
        .map_err(|_| invalid("cached crates.io index config is not JSON"))?;
    require(
        value.as_object().is_some_and(|fields| {
            fields
                .keys()
                .all(|key| matches!(key.as_str(), "dl" | "api" | "auth-required"))
        }) && value["dl"].as_str().is_some_and(|url| {
            matches!(
                url,
                "https://static.crates.io/crates" | "https://static.crates.io/crates/"
            )
        }) && value
            .get("api")
            .is_none_or(|api| api == "https://crates.io")
            && value.get("auth-required").is_none_or(|auth| auth == false),
        "cached registry capture requires the public crates.io index configuration",
    )
}

struct ArchiveBudget<R> {
    reader: R,
    consumed: u64,
    limit: u64,
}

impl<R: Read> Read for ArchiveBudget<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        let remaining = self.limit.saturating_sub(self.consumed);
        if remaining == 0 {
            let mut probe = [0_u8];
            require(
                self.reader.read(&mut probe)? == 0,
                "registry archives exceed the decompressed byte budget",
            )?;
            return Ok(0);
        }
        let available = buffer.len().min(remaining as usize);
        let count = self.reader.read(&mut buffer[..available])?;
        self.consumed += count as u64;
        Ok(count)
    }
}

#[derive(Debug)]
struct CapturedPackage {
    members: BTreeMap<String, (u64, [u8; 32])>,
}

fn inspect_archive(
    bytes: &[u8],
    name: &str,
    version: &str,
    remaining: &mut u64,
    member_count: &mut usize,
) -> io::Result<CapturedPackage> {
    let top = format!("{name}-{version}");
    // Count *all* decompressed bytes, including GNU/PAX metadata consumed inside
    // the tar iterator and padding after its end marker, before trusting sizes.
    let reader = ArchiveBudget {
        reader: MultiGzDecoder::new(bytes),
        consumed: 0,
        limit: *remaining,
    };
    let mut archive = tar::Archive::new(reader);
    let mut paths = BTreeSet::new();
    let mut directories = BTreeSet::new();
    let mut members = BTreeMap::new();
    let mut manifest = None;
    for entry in archive.entries()? {
        let mut entry = entry?;
        *member_count = member_count
            .checked_add(1)
            .filter(|count| *count <= MAX_ARCHIVE_MEMBERS)
            .ok_or_else(|| invalid("registry archives exceed the member-count bound"))?;
        let kind = entry.header().entry_type();
        require(
            kind.is_file() || kind.is_dir(),
            "registry archive contains a link or unsupported member type",
        )?;
        let raw = entry.path_bytes();
        let path = std::str::from_utf8(raw.as_ref())
            .map_err(|_| invalid("registry archive path is not UTF-8"))?;
        let path = if kind.is_dir() {
            path.strip_suffix('/').unwrap_or(path)
        } else {
            path
        };
        require(
            !path.is_empty()
                && path.len() <= 1024
                && !path.contains(['\\', ':'])
                && !path.chars().any(char::is_control)
                && path.split('/').count() <= 32
                && path
                    .split('/')
                    .all(|part| !part.is_empty() && !matches!(part, "." | "..")),
            "registry archive has an unsafe or noncanonical path",
        )?;
        require(
            paths.insert(path.to_owned()),
            "registry archive repeats a member path",
        )?;
        require(
            path == top && kind.is_dir() || path.starts_with(&format!("{top}/")),
            "registry archive does not belong to its locked name and version",
        )?;
        for (offset, _) in path.match_indices('/') {
            directories.insert(path[..offset].to_owned());
        }
        if kind.is_dir() {
            require(
                entry.size() == 0,
                "registry archive directory contains payload bytes",
            )?;
            directories.insert(path.to_owned());
            continue;
        }
        let path = path.to_owned();
        let relative = path
            .strip_prefix(&format!("{top}/"))
            .ok_or_else(|| invalid("registry archive package root is not a directory"))?;
        require(
            entry.size() <= *remaining,
            "registry archive file exceeds its decompressed byte budget",
        )?;
        let mut hash = Sha256::new();
        let mut length = 0_u64;
        let mut buffer = [0_u8; 16 * 1024];
        let mut manifest_bytes = Vec::new();
        loop {
            let count = entry.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            hash.update(&buffer[..count]);
            length += count as u64;
            if relative == "Cargo.toml" {
                require(
                    length <= OUTPUT_LIMIT,
                    "registry package manifest exceeds its bound",
                )?;
                manifest_bytes.extend_from_slice(&buffer[..count]);
            }
        }
        require(
            length == entry.size(),
            "registry archive member is truncated",
        )?;
        members.insert(relative.to_owned(), (length, hash.finalize().into()));
        if relative == "Cargo.toml" {
            manifest = Some(manifest_bytes);
        }
    }
    require(
        members
            .keys()
            .all(|path| !directories.contains(&format!("{top}/{path}"))),
        "registry archive file is also a parent directory",
    )?;
    let mut reader = archive.into_inner();
    let mut padding = [0_u8; 16 * 1024];
    loop {
        let count = reader.read(&mut padding)?;
        if count == 0 {
            break;
        }
        require(
            padding[..count].iter().all(|byte| *byte == 0),
            "registry archive has non-padding bytes after its tar end marker",
        )?;
    }
    *remaining = remaining
        .checked_sub(reader.consumed)
        .ok_or_else(|| invalid("registry archive decompressed budget overflow"))?;
    let bytes = manifest.ok_or_else(|| invalid("registry archive has no root Cargo.toml"))?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| invalid("registry package manifest is not UTF-8"))?;
    let manifest: toml::Value =
        toml::from_str(text).map_err(|_| invalid("registry package manifest is malformed"))?;
    require(
        manifest
            .get("package")
            .and_then(|package| package.get("name"))
            .and_then(toml::Value::as_str)
            == Some(name)
            && manifest
                .get("package")
                .and_then(|package| package.get("version"))
                .and_then(toml::Value::as_str)
                == Some(version),
        "registry package manifest differs from its locked name or version",
    )?;
    validate_manifest_paths(Path::new(""), &manifest, None, false)?;
    Ok(CapturedPackage { members })
}

#[derive(Debug)]
pub(super) struct RegistryCache {
    lock: PathBuf,
    files: BTreeMap<String, Vec<u8>>,
    packages: BTreeMap<(String, String, String), CapturedPackage>,
    git: Option<git::GitCache>,
}

impl RegistryCache {
    pub(super) fn capture(
        image: &SealedSourceSnapshot,
        lock: &Path,
        approved: &Path,
        cargo_home: &Path,
    ) -> io::Result<Self> {
        let lock_path = lock
            .to_str()
            .ok_or_else(|| invalid("non-UTF-8 Cargo lock path"))?;
        let bytes = image
            .file_bytes("workspace", lock_path)
            .filter(|bytes| bytes.len() <= OUTPUT_LIMIT as usize)
            .ok_or_else(|| {
                invalid("cached registry capture requires the retained workspace Cargo.lock")
            })?;
        let lock_value: toml::Value = toml::from_str(
            std::str::from_utf8(bytes).map_err(|_| invalid("Cargo lock is not UTF-8"))?,
        )
        .map_err(|_| invalid("Cargo lock is malformed"))?;
        let locked = locked_packages(&lock_value)?;
        require(
            !locked.is_empty() || git::has_locked_packages(&lock_value),
            "cargo_home_source requires at least one locked crates.io or full-revision Git package",
        )?;
        let workspace = image
            .manifest("workspace")
            .ok_or_else(|| invalid("missing captured Cargo workspace"))?;
        let mut remaining = MAX_SOURCE_BYTES;
        let mut file_count = 0_usize;
        for member in workspace.members.values() {
            if let MemberKind::Regular { size, .. } = member {
                remaining = remaining
                    .checked_sub(*size)
                    .ok_or_else(|| invalid("Cargo source exceeds its byte budget"))?;
                file_count += 1;
            }
        }
        let root = open_home(approved)?;
        let namespaces = if locked.is_empty() {
            Vec::new()
        } else {
            index_namespaces(&root)?
        };
        let mut captured = Self {
            lock: lock.to_path_buf(),
            files: BTreeMap::new(),
            packages: BTreeMap::new(),
            git: None,
        };
        let mut found = BTreeSet::new();
        let mut expanded_remaining = MAX_SOURCE_BYTES;
        let mut expanded_members = 0_usize;
        for namespace in namespaces {
            let config_path = format!("registry/index/{namespace}/config.json");
            let mut namespace_used = false;
            for ((name, version), expected) in &locked {
                let path = format!("registry/cache/{namespace}/{name}-{version}.crate");
                let bytes = match read_selected(&root, &path, remaining) {
                    Ok(bytes) => bytes,
                    Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                    Err(error) => return Err(error),
                };
                require(
                    <[u8; 32]>::from(Sha256::digest(&bytes)) == *expected,
                    "cached crate archive checksum does not match the retained Cargo.lock",
                )?;
                let package = inspect_archive(
                    &bytes,
                    name,
                    version,
                    &mut expanded_remaining,
                    &mut expanded_members,
                )?;
                captured.insert(path, bytes, &mut remaining, &mut file_count)?;
                let record = format!("registry/index/{namespace}/.cache/{}", index_record(name));
                if !captured.files.contains_key(&record) {
                    let bytes = read_selected(&root, &record, OUTPUT_LIMIT.min(remaining))?;
                    require(
                        !bytes.is_empty(),
                        "locked package sparse index record is empty",
                    )?;
                    captured.insert(record, bytes, &mut remaining, &mut file_count)?;
                }
                captured
                    .packages
                    .insert((namespace.clone(), name.clone(), version.clone()), package);
                found.insert((name.clone(), version.clone()));
                namespace_used = true;
            }
            if namespace_used {
                let config = read_selected(&root, &config_path, OUTPUT_LIMIT.min(remaining))?;
                validate_index_config(&config)?;
                captured.insert(config_path, config, &mut remaining, &mut file_count)?;
            }
        }
        require(
            found.len() == locked.len(),
            "approved Cargo home is missing a locked crates.io archive; fetch the complete locked graph before preparing",
        )?;
        // Re-read the complete selected set. An index/cache replacement during
        // acquisition refuses; a later user-home mutation cannot change the
        // retained map. Archives are independently content-bound to the lock.
        for (path, bytes) in &captured.files {
            require(
                read_selected(&root, path, bytes.len() as u64)? == *bytes,
                "selected Cargo cache changed between capture passes",
            )?;
        }
        if git::has_locked_packages(&lock_value) {
            let (git, files) = git::GitCache::capture(
                &root,
                &lock_value,
                cargo_home
                    .parent()
                    .ok_or_else(|| invalid("private Cargo home parent missing"))?,
                remaining,
                &mut expanded_remaining,
                &mut expanded_members,
            )?;
            for (path, bytes) in files {
                captured.insert(path, bytes, &mut remaining, &mut file_count)?;
            }
            captured.git = Some(git);
        }
        captured.materialize(cargo_home)?;
        Ok(captured)
    }

    fn insert(
        &mut self,
        path: String,
        bytes: Vec<u8>,
        remaining: &mut u64,
        count: &mut usize,
    ) -> io::Result<()> {
        *remaining = remaining
            .checked_sub(bytes.len() as u64)
            .ok_or_else(|| invalid("Cargo source and cache exceed their aggregate byte budget"))?;
        *count = count
            .checked_add(1)
            .filter(|count| *count <= MAX_SOURCE_FILES)
            .ok_or_else(|| {
                invalid("Cargo source and cache exceed their aggregate file-count bound")
            })?;
        require(
            self.files.insert(path, bytes).is_none(),
            "duplicate selected registry cache path",
        )
    }

    pub(super) fn materialize(&self, destination: &Path) -> io::Result<Vec<String>> {
        // Both destinations are inside a private operation-owned directory.
        // create_new prevents overwriting any workspace or Cargo-created file.
        fs::create_dir_all(destination)?;
        for (path, bytes) in &self.files {
            let output = destination.join(path);
            fs::create_dir_all(
                output
                    .parent()
                    .ok_or_else(|| invalid("cache file parent"))?,
            )?;
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(output)?;
            file.write_all(bytes)?;
        }
        Ok(self.files.keys().cloned().collect())
    }

    pub(super) fn check_lock(&self, lock: &Path) -> io::Result<()> {
        require(
            lock == self.lock,
            "resolved Cargo workspace uses a different lockfile than the captured registry graph",
        )
    }

    pub(super) fn check_package(&self, home: &Path, package: &Value) -> io::Result<()> {
        if package.get("source").is_some_and(Value::is_null) {
            return Ok(());
        }
        if package["source"]
            .as_str()
            .is_some_and(|source| source.starts_with("git+"))
        {
            return self
                .git
                .as_ref()
                .ok_or_else(|| {
                    invalid("resolved Git package was not selected from the approved Cargo home")
                })?
                .check_package(home, package);
        }
        require(
            package["source"] == CRATES_IO,
            "resolved package is not from the captured crates.io source",
        )?;
        let name = package["name"]
            .as_str()
            .ok_or_else(|| invalid("resolved registry package name missing"))?;
        let version = package["version"]
            .as_str()
            .ok_or_else(|| invalid("resolved registry package version missing"))?;
        let manifest = Path::new(
            package["manifest_path"]
                .as_str()
                .ok_or_else(|| invalid("resolved registry manifest missing"))?,
        );
        let relative = manifest
            .strip_prefix(home.join("registry/src"))
            .map_err(|_| invalid("resolved registry manifest escapes the private Cargo home"))?;
        let components: Vec<_> = relative.components().collect();
        require(
            components.len() == 3
                && components
                    .iter()
                    .all(|part| matches!(part, Component::Normal(_))),
            "resolved registry manifest has a noncanonical package path",
        )?;
        let namespace = components[0]
            .as_os_str()
            .to_str()
            .ok_or_else(|| invalid("non-UTF-8 registry namespace"))?;
        require(
            components[1].as_os_str() == std::ffi::OsStr::new(&format!("{name}-{version}"))
                && components[2].as_os_str() == "Cargo.toml",
            "resolved registry manifest differs from its locked package path",
        )?;
        let captured = self
            .packages
            .get(&(namespace.to_owned(), name.to_owned(), version.to_owned()))
            .ok_or_else(|| {
                invalid("resolved registry package was not captured from a locked archive")
            })?;
        let package_root = manifest
            .parent()
            .ok_or_else(|| invalid("resolved package root missing"))?;
        let directory = open_home(package_root)?;
        let targets = package["targets"]
            .as_array()
            .filter(|targets| !targets.is_empty())
            .ok_or_else(|| invalid("resolved registry package has no targets"))?;
        for path in std::iter::once(manifest.to_path_buf()).chain(
            targets
                .iter()
                .map(|target| {
                    target["src_path"]
                        .as_str()
                        .map(PathBuf::from)
                        .ok_or_else(|| invalid("resolved registry target path missing"))
                })
                .collect::<io::Result<Vec<_>>>()?,
        ) {
            let relative = path
                .strip_prefix(package_root)
                .ok()
                .and_then(Path::to_str)
                .ok_or_else(|| invalid("resolved registry target escapes its captured package"))?;
            let (size, expected) = captured.members.get(relative).ok_or_else(|| {
                invalid("resolved registry target was not present in its captured archive")
            })?;
            let bytes = read_selected(&directory, relative, *size)?;
            require(
                <[u8; 32]>::from(Sha256::digest(&bytes)) == *expected,
                "unpacked registry manifest or target differs from its captured archive",
            )?;
        }
        Ok(())
    }

    pub(super) fn verify_git_checkouts(&self, home: &Path, packages: &[Value]) -> io::Result<()> {
        if let Some(git) = &self.git {
            git.verify_checkouts(home, packages)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use serde_json::json;

    const MANIFEST: &[u8] = b"[package]\nname='fixture'\nversion='1.0.0'\nedition='2021'\n";

    fn archive(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut archive = tar::Builder::new(GzEncoder::new(Vec::new(), Compression::fast()));
        for (path, bytes) in files {
            let mut header = tar::Header::new_gnu();
            header.set_mode(0o644);
            header.set_size(bytes.len() as u64);
            header.set_cksum();
            archive.append_data(&mut header, path, *bytes).unwrap();
        }
        archive.into_inner().unwrap().finish().unwrap()
    }

    fn inspect(bytes: &[u8]) -> io::Result<CapturedPackage> {
        let mut remaining = MAX_SOURCE_BYTES;
        inspect_archive(bytes, "fixture", "1.0.0", &mut remaining, &mut 0)
    }

    #[test]
    fn archive_members_are_bound_to_the_locked_identity_and_exact_contents() {
        let bytes = archive(&[
            ("fixture-1.0.0/Cargo.toml", MANIFEST),
            ("fixture-1.0.0/src/lib.rs", b"pub const ANSWER: u32 = 42;\n"),
            ("fixture-1.0.0/payload.txt", b"input to a build script\n"),
        ]);
        let captured = inspect(&bytes).unwrap();
        assert_eq!(captured.members.len(), 3);
        assert_eq!(
            captured.members["Cargo.toml"],
            (
                MANIFEST.len() as u64,
                <[u8; 32]>::from(Sha256::digest(MANIFEST))
            )
        );
        let mut remaining = MAX_SOURCE_BYTES;
        assert!(inspect_archive(&bytes, "other", "1.0.0", &mut remaining, &mut 0).is_err());
        assert!(inspect_archive(&bytes, "fixture", "2.0.0", &mut remaining, &mut 0).is_err());
        let renamed = archive(&[(
            "fixture-1.0.0/Cargo.toml",
            b"[package]\nname='other'\nversion='1.0.0'\n",
        )]);
        assert!(inspect(&renamed).is_err());
    }

    #[test]
    fn duplicate_paths_file_directory_collisions_and_external_manifest_paths_refuse() {
        for files in [
            vec![("fixture-1.0.0/Cargo.toml", MANIFEST), ("fixture-1.0.0/Cargo.toml", MANIFEST)],
            vec![("fixture-1.0.0/Cargo.toml", MANIFEST), ("fixture-1.0.0/assets", b"file" as &[u8]), ("fixture-1.0.0/assets/input", b"child")],
            vec![("fixture-1.0.0/Cargo.toml", b"[package]\nname='fixture'\nversion='1.0.0'\nbuild='/outside/build.rs'\n" as &[u8])],
            vec![("fixture-1.0.0/Cargo.toml", b"[package]\nname='fixture'\nversion='1.0.0'\n[dependencies]\nexternal={path='../../outside'}\n" as &[u8])],
        ] {
            assert!(inspect(&archive(&files)).is_err());
        }
        for kind in [tar::EntryType::Symlink, tar::EntryType::Link] {
            let mut archive = tar::Builder::new(GzEncoder::new(Vec::new(), Compression::fast()));
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(kind);
            header.set_mode(0o644);
            header.set_size(0);
            header.set_link_name("/outside").unwrap();
            header.set_cksum();
            archive
                .append_data(&mut header, "fixture-1.0.0/linked", io::empty())
                .unwrap();
            assert!(inspect(&archive.into_inner().unwrap().finish().unwrap()).is_err());
        }
    }

    #[test]
    fn gzip_metadata_padding_and_member_expansion_share_one_hard_budget() {
        let bytes = archive(&[("fixture-1.0.0/Cargo.toml", MANIFEST)]);
        let mut plain = Vec::new();
        MultiGzDecoder::new(bytes.as_slice())
            .read_to_end(&mut plain)
            .unwrap();
        let mut remaining = plain.len() as u64;
        inspect_archive(&bytes, "fixture", "1.0.0", &mut remaining, &mut 0).unwrap();
        assert_eq!(
            remaining, 0,
            "padding and headers also consume the expansion budget"
        );
        assert!(
            inspect_archive(
                &bytes,
                "fixture",
                "1.0.0",
                &mut (plain.len() as u64 - 1),
                &mut 0
            )
            .is_err()
        );
        let mut truncated = bytes.clone();
        truncated.truncate(truncated.len() - 3);
        assert!(
            inspect(&truncated).is_err(),
            "the final gzip checksum/trailer must be read"
        );

        let mut archive = tar::Builder::new(GzEncoder::new(Vec::new(), Compression::fast()));
        let long_name = vec![b'a'; 8192];
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::GNULongName);
        header.set_mode(0o644);
        header.set_size(long_name.len() as u64);
        header.set_cksum();
        archive
            .append_data(&mut header, "././@LongLink", long_name.as_slice())
            .unwrap();
        let bytes = archive.into_inner().unwrap().finish().unwrap();
        let error = inspect_archive(&bytes, "fixture", "1.0.0", &mut 700, &mut 0).unwrap_err();
        assert!(
            error.to_string().contains("decompressed byte budget"),
            "{error}"
        );
    }

    #[test]
    fn lockfile_binds_archive_checksums_and_rejects_unmodeled_sources() {
        let valid = format!(
            "version=4\n[[package]]\nname='fixture'\nversion='1.0.0'\nsource='{CRATES_IO}'\nchecksum='{}'\n",
            "ab".repeat(32)
        );
        let lock: toml::Value = toml::from_str(&valid).unwrap();
        assert_eq!(locked_packages(&lock).unwrap().len(), 1);
        let revision = "0123456789abcdef0123456789abcdef01234567";
        let git: toml::Value = toml::from_str(&format!(
            "version=4\n[[package]]\nname='fixture'\nversion='1.0.0'\nsource='git+https://example.invalid/pkg?rev={revision}#{revision}'\n"
        )).unwrap();
        assert!(locked_packages(&git).unwrap().is_empty());
        assert!(git::has_locked_packages(&git));
        let mut checksummed_git = git;
        checksummed_git["package"][0]
            .as_table_mut()
            .unwrap()
            .insert("checksum".into(), "ab".repeat(32).into());
        assert!(locked_packages(&checksummed_git).is_err());
        for invalid in [
            valid.replace(CRATES_IO, "registry+https://private.invalid/index"),
            valid.replace(CRATES_IO, "git+https://example.invalid/pkg#revision"),
            valid.replace(&"ab".repeat(32), &"AB".repeat(32)),
            valid.replace("name='fixture'", "name='../fixture'"),
            valid.replace("version='1.0.0'", "version='1.0.0/escape'"),
            format!(
                "{valid}\n[[package]]{}",
                valid.split_once("[[package]]").unwrap().1
            ),
        ] {
            let lock = toml::from_str::<toml::Value>(&invalid).unwrap();
            assert!(locked_packages(&lock).is_err(), "{invalid}");
        }
        assert_eq!(index_record("A"), "1/a");
        assert_eq!(index_record("AB"), "2/ab");
        assert_eq!(index_record("ABC"), "3/a/abc");
        assert_eq!(index_record("Serde_JSON"), "se/rd/serde_json");
    }

    #[test]
    fn public_index_configuration_cannot_enable_credentials_or_redirect_downloads() {
        validate_index_config(
            br#"{"dl":"https://static.crates.io/crates","api":"https://crates.io"}"#,
        )
        .unwrap();
        for value in [
            json!({"dl":"https://private:token@registry.invalid/crates"}),
            json!({"dl":"https://static.crates.io/crates","auth-required":true}),
            json!({"dl":"https://static.crates.io/crates","token":"must-not-be-read"}),
            json!({"dl":"https://static.crates.io/crates","api":"https://other.invalid"}),
        ] {
            assert!(validate_index_config(&serde_json::to_vec(&value).unwrap()).is_err());
        }
    }

    #[cfg(unix)]
    #[test]
    fn selected_cache_reads_refuse_symlinked_ancestors_and_members() {
        let owner = tempfile::tempdir().unwrap();
        let home = owner.path().join("home");
        fs::create_dir_all(home.join("registry/index")).unwrap();
        fs::write(home.join("registry/index/input"), b"retained").unwrap();
        let root = open_home(&home).unwrap();
        assert_eq!(
            read_selected(&root, "registry/index/input", 8).unwrap(),
            b"retained"
        );
        assert!(read_selected(&root, "registry/index/input", 7).is_err());
        std::os::unix::fs::symlink(home.join("registry"), home.join("alias")).unwrap();
        std::os::unix::fs::symlink(home.join("registry/index/input"), home.join("file-alias"))
            .unwrap();
        assert!(read_selected(&root, "alias/index/input", 100).is_err());
        assert!(read_selected(&root, "file-alias", 100).is_err());
        std::os::unix::fs::symlink(&home, owner.path().join("home-alias")).unwrap();
        assert!(approved_home(&json!(owner.path().join("home-alias"))).is_err());
        assert!(approved_home(&json!(format!("{}/../home", home.display()))).is_err());
    }
}
