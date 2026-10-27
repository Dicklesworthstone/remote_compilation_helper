//! Offline sparse registry capture from an explicitly approved Cargo home.
//!
//! A lockfile selects package identities; its SHA-256 checksums select archive
//! bytes. Cargo remains the resolver and consumes only a fresh private home.
//! Expanded user sources, credentials, Cargo configuration and unrelated
//! index entries are never opened. This supplies inputs, not cache authority.

use super::{
    MAX_PACKAGES, OUTPUT_LIMIT, git, invalid, require, validate_manifest_paths_with_cache, vendor,
};
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
// Candidate discovery can encounter archives belonging to other sparse indexes
// on the same host. Bound all bytes read, including checksum mismatches, rather
// than charging only the archives selected for delivery.
const MAX_CANDIDATE_BYTES: u64 = MAX_SOURCE_BYTES;
pub(super) const MAX_ARCHIVE_MEMBERS: usize = 100_000;

// Sources are part of package identity: two registries may publish the same
// name and version with different archives. Never collapse them into one hit.
type PackageIdentity = (String, String, String);
type LockedPackages = BTreeMap<PackageIdentity, [u8; 32]>;
type CandidateIdentities<'a> = Vec<(&'a PackageIdentity, &'a [u8; 32])>;

#[derive(Debug)]
struct MatchedArchive<'a> {
    bytes: Vec<u8>,
    identities: Vec<&'a PackageIdentity>,
}

fn registry_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte))
}

/// Cargo names sparse cache directories with the URL host and a Cargo-owned
/// hash. The host only bounds candidate discovery; offline Cargo subsequently
/// chooses the exact URL-derived namespace and we bind its result to the locked
/// source identity, checksum, manifest and target bytes.
fn registry_host(source: &str) -> io::Result<&str> {
    if source == CRATES_IO {
        return Ok("index.crates.io");
    }
    require(
        source.starts_with("sparse+") && vendor::registry_source(source)? == source,
        "cached alternate registries require a canonical sparse HTTP(S) index",
    )?;
    let authority = source
        .split_once("://")
        .and_then(|(_, rest)| rest.split('/').next())
        .ok_or_else(|| invalid("cached sparse registry host missing"))?;
    let host = if let Some((host, port)) = authority.split_once(':') {
        require(
            port.parse::<u16>().is_ok_and(|port| port != 0),
            "cached sparse registry has an invalid port",
        )?;
        host
    } else {
        authority
    };
    require(
        !host.is_empty()
            && host.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || b".-".contains(&byte)
            }),
        "cached sparse registry requires a canonical DNS or IPv4 host",
    )?;
    Ok(host)
}

pub(super) fn validate_cargo_config(value: &toml::Value, base: &Path) -> io::Result<()> {
    // The shared validator permits source tables only for its caller to check.
    // This adapter admits named sparse indexes, never source replacement chains.
    super::validate_cargo_config(value, base, true)?;
    require(
        value.get("source").is_none(),
        "cached registry preparation does not import source replacements",
    )?;
    if let Some(registries) = value.get("registries") {
        let registries = registries
            .as_table()
            .filter(|registries| registries.len() <= MAX_NAMESPACES)
            .ok_or_else(|| invalid("captured sparse registry declarations exceed their bound"))?;
        for (name, registry) in registries {
            require(
                registry_name(name) && name != "crates-io",
                "invalid or reserved alternate registry name",
            )?;
            let fields = registry
                .as_table()
                .filter(|fields| fields.len() == 1)
                .ok_or_else(|| {
                    invalid("captured registry accepts only its index, not credentials or helpers")
                })?;
            let index = fields
                .get("index")
                .and_then(toml::Value::as_str)
                .ok_or_else(|| invalid("captured registry index missing"))?;
            registry_host(index)?;
        }
    }
    Ok(())
}

pub(super) fn validate_dependency(fields: &toml::map::Map<String, toml::Value>) -> io::Result<()> {
    require(
        !fields.contains_key("git")
            && !(fields.contains_key("registry") && fields.contains_key("registry-index")),
        "dependency contains conflicting registry/Git selectors",
    )?;
    if let Some(name) = fields.get("registry") {
        require(
            name.as_str().is_some_and(registry_name),
            "dependency registry name must be a bounded literal name",
        )
    } else {
        let index = fields
            .get("registry-index")
            .and_then(toml::Value::as_str)
            .ok_or_else(|| invalid("dependency registry index must be a string"))?;
        registry_host(&vendor::registry_source(index)?).map(|_| ())
    }
}

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
        if let Some(source) = source.filter(|source| source.starts_with("git+")) {
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
        if let Some(source) = source.filter(|source| !source.starts_with("git+")) {
            registry_host(source)?;
            let checksum = package
                .get("checksum")
                .and_then(toml::Value::as_str)
                .ok_or_else(|| invalid("locked registry package requires a SHA-256 checksum"))?;
            let digest = archive_checksum(checksum)?;
            require(
                selected
                    .insert(
                        (source.to_owned(), name.to_owned(), version.to_owned()),
                        digest,
                    )
                    .is_none(),
                "ambiguous locked registry package identity",
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
    read_selected_file(open_selected(root, path, false)?, limit)
}

fn read_selected_file(mut file: File, limit: u64) -> io::Result<Vec<u8>> {
    let before = file.metadata()?;
    require(
        before.is_file() && before.len() <= limit,
        "selected Cargo cache file is not a bounded regular file",
    )?;
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(before.len())
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

fn archive_candidates<'a>(
    namespace: &str,
    locked: &'a LockedPackages,
) -> io::Result<BTreeMap<String, CandidateIdentities<'a>>> {
    let host = namespace
        .rsplit_once('-')
        .map(|(host, _)| host)
        .unwrap_or_default();
    let mut candidates: BTreeMap<String, CandidateIdentities<'a>> = BTreeMap::new();
    for (identity @ (source, name, version), expected) in locked {
        if registry_host(source)? != host {
            continue;
        }
        let path = format!("registry/cache/{namespace}/{name}-{version}.crate");
        let identities = candidates.entry(path).or_default();
        if let Some(((.., previous_name, previous_version), _)) = identities.first() {
            require(
                previous_name == name && previous_version == version,
                "locked package identities alias the same registry archive path",
            )?;
        }
        identities.push((identity, expected));
    }
    Ok(candidates)
}

fn read_archive_candidate<'a>(
    root: &File,
    path: &str,
    identities: &CandidateIdentities<'a>,
    candidate_remaining: &mut u64,
    retained_limit: u64,
) -> io::Result<Option<MatchedArchive<'a>>> {
    let file = match open_selected(root, path, false) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let size = file.metadata()?.len();
    *candidate_remaining = candidate_remaining.checked_sub(size).ok_or_else(|| {
        invalid("registry archive candidates exceed their aggregate candidate-read byte budget")
    })?;
    // Reserve before reading or comparing checksums. The same descriptor and
    // size limit prevent a replacement/growth from exceeding that reservation.
    let bytes = read_selected_file(file, size.min(retained_limit))?;
    let digest = <[u8; 32]>::from(Sha256::digest(&bytes));
    let mut matches = Vec::new();
    for (identity @ (source, _, _), expected) in identities {
        if digest == **expected {
            matches.push(*identity);
        } else {
            // Same-host indexes may legitimately hold a different archive, but
            // preserve the existing crates.io checksum-mismatch refusal.
            require(
                source != CRATES_IO,
                "cached crate archive checksum does not match the retained Cargo.lock",
            )?;
        }
    }
    Ok((!matches.is_empty()).then_some(MatchedArchive {
        bytes,
        identities: matches,
    }))
}

fn index_namespaces(root: &File, locked: &LockedPackages) -> io::Result<Vec<String>> {
    #[cfg(unix)]
    {
        let directory = open_selected(root, "registry/index", true)?;
        let hosts = locked
            .keys()
            .map(|(source, _, _)| registry_host(source))
            .collect::<io::Result<BTreeSet<_>>>()?;
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
            if name.rsplit_once('-').is_some_and(|(host, suffix)| {
                hosts.contains(host)
                    && suffix.len() == 16
                    && suffix
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            }) {
                names.insert(name.to_owned());
                require(
                    names.len() <= MAX_NAMESPACES,
                    "too many selected sparse registry cache namespaces",
                )?;
            }
        }
        require(
            !names.is_empty(),
            "approved Cargo home has no selected sparse registry index cache",
        )?;
        Ok(names.into_iter().collect())
    }
    #[cfg(not(unix))]
    {
        let _ = (root, locked);
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

fn public_endpoint(value: &Value, template: bool) -> bool {
    let Some(url) = value.as_str().filter(|url| url.len() <= 4096) else {
        return false;
    };
    let Some(tail) = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
    else {
        return false;
    };
    let authority = tail.split('/').next().unwrap_or_default();
    if authority.is_empty()
        || !authority
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b".-:[]".contains(&byte))
        || url.contains(['?', '#', '@', '\\', '%'])
        || url.chars().any(|ch| ch.is_whitespace() || ch.is_control())
        || tail.split('/').any(|part| matches!(part, "." | ".."))
    {
        return false;
    }
    let mut literal = url.to_owned();
    if template {
        for marker in [
            "{crate}",
            "{version}",
            "{prefix}",
            "{lowerprefix}",
            "{sha256-checksum}",
        ] {
            literal = literal.replace(marker, "");
        }
    }
    !literal.contains(['{', '}'])
}

fn validate_index_config(bytes: &[u8], crates_io: bool) -> io::Result<()> {
    let value: Value = serde_json::from_slice(bytes)
        .map_err(|_| invalid("cached sparse index config is not JSON"))?;
    require(
        value.as_object().is_some_and(|fields| {
            fields
                .keys()
                .all(|key| matches!(key.as_str(), "dl" | "api" | "auth-required"))
        }) && if crates_io {
            value["dl"].as_str().is_some_and(|url| {
                matches!(
                    url,
                    "https://static.crates.io/crates" | "https://static.crates.io/crates/"
                )
            }) && value
                .get("api")
                .is_none_or(|api| api == "https://crates.io")
        } else {
            public_endpoint(&value["dl"], true)
                && value
                    .get("api")
                    .is_none_or(|api| public_endpoint(api, false))
        } && value.get("auth-required").is_none_or(|auth| auth == false),
        "cached registry capture requires a public index without credentials or unknown endpoints",
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
    validate_manifest_paths_with_cache(Path::new(""), &manifest, None, false, true)?;
    Ok(CapturedPackage { members })
}

#[derive(Debug)]
pub(super) struct RegistryCache {
    lock: PathBuf,
    files: BTreeMap<String, Vec<u8>>,
    packages: BTreeMap<(String, String, String), CapturedPackage>,
    package_sources: BTreeSet<(String, String, String, String)>,
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
            "cargo_home_source requires at least one locked sparse-registry or full-revision Git package",
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
            index_namespaces(&root, &locked)?
        };
        let mut captured = Self {
            lock: lock.to_path_buf(),
            files: BTreeMap::new(),
            packages: BTreeMap::new(),
            package_sources: BTreeSet::new(),
            git: None,
        };
        let mut found = BTreeSet::new();
        let mut candidate_remaining = MAX_CANDIDATE_BYTES;
        let mut expanded_remaining = MAX_SOURCE_BYTES;
        let mut expanded_members = 0_usize;
        for namespace in namespaces {
            let config_path = format!("registry/index/{namespace}/config.json");
            let mut namespace_sources = BTreeSet::new();
            // Group by the physical cache path before acquisition: many locked
            // source identities can share a host, package name and version.
            // Each candidate is read and hashed once, not once per identity.
            for (path, identities) in archive_candidates(&namespace, &locked)? {
                let Some(candidate) = read_archive_candidate(
                    &root,
                    &path,
                    &identities,
                    &mut candidate_remaining,
                    remaining,
                )?
                else {
                    continue;
                };
                let (_, name, version) = candidate.identities[0];
                let package = inspect_archive(
                    &candidate.bytes,
                    name,
                    version,
                    &mut expanded_remaining,
                    &mut expanded_members,
                )?;
                captured.insert(path, candidate.bytes, &mut remaining, &mut file_count)?;
                captured
                    .packages
                    .insert((namespace.clone(), name.clone(), version.clone()), package);
                let record = format!("registry/index/{namespace}/.cache/{}", index_record(name));
                if !captured.files.contains_key(&record) {
                    let bytes = read_selected(&root, &record, OUTPUT_LIMIT.min(remaining))?;
                    require(
                        !bytes.is_empty(),
                        "locked package sparse index record is empty",
                    )?;
                    captured.insert(record, bytes, &mut remaining, &mut file_count)?;
                }
                for (source, name, version) in candidate.identities {
                    captured.package_sources.insert((
                        source.clone(),
                        namespace.clone(),
                        name.clone(),
                        version.clone(),
                    ));
                    found.insert((source.clone(), name.clone(), version.clone()));
                    namespace_sources.insert(source.as_str());
                }
            }
            if !namespace_sources.is_empty() {
                let config = read_selected(&root, &config_path, OUTPUT_LIMIT.min(remaining))?;
                validate_index_config(&config, namespace_sources.contains(CRATES_IO))?;
                captured.insert(config_path, config, &mut remaining, &mut file_count)?;
            }
        }
        require(
            found.len() == locked.len(),
            "approved Cargo home is missing a checksum-matching locked registry archive; fetch the complete locked graph before preparing",
        )?;
        // Re-read the complete selected set. An index/cache replacement during
        // acquisition refuses; a later user-home mutation cannot change the
        // retained map. Archives are independently content-bound to the lock.
        // This pass is bounded by the selected delivery bytes; rejected archive
        // candidates were charged separately during the single acquisition pass.
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
        let source = package["source"]
            .as_str()
            .ok_or_else(|| invalid("resolved registry source missing"))?;
        registry_host(source)?;
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
        require(
            self.package_sources.contains(&(
                source.to_owned(),
                namespace.to_owned(),
                name.to_owned(),
                version.to_owned(),
            )),
            "resolved registry source and archive were not selected by the retained lockfile",
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
            true,
        )
        .unwrap();
        for value in [
            json!({"dl":"https://private:token@registry.invalid/crates"}),
            json!({"dl":"https://static.crates.io/crates","auth-required":true}),
            json!({"dl":"https://static.crates.io/crates","token":"must-not-be-read"}),
            json!({"dl":"https://static.crates.io/crates","api":"https://other.invalid"}),
        ] {
            assert!(validate_index_config(&serde_json::to_vec(&value).unwrap(), true).is_err());
        }
    }

    #[test]
    fn sparse_registry_config_admits_only_captured_index_declarations() {
        let valid = "[registries.company]\nindex='sparse+https://registry.example/team/'\n[build]\nrustflags=['-Dwarnings']\n";
        validate_cargo_config(&toml::from_str(valid).unwrap(), Path::new("")).unwrap();
        for text in [
            valid.replace("sparse+https://registry.example/team/", "https://registry.example/team/"),
            valid.replace("registry.example", "user:secret@registry.example"),
            valid.replace("registry.example", "registry.example:0"),
            valid.replace("team/", "team/?token=secret"),
            valid.replace("company", "crates-io"),
            format!("{valid}\n[registries.company.credential-provider]\nname='external'\n"),
            "[registries.company]\nindex='sparse+https://registry.example/'\ntoken='must-not-read'\n".into(),
            "[source.crates-io]\nreplace-with='company'\n".into(),
        ] {
            assert!(validate_cargo_config(&toml::from_str(&text).unwrap(), Path::new("")).is_err(), "{text}");
        }
        for text in [
            "registry='company'",
            "registry-index='sparse+https://registry.example/team/'",
            "registry-index='https://github.com/rust-lang/crates.io-index'",
        ] {
            let value: toml::Value = toml::from_str(text).unwrap();
            validate_dependency(value.as_table().unwrap()).unwrap();
        }
        for text in [
            "registry='company'\ngit='https://registry.example/repo'",
            "registry='company'\nregistry-index='sparse+https://registry.example/'",
            "registry='../../secret'",
            "registry-index='https://registry.example/git-index'",
        ] {
            let value: toml::Value = toml::from_str(text).unwrap();
            assert!(
                validate_dependency(value.as_table().unwrap()).is_err(),
                "{text}"
            );
        }
    }

    #[test]
    fn same_name_and_version_remain_distinct_across_sparse_sources() {
        let lock: toml::Value = toml::from_str(&format!(
            "version=4\n[[package]]\nname='fixture'\nversion='1.0.0'\nsource='sparse+https://registry.example/first/'\nchecksum='{}'\n[[package]]\nname='fixture'\nversion='1.0.0'\nsource='sparse+https://registry.example/second/'\nchecksum='{}'\n",
            "ab".repeat(32), "cd".repeat(32),
        )).unwrap();
        let locked = locked_packages(&lock).unwrap();
        assert_eq!(locked.len(), 2);
        assert_ne!(locked.values().next(), locked.values().next_back());
        for source in [
            "sparse+https://registry.example/index",
            "sparse+https://token@registry.example/index/",
            "sparse+file:///tmp/registry/",
            "registry+https://registry.example/index",
        ] {
            assert!(registry_host(source).is_err(), "{source}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn same_path_registry_identities_read_and_hash_one_archive_candidate() {
        let owner = tempfile::tempdir().unwrap();
        let root = open_home(owner.path()).unwrap();
        let namespace = "registry.example-0123456789abcdef";
        let bytes = archive(&[("fixture-1.0.0/Cargo.toml", MANIFEST)]);
        let digest = <[u8; 32]>::from(Sha256::digest(&bytes));
        let mut locked = LockedPackages::new();
        for index in 0..MAX_PACKAGES {
            locked.insert(
                (
                    format!("sparse+https://registry.example/{index}/"),
                    "fixture".into(),
                    "1.0.0".into(),
                ),
                if index % 2 == 0 { digest } else { [0; 32] },
            );
        }
        let candidates = archive_candidates(namespace, &locked).unwrap();
        assert_eq!(candidates.len(), 1, "group by physical archive path");
        let (path, identities) = candidates.first_key_value().unwrap();
        fs::create_dir_all(owner.path().join(path).parent().unwrap()).unwrap();
        fs::write(owner.path().join(path), &bytes).unwrap();
        // A budget of precisely one archive must cover every logical source,
        // including the half whose checksum does not match this namespace.
        let mut remaining = bytes.len() as u64;
        let matched =
            read_archive_candidate(&root, path, identities, &mut remaining, MAX_SOURCE_BYTES)
                .unwrap()
                .unwrap();
        assert_eq!(remaining, 0);
        assert_eq!(matched.bytes, bytes);
        assert_eq!(matched.identities.len(), MAX_PACKAGES.div_ceil(2));
        assert!(
            matched
                .identities
                .iter()
                .all(|identity| locked[*identity] == digest)
        );
    }

    #[cfg(unix)]
    #[test]
    fn mismatched_archive_candidates_consume_one_shared_read_budget() {
        let owner = tempfile::tempdir().unwrap();
        let root = open_home(owner.path()).unwrap();
        let bytes = archive(&[("fixture-1.0.0/Cargo.toml", MANIFEST)]);
        let locked = LockedPackages::from([(
            (
                "sparse+https://registry.example/required/".into(),
                "fixture".into(),
                "1.0.0".into(),
            ),
            [0; 32],
        )]);
        let first = archive_candidates("registry.example-0123456789abcdef", &locked).unwrap();
        let second = archive_candidates("registry.example-fedcba9876543210", &locked).unwrap();
        for path in first.keys().chain(second.keys()) {
            fs::create_dir_all(owner.path().join(path).parent().unwrap()).unwrap();
            fs::write(owner.path().join(path), &bytes).unwrap();
        }
        let mut remaining = bytes.len() as u64 * 2 - 1;
        let (path, identities) = first.first_key_value().unwrap();
        assert!(
            read_archive_candidate(&root, path, identities, &mut remaining, MAX_SOURCE_BYTES)
                .unwrap()
                .is_none()
        );
        assert_eq!(remaining, bytes.len() as u64 - 1);
        let (path, identities) = second.first_key_value().unwrap();
        let error =
            read_archive_candidate(&root, path, identities, &mut remaining, MAX_SOURCE_BYTES)
                .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("aggregate candidate-read byte budget"),
            "{error}"
        );
        assert_eq!(remaining, bytes.len() as u64 - 1);
        assert!(
            read_archive_candidate(
                &root,
                "registry/cache/absent/fixture-1.0.0.crate",
                identities,
                &mut remaining,
                MAX_SOURCE_BYTES,
            )
            .unwrap()
            .is_none()
        );
        assert_eq!(remaining, bytes.len() as u64 - 1);
    }

    #[cfg(unix)]
    #[test]
    fn crates_io_mismatch_refuses_even_when_another_same_host_source_matches() {
        let owner = tempfile::tempdir().unwrap();
        let root = open_home(owner.path()).unwrap();
        let bytes = archive(&[("fixture-1.0.0/Cargo.toml", MANIFEST)]);
        let locked = LockedPackages::from([
            (
                (CRATES_IO.into(), "fixture".into(), "1.0.0".into()),
                [0; 32],
            ),
            (
                (
                    "sparse+https://index.crates.io/alternate/".into(),
                    "fixture".into(),
                    "1.0.0".into(),
                ),
                <[u8; 32]>::from(Sha256::digest(&bytes)),
            ),
        ]);
        let candidates = archive_candidates("index.crates.io-0123456789abcdef", &locked).unwrap();
        let (path, identities) = candidates.first_key_value().unwrap();
        fs::create_dir_all(owner.path().join(path).parent().unwrap()).unwrap();
        fs::write(owner.path().join(path), &bytes).unwrap();
        let mut remaining = bytes.len() as u64;
        let error =
            read_archive_candidate(&root, path, identities, &mut remaining, MAX_SOURCE_BYTES)
                .unwrap_err();
        assert!(
            error.to_string().contains("checksum does not match"),
            "{error}"
        );
        assert_eq!(remaining, 0);
    }

    #[test]
    fn public_sparse_index_templates_do_not_import_authentication_or_local_paths() {
        for value in [
            json!({"dl":"https://registry.example/crates/{crate}/{version}/{sha256-checksum}","api":"https://registry.example/api","auth-required":false}),
            json!({"dl":"http://127.0.0.1:12345/crates/{lowerprefix}/{crate}-{version}.crate"}),
        ] {
            validate_index_config(&serde_json::to_vec(&value).unwrap(), false).unwrap();
        }
        for value in [
            json!({"dl":"file:///etc/secret"}),
            json!({"dl":"https://user:secret@registry.example/crates"}),
            json!({"dl":"https://registry.example/crates?token=secret"}),
            json!({"dl":"https://registry.example/crates","auth-required":true}),
            json!({"dl":"https://registry.example/crates","credential-provider":"external"}),
            json!({"dl":"https://registry.example/{unknown}"}),
            json!({"dl":"https://registry.example/crates","api":"file:///etc/secret"}),
        ] {
            assert!(
                validate_index_config(&serde_json::to_vec(&value).unwrap(), false).is_err(),
                "{value}"
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn two_same_host_sparse_registries_replay_offline_from_archives_without_user_home_state() {
        use rabs_sandbox::cargo_home::{CargoHomeProjection, ISOLATED_CARGO_HOME_SOURCE_VERSION};
        use rabs_sandbox::snapshot_capture::capture_sealed_source;
        use rabs_sandbox::source_transfer::{
            MAX_SOURCE_CHUNK, SourceFile, SourceManifest, SourceReceiver,
        };
        use std::net::TcpListener;
        use std::os::unix::fs::PermissionsExt;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::time::{Duration, Instant};

        const ISOLATED: &str = "RABS_TEST_REGISTRY_REPLAY_ISOLATED";
        const TEST_NAME: &str = "coord::source_delivery::preparation::cargo::registry::tests::two_same_host_sparse_registries_replay_offline_from_archives_without_user_home_state";
        if std::env::var_os(ISOLATED).is_none() {
            // prepare() creates its own planning directories through TMPDIR.
            // Scope a clean physical parent to this subprocess, rather than
            // mutating the test process environment or weakening ancestor checks.
            let scratch = tempfile::Builder::new()
                .prefix("rabs-registry-replay-")
                .tempdir_in("/tmp")
                .unwrap();
            fs::set_permissions(scratch.path(), fs::Permissions::from_mode(0o700)).unwrap();
            let clean_tmp = fs::canonicalize(scratch.path()).unwrap();
            let mut isolated = std::process::Command::new(std::env::current_exe().unwrap());
            isolated
                .args(["--exact", TEST_NAME, "--nocapture", "--test-threads=1"])
                .env(ISOLATED, "1")
                .env("TMPDIR", &clean_tmp);
            let output = super::super::bounded_command(
                isolated,
                scratch.path(),
                Duration::from_secs(180),
                OUTPUT_LIMIT,
            )
            .unwrap();
            let output = String::from_utf8_lossy(&output);
            assert!(
                output.contains(&format!("test {TEST_NAME} ... ok"))
                    && output.contains("1 passed; 0 failed; 0 ignored"),
                "isolated registry replay must execute its named test: {output}"
            );
            return;
        }
        assert_eq!(std::env::var_os(ISOLATED), Some("1".into()));

        let fixture = tempfile::tempdir().unwrap();
        let root = fixture.path();
        fs::set_permissions(root, fs::Permissions::from_mode(0o700)).unwrap();
        let workspace = root.join("workspace");
        let seed = root.join("seed");
        for path in [
            workspace.join("src"),
            workspace.join(".cargo"),
            seed.join("home"),
            seed.join("cargo-home"),
            seed.join("tools"),
        ] {
            fs::create_dir_all(path).unwrap();
        }
        let cargo = super::super::local_tool("cargo", &seed.join("tools")).unwrap();
        let rustc = super::super::local_tool("rustc", &seed.join("tools")).unwrap();
        let server = TcpListener::bind("127.0.0.1:0").unwrap();
        server.set_nonblocking(true).unwrap();
        let address = server.local_addr().unwrap();
        let mut responses = BTreeMap::new();
        for (registry, answer) in [("first", 17), ("second", 25)] {
            let code = format!("pub fn answer() -> u32 {{ {answer} }}\n");
            let bytes = archive(&[
                (
                    "fixture-1.0.0/Cargo.toml",
                    b"[package]\nname='fixture'\nversion='1.0.0'\nedition='2021'\n",
                ),
                ("fixture-1.0.0/src/lib.rs", code.as_bytes()),
            ]);
            let checksum: String = Sha256::digest(&bytes)
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();
            responses.insert(
                format!("/{registry}/config.json"),
                serde_json::to_vec(&json!({
                    "dl":format!("http://{address}/{registry}/crates"), "auth-required":false,
                }))
                .unwrap(),
            );
            responses.insert(
                format!("/{registry}/fi/xt/fixture"),
                serde_json::to_vec(&json!({
                    "name":"fixture", "vers":"1.0.0", "deps":[], "cksum":checksum,
                    "features":{}, "yanked":false,
                }))
                .unwrap(),
            );
            responses.insert(format!("/{registry}/crates/fixture/1.0.0/download"), bytes);
        }
        fs::write(workspace.join("Cargo.toml"), "[package]\nname='registry-replay'\nversion='0.1.0'\nedition='2021'\n[dependencies]\none={package='fixture',version='=1.0.0',registry='first'}\ntwo={package='fixture',version='=1.0.0',registry='second'}\n").unwrap();
        fs::write(workspace.join("src/lib.rs"), "#[test]\nfn distinct_registry_archives() { assert_eq!(one::answer(),17); assert_eq!(two::answer(),25); }\n").unwrap();
        fs::write(workspace.join(".cargo/config.toml"), format!(
            "[registries.first]\nindex='sparse+http://{address}/first/'\n[registries.second]\nindex='sparse+http://{address}/second/'\n",
        )).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = Arc::clone(&stop);
        let thread = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(30);
            while !stopped.load(Ordering::Acquire) && Instant::now() < deadline {
                let (mut stream, _) = match server.accept() {
                    Ok(stream) => stream,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(error) => panic!("fixture server: {error}"),
                };
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut request = Vec::new();
                let mut buffer = [0_u8; 2048];
                while !request.windows(4).any(|bytes| bytes == b"\r\n\r\n")
                    && request.len() < 16 * 1024
                {
                    let count = stream.read(&mut buffer).unwrap();
                    if count == 0 {
                        break;
                    }
                    request.extend_from_slice(&buffer[..count]);
                }
                let request = String::from_utf8(request).unwrap();
                let path = request
                    .lines()
                    .next()
                    .unwrap_or_default()
                    .split_whitespace()
                    .nth(1)
                    .unwrap_or_default();
                let (status, body) = match responses.get(path) {
                    Some(bytes) => ("200 OK", bytes.as_slice()),
                    None => ("404 Not Found", &b"missing"[..]),
                };
                write!(
                    stream,
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                )
                .unwrap();
                stream.write_all(body).unwrap();
            }
        });
        let mut fetch =
            super::super::planning_command(&cargo, &rustc, &workspace, "Cargo.toml", &seed, None)
                .unwrap();
        fetch.args(["fetch", "--manifest-path"]).arg(workspace.join("Cargo.toml"))
            .env("CARGO_HTTP_USER_AGENT", "remote_compilation_helper-agent (+https://github.com/Dicklesworthstone/remote_compilation_helper)");
        let fetched =
            super::super::bounded_command(fetch, &seed, Duration::from_secs(25), OUTPUT_LIMIT);
        // All subsequent preparation and worker-side replay run with the only
        // registry server shut down; a missing captured object cannot be fetched.
        stop.store(true, Ordering::Release);
        thread.join().unwrap();
        fetched.unwrap();
        let approved = seed.join("cargo-home");
        fs::write(
            approved.join("config.toml"),
            "must not parse ambient Cargo configuration",
        )
        .unwrap();
        fs::write(
            approved.join("credentials.toml"),
            "token = 'must-not-import'",
        )
        .unwrap();
        for namespace in fs::read_dir(approved.join("registry/src")).unwrap() {
            fs::write(
                namespace.unwrap().path().join("fixture-1.0.0/src/lib.rs"),
                "compile_error!(\"mutable expanded sources must not be read\");\n",
            )
            .unwrap();
        }
        let image = Arc::new(
            capture_sealed_source(
                &[("workspace".into(), workspace.clone())],
                false,
                2,
                MAX_SOURCE_BYTES,
            )
            .unwrap(),
        );
        let source = super::super::CargoSource::parse(
            &json!({"manifest":"Cargo.toml","cargo_home_source":approved}),
        )
        .unwrap();
        let (retained, selected) = source.prepare(Arc::clone(&image), None).unwrap();
        assert!(
            selected
                .iter()
                .all(|path| !path.ends_with("credentials.toml") && !path.contains("registry/src/"))
        );
        assert_eq!(
            selected
                .iter()
                .filter(|path| path.ends_with(".crate"))
                .count(),
            2
        );
        let manifest = SourceManifest::new(
            selected
                .iter()
                .map(|path| {
                    let bytes = retained.file_bytes("workspace", path).unwrap();
                    SourceFile {
                        path: path.clone(),
                        len: bytes.len() as u64,
                        sha256: Sha256::digest(bytes).into(),
                        executable: false,
                    }
                })
                .collect(),
        )
        .unwrap();
        let projection = CargoHomeProjection::for_version(
            ISOLATED_CARGO_HOME_SOURCE_VERSION,
            CACHE_PREFIX,
            &manifest,
        )
        .unwrap();
        let mut receiver = SourceReceiver::create(&root.join("transferred"), manifest).unwrap();
        for path in &selected {
            for (chunk, bytes) in retained
                .file_bytes("workspace", path)
                .unwrap()
                .chunks(MAX_SOURCE_CHUNK)
                .enumerate()
            {
                receiver
                    .write_chunk(
                        path,
                        (chunk * MAX_SOURCE_CHUNK) as u64,
                        bytes,
                        Sha256::digest(bytes).into(),
                    )
                    .unwrap();
            }
        }
        receiver.seal().unwrap();
        let prepared = projection
            .prepare(&receiver, &root.join("worker-inputs"), || false)
            .unwrap();
        let worker = prepared.projected_workspace().unwrap();
        assert!(!worker.join(CACHE_PREFIX).exists());
        assert!(!prepared.root().join("credentials.toml").exists());
        assert!(!prepared.root().join("config.toml").exists());
        let mut replay =
            super::super::planning_command(&cargo, &rustc, worker, "Cargo.toml", &seed, None)
                .unwrap();
        replay
            .args(["test", "--locked", "--offline", "--lib"])
            .env("CARGO_HOME", prepared.root())
            .env("CARGO_TARGET_DIR", root.join("worker-target"));
        let output =
            super::super::bounded_command(replay, &seed, Duration::from_secs(30), OUTPUT_LIMIT)
                .unwrap();
        assert!(String::from_utf8_lossy(&output).contains("1 passed; 0 failed"));
        // The first retained view still works after user-home mutation; a fresh
        // capture must instead refuse the now-mismatched locked archive.
        let namespace = fs::read_dir(approved.join("registry/cache"))
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        fs::write(namespace.join("fixture-1.0.0.crate"), b"checksum mismatch").unwrap();
        let error = source.prepare(image, None).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("checksum-matching locked registry archive"),
            "{error}"
        );
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
