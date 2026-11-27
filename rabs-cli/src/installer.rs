//! The local generation owner. All namespace changes are descriptor-relative,
//! under the same persistent lock used by previous installer generations.

use flate2::read::MultiGzDecoder;
use rustix::fs::{AtFlags, FileType, FlockOperation, Mode, OFlags, Stat};
use serde::de::{self, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const TOOLS: [&str; 9] = [
    "cargo-rabs",
    "rabs-wrap",
    "rabsd",
    "rabs-wkr",
    "rabs-cargo-root",
    "rabs-delivery-cas",
    "rabs-recover",
    "rabs-cargo",
    "rabs-install",
];
const VERSIONS: &str = ".rabs-versions";
const CURRENT: &str = ".rabs-current";
const LOCK: &str = ".rabs-install.lock";
const MANIFEST: &str = "manifest.json";
const MAX_FILE_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_ARCHIVE_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const MAX_MANIFEST_BYTES: u64 = 64 * 1024;
const PROBE_TIMEOUT: Duration = Duration::from_secs(10);

fn digest_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push(DIGITS[(byte >> 4) as usize] as char);
        result.push(DIGITS[(byte & 15) as usize] as char);
    }
    result
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn require(condition: bool, message: impl Into<String>) -> io::Result<()> {
    if condition {
        Ok(())
    } else {
        Err(invalid(message))
    }
}

fn directory_flags() -> OFlags {
    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC
}

fn read_flags() -> OFlags {
    OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC
}

fn host_machine() -> io::Result<u16> {
    match std::env::consts::ARCH {
        "x86_64" => Ok(62),
        "aarch64" => Ok(183),
        _ => Err(invalid("unsupported Linux installation architecture")),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Stamp {
    device: i128,
    inode: i128,
    size: i128,
    modified: (i128, i128),
    changed: (i128, i128),
    owner: u32,
    mode: u32,
    links: i128,
}

impl Stamp {
    fn of(stat: &Stat) -> Self {
        Self {
            device: i128::from(stat.st_dev),
            inode: i128::from(stat.st_ino),
            size: i128::from(stat.st_size),
            modified: (i128::from(stat.st_mtime), i128::from(stat.st_mtime_nsec)),
            changed: (i128::from(stat.st_ctime), i128::from(stat.st_ctime_nsec)),
            owner: stat.st_uid,
            mode: stat.st_mode,
            links: i128::from(stat.st_nlink),
        }
    }

    fn same_inode(&self, other: &Self) -> bool {
        self.device == other.device && self.inode == other.inode
    }
}

fn named(directory: &File, name: impl AsRef<Path>) -> io::Result<Stat> {
    Ok(rustix::fs::statat(
        directory,
        name.as_ref(),
        AtFlags::SYMLINK_NOFOLLOW,
    )?)
}

fn source_stat(path: &Path) -> io::Result<Stat> {
    Ok(rustix::fs::statat(
        rustix::fs::CWD,
        path,
        AtFlags::SYMLINK_NOFOLLOW,
    )?)
}

fn check_directory(file: &File, private: bool) -> io::Result<()> {
    let metadata = rustix::fs::fstat(file)?;
    require(
        FileType::from_raw_mode(metadata.st_mode) == FileType::Directory
            && metadata.st_uid == rustix::process::geteuid().as_raw()
            && metadata.st_mode & if private { 0o077 } else { 0o022 } == 0,
        "installation directory has unsafe ownership or permissions",
    )
}

fn open_directory_at(parent: &File, name: &str, private: bool) -> io::Result<File> {
    let file = File::from(rustix::fs::openat(
        parent,
        name,
        directory_flags(),
        Mode::empty(),
    )?);
    check_directory(&file, private)?;
    Ok(file)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ToolIdentity {
    bytes: u64,
    sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema: u8,
    machine: u16,
    #[serde(deserialize_with = "unique_files")]
    files: BTreeMap<String, ToolIdentity>,
}

fn unique_files<'de, D>(deserializer: D) -> Result<BTreeMap<String, ToolIdentity>, D::Error>
where
    D: Deserializer<'de>,
{
    struct FilesVisitor;
    impl<'de> Visitor<'de> for FilesVisitor {
        type Value = BTreeMap<String, ToolIdentity>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("nine distinct RABS executable identities")
        }

        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
            let mut files = BTreeMap::new();
            while let Some((name, identity)) = map.next_entry::<String, ToolIdentity>()? {
                if files.insert(name, identity).is_some() || files.len() > TOOLS.len() {
                    return Err(de::Error::custom("duplicate or excessive tool identities"));
                }
            }
            Ok(files)
        }
    }
    deserializer.deserialize_map(FilesVisitor)
}

impl Manifest {
    fn validate(&self) -> io::Result<()> {
        require(
            self.schema == 1
                && matches!(self.machine, 62 | 183)
                && self.files.len() == TOOLS.len()
                && TOOLS.iter().all(|name| self.files.contains_key(*name)),
            "invalid complete RABS toolset manifest",
        )?;
        let mut total = 0;
        for identity in self.files.values() {
            require(
                (1..=MAX_FILE_BYTES).contains(&identity.bytes)
                    && identity.sha256.len() == 64
                    && identity
                        .sha256
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
                "invalid executable identity in toolset manifest",
            )?;
            total += identity.bytes;
        }
        require(
            total <= MAX_ARCHIVE_BYTES,
            "toolset exceeds its total byte limit",
        )
    }

    fn digest(&self) -> io::Result<String> {
        // Match the existing sorted, compact JSON representation independently
        // of serde_json's optional map ordering feature.
        #[derive(Serialize)]
        struct Canonical<'a> {
            files: &'a BTreeMap<String, ToolIdentity>,
            machine: u16,
            schema: u8,
        }
        self.validate()?;
        let bytes = serde_json::to_vec(&Canonical {
            files: &self.files,
            machine: self.machine,
            schema: self.schema,
        })?;
        Ok(digest_hex(&Sha256::digest(bytes)))
    }
}

fn require_native_elf(name: &str, prefix: &[u8]) -> io::Result<u16> {
    require(
        prefix.len() == 64
            && prefix[..7] == *b"\x7fELF\x02\x01\x01"
            && matches!(u16::from_le_bytes([prefix[16], prefix[17]]), 2 | 3),
        format!("{name} is not a Linux ELF64 executable"),
    )?;
    let machine = u16::from_le_bytes([prefix[18], prefix[19]]);
    require(
        matches!(machine, 62 | 183),
        format!("{name} has an unsupported ELF machine"),
    )?;
    Ok(machine)
}

fn executable_metadata(stat: &Stat, installed: bool) -> io::Result<u64> {
    require(
        FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile
            && stat.st_mode & 0o111 != 0
            && stat.st_size > 0
            && stat.st_size as u64 <= MAX_FILE_BYTES,
        "tool must be a bounded regular executable, never a link or special file",
    )?;
    if installed {
        require(
            stat.st_uid == rustix::process::geteuid().as_raw()
                && stat.st_nlink == 1
                && stat.st_mode & 0o7777 == 0o555,
            "installed executable has unsafe ownership, mode or link count",
        )?;
    }
    Ok(stat.st_size as u64)
}

fn inspect_bytes(name: &str, reader: &mut File, size: u64) -> io::Result<(ToolIdentity, u16)> {
    reader.seek(SeekFrom::Start(0))?;
    let mut digest = Sha256::new();
    let mut prefix = Vec::with_capacity(64);
    let mut remaining = size;
    let mut buffer = [0_u8; 64 * 1024];
    while remaining > 0 {
        let count = reader.read(&mut buffer[..remaining.min(64 * 1024) as usize])?;
        require(count > 0, format!("truncated executable: {name}"))?;
        prefix.extend_from_slice(&buffer[..count.min(64 - prefix.len())]);
        digest.update(&buffer[..count]);
        remaining -= count as u64;
    }
    require(
        reader.read(&mut buffer[..1])? == 0,
        format!("executable grew: {name}"),
    )?;
    let machine = require_native_elf(name, &prefix)?;
    Ok((
        ToolIdentity {
            bytes: size,
            sha256: digest_hex(&digest.finalize()),
        },
        machine,
    ))
}

struct CapturedTool {
    path: PathBuf,
    file: File,
    stamp: Stamp,
}

struct Sources {
    tools: BTreeMap<String, CapturedTool>,
    expected: Manifest,
    _extracted: Option<tempfile::TempDir>,
}

impl Sources {
    fn capture(paths: BTreeMap<String, PathBuf>) -> io::Result<Self> {
        let mut observed = BTreeMap::new();
        let mut total = 0_u64;
        for (name, path) in &paths {
            let metadata = source_stat(path)?;
            total += executable_metadata(&metadata, false)?;
            observed.insert(name.clone(), Stamp::of(&metadata));
        }
        require(
            total <= MAX_ARCHIVE_BYTES,
            "source toolset exceeds its total byte limit",
        )?;
        let mut tools = BTreeMap::new();
        let mut files = BTreeMap::new();
        let mut machines = BTreeSet::new();
        for (name, path) in paths {
            let mut file = File::from(rustix::fs::open(&path, read_flags(), Mode::empty())?);
            let metadata = rustix::fs::fstat(&file)?;
            let size = executable_metadata(&metadata, false)?;
            require(
                Stamp::of(&metadata) == observed[&name],
                "source changed before capture",
            )?;
            let (identity, machine) = inspect_bytes(&name, &mut file, size)?;
            files.insert(name.clone(), identity);
            machines.insert(machine);
            tools.insert(
                name.clone(),
                CapturedTool {
                    path,
                    file,
                    stamp: observed[&name].clone(),
                },
            );
        }
        require(
            machines.len() == 1,
            "source toolset mixes executable architectures",
        )?;
        let machine = *machines
            .first()
            .ok_or_else(|| invalid("source toolset is empty"))?;
        let expected = Manifest {
            schema: 1,
            machine,
            files,
        };
        expected.validate()?;
        let result = Self {
            tools,
            expected,
            _extracted: None,
        };
        result.revalidate()?;
        Ok(result)
    }

    fn revalidate(&self) -> io::Result<()> {
        for tool in self.tools.values() {
            require(
                Stamp::of(&rustix::fs::fstat(&tool.file)?) == tool.stamp
                    && Stamp::of(&source_stat(&tool.path)?) == tool.stamp,
                "source toolset changed during capture or installation",
            )?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
enum Source {
    Bundle(PathBuf),
    Build(PathBuf),
    Archive(PathBuf),
}

fn source_paths(root: &Path, split: bool) -> BTreeMap<String, PathBuf> {
    TOOLS
        .iter()
        .map(|name| {
            let profile = if matches!(
                *name,
                "cargo-rabs" | "rabs-cargo" | "rabs-recover" | "rabs-wrap" | "rabs-install"
            ) {
                "wrapper-release"
            } else {
                "daemon-release"
            };
            (
                (*name).to_owned(),
                if split {
                    root.join(profile).join(name)
                } else {
                    root.join(name)
                },
            )
        })
        .collect()
}

impl Source {
    fn capture(&self) -> io::Result<Sources> {
        match self {
            Self::Bundle(root) => Sources::capture(source_paths(root, false)),
            Self::Build(root) => Sources::capture(source_paths(root, true)),
            Self::Archive(path) => {
                let temporary = tempfile::Builder::new()
                    .prefix("rabs-native-bundle-")
                    .tempdir()?;
                unpack_archive(path, temporary.path(), MAX_ARCHIVE_BYTES)?;
                let mut sources = Sources::capture(source_paths(temporary.path(), false))?;
                sources._extracted = Some(temporary);
                Ok(sources)
            }
        }
    }
}

struct ArchiveBudget<R> {
    inner: R,
    remaining: u64,
}

impl<R: Read> Read for ArchiveBudget<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        if self.remaining == 0 {
            let mut excess = [0];
            return if self.inner.read(&mut excess)? == 0 {
                Ok(0)
            } else {
                Err(invalid("release archive exceeds its expanded byte limit"))
            };
        }
        let size = buffer
            .len()
            .min(self.remaining.min(usize::MAX as u64) as usize);
        let count = self.inner.read(&mut buffer[..size])?;
        self.remaining -= count as u64;
        Ok(count)
    }
}

fn unpack_archive(path: &Path, destination: &Path, limit: u64) -> io::Result<()> {
    let mut input = File::from(rustix::fs::open(path, read_flags(), Mode::empty())?);
    let before = rustix::fs::fstat(&input)?;
    require(
        FileType::from_raw_mode(before.st_mode) == FileType::RegularFile
            && before.st_size > 0
            && before.st_size as u64 <= limit,
        "release archive has an invalid compressed size or file type",
    )?;
    let destination = File::from(rustix::fs::open(
        destination,
        directory_flags(),
        Mode::empty(),
    )?);
    let mut seen = BTreeSet::new();
    let mut total = 0_u64;
    {
        // Raw iteration rejects GNU/PAX extensions before the tar library can
        // consume their payload. Never unpack filesystem paths from an archive.
        let decoded = ArchiveBudget {
            inner: MultiGzDecoder::new(&mut input),
            remaining: limit + 64 * 1024,
        };
        let mut archive = tar::Archive::new(decoded);
        for entry in archive.entries()?.raw(true) {
            let mut entry = entry?;
            require(
                matches!(entry.header().entry_type().as_byte(), 0 | b'0'),
                "unsupported release archive header",
            )?;
            let name = std::str::from_utf8(entry.path_bytes().as_ref())
                .map_err(|_| invalid("non-UTF-8 release archive member"))?
                .to_owned();
            require(
                TOOLS.contains(&name.as_str())
                    || matches!(name.as_str(), "rch" | "rchd" | "rch-wkr" | "install-rabs"),
                "unexpected or noncanonical release archive member",
            )?;
            require(
                seen.insert(name.clone()),
                "duplicate release archive member",
            )?;
            let size = entry.size();
            require(
                (1..=MAX_FILE_BYTES).contains(&size),
                "release member exceeds its byte limit",
            )?;
            total = total
                .checked_add(size)
                .ok_or_else(|| invalid("release archive byte count overflow"))?;
            require(
                total <= limit,
                "release archive exceeds its expanded byte limit",
            )?;
            let copied = if TOOLS.contains(&name.as_str()) {
                require(
                    entry.header().mode()? & 0o111 != 0,
                    "release tool is not executable",
                )?;
                let mut file = File::from(rustix::fs::openat(
                    &destination,
                    &name,
                    OFlags::WRONLY
                        | OFlags::CREATE
                        | OFlags::EXCL
                        | OFlags::NOFOLLOW
                        | OFlags::CLOEXEC,
                    Mode::from_raw_mode(0o700),
                )?);
                let count = io::copy(&mut entry, &mut file)?;
                rustix::fs::fchmod(&file, Mode::from_raw_mode(0o700))?;
                count
            } else {
                io::copy(&mut entry, &mut io::sink())?
            };
            require(copied == size, "truncated release archive member")?;
        }
        // Consume gzip trailers/CRC and reject hidden payload after the tar end.
        let mut decoded = archive.into_inner();
        let mut buffer = [0; 8192];
        let mut padding = 0;
        loop {
            let count = decoded.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            padding += count;
            require(
                padding <= 64 * 1024,
                "excessive release archive end padding",
            )?;
            require(
                buffer[..count].iter().all(|byte| *byte == 0),
                "unexpected data after release archive end",
            )?;
        }
    }
    require(
        Stamp::of(&rustix::fs::fstat(&input)?) == Stamp::of(&before)
            && Stamp::of(&source_stat(path)?) == Stamp::of(&before),
        "release archive changed during extraction",
    )?;
    require(
        TOOLS.iter().all(|name| seen.contains(*name)),
        "release archive is missing RABS tools",
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Link {
    stamp: Stamp,
    target: String,
}

fn generation_name(target: &str) -> io::Result<&str> {
    let name = target
        .strip_prefix(".rabs-versions/")
        .ok_or_else(|| invalid("unmanaged current generation symlink"))?;
    require(
        name.strip_prefix("gen-").is_some_and(|suffix| {
            !suffix.is_empty()
                && suffix
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        }),
        "unmanaged current generation symlink",
    )?;
    Ok(name)
}

fn check_links(directory: &File, complete: bool) -> io::Result<BTreeMap<String, Link>> {
    let mut links = BTreeMap::new();
    for name in TOOLS.iter().copied().chain(std::iter::once(CURRENT)) {
        let metadata = match named(directory, name) {
            Ok(metadata) => metadata,
            Err(error) if !complete && error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        require(
            FileType::from_raw_mode(metadata.st_mode) == FileType::Symlink
                && metadata.st_uid == rustix::process::geteuid().as_raw(),
            format!("refusing unmanaged installation entry: {name}"),
        )?;
        let target = rustix::fs::readlinkat(directory, name, Vec::new())?
            .into_string()
            .map_err(|_| invalid("non-UTF-8 managed symlink"))?;
        if name == CURRENT {
            generation_name(&target)?;
        } else {
            require(
                target == format!("{CURRENT}/{name}"),
                format!("refusing unmanaged symlink: {name}"),
            )?;
        }
        links.insert(
            name.to_owned(),
            Link {
                stamp: Stamp::of(&metadata),
                target,
            },
        );
    }
    Ok(links)
}

struct Installation {
    path: PathBuf,
    directory: File,
    lock: File,
    lock_stamp: Stamp,
}

impl Installation {
    fn open(path: &Path, writable: bool) -> io::Result<Self> {
        require(
            path.is_absolute(),
            "installation directory must be absolute",
        )?;
        if writable {
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o755)
                .create(path)?;
        }
        let directory = File::from(rustix::fs::open(path, directory_flags(), Mode::empty())?);
        check_directory(&directory, false)?;
        let flags = if writable {
            OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC
        } else {
            read_flags()
        };
        let lock = File::from(rustix::fs::openat(
            &directory,
            LOCK,
            flags,
            Mode::from_raw_mode(0o600),
        )?);
        let metadata = rustix::fs::fstat(&lock)?;
        require(
            FileType::from_raw_mode(metadata.st_mode) == FileType::RegularFile
                && metadata.st_uid == rustix::process::geteuid().as_raw()
                && metadata.st_nlink == 1
                && metadata.st_mode & 0o077 == 0,
            "unsafe RABS installation lock",
        )?;
        rustix::fs::flock(
            &lock,
            if writable {
                FlockOperation::NonBlockingLockExclusive
            } else {
                FlockOperation::NonBlockingLockShared
            },
        )
        .map_err(|error| {
            io::Error::new(
                io::ErrorKind::WouldBlock,
                format!("RABS installation lock is unavailable: {error}"),
            )
        })?;
        let installation = Self {
            path: path.to_owned(),
            directory,
            lock,
            lock_stamp: Stamp::of(&metadata),
        };
        installation.revalidate()?;
        Ok(installation)
    }

    fn revalidate(&self) -> io::Result<()> {
        check_directory(&self.directory, false)?;
        let root = source_stat(&self.path)?;
        require(
            FileType::from_raw_mode(root.st_mode) == FileType::Directory
                && Stamp::of(&root).same_inode(&Stamp::of(&rustix::fs::fstat(&self.directory)?)),
            "installation directory changed",
        )?;
        require(
            Stamp::of(&named(&self.directory, LOCK)?) == self.lock_stamp
                && Stamp::of(&rustix::fs::fstat(&self.lock)?) == self.lock_stamp,
            "installation lock changed",
        )
    }
}

fn verify_child_directory(parent: &File, name: &str, held: &File) -> io::Result<()> {
    check_directory(held, true)?;
    let current = named(parent, name)?;
    require(
        FileType::from_raw_mode(current.st_mode) == FileType::Directory
            && Stamp::of(&current).same_inode(&Stamp::of(&rustix::fs::fstat(held)?)),
        "installation child directory changed",
    )
}

fn inventory(directory: &File) -> io::Result<()> {
    let mut entries = BTreeSet::new();
    for entry in rustix::fs::Dir::read_from(directory)? {
        let entry = entry?;
        let name = entry.file_name().to_bytes();
        if matches!(name, b"." | b"..") {
            continue;
        }
        require(
            entries.len() < TOOLS.len() + 1,
            "generation has unexpected entries",
        )?;
        entries.insert(name.to_vec());
    }
    require(
        entries.len() == TOOLS.len() + 1
            && TOOLS
                .iter()
                .copied()
                .chain(std::iter::once(MANIFEST))
                .all(|name| entries.contains(name.as_bytes())),
        "generation has missing or unexpected entries",
    )
}

fn read_manifest(directory: &File) -> io::Result<(Manifest, Stamp)> {
    let mut file = File::from(rustix::fs::openat(
        directory,
        MANIFEST,
        read_flags(),
        Mode::empty(),
    )?);
    let metadata = rustix::fs::fstat(&file)?;
    require(
        FileType::from_raw_mode(metadata.st_mode) == FileType::RegularFile
            && metadata.st_uid == rustix::process::geteuid().as_raw()
            && metadata.st_nlink == 1
            && metadata.st_mode & 0o022 == 0
            && metadata.st_size > 0
            && metadata.st_size as u64 <= MAX_MANIFEST_BYTES,
        "unsafe active generation manifest",
    )?;
    let before = Stamp::of(&metadata);
    let mut bytes = Vec::new();
    (&mut file)
        .take(MAX_MANIFEST_BYTES + 1)
        .read_to_end(&mut bytes)?;
    require(
        bytes.len() as i128 == before.size
            && Stamp::of(&rustix::fs::fstat(&file)?) == before
            && Stamp::of(&named(directory, MANIFEST)?) == before,
        "generation manifest changed during verification",
    )?;
    let manifest: Manifest = serde_json::from_slice(&bytes)?;
    manifest.validate()?;
    Ok((manifest, before))
}

fn verify_generation(directory: &File, expected: Option<&Manifest>) -> io::Result<Manifest> {
    let before = Stamp::of(&rustix::fs::fstat(directory)?);
    inventory(directory)?;
    let (manifest, manifest_stamp) = read_manifest(directory)?;
    require(
        manifest.machine == host_machine()?,
        "generation is not native to this host",
    )?;
    if let Some(expected) = expected {
        require(
            manifest == *expected,
            "active generation differs from the expected toolset",
        )?;
    }
    let mut observed = BTreeMap::from([(MANIFEST.to_owned(), manifest_stamp)]);
    for name in TOOLS {
        let mut file = File::from(rustix::fs::openat(
            directory,
            name,
            read_flags(),
            Mode::empty(),
        )?);
        let metadata = rustix::fs::fstat(&file)?;
        let size = executable_metadata(&metadata, true)?;
        require(
            size == manifest.files[name].bytes,
            format!("installed executable size differs: {name}"),
        )?;
        let (identity, machine) = inspect_bytes(name, &mut file, size)?;
        require(
            identity == manifest.files[name] && machine == manifest.machine,
            format!("installed executable differs from expected bytes: {name}"),
        )?;
        let stamp = Stamp::of(&metadata);
        require(
            Stamp::of(&rustix::fs::fstat(&file)?) == stamp,
            "installed executable changed during verification",
        )?;
        observed.insert(name.to_owned(), stamp);
    }
    for (name, stamp) in observed {
        require(
            Stamp::of(&named(directory, name)?) == stamp,
            "active generation changed during verification",
        )?;
    }
    inventory(directory)?;
    require(
        Stamp::of(&rustix::fs::fstat(directory)?) == before,
        "generation directory changed during verification",
    )?;
    Ok(manifest)
}

struct ActiveGeneration {
    installation: Installation,
    versions: File,
    directory: File,
    name: String,
    links: BTreeMap<String, Link>,
}

impl ActiveGeneration {
    fn open(root: &Path) -> io::Result<Self> {
        let installation = Installation::open(root, false)?;
        let links = check_links(&installation.directory, true)?;
        let name = generation_name(&links[CURRENT].target)?.to_owned();
        let versions = open_directory_at(&installation.directory, VERSIONS, true)?;
        let directory = open_directory_at(&versions, &name, true)?;
        Ok(Self {
            installation,
            versions,
            directory,
            name,
            links,
        })
    }

    fn verify(&self, expected: Option<&Manifest>) -> io::Result<Manifest> {
        let manifest = verify_generation(&self.directory, expected)?;
        require(
            check_links(&self.installation.directory, true)? == self.links,
            "active generation links changed during verification",
        )?;
        verify_child_directory(&self.installation.directory, VERSIONS, &self.versions)?;
        verify_child_directory(&self.versions, &self.name, &self.directory)?;
        self.installation.revalidate()?;
        Ok(manifest)
    }
}

fn verify_installed(expected: &Manifest, root: &Path) -> io::Result<Value> {
    expected.validate()?;
    require(
        expected.machine == host_machine()?,
        "expected toolset is not native to this host",
    )?;
    let active = ActiveGeneration::open(root)?;
    let manifest = active.verify(Some(expected))?;
    Ok(json!({
        "kind": "rabs-install-verification", "state": "verified", "bin_dir": root,
        "generation": active.name, "machine": manifest.machine, "files": manifest.files,
        "expected_toolset_sha256": expected.digest()?, "installation_changed": false,
        "services_started": false, "cargo_config_changed": false,
    }))
}

fn new_generation(versions: &File) -> io::Result<(String, File)> {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| invalid("installation clock predates the epoch"))?
        .as_nanos();
    for _ in 0..32 {
        let name = format!(
            "gen-{}-{timestamp:x}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        );
        match rustix::fs::mkdirat(versions, &name, Mode::from_raw_mode(0o700)) {
            Ok(()) => {
                let directory = open_directory_at(versions, &name, true)?;
                return Ok((name, directory));
            }
            Err(rustix::io::Errno::EXIST) => continue,
            Err(error) => return Err(error.into()),
        }
    }
    Err(invalid("could not allocate a unique retained generation"))
}

fn copy_sources(sources: &mut Sources, directory: &File) -> io::Result<()> {
    sources.revalidate()?;
    for (name, tool) in &mut sources.tools {
        let mut output = File::from(rustix::fs::openat(
            directory,
            name,
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )?);
        tool.file.seek(SeekFrom::Start(0))?;
        let identity = &sources.expected.files[name];
        let count = io::copy(&mut (&mut tool.file).take(identity.bytes + 1), &mut output)?;
        require(
            count == identity.bytes,
            "source changed length during installation",
        )?;
        output.flush()?;
        rustix::fs::fchmod(&output, Mode::from_raw_mode(0o555))?;
        output.sync_all()?;
        let (copied, machine) = inspect_bytes(name, &mut output, count)?;
        require(
            copied == *identity && machine == sources.expected.machine,
            "staged executable failed byte or ELF verification",
        )?;
    }
    sources.revalidate()?;
    let mut manifest = File::from(rustix::fs::openat(
        directory,
        MANIFEST,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )?);
    serde_json::to_writer_pretty(&mut manifest, &sources.expected)?;
    manifest.write_all(b"\n")?;
    // Independent of inherited umask, manifests are private even under 0002.
    rustix::fs::fchmod(&manifest, Mode::from_raw_mode(0o600))?;
    manifest.sync_all()?;
    directory.sync_all()
}

fn install(sources: &mut Sources, root: &Path, probe: bool) -> io::Result<Value> {
    require(
        sources.expected.machine == host_machine()?,
        "source toolset is not native to this host",
    )?;
    sources.revalidate()?;
    let installation = Installation::open(root, true)?;
    check_links(&installation.directory, false)?;
    match rustix::fs::mkdirat(
        &installation.directory,
        VERSIONS,
        Mode::from_raw_mode(0o700),
    ) {
        Ok(()) | Err(rustix::io::Errno::EXIST) => (),
        Err(error) => return Err(error.into()),
    }
    let versions = open_directory_at(&installation.directory, VERSIONS, true)?;
    // Failed stages and previous generations deliberately remain for inspection.
    let (name, directory) = new_generation(&versions)?;
    copy_sources(sources, &directory)?;
    versions.sync_all()?;
    if probe {
        probe_launchers(&directory)?;
    }
    verify_generation(&directory, Some(&sources.expected))?;
    sources.revalidate()?;
    installation.revalidate()?;
    verify_child_directory(&installation.directory, VERSIONS, &versions)?;
    verify_child_directory(&versions, &name, &directory)?;
    check_links(&installation.directory, false)?;
    for tool in TOOLS {
        match rustix::fs::symlinkat(format!("{CURRENT}/{tool}"), &installation.directory, tool) {
            Ok(()) => (),
            Err(rustix::io::Errno::EXIST) => {
                check_links(&installation.directory, false)?;
            }
            Err(error) => return Err(error.into()),
        }
    }
    let pending = format!(".rabs-activate-{name}");
    rustix::fs::symlinkat(
        format!("{VERSIONS}/{name}"),
        &installation.directory,
        &pending,
    )?;
    installation.directory.sync_all()?;
    // This is the sole activation point. No executable is overwritten in place.
    rustix::fs::renameat(
        &installation.directory,
        &pending,
        &installation.directory,
        CURRENT,
    )?;
    installation.directory.sync_all()?;
    Ok(json!({
        "kind": "rabs-installed", "bin_dir": root, "generation": name, "machine": sources.expected.machine,
        "files": sources.expected.files, "services_started": false, "cargo_config_changed": false,
    }))
}

struct ProbeChild {
    child: Child,
    owned: bool,
}

impl ProbeChild {
    fn waitable(&mut self) -> io::Result<bool> {
        use rustix::process::{Pid, WaitId, WaitIdOptions, waitid};
        match waitid(
            WaitId::Pid(Pid::from_child(&self.child)),
            WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT,
        ) {
            Ok(status) => Ok(status.is_some()),
            Err(rustix::io::Errno::INTR) => Ok(false),
            Err(error) => {
                if error == rustix::io::Errno::CHILD {
                    // An auto-reaped leader no longer fences numeric PGID reuse.
                    self.owned = false;
                }
                Err(error.into())
            }
        }
    }

    fn finish(&mut self) -> io::Result<ExitStatus> {
        use rustix::process::{Pid, Signal, kill_process_group};
        require(self.owned, "launch check lost its child identity")?;
        let result = (|| {
            self.waitable()?;
            // Keep the leader waitable until all in-group descendants have
            // been signaled, including descendants surviving a successful exit.
            let signal = kill_process_group(Pid::from_child(&self.child), Signal::KILL);
            if signal.is_err_and(|error| error != rustix::io::Errno::SRCH) {
                let _ = self.child.kill();
            }
            let deadline = Instant::now() + Duration::from_millis(250);
            loop {
                if self.waitable()? {
                    let status = self.child.wait()?;
                    return match signal {
                        Ok(()) | Err(rustix::io::Errno::SRCH) => Ok(status),
                        Err(error) => Err(error.into()),
                    };
                }
                require(
                    Instant::now() < deadline,
                    "launch check cleanup could not be confirmed",
                )?;
                std::thread::sleep(Duration::from_millis(2));
            }
        })();
        self.owned = false;
        result
    }
}

impl Drop for ProbeChild {
    fn drop(&mut self) {
        if self.owned {
            let _ = self.finish();
        }
    }
}

fn require_child_ownership() -> io::Result<()> {
    let mut status = String::new();
    File::open("/proc/self/status")?
        .take(64 * 1024)
        .read_to_string(&mut status)?;
    let ignored = status
        .lines()
        .find_map(|line| line.strip_prefix("SigIgn:"))
        .and_then(|value| u64::from_str_radix(value.trim(), 16).ok())
        .ok_or_else(|| invalid("launch check cannot establish child ownership"))?;
    require(
        ignored & (1_u64 << (rustix::process::Signal::CHILD.as_raw() - 1)) == 0,
        "ignored SIGCHLD prevents safe launch checks",
    )
}

fn probe_command(command: &mut Command, timeout: Duration) -> io::Result<()> {
    require_child_ownership()?;
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0);
    let mut probe = ProbeChild {
        child: command.spawn()?,
        owned: true,
    };
    let deadline = Instant::now() + timeout;
    loop {
        if probe.waitable()? {
            return require(
                probe.finish()?.success(),
                "native launcher check returned failure",
            );
        }
        if Instant::now() >= deadline {
            probe.finish()?;
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "native launcher check exceeded its deadline",
            ));
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn external_true() -> io::Result<PathBuf> {
    let search = std::env::var_os("PATH").unwrap_or_default();
    for directory in std::env::split_paths(&search) {
        let path = std::path::absolute(directory.join("true"))?;
        if fs::metadata(&path).is_ok_and(|metadata| metadata.is_file())
            && rustix::fs::accessat(
                rustix::fs::CWD,
                &path,
                rustix::fs::Access::EXEC_OK,
                AtFlags::EACCESS,
            )
            .is_ok()
        {
            return Ok(path);
        }
    }
    Err(invalid(
        "wrapper launch check requires an external true executable on PATH",
    ))
}

fn probe_launchers(directory: &File) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    let true_program = external_true()?;
    // Resolve every executable through the held generation, never through a
    // public symlink which might select a different set between two launches.
    for name in TOOLS {
        let executable =
            PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd())).join(name);
        let mut command = Command::new(executable);
        match name {
            "rabs-wrap" => {
                command.arg(&true_program).arg("-vV");
            }
            "rabsd" | "rabs-wkr" | "rabs-cargo-root" => {
                command.arg("--version");
            }
            _ => {
                command.arg("--help");
            }
        }
        probe_command(&mut command, PROBE_TIMEOUT).map_err(|error| {
            io::Error::new(error.kind(), format!("{name} launch check failed: {error}"))
        })?;
    }
    Ok(())
}

fn probe_installed(root: &Path) -> io::Result<Value> {
    let active = ActiveGeneration::open(root)?;
    let manifest = active.verify(None)?;
    probe_launchers(&active.directory)?;
    active.verify(Some(&manifest))?;
    // This is a launch check, not a trusted-source verification receipt: the
    // manifest alone cannot authorize a claim that a publisher's bytes match.
    Ok(json!({
        "kind": "rabs-launch-check", "state": "passed", "bin_dir": root,
        "generation": active.name, "files": manifest.files, "installation_changed": false,
        "services_started": false, "cargo_config_changed": false,
    }))
}

#[derive(Debug)]
struct Options {
    source: Option<Source>,
    root: PathBuf,
    verify: bool,
    probe: bool,
    probe_installed: bool,
}

fn parse(arguments: &[OsString]) -> io::Result<Options> {
    let mut source = None;
    let mut root = None;
    let mut verify = false;
    let mut probe = false;
    let mut probe_installed = false;
    let mut seen = BTreeSet::new();
    let mut arguments = arguments.iter();
    while let Some(argument) = arguments.next() {
        let option = argument
            .to_str()
            .ok_or_else(|| invalid("non-UTF-8 installer option"))?;
        require(seen.insert(option), "repeated installer option")?;
        match option {
            "--from-build" | "--from-bundle" | "--from-archive" => {
                require(source.is_none(), "select exactly one source toolset")?;
                let value = arguments
                    .next()
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| invalid("source option requires a path"))?;
                let path = std::path::absolute(value)?;
                source = Some(match option {
                    "--from-build" => Source::Build(path),
                    "--from-bundle" => Source::Bundle(path),
                    _ => Source::Archive(path),
                });
            }
            "--bin-dir" => {
                let value = arguments
                    .next()
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| invalid("--bin-dir requires an absolute directory"))?;
                require(
                    Path::new(value).is_absolute(),
                    "--bin-dir requires an absolute directory",
                )?;
                root = Some(std::path::absolute(value)?);
            }
            "--verify" => verify = true,
            "--probe" => probe = true,
            "--probe-installed" => probe_installed = true,
            _ => return Err(invalid("unsupported local installer option (see --help)")),
        }
    }
    require(
        !(verify && probe) && !(probe_installed && (verify || probe || source.is_some())),
        "verification, staged launch checks and installed launch checks are distinct operations",
    )?;
    require(
        source.is_some() || probe_installed,
        "select a source toolset or --probe-installed",
    )?;
    let root = root
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/bin")))
        .ok_or_else(|| invalid("--bin-dir is required when HOME is unavailable"))?;
    require(
        root.is_absolute() && root.to_str().is_some(),
        "installation directory must be an absolute UTF-8 path",
    )?;
    Ok(Options {
        source,
        root,
        verify,
        probe,
        probe_installed,
    })
}

pub(crate) fn run(arguments: &[OsString]) -> io::Result<(Value, bool)> {
    let options = parse(arguments)?;
    host_machine()?;
    if options.probe_installed {
        return Ok((probe_installed(&options.root)?, true));
    }
    let mut sources = options
        .source
        .as_ref()
        .ok_or_else(|| invalid("source toolset is missing"))?
        .capture()?;
    if options.verify {
        let receipt = match verify_installed(&sources.expected, &options.root) {
            Ok(receipt) => receipt,
            Err(error) => json!({
                "kind": "rabs-install-verification", "state": "unverified", "bin_dir": options.root,
                "error": error.to_string(), "expected_toolset_sha256": sources.expected.digest()?,
                "installation_changed": false, "services_started": false, "cargo_config_changed": false,
            }),
        };
        let success = receipt["state"] == "verified";
        return Ok((receipt, success));
    }
    Ok((install(&mut sources, &options.root, options.probe)?, true))
}

#[cfg(test)]
mod tests;
