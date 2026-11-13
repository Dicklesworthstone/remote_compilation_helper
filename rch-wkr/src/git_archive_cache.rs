//! Verified immutable Git archive reuse inside an already granted target pool.
//!
//! Source and target ownership belong to the dispatcher. This helper neither
//! acquires those grants nor retires source. A cache hit is an independently
//! hashed private copy; no writable hard link or cache metadata can authorize
//! source bytes. All filesystem operations stay bound to retained directory
//! descriptors, and an unsafe namespace is a failure, never an invented miss.

use std::io::{self, Write as _};

#[cfg(unix)]
const PROBE: &str = "rch-wkr git-archive-cache v1\n";
#[cfg(unix)]
const PREFIX: &str = "RCH_GIT_ARCHIVE_CACHE_V1 ";
const ERROR_PREFIX: &str = "RCH_GIT_ARCHIVE_CACHE_ERROR:";
const REFUSED: i32 = 74;

/// Run before the async runtime and optional file logging are initialized.
pub fn main(arguments: &[String]) -> i32 {
    #[cfg(unix)]
    let result = if arguments == ["probe"] {
        io::stdout().lock().write_all(PROBE.as_bytes())
    } else {
        match native::run(arguments) {
            Ok(status) => writeln!(io::stdout().lock(), "{PREFIX}{status}"),
            Err(error) => {
                let _ = writeln!(io::stderr().lock(), "{ERROR_PREFIX}{error}");
                return REFUSED;
            }
        }
    };
    #[cfg(not(unix))]
    let result: io::Result<()> = {
        let _ = arguments;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Git archive cache requires a Unix worker",
        ))
    };
    match result {
        Ok(()) => 0,
        Err(error) => {
            let _ = writeln!(io::stderr().lock(), "{ERROR_PREFIX}{error}");
            REFUSED
        }
    }
}

#[cfg(unix)]
mod native {
    use rustix::fd::{AsFd, OwnedFd};
    use rustix::fs::{AtFlags, Dir, FileType, Mode, OFlags, Stat};
    use rustix::io::Errno;
    use sha2::{Digest as _, Sha256};
    use std::collections::{BTreeMap, BTreeSet};
    use std::fs::File;
    use std::io::{self, Read as _, Seek as _, SeekFrom, Write as _};
    use std::sync::Arc;

    const CACHE_DIRECTORY: &str = ".rch-git-archive-cache-v1";
    const SOURCE_ARCHIVE: &str = ".rch-clean-overlay-base.tar";
    const MAGIC: &[u8] = b"RCH-GIT-ARCHIVE-CACHE-V1\n";
    const SCHEMA: &str = "rch.git_archive_cache.v1";
    const MAX_HEADER_BYTES: usize = 1024;
    const MAX_CACHE_BYTES: u64 = 1024 * 1024 * 1024;
    const MAX_SLOTS: usize = 64;
    const BLOCK_BYTES: usize = 1024 * 1024;
    const DIRECTORY_FLAGS: OFlags = OFlags::RDONLY
        .union(OFlags::DIRECTORY)
        .union(OFlags::NOFOLLOW)
        .union(OFlags::CLOEXEC);
    const FILE_FLAGS: OFlags = OFlags::NOFOLLOW
        .union(OFlags::CLOEXEC)
        .union(OFlags::NONBLOCK)
        .union(OFlags::NOCTTY);

    #[derive(Debug, thiserror::Error)]
    enum Error {
        #[error("{0}")]
        Unsafe(&'static str),
        #[error("{0}")]
        Corrupt(&'static str),
        #[error("{0}")]
        Bypass(&'static str),
        #[error("filesystem:{0}")]
        Io(#[from] io::Error),
    }

    impl From<Errno> for Error {
        fn from(error: Errno) -> Self {
            Self::Io(error.into())
        }
    }

    type Result<T> = std::result::Result<T, Error>;

    fn require(condition: bool, detail: &'static str) -> Result<()> {
        if condition {
            Ok(())
        } else {
            Err(Error::Unsafe(detail))
        }
    }

    fn bypass_for_io(error: &io::Error) -> Option<&'static str> {
        let code = error.raw_os_error()?;
        if [Errno::NOSPC, Errno::DQUOT]
            .iter()
            .any(|error| error.raw_os_error() == code)
        {
            Some("BYPASS_CAPACITY")
        } else if [Errno::ROFS, Errno::NOSYS, Errno::NOTSUP]
            .iter()
            .any(|error| error.raw_os_error() == code)
        {
            Some("BYPASS_UNAVAILABLE")
        } else {
            None
        }
    }

    fn classify(result: Result<&'static str>) -> Result<&'static str> {
        match result {
            Err(Error::Corrupt(_)) => Ok("BYPASS_CORRUPT"),
            Err(Error::Bypass(status)) => Ok(status),
            Err(Error::Io(error)) => match bypass_for_io(&error) {
                Some(status) => Ok(status),
                None => Err(Error::Io(error)),
            },
            result => result,
        }
    }

    fn literal_path(value: &str) -> bool {
        value.starts_with('/')
            && value != "/"
            && value.len() <= 4096
            && !value.contains('\\')
            && !value.chars().any(|ch| ch < ' ' || ch == '\u{7f}')
            && value[1..]
                .split('/')
                .all(|part| !matches!(part, "" | "." | ".."))
            && value.split('/').count() <= 128
    }

    fn hex(value: &str) -> bool {
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }

    fn byte_limit(value: &str) -> Result<u64> {
        require(
            !value.is_empty()
                && value.len() <= 20
                && value.bytes().all(|byte| byte.is_ascii_digit()),
            "invalid cache byte limits",
        )?;
        value
            .parse::<u64>()
            .ok()
            .filter(|value| *value <= i64::MAX as u64)
            .ok_or(Error::Unsafe("cache byte limits out of range"))
    }

    struct Request<'a> {
        operation: &'a str,
        source: &'a str,
        target: &'a str,
        slot: &'a str,
        digest: &'a str,
        size: u64,
        minimum: u64,
    }

    impl<'a> Request<'a> {
        fn parse(arguments: &'a [String]) -> Result<Self> {
            let [operation, source, target, slot, digest, size, minimum] = arguments else {
                return Err(Error::Unsafe("expected operation and six arguments"));
            };
            require(
                matches!(operation.as_str(), "restore" | "publish"),
                "invalid cache operation",
            )?;
            require(
                literal_path(source) && literal_path(target),
                "nonliteral root",
            )?;
            require(
                source != target
                    && !source.starts_with(&format!("{target}/"))
                    && !target.starts_with(&format!("{source}/")),
                "source and target roots overlap",
            )?;
            require(hex(slot) && hex(digest), "invalid digest or slot")?;
            let size = byte_limit(size)?;
            require(size > 0, "cache byte limits out of range")?;
            Ok(Self {
                operation,
                source,
                target,
                slot,
                digest,
                size,
                minimum: byte_limit(minimum)?,
            })
        }
    }

    fn same_inode(left: &Stat, right: &Stat) -> bool {
        left.st_dev == right.st_dev && left.st_ino == right.st_ino
    }

    fn same_snapshot(left: &Stat, right: &Stat) -> bool {
        same_inode(left, right)
            && left.st_mode == right.st_mode
            && left.st_uid == right.st_uid
            && left.st_gid == right.st_gid
            && left.st_nlink == right.st_nlink
            && left.st_size == right.st_size
            && left.st_mtime == right.st_mtime
            && left.st_mtime_nsec == right.st_mtime_nsec
            && left.st_ctime == right.st_ctime
            && left.st_ctime_nsec == right.st_ctime_nsec
    }

    fn trusted_ancestor(info: &Stat) -> bool {
        (info.st_uid == 0 || info.st_uid == rustix::process::geteuid().as_raw())
            && (info.st_mode & 0o022 == 0 || info.st_mode & 0o1000 != 0)
    }

    fn directory_metadata(info: &Stat, final_component: bool, private: bool) -> Result<()> {
        require(
            FileType::from_raw_mode(info.st_mode) == FileType::Directory,
            "non-directory root or ancestor",
        )?;
        require(
            info.st_uid == rustix::process::geteuid().as_raw()
                || (!final_component && info.st_uid == 0),
            "foreign directory owner",
        )?;
        require(
            info.st_mode & 0o022 == 0 || (!final_component && info.st_mode & 0o1000 != 0),
            "writable directory namespace",
        )?;
        require(
            !private || info.st_mode & 0o077 == 0,
            "cache directory is not private",
        )
    }

    fn regular_metadata(info: &Stat) -> Result<()> {
        require(
            FileType::from_raw_mode(info.st_mode) == FileType::RegularFile,
            "nonregular archive entry",
        )?;
        require(
            info.st_uid == rustix::process::geteuid().as_raw(),
            "foreign archive owner",
        )?;
        require(info.st_nlink == 1, "hardlinked archive entry")?;
        require(info.st_mode & 0o022 == 0, "writable archive entry")
    }

    fn named_metadata(parent: impl AsFd, name: &str) -> Result<Option<Stat>> {
        match rustix::fs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(info) => Ok(Some(info)),
            Err(Errno::NOENT) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    #[derive(Clone)]
    struct Anchor {
        parent: Arc<OwnedFd>,
        name: String,
        descriptor: Arc<OwnedFd>,
        final_component: bool,
        private: bool,
    }

    struct Directory {
        descriptor: Arc<OwnedFd>,
        anchors: Vec<Anchor>,
    }

    impl Directory {
        fn fd(&self) -> &OwnedFd {
            &self.descriptor
        }

        fn check(&self) -> Result<()> {
            for anchor in &self.anchors {
                let named = rustix::fs::statat(
                    &*anchor.parent,
                    anchor.name.as_str(),
                    AtFlags::SYMLINK_NOFOLLOW,
                )?;
                let opened = rustix::fs::fstat(&*anchor.descriptor)?;
                directory_metadata(&named, anchor.final_component, anchor.private)?;
                require(
                    same_inode(&named, &opened),
                    "directory changed during cache operation",
                )?;
            }
            Ok(())
        }

        fn open(path: &str, create: bool) -> Result<Option<Self>> {
            let mut current = Arc::new(rustix::fs::open("/", DIRECTORY_FLAGS, Mode::empty())?);
            let mut anchors = Vec::new();
            let parts: Vec<_> = path[1..].split('/').collect();
            for (index, name) in parts.iter().enumerate() {
                let final_component = index + 1 == parts.len();
                let named = match named_metadata(&*current, name)? {
                    Some(named) => named,
                    None if !create => return Ok(None),
                    None if !final_component => return Err(Error::Bypass("BYPASS_UNAVAILABLE")),
                    None => {
                        rustix::fs::mkdirat(&*current, *name, Mode::from_raw_mode(0o755))?;
                        rustix::fs::statat(&*current, *name, AtFlags::SYMLINK_NOFOLLOW)?
                    }
                };
                let kind = FileType::from_raw_mode(named.st_mode);
                if !final_component
                    && (kind == FileType::Symlink
                        || (kind == FileType::Directory && !trusted_ancestor(&named)))
                {
                    return Err(Error::Bypass("BYPASS_UNAVAILABLE"));
                }
                directory_metadata(&named, final_component, false)?;
                let next = Arc::new(rustix::fs::openat(
                    &*current,
                    *name,
                    DIRECTORY_FLAGS,
                    Mode::empty(),
                )?);
                require(
                    same_inode(&named, &rustix::fs::fstat(&*next)?),
                    "directory changed while opening",
                )?;
                anchors.push(Anchor {
                    parent: current,
                    name: (*name).to_owned(),
                    descriptor: Arc::clone(&next),
                    final_component,
                    private: false,
                });
                current = next;
            }
            let result = Self {
                descriptor: current,
                anchors,
            };
            result.check()?;
            Ok(Some(result))
        }

        fn cache(&self, create: bool) -> Result<Option<Self>> {
            let named = match named_metadata(self.fd(), CACHE_DIRECTORY)? {
                Some(named) => named,
                None if !create => return Ok(None),
                None => {
                    self.check()?;
                    rustix::fs::mkdirat(self.fd(), CACHE_DIRECTORY, Mode::from_raw_mode(0o700))?;
                    rustix::fs::statat(self.fd(), CACHE_DIRECTORY, AtFlags::SYMLINK_NOFOLLOW)?
                }
            };
            directory_metadata(&named, true, true)?;
            let descriptor = Arc::new(rustix::fs::openat(
                self.fd(),
                CACHE_DIRECTORY,
                DIRECTORY_FLAGS,
                Mode::empty(),
            )?);
            require(
                same_inode(&named, &rustix::fs::fstat(&*descriptor)?),
                "cache directory changed while opening",
            )?;
            let mut anchors = self.anchors.clone();
            anchors.push(Anchor {
                parent: Arc::clone(&self.descriptor),
                name: CACHE_DIRECTORY.into(),
                descriptor: Arc::clone(&descriptor),
                final_component: true,
                private: true,
            });
            let result = Self {
                descriptor,
                anchors,
            };
            result.check()?;
            Ok(Some(result))
        }
    }

    fn entry_metadata(directory: &Directory, name: &str) -> Result<Option<Stat>> {
        let info = named_metadata(directory.fd(), name)?;
        if let Some(info) = &info {
            regular_metadata(info)?;
        }
        Ok(info)
    }

    struct OpenFile {
        file: File,
        before: Stat,
    }

    fn open_regular(directory: &Directory, name: &str) -> Result<Option<OpenFile>> {
        let Some(before) = entry_metadata(directory, name)? else {
            return Ok(None);
        };
        let file = File::from(rustix::fs::openat(
            directory.fd(),
            name,
            FILE_FLAGS | OFlags::RDONLY,
            Mode::empty(),
        )?);
        let opened = rustix::fs::fstat(&file)?;
        regular_metadata(&opened)?;
        require(
            same_snapshot(&before, &opened),
            "archive changed while opening",
        )?;
        Ok(Some(OpenFile {
            file,
            before: opened,
        }))
    }

    fn unchanged(directory: &Directory, name: &str, opened: &OpenFile) -> Result<()> {
        directory.check()?;
        let after = rustix::fs::fstat(&opened.file)?;
        let named = entry_metadata(directory, name)?;
        require(
            named.is_some_and(|named| {
                same_snapshot(&opened.before, &after) && same_snapshot(&after, &named)
            }),
            "archive changed during cache operation",
        )
    }

    struct Inventory {
        slots: BTreeSet<String>,
        entries: BTreeMap<String, Stat>,
        total: u64,
    }

    fn inventory(cache: &Directory) -> Result<Inventory> {
        cache.check()?;
        let mut result = Inventory {
            slots: BTreeSet::new(),
            entries: BTreeMap::new(),
            total: 0,
        };
        for entry in Dir::read_from(cache.fd())? {
            let entry = entry?;
            let name = entry.file_name().to_bytes();
            if matches!(name, b"." | b"..") {
                continue;
            }
            if result.entries.len() >= MAX_SLOTS * 2 {
                return Err(Error::Bypass("BYPASS_CAPACITY"));
            }
            let name =
                std::str::from_utf8(name).map_err(|_| Error::Corrupt("unexpected cache entry"))?;
            let slot = name
                .strip_suffix(".sealed")
                .or_else(|| name.strip_suffix(".pending"))
                .filter(|slot| hex(slot))
                .ok_or(Error::Corrupt("unexpected cache entry"))?;
            let info =
                entry_metadata(cache, name)?.ok_or(Error::Unsafe("cache inventory changed"))?;
            let size =
                u64::try_from(info.st_size).map_err(|_| Error::Unsafe("invalid archive size"))?;
            result.slots.insert(slot.to_owned());
            result.total = result.total.saturating_add(size);
            result.entries.insert(name.to_owned(), info);
            if result.slots.len() > MAX_SLOTS || result.total > MAX_CACHE_BYTES {
                return Err(Error::Bypass("BYPASS_CAPACITY"));
            }
        }
        cache.check()?;
        Ok(result)
    }

    // This field order is the existing canonical ASCII JSON wire order. All
    // strings are fixed ASCII or lowercase hex; serde introduces no new escapes.
    #[derive(serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Header {
        schema: String,
        sha256: String,
        size: u64,
        slot: String,
    }

    fn header_bytes(slot: &str, digest: &str, size: u64) -> Vec<u8> {
        let header = Header {
            schema: SCHEMA.into(),
            sha256: digest.into(),
            size,
            slot: slot.into(),
        };
        let mut bytes = MAGIC.to_vec();
        serde_json::to_writer(&mut bytes, &header).expect("bounded archive header serializes");
        bytes.push(b'\n');
        bytes
    }

    fn read_header(file: &mut File, expected_slot: &str, file_size: u64) -> Result<Header> {
        file.rewind()?;
        let mut magic = vec![0; MAGIC.len()];
        match file.read_exact(&mut magic) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
                return Err(Error::Corrupt("truncated cache magic"));
            }
            Err(error) => return Err(error.into()),
        }
        if magic != MAGIC {
            return Err(Error::Corrupt("invalid cache magic"));
        }
        let mut line = Vec::new();
        while line.len() <= MAX_HEADER_BYTES {
            let mut byte = [0];
            if file.read(&mut byte)? == 0 {
                return Err(Error::Corrupt("truncated cache header"));
            }
            line.push(byte[0]);
            if byte[0] == b'\n' {
                break;
            }
        }
        if line.len() > MAX_HEADER_BYTES {
            return Err(Error::Corrupt("oversized cache header"));
        }
        let header: Header =
            serde_json::from_slice(&line).map_err(|_| Error::Corrupt("invalid cache header"))?;
        if header.schema != SCHEMA
            || header.slot != expected_slot
            || !hex(&header.sha256)
            || !(1..=MAX_CACHE_BYTES).contains(&header.size)
        {
            return Err(Error::Corrupt("invalid cache declaration"));
        }
        let canonical = header_bytes(expected_slot, &header.sha256, header.size);
        if canonical[MAGIC.len()..] != line || canonical.len() as u64 + header.size != file_size {
            return Err(Error::Corrupt("cache size or framing mismatch"));
        }
        Ok(header)
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Boundary {
        RestoreHeaderRead,
        RestorePayloadRead(usize),
        BeforeRestoreSync,
        BeforePublishRename,
        AfterPublishRename,
    }

    fn hash_payload(
        file: &mut File,
        size: u64,
        mut output: Option<&mut File>,
        mut read: impl FnMut(usize) -> Result<()>,
    ) -> Result<String> {
        let mut hasher = Sha256::new();
        let mut remaining = size;
        let mut block = vec![0; BLOCK_BYTES];
        while remaining != 0 {
            let limit = remaining.min(BLOCK_BYTES as u64) as usize;
            let count = file.read(&mut block[..limit])?;
            if count == 0 {
                return Err(Error::Corrupt("truncated archive payload"));
            }
            read(count)?;
            if let Some(output) = &mut output {
                output.write_all(&block[..count])?;
            }
            hasher.update(&block[..count]);
            remaining -= count as u64;
        }
        if file.read(&mut [0])? != 0 {
            return Err(Error::Corrupt("oversized archive payload"));
        }
        Ok(hasher
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect())
    }

    fn free_space(directory: &Directory, required: u64, minimum: u64) -> Result<()> {
        let info = rustix::fs::fstatvfs(directory.fd())?;
        let available = u128::from(info.f_bavail) * u128::from(info.f_frsize);
        if available < u128::from(required) + u128::from(minimum) {
            return Err(Error::Bypass("BYPASS_CAPACITY"));
        }
        Ok(())
    }

    fn open_pending(directory: &Directory, name: &str) -> Result<File> {
        let file = if let Some(previous) = open_regular(directory, name)? {
            // An interrupted publication can leave a fully verified 0400
            // pending file. Only this nonauthoritative slot is reset.
            rustix::fs::fchmod(&previous.file, Mode::from_raw_mode(0o600))?;
            let file = File::from(rustix::fs::openat(
                directory.fd(),
                name,
                FILE_FLAGS | OFlags::RDWR,
                Mode::empty(),
            )?);
            require(
                same_inode(&previous.before, &rustix::fs::fstat(&file)?),
                "pending archive changed",
            )?;
            file
        } else {
            File::from(rustix::fs::openat(
                directory.fd(),
                name,
                FILE_FLAGS | OFlags::RDWR | OFlags::CREATE | OFlags::EXCL,
                Mode::from_raw_mode(0o600),
            )?)
        };
        let opened = rustix::fs::fstat(&file)?;
        regular_metadata(&opened)?;
        directory.check()?;
        require(
            entry_metadata(directory, name)?.is_some_and(|named| same_inode(&named, &opened)),
            "pending archive changed before truncation",
        )?;
        file.set_len(0)?;
        Ok(file)
    }

    fn invalidate_private_copy(source: &Directory, archive: &File) -> Result<()> {
        source.check()?;
        let opened = rustix::fs::fstat(archive)?;
        regular_metadata(&opened)?;
        require(
            entry_metadata(source, SOURCE_ARCHIVE)?
                .is_some_and(|named| same_inode(&named, &opened)),
            "private archive changed before invalidation",
        )?;
        archive
            .set_len(0)
            .map_err(|_| Error::Unsafe("could not invalidate failed private archive"))?;
        require(
            rustix::fs::fstat(archive)?.st_size == 0,
            "private archive invalidation failed",
        )
    }

    fn restore(
        request: &Request<'_>,
        observe: &mut impl FnMut(Boundary) -> Result<()>,
    ) -> Result<&'static str> {
        let Some(target) = Directory::open(request.target, false)? else {
            return Ok("MISS");
        };
        let Some(cache) = target.cache(false)? else {
            return Ok("MISS");
        };
        inventory(&cache)?;
        let name = format!("{}.sealed", request.slot);
        let Some(mut opened) = open_regular(&cache, &name)? else {
            return Ok("MISS");
        };
        let header = read_header(&mut opened.file, request.slot, opened.before.st_size as u64)?;
        observe(Boundary::RestoreHeaderRead)?;
        unchanged(&cache, &name, &opened)?;
        // An unrelated declaration is a miss, not an integrity claim about
        // its bytes. Do not read that payload or modify any source file.
        if header.sha256 != request.digest || header.size != request.size {
            return Ok("MISS");
        }
        let source =
            Directory::open(request.source, true)?.ok_or(Error::Unsafe("source root is absent"))?;
        free_space(&source, request.size, request.minimum)?;
        let mut private = open_pending(&source, SOURCE_ARCHIVE)?;
        let copied = (|| {
            let digest = hash_payload(
                &mut opened.file,
                request.size,
                Some(&mut private),
                |count| observe(Boundary::RestorePayloadRead(count)),
            )?;
            unchanged(&cache, &name, &opened)?;
            if digest != request.digest {
                return Err(Error::Corrupt("cache changed during private copy"));
            }
            let copied_info = rustix::fs::fstat(&private)?;
            observe(Boundary::BeforeRestoreSync)?;
            private.sync_all()?;
            rustix::fs::fsync(source.fd())?;
            source.check()?;
            let completed = entry_metadata(&source, SOURCE_ARCHIVE)?;
            let private_info = rustix::fs::fstat(&private)?;
            require(
                completed.is_some_and(|info| {
                    info.st_size as u64 == request.size
                        && same_snapshot(&copied_info, &private_info)
                        && same_snapshot(&private_info, &info)
                }),
                "restored archive changed",
            )
        })();
        if let Err(error) = copied {
            // A handled bypass permits rsync to continue. Empty its reserved
            // receiver file first: append-verify can skip a full-size bad copy.
            if matches!(error, Error::Corrupt(_) | Error::Bypass(_))
                || matches!(&error, Error::Io(error) if bypass_for_io(error).is_some())
            {
                invalidate_private_copy(&source, &private)?;
            }
            return Err(error);
        }
        Ok("HIT")
    }

    fn verify_sealed(
        cache: &Directory,
        name: &str,
        slot: &str,
    ) -> Result<Option<(OpenFile, Header)>> {
        let Some(mut opened) = open_regular(cache, name)? else {
            return Ok(None);
        };
        let header = read_header(&mut opened.file, slot, opened.before.st_size as u64)?;
        let digest = hash_payload(&mut opened.file, header.size, None, |_| Ok(()))?;
        unchanged(cache, name, &opened)?;
        if digest != header.sha256 {
            return Err(Error::Corrupt("completed archive digest mismatch"));
        }
        Ok(Some((opened, header)))
    }

    fn source_hash_error(error: Error) -> Error {
        match error {
            Error::Corrupt(_) => Error::Unsafe("uploaded archive changed"),
            error => error,
        }
    }

    fn publish(
        request: &Request<'_>,
        observe: &mut impl FnMut(Boundary) -> Result<()>,
    ) -> Result<&'static str> {
        let source = Directory::open(request.source, false)?
            .ok_or(Error::Unsafe("uploaded source root is absent"))?;
        let mut uploaded = open_regular(&source, SOURCE_ARCHIVE)?
            .ok_or(Error::Unsafe("uploaded archive is absent"))?;
        require(
            uploaded.before.st_size as u64 == request.size,
            "uploaded archive size mismatch",
        )?;
        let digest = hash_payload(&mut uploaded.file, request.size, None, |_| Ok(()))
            .map_err(source_hash_error)?;
        unchanged(&source, SOURCE_ARCHIVE, &uploaded)?;
        require(digest == request.digest, "uploaded archive digest mismatch")?;
        let target =
            Directory::open(request.target, true)?.ok_or(Error::Unsafe("target root is absent"))?;
        let cache = target
            .cache(true)?
            .ok_or(Error::Unsafe("cache directory is absent"))?;
        let inventory = inventory(&cache)?;
        let name = format!("{}.sealed", request.slot);
        let previous = verify_sealed(&cache, &name, request.slot)?;
        if previous.as_ref().is_some_and(|(_, header)| {
            header.sha256 == request.digest && header.size == request.size
        }) {
            return Ok("PUBLISHED");
        }
        if !inventory.slots.contains(request.slot) && inventory.slots.len() >= MAX_SLOTS {
            return Ok("BYPASS_CAPACITY");
        }
        let header = header_bytes(request.slot, request.digest, request.size);
        let candidate_size = header.len() as u64 + request.size;
        let pending_name = format!("{}.pending", request.slot);
        let pending_info = inventory.entries.get(&pending_name);
        let previous_size = pending_info.map_or(0, |info| info.st_size as u64);
        if inventory.total - previous_size + candidate_size > MAX_CACHE_BYTES {
            return Ok("BYPASS_CAPACITY");
        }
        let reclaimed = pending_info.map_or(0, |info| {
            u64::try_from(info.st_blocks)
                .unwrap_or(0)
                .saturating_mul(512)
        });
        free_space(
            &cache,
            candidate_size.saturating_sub(reclaimed),
            request.minimum,
        )?;
        let mut pending = open_pending(&cache, &pending_name)?;
        pending.write_all(&header)?;
        uploaded.file.seek(SeekFrom::Start(0))?;
        let digest = hash_payload(&mut uploaded.file, request.size, Some(&mut pending), |_| {
            Ok(())
        })
        .map_err(source_hash_error)?;
        unchanged(&source, SOURCE_ARCHIVE, &uploaded)?;
        require(
            digest == request.digest,
            "uploaded archive changed during publication",
        )?;
        rustix::fs::fchmod(&pending, Mode::from_raw_mode(0o400))?;
        pending.sync_all()?;
        let pending = OpenFile {
            before: rustix::fs::fstat(&pending)?,
            file: pending,
        };
        observe(Boundary::BeforePublishRename)?;
        // Recheck every publication input after the potentially slow flush.
        // A changed pending name must not replace the previous sealed inode,
        // even if the final post-rename check would subsequently detect it.
        unchanged(&cache, &pending_name, &pending)?;
        unchanged(&source, SOURCE_ARCHIVE, &uploaded)?;
        if let Some((previous, _)) = &previous {
            unchanged(&cache, &name, previous)?;
        } else {
            require(
                entry_metadata(&cache, &name)?.is_none(),
                "completed cache appeared during publication",
            )?;
        }
        rustix::fs::renameat(cache.fd(), pending_name.as_str(), cache.fd(), name.as_str())?;
        // Rename may legitimately change ctime. Bind a fresh snapshot before
        // the directory flush so subsequent same-inode writes cannot count as
        // a successfully published immutable archive.
        let published = OpenFile {
            before: rustix::fs::fstat(&pending.file)?,
            file: pending.file,
        };
        regular_metadata(&published.before)?;
        observe(Boundary::AfterPublishRename)?;
        rustix::fs::fsync(cache.fd())?;
        unchanged(&cache, &name, &published)?;
        Ok("PUBLISHED")
    }

    fn run_with(
        arguments: &[String],
        observe: &mut impl FnMut(Boundary) -> Result<()>,
    ) -> Result<&'static str> {
        let request = Request::parse(arguments)?;
        if request.size + header_bytes(request.slot, request.digest, request.size).len() as u64
            > MAX_CACHE_BYTES
        {
            return Ok("BYPASS_CAPACITY");
        }
        classify(if request.operation == "restore" {
            restore(&request, observe)
        } else {
            publish(&request, observe)
        })
    }

    pub(super) fn run(arguments: &[String]) -> std::result::Result<&'static str, String> {
        run_with(arguments, &mut |_| Ok(())).map_err(|error| error.to_string())
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::fs;
        use std::os::unix::fs::PermissionsExt as _;
        use std::path::PathBuf;

        const SLOT: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

        struct Fixture {
            root: PathBuf,
            source: PathBuf,
            target: PathBuf,
        }

        impl Fixture {
            fn new() -> Self {
                let root = tempfile::Builder::new()
                    .prefix("rch-archive-boundary-")
                    .tempdir_in(if cfg!(target_os = "macos") {
                        "/private/tmp"
                    } else {
                        "/tmp"
                    })
                    .unwrap()
                    .keep();
                Self {
                    source: root.join("source"),
                    target: root.join("target"),
                    root,
                }
            }

            fn arguments(&self, operation: &str, payload: &[u8]) -> Vec<String> {
                vec![
                    operation.into(),
                    self.source.to_str().unwrap().into(),
                    self.target.to_str().unwrap().into(),
                    SLOT.into(),
                    Sha256::digest(payload)
                        .iter()
                        .map(|byte| format!("{byte:02x}"))
                        .collect(),
                    payload.len().to_string(),
                    "0".into(),
                ]
            }

            fn stage(&self, payload: &[u8]) {
                fs::create_dir_all(&self.source).unwrap();
                fs::set_permissions(&self.source, fs::Permissions::from_mode(0o755)).unwrap();
                fs::write(self.source.join(SOURCE_ARCHIVE), payload).unwrap();
                fs::set_permissions(
                    self.source.join(SOURCE_ARCHIVE),
                    fs::Permissions::from_mode(0o600),
                )
                .unwrap();
            }

            fn run(&self, operation: &str, payload: &[u8]) -> &'static str {
                run_with(&self.arguments(operation, payload), &mut |_| Ok(())).unwrap()
            }

            fn publish(&self, payload: &[u8]) {
                self.stage(payload);
                assert_eq!(self.run("publish", payload), "PUBLISHED");
            }

            fn sealed(&self) -> PathBuf {
                self.target
                    .join(CACHE_DIRECTORY)
                    .join(format!("{SLOT}.sealed"))
            }

            fn pending(&self) -> PathBuf {
                self.target
                    .join(CACHE_DIRECTORY)
                    .join(format!("{SLOT}.pending"))
            }
        }

        #[test]
        fn matching_pin_reads_payload_once_and_unrelated_pin_never_reads_payload() {
            let fixture = Fixture::new();
            let payload = vec![b'a'; BLOCK_BYTES + 127];
            fixture.publish(&payload);
            fs::rename(&fixture.source, fixture.root.join("retained-source")).unwrap();
            for (selected, expected, total) in [
                (b"another selected pin".as_slice(), "MISS", 0),
                (payload.as_slice(), "HIT", payload.len()),
            ] {
                let mut read = 0;
                let status = run_with(&fixture.arguments("restore", selected), &mut |boundary| {
                    if let Boundary::RestorePayloadRead(count) = boundary {
                        read += count;
                    }
                    Ok(())
                })
                .unwrap();
                assert_eq!(status, expected);
                assert_eq!(read, total);
                if expected == "MISS" {
                    assert!(!fixture.source.exists());
                } else {
                    assert_eq!(
                        fs::read(fixture.source.join(SOURCE_ARCHIVE)).unwrap(),
                        payload
                    );
                }
            }
        }

        #[test]
        fn header_path_replacement_refuses_both_matching_and_unrelated_pins() {
            for payload in [b"selected".as_slice(), b"unrelated"] {
                let fixture = Fixture::new();
                fixture.publish(b"selected");
                fs::rename(&fixture.source, fixture.root.join("retained-source")).unwrap();
                let original = fs::read(fixture.sealed()).unwrap();
                let mut replaced = false;
                let result = run_with(&fixture.arguments("restore", payload), &mut |boundary| {
                    if boundary == Boundary::RestoreHeaderRead {
                        fs::rename(fixture.sealed(), fixture.root.join("retained-sealed")).unwrap();
                        fs::write(fixture.sealed(), &original).unwrap();
                        fs::set_permissions(fixture.sealed(), fs::Permissions::from_mode(0o400))
                            .unwrap();
                        replaced = true;
                    }
                    Ok(())
                });
                assert!(replaced);
                assert!(matches!(result, Err(Error::Unsafe(_))), "{result:?}");
                assert!(!fixture.source.exists());
                assert_eq!(fs::read(fixture.sealed()).unwrap(), original);
            }
        }

        #[test]
        fn truncation_during_payload_copy_invalidates_the_partial_receiver() {
            let fixture = Fixture::new();
            let payload = vec![b'p'; BLOCK_BYTES + 8192];
            fixture.publish(&payload);
            let mut truncated = false;
            let status = run_with(&fixture.arguments("restore", &payload), &mut |boundary| {
                if matches!(boundary, Boundary::RestorePayloadRead(_)) && !truncated {
                    fs::set_permissions(fixture.sealed(), fs::Permissions::from_mode(0o600))
                        .unwrap();
                    File::options()
                        .write(true)
                        .open(fixture.sealed())
                        .unwrap()
                        .set_len(0)
                        .unwrap();
                    truncated = true;
                }
                Ok(())
            })
            .unwrap();
            assert!(truncated);
            assert_eq!(status, "BYPASS_CORRUPT");
            assert_eq!(
                fs::metadata(fixture.source.join(SOURCE_ARCHIVE))
                    .unwrap()
                    .len(),
                0
            );
            assert_eq!(fs::metadata(fixture.sealed()).unwrap().len(), 0);
            assert_eq!(fs::read_dir(&fixture.source).unwrap().count(), 1);
        }

        #[test]
        fn injected_postcopy_filesystem_failure_never_leaves_a_full_receiver_for_fallback() {
            for (error, expected) in [
                (Errno::NOSPC, "BYPASS_CAPACITY"),
                (Errno::DQUOT, "BYPASS_CAPACITY"),
                (Errno::ROFS, "BYPASS_UNAVAILABLE"),
                (Errno::NOSYS, "BYPASS_UNAVAILABLE"),
                (Errno::NOTSUP, "BYPASS_UNAVAILABLE"),
            ] {
                let fixture = Fixture::new();
                fixture.publish(b"selected archive");
                let before = fs::read(fixture.sealed()).unwrap();
                let mut failed = false;
                let status = run_with(
                    &fixture.arguments("restore", b"selected archive"),
                    &mut |boundary| {
                        if boundary == Boundary::BeforeRestoreSync {
                            assert_eq!(
                                fs::read(fixture.source.join(SOURCE_ARCHIVE)).unwrap(),
                                b"selected archive"
                            );
                            failed = true;
                            return Err(error.into());
                        }
                        Ok(())
                    },
                )
                .unwrap();
                assert!(failed);
                assert_eq!(status, expected);
                assert_eq!(
                    fs::metadata(fixture.source.join(SOURCE_ARCHIVE))
                        .unwrap()
                        .len(),
                    0
                );
                assert_eq!(fs::read(fixture.sealed()).unwrap(), before);
            }
        }

        #[test]
        fn receiver_replacement_prevents_invalidation_and_never_truncates_unrelated_bytes() {
            let fixture = Fixture::new();
            fixture.publish(b"selected archive");
            let result = run_with(
                &fixture.arguments("restore", b"selected archive"),
                &mut |boundary| {
                    if boundary == Boundary::BeforeRestoreSync {
                        let path = fixture.source.join(SOURCE_ARCHIVE);
                        fs::rename(&path, fixture.root.join("retained-receiver")).unwrap();
                        fs::write(path, b"unrelated replacement").unwrap();
                        return Err(Errno::NOSPC.into());
                    }
                    Ok(())
                },
            );
            assert!(matches!(result, Err(Error::Unsafe(_))), "{result:?}");
            assert_eq!(
                fs::read(fixture.source.join(SOURCE_ARCHIVE)).unwrap(),
                b"unrelated replacement"
            );
            assert_eq!(
                fs::read(fixture.root.join("retained-receiver")).unwrap(),
                b"selected archive"
            );
        }

        #[test]
        fn same_inode_same_length_receiver_mutation_during_flush_is_never_a_hit() {
            use std::fs::FileTimes;
            use std::os::unix::fs::MetadataExt as _;
            use std::time::{Duration, SystemTime};
            let fixture = Fixture::new();
            fixture.publish(b"selected archive");
            let mut changed = false;
            let result = run_with(
                &fixture.arguments("restore", b"selected archive"),
                &mut |boundary| {
                    if boundary == Boundary::BeforeRestoreSync {
                        let path = fixture.source.join(SOURCE_ARCHIVE);
                        let before = fs::metadata(&path).unwrap();
                        let mut file = File::options().write(true).open(&path).unwrap();
                        file.write_all(b"tampered archive").unwrap();
                        file.set_times(
                            FileTimes::new()
                                .set_modified(SystemTime::UNIX_EPOCH + Duration::from_secs(11)),
                        )
                        .unwrap();
                        let after = fs::metadata(&path).unwrap();
                        assert_eq!(before.ino(), after.ino());
                        assert_eq!(before.len(), after.len());
                        changed = true;
                    }
                    Ok(())
                },
            );
            assert!(changed);
            assert!(matches!(result, Err(Error::Unsafe(_))), "{result:?}");
            assert_eq!(
                fs::read(fixture.source.join(SOURCE_ARCHIVE)).unwrap(),
                b"tampered archive"
            );
        }

        #[test]
        fn injected_publication_interruption_exposes_only_complete_pinned_archives() {
            for boundary in [Boundary::BeforePublishRename, Boundary::AfterPublishRename] {
                let fixture = Fixture::new();
                fixture.publish(b"previous archive");
                let previous = fs::read(fixture.sealed()).unwrap();
                fixture.stage(b"next archive");
                let result = run_with(
                    &fixture.arguments("publish", b"next archive"),
                    &mut |step| {
                        if step == boundary {
                            Err(Error::Unsafe("injected publication interruption"))
                        } else {
                            Ok(())
                        }
                    },
                );
                assert!(matches!(result, Err(Error::Unsafe(_))), "{result:?}");
                if boundary == Boundary::BeforePublishRename {
                    assert_eq!(fs::read(fixture.sealed()).unwrap(), previous);
                    assert_eq!(
                        fs::metadata(fixture.pending())
                            .unwrap()
                            .permissions()
                            .mode()
                            & 0o777,
                        0o400
                    );
                    assert_eq!(fixture.run("restore", b"previous archive"), "HIT");
                    assert_eq!(fixture.run("restore", b"next archive"), "MISS");
                } else {
                    assert!(!fixture.pending().exists());
                    assert_eq!(fixture.run("restore", b"next archive"), "HIT");
                    assert_eq!(fixture.run("restore", b"previous archive"), "MISS");
                }
                fixture.stage(b"next archive");
                assert_eq!(fixture.run("publish", b"next archive"), "PUBLISHED");
                assert_eq!(fixture.run("restore", b"next archive"), "HIT");
            }
        }

        #[test]
        fn same_inode_same_length_mutation_after_rename_is_never_published() {
            use std::fs::FileTimes;
            use std::os::unix::fs::MetadataExt as _;
            use std::time::{Duration, SystemTime};
            let fixture = Fixture::new();
            fixture.publish(b"previous archive");
            fixture.stage(b"next archive");
            let mut changed = false;
            let result = run_with(
                &fixture.arguments("publish", b"next archive"),
                &mut |step| {
                    if step == Boundary::AfterPublishRename {
                        let path = fixture.sealed();
                        let before = fs::metadata(&path).unwrap();
                        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
                        let mut file = File::options().write(true).open(&path).unwrap();
                        file.seek(SeekFrom::End(-12)).unwrap();
                        file.write_all(b"bad! archive").unwrap();
                        file.set_times(
                            FileTimes::new()
                                .set_modified(SystemTime::UNIX_EPOCH + Duration::from_secs(11)),
                        )
                        .unwrap();
                        fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
                        let after = fs::metadata(path).unwrap();
                        assert_eq!(before.ino(), after.ino());
                        assert_eq!(before.len(), after.len());
                        changed = true;
                    }
                    Ok(())
                },
            );
            assert!(changed);
            assert!(matches!(result, Err(Error::Unsafe(_))), "{result:?}");
            assert!(
                fs::read(fixture.sealed())
                    .unwrap()
                    .ends_with(b"bad! archive")
            );
            assert_eq!(fixture.run("restore", b"next archive"), "BYPASS_CORRUPT");
        }

        #[test]
        fn publication_rechecks_pending_source_and_namespace_before_replacing_completed_slot() {
            for entry in ["pending", "source", "cache"] {
                let fixture = Fixture::new();
                fixture.publish(b"previous archive");
                let previous = fs::read(fixture.sealed()).unwrap();
                fixture.stage(b"next archive");
                let result = run_with(
                    &fixture.arguments("publish", b"next archive"),
                    &mut |step| {
                        if step == Boundary::BeforePublishRename {
                            let path = match entry {
                                "pending" => fixture.pending(),
                                "source" => fixture.source.join(SOURCE_ARCHIVE),
                                _ => fixture.target.join(CACHE_DIRECTORY),
                            };
                            fs::rename(&path, fixture.root.join("retained-replaced-entry"))
                                .unwrap();
                            if entry == "cache" {
                                fs::create_dir(&path).unwrap();
                                fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                                    .unwrap();
                            } else {
                                fs::write(&path, b"unselected bytes").unwrap();
                                fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
                                    .unwrap();
                            }
                        }
                        Ok(())
                    },
                );
                assert!(
                    matches!(result, Err(Error::Unsafe(_))),
                    "{entry}: {result:?}"
                );
                let sealed = if entry == "cache" {
                    fixture
                        .root
                        .join("retained-replaced-entry")
                        .join(format!("{SLOT}.sealed"))
                } else {
                    fixture.sealed()
                };
                assert_eq!(fs::read(sealed).unwrap(), previous);
            }
        }
    }
}
