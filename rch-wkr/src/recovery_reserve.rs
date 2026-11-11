//! `rch-wkr recovery-reserve`: worker-local emergency bytes for recovery metadata.
//!
//! This is a byte reserve, not an inode reserve or a quota guarantee. It
//! protects the owning source registry and the GC scratch directory on that
//! same filesystem. Finite cancellation metadata transactions may borrow an
//! existing reserve; they retain all of their own authority checks and never
//! settle a GC claim.
//!
//! The shell wrappers come from `rch_common::recovery_reserve`. This is the
//! Rust replacement for the interpreter program those wrappers used to embed;
//! the on-disk format (`.recovery-v1/reserve.v1`, two checksummed JSON header
//! slots), the inherited-lease environment and the exit statuses are unchanged:
//! 75 with `RCH_SOURCE_REGISTRY_PRESSURE` when the reserve cannot be funded,
//! 74 with `RCH_RECOVERY_RESERVE_UNSAFE` for every other refusal.
//!
//! Operations: `probe`; `ready <registry>`; `admit|recover <registry> <payload>`;
//! `gc <registry> <payload> <reconcile>`; and the GC shell callbacks
//! `bind|settle <registry> <claim-name>`. Payloads are packed shell text that
//! runs (`sh -c`) in place of this process while it holds the lease.

use rch_common::recovery_reserve::{PRESSURE_EXIT, PROBE_REPLY, UNSAFE_EXIT};

/// Why an operation refused.
#[derive(Debug)]
pub(crate) enum Failure {
    /// A damaged, substituted, contended or otherwise untrusted reserve.
    Unsafe(String),
    /// The reserve cannot be funded on this filesystem right now.
    Pressure(&'static str),
    /// An OS error; ENOSPC and EDQUOT are pressure, everything else unsafe.
    Os(std::io::Error),
}

impl From<std::io::Error> for Failure {
    fn from(error: std::io::Error) -> Self {
        Self::Os(error)
    }
}

#[cfg(unix)]
impl From<rustix::io::Errno> for Failure {
    fn from(error: rustix::io::Errno) -> Self {
        Self::Os(error.into())
    }
}

fn unsafe_(message: impl Into<String>) -> Failure {
    Failure::Unsafe(message.into())
}

/// Run one reserve operation and return the process exit status. Payload
/// operations replace this process with `sh` on success and never return.
pub fn main(arguments: &[String]) -> i32 {
    if arguments.first().map(String::as_str) == Some("probe") {
        println!("{PROBE_REPLY}");
        return 0;
    }
    let registry = arguments.get(1).map_or("unknown", String::as_str);
    match imp::run(arguments) {
        Ok(status) => status,
        Err(failure) => {
            let (status, line) = report(registry, failure);
            eprintln!("{line}");
            status
        }
    }
}

fn report(registry: &str, failure: Failure) -> (i32, String) {
    let pressure = |reason: &str| {
        (
            PRESSURE_EXIT,
            format!("RCH_SOURCE_REGISTRY_PRESSURE {registry}: {reason}"),
        )
    };
    match failure {
        Failure::Pressure(reason) => pressure(reason),
        Failure::Os(error) if imp::is_no_space(&error) => pressure("no-space"),
        Failure::Os(error) if imp::is_quota(&error) => pressure("quota-exhausted"),
        Failure::Os(error) => (
            UNSAFE_EXIT,
            format!("RCH_RECOVERY_RESERVE_UNSAFE {registry}: {error}"),
        ),
        Failure::Unsafe(message) => (
            UNSAFE_EXIT,
            format!("RCH_RECOVERY_RESERVE_UNSAFE {registry}: {message}"),
        ),
    }
}

fn payload(arguments: &[String], index: usize) -> Result<String, Failure> {
    let packed = arguments
        .get(index)
        .ok_or_else(|| unsafe_("missing payload argument"))?;
    rch_common::recovery_reserve::unpack(packed).map_err(Failure::Unsafe)
}

/// Variables the wrapper sets only so Git for Windows passes this binary its
/// arguments verbatim. The payload never inherits them.
const WRAPPER_ONLY_ENV: [&str; 2] = ["MSYS_NO_PATHCONV", "MSYS2_ARG_CONV_EXCL"];

/// Canonical JSON exactly as the original header writer produced it (sorted
/// keys, `,`/`:` separators, ASCII-only `\uXXXX` escaping). Existing header
/// checksums are computed over exactly these bytes.
fn canonical(value: &serde_json::Value) -> String {
    let mut out = String::new();
    write_canonical(value, &mut out);
    out
}

fn write_canonical(value: &serde_json::Value, out: &mut String) {
    use serde_json::Value;
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(flag) => out.push_str(if *flag { "true" } else { "false" }),
        Value::Number(number) => out.push_str(&number.to_string()),
        Value::String(text) => write_string(text, out),
        Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_canonical(item, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push('{');
            for (index, key) in keys.into_iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_string(key, out);
                out.push(':');
                write_canonical(&map[key], out);
            }
            out.push('}');
        }
    }
}

fn write_string(text: &str, out: &mut String) {
    use std::fmt::Write as _;
    out.push('"');
    for character in text.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            ' '..='~' => out.push(character),
            other => {
                let mut units = [0u16; 2];
                for unit in other.encode_utf16(&mut units) {
                    let _ = write!(out, "\\u{unit:04x}");
                }
            }
        }
    }
    out.push('"');
}

/// `fc-<36 of [a-f0-9-]>.<64 hex>.claim`; returns the embedded digest.
fn claim_digest(name: &str) -> Option<&str> {
    let rest = name.strip_prefix("fc-")?.strip_suffix(".claim")?;
    let (token, digest) = rest.split_at_checked(36)?;
    let digest = digest.strip_prefix('.')?;
    let lower_hex = |byte: u8| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte);
    (token.bytes().all(|byte| lower_hex(byte) || byte == b'-')
        && digest.len() == 64
        && digest.bytes().all(lower_hex))
    .then_some(digest)
}

fn is_generation(epoch: &str) -> bool {
    epoch.len() == 32
        && epoch
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(unix)]
mod imp {
    use super::{
        Failure, WRAPPER_ONLY_ENV, canonical, claim_digest, is_generation, payload, unsafe_,
    };
    use rustix::fd::{AsFd, OwnedFd};
    use rustix::fs::{AtFlags, FlockOperation, Mode, OFlags};
    use serde_json::{Value, json};
    use sha2::{Digest as _, Sha256};
    use std::os::unix::fs::FileExt as _;
    use std::os::unix::process::CommandExt as _;
    use std::path::{Path, PathBuf};

    pub(super) const CAPACITY: u64 = 64 * 1024 * 1024;
    pub(super) const HEADROOM: u64 = 64 * 1024 * 1024;
    const HEADER: u64 = 4096;
    const SLOT: u64 = HEADER / 2;
    const PRIVATE: &str = ".recovery-v1";
    const FILE: &str = "reserve.v1";
    const CLAIM_LIMIT: u64 = 32 * 1024 * 1024;

    fn directory_flags() -> OFlags {
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC
    }

    pub(super) fn is_no_space(error: &std::io::Error) -> bool {
        error.raw_os_error() == Some(rustix::io::Errno::NOSPC.raw_os_error())
    }

    pub(super) fn is_quota(error: &std::io::Error) -> bool {
        error.raw_os_error() == Some(rustix::io::Errno::DQUOT.raw_os_error())
    }

    fn is_busy(error: rustix::io::Errno) -> bool {
        error == rustix::io::Errno::WOULDBLOCK || error == rustix::io::Errno::AGAIN
    }

    /// The `stat` fields this protocol compares, in portable widths. Device
    /// numbers stay signed: Darwin's `dev_t` is, and the header records them
    /// exactly as the original implementation did.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(super) struct Info {
        pub dev: i64,
        pub ino: u64,
        pub mode: u32,
        pub uid: u32,
        pub nlink: u64,
        pub size: i64,
        pub blocks: i64,
        pub mtime_ns: i128,
        pub ctime_ns: i128,
    }

    impl Info {
        fn identity(&self) -> (i64, u64) {
            (self.dev, self.ino)
        }

        fn identity_json(&self) -> Value {
            json!([self.dev, self.ino])
        }

        fn is_dir(&self) -> bool {
            self.mode & 0o170_000 == 0o040_000
        }

        fn is_regular(&self) -> bool {
            self.mode & 0o170_000 == 0o100_000
        }

        fn permissions(&self) -> u32 {
            self.mode & 0o7777
        }

        fn allocated(&self) -> i64 {
            self.blocks.saturating_mul(512)
        }
    }

    // Field widths differ per platform (and are already i64/u64 on some).
    #[allow(
        clippy::unnecessary_cast,
        clippy::useless_conversion,
        clippy::cast_possible_wrap,
        clippy::cast_sign_loss
    )]
    fn info(stat: &rustix::fs::Stat) -> Info {
        Info {
            dev: stat.st_dev as i64,
            ino: stat.st_ino as u64,
            mode: stat.st_mode as u32,
            uid: stat.st_uid as u32,
            nlink: stat.st_nlink as u64,
            size: stat.st_size as i64,
            blocks: stat.st_blocks as i64,
            mtime_ns: i128::from(stat.st_mtime as i64) * 1_000_000_000
                + i128::from(stat.st_mtime_nsec as i64),
            ctime_ns: i128::from(stat.st_ctime as i64) * 1_000_000_000
                + i128::from(stat.st_ctime_nsec as i64),
        }
    }

    fn fstat(fd: impl AsFd) -> Result<Info, Failure> {
        Ok(info(&rustix::fs::fstat(fd)?))
    }

    fn lstat_at(dir: impl AsFd, name: &str) -> Result<Info, Failure> {
        Ok(info(&rustix::fs::statat(
            dir,
            name,
            AtFlags::SYMLINK_NOFOLLOW,
        )?))
    }

    #[allow(clippy::unnecessary_cast, clippy::useless_conversion)]
    fn free_bytes(fd: impl AsFd) -> Result<u64, Failure> {
        let info = rustix::fs::fstatvfs(fd)?;
        Ok((info.f_bavail as u64).saturating_mul(info.f_frsize as u64))
    }

    fn file(fd: &OwnedFd) -> std::fs::File {
        std::fs::File::from(fd.try_clone().expect("duplicate an open descriptor"))
    }

    fn pread(fd: &OwnedFd, length: u64, offset: u64) -> Result<Vec<u8>, Failure> {
        let mut buffer = vec![0u8; usize::try_from(length).unwrap_or(usize::MAX)];
        let handle = file(fd);
        let mut filled = 0;
        while filled < buffer.len() {
            let count = handle.read_at(&mut buffer[filled..], offset + filled as u64)?;
            if count == 0 {
                break;
            }
            filled += count;
        }
        buffer.truncate(filled);
        Ok(buffer)
    }

    fn pwrite_all(
        fd: &OwnedFd,
        mut data: &[u8],
        mut offset: u64,
        what: &str,
    ) -> Result<(), Failure> {
        let handle = file(fd);
        while !data.is_empty() {
            let count = handle.write_at(data, offset)?;
            if count == 0 {
                return Err(unsafe_(format!("short reserve {what} write")));
            }
            offset += count as u64;
            data = &data[count..];
        }
        Ok(())
    }

    fn random_bytes(buffer: &mut [u8]) -> Result<(), Failure> {
        use std::io::Read as _;
        std::fs::File::open("/dev/urandom")?.read_exact(buffer)?;
        Ok(())
    }

    fn new_generation() -> Result<String, Failure> {
        use std::fmt::Write as _;
        let mut bytes = [0u8; 16];
        random_bytes(&mut bytes)?;
        Ok(bytes
            .iter()
            .fold(String::with_capacity(32), |mut out, byte| {
                let _ = write!(out, "{byte:02x}");
                out
            }))
    }

    struct Dir {
        fd: OwnedFd,
        name: String,
        identity: (i64, u64),
        private: bool,
    }

    pub(super) struct Reserve {
        registry: String,
        capacity: u64,
        headroom: u64,
        uid: u32,
        original_ancestor: PathBuf,
        ancestor: PathBuf,
        ancestor_identity: (i64, u64),
        ancestor_fd: OwnedFd,
        /// authority, registry, `.recovery-v1`, scratch: each bound to its parent.
        dirs: Vec<Dir>,
        device: i64,
        fd: OwnedFd,
        created: bool,
        creation_locked: bool,
        file_identity: (i64, u64),
        immutable: Value,
        scratch: PathBuf,
        sequence: i128,
        slot: u64,
        state: Value,
        lease: Option<OwnedFd>,
        environment: Vec<(String, String)>,
    }

    const AUTHORITY: usize = 0;
    const REGISTRY: usize = 1;
    const PRIVATE_DIR: usize = 2;

    impl Reserve {
        pub(super) fn open(
            registry: &str,
            create: bool,
            capacity: u64,
            headroom: u64,
        ) -> Result<Self, Failure> {
            let path = Path::new(registry);
            if !path.is_absolute() || normalize(registry) != registry {
                return Err(unsafe_("noncanonical registry"));
            }
            if registry.contains(['\n', '\r']) {
                return Err(unsafe_("multiline registry"));
            }
            let (authority, registry_name) = split(registry);
            let (ancestor, authority_name) = split(authority);
            if ancestor.is_empty() || authority_name.is_empty() || registry_name.is_empty() {
                return Err(unsafe_("shallow registry"));
            }
            if create && std::fs::symlink_metadata(ancestor).is_err() {
                // A worker can lack the shared temp root itself (Git for
                // Windows ships no /var/tmp). Create only that MISSING root,
                // like `mkdir -p`; an existing ancestor or symlink is never
                // repaired.
                create_missing_root(Path::new(ancestor))?;
            }
            // /tmp and /var can be platform aliases. Only ancestors above the
            // worker-owned authority are resolved; managed leaves never follow links.
            let original_ancestor = PathBuf::from(ancestor);
            let resolved = std::fs::canonicalize(&original_ancestor)?;
            let ancestor_fd = rustix::fs::open(&resolved, directory_flags(), Mode::empty())?;
            let ancestor_identity = fstat(&ancestor_fd)?.identity();
            let uid = rustix::process::geteuid().as_raw();
            let mut dirs: Vec<Dir> = Vec::with_capacity(4);
            for (name, private) in [
                (authority_name, false),
                (registry_name, false),
                (PRIVATE, true),
                ("scratch", true),
            ] {
                let parent = dirs.last().map_or(&ancestor_fd, |dir| &dir.fd);
                let dir = open_directory(parent, name, create, private, uid)?;
                dirs.push(dir);
            }
            let mut creation_locked = false;
            if create {
                // Serialize first publication before the reserve file exists.
                // A concurrent first health/admission must not take SH on an
                // empty file and prevent its creator from initializing under EX.
                match rustix::fs::flock(
                    &dirs[PRIVATE_DIR].fd,
                    FlockOperation::NonBlockingLockExclusive,
                ) {
                    Ok(()) => creation_locked = true,
                    Err(error) if is_busy(error) => {
                        return Err(unsafe_("reserve initialization busy"));
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            let scratch = resolved
                .join(authority_name)
                .join(registry_name)
                .join(PRIVATE)
                .join("scratch");
            let device = fstat(&dirs[REGISTRY].fd)?.dev;
            for dir in &dirs[PRIVATE_DIR..] {
                if fstat(&dir.fd)?.dev != device {
                    return Err(unsafe_("reserve filesystem changed"));
                }
            }
            let flags = OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK;
            let mut created = false;
            let mut fd = None;
            if create {
                match rustix::fs::openat(
                    &dirs[PRIVATE_DIR].fd,
                    FILE,
                    flags | OFlags::CREATE | OFlags::EXCL,
                    Mode::from_raw_mode(0o600),
                ) {
                    Ok(opened) => {
                        fd = Some(opened);
                        created = true;
                    }
                    Err(rustix::io::Errno::EXIST) => {}
                    Err(error) => return Err(error.into()),
                }
            }
            let fd = match fd {
                Some(fd) => fd,
                None => rustix::fs::openat(&dirs[PRIVATE_DIR].fd, FILE, flags, Mode::empty())?,
            };
            let file_identity = fstat(&fd)?.identity();
            let identity_of =
                |index: usize| json!([dirs[index].identity.0, dirs[index].identity.1]);
            let immutable = json!({
                "version": 1,
                "file": [file_identity.0, file_identity.1],
                "uid": uid,
                "registry": identity_of(REGISTRY),
                "private": identity_of(PRIVATE_DIR),
                "scratch": identity_of(3),
                "capacity": capacity,
            });
            let reserve = Self {
                registry: registry.to_owned(),
                capacity,
                headroom,
                uid,
                original_ancestor,
                ancestor: resolved,
                ancestor_identity,
                ancestor_fd,
                dirs,
                device,
                fd,
                created,
                creation_locked,
                file_identity,
                immutable,
                scratch,
                sequence: 0,
                slot: 1,
                state: Value::Null,
                lease: None,
                environment: Vec::new(),
            };
            reserve.validate()?;
            Ok(reserve)
        }

        pub(super) fn validate(&self) -> Result<(), Failure> {
            if std::fs::canonicalize(&self.original_ancestor)? != self.ancestor {
                return Err(unsafe_("ancestor alias changed"));
            }
            let named = info(&rustix::fs::lstat(&self.ancestor)?);
            if named.identity() != self.ancestor_identity {
                return Err(unsafe_("ancestor replaced"));
            }
            for (index, dir) in self.dirs.iter().enumerate() {
                let parent = if index == 0 {
                    &self.ancestor_fd
                } else {
                    &self.dirs[index - 1].fd
                };
                let named = lstat_at(parent, &dir.name)?;
                let held = fstat(&dir.fd)?;
                if !named.is_dir()
                    || named.identity() != dir.identity
                    || held.identity() != dir.identity
                {
                    return Err(unsafe_("directory replaced"));
                }
                if named.uid != self.uid || named.mode & 0o022 != 0 {
                    return Err(unsafe_("directory permissions changed"));
                }
                if dir.private && named.permissions() != 0o700 {
                    return Err(unsafe_("private directory permissions changed"));
                }
            }
            let named = lstat_at(&self.dirs[PRIVATE_DIR].fd, FILE)?;
            let held = fstat(&self.fd)?;
            if !named.is_regular()
                || named.identity() != self.file_identity
                || held.identity() != self.file_identity
                || held.dev != self.device
                || held.uid != self.uid
                || held.nlink != 1
                || held.permissions() != 0o600
            {
                return Err(unsafe_("reserve identity or permissions changed"));
            }
            Ok(())
        }

        pub(super) fn lock(&self, exclusive: bool) -> Result<(), Failure> {
            // No conversion while holding SH: two refillers must never deadlock.
            rustix::fs::flock(&self.fd, FlockOperation::Unlock)?;
            let operation = if exclusive {
                FlockOperation::NonBlockingLockExclusive
            } else {
                FlockOperation::NonBlockingLockShared
            };
            match rustix::fs::flock(&self.fd, operation) {
                Ok(()) => {}
                Err(error) if is_busy(error) => return Err(unsafe_("recovery lease busy")),
                Err(error) => return Err(error.into()),
            }
            self.validate()
        }

        pub(super) fn load(&mut self) -> Result<(), Failure> {
            self.validate()?;
            let size = fstat(&self.fd)?.size;
            if !(i128::from(HEADER) <= i128::from(size)
                && i128::from(size) <= i128::from(self.capacity))
            {
                return Err(unsafe_("invalid reserve length"));
            }
            let mut valid = Vec::with_capacity(2);
            for slot in 0..2u64 {
                let mut data = pread(&self.fd, SLOT, slot * SLOT)?;
                while data.last() == Some(&0) {
                    data.pop();
                }
                match parse_slot(&data, &self.immutable) {
                    Ok((sequence, body)) => valid.push((sequence, slot, body)),
                    Err(SlotError::Incomplete) => {
                        return Err(unsafe_("reserve header incomplete"));
                    }
                    Err(SlotError::Unsafe(message)) => return Err(unsafe_(message)),
                }
            }
            // A torn/zeroed newer slot must not expose an older unbound
            // generation. Both slots must remain valid; ambiguity refuses.
            valid.sort_by_key(|entry| entry.0);
            if valid[0].0 == valid[1].0 && valid[0].2 != valid[1].2 {
                return Err(unsafe_("conflicting reserve headers"));
            }
            let (sequence, slot, state) = valid.pop().expect("two valid slots");
            self.sequence = sequence;
            self.slot = slot;
            self.state = state;
            Ok(())
        }

        fn epoch(&self) -> Option<&str> {
            self.state.get("epoch").and_then(Value::as_str)
        }

        #[cfg(test)]
        pub(super) fn current_epoch(&self) -> Option<String> {
            self.epoch().map(str::to_owned)
        }

        fn claim_state(&self) -> Option<&Value> {
            self.state.get("claim").filter(|claim| !claim.is_null())
        }

        fn provisioned(&self) -> bool {
            self.state.get("provisioned").and_then(Value::as_bool) == Some(true)
        }

        pub(super) fn write(
            &mut self,
            epoch: Option<&str>,
            claim: Option<Value>,
            provisioned: Option<bool>,
        ) -> Result<(), Failure> {
            self.validate()?;
            let provisioned = provisioned.unwrap_or_else(|| self.provisioned());
            let sequence = self.sequence + 1;
            let body = json!({
                "immutable": self.immutable,
                "sequence": i64::try_from(sequence).map_err(|_| unsafe_("reserve sequence overflow"))?,
                "epoch": epoch,
                "claim": claim.unwrap_or(Value::Null),
                "provisioned": provisioned,
            });
            let digest = hex(&Sha256::digest(canonical(&body).as_bytes()));
            let mut data = canonical(&json!({"body": body, "sha256": digest})).into_bytes();
            if data.len() as u64 > SLOT {
                return Err(unsafe_("reserve header too large"));
            }
            let slot = 1 - self.slot;
            data.resize(usize::try_from(SLOT).expect("slot size fits"), 0);
            pwrite_all(&self.fd, &data, slot * SLOT, "header")?;
            rustix::fs::fsync(&self.fd)?;
            if pread(&self.fd, SLOT, slot * SLOT)? != data {
                return Err(unsafe_("reserve header readback failed"));
            }
            self.sequence = sequence;
            self.slot = slot;
            self.state = body;
            Ok(())
        }

        pub(super) fn initialize(&mut self) -> Result<(), Failure> {
            if self.created {
                self.sequence = 0;
                self.slot = 1;
                rustix::fs::ftruncate(&self.fd, HEADER)?;
                self.write(None, None, Some(false))?;
                self.write(None, None, None)?;
                rustix::fs::fsync(&self.dirs[PRIVATE_DIR].fd)?;
            } else {
                self.load()?;
            }
            if self.creation_locked {
                rustix::fs::flock(&self.dirs[PRIVATE_DIR].fd, FlockOperation::Unlock)?;
                self.creation_locked = false;
            }
            Ok(())
        }

        pub(super) fn free_bytes(&self) -> Result<u64, Failure> {
            free_bytes(&self.fd)
        }

        pub(super) fn full(&self) -> Result<bool, Failure> {
            let held = fstat(&self.fd)?;
            Ok(i128::from(held.size) == i128::from(self.capacity)
                && i128::from(held.allocated()) >= i128::from(self.capacity))
        }

        /// The exact identity of a GC claim record, active or (when `released`)
        /// its retirement receipt. Missing records surface as `NotFound`.
        pub(super) fn claim(&self, name: &str, released: bool) -> Result<Value, Failure> {
            let digest_name = claim_digest(name).ok_or_else(|| unsafe_("invalid GC claim name"))?;
            let registry_fd = &self.dirs[REGISTRY].fd;
            let extra = if released {
                let extra =
                    rustix::fs::openat(registry_fd, "released", directory_flags(), Mode::empty())?;
                let held = fstat(&extra)?;
                if held.uid != self.uid || held.mode & 0o022 != 0 || held.dev != self.device {
                    return Err(unsafe_("unsafe released directory"));
                }
                Some(extra)
            } else {
                None
            };
            let directory = extra.as_ref().unwrap_or(registry_fd);
            let fd = rustix::fs::openat(
                directory,
                name,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                Mode::empty(),
            )?;
            let before = fstat(&fd)?;
            if !before.is_regular()
                || before.uid != self.uid
                || before.nlink != 1
                || before.dev != self.device
                || before.mode & 0o077 != 0
                || !(0 < before.size && i128::from(before.size) <= i128::from(CLAIM_LIMIT))
            {
                return Err(unsafe_("unsafe GC claim"));
            }
            let mut hasher = Sha256::new();
            let mut length: u64 = 0;
            let mut chunk = vec![0u8; 65536];
            let handle = file(&fd);
            loop {
                let count = std::io::Read::read(&mut &handle, &mut chunk)?;
                if count == 0 {
                    break;
                }
                hasher.update(&chunk[..count]);
                length += count as u64;
                if length > CLAIM_LIMIT {
                    return Err(unsafe_("GC claim grew"));
                }
            }
            let digest = hex(&hasher.finalize());
            let after = fstat(&fd)?;
            let named = lstat_at(directory, name)?;
            if i128::from(length) != i128::from(before.size)
                || digest != digest_name
                || named.identity() != before.identity()
                || after.size != before.size
                || after.mtime_ns != before.mtime_ns
                || after.ctime_ns != before.ctime_ns
            {
                return Err(unsafe_("GC claim changed"));
            }
            if released {
                let named_directory = lstat_at(registry_fd, "released")?;
                let held_directory = fstat(directory)?;
                if !named_directory.is_dir()
                    || named_directory.identity() != held_directory.identity()
                    || held_directory.uid != self.uid
                    || held_directory.mode & 0o022 != 0
                {
                    return Err(unsafe_("released directory changed"));
                }
                rustix::fs::fsync(&fd)?;
                rustix::fs::fsync(directory)?;
                rustix::fs::fsync(registry_fd)?;
            }
            Ok(json!({"name": name, "file": before.identity_json(), "sha256": digest}))
        }

        /// True once no GC claim is bound (clearing a durably retired one).
        /// False while an intact, exact active record is still pending.
        pub(super) fn reconcile_receipt(&mut self) -> Result<bool, Failure> {
            let Some(claim) = self.claim_state().cloned() else {
                return Ok(true);
            };
            let name = claim
                .get("name")
                .and_then(Value::as_str)
                .ok_or_else(|| unsafe_("invalid reserve claim binding"))?
                .to_owned();
            let receipt = match self.claim(&name, true) {
                Ok(receipt) => receipt,
                Err(Failure::Os(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                    // Only an intact exact active record is a recoverable
                    // pending GC. A missing/substituted record cannot become
                    // an eligibility hint.
                    return match self.claim(&name, false) {
                        Ok(active) if active == claim => Ok(false),
                        Ok(_) => Err(unsafe_("emergency GC ownership record changed")),
                        Err(Failure::Os(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                            Err(unsafe_("emergency GC ownership record missing"))
                        }
                        Err(other) => Err(other),
                    };
                }
                Err(other) => return Err(other),
            };
            if receipt != claim {
                return Err(unsafe_("GC retirement receipt changed"));
            }
            // Both names existing is not a completed retirement, even with
            // matching contents. The inode-bound receipt is the GC protocol's proof.
            match lstat_at(&self.dirs[REGISTRY].fd, &name) {
                Err(Failure::Os(error)) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(other) => return Err(other),
                Ok(_) => return Err(unsafe_("active GC claim also has receipt")),
            }
            let epoch = self.epoch().map(str::to_owned);
            self.write(epoch.as_deref(), None, None)?;
            Ok(true)
        }

        pub(super) fn replenish(&mut self) -> Result<(), Failure> {
            if !self.reconcile_receipt()? {
                return Err(Failure::Pressure("recovery-pending"));
            }
            let allocated = u64::try_from(fstat(&self.fd)?.allocated()).unwrap_or(0);
            let need = self.capacity.saturating_sub(allocated);
            if self.free_bytes()? < need.saturating_add(self.headroom) {
                return Err(Failure::Pressure("insufficient-headroom"));
            }
            if !self.full()? {
                self.validate()?;
                self.allocate()?;
            }
            // This barrier also covers a full file left by an interrupted
            // first allocation before its provisioning bit could be published.
            rustix::fs::fsync(&self.fd)?;
            self.validate()?;
            if !self.full()? {
                return Err(unsafe_("reserve allocation is sparse"));
            }
            if self.epoch().is_some() || !self.provisioned() {
                // Publish only after actual allocation and its fsync. An
                // existing full-length file alone is not a provisioning receipt.
                self.write(None, None, Some(true))?;
            }
            Ok(())
        }

        fn allocate(&self) -> Result<(), Failure> {
            #[cfg(target_os = "linux")]
            match rustix::fs::fallocate(
                &self.fd,
                rustix::fs::FallocateFlags::empty(),
                0,
                self.capacity,
            ) {
                Ok(()) => return Ok(()),
                Err(
                    rustix::io::Errno::OPNOTSUPP
                    | rustix::io::Errno::NOSYS
                    | rustix::io::Errno::INVAL,
                ) => {}
                Err(error) => return Err(error.into()),
            }
            // No usable fallocate (macOS, or a filesystem without it).
            // Incompressible writes physically allocate bytes; truncated or
            // zero-filled sparse files cannot pass the `full` check.
            let mut offset = HEADER;
            let mut block = vec![0u8; 262_144];
            while offset < self.capacity {
                let length =
                    usize::try_from((self.capacity - offset).min(262_144)).expect("bounded block");
                random_bytes(&mut block[..length])?;
                pwrite_all(&self.fd, &block[..length], offset, "allocation")?;
                offset += length as u64;
            }
            rustix::fs::ftruncate(&self.fd, self.capacity)?;
            Ok(())
        }

        pub(super) fn spend(&mut self) -> Result<(), Failure> {
            self.validate()?;
            if !self.provisioned() {
                return Err(Failure::Pressure("insufficient-headroom"));
            }
            // This held file was checked before and after taking EX. Never
            // truncate a pathname, unlink a reserve, or replace an
            // unrecognized old header. Release BEFORE overwriting a header:
            // CoW filesystems may need a free block even for that overwrite.
            // If killed here, the durable provisioning bit permits a later EX
            // holder to establish an epoch without refilling.
            rustix::fs::ftruncate(&self.fd, HEADER)?;
            rustix::fs::fsync(&self.fd)?;
            self.validate()?;
            if self.epoch().is_none() {
                let generation = new_generation()?;
                self.write(Some(&generation), None, None)?;
            }
            Ok(())
        }

        pub(super) fn inherit(&mut self, mode: &str) -> Result<(), Failure> {
            let lease = rustix::io::fcntl_dupfd_cloexec(&self.fd, 64)?;
            rustix::io::fcntl_setfd(&lease, rustix::io::FdFlags::empty())?;
            let raw = std::os::fd::AsRawFd::as_raw_fd(&lease);
            self.lease = Some(lease);
            let epoch = self.epoch().unwrap_or_default().to_owned();
            self.environment = vec![
                ("RCH_RECOVERY_RESERVE_FD".into(), raw.to_string()),
                (
                    "RCH_RECOVERY_RESERVE_REGISTRY".into(),
                    self.registry.clone(),
                ),
                ("RCH_RECOVERY_RESERVE_MODE".into(), mode.into()),
                ("RCH_RECOVERY_RESERVE_EPOCH".into(), epoch),
                (
                    "RCH_GC_SCRATCH".into(),
                    self.scratch.to_string_lossy().into_owned(),
                ),
            ];
            Ok(())
        }

        /// Use the lease the calling shell inherited, without touching its
        /// flock: closing this process's descriptors must not unlock the
        /// owning shell. True when it is an exclusive (spent) generation.
        pub(super) fn borrow(&mut self) -> Result<bool, Failure> {
            let lease: i32 = std::env::var("RCH_RECOVERY_RESERVE_FD")
                .map_err(|_| unsafe_("no inherited reserve descriptor"))?
                .parse()
                .map_err(|_| unsafe_("invalid inherited reserve descriptor"))?;
            // A path open of the inherited descriptor reaches the same file
            // without adopting (and later closing) the shell's descriptor.
            let reopened = rustix::fs::open(
                format!("/dev/fd/{lease}"),
                OFlags::RDWR | OFlags::CLOEXEC | OFlags::NONBLOCK,
                Mode::empty(),
            )?;
            if fstat(&reopened)?.identity() != self.file_identity {
                return Err(unsafe_("inherited reserve descriptor changed"));
            }
            self.fd = reopened;
            self.load()?;
            if std::env::var("RCH_RECOVERY_RESERVE_REGISTRY")
                .ok()
                .as_deref()
                != Some(self.registry.as_str())
            {
                return Err(unsafe_("inherited registry changed"));
            }
            let mode = std::env::var("RCH_RECOVERY_RESERVE_MODE").ok();
            if mode.as_deref() == Some("shared") {
                if self.epoch().is_some() || !self.provisioned() || !self.full()? {
                    return Err(unsafe_("shared reserve no longer ready"));
                }
                return Ok(false);
            }
            let epoch = self.epoch().unwrap_or_default();
            if mode.as_deref() != Some("exclusive")
                || epoch.is_empty()
                || std::env::var("RCH_RECOVERY_RESERVE_EPOCH").ok().as_deref() != Some(epoch)
            {
                return Err(unsafe_("inherited reserve generation changed"));
            }
            Ok(true)
        }

        pub(super) fn ready(&self) -> Result<bool, Failure> {
            Ok(self.full()?
                && self.provisioned()
                && self.epoch().is_none()
                && self.free_bytes()? >= self.headroom)
        }

        fn shell(&self, script: &str) -> std::process::Command {
            let mut command = std::process::Command::new("sh");
            command.arg("-c").arg(script);
            for name in WRAPPER_ONLY_ENV {
                command.env_remove(name);
            }
            for (name, value) in &self.environment {
                command.env(name, value);
            }
            command
        }

        /// Replace this process with the payload; returns only on failure.
        fn exec(&self, script: &str) -> Failure {
            Failure::Os(self.shell(script).exec())
        }
    }

    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        bytes
            .iter()
            .fold(String::with_capacity(bytes.len() * 2), |mut out, byte| {
                let _ = write!(out, "{byte:02x}");
                out
            })
    }

    /// `os.path.split` for an absolute, already-normalized path.
    pub(super) fn split(path: &str) -> (&str, &str) {
        match path.rfind('/') {
            Some(0) => ("/", &path[1..]),
            Some(index) => (&path[..index], &path[index + 1..]),
            None => ("", path),
        }
    }

    /// `os.path.normpath` for absolute paths: collapse `//`, `.` and `..`.
    pub(super) fn normalize(path: &str) -> String {
        let mut parts: Vec<&str> = Vec::new();
        for part in path.split('/') {
            match part {
                "" | "." => {}
                ".." => {
                    parts.pop();
                }
                other => parts.push(other),
            }
        }
        format!("/{}", parts.join("/"))
    }

    fn create_missing_root(ancestor: &Path) -> Result<(), Failure> {
        use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
        if let Some(parent) = ancestor.parent() {
            std::fs::DirBuilder::new().recursive(true).create(parent)?;
        }
        match std::fs::DirBuilder::new().mode(0o755).create(ancestor) {
            Ok(()) => {
                std::fs::set_permissions(ancestor, std::fs::Permissions::from_mode(0o1777))?;
                Ok(())
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    fn open_directory(
        parent: &OwnedFd,
        name: &str,
        create: bool,
        private: bool,
        uid: u32,
    ) -> Result<Dir, Failure> {
        if create {
            match rustix::fs::mkdirat(parent, name, Mode::from_raw_mode(0o700)) {
                Ok(()) => rustix::fs::fsync(parent)?,
                Err(rustix::io::Errno::EXIST) => {}
                Err(error) => return Err(error.into()),
            }
        }
        let fd = rustix::fs::openat(parent, name, directory_flags(), Mode::empty())?;
        let held = fstat(&fd)?;
        if held.uid != uid || held.mode & 0o022 != 0 {
            return Err(unsafe_("directory ownership or permissions"));
        }
        if private && held.permissions() != 0o700 {
            return Err(unsafe_("private directory permissions"));
        }
        Ok(Dir {
            fd,
            name: name.to_owned(),
            identity: held.identity(),
            private,
        })
    }

    pub(super) enum SlotError {
        Incomplete,
        Unsafe(&'static str),
    }

    fn is_int(value: &Value) -> bool {
        value.is_i64() || value.is_u64()
    }

    fn as_int(value: &Value) -> Option<i128> {
        value
            .as_i64()
            .map(i128::from)
            .or_else(|| value.as_u64().map(i128::from))
    }

    /// Validate one header slot exactly as the original implementation did,
    /// including which defect wins when several are present.
    pub(super) fn parse_slot(data: &[u8], immutable: &Value) -> Result<(i128, Value), SlotError> {
        use SlotError::{Incomplete, Unsafe};
        let envelope: Value = serde_json::from_slice(data).map_err(|_| Incomplete)?;
        let body = envelope
            .as_object()
            .and_then(|map| map.get("body"))
            .ok_or(Incomplete)?;
        let digest = hex(&Sha256::digest(canonical(body).as_bytes()));
        let recorded = envelope.get("sha256").ok_or(Incomplete)?;
        if recorded.as_str() != Some(digest.as_str()) {
            return Err(Unsafe("reserve header checksum failed"));
        }
        let fields = body.as_object().ok_or(Incomplete)?;
        let field = |name: &str| fields.get(name).ok_or(Incomplete);
        if field("immutable")? != immutable {
            return Err(Unsafe("reserve header identity mismatch"));
        }
        let sequence = field("sequence")?;
        let sequence = match as_int(sequence) {
            Some(value) if is_int(sequence) && value > 0 => value,
            _ => return Err(Unsafe("reserve header identity mismatch")),
        };
        let epoch = field("epoch")?;
        let claim = field("claim")?;
        let provisioned = field("provisioned")?
            .as_bool()
            .ok_or(Unsafe("invalid reserve provisioning state"))?;
        if !provisioned && (!epoch.is_null() || !claim.is_null()) {
            return Err(Unsafe("unprovisioned reserve has recovery ownership"));
        }
        if !epoch.is_null() && !epoch.as_str().is_some_and(is_generation) {
            return Err(Unsafe("invalid reserve generation"));
        }
        if !claim.is_null() && (epoch.is_null() || !claim.is_object()) {
            return Err(Unsafe("invalid reserve claim"));
        }
        if let Some(claim) = claim.as_object() {
            let name = claim.get("name").ok_or(Incomplete)?;
            let name = name.as_str().ok_or(Incomplete)?;
            let Some(digest) = claim_digest(name) else {
                return Err(Unsafe("invalid reserve claim binding"));
            };
            if claim.get("sha256").ok_or(Incomplete)?.as_str() != Some(digest) {
                return Err(Unsafe("invalid reserve claim binding"));
            }
            let file = claim.get("file").ok_or(Incomplete)?;
            let binding_ok = file.as_array().is_some_and(|items| {
                items.len() == 2
                    && items
                        .iter()
                        .all(|item| is_int(item) && as_int(item).is_some_and(|value| value >= 0))
            });
            if !binding_ok {
                return Err(Unsafe("invalid reserve claim binding"));
            }
        }
        Ok((sequence, body.clone()))
    }

    fn callback(reserve: &mut Reserve, operation: &str, name: &str) -> Result<(), Failure> {
        if !reserve.borrow()? {
            return Ok(());
        }
        // The GC shell holds metadata fd 8 before publication and through
        // checked retirement. Do not reacquire it via another lock (that
        // would deadlock); only prove fd 8 is that exact file.
        let held = info(&rustix::fs::stat("/dev/fd/8")?);
        let named = lstat_at(&reserve.dirs[REGISTRY].fd, "metadata.lock")?;
        if held.identity() != named.identity()
            || !named.is_regular()
            || named.uid != reserve.uid
            || named.nlink != 1
        {
            return Err(unsafe_("GC metadata descriptor changed"));
        }
        match operation {
            "bind" => {
                let claim = reserve.claim(name, false)?;
                if reserve.claim_state().is_some_and(|bound| *bound != claim) {
                    return Err(unsafe_("previous emergency GC claim still bound"));
                }
                let epoch = reserve.epoch().map(str::to_owned);
                reserve.write(epoch.as_deref(), Some(claim), None)
            }
            "settle" => {
                let bound = reserve
                    .claim_state()
                    .and_then(|claim| claim.get("name"))
                    .and_then(Value::as_str);
                if bound != Some(name) {
                    return Err(unsafe_("GC retirement does not match reserve"));
                }
                if !reserve.reconcile_receipt()? {
                    return Err(unsafe_("GC retirement receipt missing"));
                }
                Ok(())
            }
            _ => Err(unsafe_("unknown reserve callback")),
        }
    }

    pub(super) fn run(arguments: &[String]) -> Result<i32, Failure> {
        if arguments.len() < 2 {
            return Err(unsafe_("missing reserve operation"));
        }
        let (operation, registry) = (arguments[0].as_str(), arguments[1].as_str());
        if !matches!(
            operation,
            "ready" | "admit" | "recover" | "gc" | "bind" | "settle"
        ) {
            return Err(unsafe_("unknown reserve operation"));
        }
        let create = matches!(operation, "ready" | "admit" | "gc");
        let mut reserve = match Reserve::open(registry, create, CAPACITY, HEADROOM) {
            Ok(reserve) => reserve,
            Err(Failure::Os(error))
                if error.kind() == std::io::ErrorKind::NotFound && operation == "recover" =>
            {
                // Recovery of an older/unprovisioned namespace keeps its
                // ordinary protocol. Only an entirely absent reserve permits
                // that; a partial existing reserve is damaged evidence. Never
                // create a reserve after the disk is full, or borrow another
                // registry's reserve (the legacy namespace may be elsewhere).
                if std::fs::symlink_metadata(Path::new(registry).join(PRIVATE)).is_ok() {
                    return Err(Failure::Os(error));
                }
                let script = payload(arguments, 2)?;
                let mut command = std::process::Command::new("sh");
                command.arg("-c").arg(script);
                for name in WRAPPER_ONLY_ENV {
                    command.env_remove(name);
                }
                return Err(Failure::Os(command.exec()));
            }
            Err(other) => return Err(other),
        };
        if matches!(operation, "bind" | "settle") {
            let name = arguments
                .get(2)
                .ok_or_else(|| unsafe_("missing GC claim name"))?;
            callback(&mut reserve, operation, name)?;
            return Ok(0);
        }
        reserve.lock(reserve.created)?;
        reserve.initialize()?;
        let ready = reserve.ready()?;
        match operation {
            "recover" => {
                // The caller wraps the ENTIRE finite metadata operation, before
                // its activity/metadata locks. Never acquire this lease from an
                // inner transaction already holding either lock, or let a build
                // or its release waiter inherit it. Nonblocking acquisition and
                // the outer owned-process deadline bound contention.
                let script = payload(arguments, 2)?;
                if ready {
                    reserve.inherit("shared")?;
                } else {
                    reserve.lock(true)?;
                    reserve.load()?;
                    // spend() changes only our allocation and, when necessary,
                    // establishes an epoch. Preserve even an unretired GC
                    // claim: source cancellation neither proves its retirement
                    // nor owns its reconciler.
                    reserve.spend()?;
                    reserve.inherit("exclusive")?;
                }
                reserve.validate()?;
                Err(reserve.exec(&script))
            }
            "ready" | "admit" => {
                let script = if operation == "admit" {
                    Some(payload(arguments, 2)?)
                } else {
                    None
                };
                if !ready {
                    reserve.lock(true)?;
                    reserve.load()?;
                    reserve.replenish()?;
                }
                let Some(script) = script else {
                    return Ok(0);
                };
                // Never rely on a lock conversion. Release EX then take SH and
                // revalidate the state that will protect this short admission.
                reserve.lock(false)?;
                reserve.load()?;
                if !reserve.full()? || !reserve.provisioned() || reserve.epoch().is_some() {
                    return Err(unsafe_("reserve changed before admission"));
                }
                reserve.inherit("shared")?;
                Err(reserve.exec(&script))
            }
            _ => {
                let script = payload(arguments, 2)?;
                if ready {
                    reserve.inherit("shared")?;
                } else {
                    reserve.lock(true)?;
                    reserve.load()?;
                    reserve.reconcile_receipt()?;
                    if !reserve.provisioned() {
                        // First-use GC may provision on a healthy filesystem.
                        // It cannot manufacture emergency bytes after the disk
                        // has already filled.
                        reserve.replenish()?;
                    }
                    if reserve.full()?
                        && reserve.epoch().is_none()
                        && reserve.free_bytes()? >= reserve.headroom
                    {
                        reserve.lock(false)?;
                        reserve.load()?;
                        if !reserve.full()? || !reserve.provisioned() || reserve.epoch().is_some() {
                            return Err(unsafe_("reserve changed before GC"));
                        }
                        reserve.inherit("shared")?;
                    } else {
                        reserve.spend()?;
                        reserve.inherit("exclusive")?;
                        // Exact bound-claim recovery uses the existing
                        // six-hour, intact record, complete handle+argv
                        // protocol. Its script is supplied by the GC builder,
                        // never by the header or a filename.
                        if !reserve.reconcile_receipt()? {
                            let claim = reserve
                                .claim_state()
                                .and_then(|claim| claim.get("name"))
                                .and_then(Value::as_str)
                                .unwrap_or_default()
                                .to_owned();
                            let reconcile = payload(arguments, 3)?;
                            let status = reserve
                                .shell(&reconcile)
                                .env("RCH_RECOVERY_GC_CLAIM", claim)
                                .status()?;
                            reserve.validate()?;
                            reserve.load()?;
                            if !status.success() || !reserve.reconcile_receipt()? {
                                return Err(unsafe_("emergency GC claim still protected"));
                            }
                        }
                    }
                }
                reserve.validate()?;
                Err(reserve.exec(&script))
            }
        }
    }
}

/// Git for Windows workers have no flock/`dir_fd` primitives, and never had a
/// recovery reserve: a namespace without one keeps its ordinary protocol, so
/// readiness is a no-op and payloads run directly.
#[cfg(not(unix))]
mod imp {
    use super::{Failure, WRAPPER_ONLY_ENV, payload, unsafe_};

    pub(super) fn is_no_space(_: &std::io::Error) -> bool {
        false
    }

    pub(super) fn is_quota(_: &std::io::Error) -> bool {
        false
    }

    pub(super) fn run(arguments: &[String]) -> Result<i32, Failure> {
        if arguments.len() < 2 {
            return Err(unsafe_("missing reserve operation"));
        }
        match arguments[0].as_str() {
            "ready" => Ok(0),
            "admit" | "recover" | "gc" => {
                let script = payload(arguments, 2)?;
                let mut command = std::process::Command::new("sh");
                command.arg("-c").arg(script);
                for name in WRAPPER_ONLY_ENV {
                    command.env_remove(name);
                }
                let status = command.status()?;
                Ok(status.code().unwrap_or(super::UNSAFE_EXIT))
            }
            "bind" | "settle" => Err(unsafe_("reserve callbacks require a POSIX worker")),
            _ => Err(unsafe_("unknown reserve operation")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Failure, canonical, claim_digest, report};
    use serde_json::json;

    const CLAIM: &str = "fc-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee.ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff.claim";

    /// Bytes the original implementation wrote for this header (generated
    /// once from its `json.dumps(..., sort_keys=True, separators=(",", ":"))`).
    /// Existing reserves stay readable only while these match exactly.
    const GOLDEN_ENVELOPE: &str = r#"{"body":{"claim":{"file":[-5,99],"name":"fc-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee.ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff.claim","sha256":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"},"epoch":"0123456789abcdef0123456789abcdef","immutable":{"capacity":67108864,"file":[-5,123],"private":[-5,2],"registry":[-5,1],"scratch":[-5,3],"uid":501,"version":1},"provisioned":true,"sequence":7},"sha256":"1394812d74ab02d67f733c8f330e7ff85750b34917cbd56394690832c4dd8927"}"#;

    /// The same header with a real Darwin device number. Claim identities
    /// must be non-negative, so only this one is a valid slot.
    const GOLDEN_DARWIN: &str = r#"{"body":{"claim":{"file":[16777234,99],"name":"fc-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee.ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff.claim","sha256":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"},"epoch":"0123456789abcdef0123456789abcdef","immutable":{"capacity":67108864,"file":[16777234,123],"private":[16777234,2],"registry":[16777234,1],"scratch":[16777234,3],"uid":501,"version":1},"provisioned":true,"sequence":7},"sha256":"dd7d5a1847c7b984362c311f3ec953046aafd075b18ad30eb5d37fe1aa89ce50"}"#;

    fn golden_immutable_on(dev: i64) -> serde_json::Value {
        json!({"version": 1, "file": [dev, 123], "uid": 501, "registry": [dev, 1],
               "private": [dev, 2], "scratch": [dev, 3], "capacity": 67_108_864})
    }

    fn golden_immutable() -> serde_json::Value {
        golden_immutable_on(-5)
    }

    /// `{"a":null,"z":"<e9><7f>\n\t\"\\<U+1F600>"}` as the original writer
    /// escaped it, spelled with an explicit backslash so no layer between
    /// this source and the compiler can pre-decode the escapes.
    fn ascii_escaped() -> String {
        let b = '\\';
        format!("{{\"a\":null,\"z\":\"{b}u00e9{b}u007f{b}n{b}t{b}\"{b}{b}{b}ud83d{b}ude00\"}}")
    }

    #[test]
    fn canonical_json_matches_the_existing_header_format_byte_for_byte() {
        let body = json!({
            "immutable": golden_immutable(), "sequence": 7,
            "epoch": "0123456789abcdef0123456789abcdef",
            "claim": {"name": CLAIM, "file": [-5, 99], "sha256": "f".repeat(64)},
            "provisioned": true,
        });
        use sha2::Digest as _;
        let digest: String = sha2::Sha256::digest(canonical(&body).as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_eq!(
            canonical(&json!({"body": body, "sha256": digest})),
            GOLDEN_ENVELOPE
        );
        // ASCII-only escaping, including DEL and astral characters.
        assert_eq!(
            canonical(&json!({"z": "\u{e9}\u{7f}\n\t\"\\\u{1F600}", "a": null})),
            ascii_escaped()
        );
    }

    #[test]
    fn claim_names_are_matched_exactly() {
        assert_eq!(claim_digest(CLAIM), Some("f".repeat(64).as_str()));
        for bad in [
            CLAIM.replace("fc-", "fd-"),
            CLAIM.replace(".claim", ".claimx"),
            CLAIM.replacen('a', "A", 1),
            CLAIM.replacen('f', "g", 1),
            format!("{CLAIM}\n"),
            CLAIM.replacen("aaaaaaaa", "aaaaaaa", 1),
        ] {
            assert_eq!(claim_digest(&bad), None, "{bad}");
        }
    }

    #[test]
    fn failures_keep_their_markers_and_statuses() {
        let (status, line) = report("/r", Failure::Pressure("insufficient-headroom"));
        assert_eq!(
            (status, line.as_str()),
            (75, "RCH_SOURCE_REGISTRY_PRESSURE /r: insufficient-headroom")
        );
        let (status, line) = report("/r", Failure::Unsafe("recovery lease busy".into()));
        assert_eq!(
            (status, line.as_str()),
            (74, "RCH_RECOVERY_RESERVE_UNSAFE /r: recovery lease busy")
        );
        #[cfg(unix)]
        {
            let no_space = std::io::Error::from(rustix::io::Errno::NOSPC);
            assert_eq!(report("/r", Failure::Os(no_space)).0, 75);
            let quota = std::io::Error::from(rustix::io::Errno::DQUOT);
            assert_eq!(
                report("/r", Failure::Os(quota)).1,
                "RCH_SOURCE_REGISTRY_PRESSURE /r: quota-exhausted"
            );
            let denied = std::io::Error::from(rustix::io::Errno::ACCESS);
            assert_eq!(report("/r", Failure::Os(denied)).0, 74);
        }
    }

    #[cfg(unix)]
    mod posix {
        use super::super::Failure;
        use super::super::imp::{Reserve, SlotError, normalize, parse_slot, split};
        use super::{CLAIM, GOLDEN_DARWIN, GOLDEN_ENVELOPE, golden_immutable, golden_immutable_on};
        use std::os::unix::fs::PermissionsExt as _;
        use std::path::{Path, PathBuf};

        const SMALL: u64 = 256 * 1024;

        fn message(failure: Failure) -> String {
            match failure {
                Failure::Unsafe(message) => message,
                Failure::Pressure(reason) => format!("pressure: {reason}"),
                Failure::Os(error) => format!("os: {error}"),
            }
        }

        struct Fixture {
            _root: tempfile::TempDir,
            registry: PathBuf,
        }

        fn fixture() -> Fixture {
            let root = tempfile::tempdir().unwrap();
            // The ancestor must not be group/world writable for the managed
            // leaves; tempdir is 0700, so the authority below it is private.
            let registry = root.path().join("authority/claims");
            Fixture {
                _root: root,
                registry,
            }
        }

        fn open(registry: &Path, create: bool, headroom: u64) -> Result<Reserve, Failure> {
            Reserve::open(registry.to_str().unwrap(), create, SMALL, headroom)
        }

        fn provisioned(registry: &Path) -> Reserve {
            let mut reserve = open(registry, true, 0).unwrap();
            reserve.lock(true).unwrap();
            reserve.initialize().unwrap();
            reserve.replenish().unwrap();
            reserve
        }

        fn reserve_file(registry: &Path) -> PathBuf {
            registry.join(".recovery-v1/reserve.v1")
        }

        #[test]
        fn path_helpers_match_posix_path_semantics() {
            assert_eq!(normalize("/a//b/./c/../d"), "/a/b/d");
            assert_eq!(normalize("/"), "/");
            assert_eq!(split("/var/tmp/x"), ("/var/tmp", "x"));
            assert_eq!(split("/x"), ("/", "x"));
        }

        #[test]
        fn golden_header_slot_parses_and_tampering_is_refused() {
            // A negative claim identity is refused, exactly as before.
            assert!(matches!(
                parse_slot(GOLDEN_ENVELOPE.as_bytes(), &golden_immutable()),
                Err(SlotError::Unsafe("invalid reserve claim binding"))
            ));
            let immutable = golden_immutable_on(16_777_234);
            let (sequence, body) = parse_slot(GOLDEN_DARWIN.as_bytes(), &immutable)
                .ok()
                .unwrap();
            assert_eq!(sequence, 7);
            assert_eq!(body["claim"]["name"], CLAIM);
            let tampered = GOLDEN_DARWIN.replace("\"sequence\":7", "\"sequence\":8");
            assert!(matches!(
                parse_slot(tampered.as_bytes(), &immutable),
                Err(SlotError::Unsafe("reserve header checksum failed"))
            ));
            for torn in ["", "{", "[]", "{\"body\":{}}"] {
                assert!(
                    matches!(
                        parse_slot(torn.as_bytes(), &immutable),
                        Err(SlotError::Incomplete)
                    ),
                    "{torn}"
                );
            }
            let mut other = immutable.clone();
            other["uid"] = 502.into();
            assert!(matches!(
                parse_slot(GOLDEN_DARWIN.as_bytes(), &other),
                Err(SlotError::Unsafe("reserve header identity mismatch"))
            ));
        }

        #[test]
        fn reserve_is_physically_allocated_and_spending_preserves_its_inode() {
            let fixture = fixture();
            let mut reserve = provisioned(&fixture.registry);
            assert!(reserve.ready().unwrap());
            let path = reserve_file(&fixture.registry);
            let before = std::fs::metadata(&path).unwrap();
            assert_eq!(before.len(), SMALL);
            assert_eq!(before.permissions().mode() & 0o777, 0o600);
            reserve.spend().unwrap();
            let after = std::fs::metadata(&path).unwrap();
            assert_eq!(after.len(), 4096);
            assert_eq!(
                std::os::unix::fs::MetadataExt::ino(&after),
                std::os::unix::fs::MetadataExt::ino(&before)
            );
            assert!(!reserve.ready().unwrap(), "a spent reserve is not ready");
            // A fresh process sees the spent generation, and refilling it
            // publishes a new unbound, provisioned state.
            drop(reserve);
            let mut again = open(&fixture.registry, false, 0).unwrap();
            again.lock(true).unwrap();
            again.load().unwrap();
            assert!(!again.ready().unwrap());
            again.replenish().unwrap();
            assert!(again.ready().unwrap());
        }

        #[test]
        fn unfunded_reserve_reports_pressure_and_cannot_be_spent() {
            let fixture = fixture();
            let mut reserve = open(&fixture.registry, true, u64::MAX / 4).unwrap();
            reserve.lock(true).unwrap();
            reserve.initialize().unwrap();
            assert!(!reserve.ready().unwrap());
            assert_eq!(
                message(reserve.replenish().unwrap_err()),
                "pressure: insufficient-headroom"
            );
            assert_eq!(
                message(reserve.spend().unwrap_err()),
                "pressure: insufficient-headroom"
            );
        }

        #[test]
        fn concurrent_lease_and_first_initializer_are_refused_not_awaited() {
            let fixture = fixture();
            let holder = provisioned(&fixture.registry);
            let other = open(&fixture.registry, false, 0).unwrap();
            assert_eq!(
                message(other.lock(false).unwrap_err()),
                "recovery lease busy"
            );
            holder.lock(false).unwrap();
            other.lock(false).unwrap(); // shared admissions coexist
            assert_eq!(
                message(other.lock(true).unwrap_err()),
                "recovery lease busy"
            );
            // While a creator holds the private-directory lock, another
            // creator refuses instead of racing first publication.
            let fresh = fixture.registry.parent().unwrap().join("second");
            let mut creating = open(&fresh, true, 0).unwrap();
            assert_eq!(
                message(open(&fresh, true, 0).err().unwrap()),
                "reserve initialization busy"
            );
            // Once published, a later creator joins the reserve instead of
            // being stranded by the first initializer.
            creating.lock(true).unwrap();
            creating.initialize().unwrap();
            creating.replenish().unwrap();
            creating.lock(false).unwrap();
            let mut joined = open(&fresh, true, 0).unwrap();
            joined.lock(false).unwrap();
            joined.initialize().unwrap();
            assert!(joined.full().unwrap());
            assert_eq!(joined.current_epoch(), None);
        }

        #[test]
        fn shared_admissions_coexist_but_cannot_overlap_refill() {
            let fixture = fixture();
            let first = provisioned(&fixture.registry);
            first.lock(false).unwrap();
            let mut second = open(&fixture.registry, false, 0).unwrap();
            second.lock(false).unwrap();
            second.load().unwrap();
            assert!(second.full().unwrap());
            let mut refill = open(&fixture.registry, false, 0).unwrap();
            assert_eq!(
                message(refill.lock(true).unwrap_err()),
                "recovery lease busy"
            );
            drop(first);
            assert_eq!(
                message(refill.lock(true).unwrap_err()),
                "recovery lease busy"
            );
            drop(second);
            refill.lock(true).unwrap();
            refill.load().unwrap();
            refill.replenish().unwrap();
            assert!(refill.full().unwrap());
        }

        #[test]
        fn corrupt_or_conflicting_headers_never_fall_back() {
            use std::os::unix::fs::FileExt as _;
            let fixture = fixture();
            drop(provisioned(&fixture.registry));
            let path = reserve_file(&fixture.registry);
            let file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
            // Zero the newest slot (sequence 3 is in slot 0): the older slot
            // alone is never trusted.
            file.write_at(&[0u8; 2048], 0).unwrap();
            let mut reserve = open(&fixture.registry, false, 0).unwrap();
            assert_eq!(
                message(reserve.load().unwrap_err()),
                "reserve header incomplete"
            );
        }

        #[test]
        fn unsafe_directories_and_noncanonical_registries_are_refused() {
            let fixture = fixture();
            drop(provisioned(&fixture.registry));
            for registry in ["relative/claims", "/a/../b/claims", "/claims"] {
                let refused = message(Reserve::open(registry, false, SMALL, 0).err().unwrap());
                assert!(
                    ["noncanonical registry", "shallow registry"].contains(&refused.as_str()),
                    "{registry}: {refused}"
                );
            }
            std::fs::set_permissions(&fixture.registry, std::fs::Permissions::from_mode(0o777))
                .unwrap();
            assert_eq!(
                message(open(&fixture.registry, false, 0).err().unwrap()),
                "directory ownership or permissions"
            );
            std::fs::set_permissions(&fixture.registry, std::fs::Permissions::from_mode(0o700))
                .unwrap();
            let private = fixture.registry.join(".recovery-v1");
            std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o750)).unwrap();
            assert_eq!(
                message(open(&fixture.registry, false, 0).err().unwrap()),
                "private directory permissions"
            );
            std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o700)).unwrap();
            let file = reserve_file(&fixture.registry);
            std::fs::hard_link(&file, private.join("extra-link")).unwrap();
            assert_eq!(
                message(open(&fixture.registry, false, 0).err().unwrap()),
                "reserve identity or permissions changed"
            );
        }

        fn write_claim(directory: &Path, content: &[u8], mode: u32) -> String {
            use sha2::Digest as _;
            let digest: String = sha2::Sha256::digest(content)
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();
            let name = format!("fc-01234567-89ab-cdef-0123-456789abcdef.{digest}.claim");
            let path = directory.join(&name);
            std::fs::write(&path, content).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
            name
        }

        #[test]
        fn claims_must_be_private_exact_and_unchanged() {
            let fixture = fixture();
            let reserve = provisioned(&fixture.registry);
            let name = write_claim(&fixture.registry, b"owner record\n", 0o600);
            let claim = reserve.claim(&name, false).unwrap();
            assert_eq!(claim["name"], name.as_str());
            std::fs::set_permissions(
                fixture.registry.join(&name),
                std::fs::Permissions::from_mode(0o644),
            )
            .unwrap();
            assert_eq!(
                message(reserve.claim(&name, false).unwrap_err()),
                "unsafe GC claim"
            );
            std::fs::set_permissions(
                fixture.registry.join(&name),
                std::fs::Permissions::from_mode(0o600),
            )
            .unwrap();
            std::fs::write(fixture.registry.join(&name), b"substituted\n").unwrap();
            assert_eq!(
                message(reserve.claim(&name, false).unwrap_err()),
                "GC claim changed"
            );
            assert_eq!(
                message(reserve.claim("fc-x.claim", false).unwrap_err()),
                "invalid GC claim name"
            );
            let symlink = write_claim(&fixture.registry, b"target\n", 0o600);
            let link_name = symlink.replace("fc-0", "fc-1");
            std::os::unix::fs::symlink(
                fixture.registry.join(&symlink),
                fixture.registry.join(&link_name),
            )
            .unwrap();
            assert!(
                reserve.claim(&link_name, false).is_err(),
                "a symlinked claim was bound"
            );
        }

        #[test]
        fn bound_claim_blocks_refill_until_its_same_inode_receipt_is_durable() {
            let fixture = fixture();
            let mut reserve = provisioned(&fixture.registry);
            reserve.lock(true).unwrap();
            reserve.spend().unwrap();
            let name = write_claim(&fixture.registry, b"gc owner\n", 0o600);
            let claim = reserve.claim(&name, false).unwrap();
            let epoch = reserve_epoch(&reserve);
            reserve.write(Some(&epoch), Some(claim), None).unwrap();
            // Pending: the active record is intact, so refill must wait.
            assert!(!reserve.reconcile_receipt().unwrap());
            assert_eq!(
                message(reserve.replenish().unwrap_err()),
                "pressure: recovery-pending"
            );
            // Retire by rename into released/: the same inode is the receipt.
            let released = fixture.registry.join("released");
            std::fs::create_dir(&released).unwrap();
            std::fs::set_permissions(&released, std::fs::Permissions::from_mode(0o700)).unwrap();
            std::fs::rename(fixture.registry.join(&name), released.join(&name)).unwrap();
            assert!(reserve.reconcile_receipt().unwrap());
            reserve.replenish().unwrap();
            assert!(reserve.ready().unwrap());
        }

        #[test]
        fn substituted_receipt_or_missing_record_is_unsafe() {
            let fixture = fixture();
            let mut reserve = provisioned(&fixture.registry);
            reserve.lock(true).unwrap();
            reserve.spend().unwrap();
            let name = write_claim(&fixture.registry, b"gc owner\n", 0o600);
            let claim = reserve.claim(&name, false).unwrap();
            let epoch = reserve_epoch(&reserve);
            reserve.write(Some(&epoch), Some(claim), None).unwrap();
            let released = fixture.registry.join("released");
            std::fs::create_dir(&released).unwrap();
            std::fs::set_permissions(&released, std::fs::Permissions::from_mode(0o700)).unwrap();
            // Same bytes, different inode: not the bound record's receipt.
            std::fs::copy(fixture.registry.join(&name), released.join(&name)).unwrap();
            std::fs::set_permissions(released.join(&name), std::fs::Permissions::from_mode(0o600))
                .unwrap();
            std::fs::remove_file(fixture.registry.join(&name)).unwrap();
            assert_eq!(
                message(reserve.reconcile_receipt().unwrap_err()),
                "GC retirement receipt changed"
            );
            std::fs::remove_file(released.join(&name)).unwrap();
            assert_eq!(
                message(reserve.reconcile_receipt().unwrap_err()),
                "emergency GC ownership record missing"
            );
        }

        fn reserve_epoch(reserve: &Reserve) -> String {
            reserve
                .current_epoch()
                .expect("a spent reserve has a generation")
        }
    }
}
