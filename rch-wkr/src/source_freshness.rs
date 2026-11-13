//! Content-bound source timestamps under the dispatcher's existing source lease.
//!
//! This helper never reuses source bytes or grants source ownership. It retains
//! timestamps only from the immediately preceding sealed inventory. Owned
//! source pairs additionally require that predecessor's exact verified attempt;
//! an interrupted preparation cannot teach a later build that stale artifacts
//! are fresh. All entry access stays relative to retained directory descriptors.

use std::io::{self, Write as _};

#[cfg(unix)]
const PROBE: &str = "rch-wkr source-freshness v1\n";
const REFUSED: i32 = 74;

/// Run before async runtime or optional file logging initialization.
pub fn main(arguments: &[String]) -> i32 {
    #[cfg(unix)]
    let result = if arguments == ["probe"] {
        Ok(PROBE.to_owned())
    } else {
        native::run(arguments)
    };
    #[cfg(not(unix))]
    let result: anyhow::Result<String> = {
        let _ = arguments;
        Err(anyhow::anyhow!("source freshness requires a Unix worker"))
    };
    match result {
        Ok(response) => match io::stdout().lock().write_all(response.as_bytes()) {
            Ok(()) => 0,
            Err(error) => {
                let _ = writeln!(
                    io::stderr().lock(),
                    "RCH: source freshness unproved: {error}"
                );
                REFUSED
            }
        },
        Err(error) => {
            let _ = writeln!(
                io::stderr().lock(),
                "RCH: source freshness unproved: {error:#}"
            );
            REFUSED
        }
    }
}

#[cfg(unix)]
mod native {
    use anyhow::{Context as _, Result, bail, ensure};
    use rustix::fd::OwnedFd;
    use rustix::fs::{AtFlags, CWD, Dir, FileType, Mode, OFlags, Stat, Timestamps};
    use rustix::io::Errno;
    use rustix::time::Timespec;
    use serde::{Deserialize, Serialize};
    use serde_json::{Value, json};
    use sha2::{Digest as _, Sha256};
    use std::collections::BTreeMap;
    use std::fmt::Write as _;
    use std::fs::File;
    use std::io::{Read as _, Write as _};
    use std::path::Path;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    const MAX_ENTRIES: usize = 200_000;
    const MAX_BYTES: u64 = 8 * 1024 * 1024 * 1024;
    const MAX_LEDGER: u64 = 64 * 1024 * 1024;
    const MAX_INTENT: u64 = 64 * 1024;
    const DIRECTORY_FLAGS: OFlags = OFlags::RDONLY
        .union(OFlags::DIRECTORY)
        .union(OFlags::NOFOLLOW)
        .union(OFlags::CLOEXEC);
    const FILE_FLAGS: OFlags = OFlags::RDONLY
        .union(OFlags::NOFOLLOW)
        .union(OFlags::NONBLOCK)
        .union(OFlags::NOCTTY)
        .union(OFlags::CLOEXEC);

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Observation {
        IntentPublished,
        SourceInventoried,
        BeforePoolScan,
        BeforeLedgerCommit,
    }

    fn literal_path(value: &str) -> bool {
        value.starts_with('/')
            && value != "/"
            && !value.contains('\\')
            && !value.chars().any(|ch| ch.is_control())
            && value[1..]
                .split('/')
                .all(|part| !matches!(part, "" | "." | ".."))
    }

    fn content_identity(value: &str) -> bool {
        value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
    }

    fn attempt_identity(value: &str) -> bool {
        value.len() == 32
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
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

    fn mtime_ns(info: &Stat) -> i128 {
        i128::from(info.st_mtime) * 1_000_000_000 + i128::from(info.st_mtime_nsec)
    }

    fn named(directory: &OwnedFd, name: &str) -> Result<Stat> {
        Ok(rustix::fs::statat(
            directory,
            name,
            AtFlags::SYMLINK_NOFOLLOW,
        )?)
    }

    struct Directory {
        descriptor: OwnedFd,
        path: String,
        follow_final: bool,
    }

    impl Directory {
        fn open(path: &str, strict_ancestors: bool) -> Result<Self> {
            let descriptor = if strict_ancestors {
                let mut current = rustix::fs::open("/", DIRECTORY_FLAGS, Mode::empty())?;
                for part in path[1..].split('/') {
                    current = rustix::fs::openat(&current, part, DIRECTORY_FLAGS, Mode::empty())?;
                }
                current
            } else {
                rustix::fs::open(path, DIRECTORY_FLAGS, Mode::empty())?
            };
            let directory = Self {
                descriptor,
                path: path.to_owned(),
                follow_final: false,
            };
            directory.check()?;
            Ok(directory)
        }

        /// Overlay controls live beside the retained container. Its existing
        /// parent may be an OS alias such as Darwin's /tmp. Follow that alias
        /// when opening, then keep both the descriptor and logical path bound.
        /// Owned-source controls use the strict no-follow walk instead.
        fn open_overlay_parent(path: &str) -> Result<Self> {
            let directory = Self {
                descriptor: rustix::fs::open(
                    path,
                    DIRECTORY_FLAGS & !OFlags::NOFOLLOW,
                    Mode::empty(),
                )?,
                path: path.to_owned(),
                follow_final: true,
            };
            directory.check()?;
            Ok(directory)
        }

        fn check(&self) -> Result<()> {
            let current = rustix::fs::statat(
                CWD,
                self.path.as_str(),
                if self.follow_final {
                    AtFlags::empty()
                } else {
                    AtFlags::SYMLINK_NOFOLLOW
                },
            )?;
            ensure!(
                FileType::from_raw_mode(current.st_mode) == FileType::Directory
                    && same_inode(&current, &rustix::fs::fstat(&self.descriptor)?),
                "directory changed during source freshness"
            );
            Ok(())
        }

        fn parent(&self, relative: &str) -> Result<(OwnedFd, String)> {
            let mut directory = rustix::io::dup(&self.descriptor)?;
            if relative.is_empty() {
                return Ok((directory, ".".to_owned()));
            }
            let mut parts = relative.split('/').peekable();
            while let Some(part) = parts.next() {
                if parts.peek().is_none() {
                    return Ok((directory, part.to_owned()));
                }
                directory = rustix::fs::openat(&directory, part, DIRECTORY_FLAGS, Mode::empty())?;
            }
            bail!("invalid source relative path")
        }
    }

    /// Keep the established sorted ASCII JSON preimage, including the short
    /// control-character escapes and lowercase UTF-16 surrogate pairs.
    fn canonical(value: &Value) -> Vec<u8> {
        fn string(value: &str, out: &mut String) {
            out.push('"');
            for ch in value.chars() {
                match ch {
                    '"' => out.push_str("\\\""),
                    '\\' => out.push_str("\\\\"),
                    '\u{8}' => out.push_str("\\b"),
                    '\u{c}' => out.push_str("\\f"),
                    '\n' => out.push_str("\\n"),
                    '\r' => out.push_str("\\r"),
                    '\t' => out.push_str("\\t"),
                    ' '..='~' => out.push(ch),
                    other => {
                        let mut units = [0_u16; 2];
                        for unit in other.encode_utf16(&mut units) {
                            let _ = write!(out, "\\u{unit:04x}");
                        }
                    }
                }
            }
            out.push('"');
        }
        fn write(value: &Value, out: &mut String) {
            match value {
                Value::Null => out.push_str("null"),
                Value::Bool(value) => out.push_str(if *value { "true" } else { "false" }),
                Value::Number(value) => {
                    let _ = write!(out, "{value}");
                }
                Value::String(value) => string(value, out),
                Value::Array(values) => {
                    out.push('[');
                    for (index, value) in values.iter().enumerate() {
                        if index != 0 {
                            out.push(',');
                        }
                        write(value, out);
                    }
                    out.push(']');
                }
                Value::Object(values) => {
                    out.push('{');
                    let sorted: BTreeMap<_, _> = values.iter().collect();
                    for (index, (key, value)) in sorted.into_iter().enumerate() {
                        if index != 0 {
                            out.push(',');
                        }
                        string(key, out);
                        out.push(':');
                        write(value, out);
                    }
                    out.push('}');
                }
            }
        }
        let mut result = String::new();
        write(value, &mut result);
        result.into_bytes()
    }

    fn hex(bytes: &[u8]) -> String {
        let mut encoded = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            let _ = write!(encoded, "{byte:02x}");
        }
        encoded
    }

    fn digest(bytes: &[u8]) -> String {
        hex(&Sha256::digest(bytes))
    }

    struct ControlFiles {
        directory: Directory,
        epoch: String,
        require_owner: bool,
    }

    struct ControlRecord {
        data: Vec<u8>,
        before: Stat,
    }

    impl ControlFiles {
        fn check(&self) -> Result<()> {
            self.directory.check()?;
            if self.require_owner {
                let info = rustix::fs::fstat(&self.directory.descriptor)?;
                ensure!(
                    info.st_uid == rustix::process::geteuid().as_raw() && info.st_mode & 0o077 == 0,
                    "control directory must be private and owned by this worker user"
                );
            }
            Ok(())
        }

        fn read(&self, name: &str, cap: u64) -> Result<Option<ControlRecord>> {
            self.check()?;
            let descriptor = match rustix::fs::openat(
                &self.directory.descriptor,
                name,
                FILE_FLAGS,
                Mode::empty(),
            ) {
                Ok(descriptor) => descriptor,
                Err(Errno::NOENT) => return Ok(None),
                Err(error) => return Err(error).context("open freshness control"),
            };
            let mut file = File::from(descriptor);
            let before = rustix::fs::fstat(&file)?;
            ensure!(
                FileType::from_raw_mode(before.st_mode) == FileType::RegularFile,
                "nonregular freshness control"
            );
            ensure!(
                !self.require_owner || before.st_uid == rustix::process::geteuid().as_raw(),
                "freshness control must be a regular owned file"
            );
            let size = u64::try_from(before.st_size).context("negative freshness control size")?;
            if size > cap {
                return Ok(None);
            }
            let mut data = Vec::new();
            (&mut file).take(cap + 1).read_to_end(&mut data)?;
            ensure!(
                data.len() as u64 == size
                    && same_snapshot(&before, &rustix::fs::fstat(&file)?)
                    && same_snapshot(&before, &named(&self.directory.descriptor, name)?),
                "freshness control changed while reading"
            );
            self.check()?;
            Ok(Some(ControlRecord { data, before }))
        }

        fn stage(&self, name: &str, data: &[u8], stamp: Option<u64>) -> Result<String> {
            self.check()?;
            let mut nonce = [0_u8; 16];
            File::open("/dev/urandom")?.read_exact(&mut nonce)?;
            let suffix: String = nonce.iter().map(|byte| format!("{byte:02x}")).collect();
            let temporary = format!("{name}.pending.{suffix}");
            let descriptor = rustix::fs::openat(
                &self.directory.descriptor,
                temporary.as_str(),
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::from_raw_mode(0o600),
            )?;
            // Interrupted or conflicting publication retains its staging
            // evidence. Never unlink an ambiguous name during recovery.
            let mut file = File::from(descriptor);
            file.write_all(data)?;
            if let Some(stamp) = stamp {
                let time = timestamp(stamp)?;
                rustix::fs::futimens(
                    &file,
                    &Timestamps {
                        last_access: time,
                        last_modification: time,
                    },
                )?;
                ensure!(
                    mtime_ns(&rustix::fs::fstat(&file)?) == i128::from(stamp),
                    "epoch timestamp precision changed"
                );
            }
            rustix::fs::fsync(&file)?;
            ensure!(
                same_snapshot(
                    &rustix::fs::fstat(&file)?,
                    &named(&self.directory.descriptor, &temporary)?,
                ),
                "freshness staging record changed"
            );
            self.check()?;
            Ok(temporary)
        }

        fn replace(&self, temporary: &str, name: &str) -> Result<()> {
            self.check()?;
            rustix::fs::renameat(
                &self.directory.descriptor,
                temporary,
                &self.directory.descriptor,
                name,
            )?;
            Ok(())
        }

        fn sync(&self) -> Result<()> {
            self.check()?;
            rustix::fs::fsync(&self.directory.descriptor)?;
            self.check()
        }

        fn ledger(&self) -> String {
            format!("{}.files-v2", self.epoch)
        }
    }

    #[derive(Clone, Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    struct Entry {
        fingerprint: String,
        mtime_ns: u64,
    }

    #[derive(Deserialize, Serialize)]
    struct Payload {
        schema: u64,
        identity: String,
        epoch_ns: u64,
        entries: BTreeMap<String, Entry>,
    }

    fn decode_ledger(epoch: &ControlRecord, ledger: &ControlRecord) -> Option<Payload> {
        let stored: Value = serde_json::from_slice(&ledger.data).ok()?;
        let payload = stored.get("payload")?;
        if stored.get("sha256")?.as_str()? != digest(&canonical(payload)) {
            return None;
        }
        let payload: Payload = serde_json::from_value(payload.clone()).ok()?;
        if payload.schema != 2
            || !content_identity(&payload.identity)
            || epoch.data != format!("{}\n", payload.identity).as_bytes()
            || mtime_ns(&epoch.before) != i128::from(payload.epoch_ns)
            || payload.entries.len() > MAX_ENTRIES
        {
            return None;
        }
        for (path, entry) in &payload.entries {
            if (!path.is_empty()
                && (path.starts_with('/')
                    || path.split('/').any(|part| matches!(part, "" | "." | ".."))))
                || entry.fingerprint.len() != 64
                || !entry
                    .fingerprint
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                || entry.mtime_ns > payload.epoch_ns
            {
                return None;
            }
        }
        Some(payload)
    }

    fn previous_entries(
        controls: &ControlFiles,
        qualified: bool,
    ) -> Result<BTreeMap<String, Entry>> {
        // Always inspect control types, including when the previous attempt
        // cannot authorize reuse. A symlink is not a cache miss.
        let epoch = controls.read(&controls.epoch, 65)?;
        let ledger = controls.read(&controls.ledger(), MAX_LEDGER)?;
        Ok(if qualified {
            epoch
                .as_ref()
                .zip(ledger.as_ref())
                .and_then(|(epoch, ledger)| decode_ledger(epoch, ledger))
                .map(|payload| payload.entries)
                .unwrap_or_default()
        } else {
            BTreeMap::new()
        })
    }

    fn inventory(root: &Directory) -> Result<BTreeMap<String, Entry>> {
        fn visit(
            root: &Directory,
            relative: &str,
            depth: usize,
            entries: &mut BTreeMap<String, Entry>,
            total: &mut u64,
        ) -> Result<String> {
            ensure!(
                depth <= 128 && entries.len() < MAX_ENTRIES,
                "source inventory cap exceeded"
            );
            let (parent, name) = root.parent(relative)?;
            let before = named(&parent, &name)?;
            let mode = before.st_mode & 0o7777;
            entries.insert(
                relative.to_owned(),
                Entry {
                    fingerprint: String::new(),
                    mtime_ns: 0,
                },
            );
            let value = match FileType::from_raw_mode(before.st_mode) {
                FileType::RegularFile => {
                    let size = u64::try_from(before.st_size).context("negative source size")?;
                    *total = total
                        .checked_add(size)
                        .context("source byte cap exceeded")?;
                    ensure!(*total <= MAX_BYTES, "source byte cap exceeded");
                    let descriptor =
                        rustix::fs::openat(&parent, name.as_str(), FILE_FLAGS, Mode::empty())?;
                    let mut file = File::from(descriptor);
                    ensure!(
                        same_snapshot(&before, &rustix::fs::fstat(&file)?),
                        "source replaced while hashing"
                    );
                    let mut hasher = Sha256::new();
                    let mut buffer = vec![0_u8; 1024 * 1024];
                    let mut read_bytes = 0_u64;
                    loop {
                        let count = file.read(&mut buffer)?;
                        if count == 0 {
                            break;
                        }
                        read_bytes += count as u64;
                        ensure!(read_bytes <= size, "source grew while hashing");
                        hasher.update(&buffer[..count]);
                    }
                    ensure!(
                        read_bytes == size && same_snapshot(&before, &rustix::fs::fstat(&file)?),
                        "source changed while hashing"
                    );
                    json!(["file", mode, size, hex(&hasher.finalize())])
                }
                FileType::Symlink => {
                    let link = rustix::fs::readlinkat(&parent, name.as_str(), Vec::new())?;
                    let target = link.to_str().context("source link is not UTF-8")?;
                    json!(["symlink", mode, target])
                }
                FileType::Directory => {
                    let directory =
                        rustix::fs::openat(&parent, name.as_str(), DIRECTORY_FLAGS, Mode::empty())?;
                    ensure!(
                        same_inode(&before, &rustix::fs::fstat(&directory)?),
                        "source directory replaced while hashing"
                    );
                    let mut children = Vec::new();
                    for entry in Dir::read_from(&directory)? {
                        let entry = entry?;
                        let bytes = entry.file_name().to_bytes();
                        if matches!(bytes, b"." | b"..") {
                            continue;
                        }
                        ensure!(
                            children.len() + entries.len() < MAX_ENTRIES,
                            "source directory cap exceeded"
                        );
                        children.push(
                            entry
                                .file_name()
                                .to_str()
                                .context("source name is not UTF-8")?
                                .to_owned(),
                        );
                    }
                    children.sort();
                    let mut fingerprints = Vec::with_capacity(children.len());
                    for child in children {
                        let path = if relative.is_empty() {
                            child.clone()
                        } else {
                            format!("{relative}/{child}")
                        };
                        fingerprints.push(json!([
                            child,
                            visit(root, &path, depth + 1, entries, total)?
                        ]));
                    }
                    json!(["directory", mode, fingerprints])
                }
                _ => bail!("unsupported source entry type"),
            };
            ensure!(
                same_snapshot(&before, &named(&parent, &name)?),
                "source changed while hashing"
            );
            let fingerprint = digest(&canonical(&value));
            entries
                .get_mut(relative)
                .context("missing inventoried source")?
                .fingerprint = fingerprint.clone();
            Ok(fingerprint)
        }
        root.check()?;
        let mut entries = BTreeMap::new();
        visit(root, "", 0, &mut entries, &mut 0)?;
        root.check()?;
        Ok(entries)
    }

    fn pool_anchor(directory: &OwnedFd, anchor: &mut i128) -> Result<()> {
        for entry in Dir::read_from(directory)? {
            let entry = entry?;
            let name = entry.file_name();
            if matches!(name.to_bytes(), b"." | b"..") {
                continue;
            }
            let before = rustix::fs::statat(directory, name, AtFlags::SYMLINK_NOFOLLOW)?;
            match FileType::from_raw_mode(before.st_mode) {
                FileType::RegularFile => *anchor = (*anchor).max(mtime_ns(&before)),
                FileType::Directory => {
                    let child =
                        rustix::fs::openat(directory, name, DIRECTORY_FLAGS, Mode::empty())?;
                    ensure!(
                        same_inode(&before, &rustix::fs::fstat(&child)?),
                        "cached artifact directory changed during inventory"
                    );
                    pool_anchor(&child, anchor)?;
                    ensure!(
                        same_inode(
                            &before,
                            &rustix::fs::statat(directory, name, AtFlags::SYMLINK_NOFOLLOW)?
                        ),
                        "cached artifact directory replaced during inventory"
                    );
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn timestamp(nanos: u64) -> Result<Timespec> {
        Ok(Timespec {
            tv_sec: (nanos / 1_000_000_000).try_into()?,
            tv_nsec: (nanos % 1_000_000_000).try_into()?,
        })
    }

    fn fresh_stamp(anchor: i128) -> Result<u64> {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
            if i128::try_from(stamp)? > anchor {
                return Ok(stamp.try_into()?);
            }
            ensure!(
                Instant::now() < deadline,
                "worker clock cannot advance beyond cached artifacts"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn refresh(
        root: &Directory,
        pool: &str,
        controls: &ControlFiles,
        identity: &str,
        previous_qualified: bool,
        observe: &mut impl FnMut(Observation) -> Result<()>,
    ) -> Result<String> {
        let pool = match rustix::fs::statat(CWD, pool, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(info) => {
                ensure!(
                    FileType::from_raw_mode(info.st_mode) == FileType::Directory,
                    "target pool is not a real directory"
                );
                Some(Directory::open(pool, false)?)
            }
            Err(Errno::NOENT) => None,
            Err(error) => return Err(error).context("inspect target pool"),
        };
        let previous = previous_entries(controls, previous_qualified)?;
        let mut current = inventory(root)?;
        observe(Observation::SourceInventoried)?;
        let changed = current
            .iter()
            .filter(|(path, entry)| {
                previous
                    .get(*path)
                    .is_none_or(|previous| previous.fingerprint != entry.fingerprint)
            })
            .count();
        let mut anchor = previous
            .values()
            .map(|entry| i128::from(entry.mtime_ns))
            .max()
            .unwrap_or(0);
        if changed != 0
            && let Some(pool) = &pool
        {
            observe(Observation::BeforePoolScan)?;
            pool.check()?;
            pool_anchor(&pool.descriptor, &mut anchor)?;
            pool.check()?;
        }
        let stamp = fresh_stamp(anchor)?;
        root.check()?;
        // Descendants precede directories. Timestamp changes do not modify
        // parent mtimes, but this order also preserves the established ledger.
        let mut paths: Vec<_> = current.keys().cloned().collect();
        paths.sort_by_key(|path| {
            std::cmp::Reverse(path.bytes().filter(|byte| *byte == b'/').count())
        });
        for relative in paths {
            let entry = current.get_mut(&relative).context("missing source entry")?;
            let modified = previous
                .get(&relative)
                .filter(|previous| previous.fingerprint == entry.fingerprint)
                .map_or(stamp, |previous| previous.mtime_ns);
            let (directory, name) = root.parent(&relative)?;
            let info = named(&directory, &name)?;
            rustix::fs::utimensat(
                &directory,
                name.as_str(),
                &Timestamps {
                    last_access: Timespec {
                        tv_sec: info.st_atime as _,
                        tv_nsec: info.st_atime_nsec as _,
                    },
                    last_modification: timestamp(modified)?,
                },
                AtFlags::SYMLINK_NOFOLLOW,
            )?;
            ensure!(
                mtime_ns(&named(&directory, &name)?) == i128::from(modified),
                "source timestamp precision changed"
            );
            entry.mtime_ns = modified;
        }
        let verified = inventory(root)?;
        ensure!(
            current.len() == verified.len()
                && current.iter().all(|(path, entry)| verified
                    .get(path)
                    .is_some_and(|verified| verified.fingerprint == entry.fingerprint)),
            "source changed during freshness refresh"
        );
        let payload = serde_json::to_value(Payload {
            schema: 2,
            identity: identity.to_owned(),
            epoch_ns: stamp,
            entries: current,
        })?;
        let encoded =
            canonical(&json!({"sha256": digest(&canonical(&payload)), "payload": payload}));
        ensure!(
            encoded.len() as u64 <= MAX_LEDGER,
            "freshness ledger cap exceeded"
        );
        let pending_ledger = controls.stage(&controls.ledger(), &encoded, None)?;
        let pending_epoch = controls.stage(
            &controls.epoch,
            format!("{identity}\n").as_bytes(),
            Some(stamp),
        )?;
        observe(Observation::BeforeLedgerCommit)?;
        root.check()?;
        // Epoch is the commit marker. A crash between the replacements leaves
        // a mismatched pair and forces conservative refresh next time.
        controls.replace(&pending_ledger, &controls.ledger())?;
        controls.replace(&pending_epoch, &controls.epoch)?;
        controls.sync()?;
        root.check()?;
        Ok(format!(
            "RCH_SOURCE_FRESHNESS_V2 unchanged={} changed={changed}\n",
            verified.len() - changed
        ))
    }

    #[derive(Clone, Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    struct Intent {
        schema: String,
        source_root: String,
        target_root: String,
        content_identity: String,
        attempt: String,
    }

    fn decode_intent(record: Option<&ControlRecord>, requested: &Intent) -> Option<Intent> {
        let record = record?;
        let intent: Intent = serde_json::from_slice(&record.data).ok()?;
        if canonical(&serde_json::to_value(&intent).ok()?) != record.data
            || intent.schema != requested.schema
            || intent.source_root != requested.source_root
            || intent.target_root != requested.target_root
            || !content_identity(&intent.content_identity)
            || !attempt_identity(&intent.attempt)
        {
            return None;
        }
        Some(intent)
    }

    fn qualification(controls: &ControlFiles, intent: &Intent) -> Result<Option<Vec<u8>>> {
        let Some(epoch) = controls.read(&controls.epoch, 65)? else {
            return Ok(None);
        };
        let Some(ledger) = controls.read(&controls.ledger(), MAX_LEDGER)? else {
            return Ok(None);
        };
        let Some(payload) = decode_ledger(&epoch, &ledger) else {
            return Ok(None);
        };
        if payload.identity != intent.content_identity {
            return Ok(None);
        }
        Ok(Some(canonical(&json!({
            "schema": "rch.source_freshness_verified.v1",
            "intent": intent,
            "epoch_sha256": digest(&epoch.data),
            "ledger_sha256": digest(&ledger.data),
            "epoch_mtime_ns": payload.epoch_ns,
        }))))
    }

    fn owned(
        root: &str,
        pool: &str,
        epoch: &str,
        identity: &str,
        attempt: &str,
        operation: &str,
        observe: &mut impl FnMut(Observation) -> Result<()>,
    ) -> Result<String> {
        ensure!(
            cfg!(target_os = "linux"),
            "Linux worker required for owned source freshness"
        );
        let control = format!("{root}.freshness");
        ensure!(
            epoch == format!("{control}/epoch-v1"),
            "control directory is outside its exact authority"
        );
        ensure!(
            pool != root
                && !pool.starts_with(&format!("{root}/"))
                && pool != control
                && !pool.starts_with(&format!("{control}/")),
            "stable target must be outside source and control trees"
        );
        ensure!(attempt_identity(attempt), "invalid freshness attempt");
        ensure!(
            matches!(operation, "refresh" | "verify"),
            "invalid freshness operation"
        );
        let root = Directory::open(root, true)?;
        ensure!(
            rustix::fs::fstat(&root.descriptor)?.st_uid == rustix::process::geteuid().as_raw(),
            "source container has a foreign owner"
        );
        let parent_path = Path::new(&control)
            .parent()
            .and_then(Path::to_str)
            .context("missing control parent")?;
        let parent = if parent_path == "/" {
            Directory {
                descriptor: rustix::fs::open("/", DIRECTORY_FLAGS, Mode::empty())?,
                path: "/".into(),
                follow_final: false,
            }
        } else {
            Directory::open(parent_path, true)?
        };
        let name = Path::new(&control)
            .file_name()
            .and_then(|name| name.to_str())
            .context("missing control name")?;
        if operation == "refresh" {
            match rustix::fs::mkdirat(&parent.descriptor, name, Mode::from_raw_mode(0o700)) {
                Ok(()) | Err(Errno::EXIST) => {}
                Err(error) => {
                    return Err(error).context("create private freshness control directory");
                }
            }
        }
        let controls = ControlFiles {
            directory: Directory::open(&control, true)?,
            epoch: "epoch-v1".to_owned(),
            require_owner: true,
        };
        controls.sync()?;
        rustix::fs::fsync(&parent.descriptor)?;
        let intent = Intent {
            schema: "rch.source_freshness_attempt.v1".into(),
            source_root: root.path.clone(),
            target_root: pool.into(),
            content_identity: identity.into(),
            attempt: attempt.into(),
        };
        let encoded = canonical(&serde_json::to_value(&intent)?);
        let current = controls.read("current-attempt-v1", MAX_INTENT)?;
        if operation == "refresh" {
            let previous = decode_intent(current.as_ref(), &intent);
            let mut qualified = false;
            if let Some(previous) = previous.filter(|previous| previous.attempt != attempt)
                && let Some(expected) = qualification(&controls, &previous)?
            {
                qualified = controls
                    .read(&format!("verified-{}.json", previous.attempt), MAX_INTENT)?
                    .is_some_and(|proof| proof.data == expected);
            }
            // Durable unqualified intent must precede every source timestamp
            // mutation, including a refresh whose future verifier never runs.
            let pending = controls.stage("current-attempt-v1", &encoded, None)?;
            controls.replace(&pending, "current-attempt-v1")?;
            controls.sync()?;
            observe(Observation::IntentPublished)?;
            refresh(&root, pool, &controls, identity, qualified, observe)
        } else {
            ensure!(
                current.is_some_and(|current| current.data == encoded),
                "verified attempt does not match the current preparation"
            );
            let expected = qualification(&controls, &intent)?
                .context("verified attempt has no matching ledger and epoch")?;
            let name = format!("verified-{attempt}.json");
            let mut existing = controls.read(&name, MAX_INTENT)?;
            if existing.is_none() {
                let pending = controls.stage(&name, &expected, None)?;
                match rustix::fs::linkat(
                    &controls.directory.descriptor,
                    pending.as_str(),
                    &controls.directory.descriptor,
                    name.as_str(),
                    AtFlags::empty(),
                ) {
                    Ok(()) | Err(Errno::EXIST) => {}
                    Err(error) => {
                        return Err(error).context("publish immutable verified source freshness");
                    }
                }
                existing = controls.read(&name, MAX_INTENT)?;
            }
            ensure!(
                existing.is_some_and(|existing| existing.data == expected),
                "verified attempt conflicts with retained evidence"
            );
            let descriptor = rustix::fs::openat(
                &controls.directory.descriptor,
                name.as_str(),
                FILE_FLAGS,
                Mode::empty(),
            )?;
            rustix::fs::fsync(&descriptor)?;
            controls.sync()?;
            root.check()?;
            Ok("RCH_SOURCE_FRESHNESS_VERIFIED\n".into())
        }
    }

    fn run_with_observer(
        arguments: &[String],
        observe: &mut impl FnMut(Observation) -> Result<()>,
    ) -> Result<String> {
        let (mode, args) = arguments
            .split_first()
            .context("missing freshness operation")?;
        let [root, pool, epoch, identity, ..] = args else {
            bail!("invalid freshness arguments");
        };
        ensure!(
            literal_path(root) && literal_path(pool) && literal_path(epoch),
            "nonliteral source, target or control path"
        );
        ensure!(content_identity(identity), "invalid freshness identity");
        match (mode.as_str(), args) {
            ("owned", [root, pool, epoch, identity, attempt, operation]) => {
                owned(root, pool, epoch, identity, attempt, operation, observe)
            }
            ("overlay", [root, pool, epoch, identity]) => {
                let root = Directory::open(root, false)?;
                let path = Path::new(epoch);
                let parent = path
                    .parent()
                    .and_then(Path::to_str)
                    .context("missing epoch parent")?;
                let name = path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .context("missing epoch name")?;
                let controls = ControlFiles {
                    directory: Directory::open_overlay_parent(parent)?,
                    epoch: name.into(),
                    require_owner: false,
                };
                refresh(&root, pool, &controls, identity, true, observe)
            }
            _ => bail!("invalid freshness operation or arguments"),
        }
    }

    pub(super) fn run(arguments: &[String]) -> Result<String> {
        run_with_observer(arguments, &mut |_| Ok(()))
    }

    #[cfg(test)]
    mod compatibility_tests {
        use super::*;
        use std::fs;
        use std::os::unix::fs::PermissionsExt as _;

        fn set_time(path: &Path, nanos: u64) {
            let time = timestamp(nanos).unwrap();
            rustix::fs::utimensat(
                CWD,
                path,
                &Timestamps {
                    last_access: time,
                    last_modification: time,
                },
                AtFlags::SYMLINK_NOFOLLOW,
            )
            .unwrap();
        }

        fn observed_time(path: &Path) -> i128 {
            mtime_ns(&rustix::fs::statat(CWD, path, AtFlags::SYMLINK_NOFOLLOW).unwrap())
        }

        #[test]
        fn legacy_unicode_ledger_preserves_timestamps_for_opaque_binary_contents() {
            const LEGACY_TIME: u64 = 1_700_000_000_123_456_789;
            // Fixed legacy v2 bytes use sorted, ASCII-escaped JSON. Fingerprints
            // and the payload checksum were independently calculated with
            // sha256sum, without using the serializer under test.
            const LEGACY_LEDGER: &[u8] = concat!(
                r#"{"payload":{"entries":{"":{"fingerprint":"c52b8b688d1b5067358b34459db20d51ba629c0c7f9a2dc367ba06250a0f53c9","mtime_ns":1700000000123456789},"#,
                r#""caf\u00e9 \ud83e\udd80.bin":{"fingerprint":"4d23697e0163fb3e22541abbfec93e058bc982a4cc00f7340f9eab1434187d35","mtime_ns":1700000000123456789}},"#,
                r#""epoch_ns":1700000000123456789,"identity":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","schema":2},"#,
                r#""sha256":"d82c6ed4fa98729a0db0e8aa8e04fe5e11532cf9b325e3c5f0cccc15d9d3ab70"}"#,
            )
            .as_bytes();
            let base = tempfile::tempdir().unwrap().keep().canonicalize().unwrap();
            let root = base.join("legacy-source");
            let pool = base.join("target");
            let epoch = base.join("legacy.freshness-epoch-v1");
            let ledger = base.join("legacy.freshness-epoch-v1.files-v2");
            fs::create_dir(&root).unwrap();
            fs::create_dir(&pool).unwrap();
            fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
            let input = root.join("café 🦀.bin");
            fs::write(&input, b"\0\xff'\n").unwrap();
            fs::set_permissions(&input, fs::Permissions::from_mode(0o644)).unwrap();
            fs::write(&epoch, format!("{}\n", "a".repeat(64))).unwrap();
            fs::write(&ledger, LEGACY_LEDGER).unwrap();
            set_time(&epoch, LEGACY_TIME);
            set_time(&input, 41);
            set_time(&root, 37);

            let output = run(&[
                "overlay".to_owned(),
                root.to_str().unwrap().to_owned(),
                pool.to_str().unwrap().to_owned(),
                epoch.to_str().unwrap().to_owned(),
                "b".repeat(64),
            ])
            .unwrap();

            assert_eq!(output, "RCH_SOURCE_FRESHNESS_V2 unchanged=2 changed=0\n");
            assert_eq!(observed_time(&input), i128::from(LEGACY_TIME));
            assert_eq!(observed_time(&root), i128::from(LEGACY_TIME));
            assert_eq!(fs::read(&input).unwrap(), b"\0\xff'\n");
            assert_eq!(
                fs::read_to_string(&epoch).unwrap(),
                format!("{}\n", "b".repeat(64))
            );
        }

        #[test]
        fn oversized_sparse_source_refuses_before_touching_source_or_controls() {
            let base = tempfile::tempdir().unwrap().keep().canonicalize().unwrap();
            let root = base.join("source");
            let epoch = base.join("source.freshness-epoch-v1");
            let ledger = base.join("source.freshness-epoch-v1.files-v2");
            fs::create_dir(&root).unwrap();
            let large = root.join("large");
            File::create(&large)
                .unwrap()
                .set_len(MAX_BYTES + 1)
                .unwrap();
            let sentinel = root.join("sentinel");
            fs::write(&sentinel, b"source remains unchanged").unwrap();
            fs::write(&epoch, format!("{}\n", "a".repeat(64))).unwrap();
            fs::write(&ledger, b"retained incomplete ledger").unwrap();
            set_time(&epoch, 23);
            set_time(&large, 29);
            set_time(&sentinel, 31);
            set_time(&root, 37);

            let error = run(&[
                "overlay".to_owned(),
                root.to_str().unwrap().to_owned(),
                base.join("absent-target").to_str().unwrap().to_owned(),
                epoch.to_str().unwrap().to_owned(),
                "b".repeat(64),
            ])
            .unwrap_err();

            assert!(error.to_string().contains("source byte cap exceeded"));
            assert_eq!(observed_time(&epoch), 23);
            assert_eq!(observed_time(&large), 29);
            assert_eq!(observed_time(&sentinel), 31);
            assert_eq!(observed_time(&root), 37);
            assert_eq!(fs::metadata(&large).unwrap().len(), MAX_BYTES + 1);
            assert_eq!(fs::read(&sentinel).unwrap(), b"source remains unchanged");
            assert_eq!(
                fs::read_to_string(&epoch).unwrap(),
                format!("{}\n", "a".repeat(64))
            );
            assert_eq!(fs::read(&ledger).unwrap(), b"retained incomplete ledger");
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::fs;
        use std::os::unix::fs::symlink;
        #[cfg(target_os = "linux")]
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        use std::path::PathBuf;

        struct Fixture {
            base: PathBuf,
            root: PathBuf,
            pool: PathBuf,
            epoch: PathBuf,
            owned: bool,
        }

        impl Fixture {
            fn new(owned: bool) -> Self {
                let base = tempfile::tempdir().unwrap().keep().canonicalize().unwrap();
                let root = base.join("source é🦀");
                let pool = base.join("target");
                fs::create_dir_all(root.join("src")).unwrap();
                fs::create_dir(&pool).unwrap();
                fs::write(root.join("src/change.rs"), b"const VALUE: u8 = 1;\n").unwrap();
                fs::write(root.join("src/stable.rs"), b"const STABLE: bool = true;\n").unwrap();
                let epoch = if owned {
                    PathBuf::from(format!("{}.freshness/epoch-v1", root.display()))
                } else {
                    base.join("source.freshness-epoch-v1")
                };
                Self {
                    base,
                    root,
                    pool,
                    epoch,
                    owned,
                }
            }

            fn args(&self, identity: char, attempt: char, operation: &str) -> Vec<String> {
                let mut args = vec![
                    if self.owned { "owned" } else { "overlay" }.to_owned(),
                    self.root.to_str().unwrap().to_owned(),
                    self.pool.to_str().unwrap().to_owned(),
                    self.epoch.to_str().unwrap().to_owned(),
                    identity.to_string().repeat(64),
                ];
                if self.owned {
                    args.push(attempt.to_string().repeat(32));
                    args.push(operation.to_owned());
                }
                args
            }

            fn refresh(&self, identity: char, attempt: char) -> String {
                run(&self.args(identity, attempt, "refresh")).unwrap()
            }

            #[cfg(target_os = "linux")]
            fn verify(&self, identity: char, attempt: char) {
                assert_eq!(
                    run(&self.args(identity, attempt, "verify")).unwrap(),
                    "RCH_SOURCE_FRESHNESS_VERIFIED\n"
                );
            }

            fn ledger(&self) -> PathBuf {
                PathBuf::from(format!("{}.files-v2", self.epoch.display()))
            }

            fn change(&self) -> PathBuf {
                self.root.join("src/change.rs")
            }

            fn stable(&self) -> PathBuf {
                self.root.join("src/stable.rs")
            }

            fn cache_artifact(&self) -> u64 {
                let artifact = self.pool.join("cached-artifact.rlib");
                fs::write(&artifact, b"cached output").unwrap();
                // Exercise waiting beyond a genuinely newer cached artifact,
                // without changing the production five-second bound.
                let future = now_ns() + 20_000_000;
                set_mtime(&artifact, future);
                future
            }
        }

        fn now_ns() -> u64 {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
                .try_into()
                .unwrap()
        }

        fn stamp(path: &Path) -> u64 {
            mtime_ns(&rustix::fs::statat(CWD, path, AtFlags::SYMLINK_NOFOLLOW).unwrap())
                .try_into()
                .unwrap()
        }

        fn set_mtime(path: &Path, nanos: u64) {
            let info = rustix::fs::statat(CWD, path, AtFlags::SYMLINK_NOFOLLOW).unwrap();
            rustix::fs::utimensat(
                CWD,
                path,
                &Timestamps {
                    last_access: Timespec {
                        tv_sec: info.st_atime as _,
                        tv_nsec: info.st_atime_nsec as _,
                    },
                    last_modification: timestamp(nanos).unwrap(),
                },
                AtFlags::SYMLINK_NOFOLLOW,
            )
            .unwrap();
            assert_eq!(stamp(path), nanos);
        }

        #[test]
        fn canonical_ascii_matches_existing_escape_and_digest_contract() {
            let bytes = canonical(&json!({
                "z": "é雪🦀",
                "a": "\"\\\u{8}\u{c}\n\r\t\u{1f}\u{7f}",
            }));
            assert_eq!(
                bytes,
                br#"{"a":"\"\\\b\f\n\r\t\u001f\u007f","z":"\u00e9\u96ea\ud83e\udd80"}"#
            );
            // Independently hashed compact bytes, not a second call to the
            // serializer under test.
            assert_eq!(
                digest(&bytes),
                "281b21fcde968902ca23eab412c80d18a2e16de5f0e9ef51dc81568970b63676"
            );
        }

        #[test]
        fn overlay_preserves_unchanged_files_and_invalidates_a_b_a_reversions() {
            let fixture = Fixture::new(false);
            assert_eq!(
                fixture.refresh('a', '1'),
                "RCH_SOURCE_FRESHNESS_V2 unchanged=0 changed=4\n"
            );
            let first = stamp(&fixture.change());
            assert_eq!(stamp(&fixture.stable()), first);

            // A rematerialized source tree has old archive times. Equal
            // content still receives the immediate predecessor's per-file time
            // even if the selected commit/content seal has changed.
            set_mtime(&fixture.change(), 1);
            set_mtime(&fixture.stable(), 2);
            assert_eq!(
                fixture.refresh('b', '2'),
                "RCH_SOURCE_FRESHNESS_V2 unchanged=4 changed=0\n"
            );
            assert_eq!(stamp(&fixture.change()), first);
            assert_eq!(stamp(&fixture.stable()), first);

            let artifact_b = fixture.cache_artifact();
            fs::write(fixture.change(), b"const VALUE: u8 = 2;\n").unwrap();
            set_mtime(&fixture.change(), 1);
            assert_eq!(
                fixture.refresh('c', '3'),
                "RCH_SOURCE_FRESHNESS_V2 unchanged=1 changed=3\n"
            );
            let changed = stamp(&fixture.change());
            assert!(changed > artifact_b);
            assert_eq!(stamp(&fixture.stable()), first);

            let artifact_a = fixture.cache_artifact();
            fs::write(fixture.change(), b"const VALUE: u8 = 1;\n").unwrap();
            set_mtime(&fixture.change(), 1);
            fixture.refresh('a', '4');
            assert!(stamp(&fixture.change()) > artifact_a);
            assert!(stamp(&fixture.change()) > changed);
            assert_eq!(stamp(&fixture.stable()), first);
        }

        #[test]
        fn unicode_names_and_symlink_targets_are_sealed_without_following_links() {
            let fixture = Fixture::new(false);
            let name = "é雪🦀\n\"\\.rs";
            fs::write(fixture.root.join(name), b"unicode source\n").unwrap();
            let outside = fixture.base.join("outside é\n\"🦀");
            fs::write(&outside, b"outside bytes stay untouched").unwrap();
            set_mtime(&outside, 1_000_000_000);
            symlink(&outside, fixture.root.join("link é\n\"")).unwrap();
            fixture.refresh('a', '1');
            let first = stamp(&fixture.root.join(name));
            let bytes = fs::read(fixture.ledger()).unwrap();
            assert!(bytes.iter().all(u8::is_ascii));
            let text = std::str::from_utf8(&bytes).unwrap();
            assert!(text.contains(r"\u96ea\ud83e\udd80\n\"));
            assert_eq!(stamp(&outside), 1_000_000_000);
            assert_eq!(fs::read(&outside).unwrap(), b"outside bytes stay untouched");
            assert_eq!(
                fixture.refresh('b', '2'),
                "RCH_SOURCE_FRESHNESS_V2 unchanged=6 changed=0\n"
            );
            assert_eq!(stamp(&fixture.root.join(name)), first);
            assert_eq!(stamp(&outside), 1_000_000_000);
        }

        #[test]
        fn malformed_ledger_and_mismatched_epoch_force_conservative_freshness() {
            let fixture = Fixture::new(false);
            fixture.refresh('a', '1');
            fs::write(fixture.ledger(), b"{truncated ledger").unwrap();
            let artifact = fixture.cache_artifact();
            assert_eq!(
                fixture.refresh('a', '2'),
                "RCH_SOURCE_FRESHNESS_V2 unchanged=0 changed=4\n"
            );
            assert!(stamp(&fixture.stable()) > artifact);

            fs::write(&fixture.epoch, format!("{}\n", "b".repeat(64))).unwrap();
            let artifact = fixture.cache_artifact();
            assert_eq!(
                fixture.refresh('a', '3'),
                "RCH_SOURCE_FRESHNESS_V2 unchanged=0 changed=4\n"
            );
            assert!(stamp(&fixture.stable()) > artifact);
        }

        #[test]
        fn nonregular_control_is_a_refusal_and_never_a_reusable_cache_miss() {
            let fixture = Fixture::new(false);
            fixture.refresh('a', '1');
            let before = stamp(&fixture.change());
            let ledger = fs::read(fixture.ledger()).unwrap();
            let retained = fixture.base.join("retained-epoch");
            fs::rename(&fixture.epoch, &retained).unwrap();
            symlink(&retained, &fixture.epoch).unwrap();
            assert!(run(&fixture.args('b', '2', "refresh")).is_err());
            assert_eq!(stamp(&fixture.change()), before);
            assert_eq!(fs::read(fixture.ledger()).unwrap(), ledger);
            assert_eq!(
                fs::read(&retained).unwrap(),
                format!("{}\n", "a".repeat(64)).as_bytes()
            );
        }

        #[test]
        fn overlay_parent_alias_is_supported_but_retargeted_control_paths_refuse() {
            let mut fixture = Fixture::new(false);
            let original = fixture.base.join("original-controls");
            let replacement = fixture.base.join("replacement-controls");
            fs::create_dir(&original).unwrap();
            fs::create_dir(&replacement).unwrap();
            let alias = fixture.base.join("control-alias");
            symlink(&original, &alias).unwrap();
            fixture.epoch = alias.join("epoch");
            assert_eq!(
                fixture.refresh('a', '1'),
                "RCH_SOURCE_FRESHNESS_V2 unchanged=0 changed=4\n"
            );
            let epoch = fs::read(original.join("epoch")).unwrap();
            let ledger = fs::read(original.join("epoch.files-v2")).unwrap();
            fs::write(replacement.join("epoch"), b"unowned replacement epoch").unwrap();
            fs::write(
                replacement.join("epoch.files-v2"),
                b"unowned replacement ledger",
            )
            .unwrap();
            fs::write(fixture.change(), b"changed source\n").unwrap();
            let mut retargeted = false;
            let error = run_with_observer(&fixture.args('b', '2', "refresh"), &mut |stage| {
                if stage == Observation::BeforeLedgerCommit && !retargeted {
                    fs::rename(&alias, fixture.base.join("retained-control-alias"))?;
                    symlink(&replacement, &alias)?;
                    retargeted = true;
                }
                Ok(())
            })
            .unwrap_err();
            assert!(retargeted);
            assert!(error.to_string().contains("directory changed"));
            assert_eq!(fs::read(original.join("epoch")).unwrap(), epoch);
            assert_eq!(fs::read(original.join("epoch.files-v2")).unwrap(), ledger);
            assert_eq!(
                fs::read(replacement.join("epoch")).unwrap(),
                b"unowned replacement epoch"
            );
            assert_eq!(
                fs::read(replacement.join("epoch.files-v2")).unwrap(),
                b"unowned replacement ledger"
            );
        }

        #[test]
        fn artifact_inventory_failure_preserves_source_times_and_both_control_files() {
            let fixture = Fixture::new(false);
            fixture.refresh('a', '1');
            let epoch = fs::read(&fixture.epoch).unwrap();
            let epoch_time = stamp(&fixture.epoch);
            let ledger = fs::read(fixture.ledger()).unwrap();
            fs::write(fixture.change(), b"changed before failing pool scan\n").unwrap();
            set_mtime(&fixture.change(), 7);
            let stable = stamp(&fixture.stable());
            let mut observed = false;
            let error = run_with_observer(&fixture.args('b', '2', "refresh"), &mut |stage| {
                if stage == Observation::BeforePoolScan {
                    observed = true;
                    bail!("injected artifact inventory failure");
                }
                Ok(())
            })
            .unwrap_err();
            assert!(observed);
            assert!(error.to_string().contains("artifact inventory failure"));
            assert_eq!(stamp(&fixture.change()), 7);
            assert_eq!(stamp(&fixture.stable()), stable);
            assert_eq!(fs::read(&fixture.epoch).unwrap(), epoch);
            assert_eq!(stamp(&fixture.epoch), epoch_time);
            assert_eq!(fs::read(fixture.ledger()).unwrap(), ledger);
        }

        #[test]
        fn replaced_source_root_cannot_publish_a_ledger_or_touch_the_replacement() {
            let fixture = Fixture::new(false);
            let retained = fixture.base.join("retained-source");
            let mut replaced = false;
            let error = run_with_observer(&fixture.args('a', '1', "refresh"), &mut |stage| {
                if stage == Observation::SourceInventoried && !replaced {
                    fs::rename(&fixture.root, &retained)?;
                    fs::create_dir(&fixture.root)?;
                    fs::write(fixture.root.join("replacement"), b"unowned replacement")?;
                    set_mtime(&fixture.root.join("replacement"), 17);
                    replaced = true;
                }
                Ok(())
            })
            .unwrap_err();
            assert!(replaced);
            assert!(error.to_string().contains("directory changed"));
            assert_eq!(stamp(&fixture.root.join("replacement")), 17);
            assert_eq!(
                fs::read(fixture.root.join("replacement")).unwrap(),
                b"unowned replacement"
            );
            assert!(!fixture.epoch.exists());
            assert!(!fixture.ledger().exists());
        }

        #[test]
        fn future_cached_artifact_refuses_without_advancing_source_or_commit_marker() {
            let fixture = Fixture::new(false);
            fixture.refresh('a', '1');
            let epoch = fs::read(&fixture.epoch).unwrap();
            let epoch_time = stamp(&fixture.epoch);
            let ledger = fs::read(fixture.ledger()).unwrap();
            fs::write(fixture.change(), b"changed\n").unwrap();
            set_mtime(&fixture.change(), 13);
            let stable = stamp(&fixture.stable());
            let artifact = fixture.pool.join("future.rlib");
            fs::write(&artifact, b"future output").unwrap();
            set_mtime(&artifact, now_ns() + 60_000_000_000);
            let started = Instant::now();
            let error = run(&fixture.args('b', '2', "refresh")).unwrap_err();
            assert!(error.to_string().contains("clock cannot advance"));
            assert!(started.elapsed() >= Duration::from_secs(5));
            assert_eq!(stamp(&fixture.change()), 13);
            assert_eq!(stamp(&fixture.stable()), stable);
            assert_eq!(fs::read(&fixture.epoch).unwrap(), epoch);
            assert_eq!(stamp(&fixture.epoch), epoch_time);
            assert_eq!(fs::read(fixture.ledger()).unwrap(), ledger);
        }

        #[cfg(target_os = "linux")]
        #[test]
        fn owned_reuse_requires_the_exact_verified_immediate_predecessor() {
            let fixture = Fixture::new(true);
            fixture.refresh('a', '1');
            let first = stamp(&fixture.stable());
            fixture.verify('a', '1');
            // Verification is idempotent and retains its private staging link.
            fixture.verify('a', '1');
            let proof = fixture
                .epoch
                .parent()
                .unwrap()
                .join(format!("verified-{}.json", "1".repeat(32)));
            assert_eq!(fs::metadata(proof).unwrap().nlink(), 2);
            assert_eq!(
                fixture.refresh('a', '2'),
                "RCH_SOURCE_FRESHNESS_V2 unchanged=4 changed=0\n"
            );
            assert_eq!(stamp(&fixture.stable()), first);

            // Attempt two never verifies. Its own fresh cache output cannot
            // inherit attempt one's now-obsolete proof.
            let artifact = fixture.cache_artifact();
            assert_eq!(
                fixture.refresh('a', '3'),
                "RCH_SOURCE_FRESHNESS_V2 unchanged=0 changed=4\n"
            );
            assert!(stamp(&fixture.stable()) > artifact);
            let wrong = run(&fixture.args('a', '2', "verify")).unwrap_err();
            assert!(wrong.to_string().contains("current preparation"));
            fixture.verify('a', '3');
        }

        #[cfg(target_os = "linux")]
        #[test]
        fn interrupted_owned_intent_is_durable_before_ledger_and_forces_next_refresh() {
            let fixture = Fixture::new(true);
            fixture.refresh('a', '1');
            fixture.verify('a', '1');
            let epoch = fs::read(&fixture.epoch).unwrap();
            let ledger = fs::read(fixture.ledger()).unwrap();
            let before = stamp(&fixture.stable());
            let error = run_with_observer(&fixture.args('a', '2', "refresh"), &mut |stage| {
                if stage == Observation::IntentPublished {
                    bail!("injected stop after durable current intent");
                }
                Ok(())
            })
            .unwrap_err();
            assert!(error.to_string().contains("after durable current intent"));
            assert_eq!(fs::read(&fixture.epoch).unwrap(), epoch);
            assert_eq!(fs::read(fixture.ledger()).unwrap(), ledger);
            assert_eq!(stamp(&fixture.stable()), before);
            let current: Value = serde_json::from_slice(
                &fs::read(fixture.epoch.parent().unwrap().join("current-attempt-v1")).unwrap(),
            )
            .unwrap();
            assert_eq!(current["attempt"], "2".repeat(32));

            let artifact = fixture.cache_artifact();
            assert_eq!(
                fixture.refresh('a', '3'),
                "RCH_SOURCE_FRESHNESS_V2 unchanged=0 changed=4\n"
            );
            assert!(stamp(&fixture.stable()) > artifact);
        }

        #[cfg(target_os = "linux")]
        #[test]
        fn owned_controls_reject_public_directories_conflicting_proof_and_symlink_ancestors() {
            let fixture = Fixture::new(true);
            fixture.refresh('a', '1');
            let control = fixture.epoch.parent().unwrap();
            fs::set_permissions(control, fs::Permissions::from_mode(0o755)).unwrap();
            let error = run(&fixture.args('a', '1', "verify")).unwrap_err();
            assert!(error.to_string().contains("private and owned"));
            fs::set_permissions(control, fs::Permissions::from_mode(0o700)).unwrap();
            let proof = control.join(format!("verified-{}.json", "1".repeat(32)));
            fs::write(&proof, b"retained conflicting evidence").unwrap();
            let error = run(&fixture.args('a', '1', "verify")).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("conflicts with retained evidence")
            );
            assert_eq!(fs::read(&proof).unwrap(), b"retained conflicting evidence");

            let alias = fixture.base.join("alias");
            symlink(&fixture.base, &alias).unwrap();
            let mut args = fixture.args('a', '2', "refresh");
            args[1] = alias
                .join(fixture.root.file_name().unwrap())
                .to_str()
                .unwrap()
                .to_owned();
            args[3] = format!("{}.freshness/epoch-v1", args[1]);
            assert!(run(&args).is_err());
        }
    }
}
