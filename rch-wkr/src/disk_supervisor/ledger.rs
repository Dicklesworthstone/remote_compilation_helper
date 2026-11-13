//! Shared worker disk reservations and conservative process observations.
//!
//! The version-one ledger is shared with previously deployed workers. A live
//! process group keeps its entire reservation, even if its original leader
//! disappeared or its numeric PID was reused. Only a complete census or a
//! different verified boot can retire a record; age never grants authority.

use super::{Failure, Result};
use rustix::fd::OwnedFd;
use rustix::fs::{AtFlags, FileType, FlockOperation, Mode, OFlags, Stat};
use rustix::io::Errno;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{self, Read as _, Write as _};
#[cfg(target_os = "linux")]
use std::path::Path;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

const MAX_LEDGER_BYTES: usize = 2 * 1024 * 1024;
const MAX_RESERVATIONS: usize = 4096;
#[cfg(target_os = "linux")]
const MAX_PROCESS_RECORD_BYTES: u64 = 8192;
const FILE_FLAGS: OFlags = OFlags::NOFOLLOW
    .union(OFlags::NONBLOCK)
    .union(OFlags::CLOEXEC)
    .union(OFlags::NOCTTY);
static NEXT_TEMPORARY: AtomicU64 = AtomicU64::new(0);

pub(super) type Samples = BTreeMap<u64, u64>;
pub(super) type Sample = (Samples, Instant);
pub(super) type Snapshot = BTreeMap<u32, ProcessRecord>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ProcessRecord {
    pub pid: u32,
    pub parent: u32,
    pub group: u32,
    pub state: char,
    pub start: Option<String>,
}

impl ProcessRecord {
    pub(super) fn is_alive(&self) -> bool {
        !matches!(self.state, 'Z' | 'X' | 'x')
    }
}

#[derive(Clone, Debug)]
pub(super) struct Reservation {
    pub boot: String,
    pub group: u32,
    pub leader_start: String,
    pub devices: BTreeSet<u64>,
    pub budget: u64,
    pub floor: u64,
}

pub(super) struct Admission {
    pub free: Samples,
    pub floors: Samples,
    pub sampled_at: Instant,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct Entry {
    boot: String,
    group: u64,
    leader_start: String,
    devices: Vec<u64>,
    budget: u64,
    floor: u64,
    // Older readers retain entry fields they do not interpret. Preserve that
    // property when compacting the same shared ledger under its original lock.
    #[serde(flatten)]
    extra: BTreeMap<String, serde_json::Value>,
}

impl Entry {
    fn validate(&self) -> Result<()> {
        if !canonical_boot(&self.boot)
            || !(2..=i64::MAX as u64).contains(&self.group)
            || !(1..=i64::MAX as u64).contains(&self.budget)
            || self.floor > i64::MAX as u64
            || self.leader_start.is_empty()
            || self.devices.is_empty()
        {
            return Err(Failure::unavailable("invalid worker disk reservation"));
        }
        Ok(())
    }

    fn alive(&self, boot: &str, groups: &BTreeSet<u64>) -> bool {
        self.boot == boot && groups.contains(&self.group)
    }
}

impl From<&Reservation> for Entry {
    fn from(reservation: &Reservation) -> Self {
        Self {
            boot: reservation.boot.clone(),
            group: u64::from(reservation.group),
            leader_start: reservation.leader_start.clone(),
            devices: reservation.devices.iter().copied().collect(),
            budget: reservation.budget,
            floor: reservation.floor,
            extra: BTreeMap::new(),
        }
    }
}

#[derive(Deserialize, Serialize)]
struct Ledger {
    version: u64,
    entries: Vec<Entry>,
}

fn canonical_boot(boot: &str) -> bool {
    boot.len() == 36
        && boot.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
            }
        })
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

fn private_regular(info: &Stat) -> Result<()> {
    if FileType::from_raw_mode(info.st_mode) != FileType::RegularFile
        || info.st_uid != rustix::process::getuid().as_raw()
        || info.st_mode & 0o077 != 0
        || info.st_nlink != 1
    {
        return Err(Failure::unavailable("unsafe worker accounting file"));
    }
    Ok(())
}

fn private_directory(info: &Stat) -> Result<()> {
    if FileType::from_raw_mode(info.st_mode) != FileType::Directory
        || info.st_uid != rustix::process::getuid().as_raw()
        || info.st_mode & 0o077 != 0
    {
        return Err(Failure::unavailable("unsafe worker accounting directory"));
    }
    Ok(())
}

struct Lock {
    descriptor: OwnedFd,
    identity: Stat,
}

pub(super) struct Registry {
    root: PathBuf,
    descriptor: OwnedFd,
    identity: Stat,
    lock_timeout: Duration,
}

impl Registry {
    pub(super) fn open(lock_timeout: Duration) -> Result<Self> {
        Self::at(
            PathBuf::from(format!(
                "/var/tmp/rch-build-disk-{}",
                rustix::process::getuid().as_raw()
            )),
            lock_timeout,
        )
    }

    fn at(root: PathBuf, lock_timeout: Duration) -> Result<Self> {
        use std::os::unix::fs::DirBuilderExt as _;
        match std::fs::DirBuilder::new().mode(0o700).create(&root) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
        let named = rustix::fs::statat(rustix::fs::CWD, &root, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(io::Error::from)?;
        private_directory(&named)?;
        let descriptor = rustix::fs::open(
            &root,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(io::Error::from)?;
        let identity = rustix::fs::fstat(&descriptor).map_err(io::Error::from)?;
        private_directory(&identity)?;
        if !same_inode(&named, &identity) {
            return Err(Failure::unavailable("worker accounting directory changed"));
        }
        let registry = Self {
            root,
            descriptor,
            identity,
            lock_timeout,
        };
        registry.check()?;
        Ok(registry)
    }

    fn check(&self) -> Result<()> {
        let named = rustix::fs::statat(rustix::fs::CWD, &self.root, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(io::Error::from)?;
        let opened = rustix::fs::fstat(&self.descriptor).map_err(io::Error::from)?;
        private_directory(&named)?;
        private_directory(&opened)?;
        if !same_inode(&named, &self.identity) || !same_inode(&opened, &self.identity) {
            return Err(Failure::unavailable("worker accounting directory changed"));
        }
        Ok(())
    }

    fn named(&self, name: &str) -> Result<Option<Stat>> {
        match rustix::fs::statat(&self.descriptor, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(info) => Ok(Some(info)),
            Err(Errno::NOENT) => Ok(None),
            Err(error) => Err(io::Error::from(error).into()),
        }
    }

    fn check_lock(&self, lock: &Lock) -> Result<()> {
        self.check()?;
        let named = self
            .named("lock")?
            .ok_or_else(|| Failure::unavailable("worker reservation lock disappeared"))?;
        let opened = rustix::fs::fstat(&lock.descriptor).map_err(io::Error::from)?;
        private_regular(&named)?;
        private_regular(&opened)?;
        if !same_inode(&named, &lock.identity) || !same_inode(&opened, &lock.identity) {
            return Err(Failure::unavailable("worker reservation lock changed"));
        }
        Ok(())
    }

    fn locked(&self, heartbeat: &mut impl FnMut() -> Result<()>) -> Result<Lock> {
        let deadline = Instant::now()
            .checked_add(self.lock_timeout)
            .ok_or_else(|| Failure::unavailable("worker reservation lock deadline overflow"))?;
        self.check()?;
        let descriptor = rustix::fs::openat(
            &self.descriptor,
            "lock",
            FILE_FLAGS | OFlags::RDWR | OFlags::CREATE,
            Mode::from_raw_mode(0o600),
        )
        .map_err(io::Error::from)?;
        let identity = rustix::fs::fstat(&descriptor).map_err(io::Error::from)?;
        private_regular(&identity)?;
        let lock = Lock {
            descriptor,
            identity,
        };
        loop {
            heartbeat()?;
            self.check_lock(&lock)?;
            if Instant::now() >= deadline {
                return Err(Failure::unavailable("worker reservation lock deadline"));
            }
            match rustix::fs::flock(&lock.descriptor, FlockOperation::NonBlockingLockExclusive) {
                Ok(()) => break,
                Err(Errno::AGAIN | Errno::ACCESS | Errno::INTR) => {}
                Err(error) => return Err(io::Error::from(error).into()),
            }
            std::thread::sleep(
                deadline
                    .saturating_duration_since(Instant::now())
                    .min(Duration::from_millis(25)),
            );
        }
        self.check_lock(&lock)?;
        if Instant::now() >= deadline {
            return Err(Failure::unavailable("worker reservation lock deadline"));
        }
        Ok(lock)
    }

    fn read(&self) -> Result<(Vec<Entry>, Option<Stat>)> {
        self.check()?;
        let Some(named) = self.named("ledger.json")? else {
            return Ok((Vec::new(), None));
        };
        private_regular(&named)?;
        let file = File::from(
            rustix::fs::openat(
                &self.descriptor,
                "ledger.json",
                FILE_FLAGS | OFlags::RDONLY,
                Mode::empty(),
            )
            .map_err(io::Error::from)?,
        );
        let before = rustix::fs::fstat(&file).map_err(io::Error::from)?;
        private_regular(&before)?;
        if !same_snapshot(&named, &before) {
            return Err(Failure::unavailable(
                "worker disk ledger changed while opening",
            ));
        }
        let mut bytes = Vec::new();
        (&file)
            .take(MAX_LEDGER_BYTES as u64 + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() > MAX_LEDGER_BYTES {
            return Err(Failure::unavailable(
                "worker disk ledger exceeded size limit",
            ));
        }
        let after = rustix::fs::fstat(&file).map_err(io::Error::from)?;
        if !same_snapshot(&before, &after) {
            return Err(Failure::unavailable(
                "worker disk ledger changed during read",
            ));
        }
        self.check_ledger(Some(&before))?;
        let ledger: Ledger = serde_json::from_slice(&bytes)
            .map_err(|_| Failure::unavailable("invalid worker disk ledger"))?;
        if ledger.version != 1 {
            return Err(Failure::unavailable("unrecognized worker disk ledger"));
        }
        if ledger.entries.len() > MAX_RESERVATIONS {
            return Err(Failure::unavailable("invalid worker disk ledger"));
        }
        for entry in &ledger.entries {
            entry.validate()?;
        }
        Ok((ledger.entries, Some(before)))
    }

    fn check_ledger(&self, expected: Option<&Stat>) -> Result<()> {
        self.check()?;
        let named = self.named("ledger.json")?;
        if let Some(named) = &named {
            private_regular(named)?;
        }
        let same = match (expected, named.as_ref()) {
            (None, None) => true,
            (Some(expected), Some(named)) => same_snapshot(expected, named),
            _ => false,
        };
        if !same {
            return Err(Failure::unavailable(
                "worker disk ledger changed before publication",
            ));
        }
        Ok(())
    }

    fn publish(&self, records: Vec<Entry>, previous: Option<&Stat>, lock: &Lock) -> Result<()> {
        let bytes = serde_json::to_vec(&Ledger {
            version: 1,
            entries: records,
        })
        .map_err(|_| Failure::unavailable("cannot encode worker disk ledger"))?;
        if bytes.len() > MAX_LEDGER_BYTES {
            return Err(Failure::unavailable(
                "worker disk ledger exceeded size limit",
            ));
        }
        self.check_lock(lock)?;
        self.check_ledger(previous)?;
        let mut temporary = None;
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| Failure::unavailable("worker disk ledger staging clock unavailable"))?
            .as_nanos();
        for _ in 0..128 {
            let sequence = NEXT_TEMPORARY.fetch_add(1, Ordering::Relaxed);
            let name = format!(".disk-{}-{stamp}-{sequence}", std::process::id());
            match rustix::fs::openat(
                &self.descriptor,
                name.as_str(),
                FILE_FLAGS | OFlags::RDWR | OFlags::CREATE | OFlags::EXCL,
                Mode::from_raw_mode(0o600),
            ) {
                Ok(descriptor) => {
                    temporary = Some((name, File::from(descriptor)));
                    break;
                }
                Err(Errno::EXIST) => {}
                Err(error) => return Err(io::Error::from(error).into()),
            }
        }
        let (name, mut file) = temporary
            .ok_or_else(|| Failure::unavailable("cannot reserve worker disk ledger staging"))?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        let staged = rustix::fs::fstat(&file).map_err(io::Error::from)?;
        private_regular(&staged)?;
        self.check_lock(lock)?;
        self.check_ledger(previous)?;
        if !self
            .named(&name)?
            .is_some_and(|named| same_snapshot(&named, &staged))
        {
            return Err(Failure::unavailable("worker disk ledger staging changed"));
        }
        rustix::fs::renameat(
            &self.descriptor,
            name.as_str(),
            &self.descriptor,
            "ledger.json",
        )
        .map_err(io::Error::from)?;
        let published = rustix::fs::fstat(&file).map_err(io::Error::from)?;
        rustix::fs::fsync(&self.descriptor).map_err(io::Error::from)?;
        self.check_lock(lock)?;
        self.check_ledger(Some(&published))?;
        Ok(())
    }

    pub(super) fn admit(
        &self,
        reservation: &Reservation,
        mut sample: impl FnMut() -> Result<Sample>,
        mut heartbeat: impl FnMut() -> Result<()>,
    ) -> Result<Admission> {
        self.admit_with(reservation, &mut sample, &mut heartbeat, process_snapshot)
    }

    fn admit_with<H: FnMut() -> Result<()>>(
        &self,
        reservation: &Reservation,
        sample: &mut impl FnMut() -> Result<Sample>,
        heartbeat: &mut H,
        mut census: impl FnMut(&mut H) -> Result<Snapshot>,
    ) -> Result<Admission> {
        let entry = Entry::from(reservation);
        entry.validate()?;
        let lock = self.locked(heartbeat)?;
        let (mut records, previous) = self.read()?;
        let (mut free, mut sampled_at) = sample()?;
        verify_devices(&free, &reservation.devices)?;
        if records.len() >= MAX_RESERVATIONS || !fits(&records, reservation, &free) {
            let groups = census(heartbeat)?
                .values()
                .filter(|record| record.is_alive())
                .map(|record| u64::from(record.group))
                .collect();
            records.retain(|entry| entry.alive(&reservation.boot, &groups));
            (free, sampled_at) = sample()?;
            verify_devices(&free, &reservation.devices)?;
        }
        if records.len() >= MAX_RESERVATIONS {
            return Err(Failure::unavailable("worker disk ledger reservation limit"));
        }
        let mut floors = Samples::new();
        for (&device, &available) in &free {
            let (floor, required) = required_on_device(&records, reservation, device);
            if u128::from(available) < required {
                return Err(Failure::new(
                    "admission",
                    available,
                    0,
                    "free space cannot cover active build reservations and protected floor",
                ));
            }
            floors.insert(device, floor);
        }
        records.push(entry);
        heartbeat()?;
        self.publish(records, previous.as_ref(), &lock)?;
        Ok(Admission {
            free,
            floors,
            sampled_at,
        })
    }
}

fn verify_devices(samples: &Samples, devices: &BTreeSet<u64>) -> Result<()> {
    if samples.keys().copied().collect::<BTreeSet<_>>() != *devices {
        return Err(Failure::unavailable("filesystem changed before admission"));
    }
    Ok(())
}

fn required_on_device(records: &[Entry], reservation: &Reservation, device: u64) -> (u64, u128) {
    let mut floor = reservation.floor;
    let mut budgets = u128::from(reservation.budget);
    for entry in records
        .iter()
        .filter(|entry| entry.devices.contains(&device))
    {
        floor = floor.max(entry.floor);
        budgets += u128::from(entry.budget);
    }
    (floor, u128::from(floor) + budgets)
}

fn fits(records: &[Entry], reservation: &Reservation, free: &Samples) -> bool {
    free.iter().all(|(&device, &available)| {
        u128::from(available) >= required_on_device(records, reservation, device).1
    })
}

pub(super) fn boot_identity() -> Result<String> {
    rch_common::process_identity::current_process_identity()
        .filter(|identity| identity.is_valid() && canonical_boot(&identity.boot_id))
        .map(|identity| identity.boot_id)
        .ok_or_else(|| Failure::unavailable("unverified worker process namespace or boot identity"))
}

#[cfg(any(target_os = "linux", test))]
fn parse_linux_process(data: &str, expected_pid: u32) -> Result<ProcessRecord> {
    let invalid = || Failure::unavailable("incomplete kernel process record");
    let (prefix, tail) = data.rsplit_once(") ").ok_or_else(invalid)?;
    let (pid, _) = prefix.split_once(" (").ok_or_else(invalid)?;
    if pid.parse::<u32>().ok() != Some(expected_pid) || expected_pid == 0 {
        return Err(invalid());
    }
    let fields: Vec<_> = tail.split_whitespace().collect();
    if fields.len() < 20 {
        return Err(invalid());
    }
    let state = match fields[0] {
        "R" | "S" | "D" | "T" | "t" | "K" | "W" | "P" | "I" | "Z" | "X" | "x" => {
            fields[0].as_bytes()[0] as char
        }
        _ => return Err(invalid()),
    };
    let parent = fields[1].parse::<u32>().map_err(|_| invalid())?;
    let group = fields[2].parse::<u32>().map_err(|_| invalid())?;
    let start = fields[19].parse::<u64>().map_err(|_| invalid())?;
    Ok(ProcessRecord {
        pid: expected_pid,
        parent,
        group,
        state,
        start: Some(start.to_string()),
    })
}

#[cfg(target_os = "linux")]
fn process_disappeared(error: &Failure) -> bool {
    // The shared failure type deliberately preserves its source-independent
    // reason. Handle disappearing procfs records before converting io errors.
    error.reason == "process_absent"
}

#[cfg(target_os = "linux")]
fn read_process(path: &Path, pid: u32) -> Result<ProcessRecord> {
    // Opening a retained /proc descriptor may return ESRCH from read after
    // exit, not only ENOENT from open. Both are normal census churn.
    match File::open(path) {
        Ok(file) => read_process_record(file, pid),
        Err(error) if disappeared_io(&error) => {
            Err(Failure::new("process_absent", 0, 0, "process exited"))
        }
        Err(error) => Err(error.into()),
    }
}

#[cfg(target_os = "linux")]
fn read_process_record(reader: impl io::Read, pid: u32) -> Result<ProcessRecord> {
    let mut bytes = Vec::new();
    match reader
        .take(MAX_PROCESS_RECORD_BYTES + 1)
        .read_to_end(&mut bytes)
    {
        Ok(_) => {}
        Err(error) if disappeared_io(&error) => {
            return Err(Failure::new("process_absent", 0, 0, "process exited"));
        }
        Err(error) => return Err(error.into()),
    }
    if bytes.len() as u64 > MAX_PROCESS_RECORD_BYTES {
        return Err(Failure::unavailable("oversized kernel process record"));
    }
    parse_linux_process(
        std::str::from_utf8(&bytes)
            .map_err(|_| Failure::unavailable("invalid kernel process record"))?,
        pid,
    )
}

#[cfg(target_os = "linux")]
fn disappeared_io(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::NotFound
        || error.raw_os_error() == Some(Errno::SRCH.raw_os_error())
}

#[cfg(target_os = "linux")]
pub(super) fn process_snapshot(heartbeat: &mut impl FnMut() -> Result<()>) -> Result<Snapshot> {
    boot_identity()?;
    let mut result = Snapshot::new();
    for entry in std::fs::read_dir("/proc")? {
        heartbeat()?;
        let entry = entry?;
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        let record = match read_process(&entry.path().join("stat"), pid) {
            Ok(record) => record,
            Err(error) if process_disappeared(&error) => continue,
            Err(error) => return Err(error),
        };
        let zombie = !record.is_alive();
        result.insert(record.pid, record);
        if zombie {
            // The main thread can be a zombie while sibling threads still
            // write. Never infer group death from the leader's state alone.
            let tasks = match std::fs::read_dir(entry.path().join("task")) {
                Ok(tasks) => tasks,
                Err(error) if disappeared_io(&error) => continue,
                Err(error) => return Err(error.into()),
            };
            for task in tasks {
                heartbeat()?;
                let task = task?;
                let Some(tid) = task
                    .file_name()
                    .to_str()
                    .and_then(|name| name.parse::<u32>().ok())
                else {
                    return Err(Failure::unavailable("invalid kernel task census"));
                };
                match read_process(&task.path().join("stat"), tid) {
                    Ok(thread) => {
                        result.insert(thread.pid, thread);
                    }
                    Err(error) if process_disappeared(&error) => {}
                    Err(error) => return Err(error),
                }
            }
        }
    }
    if !result.contains_key(&std::process::id()) {
        return Err(Failure::unavailable("process census omitted supervisor"));
    }
    Ok(result)
}

#[cfg(target_os = "macos")]
pub(super) fn process_snapshot(heartbeat: &mut impl FnMut() -> Result<()>) -> Result<Snapshot> {
    use std::process::{Command, Stdio};
    const MAX_CENSUS_BYTES: usize = 16 * 1024 * 1024;
    boot_identity()?;
    let deadline = Instant::now() + rch_common::timing::scale_duration(Duration::from_secs(1));
    let mut child = Command::new("/bin/ps")
        .args(["-axo", "pid=,ppid=,pgid=,stat="])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let result = (|| {
        let mut pipe = child
            .stdout
            .take()
            .ok_or_else(|| Failure::unavailable("process census pipe unavailable"))?;
        let flags = rustix::fs::fcntl_getfl(&pipe).map_err(io::Error::from)?;
        rustix::fs::fcntl_setfl(&pipe, flags | OFlags::NONBLOCK).map_err(io::Error::from)?;
        let mut bytes = Vec::new();
        let mut eof = false;
        let mut status = None;
        while !eof || status.is_none() {
            heartbeat()?;
            if Instant::now() >= deadline {
                return Err(Failure::unavailable("process census deadline"));
            }
            let mut block = [0; 8192];
            match pipe.read(&mut block) {
                Ok(0) => eof = true,
                Ok(count) => {
                    if bytes.len() + count > MAX_CENSUS_BYTES {
                        return Err(Failure::unavailable("process census exceeded size limit"));
                    }
                    bytes.extend_from_slice(&block[..count]);
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) => {}
                Err(error) => return Err(error.into()),
            }
            if status.is_none() {
                status = child.try_wait()?;
            }
            if !eof || status.is_none() {
                std::thread::sleep(Duration::from_millis(5));
            }
        }
        if !status.is_some_and(|status| status.success()) {
            return Err(Failure::unavailable("process census failed"));
        }
        let output = std::str::from_utf8(&bytes)
            .map_err(|_| Failure::unavailable("invalid process census"))?;
        let mut result = Snapshot::new();
        for line in output.lines() {
            heartbeat()?;
            let fields: Vec<_> = line.split_whitespace().collect();
            if fields.len() != 4 {
                return Err(Failure::unavailable("invalid process census"));
            }
            let number = |index: usize| {
                fields[index]
                    .parse::<u32>()
                    .map_err(|_| Failure::unavailable("invalid process census"))
            };
            let pid = number(0)?;
            let parent = number(1)?;
            let group = number(2)?;
            let state = fields[3]
                .chars()
                .next()
                .filter(|state| "RSDTIUZE".contains(*state))
                .ok_or_else(|| Failure::unavailable("invalid process census"))?;
            if pid == 0 || result.contains_key(&pid) {
                return Err(Failure::unavailable("invalid process census"));
            }
            // This exact probe has already exited and been reaped. Its own
            // ps entry cannot count as an outstanding workload descendant.
            if pid != child.id() {
                result.insert(
                    pid,
                    ProcessRecord {
                        pid,
                        parent,
                        group,
                        state,
                        start: None,
                    },
                );
            }
        }
        if !result.contains_key(&std::process::id()) {
            return Err(Failure::unavailable("process census omitted supervisor"));
        }
        Ok(result)
    })();
    if result.is_err() {
        let _ = child.kill();
        // try_wait never blocks a stalled kernel read. The owning guardian
        // still settles this group when observation fails.
        let _ = child.try_wait();
    }
    result
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(super) fn process_snapshot(_heartbeat: &mut impl FnMut() -> Result<()>) -> Result<Snapshot> {
    Err(Failure::unavailable("process census is unavailable"))
}

pub(super) fn leader_start(group: u32, snapshot: &Snapshot, boot: &str) -> Result<String> {
    let record = snapshot
        .get(&group)
        .filter(|record| record.is_alive() && record.group == group)
        .ok_or_else(|| Failure::new("interrupted", 0, 0, "build group leader disappeared"))?;
    #[cfg(target_os = "linux")]
    {
        let _ = boot;
        record
            .start
            .clone()
            .ok_or_else(|| Failure::unavailable("missing build group birth"))
    }
    #[cfg(target_os = "macos")]
    {
        let _ = record;
        darwin_leader_start(group, boot)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (record, boot);
        Err(Failure::unavailable("unsupported worker process platform"))
    }
}

#[cfg(target_os = "macos")]
fn darwin_leader_start(group: u32, boot: &str) -> Result<String> {
    let witness = rch_common::process_identity::remote_process_witness(group)
        .ok_or_else(|| Failure::unavailable("unverified Darwin group identity"))?;
    let fields: Vec<_> = witness.split_whitespace().collect();
    if fields.len() != 3 || fields[0] != boot || fields[2].parse::<u32>().ok() != Some(group) {
        return Err(Failure::unavailable("unverified Darwin group identity"));
    }
    Ok(fields[1].to_owned())
}

pub(super) fn check_owner(group: u32, boot: &str, start: &str, parent: u32) -> Result<()> {
    if rustix::process::getppid().map(|pid| pid.as_raw_nonzero().get() as u32) != Some(parent) {
        return Err(Failure::new(
            "interrupted",
            0,
            0,
            "disk guardian disappeared",
        ));
    }
    #[cfg(target_os = "linux")]
    let observed = {
        let _ = boot;
        let path = PathBuf::from(format!("/proc/{group}/stat"));
        let record = match read_process(&path, group) {
            Ok(record) => record,
            Err(error) if process_disappeared(&error) => {
                return Err(Failure::new(
                    "interrupted",
                    0,
                    0,
                    "build group leader disappeared",
                ));
            }
            Err(error) => return Err(error),
        };
        leader_start(group, &BTreeMap::from([(group, record)]), boot)?
    };
    #[cfg(target_os = "macos")]
    let observed = darwin_leader_start(group, boot)?;
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let observed = leader_start(group, &process_snapshot(&mut || Ok(()))?, boot)?;
    if observed != start {
        return Err(Failure::new(
            "interrupted",
            0,
            0,
            "build group leader changed",
        ));
    }
    Ok(())
}

pub(super) fn kill_descendant(record: &ProcessRecord, group: u32) -> Result<()> {
    if group <= 1 || rustix::process::getpgrp().as_raw_nonzero().get() as u32 != group {
        return Err(Failure::unavailable("lost own build process group"));
    }
    #[cfg(target_os = "linux")]
    {
        use rustix::process::{Pid, PidfdFlags, Signal};
        let pid = i32::try_from(record.pid)
            .ok()
            .filter(|pid| *pid > 1)
            .and_then(Pid::from_raw)
            .ok_or_else(|| Failure::unavailable("invalid background writer identity"))?;
        let descriptor = match rustix::process::pidfd_open(pid, PidfdFlags::empty()) {
            Ok(descriptor) => descriptor,
            Err(Errno::SRCH) => return Ok(()),
            Err(error) => return Err(io::Error::from(error).into()),
        };
        let current = match read_process(
            &PathBuf::from(format!("/proc/{}/stat", record.pid)),
            record.pid,
        ) {
            Ok(current) => current,
            Err(error) if process_disappeared(&error) => return Ok(()),
            Err(error) => return Err(error),
        };
        if current.group != group || current.start != record.start || !current.is_alive() {
            return Ok(());
        }
        match rustix::process::pidfd_send_signal(&descriptor, Signal::KILL) {
            Ok(()) | Err(Errno::SRCH) => Ok(()),
            Err(error) => Err(io::Error::from(error).into()),
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = record;
        Err(Failure::unavailable(
            "background writer cleanup requires whole-group cancellation",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    const BOOT: &str = "01234567-89ab-cdef-0123-456789abcdef";
    const OTHER_BOOT: &str = "fedcba98-7654-3210-fedc-ba9876543210";
    const GIB: u64 = 1 << 30;

    struct Fixture {
        root: PathBuf,
        registry: Registry,
    }

    impl Fixture {
        fn new() -> Self {
            let root = tempfile::Builder::new()
                .prefix("rch-native-disk-ledger-")
                .tempdir()
                .unwrap()
                .keep();
            let registry = Registry::at(root.join("registry"), Duration::from_millis(100)).unwrap();
            Self { root, registry }
        }

        fn write_entries(&self, entries: Vec<Entry>) -> Vec<u8> {
            let bytes = serde_json::to_vec(&Ledger {
                version: 1,
                entries,
            })
            .unwrap();
            self.write_bytes(&bytes);
            bytes
        }

        fn write_bytes(&self, bytes: &[u8]) {
            let path = self.registry.root.join("ledger.json");
            fs::write(&path, bytes).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }

        fn bytes(&self) -> Vec<u8> {
            fs::read(self.registry.root.join("ledger.json")).unwrap()
        }
    }

    fn request(budget: u64, floor: u64, devices: &[u64]) -> Reservation {
        Reservation {
            boot: BOOT.into(),
            group: 500,
            leader_start: "new-owner".into(),
            devices: devices.iter().copied().collect(),
            budget,
            floor,
        }
    }

    fn record(group: u32, state: char) -> ProcessRecord {
        ProcessRecord {
            pid: group,
            parent: 1,
            group,
            state,
            start: Some("different-leader-birth".into()),
        }
    }

    fn census(groups: &[u32]) -> Snapshot {
        groups
            .iter()
            .map(|group| (*group, record(*group, 'S')))
            .collect()
    }

    #[test]
    fn capacity_covers_all_records_without_census_or_unproved_retirement() {
        let fixture = Fixture::new();
        let mut previous = Entry::from(&request(7 * GIB, 10 * GIB, &[1]));
        previous.boot = OTHER_BOOT.into();
        previous
            .extra
            .insert("retained_evidence".into(), serde_json::json!("keep"));
        fixture.write_entries(vec![previous]);
        let sampled_at = Instant::now();
        let admission = fixture
            .registry
            .admit_with(
                &request(4 * GIB, 2 * GIB, &[1]),
                &mut || Ok((BTreeMap::from([(1, 21 * GIB)]), sampled_at)),
                &mut || Ok(()),
                |_| panic!("ample capacity must not census the host"),
            )
            .unwrap();
        assert_eq!(admission.free, BTreeMap::from([(1, 21 * GIB)]));
        assert_eq!(admission.floors, BTreeMap::from([(1, 10 * GIB)]));
        assert_eq!(
            admission.sampled_at, sampled_at,
            "publication must not invent a fresh sample"
        );
        let (entries, _) = fixture.registry.read().unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].boot, OTHER_BOOT);
        assert_eq!(entries[0].extra["retained_evidence"], "keep");
        assert_eq!(entries[1].floor, 2 * GIB);
    }

    #[test]
    fn each_output_volume_reserves_all_budgets_and_the_largest_protected_floor() {
        let fixture = Fixture::new();
        let other = Entry::from(&request(5 * GIB, 11 * GIB, &[2]));
        fixture.write_entries(vec![other]);
        let admission = fixture
            .registry
            .admit_with(
                &request(3 * GIB, 2 * GIB, &[1, 2]),
                &mut || {
                    Ok((
                        BTreeMap::from([(1, 5 * GIB), (2, 19 * GIB)]),
                        Instant::now(),
                    ))
                },
                &mut || Ok(()),
                |_| panic!("exactly sufficient headroom must admit without reclaim"),
            )
            .unwrap();
        assert_eq!(
            admission.floors,
            BTreeMap::from([(1, 2 * GIB), (2, 11 * GIB)])
        );
        let (entries, _) = fixture.registry.read().unwrap();
        assert_eq!(entries.last().unwrap().devices, vec![1, 2]);
    }

    #[test]
    fn cold_budget_is_never_replaced_with_a_flat_slot_allowance() {
        let fixture = Fixture::new();
        let failure = fixture
            .registry
            .admit_with(
                &request(30 * GIB, 10 * GIB, &[1]),
                &mut || Ok((BTreeMap::from([(1, 33 * GIB)]), Instant::now())),
                &mut || Ok(()),
                |_| Ok(Snapshot::new()),
            )
            .err()
            .unwrap();
        assert_eq!(failure.reason, "admission");
        assert_eq!(failure.free, 33 * GIB);
        assert!(!fixture.registry.root.join("ledger.json").exists());
        let admission = fixture
            .registry
            .admit_with(
                &request(4 * GIB, 10 * GIB, &[1]),
                &mut || Ok((BTreeMap::from([(1, 33 * GIB)]), Instant::now())),
                &mut || Ok(()),
                |_| panic!("smaller independently selected budget already fits"),
            )
            .unwrap();
        assert_eq!(admission.floors[&1], 10 * GIB);
    }

    #[test]
    fn reclaim_requires_complete_census_and_resamples_before_admission() {
        let fixture = Fixture::new();
        let mut old_boot = Entry::from(&request(7 * GIB, 10 * GIB, &[1]));
        old_boot.boot = OTHER_BOOT.into();
        let mut dead = Entry::from(&request(7 * GIB, 10 * GIB, &[1]));
        dead.group = 600;
        fixture.write_entries(vec![old_boot, dead]);
        let first = Instant::now();
        let second = first + Duration::from_millis(1);
        let mut samples = [
            (BTreeMap::from([(1, 5 * GIB)]), first),
            (BTreeMap::from([(1, 6 * GIB)]), second),
        ]
        .into_iter();
        let mut censuses = 0;
        let admission = fixture
            .registry
            .admit_with(
                &request(4 * GIB, 2 * GIB, &[1]),
                &mut || Ok(samples.next().unwrap()),
                &mut || Ok(()),
                |_| {
                    censuses += 1;
                    Ok(census(&[500]))
                },
            )
            .unwrap();
        assert_eq!(censuses, 1);
        assert_eq!(admission.free[&1], 6 * GIB);
        assert_eq!(admission.sampled_at, second);
        let (entries, _) = fixture.registry.read().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].leader_start, "new-owner");
    }

    #[test]
    fn live_members_keep_old_reservation_despite_replaced_or_zombie_leader() {
        for leader_state in ['S', 'Z'] {
            let fixture = Fixture::new();
            let mut old = Entry::from(&request(7 * GIB, 10 * GIB, &[1]));
            old.leader_start = "old-owner".into();
            let before = fixture.write_entries(vec![old]);
            let mut snapshot = BTreeMap::from([(500, record(500, leader_state))]);
            snapshot.insert(
                501,
                ProcessRecord {
                    pid: 501,
                    ..record(500, 'S')
                },
            );
            let failure = fixture
                .registry
                .admit_with(
                    &request(4 * GIB, 2 * GIB, &[1]),
                    &mut || Ok((BTreeMap::from([(1, 20 * GIB)]), Instant::now())),
                    &mut || Ok(()),
                    |_| Ok(snapshot.clone()),
                )
                .err()
                .unwrap();
            assert_eq!(failure.reason, "admission");
            assert_eq!(fixture.bytes(), before);
        }
    }

    #[test]
    fn unknown_census_and_changed_filesystem_preserve_the_original_ledger() {
        for change_device in [false, true] {
            let fixture = Fixture::new();
            let before =
                fixture.write_entries(vec![Entry::from(&request(7 * GIB, 10 * GIB, &[1]))]);
            let mut samples = 0;
            let failure = fixture
                .registry
                .admit_with(
                    &request(4 * GIB, 2 * GIB, &[1]),
                    &mut || {
                        samples += 1;
                        Ok((
                            BTreeMap::from([(if samples == 1 { 1 } else { 2 }, 6 * GIB)]),
                            Instant::now(),
                        ))
                    },
                    &mut || Ok(()),
                    |_| {
                        if change_device {
                            Ok(Snapshot::new())
                        } else {
                            Err(Failure::unavailable("census unavailable"))
                        }
                    },
                )
                .err()
                .unwrap();
            assert_eq!(failure.reason, "monitor_unavailable");
            assert_eq!(samples, if change_device { 2 } else { 1 });
            assert_eq!(fixture.bytes(), before);
        }
    }

    #[test]
    fn overflowing_budget_sum_never_appears_to_fit() {
        let fixture = Fixture::new();
        let reservation = request(i64::MAX as u64, i64::MAX as u64, &[1]);
        let before =
            fixture.write_entries(vec![Entry::from(&reservation), Entry::from(&reservation)]);
        let failure = fixture
            .registry
            .admit_with(
                &reservation,
                &mut || Ok((BTreeMap::from([(1, u64::MAX)]), Instant::now())),
                &mut || Ok(()),
                |_| Ok(census(&[500])),
            )
            .err()
            .unwrap();
        assert_eq!(failure.reason, "admission");
        assert_eq!(fixture.bytes(), before);
    }

    #[test]
    fn full_live_ledger_never_publishes_an_unreadable_extra_record() {
        let fixture = Fixture::new();
        let reservation = request(1, 0, &[1]);
        let before = fixture.write_entries(vec![Entry::from(&reservation); MAX_RESERVATIONS]);
        let failure = fixture
            .registry
            .admit_with(
                &reservation,
                &mut || Ok((BTreeMap::from([(1, GIB)]), Instant::now())),
                &mut || Ok(()),
                |_| Ok(census(&[500])),
            )
            .err()
            .unwrap();
        assert_eq!(failure.reason, "monitor_unavailable");
        assert!(failure.detail.contains("reservation limit"));
        assert_eq!(fixture.bytes(), before);
    }

    #[test]
    fn invalid_shared_ledger_never_becomes_an_empty_ledger() {
        let valid = serde_json::to_value(Ledger {
            version: 1,
            entries: vec![Entry::from(&request(1, 0, &[1]))],
        })
        .unwrap();
        let mut variants = vec![b"corrupt".to_vec(), vec![b' '; MAX_LEDGER_BYTES + 1]];
        for (field, invalid) in [
            ("boot", serde_json::json!("not-a-boot")),
            ("group", serde_json::json!(1)),
            ("group", serde_json::json!(-1)),
            ("budget", serde_json::json!(true)),
            ("budget", serde_json::json!(0)),
            ("floor", serde_json::json!(-1)),
            ("leader_start", serde_json::json!("")),
            ("devices", serde_json::json!([])),
            ("devices", serde_json::json!([true])),
            ("devices", serde_json::json!([-1])),
        ] {
            let mut value = valid.clone();
            value["entries"][0][field] = invalid;
            variants.push(serde_json::to_vec(&value).unwrap());
        }
        for version in [
            serde_json::json!(2),
            serde_json::json!(true),
            serde_json::Value::Null,
        ] {
            let mut value = valid.clone();
            value["version"] = version;
            variants.push(serde_json::to_vec(&value).unwrap());
        }
        for bytes in variants {
            let fixture = Fixture::new();
            fixture.write_bytes(&bytes);
            let failure = fixture
                .registry
                .admit_with(
                    &request(1, 0, &[1]),
                    &mut || panic!("invalid ledger cannot reach a capacity sample"),
                    &mut || Ok(()),
                    |_| panic!("invalid ledger cannot retire reservations"),
                )
                .err()
                .unwrap();
            assert_eq!(failure.reason, "monitor_unavailable");
            assert_eq!(fixture.bytes(), bytes);
        }
    }

    #[test]
    fn lock_contention_obeys_deadline_without_sampling_or_replacing_the_ledger() {
        let mut fixture = Fixture::new();
        fixture.registry.lock_timeout = Duration::from_millis(30);
        let before = fixture.write_entries(vec![]);
        let held = fixture.registry.locked(&mut || Ok(())).unwrap();
        let failure = fixture
            .registry
            .admit_with(
                &request(1, 0, &[1]),
                &mut || panic!("unacquired lock must not sample capacity"),
                &mut || Ok(()),
                |_| panic!("unacquired lock must not census processes"),
            )
            .err()
            .unwrap();
        assert!(failure.detail.contains("lock deadline"));
        assert_eq!(fixture.bytes(), before);
        drop(held);
        fixture
            .registry
            .admit_with(
                &request(1, 0, &[1]),
                &mut || Ok((BTreeMap::from([(1, 1)]), Instant::now())),
                &mut || Ok(()),
                |_| panic!("zero floor and exact budget fit"),
            )
            .unwrap();
    }

    #[test]
    fn replaced_registry_lock_or_ledger_never_accepts_admission() {
        for replacement in ["root", "lock", "ledger"] {
            let fixture = Fixture::new();
            fixture.write_entries(vec![]);
            let mut replaced = false;
            let failure = fixture
                .registry
                .admit_with(
                    &request(1, 0, &[1]),
                    &mut || {
                        let path = match replacement {
                            "root" => fixture.registry.root.clone(),
                            "lock" => fixture.registry.root.join("lock"),
                            _ => fixture.registry.root.join("ledger.json"),
                        };
                        fs::rename(&path, fixture.root.join("retained-original")).unwrap();
                        if replacement == "root" {
                            fs::create_dir(&path).unwrap();
                            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
                        } else {
                            fs::write(&path, b"replacement evidence").unwrap();
                            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
                        }
                        replaced = true;
                        Ok((BTreeMap::from([(1, 1)]), Instant::now()))
                    },
                    &mut || Ok(()),
                    |_| panic!("capacity fits"),
                )
                .err()
                .unwrap();
            assert!(replaced);
            assert_eq!(failure.reason, "monitor_unavailable");
            if replacement == "root" {
                assert_eq!(fs::read_dir(&fixture.registry.root).unwrap().count(), 0);
            } else {
                let name = if replacement == "lock" {
                    "lock"
                } else {
                    "ledger.json"
                };
                assert_eq!(
                    fs::read(fixture.registry.root.join(name)).unwrap(),
                    b"replacement evidence"
                );
            }
        }
    }

    #[test]
    fn unsafe_accounting_entries_are_refused_without_mutating_aliases() {
        for name in ["lock", "ledger.json"] {
            for kind in ["symlink", "hardlink", "fifo", "public"] {
                let fixture = Fixture::new();
                let victim = fixture.root.join("unrelated");
                fs::write(&victim, b"keep unrelated bytes").unwrap();
                fs::set_permissions(&victim, fs::Permissions::from_mode(0o600)).unwrap();
                let path = fixture.registry.root.join(name);
                match kind {
                    "symlink" => symlink(&victim, &path).unwrap(),
                    "hardlink" => fs::hard_link(&victim, &path).unwrap(),
                    "fifo" => rustix::fs::mknodat(
                        rustix::fs::CWD,
                        &path,
                        FileType::Fifo,
                        Mode::from_raw_mode(0o600),
                        0,
                    )
                    .unwrap(),
                    _ => {
                        fs::write(&path, b"private protocol is unavailable").unwrap();
                        fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
                    }
                }
                let failure = fixture
                    .registry
                    .admit_with(
                        &request(1, 0, &[1]),
                        &mut || panic!("unsafe accounting cannot reach capacity sample"),
                        &mut || Ok(()),
                        |_| panic!("unsafe accounting cannot retire reservations"),
                    )
                    .err()
                    .unwrap();
                assert_eq!(failure.reason, "monitor_unavailable", "{name}:{kind}");
                assert_eq!(fs::read(&victim).unwrap(), b"keep unrelated bytes");
            }
        }
    }

    #[test]
    fn private_registry_root_never_follows_a_symlink_or_accepts_writable_modes() {
        for kind in ["symlink", "public"] {
            let fixture = Fixture::new();
            let candidate = fixture.root.join("candidate");
            if kind == "symlink" {
                symlink(&fixture.registry.root, &candidate).unwrap();
            } else {
                fs::create_dir(&candidate).unwrap();
                fs::set_permissions(&candidate, fs::Permissions::from_mode(0o770)).unwrap();
            }
            assert!(Registry::at(candidate, Duration::from_millis(10)).is_err());
            assert_eq!(fs::read_dir(&fixture.registry.root).unwrap().count(), 0);
        }
    }

    #[test]
    fn kernel_record_parser_binds_pid_and_uses_the_last_command_parenthesis() {
        let mut fields = vec!["0"; 20];
        fields[0] = "S";
        fields[1] = "123";
        fields[2] = "456";
        fields[19] = "789";
        let data = format!("457 (worker ) strange ( name) {}\n", fields.join(" "));
        let parsed = parse_linux_process(&data, 457).unwrap();
        assert_eq!(parsed.parent, 123);
        assert_eq!(parsed.group, 456);
        assert_eq!(parsed.start.as_deref(), Some("789"));
        assert!(parsed.is_alive());
        assert!(parse_linux_process(&data, 458).is_err());
        for state in ["?", "SS", "", "-1"] {
            fields[0] = state;
            assert!(
                parse_linux_process(&format!("457 (worker) {}", fields.join(" ")), 457).is_err()
            );
        }
        assert!(parse_linux_process("457 (worker) S 1", 457).is_err());
    }

    #[cfg(target_os = "linux")]
    struct Child(std::process::Child);

    #[cfg(target_os = "linux")]
    impl Drop for Child {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn native_census_observes_live_child_and_ticks_progress_heartbeat() {
        let mut child = Child(
            std::process::Command::new("/bin/sleep")
                .arg("30")
                .spawn()
                .unwrap(),
        );
        let mut heartbeats = 0;
        let snapshot = process_snapshot(&mut || {
            heartbeats += 1;
            Ok(())
        })
        .unwrap();
        assert!(snapshot[&child.0.id()].is_alive());
        assert_eq!(snapshot[&child.0.id()].parent, std::process::id());
        assert!(snapshot.contains_key(&std::process::id()));
        assert!(heartbeats >= snapshot.len());
        assert!(child.0.try_wait().unwrap().is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn exited_procfs_descriptor_is_absent_but_permission_failure_is_unknown() {
        let mut child = Child(
            std::process::Command::new("/bin/sleep")
                .arg("30")
                .spawn()
                .unwrap(),
        );
        let descriptor = File::open(format!("/proc/{}/stat", child.0.id())).unwrap();
        child.0.kill().unwrap();
        child.0.wait().unwrap();
        let failure = read_process_record(descriptor, child.0.id()).unwrap_err();
        assert!(process_disappeared(&failure));
        struct Denied;
        impl io::Read for Denied {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::from_raw_os_error(Errno::ACCESS.raw_os_error()))
            }
        }
        let failure = read_process_record(Denied, std::process::id()).unwrap_err();
        assert!(!process_disappeared(&failure));
        assert_eq!(failure.reason, "monitor_unavailable");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn writer_signal_requires_current_birth_and_membership_and_uses_owned_pidfd() {
        const OWNED_GROUP_FIXTURE: &str = "RCH_PIDFD_UNIT_TEST_OWNED_GROUP";
        if std::env::var_os(OWNED_GROUP_FIXTURE).as_deref() != Some(std::ffi::OsStr::new("1")) {
            // A test runner may itself belong to reserved group 1. Give this
            // real signalling fixture the same owned group as the supervisor,
            // without changing any other concurrently running test's group.
            use std::os::unix::process::CommandExt as _;
            let current = std::thread::current();
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", current.name().unwrap(), "--nocapture"])
                .env(OWNED_GROUP_FIXTURE, "1")
                .process_group(0)
                .status()
                .unwrap();
            assert!(status.success(), "owned process-group fixture failed");
            return;
        }
        assert_eq!(
            rustix::process::getpgrp().as_raw_nonzero().get() as u32,
            std::process::id(),
        );
        let mut child = Child(
            std::process::Command::new("/bin/sleep")
                .arg("30")
                .spawn()
                .unwrap(),
        );
        let group = rustix::process::getpgrp().as_raw_nonzero().get() as u32;
        let actual = read_process(
            &PathBuf::from(format!("/proc/{}/stat", child.0.id())),
            child.0.id(),
        )
        .unwrap();
        let mut stale = actual.clone();
        stale.start = Some("stale birth".into());
        kill_descendant(&stale, group).unwrap();
        assert!(child.0.try_wait().unwrap().is_none());
        assert!(kill_descendant(&actual, group.saturating_add(1)).is_err());
        assert!(child.0.try_wait().unwrap().is_none());
        kill_descendant(&actual, group).unwrap();
        use std::os::unix::process::ExitStatusExt as _;
        assert_eq!(child.0.wait().unwrap().signal(), Some(9));
    }
}
