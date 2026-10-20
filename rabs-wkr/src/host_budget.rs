//! Optional shared-host execution admission across independent worker processes.
//!
//! Every participating worker opens the SAME private local directory with the
//! SAME fixed capacity. One attempt reserves its entire, unchanged logical C
//! before spawn; its jobserver can then expose only C-1 transferable tokens.
//! This is cooperative execution admission, not a CPU cgroup, Cargo frontier
//! broker, or a fairness guarantee for competing weighted requests.
//!
//! OS locks alone are insufficient: a killed worker can release its descriptors
//! before its descendants have stopped. Each slot is therefore durably armed
//! BEFORE spawn. An unlocked armed slot remains quarantined, even after its PID
//! disappears or the worker restarts. Only the execution owner's explicit
//! cleanup proof may clear it: workers require process-group AND stream-drain
//! completion; the separately versioned local-root domain requires the reaped
//! Cargo leader AND an empty pinned cgroup. No timeout, PID scan, ordinary Drop,
//! or newly created inode manufactures cleanup evidence.
//!
//! The immutable manifest pins directory/slot identities. State must stay on one
//! local filesystem and must never be copied, replaced or edited while in use.
//! Same-credential malicious host mutation is outside this advisory-lock domain.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub const DIRECTORY_ENV: &str = "RABS_WORKER_HOST_BUDGET_DIR";
pub const CAPACITY_ENV: &str = "RABS_WORKER_HOST_SLOTS";
pub const MAX_HOST_SLOTS: u32 = 4096;
const VERSION: &str = "rabs-worker-host-budget-v1";
#[cfg(target_os = "linux")]
const ROOT_COUNT_VERSION: &str = "rabs-local-cargo-root-budget-v1";
const MANIFEST: &str = "capacity.lock";
const MAX_MANIFEST_BYTES: u64 = 256 * 1024;
const FREE: &[u8] = b"free\n";
const POLL: Duration = Duration::from_millis(20);

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Identity {
    device: u64,
    inode: u64,
}

#[cfg(target_os = "linux")]
fn identity(metadata: &fs::Metadata) -> Identity {
    use std::os::unix::fs::MetadataExt;
    Identity {
        device: metadata.dev(),
        inode: metadata.ino(),
    }
}

#[cfg(not(target_os = "linux"))]
fn identity(_metadata: &fs::Metadata) -> Identity {
    Identity {
        device: 0,
        inode: 0,
    }
}

#[cfg(target_os = "linux")]
fn current_uid() -> io::Result<u32> {
    use std::os::unix::fs::MetadataExt;
    Ok(fs::metadata("/proc/self")?.uid())
}

#[cfg(not(target_os = "linux"))]
fn current_uid() -> io::Result<u32> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "shared worker host budgets require Linux",
    ))
}

fn check_metadata(metadata: &fs::Metadata, directory: bool, uid: u32) -> io::Result<()> {
    if metadata.file_type().is_symlink()
        || if directory {
            !metadata.is_dir()
        } else {
            !metadata.is_file()
        }
    {
        return Err(invalid(
            "host budget path must be ordinary and not a symlink",
        ));
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != uid
            || metadata.permissions().mode() & 0o077 != 0
            || (!directory && metadata.nlink() != 1)
        {
            return Err(invalid(
                "host budget paths must be private, owned by this user, and singly linked",
            ));
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = uid;
    Ok(())
}

fn check_ancestors(root: &Path) -> io::Result<()> {
    if !root.is_absolute()
        || root == Path::new("/")
        || root
            .components()
            .any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
    {
        return Err(invalid(
            "host budget directory must be absolute without aliases",
        ));
    }
    for path in root.ancestors() {
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(invalid(
                "host budget directory ancestors must be ordinary directories",
            ));
        }
    }
    Ok(())
}

fn check_before_creation(root: &Path) -> io::Result<()> {
    if !root.is_absolute()
        || root == Path::new("/")
        || root
            .components()
            .any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
    {
        return Err(invalid(
            "host budget directory must be absolute without aliases",
        ));
    }
    for path in root.ancestors() {
        match fs::symlink_metadata(path) {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
            Ok(_) => return Err(invalid("host budget ancestors must not be symlinks")),
        }
    }
    Ok(())
}

fn options(create: bool) -> OpenOptions {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(create);
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // Linux O_NOFOLLOW | O_NONBLOCK: a replacement symlink or FIFO cannot
        // redirect or indefinitely block opening before identity validation.
        options.mode(0o600).custom_flags(0x2_0000 | 0x800);
    }
    options
}

fn validate_file(path: &Path, file: &File, uid: u32) -> io::Result<Identity> {
    let named = fs::symlink_metadata(path)?;
    let opened = file.metadata()?;
    check_metadata(&named, false, uid)?;
    check_metadata(&opened, false, uid)?;
    if identity(&named) != identity(&opened) {
        return Err(invalid("host budget file changed while being opened"));
    }
    Ok(identity(&opened))
}

/// Explicit unlock prevents an unrelated concurrent fork from extending the
/// lock until its inherited CLOEXEC descriptor finally reaches exec.
#[derive(Debug)]
struct LockedFile(File);

impl Drop for LockedFile {
    fn drop(&mut self) {
        let _ = self.0.unlock();
    }
}

fn try_lock(file: File) -> io::Result<Option<LockedFile>> {
    match file.try_lock() {
        Ok(()) => Ok(Some(LockedFile(file))),
        Err(fs::TryLockError::WouldBlock) => Ok(None),
        Err(fs::TryLockError::Error(error)) => Err(error),
    }
}

fn read_bounded(file: &File, maximum: u64) -> io::Result<Vec<u8>> {
    let length = file.metadata()?.len();
    if length > maximum {
        return Err(invalid("host budget record exceeds its bound"));
    }
    let mut bytes = vec![0; length as usize];
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::FileExt;
        // The immutable manifest is shared through Arc. Cloned File handles
        // share an offset, so seek/read would race independent admissions.
        file.read_exact_at(&mut bytes, 0)?;
    }
    #[cfg(not(target_os = "linux"))]
    {
        use std::io::Read;
        let mut reader = file.try_clone()?;
        reader.seek(SeekFrom::Start(0))?;
        reader.read_exact(&mut bytes)?;
    }
    if file.metadata()?.len() != length {
        return Err(invalid("host budget record changed while being read"));
    }
    Ok(bytes)
}

fn write_durable(file: &mut File, bytes: &[u8]) -> io::Result<()> {
    file.seek(SeekFrom::Start(0))?;
    file.write_all(bytes)?;
    file.set_len(bytes.len() as u64)?;
    file.sync_all()
}

fn slot_name(index: u32) -> String {
    format!("slot-{index:04}.lease")
}

fn number<T: std::str::FromStr + ToString>(text: &str) -> io::Result<T> {
    let value = text
        .parse::<T>()
        .map_err(|_| invalid("invalid host budget number"))?;
    if value.to_string() != text {
        return Err(invalid(
            "host budget numbers must use canonical decimal spelling",
        ));
    }
    Ok(value)
}

fn held_marker(bytes: &[u8]) -> io::Result<bool> {
    if bytes == FREE {
        return Ok(false);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| invalid("invalid host slot record"))?;
    let Some(fields) = text.strip_suffix('\n') else {
        return Err(invalid("incomplete host slot record"));
    };
    let fields: Vec<_> = fields.split(' ').collect();
    if fields.len() != 3 || fields[0] != "held" || number::<u32>(fields[1])? == 0 {
        return Err(invalid("invalid host slot ownership record"));
    }
    number::<u64>(fields[2])?;
    Ok(true)
}

/// One fixed admission domain, shared across processes by pathname AND pinned
/// inode identity. Opening it does not reserve any execution capacity.
#[derive(Debug)]
pub struct HostBudget {
    root: PathBuf,
    root_file: File,
    root_identity: Identity,
    uid: u32,
    capacity: u32,
    manifest: File,
    manifest_identity: Identity,
    manifest_bytes: Vec<u8>,
    slots: Vec<Identity>,
}

impl HostBudget {
    /// Both variables are required together. Unconfigured workers retain their
    /// prior behavior; malformed configuration never silently disables admission.
    pub fn from_environment() -> io::Result<Option<Arc<Self>>> {
        Self::from_values(
            std::env::var_os(DIRECTORY_ENV),
            std::env::var_os(CAPACITY_ENV),
        )
    }

    fn from_values(
        directory: Option<std::ffi::OsString>,
        capacity: Option<std::ffi::OsString>,
    ) -> io::Result<Option<Arc<Self>>> {
        match (directory, capacity) {
            (None, None) => Ok(None),
            (Some(directory), Some(capacity)) => {
                let capacity = capacity
                    .to_str()
                    .ok_or_else(|| invalid("host budget capacity must be UTF-8 decimal"))?;
                Ok(Some(Arc::new(Self::open(
                    Path::new(&directory),
                    number(capacity)?,
                )?)))
            }
            _ => Err(invalid(format!(
                "{DIRECTORY_ENV} and {CAPACITY_ENV} must be configured together"
            ))),
        }
    }

    /// Create a new private domain or verify its immutable existing manifest.
    /// Initialization is serialized and durably publishes all slot identities
    /// before any opener can grant work. An incomplete/corrupt prior manifest
    /// refuses rather than resetting possible ownership.
    pub fn open(root: &Path, capacity: u32) -> io::Result<Self> {
        Self::open_domain(root, capacity, VERSION)
    }

    /// The native local Cargo supervisor counts whole trees rather than CPU
    /// grants. A separate immutable version prevents accidentally mixing both
    /// resource dimensions in one directory while sharing the lock substrate.
    #[cfg(target_os = "linux")]
    pub(crate) fn open_root_count(root: &Path, capacity: u32) -> io::Result<Self> {
        Self::open_domain(root, capacity, ROOT_COUNT_VERSION)
    }

    fn open_domain(root: &Path, capacity: u32, version: &'static str) -> io::Result<Self> {
        if capacity == 0 || capacity > MAX_HOST_SLOTS {
            return Err(invalid("host budget capacity must be between 1 and 4096"));
        }
        let uid = current_uid()?;
        check_before_creation(root)?;
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(root)?;
        check_ancestors(root)?;
        let root_metadata = fs::symlink_metadata(root)?;
        check_metadata(&root_metadata, true, uid)?;
        let root_file = File::open(root)?;
        let root_identity = identity(&root_metadata);
        if identity(&root_file.metadata()?) != root_identity {
            return Err(invalid("host budget directory changed during opening"));
        }
        let manifest_path = root.join(MANIFEST);
        let (file, created) = match options(true).open(&manifest_path) {
            Ok(file) => (file, true),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                (options(false).open(&manifest_path)?, false)
            }
            Err(error) => return Err(error),
        };
        validate_file(&manifest_path, &file, uid)?;
        let until = Instant::now() + Duration::from_secs(5);
        let mut manifest = LockedFile(file);
        loop {
            match manifest.0.try_lock() {
                Ok(()) => {
                    validate_file(&manifest_path, &manifest.0, uid)?;
                    if created || manifest.0.metadata()?.len() != 0 {
                        break;
                    }
                    // create_new publishes the name before its creator can
                    // lock it. Release an empty manifest so that creator can
                    // finish. Never fill, reset, or accept it ourselves.
                    manifest.0.unlock()?;
                    if Instant::now() >= until {
                        return Err(invalid("host budget manifest initialization is incomplete"));
                    }
                    std::thread::sleep(POLL);
                }
                Err(fs::TryLockError::WouldBlock) if Instant::now() < until => {
                    std::thread::sleep(POLL);
                }
                Err(error) => return Err(error.into()),
            }
        }
        let manifest_identity = validate_file(&manifest_path, &manifest.0, uid)?;
        if created {
            let mut bytes = format!(
                "{version}\ncapacity {capacity}\nroot {} {} {uid}\n",
                root_identity.device, root_identity.inode,
            );
            for index in 0..capacity {
                let path = root.join(slot_name(index));
                let mut slot = options(true).open(&path)?;
                let identity = validate_file(&path, &slot, uid)?;
                write_durable(&mut slot, FREE)?;
                bytes.push_str(&format!(
                    "slot {index} {} {}\n",
                    identity.device, identity.inode,
                ));
            }
            root_file.sync_all()?;
            write_durable(&mut manifest.0, bytes.as_bytes())?;
            // A new directory's ancestors must survive as well as its contents.
            for ancestor in root.ancestors() {
                File::open(ancestor)?.sync_all()?;
            }
        }
        let manifest_bytes = read_bounded(&manifest.0, MAX_MANIFEST_BYTES)?;
        let slots = parse_manifest(&manifest_bytes, capacity, root_identity, uid, version)?;
        let budget = Self {
            root: root.to_path_buf(),
            root_file,
            root_identity,
            uid,
            capacity,
            manifest: manifest.0.try_clone()?,
            manifest_identity,
            manifest_bytes,
            slots,
        };
        budget.validate_domain()?;
        for index in 0..capacity {
            // Existing armed records remain armed. Startup verifies identity,
            // never infers that an absent old process made its slot safe.
            let file = budget.open_slot(index)?;
            if let Some(slot) = try_lock(file)? {
                held_marker(&read_bounded(&slot.0, 128)?)?;
            }
        }
        Ok(budget)
    }

    #[must_use]
    pub const fn capacity(&self) -> u32 {
        self.capacity
    }

    fn validate_domain(&self) -> io::Result<()> {
        check_ancestors(&self.root)?;
        let named = fs::symlink_metadata(&self.root)?;
        check_metadata(&named, true, self.uid)?;
        if identity(&named) != self.root_identity
            || identity(&self.root_file.metadata()?) != self.root_identity
            || validate_file(&self.root.join(MANIFEST), &self.manifest, self.uid)?
                != self.manifest_identity
            || read_bounded(&self.manifest, MAX_MANIFEST_BYTES)? != self.manifest_bytes
        {
            return Err(invalid(
                "host budget directory or immutable manifest changed",
            ));
        }
        Ok(())
    }

    fn open_slot(&self, index: u32) -> io::Result<File> {
        let path = self.root.join(slot_name(index));
        let file = options(false).open(&path)?;
        self.validate_slot(index, &file)?;
        Ok(file)
    }

    fn validate_slot(&self, index: u32, file: &File) -> io::Result<()> {
        if validate_file(&self.root.join(slot_name(index)), file, self.uid)?
            != self.slots[index as usize]
        {
            return Err(invalid(
                "host budget slot inode changed; capacity cannot be recreated",
            ));
        }
        Ok(())
    }

    /// Reserve the complete fixed grant or retain nothing while waiting. This
    /// blocking API belongs only on the existing execution thread. Cancellation
    /// and execution-lease expiry remain authoritative throughout the wait.
    pub(crate) fn acquire(
        &self,
        grant: u32,
        mut stopped: impl FnMut() -> bool,
    ) -> io::Result<HostLease<'_>> {
        loop {
            if stopped() {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "host execution admission cancelled before spawn",
                ));
            }
            if let Some(lease) = self.try_acquire(grant)? {
                return Ok(lease);
            }
            std::thread::sleep(POLL);
        }
    }

    fn try_acquire(&self, grant: u32) -> io::Result<Option<HostLease<'_>>> {
        if grant == 0 || grant > self.capacity {
            return Err(invalid(format!(
                "fixed execution grant {grant} exceeds host capacity {}; configure an explicit jobserver_grant within that capacity",
                self.capacity,
            )));
        }
        self.validate_domain()?;
        let mut slots = Vec::with_capacity(grant as usize);
        let mut quarantined = 0;
        for index in 0..self.capacity {
            let Some(file) = try_lock(self.open_slot(index)?)? else {
                continue;
            };
            self.validate_slot(index, &file.0)?;
            if held_marker(&read_bounded(&file.0, 128)?)? {
                quarantined += 1;
                continue;
            }
            slots.push((index, file));
            if slots.len() == grant as usize {
                self.validate_domain()?;
                return Ok(Some(HostLease {
                    budget: self,
                    slots,
                    armed: None,
                }));
            }
        }
        if self.capacity - quarantined < grant {
            return Err(invalid(format!(
                "host budget has {quarantined} quarantined slots requiring proved cleanup before this grant can fit",
            )));
        }
        // Dropping every partial lock avoids weighted-acquisition deadlocks.
        Ok(None)
    }
}

fn parse_manifest(
    bytes: &[u8],
    capacity: u32,
    root: Identity,
    uid: u32,
    version: &str,
) -> io::Result<Vec<Identity>> {
    let text = std::str::from_utf8(bytes).map_err(|_| invalid("invalid host budget manifest"))?;
    let mut lines = text.lines();
    let expected_root = format!("root {} {} {uid}", root.device, root.inode);
    if !text.ends_with('\n')
        || lines.next() != Some(version)
        || lines.next() != Some(format!("capacity {capacity}").as_str())
        || lines.next() != Some(expected_root.as_str())
    {
        return Err(invalid(
            "host budget manifest is incomplete or differs from configured capacity/directory",
        ));
    }
    let mut slots = Vec::with_capacity(capacity as usize);
    let mut identities = std::collections::BTreeSet::new();
    for index in 0..capacity {
        let fields: Vec<_> = lines
            .next()
            .ok_or_else(|| invalid("host budget manifest lacks slot identities"))?
            .split(' ')
            .collect();
        if fields.len() != 4 || fields[0] != "slot" || number::<u32>(fields[1])? != index {
            return Err(invalid("invalid host budget slot manifest"));
        }
        let slot = Identity {
            device: number(fields[2])?,
            inode: number(fields[3])?,
        };
        if !identities.insert((slot.device, slot.inode)) {
            return Err(invalid("host budget slots alias one inode"));
        }
        slots.push(slot);
    }
    if lines.next().is_some() {
        return Err(invalid("host budget manifest contains extra fields"));
    }
    Ok(slots)
}

/// File descriptors remain CLOEXEC and never become child authority. Once
/// armed, Drop only unlocks: durable quarantine survives every uncertain exit.
pub(crate) struct HostLease<'a> {
    budget: &'a HostBudget,
    slots: Vec<(u32, LockedFile)>,
    armed: Option<Vec<u8>>,
}

impl HostLease<'_> {
    /// Persist possible execution BEFORE the only spawn boundary. A failed or
    /// partial arm quarantines written records; it never authorizes a spawn.
    pub(crate) fn arm(&mut self, request_id: u64) -> io::Result<()> {
        if self.armed.is_some() {
            return Err(invalid("host execution lease was already armed"));
        }
        self.budget.validate_domain()?;
        let marker = format!("held {} {request_id}\n", std::process::id()).into_bytes();
        self.armed = Some(marker.clone());
        for (index, slot) in &mut self.slots {
            self.budget.validate_slot(*index, &slot.0)?;
            if read_bounded(&slot.0, 128)? != FREE {
                return Err(invalid("host slot changed before execution admission"));
            }
            write_durable(&mut slot.0, &marker)?;
        }
        self.budget.validate_domain()
    }

    /// Explicit cancellation after arming but BEFORE any spawn was attempted.
    /// The owner still knows no child exists; this is never used for a spawn or
    /// wait error. Partial arm failures may leave free records alongside ours.
    pub(crate) fn abandon_unstarted(mut self) -> io::Result<()> {
        self.budget.validate_domain()?;
        for (index, slot) in &self.slots {
            self.budget.validate_slot(*index, &slot.0)?;
            let observed = read_bounded(&slot.0, 128)?;
            if observed != FREE && self.armed.as_ref() != Some(&observed) {
                return Err(invalid(
                    "host slot ownership changed before unstarted cancellation",
                ));
            }
        }
        for (_, slot) in &mut self.slots {
            write_durable(&mut slot.0, FREE)?;
        }
        self.armed = None;
        Ok(())
    }

    /// Called ONLY after the execution owner's complete cleanup contract. A
    /// worker's managed wait must join BOTH bounded drain lanes and reap its
    /// leader. The local-root supervisor must reap Cargo and prove its pinned
    /// cgroup unpopulated. Nonzero residual members refuse release. Any uncertain
    /// wait/drain/containment result or unwind must leave this armed.
    pub(crate) fn finish(mut self, residual_group_members: u32) -> io::Result<()> {
        if residual_group_members != 0 {
            return Err(invalid("host execution lease retains residual descendants"));
        }
        let expected = self
            .armed
            .as_ref()
            .ok_or_else(|| invalid("unarmed host execution lease cannot attest cleanup"))?;
        self.budget.validate_domain()?;
        for (index, slot) in &self.slots {
            self.budget.validate_slot(*index, &slot.0)?;
            if read_bounded(&slot.0, 128)? != *expected {
                return Err(invalid(
                    "host execution ownership record changed before cleanup",
                ));
            }
        }
        for (_, slot) in &mut self.slots {
            write_durable(&mut slot.0, FREE)?;
        }
        self.armed = None;
        Ok(())
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    use std::process::{Child, Command, Stdio};
    use std::sync::atomic::{AtomicU64, Ordering};

    const HELPER: &str = "RABS_TEST_HOST_BUDGET_HELPER";
    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    fn test_root() -> PathBuf {
        let time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "rabs-host-budget-test-{}-{time}-{}",
            std::process::id(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed),
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        path
    }

    struct Helper(Child);

    impl Helper {
        fn start(root: &Path, capacity: u32, grant: u32, mode: &str) -> Self {
            let module = module_path!().split_once("::").unwrap().1;
            Self(
                Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        &format!("{module}::process_helper"),
                        "--nocapture",
                    ])
                    .env(HELPER, mode)
                    .env("RABS_TEST_BUDGET_ROOT", root)
                    .env("RABS_TEST_BUDGET_CAPACITY", capacity.to_string())
                    .env("RABS_TEST_BUDGET_GRANT", grant.to_string())
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::inherit())
                    .spawn()
                    .unwrap(),
            )
        }

        fn ready(&mut self, root: &Path) {
            let until = Instant::now() + Duration::from_secs(10);
            while !root.join("ready").is_file() {
                assert!(
                    self.0.try_wait().unwrap().is_none(),
                    "helper exited before admission"
                );
                assert!(Instant::now() < until, "helper did not become ready");
                std::thread::sleep(Duration::from_millis(5));
            }
        }

        fn finish(&mut self, root: &Path) {
            fs::write(root.join("release"), b"release").unwrap();
            let until = Instant::now() + Duration::from_secs(10);
            loop {
                if let Some(status) = self.0.try_wait().unwrap() {
                    assert!(status.success(), "helper failed: {status}");
                    return;
                }
                assert!(Instant::now() < until, "helper did not release its lease");
                std::thread::sleep(Duration::from_millis(5));
            }
        }

        fn crash(&mut self) {
            self.0.kill().unwrap();
            self.0.wait().unwrap();
        }
    }

    impl Drop for Helper {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    #[test]
    fn process_helper() {
        let Ok(mode) = std::env::var(HELPER) else {
            return;
        };
        let root = PathBuf::from(std::env::var_os("RABS_TEST_BUDGET_ROOT").unwrap());
        if mode == "fd-audit" {
            for entry in fs::read_dir("/proc/self/fd").unwrap() {
                if let Ok(target) = fs::read_link(entry.unwrap().path()) {
                    assert!(
                        !target.starts_with(root.join("budget")),
                        "budget FD crossed exec"
                    );
                }
            }
            return;
        }
        let capacity = std::env::var("RABS_TEST_BUDGET_CAPACITY")
            .unwrap()
            .parse()
            .unwrap();
        let grant = std::env::var("RABS_TEST_BUDGET_GRANT")
            .unwrap()
            .parse()
            .unwrap();
        let budget = HostBudget::open(&root.join("budget"), capacity).unwrap();
        let mut lease = budget.acquire(grant, || false).unwrap();
        if mode == "armed" {
            lease.arm(42).unwrap();
        }
        fs::write(root.join("ready"), b"ready").unwrap();
        let until = Instant::now() + Duration::from_secs(15);
        while !root.join("release").is_file() {
            assert!(Instant::now() < until, "parent did not release helper");
            std::thread::sleep(Duration::from_millis(5));
        }
        if mode == "armed" {
            lease.finish(0).unwrap();
        }
    }

    #[test]
    fn configuration_is_explicit_bounded_and_persistently_consistent() {
        assert!(HostBudget::from_values(None, None).unwrap().is_none());
        assert!(HostBudget::from_values(Some("/tmp/x".into()), None).is_err());
        assert!(HostBudget::from_values(None, Some("2".into())).is_err());
        for capacity in ["", "0", "01", "+2", "4097", "1.0"] {
            assert!(HostBudget::from_values(Some("/tmp/x".into()), Some(capacity.into())).is_err());
        }
        let root = test_root().join("budget");
        let budget = HostBudget::open(&root, 3).unwrap();
        assert_eq!(budget.capacity(), 3);
        assert!(HostBudget::open(&root, 2).is_err());
        assert_eq!(HostBudget::open(&root, 3).unwrap().capacity(), 3);
        assert!(
            budget.try_acquire(4).is_err(),
            "fixed C must never shrink to fit"
        );
        assert!(budget.try_acquire(0).is_err());
    }

    #[test]
    fn worker_cpu_and_cargo_root_dimensions_cannot_share_a_budget() {
        let root = test_root();
        let worker_path = root.join("worker");
        let roots_path = root.join("roots");
        let worker = HostBudget::open(&worker_path, 2).unwrap();
        let roots = HostBudget::open_root_count(&roots_path, 2).unwrap();
        assert!(HostBudget::open_root_count(&worker_path, 2).is_err());
        assert!(HostBudget::open(&roots_path, 2).is_err());
        assert!(worker.try_acquire(2).unwrap().is_some());
        assert!(roots.try_acquire(2).unwrap().is_some());
        assert_eq!(
            HostBudget::open_root_count(&roots_path, 2)
                .unwrap()
                .capacity(),
            2
        );
    }

    #[test]
    fn simultaneous_first_worker_opens_share_one_initialized_domain() {
        let root = test_root().join("budget");
        let barrier = std::sync::Barrier::new(16);
        std::thread::scope(|scope| {
            let threads: Vec<_> = (0..16)
                .map(|_| {
                    scope.spawn(|| {
                        barrier.wait();
                        HostBudget::open(&root, 2).unwrap()
                    })
                })
                .collect();
            for thread in threads {
                assert_eq!(thread.join().unwrap().capacity(), 2);
            }
        });
        let budget = HostBudget::open(&root, 2).unwrap();
        assert!(budget.try_acquire(2).unwrap().is_some());
    }

    #[test]
    fn independent_processes_share_weighted_capacity_and_partial_attempts_release() {
        let root = test_root();
        let budget = HostBudget::open(&root.join("budget"), 3).unwrap();
        let mut worker = Helper::start(&root, 3, 2, "armed");
        worker.ready(&root);
        assert!(budget.try_acquire(2).unwrap().is_none());
        // The failed two-credit attempt must not retain the one free credit.
        let mut last = budget.try_acquire(1).unwrap().unwrap();
        last.arm(43).unwrap();
        assert!(budget.try_acquire(1).unwrap().is_none());
        last.finish(0).unwrap();
        worker.finish(&root);
        let mut all = budget.try_acquire(3).unwrap().unwrap();
        all.arm(44).unwrap();
        all.finish(0).unwrap();
    }

    #[test]
    fn worker_crash_quarantines_armed_credits_across_reopen_without_pid_guessing() {
        let root = test_root();
        let budget = HostBudget::open(&root.join("budget"), 3).unwrap();
        let mut worker = Helper::start(&root, 3, 2, "armed");
        worker.ready(&root);
        worker.crash();
        drop(budget);
        let reopened = HostBudget::open(&root.join("budget"), 3).unwrap();
        assert!(
            reopened.try_acquire(2).is_err(),
            "dead owner is not descendant cleanup proof"
        );
        let mut remaining = reopened.try_acquire(1).unwrap().unwrap();
        remaining.arm(45).unwrap();
        remaining.finish(0).unwrap();
    }

    #[test]
    fn crash_before_arming_does_not_leak_unstarted_capacity() {
        let root = test_root();
        let budget = HostBudget::open(&root.join("budget"), 2).unwrap();
        let mut worker = Helper::start(&root, 2, 2, "unarmed");
        worker.ready(&root);
        assert!(budget.try_acquire(1).unwrap().is_none());
        worker.crash();
        assert!(budget.try_acquire(2).unwrap().is_some());
    }

    #[test]
    fn waiting_observes_cancellation_and_leaves_no_partial_reservation() {
        let root = test_root();
        let budget = HostBudget::open(&root.join("budget"), 2).unwrap();
        let held = budget.try_acquire(1).unwrap().unwrap();
        let until = Instant::now() + Duration::from_millis(40);
        let error = match budget.acquire(2, || Instant::now() >= until) {
            Ok(_) => panic!("cancelled full grant unexpectedly admitted"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
        assert!(budget.try_acquire(1).unwrap().is_some());
        drop(held);
        assert!(budget.try_acquire(2).unwrap().is_some());
    }

    #[test]
    fn uncertain_drop_and_nonzero_descendants_never_release_armed_capacity() {
        for residual in [None, Some(1)] {
            let root = test_root();
            let budget = HostBudget::open(&root.join("budget"), 1).unwrap();
            let mut lease = budget.try_acquire(1).unwrap().unwrap();
            lease.arm(46).unwrap();
            if let Some(residual) = residual {
                assert!(lease.finish(residual).is_err());
            } else {
                drop(lease);
            }
            assert!(budget.try_acquire(1).is_err());
        }
    }

    #[test]
    fn explicit_unstarted_cancellation_returns_armed_capacity_without_spawning() {
        let root = test_root();
        let budget = HostBudget::open(&root.join("budget"), 2).unwrap();
        let mut lease = budget.try_acquire(2).unwrap().unwrap();
        lease.arm(47).unwrap();
        lease.abandon_unstarted().unwrap();
        assert!(budget.try_acquire(2).unwrap().is_some());
    }

    #[test]
    fn slot_replacement_is_refused_even_by_a_new_worker_process() {
        let root = test_root().join("budget");
        let budget = HostBudget::open(&root, 1).unwrap();
        let mut lease = budget.try_acquire(1).unwrap().unwrap();
        lease.arm(48).unwrap();
        fs::rename(
            root.join(slot_name(0)),
            root.join("retained-original.lease"),
        )
        .unwrap();
        let mut replacement = options(true).open(root.join(slot_name(0))).unwrap();
        write_durable(&mut replacement, FREE).unwrap();
        assert!(lease.finish(0).is_err());
        assert!(budget.try_acquire(1).is_err());
        assert!(HostBudget::open(&root, 1).is_err());
        assert!(held_marker(&fs::read(root.join("retained-original.lease")).unwrap()).unwrap());
    }

    #[test]
    fn symlinks_hardlinks_and_incomplete_manifests_cannot_create_capacity() {
        let root = test_root();
        let budget = HostBudget::open(&root.join("budget"), 1).unwrap();
        std::os::unix::fs::symlink(root.join("budget"), root.join("alias")).unwrap();
        assert!(HostBudget::open(&root.join("alias"), 1).is_err());
        fs::hard_link(
            root.join("budget").join(slot_name(0)),
            root.join("extra-link"),
        )
        .unwrap();
        assert!(budget.try_acquire(1).is_err());

        let incomplete = root.join("incomplete");
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&incomplete)
            .unwrap();
        let _empty = options(true).open(incomplete.join(MANIFEST)).unwrap();
        assert!(HostBudget::open(&incomplete, 1).is_err());
        fs::set_permissions(&incomplete, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(HostBudget::open(&incomplete, 1).is_err());
    }

    #[test]
    fn host_budget_descriptors_do_not_cross_a_real_exec() {
        let root = test_root();
        let budget = HostBudget::open(&root.join("budget"), 2).unwrap();
        let mut lease = budget.try_acquire(2).unwrap().unwrap();
        lease.arm(49).unwrap();
        let mut child = Helper::start(&root, 2, 1, "fd-audit");
        assert!(child.0.wait().unwrap().success());
        lease.abandon_unstarted().unwrap();
    }
}
