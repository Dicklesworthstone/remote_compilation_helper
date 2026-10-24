//! Explicit host-local admission of complete Cargo process trees.
//!
//! This helper reserves ONE durable root credit, attaches a self-exec
//! trampoline to a newly created cgroup before Cargo can start, and returns
//! the credit only after reaping Cargo and observing `populated 0`. A child
//! which calls setsid remains in the cgroup. Crashes and uncertain cleanup
//! leave the existing HostBudget substrate's durable quarantine intact.
//!
//! This is a local root-count limit, not a worker CPU grant, a fleet lease,
//! or a replacement jobserver. Cargo's raw argv/environment, inherited
//! jobserver descriptors, terminal streams, cwd and process group survive.
//! The launcher explicitly opts in; absent configuration still execs Cargo.
//! The delegation and budget are trusted same-user local state. Deliberate
//! cgroup migration by that user is outside this cooperative admission domain.

use crate::host_budget::HostBudget;
use rustix::fs::{Mode, OFlags, fstatfs, openat};
use rustix::process::{Pid, PidfdFlags, Signal, pidfd_open, pidfd_send_signal};
use signal_hook::consts::{SIGHUP, SIGINT, SIGQUIT, SIGTERM};
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const BUDGET_ENV: &str = "CARGO_RABS_ROOT_BUDGET_DIR";
pub const CAPACITY_ENV: &str = "CARGO_RABS_ROOT_CAPACITY";
pub const CGROUP_ENV: &str = "CARGO_RABS_ROOT_CGROUP";
pub const ACTIVE_ENV: &str = "CARGO_RABS_ROOT_ACTIVE";
const CGROUP_MOUNT: &str = "/sys/fs/cgroup";
const CGROUP2_MAGIC: i64 = 0x6367_7270;
const MAX_CONTROL_BYTES: u64 = 64 * 1024;
const POLL: Duration = Duration::from_millis(20);
const GRACE: Duration = Duration::from_secs(2);
const CLEANUP_BUDGET: Duration = Duration::from_secs(10);

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

#[derive(Debug)]
struct Config {
    budget: PathBuf,
    capacity: u32,
    cgroup: PathBuf,
}

fn absolute_path(value: OsString) -> io::Result<PathBuf> {
    let path = PathBuf::from(value);
    if !path.is_absolute()
        || path == Path::new("/")
        || path
            .components()
            .any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
    {
        return Err(invalid(
            "root-admission paths must be ordinary absolute paths",
        ));
    }
    Ok(path)
}

impl Config {
    fn from_values(values: [Option<OsString>; 3]) -> io::Result<Self> {
        let [Some(budget), Some(capacity), Some(cgroup)] = values else {
            return Err(invalid(format!(
                "{BUDGET_ENV}, {CAPACITY_ENV} and {CGROUP_ENV} are required together"
            )));
        };
        let text = capacity
            .to_str()
            .ok_or_else(|| invalid("root capacity must be canonical decimal"))?;
        let capacity: u32 = text
            .parse()
            .map_err(|_| invalid("root capacity must be from 1 to 4096"))?;
        if capacity == 0 || capacity > 4096 || capacity.to_string() != text {
            return Err(invalid(
                "root capacity must be canonical decimal from 1 to 4096",
            ));
        }
        let budget = absolute_path(budget)?;
        let cgroup = absolute_path(cgroup)?;
        if cgroup == Path::new(CGROUP_MOUNT) || !cgroup.starts_with(CGROUP_MOUNT) {
            return Err(invalid(
                "root cgroup must be an explicitly delegated child of /sys/fs/cgroup",
            ));
        }
        if budget.starts_with(CGROUP_MOUNT) {
            return Err(invalid(
                "durable root budget must be on a local state filesystem, outside cgroupfs",
            ));
        }
        Ok(Self {
            budget,
            capacity,
            cgroup,
        })
    }

    fn from_environment() -> io::Result<Self> {
        if std::env::var_os(ACTIVE_ENV).is_some() {
            return Err(invalid(
                "nested cargo-rabs root admission is unsupported; use ordinary Cargo inside the admitted tree",
            ));
        }
        Self::from_values([
            std::env::var_os(BUDGET_ENV),
            std::env::var_os(CAPACITY_ENV),
            std::env::var_os(CGROUP_ENV),
        ])
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Identity {
    device: u64,
    inode: u64,
}

impl Identity {
    fn of(file: &File) -> io::Result<Self> {
        let metadata = file.metadata()?;
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
}

fn open_directory(path: &Path) -> io::Result<File> {
    if !path.is_absolute() {
        return Err(invalid("cgroup path must be absolute"));
    }
    let mut directory = File::open("/")?;
    for part in path.components() {
        match part {
            Component::RootDir => {}
            Component::Normal(name) => {
                directory = File::from(openat(
                    &directory,
                    name,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )?);
            }
            _ => return Err(invalid("cgroup path contains a non-normal component")),
        }
    }
    if fstatfs(&directory)?.f_type as i64 != CGROUP2_MAGIC {
        return Err(invalid(
            "root delegation must be on a real cgroup-v2 filesystem",
        ));
    }
    Ok(directory)
}

fn control(directory: &File, name: &str, write: bool) -> io::Result<File> {
    Ok(File::from(openat(
        directory,
        name,
        (if write {
            OFlags::WRONLY
        } else {
            OFlags::RDONLY
        }) | OFlags::NOFOLLOW
            | OFlags::CLOEXEC
            | OFlags::NONBLOCK,
        Mode::empty(),
    )?))
}

fn read_bounded(mut file: &File) -> io::Result<String> {
    file.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    file.take(MAX_CONTROL_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_CONTROL_BYTES {
        return Err(invalid("cgroup control value exceeds the read bound"));
    }
    String::from_utf8(bytes).map_err(|_| invalid("cgroup control value is not UTF-8"))
}

fn populated(text: &str) -> io::Result<bool> {
    if !text.ends_with('\n') {
        return Err(invalid("incomplete cgroup.events"));
    }
    let mut value = None;
    for line in text.lines() {
        let fields: Vec<_> = line.split_ascii_whitespace().collect();
        if fields.len() != 2 {
            return Err(invalid("malformed cgroup.events"));
        }
        if fields[0] == "populated" {
            if value.is_some() {
                return Err(invalid("duplicate cgroup populated field"));
            }
            value = Some(match fields[1] {
                "0" => false,
                "1" => true,
                _ => return Err(invalid("invalid cgroup populated value")),
            });
        }
    }
    value.ok_or_else(|| invalid("cgroup.events lacks populated evidence"))
}

struct Cgroup {
    path: PathBuf,
    directory: File,
    identity: Identity,
    events: File,
    kill: File,
}

impl Cgroup {
    fn create(root: &Path) -> io::Result<Self> {
        let parent = open_directory(root)?;
        let parent_identity = Identity::of(&parent)?;
        if read_bounded(&control(&parent, "cgroup.type", false)?)?.trim() != "domain" {
            return Err(invalid(
                "root admission requires a cgroup-v2 domain delegation",
            ));
        }
        // Names are allocation identities only; create_dir is exclusive. Never
        // reopen an old attempt or infer ownership from a PID in its name.
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| invalid("clock precedes allocation epoch"))?
            .as_nanos();
        let name = format!("rabs-root-{}-{nonce}", std::process::id());
        rustix::fs::mkdirat(&parent, &name, Mode::RWXU)?;
        let path = root.join(name);
        if Identity::of(&open_directory(root)?)? != parent_identity {
            return Err(invalid("delegated root changed during creation"));
        }
        let directory = open_directory(&path)?;
        let identity = Identity::of(&directory)?;
        let events = control(&directory, "cgroup.events", false)?;
        let kill = control(&directory, "cgroup.kill", true)?;
        // Open write authority before reserving or spawning; a read-only or
        // incomplete delegation refuses without running a Cargo command.
        let _procs = control(&directory, "cgroup.procs", true)?;
        let group = Self {
            path,
            directory,
            identity,
            events,
            kill,
        };
        if group.populated()? {
            return Err(invalid("new root cgroup unexpectedly contains processes"));
        }
        Ok(group)
    }

    fn validate(&self) -> io::Result<()> {
        if Identity::of(&open_directory(&self.path)?)? != self.identity
            || Identity::of(&self.directory)? != self.identity
        {
            return Err(invalid(
                "root cgroup identity changed; capacity remains quarantined",
            ));
        }
        Ok(())
    }

    fn populated(&self) -> io::Result<bool> {
        self.validate()?;
        populated(&read_bounded(&self.events)?)
    }

    fn kill(&mut self) -> io::Result<()> {
        self.validate()?;
        self.kill.write_all(b"1\n")
    }

    fn signal(&self, signal: Signal, leader: Pid) -> io::Result<()> {
        self.validate()?;
        let raw = read_bounded(&control(&self.directory, "cgroup.procs", false)?)?;
        for line in raw.lines() {
            let pid = line
                .parse::<i32>()
                .ok()
                .and_then(Pid::from_raw)
                .ok_or_else(|| invalid("invalid cgroup process id"))?;
            if pid == leader {
                // The owner retains its leader pidfd before the trampoline
                // can attach; send through that descriptor exactly once.
                continue;
            }
            let descriptor = match pidfd_open(pid, PidfdFlags::empty()) {
                Ok(descriptor) => descriptor,
                Err(rustix::io::Errno::SRCH) => continue,
                Err(error) => return Err(error.into()),
            };
            // A proc-list PID can be recycled before pidfd_open. Verify the
            // pinned process still belongs to this group before sending it a
            // graceful signal; cgroup.kill is the bounded final tree cleanup.
            match process_cgroup(pid.as_raw_nonzero().get()) {
                Ok(path) if path == self.path => {}
                Ok(_) => continue,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error),
            }
            match pidfd_send_signal(&descriptor, signal) {
                Ok(()) | Err(rustix::io::Errno::SRCH) => {}
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }
}

fn signal_owned(descriptor: &rustix::fd::OwnedFd, signal: Signal) -> io::Result<()> {
    match pidfd_send_signal(descriptor, signal) {
        Ok(()) | Err(rustix::io::Errno::SRCH) => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn process_cgroup(pid: i32) -> io::Result<PathBuf> {
    let text = read_bounded(&File::open(format!("/proc/{pid}/cgroup"))?)?;
    let mut lines = text.lines();
    let line = lines
        .next()
        .ok_or_else(|| invalid("missing process cgroup"))?;
    if lines.next().is_some() {
        return Err(invalid("root admission requires unified cgroup v2"));
    }
    let path = line
        .strip_prefix("0::/")
        .ok_or_else(|| invalid("invalid process cgroup"))?;
    absolute_path(Path::new(CGROUP_MOUNT).join(path).into_os_string())
}

struct Signals {
    value: Arc<AtomicUsize>,
    registrations: Vec<signal_hook::SigId>,
}

impl Signals {
    fn install() -> io::Result<Self> {
        let mut signals = Self {
            value: Arc::new(AtomicUsize::new(0)),
            registrations: Vec::new(),
        };
        for signal in [SIGINT, SIGTERM, SIGHUP, SIGQUIT] {
            signals
                .registrations
                .push(signal_hook::flag::register_usize(
                    signal,
                    Arc::clone(&signals.value),
                    signal as usize,
                )?);
        }
        Ok(signals)
    }

    fn requested(&self) -> usize {
        self.value.load(Ordering::SeqCst)
    }
}

impl Drop for Signals {
    fn drop(&mut self) {
        for registration in self.registrations.drain(..) {
            signal_hook::low_level::unregister(registration);
        }
    }
}

/// Drop never releases an armed credit. It tries to stop owned effects; an
/// incomplete proof remains quarantined even if OS locks are later released.
struct Running {
    child: Option<Child>,
    group: Cgroup,
    complete: bool,
}

impl Drop for Running {
    fn drop(&mut self) {
        if !self.complete {
            let _ = self.group.kill();
            if let Some(child) = self.child.as_mut() {
                let _ = child.kill();
                let until = Instant::now() + Duration::from_secs(1);
                while matches!(child.try_wait(), Ok(None)) && Instant::now() < until {
                    std::thread::sleep(POLL);
                }
            }
        }
        if self.group.populated().is_ok_and(|populated| !populated) {
            // Kernel removes only an empty cgroup. There is no recursive file
            // cleanup or unlink of arbitrary user state behind this path.
            let _ = fs::remove_dir(&self.group.path);
        }
    }
}

fn requested_signal(value: usize) -> Signal {
    match value as i32 {
        SIGINT => Signal::INT,
        SIGHUP => Signal::HUP,
        SIGQUIT => Signal::QUIT,
        _ => Signal::TERM,
    }
}

fn supervise(config: &Config, command: &[OsString], signals: &Signals) -> io::Result<ExitStatus> {
    let group = Cgroup::create(&config.cgroup)?;
    let mut running = Running {
        child: None,
        group,
        complete: false,
    };
    let budget = HostBudget::open_root_count(&config.budget, config.capacity)?;
    let mut lease = budget.acquire(1, || signals.requested() != 0)?;
    lease.arm(running.group.identity.inode)?;
    if signals.requested() != 0 {
        lease.abandon_unstarted()?;
        return Ok(ExitStatus::from_raw(signals.requested() as i32));
    }
    let mut child = Command::new(std::env::current_exe()?);
    child
        .arg("--attach")
        .arg(&running.group.path)
        .arg(running.group.identity.device.to_string())
        .arg(running.group.identity.inode.to_string())
        .arg("--")
        .args(command)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    // Preserve the parent's group: inherited terminal access and jobserver
    // descriptors are Cargo's. Cgroup membership provides tree containment.
    running.child = Some(child.spawn()?);
    let leader = Pid::from_raw(running.child.as_ref().expect("spawned child retained").id() as i32)
        .ok_or_else(|| invalid("spawned Cargo trampoline has an invalid PID"))?;
    // Child has not been reaped, so its PID cannot be recycled before opening
    // this descriptor. It remains safe after reaping as well. Cancellation
    // must reach a trampoline which has not yet entered the new cgroup.
    let (leader_descriptor, mut status) = match pidfd_open(leader, PidfdFlags::empty()) {
        Ok(descriptor) => (Some(descriptor), None),
        Err(rustix::io::Errno::SRCH) => {
            let status = running
                .child
                .as_mut()
                .expect("spawned child retained")
                .try_wait()?
                .ok_or_else(|| {
                    invalid("Cargo disappeared before pidfd ownership was established")
                })?;
            (None, Some(status))
        }
        Err(error) => return Err(error.into()),
    };
    let mut stopping = None;
    let mut killed = false;
    loop {
        if status.is_none() {
            status = running
                .child
                .as_mut()
                .expect("spawned child retained")
                .try_wait()?;
        }
        let requested = signals.requested();
        if requested != 0 && stopping.is_none() {
            stopping = Some(Instant::now());
            // Unsupported pidfds or an unreadable process list trigger the
            // same cgroup-wide cleanup through Running's guard, not PID kills.
            let signal = requested_signal(requested);
            if let Some(descriptor) = &leader_descriptor {
                signal_owned(descriptor, signal)?;
            }
            running.group.signal(signal, leader)?;
        }
        if status.is_some() && !running.group.populated()? {
            break;
        }
        if !killed
            && (status.is_some() || stopping.is_some_and(|at: Instant| at.elapsed() >= GRACE))
        {
            if let Some(descriptor) = &leader_descriptor {
                signal_owned(descriptor, Signal::KILL)?;
            }
            running.group.kill()?;
            killed = true;
            stopping.get_or_insert_with(Instant::now);
        }
        if stopping.is_some_and(|at: Instant| at.elapsed() >= CLEANUP_BUDGET) {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "Cargo tree did not drain; its root credit remains quarantined",
            ));
        }
        std::thread::sleep(POLL);
    }
    running.group.validate()?;
    lease.finish(0)?;
    running.complete = true;
    Ok(if signals.requested() != 0 {
        ExitStatus::from_raw(signals.requested() as i32)
    } else {
        status.expect("Cargo was reaped before cgroup completion")
    })
}

fn attach_and_exec(args: &[OsString]) -> io::Result<()> {
    if args.len() < 5 || args[3] != "--" {
        return Err(invalid("invalid internal Cargo attachment command"));
    }
    let path = absolute_path(args[0].clone())?;
    if !path.starts_with(CGROUP_MOUNT) || path == Path::new(CGROUP_MOUNT) {
        return Err(invalid("attachment requires a child cgroup"));
    }
    let parse = |value: &OsString| -> io::Result<u64> {
        value
            .to_str()
            .and_then(|text| text.parse().ok())
            .ok_or_else(|| invalid("invalid attachment identity"))
    };
    let expected = Identity {
        device: parse(&args[1])?,
        inode: parse(&args[2])?,
    };
    let directory = open_directory(&path)?;
    if Identity::of(&directory)? != expected {
        return Err(invalid("Cargo attachment cgroup identity changed"));
    }
    control(&directory, "cgroup.procs", true)?
        .write_all(format!("{}\n", std::process::id()).as_bytes())?;
    let observed = open_directory(&process_cgroup(std::process::id() as i32)?)?;
    if Identity::of(&observed)? != expected || Identity::of(&open_directory(&path)?)? != expected {
        return Err(invalid("Cargo attachment was not enforced"));
    }
    let error = Command::new(&args[4])
        .args(&args[5..])
        // This marker prevents recursive admission; it is not authority and
        // must not expose a per-attempt inode to Cargo's build environment.
        .env(ACTIVE_ENV, "1")
        .exec();
    Err(error)
}

/// Native entry point. All command arguments remain OsString, including Cargo
/// target names and paths which are not UTF-8. No shell parses user arguments.
pub fn main_entry(args: Vec<OsString>) -> ! {
    if args.as_slice() == [OsString::from("--version")] {
        println!("rabs-cargo-root {}", env!("CARGO_PKG_VERSION"));
        std::process::exit(0);
    }
    if args.as_slice() == [OsString::from("--help")] {
        println!(
            "rabs-cargo-root -- CARGO [ARGS...]\n\
            Explicit Linux cgroup-v2 local root-count admission.\n\
            Set {BUDGET_ENV}, {CAPACITY_ENV} and {CGROUP_ENV} together.\n\
            Cargo argv, environment and jobserver are preserved; this is not a CPU limit."
        );
        std::process::exit(0);
    }
    if args.first().is_some_and(|arg| arg == "--attach") {
        let error = attach_and_exec(&args[1..]).expect_err("successful exec does not return");
        eprintln!("rabs-cargo-root: child attachment/exec: {error}");
        std::process::exit(127);
    }
    let result = (|| {
        if args.len() < 2 || args[0] != "--" {
            return Err(invalid("expected -- CARGO [ARGS...]"));
        }
        let config = Config::from_environment()?;
        let signals = Signals::install()?;
        match supervise(&config, &args[1..], &signals) {
            Err(error)
                if error.kind() == io::ErrorKind::Interrupted && signals.requested() != 0 =>
            {
                Ok(ExitStatus::from_raw(signals.requested() as i32))
            }
            result => result,
        }
    })();
    match result {
        Ok(status) => {
            if let Some(signal) = status.signal() {
                let _ = signal_hook::low_level::emulate_default_handler(signal);
                std::process::exit(128 + signal);
            }
            std::process::exit(status.code().unwrap_or(1));
        }
        Err(error) => {
            eprintln!("rabs-cargo-root: {error}");
            std::process::exit(2);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(capacity: &str) -> io::Result<Config> {
        Config::from_values([
            Some("/tmp/root-budget".into()),
            Some(capacity.into()),
            Some("/sys/fs/cgroup/delegated".into()),
        ])
    }

    #[test]
    fn configuration_is_explicit_and_canonical() {
        assert_eq!(config("2").unwrap().capacity, 2);
        for value in ["", "0", "+2", "02", " 2", "4097", "-1"] {
            assert!(config(value).is_err(), "{value}");
        }
        assert!(Config::from_values([None, None, None]).is_err());
        assert!(Config::from_values([Some("/tmp/budget".into()), Some("2".into()), None]).is_err());
        for path in ["relative", "/", "/tmp/../state"] {
            assert!(absolute_path(path.into()).is_err());
        }
    }

    #[test]
    fn only_complete_unique_populated_evidence_can_release() {
        assert!(!populated("populated 0\nfrozen 0\n").unwrap());
        assert!(populated("populated 1\nfrozen 0\n").unwrap());
        for text in [
            "",
            "frozen 0\n",
            "populated 0",
            "populated 2\n",
            "populated 0\npopulated 1\n",
            "populated 0 ignored\n",
        ] {
            assert!(populated(text).is_err(), "{text:?}");
        }
    }

    #[test]
    fn ordinary_filesystem_cannot_impersonate_cgroup_delegation() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(directory.path().join("cgroup.events"), "populated 0\n").unwrap();
        assert!(Cgroup::create(directory.path()).is_err());
    }

    #[test]
    fn pidfd_signal_targets_an_actual_owned_child() {
        let mut child = Command::new("sleep").arg("30").spawn().unwrap();
        let pid = Pid::from_raw(child.id() as i32).unwrap();
        let descriptor = pidfd_open(pid, PidfdFlags::empty()).unwrap();
        pidfd_send_signal(&descriptor, Signal::TERM).unwrap();
        assert_eq!(child.wait().unwrap().signal(), Some(SIGTERM));
        assert_eq!(
            pidfd_send_signal(&descriptor, Signal::TERM),
            Err(rustix::io::Errno::SRCH)
        );
    }

    #[test]
    fn cancellation_reaches_a_launcher_before_cgroup_attachment() {
        let directory = tempfile::tempdir().unwrap();
        let marker = directory.path().join("must-not-execute");
        let mut child = Command::new("sh")
            .args(["-c", "read ready; printf started > \"$1\"", "launcher"])
            .arg(&marker)
            .stdin(Stdio::piped())
            .spawn()
            .unwrap();
        let descriptor = pidfd_open(
            Pid::from_raw(child.id() as i32).unwrap(),
            PidfdFlags::empty(),
        )
        .unwrap();
        // No cgroup member exists yet: the exact retained child descriptor is
        // the only safe cancellation target before the attachment boundary.
        signal_owned(&descriptor, Signal::TERM).unwrap();
        assert_eq!(child.wait().unwrap().signal(), Some(SIGTERM));
        assert!(!marker.exists());
        signal_owned(&descriptor, Signal::KILL).unwrap();
    }
}
