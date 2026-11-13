//! Native disk reservation and execution supervisor.
//!
//! The guardian remains in the build's owned group while a separate process
//! performs admission, probes, scans, and receipt I/O. Filesystem stalls cannot
//! disable its heartbeat fence. A private lifetime pipe also revokes the group
//! when the guardian itself disappears. Neither process signals a historical
//! ledger PID; cancellation always uses its own current group membership.

use std::ffi::OsString;

#[cfg(unix)]
mod ledger;
#[cfg(unix)]
mod scan;

const EXIT_BUDGET: i32 = 120;

#[cfg(unix)]
pub(super) type Result<T> = std::result::Result<T, Failure>;

#[cfg(unix)]
#[derive(Debug, Clone)]
pub(super) struct Failure {
    pub reason: &'static str,
    pub free: u64,
    pub growth: u64,
    pub detail: String,
    pub required_growth_bytes: Option<u64>,
}

#[cfg(unix)]
impl Failure {
    pub fn new(reason: &'static str, free: u64, growth: u64, detail: impl Into<String>) -> Self {
        Self {
            reason,
            free,
            growth,
            detail: detail.into(),
            required_growth_bytes: None,
        }
    }

    pub fn unavailable(detail: impl Into<String>) -> Self {
        Self::new("monitor_unavailable", 0, 0, detail)
    }
}

#[cfg(unix)]
impl std::fmt::Display for Failure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.reason, self.detail)
    }
}

#[cfg(unix)]
impl std::error::Error for Failure {}

#[cfg(unix)]
impl From<std::io::Error> for Failure {
    fn from(error: std::io::Error) -> Self {
        Self::unavailable(error.to_string())
    }
}

#[cfg(unix)]
impl From<rustix::io::Errno> for Failure {
    fn from(error: rustix::io::Errno) -> Self {
        Self::unavailable(error.to_string())
    }
}

/// Synchronous entry point, before logging, runtimes, or worker child reapers.
pub fn main(arguments: &[OsString]) -> i32 {
    #[cfg(unix)]
    {
        match unix::run(arguments) {
            Ok(status) => status,
            Err(error) => {
                unix::diagnostic(format!("RCH_DISK_SUPERVISOR_UNAVAILABLE: {error}\n").as_bytes());
                EXIT_BUDGET
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = arguments;
        use std::io::Write as _;
        let _ = writeln!(
            std::io::stderr(),
            "RCH_DISK_SUPERVISOR_UNAVAILABLE: requires Unix process ownership"
        );
        EXIT_BUDGET
    }
}

#[cfg(unix)]
mod unix {
    use super::{EXIT_BUDGET, Failure, Result, ledger, scan};
    use std::collections::BTreeSet;
    use std::ffi::{OsStr, OsString};
    use std::fs::{File, OpenOptions};
    use std::io::{self, Read as _, Write as _};
    use std::os::fd::{AsRawFd as _, OwnedFd};
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
    use std::os::unix::process::ExitStatusExt as _;
    use std::path::{Path, PathBuf};
    use std::process::{Command, ExitStatus, Stdio};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, mpsc};
    use std::thread;
    use std::time::{Duration, Instant};

    use rustix::fs::{FileType, OFlags};
    use rustix::process::{Pid, Signal};
    use serde_json::{Value, json};

    const PROBE: &[u8] = b"rch-wkr disk-supervise v1\n";
    const INTERNAL: &str = "__supervise";
    const DISK_SUFFIX: &str = "_DISK_BUDGET:";
    const MAX_RECEIPT_BYTES: usize = 8192;
    const POLL: Duration = Duration::from_millis(250);
    const TASK_POLL: Duration = Duration::from_millis(25);
    const SCAN_INTERVAL: Duration = Duration::from_secs(2);

    #[derive(Clone)]
    struct Invocation {
        budget: u64,
        floor: u64,
        marker: String,
        target: PathBuf,
        probes: Vec<PathBuf>,
        outputs: Vec<PathBuf>,
        receipt: Option<PathBuf>,
        receipt_initialized: bool,
        timeout: Duration,
        warm: Option<Value>,
        cargo: Option<Value>,
        cargo_required: bool,
        strict: bool,
        standalone: bool,
        command: Vec<OsString>,
    }

    #[derive(Clone, Copy)]
    struct Timing {
        free: Duration,
        scan: Duration,
        heartbeat: Duration,
        reservation_lock: Duration,
        admission: Duration,
        finalization: Duration,
        bootstrap: Duration,
    }

    impl Timing {
        fn from_environment() -> Result<Self> {
            let scale = rch_common::timing::TimeoutsConfig::default()
                .with_environment()
                .map_err(|error| Failure::unavailable(error.to_string()))?
                .scale;
            rch_common::timing::install(scale);
            let duration = |seconds| scale.duration(Duration::from_secs(seconds));
            Ok(Self {
                free: duration(1),
                scan: duration(30),
                heartbeat: duration(3),
                reservation_lock: duration(2),
                admission: duration(5),
                finalization: duration(2),
                bootstrap: duration(40),
            })
        }
    }

    fn unsigned(argument: &OsStr, positive: bool) -> Result<u64> {
        let value = argument
            .to_str()
            .filter(|value| !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()))
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|value| *value <= i64::MAX as u64 && (!positive || *value != 0));
        value.ok_or_else(|| Failure::unavailable("invalid bounded unsigned decimal argument"))
    }

    fn text(argument: &OsStr) -> Result<&str> {
        argument
            .to_str()
            .ok_or_else(|| Failure::unavailable("disk protocol argument is not UTF-8"))
    }

    fn absolute(value: &Value) -> Result<PathBuf> {
        let value = value
            .as_str()
            .ok_or_else(|| Failure::unavailable("disk path is not a string"))?;
        if value.contains('\0') || !Path::new(value).is_absolute() {
            return Err(Failure::unavailable("disk paths must be absolute"));
        }
        Ok(PathBuf::from(value))
    }

    fn path_list(plan: &Value, name: &str) -> Result<Vec<PathBuf>> {
        plan.get(name)
            .and_then(Value::as_array)
            .filter(|values| !values.is_empty() && values.len() <= 64)
            .ok_or_else(|| Failure::unavailable("invalid disk path plan"))?
            .iter()
            .map(absolute)
            .collect()
    }

    fn flag(plan: &Value, name: &str) -> Result<bool> {
        match plan.get(name) {
            None => Ok(false),
            Some(Value::Bool(value)) => Ok(*value),
            _ => Err(Failure::unavailable(format!("invalid {name} flag"))),
        }
    }

    impl Invocation {
        fn parse(arguments: &[OsString]) -> Result<Self> {
            let [budget, floor, marker, target, plan, mode, command @ ..] = arguments else {
                return Err(Failure::unavailable(
                    "expected budget, floor, marker, target, plan, mode and command",
                ));
            };
            if command.is_empty() {
                return Err(Failure::unavailable(
                    "a disk-supervised command is required",
                ));
            }
            let marker = text(marker)?;
            if marker.chars().count() > 160
                || !marker.ends_with(DISK_SUFFIX)
                || marker
                    .chars()
                    .any(|ch| ch.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&ch))
            {
                return Err(Failure::unavailable("invalid disk receipt marker"));
            }
            let plan: Value = serde_json::from_str(text(plan)?)
                .map_err(|error| Failure::unavailable(format!("invalid disk plan: {error}")))?;
            if !plan.is_object() {
                return Err(Failure::unavailable("disk plan must be an object"));
            }
            let receipt = match plan.get("receipt") {
                None | Some(Value::Null) => None,
                Some(value) => Some(absolute(value)?),
            };
            let seconds = match plan.get("timeout_seconds") {
                None => 0,
                Some(value) => value
                    .as_u64()
                    .filter(|value| *value <= i64::MAX as u64)
                    .ok_or_else(|| Failure::unavailable("invalid execution deadline"))?,
            };
            let standalone = match text(mode)? {
                "standalone" => true,
                "tracked" => false,
                _ => return Err(Failure::unavailable("invalid build supervisor mode")),
            };
            Ok(Self {
                budget: unsigned(budget, true)?,
                floor: unsigned(floor, false)?,
                marker: marker.to_owned(),
                target: absolute(&Value::String(text(target)?.to_owned()))?,
                probes: path_list(&plan, "probe")?,
                outputs: path_list(&plan, "output")?,
                receipt,
                receipt_initialized: flag(&plan, "receipt_initialized")?,
                timeout: Duration::from_secs(seconds),
                warm: plan.get("warm_policy").cloned(),
                cargo: plan.get("cargo_cache").cloned(),
                cargo_required: flag(&plan, "cargo_cache_required")?,
                strict: flag(&plan, "require_incremental_tracking")?,
                standalone,
                command: command.to_vec(),
            })
        }

        fn prefix(&self) -> &str {
            self.marker
                .strip_suffix(DISK_SUFFIX)
                .expect("validated marker")
        }
    }

    pub(super) fn run(arguments: &[OsString]) -> Result<i32> {
        if arguments.len() == 1 && arguments[0] == "probe" {
            io::stdout().lock().write_all(PROBE)?;
            return Ok(0);
        }
        let timing = Timing::from_environment()?;
        if arguments
            .first()
            .is_some_and(|argument| argument == INTERNAL)
        {
            return supervisor_entry(&arguments[1..], timing);
        }
        let invocation = Invocation::parse(arguments)?;
        guardian(&invocation, arguments, timing)
    }

    struct SignalState {
        interrupted: Arc<AtomicUsize>,
        registrations: Vec<signal_hook::SigId>,
    }

    impl SignalState {
        fn new() -> Result<Self> {
            let interrupted = Arc::new(AtomicUsize::new(0));
            let mut registrations = Vec::new();
            for number in [
                signal_hook::consts::SIGHUP,
                signal_hook::consts::SIGINT,
                signal_hook::consts::SIGTERM,
            ] {
                registrations.push(signal_hook::flag::register_usize(
                    number,
                    Arc::clone(&interrupted),
                    number as usize,
                )?);
            }
            // Clear inherited SIG_IGN/SA_NOCLDWAIT before any child creation.
            // The caught disposition becomes default on the supervisor exec.
            registrations.push(signal_hook::flag::register_usize(
                signal_hook::consts::SIGCHLD,
                Arc::new(AtomicUsize::new(0)),
                1,
            )?);
            Ok(Self {
                interrupted,
                registrations,
            })
        }

        fn check(&self) -> Result<()> {
            let number = self.interrupted.load(Ordering::Relaxed);
            if number == 0 {
                Ok(())
            } else {
                Err(Failure::new(
                    "interrupted",
                    0,
                    0,
                    format!("supervisor received signal {number}"),
                ))
            }
        }
    }

    impl Drop for SignalState {
        fn drop(&mut self) {
            for registration in self.registrations.drain(..) {
                signal_hook::low_level::unregister(registration);
            }
        }
    }

    fn own_group() -> Result<u32> {
        let group = rustix::process::getpgrp().as_raw_nonzero().get();
        if group <= 1 {
            return Err(Failure::unavailable("build has no isolated process group"));
        }
        Ok(group as u32)
    }

    fn kill_group(group: u32) -> ! {
        if own_group().ok() == Some(group)
            && let Some(pid) = i32::try_from(group).ok().and_then(Pid::from_raw)
        {
            let _ = rustix::process::kill_process_group(pid, Signal::KILL);
        }
        std::process::exit(EXIT_BUDGET);
    }

    /// Supplemental diagnostics must never block a cancellation fence or
    /// change the shared stderr open description permanently.
    pub(super) fn diagnostic(bytes: &[u8]) {
        let stderr = rustix::stdio::stderr();
        if let Ok(flags) = rustix::fs::fcntl_getfl(stderr)
            && rustix::fs::fcntl_setfl(stderr, flags | OFlags::NONBLOCK).is_ok()
        {
            let _ = rustix::io::write(stderr, &bytes[..bytes.len().min(MAX_RECEIPT_BYTES + 1)]);
            let _ = rustix::fs::fcntl_setfl(stderr, flags);
        }
    }

    fn inherit(fd: &OwnedFd) -> Result<OwnedFd> {
        let inherited = rustix::io::fcntl_dupfd_cloexec(fd, 64)?;
        rustix::io::fcntl_setfd(&inherited, rustix::io::FdFlags::empty())?;
        Ok(inherited)
    }

    fn guardian(invocation: &Invocation, original: &[OsString], timing: Timing) -> Result<i32> {
        if invocation.standalone {
            nix::unistd::setsid().map_err(|error| Failure::unavailable(error.to_string()))?;
        }
        let group = own_group()?;
        let parent = rustix::process::getppid();
        let signals = SignalState::new()?;
        let (progress_read, progress_write) = rustix::pipe::pipe_with(
            rustix::pipe::PipeFlags::CLOEXEC | rustix::pipe::PipeFlags::NONBLOCK,
        )?;
        let (owner_read, owner_write) = rustix::pipe::pipe_with(
            rustix::pipe::PipeFlags::CLOEXEC | rustix::pipe::PipeFlags::NONBLOCK,
        )?;
        let inherited_progress = inherit(&progress_write)?;
        let inherited_owner = inherit(&owner_read)?;
        let mut child = Command::new(crate::native_worker_executable()?)
            .args([OsStr::new("disk-supervise"), OsStr::new(INTERNAL)])
            .arg(inherited_progress.as_raw_fd().to_string())
            .arg(inherited_owner.as_raw_fd().to_string())
            .arg(std::process::id().to_string())
            .arg(group.to_string())
            .args(original)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .envs(rch_common::MANAGED_CARGO_ENV)
            .spawn()?;
        drop(inherited_progress);
        drop(inherited_owner);
        drop(progress_write);
        drop(owner_read);
        let _lifetime = owner_write;
        let mut progress = File::from(progress_read);
        let mut last_heartbeat = Instant::now();
        let mut started = false;
        let mut completed = false;
        let mut bytes = [0; 4096];
        let stop = |reason: &str, started: bool, detail: Value| -> ! {
            let mut value = json!({"reason": reason, "started": started});
            if let (Some(value), Some(detail)) = (value.as_object_mut(), detail.as_object()) {
                value.extend(detail.clone());
            }
            if let Ok(receipt) = diagnostic_receipt(&[(
                format!("{}_DISK_GUARDIAN:", invocation.prefix()),
                Some(value),
            )]) {
                diagnostic(&receipt);
            }
            kill_group(group)
        };
        loop {
            match progress.read(&mut bytes) {
                Ok(count) if count > 0 => {
                    started |= bytes[..count].contains(&b'S');
                    completed |= bytes[..count].contains(&b'C');
                    last_heartbeat = Instant::now();
                }
                Ok(_) => {}
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) => {}
                Err(_) => stop("supervisor_exit_unconfirmed", started, json!({})),
            }
            let status = match child.try_wait() {
                Ok(status) => status,
                Err(_) => stop("supervisor_exit_unconfirmed", started, json!({})),
            };
            if let Some(status) = status {
                if status.code().is_none() {
                    stop(
                        "supervisor_exit_unconfirmed",
                        started,
                        json!({"wait_status": status.into_raw()}),
                    );
                }
                // Normal exit can race the preceding read. Completion must
                // survive a full heartbeat backlog within one finite window.
                let deadline = Instant::now() + timing.heartbeat;
                while !completed && Instant::now() < deadline {
                    if signals.check().is_err() || rustix::process::getppid() != parent {
                        stop("cancelled", started, json!({}));
                    }
                    match progress.read(&mut bytes) {
                        Ok(0) => break,
                        Ok(count) => {
                            started |= bytes[..count].contains(&b'S');
                            completed |= bytes[..count].contains(&b'C');
                        }
                        Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                        Err(_) => stop("supervisor_exit_unconfirmed", started, json!({})),
                    }
                }
                if signals.check().is_err() || rustix::process::getppid() != parent {
                    stop("cancelled", started, json!({}));
                }
                if completed && Instant::now() < deadline {
                    return Ok(status.code().expect("normal supervisor exit"));
                }
                stop(
                    "supervisor_exit_unconfirmed",
                    started,
                    json!({"wait_status": status.into_raw()}),
                );
            }
            let age = last_heartbeat.elapsed();
            let reason = if signals.check().is_err() {
                Some("cancelled")
            } else if rustix::process::getppid() != parent {
                Some("parent_lost")
            } else if age
                > if started {
                    timing.heartbeat
                } else {
                    timing.bootstrap
                }
            {
                Some("heartbeat_timeout")
            } else {
                None
            };
            if let Some(reason) = reason {
                stop(
                    reason,
                    started,
                    json!({"heartbeat_age_seconds": age.as_secs_f64()}),
                );
            }
            thread::sleep(Duration::from_millis(100));
        }
    }

    fn inherited_number(argument: &OsStr) -> Result<i32> {
        let value = unsigned(argument, true)?;
        i32::try_from(value)
            .ok()
            .filter(|value| *value >= 64)
            .ok_or_else(|| Failure::unavailable("invalid private disk supervisor descriptor"))
    }

    fn close_unrelated_inherited(keep: &[i32]) -> Result<()> {
        let directory = if cfg!(target_os = "linux") {
            "/proc/self/fd"
        } else {
            "/dev/fd"
        };
        // Collect and drop read_dir before closing: no Rust-owned descriptors
        // exist here yet besides stdio, and the two explicit inherited pipes.
        let descriptors: Vec<i32> = std::fs::read_dir(directory)?
            .map(|entry| entry.map(|entry| entry.file_name()))
            .collect::<io::Result<Vec<_>>>()?
            .into_iter()
            .filter_map(|name| name.to_str().and_then(|name| name.parse().ok()))
            .filter(|fd| *fd > 2 && !keep.contains(fd))
            .collect();
        for descriptor in descriptors {
            if let Err(error) = nix::unistd::close(descriptor)
                && error != nix::errno::Errno::EBADF
            {
                return Err(Failure::unavailable(error.to_string()));
            }
        }
        Ok(())
    }

    fn take_pipe(descriptor: i32, writable: bool) -> Result<File> {
        let path = if cfg!(target_os = "linux") {
            format!("/proc/self/fd/{descriptor}")
        } else {
            format!("/dev/fd/{descriptor}")
        };
        let pipe = OpenOptions::new()
            .read(!writable)
            .write(writable)
            .custom_flags(OFlags::NONBLOCK.bits() as i32)
            .open(path)?;
        if FileType::from_raw_mode(rustix::fs::fstat(&pipe)?.st_mode) != FileType::Fifo {
            return Err(Failure::unavailable(
                "disk supervisor handoff is not a pipe",
            ));
        }
        nix::unistd::close(descriptor).map_err(|error| Failure::unavailable(error.to_string()))?;
        Ok(pipe)
    }

    #[derive(Clone)]
    struct Heartbeat {
        writer: Arc<File>,
        guardian: u32,
        group: u32,
    }

    impl Heartbeat {
        fn owner(&self) -> Result<()> {
            if rustix::process::getppid().map(|pid| pid.as_raw_nonzero().get() as u32)
                != Some(self.guardian)
                || own_group()? != self.group
            {
                return Err(Failure::new(
                    "interrupted",
                    0,
                    0,
                    "disk guardian disappeared",
                ));
            }
            Ok(())
        }

        fn progress(&self, byte: u8) -> Result<()> {
            self.owner()?;
            match rustix::io::write(&*self.writer, &[byte]) {
                Ok(1) | Err(rustix::io::Errno::AGAIN | rustix::io::Errno::INTR) => Ok(()),
                Ok(_) => Err(Failure::unavailable("short disk heartbeat write")),
                Err(error) => Err(error.into()),
            }
        }

        fn deliver(&self, byte: u8, allowance: Duration) -> Result<()> {
            let deadline = Instant::now() + allowance;
            loop {
                self.owner()?;
                if Instant::now() >= deadline {
                    return Err(Failure::unavailable(
                        "completion acknowledgement deadline reached",
                    ));
                }
                match rustix::io::write(&*self.writer, &[byte]) {
                    Ok(1) => {
                        self.owner()?;
                        if Instant::now() >= deadline {
                            return Err(Failure::unavailable(
                                "completion acknowledgement remained unconfirmed",
                            ));
                        }
                        return Ok(());
                    }
                    Err(rustix::io::Errno::AGAIN | rustix::io::Errno::INTR) => thread::sleep(
                        TASK_POLL.min(deadline.saturating_duration_since(Instant::now())),
                    ),
                    _ => {
                        return Err(Failure::unavailable(
                            "completion acknowledgement remained unconfirmed",
                        ));
                    }
                }
            }
        }
    }

    fn supervisor_entry(arguments: &[OsString], timing: Timing) -> Result<i32> {
        let [progress, lifetime, guardian, group, original @ ..] = arguments else {
            return Err(Failure::unavailable("incomplete disk supervisor handoff"));
        };
        let progress = inherited_number(progress)?;
        let lifetime = inherited_number(lifetime)?;
        if progress == lifetime {
            return Err(Failure::unavailable("aliased disk supervisor pipes"));
        }
        let guardian = u32::try_from(unsigned(guardian, true)?)
            .map_err(|_| Failure::unavailable("invalid guardian PID"))?;
        let group = u32::try_from(unsigned(group, true)?)
            .map_err(|_| Failure::unavailable("invalid owned group"))?;
        if group <= 1 || own_group()? != group || guardian <= 1 {
            return Err(Failure::unavailable(
                "disk supervisor lost its group handoff",
            ));
        }
        close_unrelated_inherited(&[progress, lifetime])?;
        let progress = take_pipe(progress, true)?;
        let mut lifetime = take_pipe(lifetime, false)?;
        let heartbeat = Heartbeat {
            writer: Arc::new(progress),
            guardian,
            group,
        };
        heartbeat.owner()?;
        // This thread remains runnable while admission/receipt I/O is stuck.
        // The pipe has no workload writer, so EOF proves guardian death.
        thread::Builder::new()
            .name("rch-disk-owner".into())
            .spawn(move || {
                let mut byte = [0];
                loop {
                    match lifetime.read(&mut byte) {
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            thread::sleep(TASK_POLL)
                        }
                        Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                        _ => kill_group(group),
                    }
                }
            })?;
        let mut child_signal = nix::sys::signal::SigSet::empty();
        child_signal.add(nix::sys::signal::Signal::SIGCHLD);
        child_signal
            .thread_unblock()
            .map_err(|error| Failure::unavailable(error.to_string()))?;
        let signals = SignalState::new()?;
        let invocation = Invocation::parse(original)?;
        let status = supervise(&invocation, &heartbeat, timing, &signals);
        if signals.check().is_err()
            || heartbeat.deliver(b'C', timing.heartbeat).is_err()
            || signals.check().is_err()
        {
            // C may already be queued. Pair it only with normal completion;
            // abnormal exit must make the guardian revoke its whole group.
            kill_group(group);
        }
        Ok(status)
    }

    struct Pending<T> {
        receiver: mpsc::Receiver<(Result<T>, Instant)>,
        deadline: Instant,
        description: &'static str,
    }

    impl<T: Send + 'static> Pending<T> {
        fn spawn(
            allowance: Duration,
            description: &'static str,
            operation: impl FnOnce() -> Result<T> + Send + 'static,
        ) -> Result<Self> {
            let deadline = Instant::now() + allowance;
            let (sender, receiver) = mpsc::sync_channel(1);
            thread::Builder::new()
                .name("rch-disk-probe".into())
                .spawn(move || {
                    let result = operation();
                    let _ = sender.send((result, Instant::now()));
                })?;
            Ok(Self {
                receiver,
                deadline,
                description,
            })
        }

        fn ready(&self) -> Result<Option<T>> {
            match self.receiver.try_recv() {
                // Bound the operation, not the supervisor's consumption time.
                // A sample completed on time may wait behind another final
                // check; accepting a genuinely late probe would erase its cap.
                Ok((result, completed)) if completed < self.deadline => result.map(Some),
                Ok(_) => Err(Failure::unavailable(self.description)),
                Err(mpsc::TryRecvError::Empty) if Instant::now() < self.deadline => Ok(None),
                Err(mpsc::TryRecvError::Empty) => Err(Failure::unavailable(self.description)),
                Err(mpsc::TryRecvError::Disconnected) => Err(Failure::unavailable(
                    "disk sampler terminated without a result",
                )),
            }
        }

        fn wait(self, heartbeat: &Heartbeat, signals: &SignalState) -> Result<T> {
            loop {
                heartbeat.progress(b'H')?;
                signals.check()?;
                if let Some(result) = self.ready()? {
                    return Ok(result);
                }
                thread::sleep(TASK_POLL);
            }
        }
    }

    struct Owner {
        boot: String,
        start: String,
        group: u32,
        guardian: u32,
        controls: BTreeSet<u32>,
    }

    fn initialize(
        invocation: Invocation,
        heartbeat: Heartbeat,
    ) -> Result<(Arc<scan::Scanner>, Owner)> {
        let boot = ledger::boot_identity()?;
        let snapshot = ledger::process_snapshot(&mut || heartbeat.progress(b'H'))?;
        let start = ledger::leader_start(heartbeat.group, &snapshot, &boot)?;
        let mut controls = BTreeSet::new();
        let mut parent = std::process::id();
        while let Some(record) = snapshot.get(&parent) {
            if record.group != heartbeat.group || !controls.insert(parent) {
                break;
            }
            parent = record.parent;
        }
        let scanner = scan::Scanner::new(
            &invocation.target,
            &invocation.probes,
            &invocation.outputs,
            invocation.cargo.as_ref(),
            &boot,
        )?;
        Ok((
            Arc::new(scanner),
            Owner {
                boot,
                start,
                group: heartbeat.group,
                guardian: heartbeat.guardian,
                controls,
            },
        ))
    }

    fn finish_descendants(owner: &Owner, heartbeat: &Heartbeat, allowance: Duration) -> Result<()> {
        let mut deadline = None;
        loop {
            heartbeat.progress(b'H')?;
            ledger::check_owner(owner.group, &owner.boot, &owner.start, owner.guardian)?;
            let snapshot = ledger::process_snapshot(&mut || heartbeat.progress(b'H'))?;
            let descendants: Vec<_> = snapshot
                .values()
                .filter(|record| {
                    record.group == owner.group
                        && !owner.controls.contains(&record.pid)
                        && record.is_alive()
                })
                .collect();
            if descendants.is_empty() {
                return Ok(());
            }
            // A progressing initial census may be slow. Start the writer exit
            // window only after discovery, retaining the stalled-read fence.
            let deadline = *deadline.get_or_insert_with(|| Instant::now() + allowance);
            for descendant in descendants {
                ledger::kill_descendant(descendant, owner.group)?;
            }
            if Instant::now() >= deadline {
                return Err(Failure::unavailable(
                    "background build writers did not stop",
                ));
            }
            thread::sleep(TASK_POLL);
        }
    }

    fn private_regular(file: &File) -> Result<()> {
        let info = file.metadata()?;
        if !info.is_file()
            || info.uid() != rustix::process::getuid().as_raw()
            || info.mode() & 0o077 != 0
        {
            return Err(Failure::unavailable("unsafe worker accounting file"));
        }
        Ok(())
    }

    fn claim_receipt(invocation: &Invocation) -> Result<bool> {
        let Some(path) = &invocation.receipt else {
            return Ok(false);
        };
        if invocation.receipt_initialized {
            let mut file = OpenOptions::new()
                .read(true)
                .custom_flags((OFlags::NOFOLLOW | OFlags::NONBLOCK).bits() as i32)
                .open(path)?;
            private_regular(&file)?;
            let mut bytes = Vec::new();
            (&mut file)
                .take((MAX_RECEIPT_BYTES + 1) as u64)
                .read_to_end(&mut bytes)?;
            if bytes != format!("{}\n", invocation.marker).as_bytes() {
                return Err(Failure::unavailable(
                    "disk receipt initialization does not match this attempt",
                ));
            }
        } else {
            let file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(OFlags::NOFOLLOW.bits() as i32)
                .open(path)?;
            private_regular(&file)?;
        }
        Ok(true)
    }

    fn receipt_text(receipts: &[(String, Option<Value>)]) -> Result<Vec<u8>> {
        let mut output = Vec::new();
        for (marker, value) in receipts {
            output.extend_from_slice(marker.as_bytes());
            if let Some(value) = value {
                serde_json::to_writer(&mut output, value)
                    .map_err(|error| Failure::unavailable(error.to_string()))?;
            }
            output.push(b'\n');
        }
        if output.len() > MAX_RECEIPT_BYTES {
            return Err(Failure::unavailable("disk receipt exceeds its size limit"));
        }
        Ok(output)
    }

    fn diagnostic_receipt(receipts: &[(String, Option<Value>)]) -> Result<Vec<u8>> {
        let mut bytes = receipt_text(receipts)?;
        // Workload stderr may finish without a newline. Keep protocol markers
        // on their own line even when this is the only surviving diagnostic.
        bytes.insert(0, b'\n');
        Ok(bytes)
    }

    fn persist_receipt(path: &Path, receipts: &[(String, Option<Value>)]) -> Result<()> {
        let bytes = receipt_text(receipts)?;
        let parent = path
            .parent()
            .ok_or_else(|| Failure::unavailable("disk receipt has no parent"))?;
        let mut file = tempfile::Builder::new()
            .prefix(".disk-receipt-")
            .tempfile_in(parent)?;
        file.write_all(&bytes)?;
        file.flush()?;
        file.as_file().sync_all()?;
        file.persist(path)
            .map_err(|error| Failure::unavailable(error.to_string()))?;
        Ok(())
    }

    fn failure_receipts(
        invocation: &Invocation,
        failure: &Failure,
        started: bool,
        accounting: Option<&scan::Accounting>,
        peak: Option<u64>,
    ) -> Vec<(String, Option<Value>)> {
        let mut receipts = if failure.reason == "deadline" {
            vec![(invocation.prefix().to_owned(), None)]
        } else {
            let mut value = json!({
                "reason": failure.reason, "free_bytes": failure.free, "growth_bytes": failure.growth,
                "max_growth_bytes": invocation.budget, "min_free_bytes": invocation.floor,
                "started": started, "detail": failure.detail.chars().take(240).collect::<String>(),
                "peak_output_bytes": accounting.map(|accounting| accounting.peak_output).or(peak),
            });
            if failure.reason == "cold_required" {
                value["required_growth_bytes"] = json!(failure.required_growth_bytes);
            }
            vec![(invocation.marker.clone(), Some(value))]
        };
        if (started || failure.reason == "deadline")
            && let Some(accounting) = accounting
        {
            receipts.push((
                format!("{}_DISK_USAGE:", invocation.prefix()),
                Some(accounting.usage(false, None)),
            ));
        }
        receipts
    }

    fn exit_code(status: ExitStatus) -> i32 {
        status
            .code()
            .or_else(|| status.signal().map(|signal| 128 + signal))
            .unwrap_or(EXIT_BUDGET)
    }

    fn supervise(
        invocation: &Invocation,
        heartbeat: &Heartbeat,
        timing: Timing,
        signals: &SignalState,
    ) -> i32 {
        let mut started = false;
        let mut receipt_owned = false;
        let mut accounting = None;
        let mut initial_peak = None;
        let operation = (|| -> Result<i32> {
            receipt_owned = claim_receipt(invocation)?;
            scan::validate_warm_policy(invocation.warm.as_ref(), invocation.budget)?;
            scan::validate_cargo_cache_plan(invocation.cargo.as_ref(), invocation.cargo_required)?;
            let initial_invocation = invocation.clone();
            let initial_heartbeat = heartbeat.clone();
            let (scanner, owner) = Pending::spawn(
                timing.scan,
                "disk probe or scan deadline reached",
                move || initialize(initial_invocation, initial_heartbeat),
            )?
            .wait(heartbeat, signals)?;
            initial_peak = Some(scanner.baseline_output_bytes());
            accounting = Some(scan::Accounting::new(
                invocation.budget,
                invocation.floor,
                &scanner,
                invocation.warm.as_ref(),
                invocation.strict,
            )?);
            let reservation = ledger::Reservation {
                boot: owner.boot.clone(),
                group: owner.group,
                leader_start: owner.start.clone(),
                devices: scanner.devices.clone(),
                budget: invocation.budget,
                floor: invocation.floor,
            };
            let admitted_scanner = Arc::clone(&scanner);
            let admission_heartbeat = heartbeat.clone();
            let admission = Pending::spawn(
                timing.admission,
                "disk probe or scan deadline reached",
                move || {
                    ledger::Registry::open(timing.reservation_lock)?.admit(
                        &reservation,
                        || admitted_scanner.sample(),
                        || admission_heartbeat.progress(b'H'),
                    )
                },
            )?
            .wait(heartbeat, signals)?;
            let accounting = accounting.as_mut().expect("initialized accounting");
            accounting.admit(admission.free, admission.floors, admission.sampled_at);
            signals.check()?;
            // Mark potentially started BEFORE spawn. A partial exec handoff or
            // interruption must never become permission to replay a workload.
            started = true;
            // A full heartbeat pipe may coalesce H, but must never lose S:
            // the guardian needs the shorter running-workload deadline before
            // any command can start.
            heartbeat.deliver(b'S', timing.heartbeat)?;
            let execution_started = Instant::now();
            let mut child = Command::new(&invocation.command[0])
                .args(&invocation.command[1..])
                .stdin(Stdio::inherit())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .envs(rch_common::MANAGED_CARGO_ENV)
                .spawn()?;
            let sample = |scanner: Arc<scan::Scanner>| {
                Pending::spawn(timing.free, "free-space telemetry deadline", move || {
                    scanner.sample()
                })
            };
            let scan = |scanner: Arc<scan::Scanner>| {
                Pending::spawn(timing.scan, "output scan deadline", move || scanner.scan())
            };
            let mut free = sample(Arc::clone(&scanner))?;
            let mut output = Some(scan(Arc::clone(&scanner))?);
            let mut next_scan = Instant::now() + SCAN_INTERVAL;
            let status = loop {
                if let Some(status) = child.try_wait()? {
                    break status;
                }
                heartbeat.progress(b'H')?;
                signals.check()?;
                ledger::check_owner(owner.group, &owner.boot, &owner.start, owner.guardian)?;
                if !invocation.timeout.is_zero()
                    && execution_started.elapsed() >= invocation.timeout
                {
                    return Err(Failure::new(
                        "deadline",
                        0,
                        0,
                        "remote execution deadline reached",
                    ));
                }
                if let Some((samples, at)) = free.ready()? {
                    accounting.observe_free(samples, at)?;
                    free = sample(Arc::clone(&scanner))?;
                }
                if let Some(pending) = output.as_ref()
                    && let Some(observation) = pending.ready()?
                {
                    accounting.observe_output(observation)?;
                    output = None;
                }
                if output.is_none() && Instant::now() >= next_scan {
                    output = Some(scan(Arc::clone(&scanner))?);
                    next_scan = Instant::now() + SCAN_INTERVAL;
                }
                thread::sleep(POLL);
            };
            finish_descendants(&owner, heartbeat, timing.finalization)?;
            let (samples, at) = free.wait(heartbeat, signals)?;
            accounting.observe_free(samples, at)?;
            if let Some(output) = output {
                accounting.observe_output(output.wait(heartbeat, signals)?)?;
            }
            accounting.observe_output(scan(Arc::clone(&scanner))?.wait(heartbeat, signals)?)?;
            // Only a new probe AFTER stopped writers and the final scan can
            // attest the terminal filesystem floor.
            let (samples, at) = sample(scanner)?.wait(heartbeat, signals)?;
            accounting.observe_free(samples, at)?;
            let code = exit_code(status);
            let receipts = vec![(
                format!("{}_DISK_USAGE:", invocation.prefix()),
                Some(accounting.usage(true, Some(code))),
            )];
            if receipt_owned {
                persist_receipt(
                    invocation.receipt.as_ref().expect("owned receipt"),
                    &receipts,
                )?;
            }
            diagnostic(&diagnostic_receipt(&receipts)?);
            Ok(code)
        })();
        match operation {
            Ok(code) => code,
            Err(failure) => {
                let receipts = failure_receipts(
                    invocation,
                    &failure,
                    started,
                    accounting.as_ref(),
                    initial_peak,
                );
                // Failure diagnostics precede possibly blocked fsync. They
                // cannot acknowledge completion; the guardian still fences it.
                if let Ok(bytes) = diagnostic_receipt(&receipts) {
                    diagnostic(&bytes);
                }
                if receipt_owned {
                    let _ = persist_receipt(
                        invocation.receipt.as_ref().expect("owned receipt"),
                        &receipts,
                    );
                }
                if started {
                    kill_group(heartbeat.group);
                }
                EXIT_BUDGET
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::os::unix::ffi::OsStringExt as _;

        fn arguments(plan: Value) -> Vec<OsString> {
            [
                "1048576".into(),
                "0".into(),
                "RCH_TEST_DISK_BUDGET:".into(),
                "/outputs".into(),
                plan.to_string(),
                "tracked".into(),
                "/bin/true".into(),
            ]
            .into_iter()
            .map(OsString::from)
            .collect()
        }

        fn plan() -> Value {
            json!({"probe": ["/outputs"], "output": ["/outputs"], "receipt": null})
        }

        #[test]
        fn command_arguments_remain_bytes_and_zero_floor_remains_valid() {
            let mut argv = arguments(plan());
            let binary = OsString::from_vec(b"literal argument\xff\n".to_vec());
            argv.push(binary.clone());
            let parsed = Invocation::parse(&argv).unwrap();
            assert_eq!(parsed.floor, 0);
            assert_eq!(parsed.command, [OsString::from("/bin/true"), binary]);
            assert!(!parsed.standalone);
            assert!(parsed.timeout.is_zero());
        }

        #[test]
        fn malformed_plans_and_integer_domains_refuse_before_execution() {
            let base = plan();
            for (field, value) in [
                ("probe", json!([])),
                ("output", json!(["relative"])),
                ("output", json!(["/bad\u{0}path"])),
                ("receipt", json!("relative")),
                ("timeout_seconds", json!(true)),
                ("timeout_seconds", json!(-1)),
                ("timeout_seconds", json!(1.0)),
                ("receipt_initialized", Value::Null),
                ("require_incremental_tracking", json!(1)),
                ("cargo_cache_required", json!("yes")),
            ] {
                let mut candidate = base.clone();
                candidate[field] = value;
                assert!(Invocation::parse(&arguments(candidate)).is_err(), "{field}");
            }
            for budget in ["0", "-1", "9223372036854775808", "18446744073709551616"] {
                let mut argv = arguments(base.clone());
                argv[0] = budget.into();
                assert!(Invocation::parse(&argv).is_err(), "{budget}");
            }
            for marker in ["plain", "RCH TEST_DISK_BUDGET:", "RCH\n_DISK_BUDGET:"] {
                let mut argv = arguments(base.clone());
                argv[2] = marker.into();
                assert!(Invocation::parse(&argv).is_err(), "{marker:?}");
            }
        }

        #[test]
        fn initialized_receipt_is_exact_private_and_cannot_replay_completion() {
            let fixture = tempfile::tempdir().unwrap().keep();
            let receipt = fixture.join("receipt");
            let mut value = plan();
            value["receipt"] = json!(receipt);
            let mut invocation = Invocation::parse(&arguments(value)).unwrap();
            assert!(claim_receipt(&invocation).unwrap());
            assert!(
                claim_receipt(&invocation).is_err(),
                "exclusive attempt creation"
            );
            invocation.receipt_initialized = true;
            assert!(
                claim_receipt(&invocation).is_err(),
                "an empty existing file is no handoff"
            );
            std::fs::write(&receipt, b"RCH_TEST_DISK_BUDGET:\n").unwrap();
            assert!(claim_receipt(&invocation).unwrap());
            persist_receipt(
                &receipt,
                &[(
                    "RCH_TEST_DISK_USAGE:".into(),
                    Some(json!({"complete": true})),
                )],
            )
            .unwrap();
            assert!(
                claim_receipt(&invocation).is_err(),
                "an earlier result cannot authorize another attempt"
            );
            let alias = fixture.join("alias");
            std::os::unix::fs::symlink(&receipt, &alias).unwrap();
            invocation.receipt = Some(alias);
            assert!(
                claim_receipt(&invocation).is_err(),
                "never follow a receipt symlink"
            );
        }

        #[test]
        fn receipt_diagnostics_are_line_delimited_and_oversize_is_not_published() {
            let fixture = tempfile::tempdir().unwrap().keep();
            let receipt = fixture.join("receipt");
            std::fs::write(&receipt, b"previous receipt").unwrap();
            let receipts = [(
                "RCH_TEST_DISK_USAGE:".into(),
                Some(json!({"complete":true,"exit_code":17})),
            )];
            let bytes = diagnostic_receipt(&receipts).unwrap();
            assert!(bytes.starts_with(b"\nRCH_TEST_DISK_USAGE:{"));
            assert!(bytes.ends_with(b"}\n"));
            let oversized = [(
                "RCH_TEST_DISK_BUDGET:".into(),
                Some(json!({"detail":"x".repeat(MAX_RECEIPT_BYTES)})),
            )];
            assert!(persist_receipt(&receipt, &oversized).is_err());
            assert_eq!(std::fs::read(&receipt).unwrap(), b"previous receipt");
        }

        #[test]
        fn sampler_deadline_bounds_completion_without_expiring_queued_evidence() {
            let deadline = Instant::now();
            for (completed, accepted) in [
                (deadline - Duration::from_millis(1), true),
                (deadline + Duration::from_millis(1), false),
            ] {
                let (sender, receiver) = mpsc::sync_channel(1);
                sender.send((Ok(17), completed)).unwrap();
                let pending = Pending {
                    receiver,
                    deadline,
                    description: "probe deadline",
                };
                let result = pending.ready();
                if accepted {
                    assert_eq!(result.unwrap(), Some(17));
                } else {
                    assert_eq!(result.unwrap_err().detail, "probe deadline");
                }
            }
        }
    }
}
