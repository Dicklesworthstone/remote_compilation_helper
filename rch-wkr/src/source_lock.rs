//! Native source-authority advisory locks and their independent liveness owner.
//!
//! The observer never reaps its direct child until it has revoked both that
//! exact child and the process group whose identity the child still pins. The
//! monitor owns that private group, including the shell and inherited locks.
//! Neither process edits durable claims: expiry revokes only this control
//! session, leaving the existing activity/claim recovery protocol authoritative.

use std::ffi::OsString;

/// Run before the worker creates a runtime or any background reaper threads.
pub fn main(arguments: &[OsString]) -> i32 {
    #[cfg(unix)]
    {
        imp::main(arguments)
    }
    #[cfg(not(unix))]
    {
        let _ = arguments;
        eprintln!(
            "RCH_SOURCE_LOCK_LIVENESS_UNAVAILABLE: native advisory source locks require Unix"
        );
        73
    }
}

#[cfg(unix)]
mod imp {
    use std::collections::HashSet;
    use std::ffi::{OsStr, OsString};
    use std::fs::File;
    use std::io::{self, Read};
    use std::os::fd::{AsFd, AsRawFd, OwnedFd};
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    use std::os::unix::process::{CommandExt, ExitStatusExt};
    use std::path::PathBuf;
    use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::Duration;

    use nix::sys::signal::{SigSet, Signal as NixSignal};
    use rustix::event::{PollFd, PollFlags, Timespec, poll};
    use rustix::fs::{AtFlags, CWD, FileType, FlockOperation, Mode, OFlags, Stat};
    use rustix::io::{Errno, FdFlags};
    use rustix::process::{Pid, Signal};

    const REFUSED: i32 = 73;
    const MAX_FRAME: usize = 4096;
    const MAX_PROGRAM: usize = 32 * 1024 * 1024;
    const MAX_RECORD: usize = 1024 * 1024;
    const HEARTBEAT: &[u8] = b"RCH_SOURCE_LOCK_HEARTBEAT\n";
    const SESSION_READY: &[u8] = b"RCH_SOURCE_LOCK_SESSION_READY\n";
    const SESSION: &str = "--rch-session";
    const FINITE: &str = "--rch-finite-rpc";
    const MONITOR: &str = "--rch-monitor";
    const MAX_BUDGET_MS: u128 = Duration::MAX.as_millis();
    const TICK_NS: u128 = 50_000_000;
    const RELEASE_NS: u128 = 15_000_000_000;

    type Result<T> = std::result::Result<T, io::Error>;

    fn invalid(message: &'static str) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidInput, message)
    }

    fn nonblocking(fd: impl AsFd) -> Result<()> {
        let flags = rustix::fs::fcntl_getfl(&fd)?;
        rustix::fs::fcntl_setfl(&fd, flags | OFlags::NONBLOCK)?;
        Ok(())
    }

    fn diagnostic(fd: impl AsFd, message: &str) {
        // A full or abandoned SSH error pipe must never postpone revocation.
        if nonblocking(&fd).is_ok() {
            let mut bytes = message.as_bytes().to_vec();
            bytes.truncate(8191);
            bytes.push(b'\n');
            let _ = rustix::io::write(fd, &bytes);
        }
    }

    fn reopen_inherited(fd: i32, flags: OFlags) -> Result<OwnedFd> {
        // The inherited raw descriptor is not owned by a Rust value. Reopen it
        // first, then close the original with nix's safe raw-descriptor API.
        // No runtime threads may allocate/reuse descriptors during this handoff.
        Ok(rustix::fs::open(
            format!("/dev/fd/{fd}"),
            flags | OFlags::CLOEXEC,
            Mode::empty(),
        )?)
    }

    fn take_inherited(fd: i32, flags: OFlags) -> Result<OwnedFd> {
        let owned = reopen_inherited(fd, flags)?;
        nix::unistd::close(fd)?;
        Ok(owned)
    }

    fn decimal(value: &OsStr) -> Result<u128> {
        let bytes = value.as_bytes();
        if bytes.is_empty() || !bytes.iter().all(u8::is_ascii_digit) {
            return Err(invalid("invalid unsigned decimal argument"));
        }
        value
            .to_str()
            .and_then(|text| text.parse().ok())
            .ok_or_else(|| invalid("decimal argument exceeds its byte/count bound"))
    }

    fn now_ns() -> u128 {
        let time = rustix::time::clock_gettime(rustix::time::ClockId::Monotonic);
        // CLOCK_MONOTONIC is nonnegative on the supported Unix worker hosts.
        u128::try_from(time.tv_sec).unwrap_or_default() * 1_000_000_000
            + u128::try_from(time.tv_nsec).unwrap_or_default()
    }

    #[derive(Clone, Copy)]
    struct Policy {
        finite: bool,
        budget: u128,
    }

    impl Policy {
        fn parse(mode: &OsStr, budget: &OsStr) -> Result<Self> {
            let finite = mode == FINITE;
            if !finite && mode != SESSION {
                return Err(invalid("invalid source liveness mode"));
            }
            let budget = decimal(budget)?;
            if budget == 0 || budget > if finite { MAX_BUDGET_MS } else { 3600 } {
                return Err(invalid("invalid source liveness deadline"));
            }
            Ok(Self { finite, budget })
        }

        fn family(self) -> &'static str {
            if self.finite {
                "RCH_SOURCE_ACTIVITY"
            } else {
                "RCH_SOURCE_LOCK"
            }
        }

        fn interval_ns(self) -> u128 {
            self.budget
                * if self.finite {
                    1_000_000
                } else {
                    1_000_000_000
                }
        }

        fn expired(self, released: bool) -> (i32, Option<String>) {
            let message = if self.finite {
                format!(
                    "RCH_SOURCE_ACTIVITY_TIMEOUT: budget_ms={}; durable ownership retained",
                    self.budget
                )
            } else {
                let reason = if released {
                    "RELEASE_TIMEOUT"
                } else {
                    "HEARTBEAT_EXPIRED"
                };
                format!(
                    "RCH_SOURCE_LOCK_{reason}: durable ownership retained; idle_seconds={}",
                    self.budget
                )
            };
            (if self.finite { 124 } else { REFUSED }, Some(message))
        }
    }

    pub(super) fn main(arguments: &[OsString]) -> i32 {
        if arguments.len() == 1 && arguments[0] == "probe" {
            return match rustix::io::write(rustix::stdio::stdout(), b"rch-wkr source-lock v1\n") {
                Ok(23) => 0,
                _ => REFUSED,
            };
        }
        let mode = arguments.first().map(OsString::as_os_str);
        if mode == Some(OsStr::new(MONITOR)) {
            return monitor(&arguments[1..]);
        }
        if mode == Some(OsStr::new(SESSION)) || mode == Some(OsStr::new(FINITE)) {
            let family = if mode == Some(OsStr::new(FINITE)) {
                "RCH_SOURCE_ACTIVITY"
            } else {
                "RCH_SOURCE_LOCK"
            };
            return match observe(arguments) {
                Ok(status) => status,
                Err(error) => {
                    diagnostic(
                        rustix::stdio::stderr(),
                        &format!(
                            "{family}_LIVENESS_UNAVAILABLE: {error}; durable ownership retained"
                        ),
                    );
                    REFUSED
                }
            };
        }
        match acquire(arguments) {
            Ok(status) => status,
            Err(error) => {
                diagnostic(
                    rustix::stdio::stderr(),
                    &format!("RCH: native source lock acquisition failed: {error}"),
                );
                REFUSED
            }
        }
    }

    /// The direct child is deliberately never passed to try_wait or wait until
    /// both revocation signals have been sent. Even a stopped or dead monitor
    /// still pins its PID, so a group lookup/reused PID cannot redirect cleanup.
    struct PinnedMonitor {
        child: Child,
        pid: Pid,
        reaped: bool,
    }

    impl PinnedMonitor {
        fn revoke(&mut self) -> Result<ExitStatus> {
            let child_kill = rustix::process::kill_process(self.pid, Signal::KILL);
            let group_kill = rustix::process::kill_process_group(self.pid, Signal::KILL);
            // Always attempt both signals, and reap only after both attempts.
            // Darwin can report EPERM when a group contains only zombies.
            let status = self.child.wait()?;
            self.reaped = true;
            for result in [child_kill, group_kill] {
                match result {
                    Ok(()) | Err(Errno::SRCH) => {}
                    Err(Errno::PERM) if cfg!(target_os = "macos") => {}
                    Err(error) => return Err(error.into()),
                }
            }
            Ok(status)
        }
    }

    impl Drop for PinnedMonitor {
        fn drop(&mut self) {
            if !self.reaped {
                let _ = self.revoke();
            }
        }
    }

    fn observe(arguments: &[OsString]) -> Result<i32> {
        if arguments.len() != 2 {
            return Err(invalid(
                "source liveness mode requires exactly one deadline",
            ));
        }
        let policy = Policy::parse(&arguments[0], &arguments[1])?;
        // Validate the inherited program before creating any session. The
        // monitor reads it after setsid; finite RPCs never copy or size-cap it.
        let program = reopen_inherited(3, OFlags::RDONLY)?;
        rustix::fs::fstat(&program)?;
        drop(program);
        let deadline = if policy.finite {
            now_ns() + policy.interval_ns()
        } else {
            0
        };

        let mut notification = SigSet::empty();
        notification.add(NixSignal::SIGCHLD);
        notification.thread_block()?;
        // Installing a caught handler clears inherited SIG_IGN/SA_NOCLDWAIT.
        // signal-hook installs neither SA_NOCLDWAIT nor SA_NOCLDSTOP. Thus
        // Darwin queues notifications, and stop/continue also revoke authority.
        let _child_notification = signal_hook::flag::register(
            signal_hook::consts::SIGCHLD,
            Arc::new(AtomicBool::new(false)),
        )?;

        let (receipt_read, receipt_write) =
            rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC)?;
        let inherited_receipt = rustix::io::fcntl_dupfd_cloexec(&receipt_write, 64)?;
        rustix::io::fcntl_setfd(&inherited_receipt, FdFlags::empty())?;
        // Only this known anonymous pipe is reopened by the monitor. Inherited
        // stdio keeps its original open descriptions, including socket endpoints
        // and a regular stderr log's current offset/append policy.
        let child = Command::new(std::env::current_exe()?)
            .args([OsStr::new("source-lock"), OsStr::new(MONITOR)])
            .args(arguments)
            .arg(inherited_receipt.as_raw_fd().to_string())
            .arg(deadline.to_string())
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()?;
        drop(inherited_receipt);
        drop(receipt_write);
        let pid = Pid::from_child(&child);
        let mut monitor = PinnedMonitor {
            child,
            pid,
            reaped: false,
        };
        let mut receipt = File::from(receipt_read);
        // This independent observer owns no source input or lock descriptors.
        // Keep stdio valid for Rust while relinquishing the SSH read endpoint.
        rustix::stdio::dup2_stdin(File::open("/dev/null")?)?;
        nix::unistd::close(3)?;
        notification.wait()?;
        let status = monitor.revoke()?;
        nonblocking(&receipt)?;
        let mut bytes = [0_u8; 32];
        let count = match receipt.read(&mut bytes) {
            Ok(count) => count,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => 0,
            Err(error) => return Err(error),
        };
        if status.signal() == Some(signal_hook::consts::SIGKILL)
            && let Some(code) = completion_receipt(&bytes[..count])
        {
            return Ok(code);
        }
        diagnostic(
            rustix::stdio::stderr(),
            &format!(
                "{}_SUPERVISOR_TERMINATED: no holder completion receipt; durable ownership retained; status={status}",
                policy.family(),
            ),
        );
        Ok(REFUSED)
    }

    fn completion_receipt(bytes: &[u8]) -> Option<i32> {
        let digits = bytes.strip_suffix(b"\n")?;
        if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
            return None;
        }
        let code: u8 = std::str::from_utf8(digits).ok()?.parse().ok()?;
        Some(i32::from(code))
    }

    struct MonitorGroup {
        identity: Pid,
        receipt: OwnedFd,
    }

    impl MonitorGroup {
        fn kill(&self) {
            // Live self-membership pins this identity independently of the
            // observer. A broken receipt pipe must still kill every descendant.
            if self.identity == rustix::process::getpid()
                && self.identity == rustix::process::getpgrp()
            {
                let _ = rustix::process::kill_current_process_group(Signal::KILL);
            }
        }

        fn finish(&self, status: i32, message: Option<&str>) -> ! {
            if let Some(message) = message {
                diagnostic(rustix::stdio::stderr(), message);
            }
            if self.identity == rustix::process::getpid()
                && self.identity == rustix::process::getpgrp()
            {
                if nonblocking(&self.receipt).is_ok() {
                    let _ = rustix::io::write(&self.receipt, format!("{status}\n").as_bytes());
                }
                self.kill();
            }
            std::process::exit(REFUSED);
        }
    }

    impl Drop for MonitorGroup {
        fn drop(&mut self) {
            self.kill();
        }
    }

    fn monitor(arguments: &[OsString]) -> i32 {
        // Internal reexec only: mode, original budget, receipt fd, absolute
        // finite deadline. No source authority comes from these arguments.
        let setup = || -> Result<(Policy, u128, MonitorGroup)> {
            if arguments.len() != 4 {
                return Err(invalid("invalid source supervisor reexec arguments"));
            }
            let policy = Policy::parse(&arguments[0], &arguments[1])?;
            let receipt_fd = i32::try_from(decimal(&arguments[2])?)
                .ok()
                .filter(|fd| *fd >= 64)
                .ok_or_else(|| invalid("invalid source supervisor receipt descriptor"))?;
            let deadline = decimal(&arguments[3])?;
            let receipt = take_inherited(receipt_fd, OFlags::WRONLY | OFlags::NONBLOCK)?;
            if FileType::from_raw_mode(rustix::fs::fstat(&receipt)?.st_mode) != FileType::Fifo {
                return Err(invalid(
                    "source supervisor receipt is not an anonymous pipe",
                ));
            }
            let identity = rustix::process::setsid()?;
            let group = MonitorGroup { identity, receipt };
            if identity != rustix::process::getpid() || identity != rustix::process::getpgrp() {
                return Err(invalid("source supervisor has no private process group"));
            }
            Ok((policy, deadline, group))
        };
        let (policy, deadline, group) = match setup() {
            Ok(setup) => setup,
            // An absent receipt makes the independent observer fail closed and
            // clean up even if setsid or argument validation failed very early.
            Err(_) => return REFUSED,
        };
        match supervise(policy, deadline) {
            Ok((status, message)) => group.finish(status, message.as_deref()),
            Err(error) => group.finish(
                REFUSED,
                Some(&format!(
                    "{}_LIVENESS_FAILED: {error}; durable ownership retained",
                    policy.family(),
                )),
            ),
        }
    }

    fn bounded_program(fd: OwnedFd) -> Result<Vec<u8>> {
        let mut program = Vec::new();
        File::from(fd)
            .take((MAX_PROGRAM + 1) as u64)
            .read_to_end(&mut program)?;
        if program.is_empty() || program.len() > MAX_PROGRAM || program.contains(&0) {
            return Err(invalid("invalid bounded holder program"));
        }
        Ok(program)
    }

    fn handoff() -> Result<()> {
        let stdout = rustix::stdio::stdout();
        let original = rustix::fs::fcntl_getfl(stdout)?;
        rustix::fs::fcntl_setfl(stdout, original | OFlags::NONBLOCK)?;
        let written = rustix::io::write(stdout, SESSION_READY);
        rustix::fs::fcntl_setfl(stdout, original)?;
        if written? != SESSION_READY.len() {
            return Err(invalid("incomplete source control handoff"));
        }
        Ok(())
    }

    fn supervise(policy: Policy, mut deadline: u128) -> Result<(i32, Option<String>)> {
        // exec reset the observer's caught SIGCHLD disposition to default.
        // Unblock it even when the original SSH environment blocked it: shells
        // and tools need their own child notifications and reaping semantics.
        let mut child_signal = SigSet::empty();
        child_signal.add(NixSignal::SIGCHLD);
        child_signal.thread_unblock()?;
        let interrupted = Arc::new(AtomicUsize::new(0));
        for signal in [
            signal_hook::consts::SIGHUP,
            signal_hook::consts::SIGINT,
            signal_hook::consts::SIGTERM,
        ] {
            signal_hook::flag::register_usize(signal, Arc::clone(&interrupted), signal as usize)?;
        }

        let program = take_inherited(3, OFlags::RDONLY)?;
        let mut pending = if policy.finite {
            Vec::new()
        } else {
            let program = bounded_program(program.try_clone()?)?;
            let mut framed = Vec::with_capacity(program.len() + 5);
            framed.extend_from_slice(b"{\n");
            framed.extend_from_slice(&program);
            framed.extend_from_slice(b"\n}\n");
            handoff()?;
            framed
        };
        let mut command = Command::new("sh");
        command
            .arg("-s")
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());
        if policy.finite {
            command.stdin(Stdio::from(program));
        } else {
            drop(program);
            command.stdin(Stdio::piped());
        }
        // The finite budget started before observer/monitor reexec. If startup
        // consumed it, do not begin a new source activity even momentarily.
        if policy.finite && now_ns() >= deadline {
            return Ok(policy.expired(false));
        }
        let mut child = match command.spawn() {
            Ok(child) => child,
            // The original supervisor's shell child reported exec failures as
            // 127. Resource/setup failures still refuse through liveness73.
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied
                ) =>
            {
                return Ok((127, None));
            }
            Err(error) => return Err(error),
        };
        let mut writer = child.stdin.take();
        if let Some(writer) = &writer {
            nonblocking(writer)?;
        }
        if policy.finite {
            rustix::stdio::dup2_stdin(File::open("/dev/null")?)?;
        } else {
            nonblocking(rustix::stdio::stdin())?;
            deadline = now_ns() + policy.interval_ns();
        }
        let mut sent = 0;
        let mut control = ControlInput::default();

        loop {
            let now = now_ns();
            let signal = interrupted.load(Ordering::SeqCst);
            if signal != 0 {
                let status = if policy.finite {
                    128 + signal as i32
                } else {
                    REFUSED
                };
                return Ok((
                    status,
                    Some(format!(
                        "{}_INTERRUPTED: signal={signal}; durable ownership retained",
                        policy.family(),
                    )),
                ));
            }
            if now >= deadline {
                return Ok(policy.expired(control.released));
            }
            if let Some(status) = child.try_wait()? {
                if let Some(code) = status.code() {
                    return Ok((code, None));
                }
                let signal = status.signal().unwrap_or(0);
                return Ok((
                    128 + signal,
                    Some(format!(
                        "{}_PROCESS_TERMINATED: signal={signal}; durable ownership retained",
                        policy.family(),
                    )),
                ));
            }
            let readable = !policy.finite && !control.eof;
            let writable = writer.as_ref().filter(|_| sent < pending.len());
            let (input_ready, output_ready) = wait_io(readable, writable, deadline - now)?;
            if input_ready
                && let Some(error) = control.receive(&mut pending, &mut deadline, policy)?
            {
                return Ok((REFUSED, Some(error)));
            }
            if output_ready && let Some(output) = &writer {
                let end = pending.len().min(sent + 65_536);
                match rustix::io::write(output, &pending[sent..end]) {
                    Ok(count) => sent += count,
                    Err(Errno::AGAIN | Errno::INTR) => {}
                    Err(Errno::PIPE) => {
                        writer = None;
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            if sent == pending.len() {
                pending.clear();
                sent = 0;
                if control.released || policy.finite {
                    writer = None;
                }
            }
        }
    }

    fn wait_io(input: bool, output: Option<&ChildStdin>, remaining: u128) -> Result<(bool, bool)> {
        let mut descriptors = Vec::with_capacity(2);
        if input {
            descriptors.push(PollFd::from_borrowed_fd(
                rustix::stdio::stdin(),
                PollFlags::IN,
            ));
        }
        if let Some(output) = output {
            descriptors.push(PollFd::new(output, PollFlags::OUT));
        }
        let timeout = Timespec {
            tv_sec: 0,
            tv_nsec: remaining.min(TICK_NS) as _,
        };
        match poll(&mut descriptors, Some(&timeout)) {
            Ok(_) => {}
            Err(Errno::INTR) => return Ok((false, false)),
            Err(error) => return Err(error.into()),
        }
        let input_ready = input && !descriptors[0].revents().is_empty();
        let output_ready =
            output.is_some() && !descriptors[usize::from(input)].revents().is_empty();
        Ok((input_ready, output_ready))
    }

    #[derive(Default)]
    struct ControlInput {
        buffer: Vec<u8>,
        released: bool,
        eof: bool,
    }

    impl ControlInput {
        fn receive(
            &mut self,
            pending: &mut Vec<u8>,
            deadline: &mut u128,
            policy: Policy,
        ) -> Result<Option<String>> {
            let mut bytes = [0_u8; MAX_FRAME + 1];
            let length = match rustix::io::read(
                rustix::stdio::stdin(),
                &mut bytes[..MAX_FRAME + 1 - self.buffer.len()],
            ) {
                Ok(length) => length,
                Err(Errno::AGAIN | Errno::INTR) => return Ok(None),
                Err(error) => return Err(error.into()),
            };
            if length == 0 {
                if !self.released || !self.buffer.is_empty() {
                    return Ok(Some("RCH_SOURCE_LOCK_DISCONNECTED: no complete release; durable ownership retained".into()));
                }
                self.eof = true;
                return Ok(None);
            }
            self.buffer.extend_from_slice(&bytes[..length]);
            while let Some(end) = self.buffer.iter().position(|byte| *byte == b'\n') {
                let frame = &self.buffer[..=end];
                if self.released {
                    return Ok(Some(
                        "RCH_SOURCE_LOCK_PROTOCOL_ERROR: input after release".into(),
                    ));
                }
                if frame == HEARTBEAT {
                    *deadline = now_ns() + policy.interval_ns();
                } else if valid_release(frame) {
                    pending.extend_from_slice(frame);
                    self.released = true;
                    *deadline = now_ns() + RELEASE_NS;
                } else {
                    return Ok(Some(
                        "RCH_SOURCE_LOCK_PROTOCOL_ERROR: invalid release frame".into(),
                    ));
                }
                self.buffer.drain(..=end);
            }
            if self.buffer.len() >= MAX_FRAME {
                return Ok(Some(
                    "RCH_SOURCE_LOCK_PROTOCOL_ERROR: frame exceeded byte bound".into(),
                ));
            }
            Ok(None)
        }
    }

    fn valid_release(frame: &[u8]) -> bool {
        let Some(line) = frame.strip_suffix(b"\n") else {
            return false;
        };
        let Some(separator) = line.iter().position(|byte| *byte == b':') else {
            return false;
        };
        let (prefix, suffix) = line.split_at(separator);
        let token = &suffix[1..];
        matches!(
            prefix,
            b"RCH_SOURCE_AUTHORITY_RELEASE" | b"RCH_SOURCE_PAIR_RELEASE"
        ) && (1..=128).contains(&token.len())
            && token
                .iter()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte) || *byte == b'-')
    }

    struct Lock {
        descriptor: OwnedFd,
        path: PathBuf,
        identity: Stat,
        operation: FlockOperation,
    }

    impl Lock {
        fn verify(&self) -> Result<()> {
            let current = rustix::fs::statat(CWD, &self.path, AtFlags::SYMLINK_NOFOLLOW)?;
            if FileType::from_raw_mode(current.st_mode) != FileType::RegularFile
                || current.st_dev != self.identity.st_dev
                || current.st_ino != self.identity.st_ino
            {
                return Err(invalid("source lock path changed during acquisition"));
            }
            Ok(())
        }
    }

    fn requester_open(wait_ns: i64) -> Result<()> {
        let mut descriptor = [PollFd::from_borrowed_fd(
            rustix::stdio::stdin(),
            PollFlags::IN,
        )];
        let timeout = Timespec {
            tv_sec: 0,
            tv_nsec: wait_ns as _,
        };
        loop {
            match poll(&mut descriptor, Some(&timeout)) {
                Ok(0) => return Ok(()),
                Ok(_) => {
                    return Err(invalid(
                        "source lock requester ended or sent input before readiness",
                    ));
                }
                Err(Errno::INTR) => {}
                Err(error) => return Err(error.into()),
            }
        }
    }

    fn plan(count: usize, contents: &[u8]) -> Result<Vec<(PathBuf, FlockOperation)>> {
        if contents.len() > MAX_PROGRAM || contents.contains(&0) || contents.contains(&b'\r') {
            return Err(invalid("invalid bounded source lock plan"));
        }
        let mut parsed = Vec::new();
        let mut seen = HashSet::new();
        for record in contents.split_inclusive(|byte| *byte == b'\n') {
            if record.len() > MAX_RECORD || !record.ends_with(b"\n") || record.len() < 4 {
                return Err(invalid("invalid or incomplete source lock plan"));
            }
            let operation = match &record[..3] {
                b"x /" => FlockOperation::NonBlockingLockExclusive,
                b"s /" => FlockOperation::NonBlockingLockShared,
                _ => return Err(invalid("invalid source lock mode or absolute path")),
            };
            let path = PathBuf::from(OsString::from_vec(record[2..record.len() - 1].to_vec()));
            if !seen.insert(path.clone()) {
                return Err(invalid("duplicate source lock path"));
            }
            parsed.push((path, operation));
            if parsed.len() > count {
                return Err(invalid("source lock count does not match the plan"));
            }
        }
        if parsed.len() != count {
            return Err(invalid("source lock count does not match the plan"));
        }
        Ok(parsed)
    }

    fn acquire(arguments: &[OsString]) -> Result<i32> {
        if arguments.len() < 2 {
            return Err(invalid(
                "source lock acquisition requires count and ready marker",
            ));
        }
        let count = usize::try_from(decimal(&arguments[0])?)
            .map_err(|_| invalid("source lock count exceeds platform capacity"))?;
        if count > MAX_PROGRAM / 4 {
            return Err(invalid("source lock count exceeds bounded plan capacity"));
        }
        let ready = arguments[1].as_bytes();
        if ready.is_empty()
            || ready.len() >= MAX_FRAME
            || ready.iter().any(|byte| matches!(*byte, 0 | b'\n' | b'\r'))
        {
            return Err(invalid("invalid source lock ready marker"));
        }
        let input = take_inherited(3, OFlags::RDONLY)?;
        let mut contents = Vec::new();
        File::from(input)
            .take((MAX_PROGRAM + 1) as u64)
            .read_to_end(&mut contents)?;
        let records = plan(count, &contents)?;
        let mut held = Vec::with_capacity(records.len());
        let mut identities = HashSet::new();
        for (path, operation) in records {
            requester_open(0)?;
            let opened = rustix::fs::open(
                &path,
                OFlags::RDWR
                    | OFlags::CREATE
                    | OFlags::NOFOLLOW
                    | OFlags::NONBLOCK
                    | OFlags::CLOEXEC,
                Mode::from_raw_mode(0o600),
            )?;
            let identity = rustix::fs::fstat(&opened)?;
            if FileType::from_raw_mode(identity.st_mode) != FileType::RegularFile {
                return Err(invalid("source lock is not a regular file"));
            }
            if !identities.insert((identity.st_dev, identity.st_ino)) {
                return Err(invalid("duplicate source lock inode"));
            }
            // Do not collide with fd 3/4 protocol data or the terminal's
            // conventional low-numbered transaction descriptors. Transfer
            // inheritance only after the complete closure has been admitted.
            let descriptor = rustix::io::fcntl_dupfd_cloexec(&opened, 64)?;
            let lock = Lock {
                descriptor,
                path,
                identity,
                operation,
            };
            lock.verify()?;
            held.push(lock);
        }
        // Keep the supplied canonical ROOT order. The lock filenames are hashes
        // whose lexical order has no relation to the required acquisition order.
        loop {
            let mut acquired = 0;
            for lock in &held {
                requester_open(0)?;
                lock.verify()?;
                match rustix::fs::flock(&lock.descriptor, lock.operation) {
                    Ok(()) => acquired += 1,
                    Err(Errno::AGAIN | Errno::ACCESS) => break,
                    Err(error) => return Err(error.into()),
                }
            }
            if acquired == held.len() {
                break;
            }
            for lock in held[..acquired].iter().rev() {
                rustix::fs::flock(&lock.descriptor, FlockOperation::Unlock)?;
            }
            requester_open(TICK_NS as i64)?;
        }
        for lock in &held {
            lock.verify()?;
        }
        if !held.is_empty() {
            requester_open(0)?;
        }
        for lock in &held {
            rustix::io::fcntl_setfd(&lock.descriptor, FdFlags::empty())?;
        }
        if let Some(terminal) = arguments.get(2) {
            // fd 4 remains untouched for durable claim input. exec transfers
            // the same PID and open file descriptions to the existing terminal.
            return Err(Command::new("sh")
                .arg("-c")
                .arg(terminal)
                .arg(terminal)
                .arg(&arguments[1])
                .args(&arguments[3..])
                .exec());
        }
        let mut line = ready.to_vec();
        line.push(b'\n');
        if rustix::io::write(rustix::stdio::stdout(), &line)? != line.len() {
            return Err(invalid("incomplete source lock ready marker"));
        }
        Err(Command::new("cat").stdout(Stdio::null()).exec())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn validates_release_frames_exactly() {
            for valid in [
                b"RCH_SOURCE_AUTHORITY_RELEASE:0123456789abcdef-\n".as_slice(),
                b"RCH_SOURCE_PAIR_RELEASE:a\n",
            ] {
                assert!(valid_release(valid));
            }
            for invalid in [
                b"RCH_SOURCE_AUTHORITY_RELEASE:\n".as_slice(),
                b"RCH_SOURCE_AUTHORITY_RELEASE:A\n",
                b"RCH_SOURCE_AUTHORITY_RELEASE:a\r\n",
                b"RCH_SOURCE_AUTHORITY_RELEASE:a:b\n",
                b"RCH_SOURCE_AUTHORITY_RELEASE:a",
                b"RCH_SOURCE_LOCK_HEARTBEAT\n",
            ] {
                assert!(!valid_release(invalid));
            }
            assert!(!valid_release(
                format!("RCH_SOURCE_PAIR_RELEASE:{}\n", "a".repeat(129)).as_bytes()
            ));
        }

        #[test]
        fn validates_plan_count_modes_bounds_and_literal_root_order() {
            let records = plan(2, b"x /z hashed ' name\ns /a\n").unwrap();
            assert_eq!(records[0].0, PathBuf::from("/z hashed ' name"));
            assert_eq!(records[1].0, PathBuf::from("/a"));
            assert!(matches!(
                records[0].1,
                FlockOperation::NonBlockingLockExclusive
            ));
            assert!(matches!(
                records[1].1,
                FlockOperation::NonBlockingLockShared
            ));
            assert!(plan(0, b"").unwrap().is_empty());
            for invalid in [
                b"x /a".as_slice(),
                b"q /a\n",
                b"x relative\n",
                b"x /a\r\n",
                b"x /a\0\n",
                b"x /a\nx /a\n",
            ] {
                assert!(plan(1, invalid).is_err());
            }
            assert!(plan(2, b"x /a\n").is_err());
            assert!(plan(1, b"x /a\nx /b\n").is_err());
            let overlong = format!("x /{}\n", "a".repeat(MAX_RECORD));
            assert!(plan(1, overlong.as_bytes()).is_err());
        }

        #[test]
        fn budgets_preserve_subsecond_and_above_hour_finite_deadlines() {
            for budget in ["1", "3600001", "18446744073709551615999"] {
                assert!(Policy::parse(OsStr::new(FINITE), OsStr::new(budget)).is_ok());
            }
            for budget in ["0", "-1", "18446744073709551616000", "1.0", "+1"] {
                assert!(Policy::parse(OsStr::new(FINITE), OsStr::new(budget)).is_err());
            }
            assert!(Policy::parse(OsStr::new(SESSION), OsStr::new("3600")).is_ok());
            assert!(Policy::parse(OsStr::new(SESSION), OsStr::new("3601")).is_err());
        }

        #[test]
        fn completion_requires_exact_bounded_status_receipt() {
            assert_eq!(completion_receipt(b"0\n"), Some(0));
            assert_eq!(completion_receipt(b"255\n"), Some(255));
            for invalid in [
                b"".as_slice(),
                b"0",
                b"\n",
                b"256\n",
                b"-1\n",
                b"0\n0\n",
                b"0\nextra",
                b" 0\n",
            ] {
                assert_eq!(completion_receipt(invalid), None);
            }
        }
    }
}
