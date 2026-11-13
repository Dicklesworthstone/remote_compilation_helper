//! Storage-independent observation of finite source-namespace transactions.
//!
//! A successful program exit is not a readiness receipt. An unreaped guardian
//! pins the private execution session until an independent, bounded census has
//! proved that its processes and threads stopped. The guardian also watches its
//! observer's private socket and owns the execution deadline independently.

use std::ffi::OsString;

/// Confirm that an unreaped private-session leader has no executing members.
/// The caller must retain its direct-child relationship throughout this check.
#[cfg(target_os = "linux")]
pub(crate) fn session_quiescent(
    leader: rustix::process::Pid,
    allowance: std::time::Duration,
) -> std::io::Result<bool> {
    imp::session_quiescent(leader, allowance)
}

pub fn main(arguments: &[OsString]) -> i32 {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        imp::main(arguments)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = arguments;
        eprintln!(
            "RCH_SOURCE_NAMESPACE_OBSERVER_UNAVAILABLE: native supervision requires Linux or Darwin"
        );
        73
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod imp {
    use std::ffi::OsString;
    use std::fs::File;
    use std::io::{self, Read};
    use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
    use std::os::unix::net::UnixStream;
    use std::os::unix::process::ExitStatusExt;
    #[cfg(target_os = "linux")]
    use std::path::Path;
    use std::process::{Child, Command, ExitStatus, Stdio};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::time::Duration;

    use nix::sys::signal::{SigSet, Signal as NixSignal};
    use rustix::event::{PollFd, PollFlags, Timespec, poll};
    use rustix::fs::OFlags;
    use rustix::io::Errno;
    use rustix::process::{Pid, Signal, WaitId, WaitIdOptions, WaitIdStatus};

    const REFUSED: i32 = 73;
    const STDOUT_LIMIT: usize = 4096;
    const STDERR_LIMIT: usize = 65_536;
    const HEADER: usize = 10;
    const FRAME_LIMIT: usize = HEADER + STDOUT_LIMIT + STDERR_LIMIT + 1;
    const SECOND: u64 = 1_000_000_000;
    const TICK: u64 = 20_000_000;
    const GUARDIAN: &str = "--guardian";
    const CHECKER: &str = "--checker";
    const UNSETTLED: &[u8] = b"RCH_SOURCE_NAMESPACE_CONTROL_UNSETTLED cause=execution-or-process-settlement-unconfirmed\n";
    const OVERFLOW: &[u8] = b"RCH: namespace control output exceeded its byte bound\n";
    const READINESS: &[u8] = b"RCH: namespace control returned invalid readiness\n";

    type Result<T> = io::Result<T>;

    fn invalid(message: &'static str) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, message)
    }

    fn now() -> u64 {
        #[cfg(target_os = "linux")]
        let (seconds, nanos) = {
            let time = rustix::time::clock_gettime(rustix::time::ClockId::Monotonic);
            (time.tv_sec, time.tv_nsec)
        };
        #[cfg(target_os = "macos")]
        let (seconds, nanos) = {
            // Preserve the elapsed-clock policy: mach_absolute_time excludes
            // suspend, just as the source-admission clock does on Darwin.
            let time =
                nix::time::clock_gettime(nix::time::ClockId::from_raw(nix::libc::CLOCK_UPTIME_RAW))
                    .expect("macOS uptime clock is unavailable");
            (time.tv_sec(), time.tv_nsec())
        };
        u64::try_from(seconds).unwrap_or_default() * SECOND
            + u64::try_from(nanos).unwrap_or_default()
    }

    fn nonblocking(fd: impl AsFd) -> Result<()> {
        let flags = rustix::fs::fcntl_getfl(&fd)?;
        rustix::fs::fcntl_setfl(fd, flags | OFlags::NONBLOCK)?;
        Ok(())
    }

    struct RestoreFlags<'a> {
        fd: BorrowedFd<'a>,
        original: OFlags,
    }

    impl<'a> RestoreFlags<'a> {
        fn new(fd: BorrowedFd<'a>) -> Result<Self> {
            Ok(Self {
                fd,
                original: rustix::fs::fcntl_getfl(fd)?,
            })
        }
    }

    impl Drop for RestoreFlags<'_> {
        fn drop(&mut self) {
            // These descriptions can still belong to the preflight/holder
            // shell. Do not leave its subsequent writes nonblocking.
            let _ = rustix::fs::fcntl_setfl(self.fd, self.original);
        }
    }

    fn pause(descriptors: &mut [PollFd<'_>], deadline: u64) -> Result<()> {
        let timeout = Timespec {
            tv_sec: 0,
            tv_nsec: deadline.saturating_sub(now()).min(TICK) as _,
        };
        match poll(descriptors, Some(&timeout)) {
            Ok(_) | Err(Errno::INTR) => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    fn signals() -> Result<Arc<AtomicBool>> {
        let interrupted = Arc::new(AtomicBool::new(false));
        let mut mask = SigSet::empty();
        for signal in [NixSignal::SIGHUP, NixSignal::SIGINT, NixSignal::SIGTERM] {
            signal_hook::flag::register(signal as i32, Arc::clone(&interrupted))?;
            mask.add(signal);
        }
        // Clear inherited SIG_IGN/SA_NOCLDWAIT, even when the caller also
        // blocked notifications. Only explicit waits may reap owned children.
        signal_hook::flag::register(
            signal_hook::consts::SIGCHLD,
            Arc::new(AtomicBool::new(false)),
        )?;
        mask.add(NixSignal::SIGCHLD);
        // EPIPE must return through owned-group cleanup, never terminate a
        // guardian before it can revoke quiet descendants.
        signal_hook::flag::register(
            signal_hook::consts::SIGPIPE,
            Arc::new(AtomicBool::new(false)),
        )?;
        mask.add(NixSignal::SIGPIPE);
        mask.thread_unblock().map_err(io::Error::other)?;
        Ok(interrupted)
    }

    fn scale(value: &str) -> Result<f64> {
        // Match the transport's ASCII decimal grammar, without trimming or
        // accepting NaN/inf, locale digits, or an unbounded environment value.
        let mut bytes = value.as_bytes();
        if bytes.is_empty() || bytes.len() > 128 {
            return Err(invalid("invalid timing scale"));
        }
        if matches!(bytes.first(), Some(b'+' | b'-')) {
            bytes = &bytes[1..];
        }
        let integer = bytes
            .iter()
            .take_while(|byte| byte.is_ascii_digit())
            .count();
        bytes = &bytes[integer..];
        let mut fraction = 0;
        if bytes.first() == Some(&b'.') {
            bytes = &bytes[1..];
            fraction = bytes
                .iter()
                .take_while(|byte| byte.is_ascii_digit())
                .count();
            bytes = &bytes[fraction..];
        }
        if integer + fraction == 0 {
            return Err(invalid("invalid timing scale"));
        }
        if matches!(bytes.first(), Some(b'e' | b'E')) {
            bytes = &bytes[1..];
            if matches!(bytes.first(), Some(b'+' | b'-')) {
                bytes = &bytes[1..];
            }
            if bytes.is_empty() || !bytes.iter().all(u8::is_ascii_digit) {
                return Err(invalid("invalid timing scale"));
            }
            bytes = &[];
        }
        let parsed = value
            .parse::<f64>()
            .map_err(|_| invalid("invalid timing scale"))?;
        if !bytes.is_empty() || !parsed.is_finite() || !(1.0..=10.0).contains(&parsed) {
            return Err(invalid("invalid timing scale"));
        }
        Ok(parsed)
    }

    fn replies(contract: &str) -> Option<&'static [&'static [u8]]> {
        match contract {
            "RCH_TOPOLOGY_OK" => Some(&[b"RCH_TOPOLOGY_OK\n"]),
            "RCH_SOURCE_CANCELLATION_SETTLED" => Some(&[b"RCH_SOURCE_CANCELLATION_SETTLED\n"]),
            "RCH_SOURCE_AUTHORITY_NAMESPACE" => Some(&[
                b"RCH_SOURCE_AUTHORITY_NAMESPACE current\n",
                b"RCH_SOURCE_AUTHORITY_NAMESPACE legacy\n",
            ]),
            "RCH_SOURCE_AUTHORITY_DISCOVERY" => Some(&[
                b"RCH_SOURCE_AUTHORITY_DISCOVERY current\n",
                b"RCH_SOURCE_AUTHORITY_DISCOVERY legacy\n",
                b"RCH_SOURCE_AUTHORITY_DISCOVERY absent\n",
            ]),
            "RCH_SOURCE_INTENT_CANCEL" => Some(&[b"owned", b"unowned"]),
            "RCH_SOURCE_INTENT_RELEASED" => Some(&[b"released", b"pending"]),
            "RCH_SOURCE_INTENT_CANCELLED" => Some(&[b"cancelled", b"pending"]),
            "RCH_SOURCE_INTENT_CANCELLATION_STATE" => Some(&[b"cancellation", b"pending"]),
            "RCH_SOURCE_INTENT_FINISHED" => Some(&[b""]),
            _ => None,
        }
    }

    fn diagnostic(bytes: &[u8]) -> i32 {
        let fd = rustix::stdio::stderr();
        let Ok(_restore) = RestoreFlags::new(fd) else {
            return REFUSED;
        };
        if nonblocking(fd).is_ok() {
            let _ = rustix::io::write(fd, bytes);
        }
        REFUSED
    }

    pub(super) fn main(arguments: &[OsString]) -> i32 {
        if arguments.len() == 1 && arguments[0] == "probe" {
            let bytes = b"rch-wkr source-control v1\n";
            return match rustix::io::write(rustix::stdio::stdout(), bytes) {
                Ok(count) if count == bytes.len() => 0,
                _ => REFUSED,
            };
        }
        match arguments.first().and_then(|arg| arg.to_str()) {
            Some(GUARDIAN) => return guardian(&arguments[1..]).unwrap_or(REFUSED),
            Some(CHECKER) => return checker(&arguments[1..]).unwrap_or(REFUSED),
            _ => {}
        }
        let contract = match arguments {
            [protocol, version] if protocol == "--protocol" && version == "v1" => "RCH_TOPOLOGY_OK",
            [protocol, version, argument] if protocol == "--protocol" && version == "v1" => argument.to_str().unwrap_or(""),
            _ => return diagnostic(b"RCH_SOURCE_NAMESPACE_OBSERVER_UNAVAILABLE: expected source-control --protocol v1 CONTRACT\n"),
        };
        let Some(replies) = replies(contract) else {
            return diagnostic(b"RCH: invalid metadata control result marker\n");
        };
        let scale = match std::env::var("RCH_TIMING_SCALE") {
            Ok(value) => scale(&value),
            Err(std::env::VarError::NotPresent) => Ok(1.0),
            Err(_) => Err(invalid("invalid timing scale")),
        };
        let Ok(scale) = scale else {
            return diagnostic(b"RCH: invalid RCH_TIMING_SCALE (expected finite 1..10)\n");
        };
        match observe(replies, scale) {
            Ok(status) => status,
            Err(_) => diagnostic(UNSETTLED),
        }
    }

    /// Neither observation nor Drop reaps before signalling the pinned group.
    /// An unresponsive kernel task cannot turn cleanup into an unbounded wait.
    struct Pinned {
        child: Child,
        pid: Pid,
        reaped: bool,
        cleanup_deadline: u64,
    }

    impl Pinned {
        fn new(child: Child, cleanup_deadline: u64) -> Self {
            let pid = Pid::from_child(&child);
            Self {
                child,
                pid,
                reaped: false,
                cleanup_deadline,
            }
        }

        fn state(&self, changes: bool) -> Result<Option<WaitIdStatus>> {
            let mut options = WaitIdOptions::EXITED | WaitIdOptions::NOWAIT | WaitIdOptions::NOHANG;
            if changes {
                options |= WaitIdOptions::STOPPED | WaitIdOptions::CONTINUED;
            }
            match rustix::process::waitid(WaitId::Pid(self.pid), options) {
                Ok(status) => Ok(status),
                Err(Errno::INTR) => Ok(None),
                Err(error) => Err(error.into()),
            }
        }

        fn signal(&self) -> Result<()> {
            let child = rustix::process::kill_process(self.pid, Signal::KILL);
            let group = rustix::process::kill_process_group(self.pid, Signal::KILL);
            for result in [child, group] {
                match result {
                    Ok(()) | Err(Errno::SRCH) => {}
                    Err(Errno::PERM) if cfg!(target_os = "macos") => {}
                    Err(error) => return Err(error.into()),
                }
            }
            Ok(())
        }

        fn reap(&mut self, deadline: u64) -> Result<ExitStatus> {
            loop {
                if self.state(false)?.is_some() {
                    let status = self.child.wait()?;
                    self.reaped = true;
                    return Ok(status);
                }
                if now() >= deadline {
                    break;
                }
                pause(&mut [], deadline)?;
            }
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "child settlement expired",
            ))
        }
    }

    impl Drop for Pinned {
        fn drop(&mut self) {
            if !self.reaped {
                let _ = self.signal();
                let _ = self.reap(self.cleanup_deadline);
            }
        }
    }

    fn executable() -> Result<std::path::PathBuf> {
        // Linux reexecutes the running image, including during an atomic worker
        // upgrade. No temporary executable or writable directory is needed.
        #[cfg(target_os = "linux")]
        {
            Ok("/proc/self/exe".into())
        }
        #[cfg(target_os = "macos")]
        {
            std::env::current_exe()
        }
    }

    fn launch(
        mode: &str,
        arguments: &[String],
        upload: bool,
        cleanup_deadline: u64,
    ) -> Result<(Pinned, UnixStream)> {
        let (owner, child) = UnixStream::pair()?;
        owner.set_nonblocking(true)?;
        let child = Command::new(executable()?)
            .args(["source-control", mode])
            .args(arguments)
            .stdin(if upload {
                Stdio::inherit()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::from(OwnedFd::from(child)))
            .stderr(Stdio::null())
            .spawn()?;
        Ok((Pinned::new(child, cleanup_deadline), owner))
    }

    fn write_before(
        fd: impl AsFd,
        bytes: &[u8],
        deadline: u64,
        interrupted: &AtomicBool,
    ) -> Result<()> {
        nonblocking(&fd)?;
        let mut sent = 0;
        while sent < bytes.len() {
            if interrupted.load(Ordering::SeqCst) || now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "control write expired",
                ));
            }
            // Darwin cannot poll some writable devices (including /dev/null).
            // A nonblocking write needs readiness polling only after EAGAIN.
            match rustix::io::write(&fd, &bytes[sent..]) {
                Ok(0) => return Err(invalid("control write returned zero")),
                Ok(count) => sent += count,
                Err(Errno::AGAIN) => {
                    pause(&mut [PollFd::new(&fd, PollFlags::OUT)], deadline)?;
                }
                Err(Errno::INTR) => {}
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }

    fn receive(fd: impl AsFd, buffer: &mut Vec<u8>, limit: usize, eof: &mut bool) -> Result<bool> {
        let mut bytes = [0_u8; 8192];
        let available = bytes.len().min(limit + 1 - buffer.len());
        match rustix::io::read(fd, &mut bytes[..available]) {
            Ok(0) => *eof = true,
            Ok(count) => buffer.extend_from_slice(&bytes[..count]),
            Err(Errno::AGAIN | Errno::INTR) => {}
            Err(error) => return Err(error.into()),
        }
        Ok(buffer.len() > limit)
    }

    struct Payload {
        code: u8,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
    }

    impl Payload {
        fn frame(&self) -> Vec<u8> {
            let mut frame = Vec::with_capacity(HEADER + self.stdout.len() + self.stderr.len());
            frame.extend_from_slice(&[b'R', self.code]);
            frame.extend_from_slice(&(self.stdout.len() as u32).to_be_bytes());
            frame.extend_from_slice(&(self.stderr.len() as u32).to_be_bytes());
            frame.extend_from_slice(&self.stdout);
            frame.extend_from_slice(&self.stderr);
            frame
        }

        fn read(frame: &[u8]) -> Result<Option<Self>> {
            if frame.first().is_some_and(|byte| *byte != b'R') {
                return Err(invalid("invalid guardian result"));
            }
            if frame.len() < HEADER {
                return Ok(None);
            }
            let stdout = u32::from_be_bytes(
                frame[2..6]
                    .try_into()
                    .map_err(|_| invalid("invalid header"))?,
            ) as usize;
            let stderr = u32::from_be_bytes(
                frame[6..10]
                    .try_into()
                    .map_err(|_| invalid("invalid header"))?,
            ) as usize;
            if stdout > STDOUT_LIMIT || stderr > STDERR_LIMIT {
                return Err(invalid("oversized guardian result"));
            }
            let length = HEADER + stdout + stderr;
            if frame.len() < length {
                return Ok(None);
            }
            if frame.len() > length {
                return Err(invalid("unsolicited guardian completion"));
            }
            Ok(Some(Self {
                code: frame[1],
                stdout: frame[HEADER..HEADER + stdout].to_vec(),
                stderr: frame[HEADER + stdout..].to_vec(),
            }))
        }
    }

    fn observer_watchdog(deadline: Arc<AtomicU64>) -> Result<()> {
        let stdout_flags = rustix::fs::fcntl_getfl(rustix::stdio::stdout())?;
        let stderr_flags = rustix::fs::fcntl_getfl(rustix::stdio::stderr())?;
        std::thread::Builder::new()
            .name("rch-source-observer-deadline".into())
            .stack_size(128 * 1024)
            .spawn(move || {
                loop {
                    if now() >= deadline.load(Ordering::SeqCst) {
                        let _ = rustix::fs::fcntl_setfl(rustix::stdio::stdout(), stdout_flags);
                        let _ = rustix::fs::fcntl_setfl(rustix::stdio::stderr(), stderr_flags);
                        // Closing the private owner endpoint revokes the guardian
                        // even if this observer is blocked in spawn or delivery.
                        std::process::exit(REFUSED);
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
            })?;
        Ok(())
    }

    fn observe(replies: &[&[u8]], scale: f64) -> Result<i32> {
        let interrupted = signals()?;
        let execution = now() + (15.0 * scale * SECOND as f64).ceil() as u64;
        // The original one-second escalation/settlement allowance is fixed.
        let settlement = execution + SECOND;
        let delivery = (2.0 * scale * SECOND as f64).ceil() as u64;
        let hard_deadline = Arc::new(AtomicU64::new(settlement + delivery));
        observer_watchdog(Arc::clone(&hard_deadline))?;
        let (mut guardian, owner) = launch(GUARDIAN, &[execution.to_string()], true, settlement)?;
        // Only sh consumes the real upload. Closing this observer's duplicate
        // also prevents an incomplete upload from surviving observer death.
        rustix::stdio::dup2_stdin(File::open("/dev/null")?)?;
        let mut frame = Vec::new();
        let mut eof = false;
        let mut payload = None;
        let mut requested = false;
        let mut failure = UNSETTLED;
        let result = (|| -> Result<bool> {
            while now() < settlement && !interrupted.load(Ordering::SeqCst) {
                if receive(&owner, &mut frame, FRAME_LIMIT, &mut eof)? {
                    return Ok(false);
                }
                if frame.first() == Some(&b'X') {
                    if frame.len() >= 2 {
                        if frame == b"XO" {
                            failure = OVERFLOW;
                        }
                        return Ok(false);
                    }
                } else if !requested && let Some(result) = Payload::read(&frame)? {
                    if result.code == 0 && !replies.contains(&result.stdout.as_slice()) {
                        failure = READINESS;
                        return Ok(false);
                    }
                    // A stop, continue, or death before this request cannot
                    // authorize a receipt, even if program bytes look valid.
                    if guardian.state(true)?.is_some() {
                        return Ok(false);
                    }
                    write_before(&owner, b"F", execution, &interrupted)?;
                    payload = Some(result);
                    requested = true;
                }
                if let Some(state) = guardian.state(true)? {
                    if !requested || state.stopped() || state.continued() {
                        return Ok(false);
                    }
                    break;
                }
                if eof {
                    break;
                }
                pause(&mut [PollFd::new(&owner, PollFlags::IN)], settlement)?;
            }
            guardian.signal()?;
            if !requested || interrupted.load(Ordering::SeqCst) || now() >= settlement {
                return Ok(false);
            }
            // The guardian stays unreaped throughout both complete snapshots.
            if !quiescent(guardian.pid, settlement, &interrupted)? {
                return Ok(false);
            }
            let status = guardian.reap(settlement)?;
            while !eof {
                if receive(&owner, &mut frame, FRAME_LIMIT, &mut eof)? {
                    return Ok(false);
                }
                if !eof && now() >= settlement {
                    return Ok(false);
                }
            }
            let Some(payload) = &payload else {
                return Ok(false);
            };
            let mut expected = payload.frame();
            expected.push(b'D');
            Ok(status.signal() == Some(signal_hook::consts::SIGKILL)
                && frame == expected
                && now() < settlement
                && !interrupted.load(Ordering::SeqCst))
        })();
        // Drop always attempts exact-child and pinned-group revocation before
        // releasing ownership, including every malformed/oversized response.
        drop(guardian);
        drop(owner);
        let mut output = if matches!(result, Ok(true)) {
            payload.ok_or_else(|| invalid("missing settled result"))?
        } else {
            Payload {
                code: REFUSED as u8,
                stdout: Vec::new(),
                stderr: failure.to_vec(),
            }
        };
        if output.code >= 128 {
            output.stderr.extend_from_slice(format!(
                "RCH_SOURCE_NAMESPACE_PROCESS_TERMINATED status={} signal={} signal_origin=unknown\n",
                output.code, output.code - 128,
            ).as_bytes());
            if output.stderr.len() > STDERR_LIMIT {
                output = Payload {
                    code: REFUSED as u8,
                    stdout: Vec::new(),
                    stderr: OVERFLOW.to_vec(),
                };
            }
        }
        let deadline = now() + delivery;
        hard_deadline.store(deadline, Ordering::SeqCst);
        // Diagnostics finish before any readiness. Both streams share this
        // deadline; blocked SSH readers do not retain the observer indefinitely.
        {
            let _restore = RestoreFlags::new(rustix::stdio::stderr())?;
            write_before(
                rustix::stdio::stderr(),
                &output.stderr,
                deadline,
                &interrupted,
            )?;
        }
        if output.code == 0 {
            let _restore = RestoreFlags::new(rustix::stdio::stdout())?;
            write_before(
                rustix::stdio::stdout(),
                &output.stdout,
                deadline,
                &interrupted,
            )?;
        }
        Ok(if interrupted.load(Ordering::SeqCst) {
            REFUSED
        } else {
            i32::from(output.code)
        })
    }

    struct OwnGroup(Pid);

    impl OwnGroup {
        fn establish() -> Result<Self> {
            let pid = rustix::process::setsid()?;
            if pid != rustix::process::getpid() || pid != rustix::process::getpgrp() {
                return Err(invalid("missing private control session"));
            }
            Ok(Self(pid))
        }

        fn kill(&self) -> ! {
            let _ = rustix::process::kill_process_group(self.0, Signal::KILL);
            std::process::exit(REFUSED);
        }
    }

    impl Drop for OwnGroup {
        fn drop(&mut self) {
            let _ = rustix::process::kill_process_group(self.0, Signal::KILL);
        }
    }

    fn deadline(argument: &OsString) -> Result<u64> {
        let value = argument
            .to_str()
            .filter(|text| {
                !text.is_empty()
                    && text.len() <= 20
                    && text.bytes().all(|byte| byte.is_ascii_digit())
            })
            .and_then(|text| text.parse::<u64>().ok())
            .ok_or_else(|| invalid("invalid internal control deadline"))?;
        if value <= now() || value > now().saturating_add(151 * SECOND) {
            return Err(invalid("expired or unbounded internal control deadline"));
        }
        Ok(value)
    }

    /// Started before sh/ps spawn or any filesystem census. This thread uses
    /// only the private socket, signals and the monotonic clock, so blocked
    /// exec, output and procfs operations cannot suspend lifetime enforcement.
    fn group_watchdog(
        group: Pid,
        deadline: u64,
        interrupted: Arc<AtomicBool>,
        ready: Option<Arc<AtomicBool>>,
    ) -> Result<()> {
        nonblocking(rustix::stdio::stdout())?;
        std::thread::Builder::new()
            .name("rch-source-control-owner".into())
            .stack_size(128 * 1024)
            .spawn(move || {
                let group = OwnGroup(group);
                let mut escalation = None;
                loop {
                    let current = now();
                    if let Some(kill_at) = escalation {
                        if current >= kill_at {
                            group.kill();
                        }
                    } else if interrupted.load(Ordering::SeqCst) || current >= deadline {
                        if ready.is_none() {
                            group.kill();
                        }
                        // Execution retains the fixed one-second TERM grace;
                        // census expiry has no executing metadata to unwind.
                        escalation = Some((current + SECOND).min(deadline + SECOND));
                        let _ = rustix::process::kill_process_group(group.0, Signal::TERM);
                    }
                    let mut request = [0_u8; 2];
                    match rustix::io::read(rustix::stdio::stdout(), &mut request) {
                        Ok(1)
                            if escalation.is_none()
                                && request[0] == b'F'
                                && ready
                                    .as_ref()
                                    .is_some_and(|flag| flag.load(Ordering::SeqCst)) =>
                        {
                            if !interrupted.load(Ordering::SeqCst) && now() < deadline {
                                let _ = rustix::io::write(rustix::stdio::stdout(), b"D");
                            }
                            group.kill();
                        }
                        Ok(_) => group.kill(),
                        Err(Errno::AGAIN | Errno::INTR) => {}
                        Err(_) => group.kill(),
                    }
                    if pause(
                        &mut [PollFd::from_borrowed_fd(
                            rustix::stdio::stdout(),
                            PollFlags::IN,
                        )],
                        escalation.unwrap_or(deadline),
                    )
                    .is_err()
                    {
                        group.kill();
                    }
                }
            })?;
        Ok(())
    }

    fn guardian(arguments: &[OsString]) -> Result<i32> {
        let [argument] = arguments else {
            return Err(invalid("invalid guardian arguments"));
        };
        let deadline = deadline(argument)?;
        let group = OwnGroup::establish()?;
        let interrupted = signals()?;
        let ready = Arc::new(AtomicBool::new(false));
        group_watchdog(
            group.0,
            deadline,
            Arc::clone(&interrupted),
            Some(Arc::clone(&ready)),
        )?;
        // Check owner liveness before starting a transaction, including a
        // guardian which only reached exec after its observer disappeared.
        let mut request = [0_u8; 1];
        match rustix::io::read(rustix::stdio::stdout(), &mut request) {
            Err(Errno::AGAIN) => {}
            _ => return Err(invalid("source observer disappeared before launch")),
        }
        let captured = match capture(deadline, &interrupted) {
            Ok(payload) => payload,
            Err(error) if error.kind() == io::ErrorKind::TimedOut => {
                // Do not let a scope drop shorten the independent watchdog's
                // TERM grace. It owns the final group-wide KILL at +1 second.
                loop {
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
            Err(error) => return Err(error),
        };
        let Some(payload) = captured else {
            let _ = write_before(rustix::stdio::stdout(), b"XO", deadline, &interrupted);
            group.kill();
        };
        ready.store(true, Ordering::SeqCst);
        write_before(
            rustix::stdio::stdout(),
            &payload.frame(),
            deadline,
            &interrupted,
        )?;
        // Only the independent owner thread may acknowledge F and stop this
        // group. An ordinary exit(137) cannot impersonate its deliberate kill.
        loop {
            pause(&mut [], deadline)?;
        }
    }

    fn capture(deadline: u64, interrupted: &AtomicBool) -> Result<Option<Payload>> {
        if interrupted.load(Ordering::SeqCst) || now() >= deadline {
            return Err(invalid("source execution expired before launch"));
        }
        let mut child = match Command::new("sh")
            .arg("-s")
            .stdin(Stdio::inherit())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(child) => child,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied
                ) =>
            {
                return Ok(Some(Payload {
                    code: 127,
                    stdout: Vec::new(),
                    stderr: Vec::new(),
                }));
            }
            Err(error) => return Err(error),
        };
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| invalid("missing program stdout"))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| invalid("missing program stderr"))?;
        nonblocking(&stdout)?;
        nonblocking(&stderr)?;
        rustix::stdio::dup2_stdin(File::open("/dev/null")?)?;
        let mut out = Vec::new();
        let mut err = Vec::new();
        let mut out_eof = false;
        let mut err_eof = false;
        let mut status = None;
        while now() < deadline && !interrupted.load(Ordering::SeqCst) {
            if (!out_eof && receive(&stdout, &mut out, STDOUT_LIMIT, &mut out_eof)?)
                || (!err_eof && receive(&stderr, &mut err, STDERR_LIMIT, &mut err_eof)?)
            {
                return Ok(None);
            }
            if status.is_none() {
                status = child.try_wait()?;
            }
            if out_eof
                && err_eof
                && let Some(status) = status
            {
                let code = status
                    .code()
                    .or_else(|| status.signal().map(|signal| 128 + signal))
                    .and_then(|code| u8::try_from(code).ok())
                    .ok_or_else(|| invalid("invalid program exit status"))?;
                return Ok(Some(Payload {
                    code,
                    stdout: out,
                    stderr: err,
                }));
            }
            let mut descriptors = Vec::with_capacity(2);
            if !out_eof {
                descriptors.push(PollFd::new(&stdout, PollFlags::IN));
            }
            if !err_eof {
                descriptors.push(PollFd::new(&stderr, PollFlags::IN));
            }
            pause(&mut descriptors, deadline)?;
        }
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "source execution expired",
        ))
    }

    #[cfg(target_os = "linux")]
    pub(super) fn session_quiescent(group: Pid, allowance: Duration) -> Result<bool> {
        let nanos = u64::try_from(allowance.as_nanos())
            .map_err(|_| invalid("unbounded session-settlement allowance"))?;
        quiescent(group, now().saturating_add(nanos), &AtomicBool::new(false))
    }

    fn quiescent(group: Pid, deadline: u64, interrupted: &AtomicBool) -> Result<bool> {
        let (mut child, owner) = launch(
            CHECKER,
            &[group.as_raw_pid().to_string(), deadline.to_string()],
            false,
            deadline,
        )?;
        let mut bytes = Vec::new();
        let mut eof = false;
        while now() < deadline && !interrupted.load(Ordering::SeqCst) {
            if receive(&owner, &mut bytes, 1, &mut eof)? {
                return Ok(false);
            }
            if let Some(state) = child.state(true)? {
                if state.stopped() || state.continued() {
                    return Ok(false);
                }
                // Keep its PID pinned through signalling its own ps/helper
                // group, just as for the execution guardian.
                child.signal()?;
                let status = child.reap(deadline)?;
                while !eof {
                    if receive(&owner, &mut bytes, 1, &mut eof)? || now() >= deadline {
                        return Ok(false);
                    }
                }
                return Ok(status.success()
                    && bytes == b"E"
                    && !interrupted.load(Ordering::SeqCst));
            }
            if eof && bytes != b"E" {
                return Ok(false);
            }
            pause(&mut [PollFd::new(&owner, PollFlags::IN)], deadline)?;
        }
        Ok(false)
    }

    fn checker(arguments: &[OsString]) -> Result<i32> {
        let [group, end] = arguments else {
            return Err(invalid("invalid checker arguments"));
        };
        let group = group
            .to_str()
            .and_then(|text| text.parse::<i32>().ok())
            .and_then(Pid::from_raw)
            .filter(|pid| !pid.is_init())
            .ok_or_else(|| invalid("invalid checker target"))?;
        let deadline = deadline(end)?;
        let own = OwnGroup::establish()?;
        if own.0 == group {
            return Err(invalid("checker cannot observe its own session"));
        }
        let interrupted = signals()?;
        group_watchdog(own.0, deadline, Arc::clone(&interrupted), None)?;
        // Do not keep inherited source lock descriptions alive while checking.
        // Collect first: the directory's own descriptor is gone before closing,
        // and the watchdog allocates no descriptors during this handoff.
        let descriptors: Vec<i32> = std::fs::read_dir("/dev/fd")?
            .map(|entry| entry.map(|entry| entry.file_name().to_string_lossy().parse::<i32>().ok()))
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .flatten()
            .filter(|fd| *fd >= 3)
            .collect();
        for descriptor in descriptors {
            let _ = nix::unistd::close(descriptor);
        }
        let mut consecutive = 0;
        while now() < deadline && !interrupted.load(Ordering::SeqCst) {
            consecutive = if session_empty(group)? {
                consecutive + 1
            } else {
                0
            };
            if consecutive == 2 {
                write_before(rustix::stdio::stdout(), b"E", deadline, &interrupted)?;
                // Normal exit, not the Drop-time group kill, is part of the
                // receipt. The observer still signals the pinned checker group.
                std::mem::forget(own);
                return Ok(0);
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "source census expired",
        ))
    }

    #[cfg(target_os = "linux")]
    fn bounded_file(path: impl AsRef<Path>, limit: usize) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        File::open(path)?
            .take((limit + 1) as u64)
            .read_to_end(&mut bytes)?;
        if bytes.len() > limit {
            return Err(invalid("oversized process observation"));
        }
        Ok(bytes)
    }

    #[cfg(target_os = "linux")]
    #[derive(Debug, PartialEq, Eq)]
    struct Record {
        pid: u32,
        state: u8,
        group: u32,
        session: u32,
        threads: u32,
        birth: u64,
    }

    #[cfg(target_os = "linux")]
    fn record(path: impl AsRef<Path>) -> Result<Record> {
        let bytes = bounded_file(path, 8192)?;
        let separator = bytes
            .windows(2)
            .rposition(|bytes| bytes == b") ")
            .ok_or_else(|| invalid("invalid process stat framing"))?;
        let pid = bytes[..separator]
            .split(|byte| *byte == b' ')
            .next()
            .ok_or_else(|| invalid("missing process identity"))?;
        let fields: Vec<_> = bytes[separator + 2..]
            .split(|byte| byte.is_ascii_whitespace())
            .filter(|field| !field.is_empty())
            .collect();
        let number = |bytes: &[u8]| -> Result<u64> {
            if bytes.is_empty() || !bytes.iter().all(u8::is_ascii_digit) {
                return Err(invalid("invalid process number"));
            }
            std::str::from_utf8(bytes)
                .ok()
                .and_then(|text| text.parse().ok())
                .ok_or_else(|| invalid("invalid process number"))
        };
        if fields.len() < 20 || fields[0].len() != 1 || !b"RSDTtKWPIXZx".contains(&fields[0][0]) {
            return Err(invalid("invalid process state"));
        }
        let narrow = |bytes: &[u8]| {
            u32::try_from(number(bytes)?).map_err(|_| invalid("invalid process identifier"))
        };
        let result = Record {
            pid: narrow(pid)?,
            state: fields[0][0],
            group: narrow(fields[2])?,
            session: narrow(fields[3])?,
            threads: narrow(fields[17])?,
            birth: number(fields[19])?,
        };
        if result.pid == 0 || result.threads == 0 {
            return Err(invalid("empty process identity"));
        }
        Ok(result)
    }

    #[cfg(target_os = "linux")]
    fn verify_linux_namespace(status: &[u8], pid: u32) -> Result<()> {
        let namespaces: Vec<_> = status
            .split(|byte| *byte == b'\n')
            .filter_map(|line| line.strip_prefix(b"NSpid:"))
            .map(|line| {
                line.split(|byte| byte.is_ascii_whitespace())
                    .filter(|part| !part.is_empty())
                    .collect::<Vec<_>>()
            })
            .collect();
        let pid = pid.to_string();
        if namespaces != vec![vec![pid.as_bytes()]] {
            return Err(invalid("unverified process namespace"));
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn verify_linux_observer(record: &Record, pid: u32, group: u32, session: u32) -> Result<()> {
        if (record.pid, record.group, record.session) != (pid, group, session) {
            return Err(invalid("foreign process observation"));
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn linux_view() -> Result<()> {
        let status = bounded_file("/proc/self/status", 1_048_576)?;
        verify_linux_namespace(&status, std::process::id())?;
        let record = record("/proc/self/stat")?;
        verify_linux_observer(
            &record,
            std::process::id(),
            rustix::process::getpgrp().as_raw_pid() as u32,
            rustix::process::getsid(None)?.as_raw_pid() as u32,
        )
    }

    #[cfg(target_os = "linux")]
    fn terminal_tasks_empty(process: &Path, observed: &Record) -> Result<bool> {
        let mut count = 0;
        for task in std::fs::read_dir(process.join("task"))? {
            let task = task?;
            let name = task.file_name();
            let tid = name
                .to_str()
                .filter(|name| !name.is_empty() && name.bytes().all(|byte| byte.is_ascii_digit()))
                .and_then(|name| name.parse::<u32>().ok())
                .ok_or_else(|| invalid("invalid task census"))?;
            let thread = record(task.path().join("stat"))?;
            count += 1;
            if thread.pid != tid
                || (thread.group, thread.session) != (observed.group, observed.session)
            {
                return Err(invalid("task census changed identity"));
            }
            if !b"ZXx".contains(&thread.state) {
                return Ok(false);
            }
        }
        Ok(count == observed.threads && record(process.join("stat"))? == *observed)
    }

    #[cfg(target_os = "linux")]
    fn session_empty(group: Pid) -> Result<bool> {
        linux_view()?;
        let group = group.as_raw_pid() as u32;
        let mut owner = false;
        for entry in std::fs::read_dir("/proc")? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(pid) = name
                .to_str()
                .filter(|name| !name.is_empty() && name.bytes().all(|byte| byte.is_ascii_digit()))
                .and_then(|name| name.parse::<u32>().ok())
            else {
                continue;
            };
            let observed = match record(entry.path().join("stat")) {
                Ok(record) => record,
                Err(error) if matches!(error.raw_os_error(), Some(2 | 3)) => continue,
                Err(error) => return Err(error),
            };
            if observed.pid != pid {
                return Err(invalid("process census changed identity"));
            }
            if pid == group {
                owner = observed.group == group && observed.session == group;
            }
            if observed.group != group && observed.session != group {
                continue;
            }
            if !b"ZXx".contains(&observed.state) {
                return Ok(false);
            }
            // A dead main thread can retain executing siblings. Require every
            // task, the exact task count, and an unchanged leader birth record.
            let tasks = terminal_tasks_empty(&entry.path(), &observed);
            match tasks {
                Ok(true) => {}
                Ok(false) => return Ok(false),
                Err(error) if matches!(error.raw_os_error(), Some(2 | 3)) => return Ok(false),
                Err(error) => return Err(error),
            }
        }
        linux_view()?;
        Ok(owner)
    }

    #[cfg(target_os = "macos")]
    fn session_empty(group: Pid) -> Result<bool> {
        use std::collections::HashSet;
        let mut child = Command::new("ps")
            .args(["-axo", "pid=,pgid=,stat="])
            .env("LC_ALL", "C")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        let mut bytes = Vec::new();
        child
            .stdout
            .take()
            .ok_or_else(|| invalid("missing census stdout"))?
            .take(1_048_577)
            .read_to_end(&mut bytes)?;
        if bytes.len() > 1_048_576 || !child.wait()?.success() {
            return Err(invalid("unavailable process census"));
        }
        let mut owner = false;
        let mut observer = false;
        let mut seen = HashSet::new();
        for line in bytes
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
        {
            let fields: Vec<_> = line
                .split(|byte| byte.is_ascii_whitespace())
                .filter(|field| !field.is_empty())
                .collect();
            let number = |field: &[u8]| {
                std::str::from_utf8(field)
                    .ok()
                    .filter(|text| {
                        !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit())
                    })
                    .and_then(|text| text.parse::<i32>().ok())
            };
            if fields.len() != 3 || fields[2].is_empty() || !b"RSDTIUZE".contains(&fields[2][0]) {
                return Err(invalid("invalid process census"));
            }
            let pid = number(fields[0]).ok_or_else(|| invalid("invalid census identity"))?;
            let pgid = number(fields[1]).ok_or_else(|| invalid("invalid census group"))?;
            if !seen.insert(pid) {
                return Err(invalid("duplicate process census entry"));
            }
            if pid == rustix::process::getpid().as_raw_pid() {
                observer =
                    pgid == rustix::process::getpgrp().as_raw_pid() && pgid != group.as_raw_pid();
            }
            if pid == group.as_raw_pid() {
                owner = pgid == group.as_raw_pid();
            }
            if pid == Pid::from_child(&child).as_raw_pid() {
                continue;
            }
            // Kernel entries may use PID/group zero. They cannot belong to
            // this positive, pinned session; getsid(0) would inspect ourselves.
            let Some(pid) = Pid::from_raw(pid) else {
                continue;
            };
            let session = match rustix::process::getsid(Some(pid)) {
                Ok(session) => session,
                Err(Errno::SRCH) => continue,
                Err(error) => return Err(error.into()),
            };
            if (pgid == group.as_raw_pid() || session == group) && fields[2][0] != b'Z' {
                return Ok(false);
            }
        }
        if !observer {
            return Err(invalid("census omitted observer"));
        }
        Ok(owner)
    }

    // Byte/file fixtures exercise the actual census validators. These do not
    // claim live-kernel coverage of a zombie leader with executing siblings.
    #[cfg(all(test, target_os = "linux"))]
    mod linux_census_tests {
        use super::*;

        fn leader() -> Record {
            Record {
                pid: 41,
                state: b'Z',
                group: 301,
                session: 301,
                threads: 2,
                birth: 901,
            }
        }

        fn encode(record: &Record) -> String {
            let mut fields = vec!["0".to_owned(); 20];
            fields[0] = char::from(record.state).to_string();
            fields[2] = record.group.to_string();
            fields[3] = record.session.to_string();
            fields[17] = record.threads.to_string();
            fields[19] = record.birth.to_string();
            format!(
                "{} (worker ) with (parentheses)) {}\n",
                record.pid,
                fields.join(" ")
            )
        }

        fn write_record(path: impl AsRef<Path>, observed: &Record) {
            std::fs::write(path, encode(observed)).unwrap();
        }

        fn fixture() -> std::path::PathBuf {
            let path = tempfile::Builder::new()
                .prefix("rch-source-census-")
                .tempdir()
                .unwrap()
                .keep();
            std::fs::create_dir_all(path.join("task/41")).unwrap();
            std::fs::create_dir_all(path.join("task/42")).unwrap();
            let observed = leader();
            write_record(path.join("stat"), &observed);
            write_record(path.join("task/41/stat"), &observed);
            write_record(
                path.join("task/42/stat"),
                &Record {
                    pid: 42,
                    ..leader()
                },
            );
            path
        }

        #[test]
        fn foreign_incomplete_or_nested_pid_views_never_authorize_absence() {
            assert!(verify_linux_namespace(b"Name:\tworker\nNSpid:\t41\n", 41).is_ok());
            for status in [
                b"Name:\tworker\n".as_slice(),
                b"NSpid:\n",
                b"NSpid:\t142\n",
                b"NSpid:\t142 41\n",
                b"NSpid:\t41 41\n",
                b"NSpid:\t41\nNSpid:\t41\n",
                b"NSpid:\t041\n",
                b"NSpid:\t41\0\n",
            ] {
                assert!(verify_linux_namespace(status, 41).is_err(), "{status:?}");
            }
            assert!(verify_linux_observer(&leader(), 41, 301, 301).is_ok());
            for expected in [(42, 301, 301), (41, 302, 301), (41, 301, 302)] {
                assert!(
                    verify_linux_observer(&leader(), expected.0, expected.1, expected.2).is_err()
                );
            }
        }

        #[test]
        fn process_records_are_bounded_and_do_not_repair_malformed_evidence() {
            let path = fixture().join("stat");
            let expected = leader();
            assert_eq!(record(&path).unwrap(), expected);
            let mut exact = encode(&expected).into_bytes();
            exact.resize(8192, b' ');
            std::fs::write(&path, &exact).unwrap();
            assert_eq!(record(&path).unwrap(), expected);
            exact.push(b' ');
            std::fs::write(&path, exact).unwrap();
            assert!(record(&path).is_err(), "one byte beyond the stat bound");
            for malformed in [
                "41 (worker) Z 1 301 301\n".to_owned(),
                encode(&expected).replacen(" Z ", " ZZ ", 1),
                encode(&expected).replacen("301 301", "-1 301", 1),
                encode(&Record { pid: 0, ..leader() }),
                encode(&Record {
                    threads: 0,
                    ..leader()
                }),
            ] {
                std::fs::write(&path, malformed).unwrap();
                assert!(record(&path).is_err());
            }
        }

        #[test]
        fn zombie_leader_is_not_empty_while_any_sibling_task_executes() {
            let path = fixture();
            let observed = record(path.join("stat")).unwrap();
            write_record(
                path.join("task/42/stat"),
                &Record {
                    pid: 42,
                    state: b'S',
                    ..leader()
                },
            );
            assert!(!terminal_tasks_empty(&path, &observed).unwrap());
            write_record(
                path.join("task/42/stat"),
                &Record {
                    pid: 42,
                    ..leader()
                },
            );
            assert!(terminal_tasks_empty(&path, &observed).unwrap());
        }

        #[test]
        fn incomplete_task_census_and_changed_leader_birth_cannot_settle() {
            let path = fixture();
            let observed = Record {
                threads: 3,
                ..leader()
            };
            write_record(path.join("stat"), &observed);
            assert!(
                !terminal_tasks_empty(&path, &observed).unwrap(),
                "missing recorded task"
            );
            let path = fixture();
            let observed = record(path.join("stat")).unwrap();
            write_record(
                path.join("stat"),
                &Record {
                    birth: 902,
                    ..leader()
                },
            );
            assert!(
                !terminal_tasks_empty(&path, &observed).unwrap(),
                "replaced leader identity"
            );
            let path = fixture();
            std::fs::create_dir(path.join("task/43")).unwrap();
            assert!(
                terminal_tasks_empty(&path, &leader()).is_err(),
                "unreadable task record"
            );
        }

        #[test]
        fn task_identity_or_membership_changes_are_never_ignored() {
            for task in [
                Record {
                    pid: 43,
                    ..leader()
                },
                Record {
                    pid: 42,
                    group: 302,
                    ..leader()
                },
                Record {
                    pid: 42,
                    session: 302,
                    ..leader()
                },
            ] {
                let path = fixture();
                write_record(path.join("task/42/stat"), &task);
                assert!(terminal_tasks_empty(&path, &leader()).is_err(), "{task:?}");
            }
            let path = fixture();
            std::fs::create_dir(path.join("task/not-a-tid")).unwrap();
            assert!(terminal_tasks_empty(&path, &leader()).is_err());
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn strict_scale_and_reply_contracts() {
            for value in ["1", "+1", "1.", "1.5", "10", "1e1", ".1e1"] {
                assert!(scale(value).is_ok(), "{value}");
            }
            for value in [
                "", " 1", "1 ", "nan", "inf", "0.9", "10.1", "1e", "١", "1\n",
            ] {
                assert!(scale(value).is_err(), "{value}");
            }
            assert_eq!(
                replies("RCH_SOURCE_INTENT_FINISHED"),
                Some(&[b"".as_slice()][..])
            );
            assert!(replies("RCH_SOURCE_NAMESPACE_FINISHED").is_none());
            assert_eq!(replies("RCH_SOURCE_AUTHORITY_DISCOVERY").unwrap().len(), 3);
        }

        #[test]
        fn bounded_result_framing_never_accepts_partial_or_extra_data() {
            let payload = Payload {
                code: 75,
                stdout: b"owned".to_vec(),
                stderr: b"busy\n".to_vec(),
            };
            let frame = payload.frame();
            for size in 0..frame.len() {
                assert!(Payload::read(&frame[..size]).unwrap().is_none());
            }
            assert_eq!(Payload::read(&frame).unwrap().unwrap().code, 75);
            let mut extra = frame;
            extra.push(b'D');
            assert!(Payload::read(&extra).is_err());
            let mut oversized = vec![b'R', 0];
            oversized.extend_from_slice(&4097_u32.to_be_bytes());
            oversized.extend_from_slice(&0_u32.to_be_bytes());
            assert!(Payload::read(&oversized).is_err());
        }

        #[test]
        fn stopped_child_before_private_session_is_revoked_and_reaped() {
            // Exercise the pre-setsid interval with a real stopped process,
            // while keeping its ordinary caller group alive throughout.
            let _signals = signals().unwrap();
            let original_group = rustix::process::getpgrp();
            let child = Command::new("/bin/sh")
                .args(["-c", "kill -STOP $$; sleep 60"])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            let end = now() + 2 * SECOND;
            let mut owned = Pinned::new(child, end);
            loop {
                if owned
                    .state(true)
                    .unwrap()
                    .is_some_and(|state| state.stopped())
                {
                    break;
                }
                assert!(
                    now() < end,
                    "fixture must really stop before session creation"
                );
                pause(&mut [], end).unwrap();
            }
            assert_eq!(
                rustix::process::getpgid(Some(owned.pid)).unwrap(),
                original_group
            );
            owned.signal().unwrap();
            assert_eq!(
                owned.reap(end).unwrap().signal(),
                Some(signal_hook::consts::SIGKILL)
            );
            assert_eq!(rustix::process::getpgrp(), original_group);
            assert_eq!(
                owned.state(false).unwrap_err().raw_os_error(),
                Some(nix::errno::Errno::ECHILD as i32)
            );
        }
    }
}
