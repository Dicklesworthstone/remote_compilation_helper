//! Opt-in worker-local RABS preparation followed by exactly one Cargo exec.
//!
//! Preparation runs in a private session. Its guardian observes the adapter's
//! lifetime independently, including when the adapter is stopped or killed.
//! Cargo keeps its original stdin, opaque arguments and jobserver descriptors;
//! none of them are inherited by preparation or the shared daemon.

use std::ffi::OsString;

#[cfg(target_os = "linux")]
mod prepare;

pub(crate) fn main(arguments: &[OsString]) -> i32 {
    #[cfg(target_os = "linux")]
    {
        native::main(arguments)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = arguments;
        eprintln!("RCH_RABS_WORKER_UNAVAILABLE: native preparation requires Linux");
        73
    }
}

#[cfg(target_os = "linux")]
fn now_ns() -> u64 {
    let time = rustix::time::clock_gettime(rustix::time::ClockId::Monotonic);
    u64::try_from(time.tv_sec).unwrap_or_default() * 1_000_000_000
        + u64::try_from(time.tv_nsec).unwrap_or_default()
}

#[cfg(target_os = "linux")]
fn native_worker_executable() -> std::io::Result<std::path::PathBuf> {
    // Reexecute the running image even during an atomic worker upgrade.
    Ok("/proc/self/exe".into())
}

#[cfg(target_os = "linux")]
mod native {
    use super::{native_worker_executable, now_ns, prepare};
    use nix::sys::signal::{SigSet, Signal as NixSignal};
    use rustix::event::{PollFd, PollFlags, Timespec, poll};
    use rustix::fd::{AsFd, OwnedFd};
    use rustix::fs::OFlags;
    use rustix::io::Errno;
    use rustix::process::{Pid, Signal, WaitId, WaitIdOptions};
    use serde::{Deserialize, Serialize};
    use std::ffi::OsString;
    use std::io::{self, Read, Write};
    use std::os::unix::net::UnixStream;
    use std::os::unix::process::{CommandExt, ExitStatusExt};
    use std::process::{Child, Command, Stdio};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::Duration;

    const ACTIVE: &str = "RCH_RABS_WORKER_ACTIVE";
    const MILLISECOND: u64 = 1_000_000;
    const CLEANUP: Duration = Duration::from_millis(250);
    const RESPONSE_LIMIT: usize = 1024 * 1024;
    const LOG_LIMIT: usize = 16 * 1024;
    const HEADER: usize = 10;
    const FRAME_LIMIT: usize = HEADER + RESPONSE_LIMIT + LOG_LIMIT;
    const UNCONFIRMED: i32 = 255;

    type Result<T> = io::Result<T>;

    fn invalid(message: &'static str) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, message)
    }

    fn remaining(deadline: u64) -> Result<()> {
        if now_ns() >= deadline {
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "preparation deadline expired",
            ))
        } else {
            Ok(())
        }
    }

    fn nonblocking(descriptor: impl AsFd) -> Result<()> {
        let flags = rustix::fs::fcntl_getfl(&descriptor)?;
        rustix::fs::fcntl_setfl(descriptor, flags | OFlags::NONBLOCK)?;
        Ok(())
    }

    fn pause(descriptors: &mut [PollFd<'_>], deadline: u64) -> Result<()> {
        let duration = Timespec {
            tv_sec: 0,
            tv_nsec: deadline.saturating_sub(now_ns()).min(5 * MILLISECOND) as _,
        };
        match poll(descriptors, Some(&duration)) {
            Ok(_) | Err(Errno::INTR) => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    fn deadline(argument: &OsString) -> Result<u64> {
        let parsed = argument
            .to_str()
            .filter(|text| {
                !text.is_empty() && text.len() <= 20 && text.bytes().all(|b| b.is_ascii_digit())
            })
            .and_then(|text| text.parse::<u64>().ok())
            .ok_or_else(|| invalid("invalid preparation deadline"))?;
        if parsed <= now_ns() || parsed > now_ns().saturating_add(36_000 * MILLISECOND) {
            return Err(invalid("expired or unbounded preparation deadline"));
        }
        Ok(parsed)
    }

    fn bounded_milliseconds(value: Option<&str>, default: u64, maximum: u64) -> u64 {
        value
            .and_then(|value| value.trim().parse::<i128>().ok())
            .map(|number| number.clamp(0, i128::from(maximum)) as u64)
            .unwrap_or(default)
    }

    fn preparation_budget() -> u64 {
        let startup = bounded_milliseconds(
            std::env::var("CARGO_RABS_STARTUP_MS").ok().as_deref(),
            5_000,
            30_000,
        );
        bounded_milliseconds(
            std::env::var("RCH_RABS_PREPARE_TIMEOUT_MS").ok().as_deref(),
            startup + 2_000,
            35_000,
        )
    }

    fn close_inherited_descriptors() -> Result<()> {
        // Collect first, so the enumeration's own descriptor is already closed.
        let descriptors = std::fs::read_dir("/proc/self/fd")?
            .map(|entry| entry.map(|entry| entry.file_name().to_string_lossy().parse::<i32>().ok()))
            .collect::<Result<Vec<_>>>()?;
        for descriptor in descriptors.into_iter().flatten().filter(|fd| *fd >= 3) {
            let _ = nix::unistd::close(descriptor);
        }
        Ok(())
    }

    fn child_is_autoreaped() -> Result<bool> {
        let mut bytes = Vec::new();
        std::fs::File::open("/proc/self/status")?
            .take(1024 * 1024 + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() > 1024 * 1024 {
            return Err(invalid("process signal status exceeded its bound"));
        }
        let text = std::str::from_utf8(&bytes).map_err(|_| invalid("invalid signal status"))?;
        let ignored = text
            .lines()
            .find_map(|line| line.strip_prefix("SigIgn:"))
            .and_then(|value| u64::from_str_radix(value.trim(), 16).ok())
            .ok_or_else(|| invalid("missing signal disposition"))?;
        Ok(ignored & (1_u64 << (signal_hook::consts::SIGCHLD - 1)) != 0)
    }

    struct Signals {
        interrupted: Arc<AtomicUsize>,
        original_mask: SigSet,
        registrations: Vec<signal_hook::SigId>,
    }

    impl Signals {
        fn new() -> Result<Self> {
            let mut signals = Self {
                interrupted: Arc::new(AtomicUsize::new(0)),
                original_mask: SigSet::thread_get_mask().map_err(io::Error::other)?,
                registrations: Vec::new(),
            };
            let mut unblocked = SigSet::empty();
            for signal in [NixSignal::SIGHUP, NixSignal::SIGINT, NixSignal::SIGTERM] {
                signals
                    .registrations
                    .push(signal_hook::flag::register_usize(
                        signal as i32,
                        Arc::clone(&signals.interrupted),
                        signal as usize,
                    )?);
                unblocked.add(signal);
            }
            for signal in [NixSignal::SIGCHLD, NixSignal::SIGPIPE] {
                signals.registrations.push(signal_hook::flag::register(
                    signal as i32,
                    Arc::new(AtomicBool::new(false)),
                )?);
                unblocked.add(signal);
            }
            unblocked.thread_unblock().map_err(io::Error::other)?;
            Ok(signals)
        }

        fn number(&self) -> usize {
            self.interrupted.load(Ordering::SeqCst)
        }

        fn ready_to_exec(&mut self) -> Result<()> {
            // After setup is settled, cancellation must not fall into the
            // gap between the final flag check and exec. Default termination
            // is safe now; caught handlers reset normally in the Cargo image.
            for signal in [NixSignal::SIGHUP, NixSignal::SIGINT, NixSignal::SIGTERM] {
                self.registrations
                    .push(signal_hook::flag::register_conditional_default(
                        signal as i32,
                        Arc::new(AtomicBool::new(true)),
                    )?);
            }
            self.original_mask
                .thread_set_mask()
                .map_err(io::Error::other)
        }
    }

    impl Drop for Signals {
        fn drop(&mut self) {
            for registration in self.registrations.drain(..) {
                signal_hook::low_level::unregister(registration);
            }
            let _ = self.original_mask.thread_set_mask();
        }
    }

    struct Watchdog {
        finished: Arc<AtomicBool>,
        handle: Option<std::thread::JoinHandle<()>>,
    }

    impl Watchdog {
        fn new(deadline: u64) -> Result<Self> {
            let finished = Arc::new(AtomicBool::new(false));
            let observed = Arc::clone(&finished);
            let handle = std::thread::Builder::new()
                .name("rch-rabs-adapter-deadline".into())
                .stack_size(128 * 1024)
                .spawn(move || {
                    while !observed.load(Ordering::SeqCst) {
                        if now_ns() >= deadline {
                            // Closing the private guardian socket also revokes
                            // preparation if this thread's owner is kernel-blocked.
                            std::process::exit(UNCONFIRMED);
                        }
                        std::thread::sleep(Duration::from_millis(5));
                    }
                })?;
            Ok(Self {
                finished,
                handle: Some(handle),
            })
        }
    }

    impl Drop for Watchdog {
        fn drop(&mut self) {
            self.finished.store(true, Ordering::SeqCst);
            if let Some(handle) = self.handle.take() {
                let _ = handle.join();
            }
        }
    }

    struct Pinned {
        child: Child,
        pid: Pid,
        reaped: bool,
    }

    impl Pinned {
        fn new(child: Child) -> Self {
            Self {
                pid: Pid::from_child(&child),
                child,
                reaped: false,
            }
        }

        fn kill(&self) -> Result<()> {
            // WNOWAIT retains the kernel child relationship even after exit.
            // ECHILD is uncertainty, never permission to signal a remembered PID.
            rustix::process::waitid(
                WaitId::Pid(self.pid),
                WaitIdOptions::EXITED | WaitIdOptions::NOWAIT | WaitIdOptions::NOHANG,
            )?;
            for result in [
                rustix::process::kill_process_group(self.pid, Signal::KILL),
                rustix::process::kill_process(self.pid, Signal::KILL),
            ] {
                match result {
                    Ok(()) | Err(Errno::SRCH) => {}
                    Err(error) => return Err(error.into()),
                }
            }
            Ok(())
        }

        fn reap(&mut self, deadline: u64) -> Result<()> {
            loop {
                if rustix::process::waitid(
                    WaitId::Pid(self.pid),
                    WaitIdOptions::EXITED | WaitIdOptions::NOWAIT | WaitIdOptions::NOHANG,
                )?
                .is_some()
                {
                    self.child.wait()?;
                    self.reaped = true;
                    return Ok(());
                }
                remaining(deadline)?;
                pause(&mut [], deadline)?;
            }
        }

        fn settle(&mut self) -> Result<()> {
            let end = now_ns() + CLEANUP.as_nanos() as u64;
            self.kill()?;
            // Keep the guardian unreaped through the independent full-session
            // census. A dead main thread with live siblings is not settlement.
            if !crate::source_control::session_quiescent(self.pid, CLEANUP)? {
                return Err(invalid("preparation session is not quiescent"));
            }
            self.reap(end)
        }
    }

    impl Drop for Pinned {
        fn drop(&mut self) {
            if !self.reaped {
                let _ = self.kill();
                let _ = self.reap(now_ns() + CLEANUP.as_nanos() as u64);
            }
        }
    }

    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Response {
        prepared: Option<prepare::Prepared>,
        error: Option<String>,
    }

    struct Payload {
        code: u8,
        response: Vec<u8>,
        logs: Vec<u8>,
    }

    impl Payload {
        fn encode(&self) -> Vec<u8> {
            let mut bytes = Vec::with_capacity(HEADER + self.response.len() + self.logs.len());
            bytes.extend_from_slice(&[b'R', self.code]);
            bytes.extend_from_slice(&(self.response.len() as u32).to_be_bytes());
            bytes.extend_from_slice(&(self.logs.len() as u32).to_be_bytes());
            bytes.extend_from_slice(&self.response);
            bytes.extend_from_slice(&self.logs);
            bytes
        }

        fn decode(bytes: &[u8]) -> Result<Option<Self>> {
            if bytes.first().is_some_and(|byte| *byte != b'R') {
                return Err(invalid("preparation failed before a complete response"));
            }
            if bytes.len() < HEADER {
                return Ok(None);
            }
            let response = u32::from_be_bytes(bytes[2..6].try_into().unwrap()) as usize;
            let logs = u32::from_be_bytes(bytes[6..10].try_into().unwrap()) as usize;
            if response > RESPONSE_LIMIT || logs > LOG_LIMIT {
                return Err(invalid("preparation frame exceeded its bound"));
            }
            let end = HEADER + response + logs;
            if bytes.len() > end {
                return Err(invalid("preparation returned unsolicited bytes"));
            }
            if bytes.len() < end {
                return Ok(None);
            }
            Ok(Some(Self {
                code: bytes[1],
                response: bytes[HEADER..HEADER + response].to_vec(),
                logs: bytes[HEADER + response..].to_vec(),
            }))
        }
    }

    fn read_available(
        fd: impl AsFd,
        bytes: &mut Vec<u8>,
        limit: usize,
        eof: &mut bool,
    ) -> Result<()> {
        let mut buffer = [0_u8; 4096];
        let room = buffer.len().min(limit + 1 - bytes.len());
        match rustix::io::read(fd, &mut buffer[..room]) {
            Ok(0) => *eof = true,
            Ok(count) => bytes.extend_from_slice(&buffer[..count]),
            Err(Errno::AGAIN | Errno::INTR) => {}
            Err(error) => return Err(error.into()),
        }
        if bytes.len() > limit {
            return Err(invalid("preparation output exceeded its bound"));
        }
        Ok(())
    }

    fn send_before(fd: impl AsFd, bytes: &[u8], deadline: u64) -> Result<()> {
        nonblocking(&fd)?;
        let mut offset = 0;
        while offset < bytes.len() {
            remaining(deadline)?;
            match rustix::io::write(&fd, &bytes[offset..]) {
                Ok(0) => return Err(invalid("preparation response write returned zero")),
                Ok(count) => offset += count,
                Err(Errno::INTR) => {}
                Err(Errno::AGAIN) => pause(&mut [PollFd::new(&fd, PollFlags::OUT)], deadline)?,
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }

    fn observe(deadline: u64, signals: &Signals) -> Result<(Option<prepare::Prepared>, Vec<u8>)> {
        let (owner, remote) = match UnixStream::pair() {
            Ok(pair) => pair,
            Err(error) => return Ok((None, fallback_diagnostic(&error.to_string()))),
        };
        if let Err(error) = owner.set_nonblocking(true) {
            return Ok((None, fallback_diagnostic(&error.to_string())));
        }
        let child = match Command::new(native_worker_executable()?)
            .args(["worker-cache", "--guardian", &deadline.to_string()])
            .stdin(Stdio::null())
            .stdout(Stdio::from(OwnedFd::from(remote)))
            .stderr(Stdio::null())
            .spawn()
        {
            Ok(child) => child,
            Err(error) => return Ok((None, fallback_diagnostic(&error.to_string()))),
        };
        let mut guardian = Pinned::new(child);
        let mut bytes = Vec::new();
        let mut eof = false;
        let response = (|| -> Result<Payload> {
            loop {
                remaining(deadline)?;
                if signals.number() != 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::Interrupted,
                        "preparation cancelled",
                    ));
                }
                read_available(&owner, &mut bytes, FRAME_LIMIT, &mut eof)?;
                if let Some(payload) = Payload::decode(&bytes)? {
                    return Ok(payload);
                }
                if eof {
                    return Err(invalid(
                        "preparation guardian exited without a complete response",
                    ));
                }
                pause(&mut [PollFd::new(&owner, PollFlags::IN)], deadline)?;
            }
        })();
        let settled = guardian.settle();
        drop(owner);
        if settled.is_err() {
            return Err(invalid(
                "preparation cleanup is unconfirmed; Cargo was not run",
            ));
        }
        if signals.number() != 0 {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "preparation cancelled",
            ));
        }
        let payload = match response {
            Ok(payload) => payload,
            Err(error) => return Ok((None, fallback_diagnostic(&error.to_string()))),
        };
        let mut logs = payload.logs;
        let prepared = if payload.code == 0 {
            serde_json::from_slice::<Response>(&payload.response)
                .map_err(|error| error.to_string())
                .and_then(|response| match (response.prepared, response.error) {
                    (Some(prepared), None) if valid_prepared(&prepared) => Ok(prepared),
                    (None, Some(error)) => Err(error),
                    _ => Err("preparation returned an invalid environment selection".into()),
                })
        } else {
            Err(format!("preparation exited with status {}", payload.code))
        };
        match prepared {
            Ok(prepared) => Ok((Some(prepared), logs)),
            Err(error) => {
                let mut failure = fallback_diagnostic(&error);
                failure.append(&mut logs);
                Ok((None, failure))
            }
        }
    }

    fn valid_prepared(prepared: &prepare::Prepared) -> bool {
        use std::os::unix::ffi::OsStrExt;
        prepared.wrapper.is_absolute()
            && !prepared.wrapper.as_os_str().as_bytes().contains(&0)
            && prepared.socket.is_absolute()
            && prepared.socket.as_os_str().as_bytes().len() <= 107
            && !prepared.socket.as_os_str().as_bytes().contains(&0)
    }

    fn fallback_diagnostic(error: &str) -> Vec<u8> {
        let error = error.chars().take(4096).collect::<String>();
        format!("rch: worker-local RABS setup unavailable: {error}; using stock Cargo\n")
            .into_bytes()
    }

    struct OwnGroup(Pid);

    impl OwnGroup {
        fn establish() -> Result<Self> {
            let group = rustix::process::setsid()?;
            if group != rustix::process::getpid() || group != rustix::process::getpgrp() {
                return Err(invalid("missing private preparation session"));
            }
            Ok(Self(group))
        }
    }

    impl Drop for OwnGroup {
        fn drop(&mut self) {
            let _ = rustix::process::kill_process_group(self.0, Signal::KILL);
        }
    }

    fn guardian(deadline: u64) -> Result<()> {
        // Keep ownership on the main thread too: an error while delivering a
        // response must kill preparation even if the owner watcher has not
        // observed EOF yet and process exit would otherwise stop that thread.
        let ownership = OwnGroup::establish()?;
        let group = ownership.0;
        let signals = Signals::new()?;
        nonblocking(rustix::stdio::stdout())?;
        let interrupted = Arc::clone(&signals.interrupted);
        let (armed, ready) = std::sync::mpsc::sync_channel(0);
        std::thread::Builder::new()
            .name("rch-rabs-prepare-owner".into())
            .stack_size(128 * 1024)
            .spawn(move || {
                let revoke = || -> ! {
                    let _ = rustix::process::kill_process_group(group, Signal::KILL);
                    std::process::exit(UNCONFIRMED);
                };
                let mut bytes = [0_u8; 1];
                // Only the observer owns the peer. Unexpected data and EOF
                // both revoke preparation; no installed executable can arm it.
                match rustix::io::read(rustix::stdio::stdout(), &mut bytes) {
                    Err(Errno::AGAIN) if now_ns() < deadline => {}
                    _ => revoke(),
                }
                if armed.send(()).is_err() {
                    revoke();
                }
                loop {
                    if now_ns() >= deadline || interrupted.load(Ordering::SeqCst) != 0 {
                        revoke();
                    }
                    match rustix::io::read(rustix::stdio::stdout(), &mut bytes) {
                        Err(Errno::AGAIN | Errno::INTR) => {}
                        _ => revoke(),
                    }
                    if pause(
                        &mut [PollFd::from_borrowed_fd(
                            rustix::stdio::stdout(),
                            PollFlags::IN,
                        )],
                        deadline,
                    )
                    .is_err()
                    {
                        revoke();
                    }
                }
            })?;
        ready
            .recv()
            .map_err(|_| invalid("preparation lifetime watch did not arm"))?;
        close_inherited_descriptors()?;
        let result = capture_preparer(deadline);
        match result {
            Ok(payload) => send_before(rustix::stdio::stdout(), &payload.encode(), deadline)?,
            Err(_) => send_before(rustix::stdio::stdout(), b"X", deadline)?,
        }
        // Remain unreaped while the observer revokes and checks this session.
        loop {
            pause(&mut [], deadline)?;
        }
    }

    fn capture_preparer(deadline: u64) -> Result<Payload> {
        let mut child = Command::new(native_worker_executable()?)
            .args(["worker-cache", "--prepare", &deadline.to_string()])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let output = child
            .stdout
            .take()
            .ok_or_else(|| invalid("missing preparation response"))?;
        let diagnostic = child
            .stderr
            .take()
            .ok_or_else(|| invalid("missing preparation log"))?;
        nonblocking(&output)?;
        nonblocking(&diagnostic)?;
        let mut response = Vec::new();
        let mut logs = Vec::new();
        let mut response_eof = false;
        let mut log_eof = false;
        let mut truncated = false;
        let mut status = None;
        loop {
            remaining(deadline)?;
            if !response_eof {
                read_available(&output, &mut response, RESPONSE_LIMIT, &mut response_eof)?;
            }
            if !log_eof {
                let mut buffer = [0_u8; 4096];
                match rustix::io::read(&diagnostic, &mut buffer) {
                    Ok(0) => log_eof = true,
                    Ok(count) => {
                        let keep = count.min(LOG_LIMIT.saturating_sub(logs.len()));
                        logs.extend_from_slice(&buffer[..keep]);
                        truncated |= keep < count;
                    }
                    Err(Errno::AGAIN | Errno::INTR) => {}
                    Err(error) => return Err(error.into()),
                }
            }
            if status.is_none() {
                status = child.try_wait()?;
            }
            if response_eof
                && log_eof
                && let Some(status) = status
            {
                if truncated {
                    const MARKER: &[u8] = b"\nrch: RABS preparation diagnostics truncated\n";
                    logs.truncate(LOG_LIMIT - MARKER.len());
                    logs.extend_from_slice(MARKER);
                }
                let code = status
                    .code()
                    .or_else(|| status.signal().map(|signal| 128 + signal))
                    .and_then(|code| u8::try_from(code).ok())
                    .ok_or_else(|| invalid("invalid preparation status"))?;
                return Ok(Payload {
                    code,
                    response,
                    logs,
                });
            }
            let mut descriptors = Vec::new();
            if !response_eof {
                descriptors.push(PollFd::new(&output, PollFlags::IN));
            }
            if !log_eof {
                descriptors.push(PollFd::new(&diagnostic, PollFlags::IN));
            }
            pause(&mut descriptors, deadline)?;
        }
    }

    fn prepare_response(deadline: u64) -> Result<()> {
        close_inherited_descriptors()?;
        let response = match prepare::run(deadline) {
            Ok(prepared) => Response {
                prepared: Some(prepared),
                error: None,
            },
            Err(error) => Response {
                prepared: None,
                error: Some(error.chars().take(4096).collect()),
            },
        };
        let bytes = serde_json::to_vec(&response).map_err(io::Error::other)?;
        if bytes.len() > RESPONSE_LIMIT {
            return Err(invalid("preparation environment exceeds its frame bound"));
        }
        io::stdout().lock().write_all(&bytes)
    }

    fn diagnostic_relay() -> Result<()> {
        close_inherited_descriptors()?;
        let group = rustix::process::setsid()?;
        let deadline = now_ns() + 100 * MILLISECOND;
        std::thread::spawn(move || {
            while now_ns() < deadline {
                std::thread::sleep(Duration::from_millis(5));
            }
            let _ = rustix::process::kill_process_group(group, Signal::KILL);
        });
        let mut bytes = Vec::new();
        io::stdin()
            .take((LOG_LIMIT + 8192) as u64)
            .read_to_end(&mut bytes)?;
        io::stderr().lock().write_all(&bytes)
    }

    fn replay_diagnostics(bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        let result = (|| -> Result<()> {
            let end = now_ns() + 100 * MILLISECOND;
            let child = Command::new(native_worker_executable()?)
                .args(["worker-cache", "--diagnostics"])
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::inherit())
                .spawn()?;
            let mut relay = Pinned::new(child);
            if let Some(input) = relay.child.stdin.take() {
                let _ = send_before(&input, &bytes[..bytes.len().min(LOG_LIMIT + 8192)], end);
                drop(input);
            }
            // The fixed relay has no descendants. Retain the child pin until
            // signalling, then reap it; never change Cargo's stderr OFD flags.
            let _ = relay.reap(end);
            if !relay.reaped {
                relay.kill()?;
                relay.reap(now_ns() + CLEANUP.as_nanos() as u64)?;
            }
            Ok(())
        })();
        let _ = result;
    }

    fn exec_command(arguments: &[OsString], prepared: Option<prepare::Prepared>) -> i32 {
        let Some(program) = arguments.first() else {
            return 127;
        };
        // Rust starts with SIGPIPE ignored. A caught disposition resets on
        // exec, so Cargo receives the ordinary shell default even on bypass.
        let _pipe = signal_hook::flag::register(
            signal_hook::consts::SIGPIPE,
            Arc::new(AtomicBool::new(false)),
        );
        let mut command = Command::new(program);
        command.args(&arguments[1..]);
        if let Some(prepared) = prepared {
            command
                .env(ACTIVE, "1")
                .env("RUSTC_WRAPPER", prepared.wrapper)
                .env("RABS_SOCKET_PATH", prepared.socket);
        }
        let error = command.exec();
        replay_diagnostics(
            format!(
                "rch: could not execute {}: {error}\n",
                program.to_string_lossy()
            )
            .as_bytes(),
        );
        if error.kind() == io::ErrorKind::NotFound {
            127
        } else {
            126
        }
    }

    fn run(arguments: &[OsString]) -> i32 {
        if arguments.is_empty() {
            return 127;
        }
        let budget = preparation_budget();
        if budget == 0 || std::env::var_os(ACTIVE).as_deref() == Some(std::ffi::OsStr::new("1")) {
            return exec_command(arguments, None);
        }
        let end = now_ns() + budget * MILLISECOND;
        let Ok(watchdog) = Watchdog::new(end + 1_000 * MILLISECOND) else {
            // No preparation child or daemon exists yet. Failure to acquire
            // supervision resources can still safely preserve stock Cargo.
            return exec_command(arguments, None);
        };
        // Preserve inherited auto-reap behavior by bypassing setup entirely.
        // No setup child may be started without a waitable identity pin.
        if !matches!(child_is_autoreaped(), Ok(false)) {
            drop(watchdog);
            return exec_command(arguments, None);
        }
        let Ok(mut signals) = Signals::new() else {
            drop(watchdog);
            return exec_command(arguments, None);
        };
        let observed = observe(end, &signals);
        let number = signals.number();
        match observed {
            Ok((prepared, logs)) if number == 0 => {
                replay_diagnostics(&logs);
                drop(watchdog);
                if signals.ready_to_exec().is_err() {
                    return UNCONFIRMED;
                }
                let number = signals.number();
                if number != 0 {
                    return 128 + number as i32;
                }
                exec_command(arguments, prepared)
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                128 + if number == 0 {
                    signal_hook::consts::SIGINT
                } else {
                    number as i32
                }
            }
            Ok(_) if number != 0 => 128 + number as i32,
            _ => {
                replay_diagnostics(
                    b"rch: RABS preparation cleanup is unconfirmed; Cargo was not run\n",
                );
                UNCONFIRMED
            }
        }
    }

    pub(super) fn main(arguments: &[OsString]) -> i32 {
        match arguments {
            [role, time] if role == "--guardian" => deadline(time)
                .and_then(guardian)
                .map_or(UNCONFIRMED, |()| 0),
            [role, time] if role == "--prepare" => {
                deadline(time).and_then(prepare_response).map_or(1, |()| 0)
            }
            [role] if role == "--diagnostics" => diagnostic_relay().map_or(1, |()| 0),
            [role, rest @ ..] if role == "--daemon-exec" => {
                prepare::daemon_exec(rest).map_or(1, |()| 0)
            }
            [protocol, version, separator, command @ ..]
                if protocol == "--protocol" && version == "v1" && separator == "--" =>
            {
                run(command)
            }
            _ => 73,
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn preparation_budget_is_bounded_without_affecting_cargo_arguments() {
            for (value, expected) in [
                (None, 7000),
                (Some("0"), 0),
                (Some("-9"), 0),
                (Some("35001"), 35000),
                (Some("unlimited"), 7000),
                (Some("100000000000000000000000000000000000000000"), 7000),
            ] {
                assert_eq!(bounded_milliseconds(value, 7000, 35000), expected);
            }
        }

        #[test]
        fn preparation_frame_requires_exact_complete_bounded_bytes() {
            let payload = Payload {
                code: 0,
                response: b"{}".to_vec(),
                logs: b"log".to_vec(),
            };
            let encoded = payload.encode();
            for prefix in 0..encoded.len() {
                assert!(Payload::decode(&encoded[..prefix]).unwrap().is_none());
            }
            let decoded = Payload::decode(&encoded).unwrap().unwrap();
            assert_eq!(decoded.response, b"{}");
            assert_eq!(decoded.logs, b"log");
            let mut extra = encoded.clone();
            extra.push(0);
            assert!(Payload::decode(&extra).is_err());
            let mut oversized = encoded;
            oversized[2..6].copy_from_slice(&((RESPONSE_LIMIT + 1) as u32).to_be_bytes());
            assert!(Payload::decode(&oversized).is_err());
        }
    }
}
