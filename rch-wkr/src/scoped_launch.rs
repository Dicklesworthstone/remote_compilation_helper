//! Native lifecycle primitives for the shared owned-group launch protocol.
//!
//! An absence witness proves only ESRCH for one process. Group signals are
//! limited to this helper's own kernel-confirmed membership, never a historical
//! receipt or a reaped child PID. The timeout monitor owns its private session
//! until exit, so its identity cannot be recycled while the watchdog is armed.

use std::ffi::OsString;

const REFUSED: i32 = 125;

/// Run before the worker creates a runtime, logging sinks, or child reapers.
pub fn main(arguments: &[OsString]) -> i32 {
    #[cfg(unix)]
    {
        match unix::run(arguments) {
            Ok(status) => status,
            Err(error) => {
                unix::diagnostic(&format!("RCH_SCOPED_LAUNCH_UNAVAILABLE: {error}"));
                REFUSED
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = arguments;
        eprintln!("RCH_SCOPED_LAUNCH_UNAVAILABLE: requires Unix process ownership");
        REFUSED
    }
}

#[cfg(unix)]
mod unix {
    use super::REFUSED;
    use std::ffi::{OsStr, OsString};
    use std::io::{self, Write as _};
    use std::os::unix::process::ExitStatusExt as _;
    use std::process::Command;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
    use std::thread::{self, JoinHandle};
    use std::time::Duration;

    use rustix::io::Errno;
    use rustix::process::{Pid, Signal};

    fn invalid(message: &'static str) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidInput, message)
    }

    pub(super) fn diagnostic(message: &str) {
        let stderr = rustix::stdio::stderr();
        if let Ok(flags) = rustix::fs::fcntl_getfl(stderr)
            && rustix::fs::fcntl_setfl(stderr, flags | rustix::fs::OFlags::NONBLOCK).is_ok()
        {
            let mut bytes = message.as_bytes().to_vec();
            bytes.truncate(4095);
            bytes.push(b'\n');
            let _ = rustix::io::write(stderr, &bytes);
            // The descriptor may share its open description with the caller.
            // A best-effort diagnostic must not leave that stream nonblocking.
            let _ = rustix::fs::fcntl_setfl(stderr, flags);
        }
    }

    fn decimal(argument: &OsStr) -> io::Result<u32> {
        argument
            .to_str()
            .filter(|value| !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()))
            .and_then(|value| value.parse().ok())
            .ok_or_else(|| invalid("invalid unsigned decimal argument"))
    }

    fn process(argument: &OsStr) -> io::Result<Pid> {
        let number = decimal(argument)?;
        if number <= 1 {
            return Err(invalid("process identity must exceed one"));
        }
        i32::try_from(number)
            .ok()
            .and_then(Pid::from_raw)
            .ok_or_else(|| invalid("process identity exceeds the kernel PID domain"))
    }

    pub(super) fn run(arguments: &[OsString]) -> io::Result<i32> {
        if arguments.len() == 1 && arguments[0] == "probe" {
            io::stdout()
                .lock()
                .write_all(b"rch-wkr scoped-launch v1\n")?;
            return Ok(0);
        }
        match arguments.first().and_then(|argument| argument.to_str()) {
            Some("absent") if arguments.len() == 2 => {
                let pid = process(&arguments[1])?;
                match rustix::process::getpgid(Some(pid)) {
                    Err(Errno::SRCH) => {
                        // Keep the caller's validated decimal spelling: shell
                        // consumers compare the complete marker, not a prefix.
                        writeln!(
                            io::stdout().lock(),
                            "RCH_PROCESS_ABSENT_V1:{}",
                            arguments[1].to_string_lossy()
                        )?;
                        Ok(0)
                    }
                    Ok(_) => Ok(1),
                    Err(error) => Err(error.into()),
                }
            }
            Some("kill-self") if arguments.len() == 2 => {
                let expected = process(&arguments[1])?;
                if rustix::process::getpgrp() != expected {
                    return Err(invalid(
                        "requested group is not this helper's current group",
                    ));
                }
                // This process is a live member of the group it signals. It
                // cannot disappear or change groups between this check and
                // killpg; no child was reaped and no receipt grants authority.
                rustix::process::kill_process_group(expected, Signal::KILL)?;
                Ok(REFUSED)
            }
            Some("timeout") => timeout(&arguments[1..]),
            _ => Err(invalid("expected probe, absent, kill-self, or timeout")),
        }
    }

    /// The monitor itself pins its process group, including during spawn and
    /// after the direct command is reaped. Deadline and cancellation never use
    /// the child's recyclable PID. The command must wait for any pipe holders
    /// before returning; control-capture owns that drain on observation paths.
    struct Watchdog {
        done: Arc<AtomicBool>,
        interrupted: Arc<AtomicUsize>,
        observed: Arc<AtomicU64>,
        deadline: u64,
        thread: Option<JoinHandle<()>>,
        registrations: Vec<signal_hook::SigId>,
    }

    impl Watchdog {
        fn start(seconds: u64) -> io::Result<Self> {
            let start = crate::control_clock::continuous_ns()?;
            let deadline = timeout_deadline(start, seconds)?;
            let done = Arc::new(AtomicBool::new(false));
            let interrupted = Arc::new(AtomicUsize::new(0));
            let observed = Arc::new(AtomicU64::new(start));
            let mut watchdog = Self {
                done: Arc::clone(&done),
                interrupted: Arc::clone(&interrupted),
                observed: Arc::clone(&observed),
                deadline,
                thread: None,
                registrations: Vec::new(),
            };
            for signal in [
                signal_hook::consts::SIGHUP,
                signal_hook::consts::SIGINT,
                signal_hook::consts::SIGTERM,
                signal_hook::consts::SIGALRM,
            ] {
                watchdog
                    .registrations
                    .push(signal_hook::flag::register_usize(
                        signal,
                        Arc::clone(&interrupted),
                        signal as usize,
                    )?);
            }
            // Arm independently before spawn: waiting for a command's exec,
            // stopped direct children, and full inherited pipes stay bounded.
            watchdog.thread = Some(
                thread::Builder::new()
                    .name("rch-control-deadline".into())
                    .spawn(move || {
                        while !done.load(Ordering::Acquire) {
                            let previous = observed.load(Ordering::Acquire);
                            let now = crate::control_clock::continuous_ns()
                                .unwrap_or_else(|_| kill_owned_session());
                            if interrupted.load(Ordering::Relaxed) != 0
                                || now < previous
                                || now >= deadline
                            {
                                kill_owned_session();
                            }
                            observed.store(now, Ordering::Release);
                            thread::park_timeout(
                                Duration::from_nanos(deadline - now).min(Duration::from_millis(10)),
                            );
                        }
                    })?,
            );
            Ok(watchdog)
        }

        fn finish(&mut self) {
            self.enforce_deadline();
            self.done.store(true, Ordering::Release);
            if let Some(thread) = self.thread.take() {
                thread.thread().unpark();
                if thread.join().is_err() {
                    kill_owned_session();
                }
            }
            self.enforce_deadline();
        }

        fn enforce_deadline(&self) {
            // Read the previous observation before reading the kernel clock;
            // a newer concurrent watchdog sample cannot look like rollback.
            let previous = self.observed.load(Ordering::Acquire);
            let now =
                crate::control_clock::continuous_ns().unwrap_or_else(|_| kill_owned_session());
            if self.interrupted.load(Ordering::Relaxed) != 0
                || now < previous
                || now >= self.deadline
            {
                kill_owned_session();
            }
        }
    }

    impl Drop for Watchdog {
        fn drop(&mut self) {
            self.done.store(true, Ordering::Release);
            if let Some(thread) = self.thread.take() {
                thread.thread().unpark();
                let _ = thread.join();
            }
            for registration in self.registrations.drain(..) {
                signal_hook::low_level::unregister(registration);
            }
        }
    }

    fn kill_owned_session() -> ! {
        let pid = rustix::process::getpid();
        if pid.as_raw_nonzero().get() > 1 && rustix::process::getpgrp() == pid {
            let _ = rustix::process::kill_process_group(pid, Signal::KILL);
        }
        // A failed signal is an unavailable cleanup proof, never success.
        std::process::exit(REFUSED);
    }

    fn timeout_deadline(now: u64, seconds: u64) -> io::Result<u64> {
        if now > i64::MAX as u64 || !(1..=80).contains(&seconds) {
            return Err(invalid("invalid continuous timeout clock or duration"));
        }
        now.checked_add(seconds * 1_000_000_000)
            .filter(|deadline| *deadline <= i64::MAX as u64)
            .ok_or_else(|| invalid("timeout deadline overflow"))
    }

    fn timeout(arguments: &[OsString]) -> io::Result<i32> {
        if arguments.len() < 5
            || arguments[0] != "--closed-stdio"
            || arguments[2] != "--signal=KILL"
            || arguments[4].is_empty()
        {
            return Err(invalid(
                "expected --closed-stdio MASK --signal=KILL 1s..80s COMMAND",
            ));
        }
        let closed = decimal(&arguments[1])?;
        if closed > 7 {
            return Err(invalid("closed standard descriptor mask exceeds seven"));
        }
        let seconds = arguments[3]
            .to_str()
            .and_then(|value| value.strip_suffix('s'))
            .filter(|value| !value.starts_with('0'))
            .and_then(|value| decimal(OsStr::new(value)).ok())
            .filter(|seconds| (1..=80).contains(seconds))
            .ok_or_else(|| invalid("timeout must be an integer from 1s to 80s"))?;
        rustix::process::setsid()?;
        if rustix::process::getpgrp() != rustix::process::getpid() {
            return Err(invalid(
                "timeout monitor did not acquire its own process group",
            ));
        }
        let mut watchdog = Watchdog::start(u64::from(seconds))?;
        // libstd guarantees open standard descriptors at startup. Restore the
        // original shell's explicit closures before handing them to a command.
        for descriptor in 0..3 {
            if closed & (1 << descriptor) != 0 {
                nix::unistd::close(descriptor)?;
            }
        }
        let mut child = Command::new(&arguments[4]).args(&arguments[5..]).spawn()?;
        let status = loop {
            match child.wait() {
                Ok(status) => break status,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => {
                    // The child may still own pipes and authority. Retain the
                    // monitor until its armed watchdog kills the whole group.
                    loop {
                        thread::park_timeout(Duration::from_secs(1));
                    }
                }
            }
        };
        watchdog.finish();
        Ok(status
            .code()
            .unwrap_or_else(|| 128 + status.signal().unwrap_or(0)))
    }

    #[cfg(test)]
    mod tests {
        use super::timeout_deadline;

        #[test]
        fn continuous_deadlines_keep_the_original_bounds_without_overflow() {
            assert_eq!(timeout_deadline(900_000_000, 1).unwrap(), 1_900_000_000);
            assert_eq!(timeout_deadline(10, 80).unwrap(), 80_000_000_010);
            for (now, seconds) in [
                (0, 0),
                (0, 81),
                (i64::MAX as u64, 1),
                (i64::MAX as u64 + 1, 1),
                (u64::MAX, 1),
            ] {
                assert!(timeout_deadline(now, seconds).is_err());
            }
        }
    }
}
