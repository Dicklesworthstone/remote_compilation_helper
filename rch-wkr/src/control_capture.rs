//! Bounded capture for lifecycle observations and GC inventories.
//!
//! For small lifecycle responses, the caller's group timeout owns the observed
//! command, and every descendant that inherits its output pipe. Do not create
//! another session or return early on invalid output: either would let that
//! timeout forget a still-running observer. Only bounded, validated bytes are
//! retained, and no temporary files are needed on a full worker.
//!
//! GC snapshots stream arbitrary bytes to an existing file under an independent
//! deadline. A separately owned writer group and private lifetime pipe keep a
//! blocked write or abruptly killed observer from stranding inventory commands.

use std::ffi::OsString;

const REFUSED: i32 = 125;
const PROBE: &[u8] = b"rch-wkr control-capture v1\n";
const SNAPSHOT_PROBE: &[u8] = b"rch-wkr control-capture snapshot v1\n";

/// Run before the async runtime and optional file logging are initialized.
pub fn main(arguments: &[OsString]) -> i32 {
    use std::io::Write as _;

    if arguments.len() == 1 && matches!(arguments[0].to_str(), Some("probe" | "snapshot-probe")) {
        let probe = if arguments[0] == "snapshot-probe" {
            SNAPSHOT_PROBE
        } else {
            PROBE
        };
        return if std::io::stdout().lock().write_all(probe).is_ok() {
            0
        } else {
            REFUSED
        };
    }
    #[cfg(unix)]
    match match arguments.first().and_then(|value| value.to_str()) {
        Some("snapshot") => snapshot(&arguments[1..]),
        Some("snapshot-write") => snapshot_writer(&arguments[1..]),
        _ => capture(arguments),
    } {
        Ok(status) => status,
        Err(error) => {
            let _ = writeln!(
                std::io::stderr().lock(),
                "RCH_CONTROL_CAPTURE_REFUSED: {error}"
            );
            REFUSED
        }
    }
    #[cfg(not(unix))]
    {
        let _ = writeln!(
            std::io::stderr().lock(),
            "RCH_CONTROL_CAPTURE_UNAVAILABLE: requires Unix process ownership"
        );
        REFUSED
    }
}

/// Capture a complete GC inventory into its already-created snapshot. Unlike
/// the small lifecycle response above, an inventory may contain arbitrary path
/// bytes and is streamed instead of buffered. A producer's zero exit alone is
/// insufficient: writing, EOF, the deadline, group cleanup and leader reaping
/// must all succeed before the shell may use this file as collection evidence.
#[cfg(unix)]
fn snapshot(arguments: &[OsString]) -> std::io::Result<i32> {
    use std::io;
    use std::time::Duration;

    let invalid = || {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "expected snapshot milliseconds, existing file and command",
        )
    };
    let milliseconds = arguments
        .first()
        .and_then(|value| value.to_str())
        .filter(|value| !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()))
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| (1..=3_600_000).contains(value))
        .ok_or_else(invalid)?;
    let path = arguments
        .get(1)
        .filter(|value| !value.is_empty())
        .ok_or_else(invalid)?;
    let program = arguments
        .get(2)
        .filter(|value| !value.is_empty())
        .ok_or_else(invalid)?;
    let scale = rch_common::timing::TimeoutsConfig::default()
        .with_environment()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?
        .scale;
    // The explicit current-thread runtime ignores TOKIO_WORKER_THREADS and
    // needs neither worker logging nor a writable runtime/scratch directory.
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(snapshot_capture(
            std::path::Path::new(path),
            program,
            &arguments[3..],
            scale.duration(Duration::from_millis(milliseconds)),
        ))
}

#[cfg(unix)]
async fn snapshot_capture(
    path: &std::path::Path,
    program: &std::ffi::OsStr,
    arguments: &[OsString],
    allowance: std::time::Duration,
) -> std::io::Result<i32> {
    use std::io;
    use std::process::Stdio;
    use std::time::Duration;
    use tokio::io::AsyncWriteExt as _;
    use tokio::signal::unix::{SignalKind, signal};
    use tokio::time::{Instant, timeout};

    // Keep blocking filesystem operations in a separately owned worker. A
    // stalled write/fsync cannot starve this observer's timer or signals.
    let mut hangup = signal(SignalKind::hangup())?;
    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut terminate = signal(SignalKind::terminate())?;
    // Clear an inherited SIG_IGN/SA_NOCLDWAIT before spawning. A caught
    // disposition resets on exec, so the writer can retain and reap its own
    // producer even when Tokio uses pidfds without a SIGCHLD subscription.
    let _child_notification = signal(SignalKind::child())?;
    let deadline = Instant::now() + allowance;
    let mut command = tokio::process::Command::new(std::env::current_exe()?);
    command
        .args(["control-capture", "snapshot-write"])
        .arg(path)
        .arg(program)
        .args(arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());
    let mut child = rch_common::ssh::OwnedProcessGroup::spawn(&mut command)?;
    // Only this observer owns the writer end. An abrupt observer death closes
    // it, and the writer's independent owner thread stops its entire group.
    let mut lifetime = child
        .take_stdin()
        .ok_or_else(|| io::Error::other("missing GC snapshot lifetime pipe"))?;
    let capture = async {
        lifetime.write_all(b"S").await?;
        // wait() observes the unreaped writer, stops remaining group members,
        // and only then reaps it. The writer cannot finish before producer EOF,
        // checked output, and producer exit; a held pipe expires this budget.
        let status = child.wait().await?;
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "GC snapshot timed out",
            ));
        }
        if !status.success() {
            return Err(io::Error::other(format!(
                "GC snapshot writer failed: {status}"
            )));
        }
        Ok(0)
    };
    let interrupted = || io::Error::new(io::ErrorKind::Interrupted, "GC snapshot interrupted");
    let result = tokio::select! {
        // Already pending cancellation must beat a simultaneously ready EOF.
        biased;
        _ = hangup.recv() => Err(interrupted()),
        _ = interrupt.recv() => Err(interrupted()),
        _ = terminate.recv() => Err(interrupted()),
        _ = tokio::time::sleep_until(deadline) => {
            Err(io::Error::new(io::ErrorKind::TimedOut, "GC snapshot timed out"))
        }
        result = capture => result,
    };
    drop(lifetime);
    if let Err(error) = result {
        let _ = child.start_kill();
        if !matches!(
            timeout(Duration::from_secs(1), child.wait()).await,
            Ok(Ok(_))
        ) {
            return Err(io::Error::other(format!(
                "{error}; GC snapshot producer settlement unconfirmed"
            )));
        }
        return Err(error);
    }
    result
}

/// The writer and producer share a group owned by the outer observer. The
/// observer's lifetime pipe is watched by an independent thread, so SIGKILL of
/// that observer cannot strand a blocked writer or a producer in its group.
#[cfg(unix)]
fn snapshot_writer(arguments: &[OsString]) -> std::io::Result<i32> {
    use rustix::process::{Signal, getpgrp, getpid, kill_process_group};
    use std::io::{self, Read as _, Write as _};
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
    use std::process::{Command, Stdio};

    let [path, program, rest @ ..] = arguments else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "missing snapshot writer arguments",
        ));
    };
    let group = getpid();
    if group.is_init() || getpgrp() != group {
        return Err(io::Error::other(
            "GC snapshot writer requires its owned process group",
        ));
    }
    // The observer's caught SIGCHLD disposition became default at exec.
    // Producers also need notifications when the original caller blocked it.
    let mut child_notification = nix::sys::signal::SigSet::empty();
    child_notification.add(nix::sys::signal::Signal::SIGCHLD);
    child_notification
        .thread_unblock()
        .map_err(io::Error::other)?;
    let mut start = [0];
    io::stdin().read_exact(&mut start)?;
    if start != *b"S" {
        return Err(io::Error::other("invalid GC snapshot owner handoff"));
    }
    std::thread::Builder::new()
        .name("rch-gc-snapshot-owner".into())
        .stack_size(128 * 1024)
        .spawn(move || {
            let mut byte = [0];
            loop {
                match io::stdin().read(&mut byte) {
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                    _ => break,
                }
            }
            // This process is still alive and is the group leader: its PID
            // cannot have been recycled and no remembered foreign PID is used.
            let _ = kill_process_group(group, Signal::KILL);
            std::process::exit(REFUSED);
        })?;
    let path = std::path::Path::new(path);
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .custom_flags((rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32)
        .open(path)?;
    let original = output.metadata()?;
    if !original.is_file()
        || original.uid() != rustix::process::geteuid().as_raw()
        || original.nlink() != 1
    {
        return Err(io::Error::other("unsafe GC snapshot file"));
    }
    output.set_len(0)?;
    let mut child = Command::new(program)
        .args(rest)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        // Deliberately stay in the writer's group. Every error returns through
        // that group's leader so its observer can terminate all descendants.
        .spawn()?;
    let mut reader = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("missing producer pipe"))?;
    let mut bytes = [0_u8; 65_536];
    loop {
        let count = match reader.read(&mut bytes) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            result => result?,
        };
        if count == 0 {
            break;
        }
        output.write_all(&bytes[..count])?;
    }
    output.flush()?;
    output.sync_all()?;
    let status = child.wait()?;
    let named = std::fs::symlink_metadata(path)?;
    if !named.is_file()
        || named.dev() != original.dev()
        || named.ino() != original.ino()
        || named.nlink() != 1
    {
        return Err(io::Error::other("GC snapshot was replaced during capture"));
    }
    if !status.success() {
        return Err(io::Error::other(format!(
            "GC snapshot producer failed: {status}"
        )));
    }
    Ok(0)
}

#[cfg(unix)]
fn capture(arguments: &[OsString]) -> std::io::Result<i32> {
    use std::fs::File;
    use std::io::{self, Read as _, Write as _};
    use std::os::unix::process::ExitStatusExt as _;
    use std::process::{Command, Stdio};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let invalid = || {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "expected a byte limit and command",
        )
    };
    let limit = arguments
        .first()
        .and_then(|value| value.to_str())
        .filter(|value| !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()))
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|limit| (1..=1_048_576).contains(limit))
        .ok_or_else(invalid)?;
    let program = arguments
        .get(1)
        .filter(|value| !value.is_empty())
        .ok_or_else(invalid)?;

    // Catch collector-only interruptions without letting the owning timeout
    // exit while the command or an inherited pipe holder remains. exec resets
    // these caught dispositions in the observed command as usual.
    let interrupted = Arc::new(AtomicUsize::new(0));
    for signal in [
        signal_hook::consts::SIGHUP,
        signal_hook::consts::SIGINT,
        signal_hook::consts::SIGTERM,
    ] {
        signal_hook::flag::register_usize(signal, Arc::clone(&interrupted), signal as usize)?;
    }
    let interruption = || {
        let signal = interrupted.load(Ordering::Relaxed);
        (signal != 0).then_some(128 + signal as i32)
    };
    if let Some(status) = interruption() {
        return Ok(status);
    }

    // One kernel pipe preserves the order of stdout/stderr writes. CLOEXEC
    // closes only our private descriptors; inherited witnesses such as fd 8
    // retain their original open descriptions in the command. No process_group
    // or setsid call may move either process outside the enclosing timeout.
    let (reader, writer) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC)?;
    let mut child = Command::new(program)
        .args(&arguments[2..])
        .stdin(Stdio::null())
        .stdout(Stdio::from(writer.try_clone()?))
        .stderr(Stdio::from(writer))
        .spawn()?;
    let mut reader = File::from(reader);
    let mut output = Vec::with_capacity(limit.min(8192));
    let mut invalid_output = false;
    let mut buffer = [0_u8; 8192];
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) if !invalid_output => {
                let chunk = &buffer[..count];
                if count > limit - output.len()
                    || chunk
                        .iter()
                        .any(|&byte| !matches!(byte, b'\t' | b'\n' | b' '..=b'~'))
                {
                    invalid_output = true;
                    output.clear();
                } else {
                    output.extend_from_slice(chunk);
                }
            }
            Ok(_) => {} // Invalid output must still drain to EOF.
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => wait_for_owner(),
        }
    }
    let status = loop {
        match child.wait() {
            Ok(status) => break status,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => wait_for_owner(),
        }
    };
    if let Some(status) = interruption() {
        return Ok(status);
    }
    if invalid_output {
        return Ok(REFUSED);
    }

    let code = status
        .code()
        .unwrap_or_else(|| 128 + status.signal().unwrap_or(0));
    if status.success() {
        let mut stream = io::stdout().lock();
        stream.write_all(&output)?;
        stream.flush()?;
    } else {
        let mut stream = io::stderr().lock();
        stream.write_all(&output)?;
        stream.flush()?;
    }
    Ok(interruption().unwrap_or(code))
}

/// An unreadable pipe or unobservable child is not proof that its writers
/// exited. Keep the outer group timeout alive until it terminates this entire
/// operation, rather than abandoning descendants on an observation failure.
#[cfg(unix)]
fn wait_for_owner() -> ! {
    loop {
        nix::unistd::pause();
    }
}
