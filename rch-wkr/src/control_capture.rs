//! Storage-independent capture for remote lifecycle observations.
//!
//! The caller's bounded group timeout owns this collector, the observed
//! command, and every descendant that inherits its output pipe. Do not create
//! another session or return early on invalid output: either would let that
//! timeout forget a still-running observer. Only bounded, validated bytes are
//! retained, and no temporary files are needed on a full worker.

use std::ffi::OsString;

const REFUSED: i32 = 125;
const PROBE: &[u8] = b"rch-wkr control-capture v1\n";

/// Run before the async runtime and optional file logging are initialized.
pub fn main(arguments: &[OsString]) -> i32 {
    use std::io::Write as _;

    if arguments.len() == 1 && arguments[0] == "probe" {
        return if std::io::stdout().lock().write_all(PROBE).is_ok() {
            0
        } else {
            REFUSED
        };
    }
    #[cfg(unix)]
    match capture(arguments) {
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
