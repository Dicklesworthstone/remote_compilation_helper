//! Bounded source-admission clocks and metadata locking, before Tokio starts.
//!
//! The enclosing namespace controller owns descendant settlement. This helper
//! only measures the existing retry window or transfers one verified flock to
//! the existing transaction with exec; it never creates a source claim.

use std::ffi::OsString;

pub fn main(arguments: &[OsString]) -> i32 {
    #[cfg(unix)]
    {
        unix::main(arguments)
    }
    #[cfg(not(unix))]
    {
        let _ = arguments;
        eprintln!("RCH_SOURCE_ADMISSION_CLOCK_UNAVAILABLE native admission requires Unix");
        73
    }
}

#[cfg(unix)]
mod unix {
    use std::ffi::{OsStr, OsString};
    use std::io::{self, Write};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::process::CommandExt;
    use std::process::Command;
    use std::time::Duration;

    use rustix::fs::{AtFlags, CWD, FileType, FlockOperation, Mode, OFlags};
    use rustix::io::{Errno, FdFlags};

    const REFUSED: i32 = 73;
    const EXPIRED: i32 = 75;
    const MAX_BUDGET_NS: u64 = 600_000_000_000;
    const MAX_CLOCK_NS: u64 = i64::MAX as u64;

    fn invalid(message: &'static str) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidInput, message)
    }

    fn decimal(text: &OsStr) -> io::Result<u64> {
        let bytes = text.as_bytes();
        if bytes.is_empty() || bytes.len() > 20 || !bytes.iter().all(u8::is_ascii_digit) {
            return Err(invalid("invalid clock argument"));
        }
        text.to_str()
            .and_then(|value| value.parse().ok())
            .ok_or_else(|| invalid("clock argument exceeds its bound"))
    }

    fn scale(text: &OsStr) -> io::Result<f64> {
        let text = text
            .to_str()
            .ok_or_else(|| invalid("invalid transported scale"))?;
        if text.is_empty() || text.len() > 128 || text.trim() != text {
            return Err(invalid("invalid transported scale"));
        }
        let value = text
            .parse::<f64>()
            .map_err(|_| invalid("invalid transported scale"))?;
        rch_common::timing::TimingScale::try_from(value)
            .map(f64::from)
            .map_err(|_| invalid("scale outside [1, 10]"))
    }

    fn configured_scale() -> io::Result<f64> {
        scale(
            std::env::var_os(rch_common::timing::TIMING_SCALE_ENV)
                .as_deref()
                .unwrap_or_else(|| OsStr::new("1")),
        )
    }

    fn budget(seconds: u64, scale: f64) -> io::Result<u64> {
        if !(1..=60).contains(&seconds) {
            return Err(invalid("invalid retry window"));
        }
        // Round upward exactly once at the nanosecond boundary. A fractional
        // multiplier must never shorten the transported admission window.
        let nanos = (seconds as f64 * scale * 1_000_000_000.0).ceil();
        if !nanos.is_finite() || !(1.0..=MAX_BUDGET_NS as f64).contains(&nanos) {
            return Err(invalid("invalid scaled window"));
        }
        Ok(nanos as u64)
    }

    fn now_ns() -> io::Result<u64> {
        #[cfg(target_os = "macos")]
        let time =
            nix::time::clock_gettime(nix::time::ClockId::from_raw(nix::libc::CLOCK_UPTIME_RAW))
                .map(|time| (time.tv_sec(), time.tv_nsec()))?;
        #[cfg(not(target_os = "macos"))]
        let time = {
            let time = rustix::time::clock_gettime(rustix::time::ClockId::Monotonic);
            (time.tv_sec, time.tv_nsec)
        };
        let seconds = u64::try_from(time.0).map_err(|_| invalid("invalid monotonic clock"))?;
        let nanos = u64::try_from(time.1).map_err(|_| invalid("invalid monotonic clock"))?;
        if nanos >= 1_000_000_000 {
            return Err(invalid("invalid monotonic clock"));
        }
        seconds
            .checked_mul(1_000_000_000)
            .and_then(|value| value.checked_add(nanos))
            .filter(|value| *value <= MAX_CLOCK_NS)
            .ok_or_else(|| invalid("monotonic clock exceeds its bound"))
    }

    fn deadline(now: u64, budget: u64) -> io::Result<u64> {
        if budget == 0 || budget > MAX_BUDGET_NS {
            return Err(invalid("invalid absolute deadline"));
        }
        now.checked_add(budget)
            .filter(|value| *value <= MAX_CLOCK_NS)
            .ok_or_else(|| invalid("invalid absolute deadline"))
    }

    fn remaining(now: u64, deadline: u64) -> io::Result<Option<Duration>> {
        if deadline == 0 || deadline > MAX_CLOCK_NS {
            return Err(invalid("invalid absolute deadline"));
        }
        if now >= deadline {
            return Ok(None);
        }
        let nanos = deadline - now;
        if nanos > MAX_BUDGET_NS {
            return Err(invalid("invalid absolute deadline"));
        }
        Ok(Some(Duration::from_nanos(nanos)))
    }

    fn clock(arguments: &[OsString]) -> io::Result<i32> {
        if arguments.len() != 2 {
            return Err(invalid("invalid clock invocation"));
        }
        let value = decimal(&arguments[1])?;
        let result = match arguments[0].as_bytes() {
            b"budget" => Some(budget(value, configured_scale()?)?),
            b"start" => Some(deadline(now_ns()?, value)?),
            b"check" | b"wait" => {
                let Some(left) = remaining(now_ns()?, value)? else {
                    return Ok(EXPIRED);
                };
                if arguments[0] == "wait" {
                    // Retry cadence remains one second even at scale ten.
                    std::thread::sleep(left.min(Duration::from_secs(1)));
                }
                return Ok(if remaining(now_ns()?, value)?.is_some() {
                    0
                } else {
                    EXPIRED
                });
            }
            _ => return Err(invalid("invalid clock operation")),
        };
        if let Some(value) = result {
            writeln!(io::stdout().lock(), "{value}")?;
        }
        Ok(0)
    }

    fn metadata_lock(arguments: &[OsString], timing_scale: f64) -> io::Result<i32> {
        if arguments.len() < 2 {
            return Err(invalid("metadata lock requires a path and command"));
        }
        let started = now_ns()?;
        let deadline = deadline(started, budget(5, timing_scale)?)?;
        let path = &arguments[0];
        let descriptor = rustix::fs::open(
            path,
            OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )?;
        let identity = rustix::fs::fstat(&descriptor)?;
        if FileType::from_raw_mode(identity.st_mode) != FileType::RegularFile
            || identity.st_nlink != 1
        {
            return Err(invalid("invalid metadata lock inode"));
        }
        let verify = || -> io::Result<()> {
            let named = rustix::fs::statat(CWD, path, AtFlags::SYMLINK_NOFOLLOW)?;
            if (named.st_dev, named.st_ino) != (identity.st_dev, identity.st_ino) {
                return Err(invalid("metadata lock changed while waiting"));
            }
            Ok(())
        };
        let admit = || -> io::Result<bool> {
            let now = now_ns()?;
            if now >= deadline {
                writeln!(
                    io::stderr().lock(),
                    "RCH_SOURCE_NAMESPACE_METADATA_LOCK_BUSY elapsed_ms={} lock={}",
                    now.saturating_sub(started) / 1_000_000,
                    path.to_string_lossy(),
                )?;
                return Ok(false);
            }
            Ok(true)
        };
        loop {
            verify()?;
            // An externally stopped waiter cannot acquire upon resumption
            // after its observation budget has already expired.
            if !admit()? {
                return Ok(76);
            }
            match rustix::fs::flock(&descriptor, FlockOperation::NonBlockingLockExclusive) {
                Ok(()) => break,
                Err(Errno::AGAIN | Errno::ACCESS) => {}
                Err(error) => return Err(error.into()),
            }
            let wait = Duration::from_nanos(deadline.saturating_sub(now_ns()?));
            std::thread::sleep(wait.min(Duration::from_millis(20)));
        }
        verify()?;
        rustix::io::fcntl_setfd(&descriptor, FdFlags::empty())?;
        // Even successful nonblocking acquisition can return after a scheduler
        // stall. Recheck before transferring the same locked inode with exec.
        if !admit()? {
            return Ok(76);
        }
        Err(Command::new(&arguments[1]).args(&arguments[2..]).exec())
    }

    pub(super) fn main(arguments: &[OsString]) -> i32 {
        if arguments.len() == 1 && arguments[0] == "probe" {
            return match io::stdout()
                .lock()
                .write_all(b"rch-wkr source-admission v1\n")
            {
                Ok(()) => 0,
                Err(_) => REFUSED,
            };
        }
        if arguments
            .first()
            .is_some_and(|value| value == "metadata-lock")
        {
            let timing_scale = match configured_scale() {
                Ok(value) => value,
                Err(_) => {
                    let _ = writeln!(
                        io::stderr().lock(),
                        "RCH_SOURCE_NAMESPACE_INVALID_TIMING_SCALE"
                    );
                    return 78;
                }
            };
            return match metadata_lock(&arguments[1..], timing_scale) {
                Ok(status) => status,
                Err(error) => {
                    let _ = writeln!(
                        io::stderr().lock(),
                        "RCH_SOURCE_NAMESPACE_METADATA_LOCK_INVALID {error}"
                    );
                    REFUSED
                }
            };
        }
        match clock(arguments) {
            Ok(status) => status,
            Err(_) => {
                let _ = writeln!(
                    io::stderr().lock(),
                    "RCH_SOURCE_ADMISSION_CLOCK_UNAVAILABLE"
                );
                REFUSED
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn transported_scale_preserves_the_finite_decimal_domain() {
            for (text, expected) in [("1", 1.0), ("+1.25", 1.25), ("1e1", 10.0), ("1.", 1.0)] {
                assert_eq!(scale(OsStr::new(text)).unwrap(), expected);
            }
            for text in [
                "", " 1", "1\n", "NaN", "inf", "0.9", "10.01", "1_0", "1;true",
            ] {
                assert!(scale(OsStr::new(text)).is_err(), "{text:?}");
            }
            assert!(scale(OsStr::from_bytes(&[0xff])).is_err());
            assert!(scale(OsStr::new(&"0".repeat(129))).is_err());
        }

        #[test]
        fn bounds_round_up_and_never_overflow_or_disable_a_deadline() {
            assert_eq!(budget(5, 1.5).unwrap(), 7_500_000_000);
            assert_eq!(budget(60, 10.0).unwrap(), MAX_BUDGET_NS);
            assert_eq!(budget(1, 1.000_000_000_1).unwrap(), 1_000_000_001);
            for seconds in [0, 61, u64::MAX] {
                assert!(budget(seconds, 1.0).is_err());
            }
            assert!(deadline(MAX_CLOCK_NS, 1).is_err());
            assert!(deadline(0, 0).is_err());
            assert!(deadline(0, MAX_BUDGET_NS + 1).is_err());
            assert_eq!(remaining(500, 500).unwrap(), None);
            assert_eq!(remaining(501, 500).unwrap(), None);
            assert!(remaining(0, MAX_BUDGET_NS + 1).is_err());
            assert!(remaining(0, 0).is_err());
        }

        #[test]
        fn clock_arguments_are_bounded_ascii_decimals() {
            assert_eq!(decimal(OsStr::new("0001")).unwrap(), 1);
            for text in ["", "-1", "+1", "1e3", " 1", "1\n", "18446744073709551616"] {
                assert!(decimal(OsStr::new(text)).is_err());
            }
            assert!(decimal(OsStr::new(&"0".repeat(21))).is_err());
        }
    }
}
