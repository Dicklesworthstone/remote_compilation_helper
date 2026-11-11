//! Native monotonic clocks for source admission and remote lifecycle deadlines.
//!
//! These short-lived probes own no locks or process authority. Admission keeps
//! its fresh-subshell transaction and starts its elapsed retry window only after
//! a validated pre-grant conflict. Lifecycle ticks include suspend, matching the
//! Linux uptime and Darwin continuous-clock policies used by the supervisor.

use std::io::{self, Write};

const REFUSED: i32 = 73;
const EXPIRED: i32 = 75;
const NANOS_PER_SECOND: u64 = 1_000_000_000;
const MAX_BUDGET_NS: u64 = 600 * NANOS_PER_SECOND;
const MAX_CLOCK_NS: u64 = i64::MAX as u64;

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn decimal(text: &str) -> io::Result<u64> {
    if text.is_empty() || text.len() > 20 || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(invalid("invalid clock argument"));
    }
    text.parse().map_err(|_| invalid("clock argument overflow"))
}

/// The transported form is strict: unlike human-facing configuration parsing,
/// whitespace, non-ASCII digits, NaN and infinity must never enter shell policy.
pub(crate) fn timing_scale(text: &str) -> io::Result<f64> {
    if text.is_empty()
        || text.len() > 128
        || !text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'+' | b'-' | b'.' | b'e' | b'E'))
    {
        return Err(invalid("invalid transported scale"));
    }
    let scale: f64 = text
        .parse()
        .map_err(|_| invalid("invalid transported scale"))?;
    if !scale.is_finite() || !(1.0..=10.0).contains(&scale) {
        return Err(invalid("scale outside [1, 10]"));
    }
    Ok(scale)
}

fn budget(seconds: u64, scale: &str) -> io::Result<u64> {
    if !(1..=60).contains(&seconds) {
        return Err(invalid("invalid retry window"));
    }
    let nanos = (seconds as f64 * timing_scale(scale)? * NANOS_PER_SECOND as f64).ceil();
    if !(1.0..=MAX_BUDGET_NS as f64).contains(&nanos) {
        return Err(invalid("invalid scaled window"));
    }
    Ok(nanos as u64)
}

#[cfg(any(unix, test))]
fn checked_nanoseconds(seconds: i64, nanos: i64) -> io::Result<u64> {
    let seconds = u64::try_from(seconds).map_err(|_| invalid("negative monotonic clock"))?;
    if !(0..NANOS_PER_SECOND as i64).contains(&nanos) {
        return Err(invalid("invalid clock fraction"));
    }
    seconds
        .checked_mul(NANOS_PER_SECOND)
        .and_then(|value| value.checked_add(nanos as u64))
        .filter(|value| *value <= MAX_CLOCK_NS)
        .ok_or_else(|| invalid("monotonic clock overflow"))
}

#[cfg(unix)]
fn now_ns(continuous: bool) -> io::Result<u64> {
    use nix::time::{ClockId, clock_gettime};

    let clock = if continuous {
        #[cfg(target_os = "macos")]
        {
            // This is mach_continuous_time, including suspend. MONOTONIC is
            // not a substitute for the previous remote-launch clock contract.
            ClockId::from_raw(nix::libc::CLOCK_MONOTONIC_RAW)
        }
        #[cfg(target_os = "linux")]
        {
            ClockId::CLOCK_BOOTTIME
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            return Err(invalid("continuous lifecycle clock unsupported"));
        }
    } else {
        #[cfg(target_os = "macos")]
        {
            // Admission historically used mach_absolute_time, excluding
            // suspend, rather than the supervisor's continuous wall budget.
            ClockId::from_raw(nix::libc::CLOCK_UPTIME_RAW)
        }
        #[cfg(not(target_os = "macos"))]
        {
            ClockId::CLOCK_MONOTONIC
        }
    };
    let time = clock_gettime(clock).map_err(io::Error::from)?;
    checked_nanoseconds(time.tv_sec(), time.tv_nsec())
}

#[cfg(not(unix))]
fn now_ns(_continuous: bool) -> io::Result<u64> {
    Err(invalid("native source admission clock requires Unix"))
}

/// Elapsed lifecycle time includes suspend on both supported worker platforms.
/// Long-lived timeout owners use the same clock as their shell callers.
pub(crate) fn continuous_ns() -> io::Result<u64> {
    now_ns(true)
}

fn remaining(deadline: u64, now: u64) -> io::Result<Option<u64>> {
    if deadline == 0 || deadline > MAX_CLOCK_NS || now > MAX_CLOCK_NS {
        return Err(invalid("invalid absolute deadline"));
    }
    if deadline <= now {
        return Ok(None);
    }
    let left = deadline - now;
    if left > MAX_BUDGET_NS {
        return Err(invalid("deadline exceeds bounded retry window"));
    }
    Ok(Some(left))
}

fn publish(value: u64) -> io::Result<i32> {
    let mut stdout = io::stdout().lock();
    writeln!(stdout, "{value}")?;
    stdout.flush()?;
    Ok(0)
}

fn run(arguments: &[String]) -> io::Result<i32> {
    if arguments == ["ticks"] {
        let ticks = continuous_ns()? / 10_000_000;
        if ticks > 999_999_999_999_999 {
            return Err(invalid("lifecycle clock exceeds shell bound"));
        }
        return publish(ticks);
    }
    if arguments.len() != 2 {
        return Err(invalid("invalid clock invocation"));
    }
    let value = decimal(&arguments[1])?;
    match arguments[0].as_str() {
        "budget" => {
            let scale = match std::env::var("RCH_TIMING_SCALE") {
                Ok(value) => value,
                Err(std::env::VarError::NotPresent) => "1".to_owned(),
                Err(std::env::VarError::NotUnicode(_)) => {
                    return Err(invalid("invalid transported scale"));
                }
            };
            publish(budget(value, &scale)?)
        }
        "start" => {
            if value == 0 || value > MAX_BUDGET_NS {
                return Err(invalid("invalid scaled window"));
            }
            let deadline = now_ns(false)?
                .checked_add(value)
                .filter(|value| *value <= MAX_CLOCK_NS)
                .ok_or_else(|| invalid("invalid absolute deadline"))?;
            publish(deadline)
        }
        "check" | "wait" => {
            let before = now_ns(false)?;
            let Some(left) = remaining(value, before)? else {
                return Ok(EXPIRED);
            };
            if arguments[0] == "wait" {
                std::thread::sleep(std::time::Duration::from_nanos(left.min(NANOS_PER_SECOND)));
            }
            let after = now_ns(false)?;
            if after < before {
                return Err(invalid("monotonic clock moved backwards"));
            }
            Ok(if remaining(value, after)?.is_some() {
                0
            } else {
                EXPIRED
            })
        }
        _ => Err(invalid("invalid clock operation")),
    }
}

/// Called before any async runtime or optional logging sink is initialized.
pub fn main(arguments: &[String]) -> i32 {
    match run(arguments) {
        Ok(status) => status,
        Err(error) => {
            let _ = writeln!(
                io::stderr(),
                "RCH_SOURCE_ADMISSION_CLOCK_UNAVAILABLE: {error}"
            );
            REFUSED
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_transported_policy_bounds_and_rounds_up() {
        for scale in ["1", "+1", "1.", ".15e1", "1e1", "1.0000000001"] {
            assert!(timing_scale(scale).is_ok(), "{scale}");
        }
        for scale in [
            "", " 1", "1\n", "NaN", "inf", "0.99", "10.01", "1_0", "1e999", "1\0",
        ] {
            assert!(timing_scale(scale).is_err(), "{scale:?}");
        }
        assert!(timing_scale(&"1".repeat(129)).is_err());
        assert_eq!(budget(5, "1.5").unwrap(), 7_500_000_000);
        assert_eq!(budget(1, "1.0000000001").unwrap(), 1_000_000_001);
        assert_eq!(budget(60, "10").unwrap(), MAX_BUDGET_NS);
        assert!(budget(0, "1").is_err());
        assert!(budget(61, "1").is_err());
    }

    #[test]
    fn clock_arguments_and_deadlines_reject_ambiguity_and_overflow() {
        for value in ["", "-1", "+1", "1.0", "1e3", "1\n", "18446744073709551616"] {
            assert!(decimal(value).is_err(), "{value:?}");
        }
        assert_eq!(decimal("0001").unwrap(), 1);
        assert!(remaining(0, 0).is_err());
        assert_eq!(remaining(10, 10).unwrap(), None);
        assert_eq!(remaining(9, 10).unwrap(), None);
        assert_eq!(remaining(11, 10).unwrap(), Some(1));
        assert!(remaining(MAX_BUDGET_NS + 1, 0).is_err());
        assert!(remaining(MAX_CLOCK_NS + 1, MAX_CLOCK_NS).is_err());
        assert!(checked_nanoseconds(-1, 0).is_err());
        assert!(checked_nanoseconds(1, NANOS_PER_SECOND as i64).is_err());
        assert!(checked_nanoseconds(i64::MAX, 0).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn native_wait_observes_expiry_without_extending_the_window() {
        let deadline = now_ns(false).unwrap() + 2_000_000;
        assert_eq!(
            run(&["wait".into(), deadline.to_string()]).unwrap(),
            EXPIRED
        );
        assert_eq!(
            run(&["check".into(), deadline.to_string()]).unwrap(),
            EXPIRED
        );
    }
}
