//! Kernel process birth identity shared by durable clients and the daemon.
//!
//! A PID alone, or a display timestamp rounded to seconds, cannot establish
//! ownership after a restart. Failed inspection never proves that an owner died.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "platform", rename_all = "snake_case")]
pub enum ProcessStart {
    Linux { ticks: u64 },
    Darwin { seconds: u64, microseconds: u32 },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessIdentity {
    pub boot_id: String,
    pub start: ProcessStart,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProcessObservation {
    Present(ProcessIdentity),
    Absent,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OwnerPresence {
    Live,
    Absent,
    Unknown,
}

impl ProcessIdentity {
    pub fn is_valid(&self) -> bool {
        uuid::Uuid::parse_str(&self.boot_id).is_ok_and(|uuid| uuid.to_string() == self.boot_id)
            && match self.start {
                ProcessStart::Linux { .. } => true,
                ProcessStart::Darwin {
                    seconds,
                    microseconds,
                } => seconds > 0 && microseconds < 1_000_000,
            }
    }

    /// Linux's existing durable daemon representation remains byte-compatible.
    /// The Darwin marker is versioned by kind and retains kernel precision.
    pub fn to_record(&self) -> Option<String> {
        self.is_valid().then(|| match self.start {
            ProcessStart::Linux { ticks } => format!("{}:{ticks}", self.boot_id),
            ProcessStart::Darwin {
                seconds,
                microseconds,
            } => format!("{}:darwin:{seconds}:{microseconds}", self.boot_id),
        })
    }

    pub fn from_record(record: &str) -> Option<Self> {
        let (boot, marker) = record.split_once(':')?;
        let start = if let Some(time) = marker.strip_prefix("darwin:") {
            let (seconds, microseconds) = time.split_once(':')?;
            ProcessStart::Darwin {
                seconds: decimal(seconds)?,
                microseconds: u32::try_from(decimal(microseconds)?).ok()?,
            }
        } else {
            ProcessStart::Linux {
                ticks: decimal(marker)?,
            }
        };
        let identity = Self {
            boot_id: boot.into(),
            start,
        };
        identity.is_valid().then_some(identity)
    }

    pub fn presence(&self, observation: &ProcessObservation) -> OwnerPresence {
        if !self.is_valid() {
            return OwnerPresence::Unknown;
        }
        match observation {
            ProcessObservation::Absent => OwnerPresence::Absent,
            ProcessObservation::Unknown => OwnerPresence::Unknown,
            ProcessObservation::Present(current) => {
                if !current.is_valid()
                    || std::mem::discriminant(&self.start) != std::mem::discriminant(&current.start)
                {
                    return OwnerPresence::Unknown;
                }
                if self == current {
                    OwnerPresence::Live
                } else {
                    OwnerPresence::Absent
                }
            }
        }
    }
}

fn decimal(value: &str) -> Option<u64> {
    (!value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()))
        .then(|| value.parse().ok())
        .flatten()
}

/// Only call this with the PID whose identity was recorded in the journal.
/// The result authorizes observation/recovery, never an unfenced kill(pid).
pub fn owner_presence(pid: u32, expected: Option<&ProcessIdentity>) -> OwnerPresence {
    if pid <= 1 || i32::try_from(pid).is_err() {
        return OwnerPresence::Unknown;
    }
    observed_owner_presence(expected, &observe_process(pid))
}

fn observed_owner_presence(
    expected: Option<&ProcessIdentity>,
    observed: &ProcessObservation,
) -> OwnerPresence {
    if *observed == ProcessObservation::Absent {
        return OwnerPresence::Absent;
    }
    expected.map_or(OwnerPresence::Unknown, |identity| {
        identity.presence(observed)
    })
}

/// Read our own birth marker without accidentally inspecting an unrelated
/// /proc/<getpid> when procfs belongs to a different PID namespace.
pub fn current_process_identity() -> Option<ProcessIdentity> {
    #[cfg(target_os = "linux")]
    let observation = linux_stat(
        &std::fs::read_to_string("/proc/self/stat").ok()?,
        std::process::id(),
        &boot_identity()?,
    );
    #[cfg(not(target_os = "linux"))]
    let observation = observe_process(std::process::id());
    match observation {
        ProcessObservation::Present(identity) => Some(identity),
        _ => None,
    }
}

#[cfg(target_os = "linux")]
fn boot_identity() -> Option<String> {
    let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id").ok()?;
    let boot = boot.trim();
    uuid::Uuid::parse_str(boot).ok()?;
    Some(boot.into())
}

#[cfg(target_os = "macos")]
fn boot_identity() -> Option<String> {
    static BOOT: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    if let Some(boot) = BOOT.get() {
        return Some(boot.clone());
    }
    let output = std::process::Command::new("/usr/sbin/sysctl")
        .args(["-n", "kern.bootsessionuuid"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = std::str::from_utf8(&output.stdout).ok()?.trim();
    let boot = uuid::Uuid::parse_str(text).ok()?.to_string();
    // Do not cache failures: a transient inspection error is not permanent.
    let _ = BOOT.set(boot.clone());
    Some(boot)
}

#[cfg(target_os = "linux")]
pub fn observe_process(pid: u32) -> ProcessObservation {
    if pid <= 1 || i32::try_from(pid).is_err() {
        return ProcessObservation::Unknown;
    }
    // /proc may have been mounted by a different PID namespace. Neither a
    // matching numeric entry nor ENOENT there describes our signal namespace.
    // In particular, never release ownership because a live wrapper's PID is
    // absent from a foreign procfs view.
    if !std::fs::read_to_string("/proc/self/stat").is_ok_and(|stat| {
        stat.split_once(" (").and_then(|(pid, _)| decimal(pid))
            == Some(u64::from(std::process::id()))
    }) {
        return ProcessObservation::Unknown;
    }
    let Some(boot) = boot_identity() else {
        return ProcessObservation::Unknown;
    };
    match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(stat) => linux_stat(&stat, pid, &boot),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => ProcessObservation::Absent,
        Err(_) => ProcessObservation::Unknown,
    }
}

#[cfg(any(target_os = "linux", test))]
fn linux_stat(stat: &str, pid: u32, boot: &str) -> ProcessObservation {
    let Some((prefix, rest)) = stat.rsplit_once(") ") else {
        return ProcessObservation::Unknown;
    };
    if prefix.split_once(" (").and_then(|(pid, _)| decimal(pid)) != Some(u64::from(pid)) {
        return ProcessObservation::Unknown;
    }
    let mut fields = rest.split_whitespace();
    let state = fields.next();
    let Some(ticks) = fields.nth(18).and_then(decimal) else {
        return ProcessObservation::Unknown;
    };
    match state {
        Some("Z" | "X" | "x") => ProcessObservation::Absent,
        Some("R" | "S" | "D" | "T" | "t" | "K" | "W" | "P" | "I") => {
            ProcessObservation::Present(ProcessIdentity {
                boot_id: boot.into(),
                start: ProcessStart::Linux { ticks },
            })
        }
        _ => ProcessObservation::Unknown,
    }
}

#[cfg(target_os = "macos")]
pub fn observe_process(pid: u32) -> ProcessObservation {
    if pid <= 1 || i32::try_from(pid).is_err() {
        return ProcessObservation::Unknown;
    }
    let Some(boot) = boot_identity() else {
        return ProcessObservation::Unknown;
    };
    match libproc::proc_pid::pidinfo::<libproc::bsd_info::BSDInfo>(pid as i32, 0) {
        Ok(info) => darwin_info(
            pid,
            info.pbi_pid,
            info.pbi_status,
            info.pbi_start_tvsec,
            info.pbi_start_tvusec,
            &boot,
        ),
        Err(_) => {
            // libproc's error is textual. Do not infer ESRCH from text or a
            // stale errno: perform a safe, signal-free kernel existence probe.
            match rustix::process::test_kill_process(
                rustix::process::Pid::from_raw(pid as i32).expect("validated positive PID"),
            ) {
                Err(rustix::io::Errno::SRCH) => ProcessObservation::Absent,
                _ => ProcessObservation::Unknown,
            }
        }
    }
}

#[cfg(any(target_os = "macos", test))]
fn darwin_info(
    requested: u32,
    actual: u32,
    state: u32,
    seconds: u64,
    microseconds: u64,
    boot: &str,
) -> ProcessObservation {
    if actual != requested || seconds == 0 || microseconds >= 1_000_000 {
        return ProcessObservation::Unknown;
    }
    // Darwin bsd/sys/proc.h: SIDL=1, SRUN=2, SSLEEP=3, SSTOP=4, SZOMB=5.
    // proc_info.c fills pbi_start_tv{sec,usec} directly from p_start.
    match state {
        5 => ProcessObservation::Absent,
        1..=4 => ProcessObservation::Present(ProcessIdentity {
            boot_id: boot.into(),
            start: ProcessStart::Darwin {
                seconds,
                microseconds: microseconds as u32,
            },
        }),
        _ => ProcessObservation::Unknown,
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn observe_process(_pid: u32) -> ProcessObservation {
    ProcessObservation::Unknown
}

#[cfg(test)]
mod tests {
    use super::*;

    const BOOT: &str = "3f1c2a9e-5b7d-4e2a-9c1f-0a1b2c3d4e5f";

    #[test]
    fn native_precision_survives_records_and_rejects_second_resolution_history() {
        let linux = format!("{BOOT}:123456789");
        let darwin = format!("{BOOT}:darwin:1791280000:123456");
        for record in [&linux, &darwin] {
            let identity = ProcessIdentity::from_record(record).unwrap();
            assert_eq!(identity.to_record().as_ref(), Some(record));
            assert_eq!(
                serde_json::from_str::<ProcessIdentity>(&serde_json::to_string(&identity).unwrap())
                    .unwrap(),
                identity
            );
        }
        for record in [
            format!("{BOOT}:Mon Sep 28 10:48:17 2026"),
            format!("{BOOT}:darwin:1791280000:1000000"),
            format!("{BOOT}:darwin:0:123"),
            format!("{BOOT}:darwin:1791280000:123:4"),
            format!("{BOOT}:+123"),
            "unverified-boot:123".into(),
            format!("{}:123", BOOT.to_uppercase()),
        ] {
            assert!(ProcessIdentity::from_record(&record).is_none(), "{record}");
        }
    }

    #[test]
    fn matching_distinguishes_microseconds_reboots_and_unknown_observation() {
        let owner =
            ProcessIdentity::from_record(&format!("{BOOT}:darwin:1791280000:123456")).unwrap();
        assert_eq!(
            owner.presence(&ProcessObservation::Present(owner.clone())),
            OwnerPresence::Live
        );
        let mut reused = owner.clone();
        reused.start = ProcessStart::Darwin {
            seconds: 1791280000,
            microseconds: 123457,
        };
        assert_eq!(
            owner.presence(&ProcessObservation::Present(reused)),
            OwnerPresence::Absent
        );
        let mut rebooted = owner.clone();
        rebooted.boot_id = "00000000-0000-0000-0000-000000000001".into();
        assert_eq!(
            owner.presence(&ProcessObservation::Present(rebooted)),
            OwnerPresence::Absent
        );
        assert_eq!(
            owner.presence(&ProcessObservation::Unknown),
            OwnerPresence::Unknown
        );
        assert_eq!(
            owner.presence(&ProcessObservation::Absent),
            OwnerPresence::Absent
        );
        let linux = ProcessIdentity::from_record(&format!("{BOOT}:123")).unwrap();
        assert_eq!(
            owner.presence(&ProcessObservation::Present(linux)),
            OwnerPresence::Unknown
        );
    }

    #[test]
    fn absent_pid_is_independent_proof_but_unknown_or_legacy_birth_cannot_adopt_a_live_pid() {
        let current =
            ProcessIdentity::from_record(&format!("{BOOT}:darwin:1791280000:123456")).unwrap();
        let legacy = ProcessIdentity::from_record(&format!("{BOOT}:Mon Sep 28 10:48:17 2026"));
        assert!(legacy.is_none());
        for expected in [None, legacy.as_ref(), Some(&current)] {
            assert_eq!(
                observed_owner_presence(expected, &ProcessObservation::Absent),
                OwnerPresence::Absent
            );
            assert_eq!(
                observed_owner_presence(expected, &ProcessObservation::Unknown),
                OwnerPresence::Unknown
            );
        }
        assert_eq!(
            observed_owner_presence(None, &ProcessObservation::Present(current)),
            OwnerPresence::Unknown
        );
    }

    #[test]
    fn proc_stat_handles_command_parentheses_and_refuses_wrong_pid_namespace() {
        let stat = |state| format!("123 (rch (wrapper)) {state} {} 42", vec!["0"; 18].join(" "));
        let expected = ProcessIdentity::from_record(&format!("{BOOT}:42")).unwrap();
        assert_eq!(
            expected.presence(&linux_stat(&stat("S"), 123, BOOT)),
            OwnerPresence::Live
        );
        for state in ["Z", "X", "x"] {
            assert_eq!(
                linux_stat(&stat(state), 123, BOOT),
                ProcessObservation::Absent
            );
        }
        assert_eq!(
            linux_stat(&stat("S"), 456, BOOT),
            ProcessObservation::Unknown
        );
        assert_eq!(
            linux_stat(&stat("?"), 123, BOOT),
            ProcessObservation::Unknown
        );
        assert_eq!(
            linux_stat("truncated", 123, BOOT),
            ProcessObservation::Unknown
        );
    }

    #[test]
    fn darwin_kernel_records_validate_pid_status_and_fractional_time() {
        assert!(matches!(
            darwin_info(42, 42, 2, 1791280000, 123456, BOOT),
            ProcessObservation::Present(_)
        ));
        assert_eq!(
            darwin_info(42, 42, 5, 1791280000, 123456, BOOT),
            ProcessObservation::Absent
        );
        for (pid, state, seconds, micros) in [
            (43, 2, 1791280000, 123456),
            (42, 99, 1791280000, 123456),
            (42, 2, 0, 1),
            (42, 2, 1791280000, 1000000),
        ] {
            assert_eq!(
                darwin_info(42, pid, state, seconds, micros, BOOT),
                ProcessObservation::Unknown
            );
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn darwin_native_birth_is_stable_and_a_reaped_child_is_absent() {
        let own = current_process_identity().expect("native own process identity");
        assert!(matches!(own.start, ProcessStart::Darwin { .. }));
        assert_eq!(current_process_identity(), Some(own));
        let mut child = std::process::Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let observed = observe_process(child.id());
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(
            matches!(observed, ProcessObservation::Present(_)),
            "{observed:?}"
        );
        assert_eq!(observe_process(child.id()), ProcessObservation::Absent);
    }
}
