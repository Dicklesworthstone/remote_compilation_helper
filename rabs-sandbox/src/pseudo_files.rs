//! Canonical pseudo-files, devices, hostname, locale, timezone (bead
//! D017; plan §28; risk R46-adjacent).
//!
//! The canonical namespace presents a DETERMINISTIC machine face:
//! hostname `rabs` (D003's UTS namespace), locale `C.UTF-8`, `TZ=UTC`
//! (D005 canonical env), a private procfs, and a minimal device set —
//! bubblewrap's `--dev` tmpfs, which contains exactly the approved
//! allowlist below. Everything a probe can observe beyond that list is
//! a violation CLASSIFIED BY EFFECT, because "some extra device" is not
//! one risk: an entropy device changes randomized outputs, a clock
//! surface changes embedded times, a host-identity surface splits
//! caches across machines, and a storage device is an escape hatch.

/// The approved device allowlist (bwrap `--dev` minimal tmpfs; `core`
/// is bwrap's `/proc/kcore` symlink, unreadable inside the userns —
/// observed live on hz2 as part of the audited minimal set).
pub const APPROVED_DEVICES: [&str; 9] = [
    "null", "zero", "full", "random", "urandom", "tty", "console", "ptmx", "core",
];

/// Approved device DIRECTORIES in the minimal /dev.
pub const APPROVED_DEVICE_DIRS: [&str; 4] = ["pts", "shm", "fd", "std"];

/// Effect classification of one observed pseudo-file/device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PseudoFileEffect {
    /// On the allowlist — canonical.
    Approved,
    /// Entropy source beyond the approved pair (`hwrng`, …): randomized
    /// output divergence.
    UnapprovedEntropySource,
    /// Clock/timer surface (`rtc*`, `hpet`, `ptp*`): embedded-time
    /// divergence.
    UnapprovedClockSurface,
    /// Host identity/hardware surface (`disk*`, `sd*`, `nvme*`,
    /// `cpu*`, `mem`, `kmsg`): cache-splitting host leakage or worse.
    HostHardwareSurface,
    /// Anything else off-list.
    UnapprovedOther,
}

/// Classify one observed `/dev` entry name.
#[must_use]
pub fn classify_device(name: &str) -> PseudoFileEffect {
    if APPROVED_DEVICES.contains(&name)
        || APPROVED_DEVICE_DIRS.contains(&name)
        || name.starts_with("std")
    // stdin/stdout/stderr symlinks
    {
        return PseudoFileEffect::Approved;
    }
    if name == "hwrng" {
        return PseudoFileEffect::UnapprovedEntropySource;
    }
    if ["rtc", "hpet", "ptp"].iter().any(|p| name.starts_with(p)) {
        return PseudoFileEffect::UnapprovedClockSurface;
    }
    if ["disk", "sd", "nvme", "cpu", "mem", "kmsg", "loop"]
        .iter()
        .any(|p| name.starts_with(p))
    {
        return PseudoFileEffect::HostHardwareSurface;
    }
    PseudoFileEffect::UnapprovedOther
}

/// The canonical machine-face values (single source for specs + tests).
pub mod canonical_values {
    /// UTS hostname inside the namespace.
    pub const HOSTNAME: &str = "rabs";
    /// Locale (LANG and LC_ALL).
    pub const LOCALE: &str = "C.UTF-8";
    /// Timezone.
    pub const TIMEZONE: &str = "UTC";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn approved_devices_classify_approved() {
        for name in APPROVED_DEVICES {
            assert_eq!(classify_device(name), PseudoFileEffect::Approved, "{name}");
        }
        for name in APPROVED_DEVICE_DIRS {
            assert_eq!(classify_device(name), PseudoFileEffect::Approved, "{name}");
        }
    }

    #[test]
    fn violations_classify_per_effect_class() {
        // THE bead's classification requirement, one fixture per class.
        assert_eq!(
            classify_device("hwrng"),
            PseudoFileEffect::UnapprovedEntropySource
        );
        for clock in ["rtc0", "hpet", "ptp1"] {
            assert_eq!(
                classify_device(clock),
                PseudoFileEffect::UnapprovedClockSurface,
                "{clock}"
            );
        }
        for hardware in ["sda1", "nvme0", "mem", "kmsg", "loop0", "disk0"] {
            assert_eq!(
                classify_device(hardware),
                PseudoFileEffect::HostHardwareSurface,
                "{hardware}"
            );
        }
        assert_eq!(
            classify_device("weird-device"),
            PseudoFileEffect::UnapprovedOther
        );
    }

    #[test]
    fn canonical_env_carries_the_canonical_machine_face() {
        // The D005 canonical env and this module must agree — a drift
        // in either breaks this coupling test.
        use crate::canonical_mounts::CanonicalMountPlan;
        let spec = CanonicalMountPlan::new("/b/tc", "/b/ws", "/b/ch", "/b/home")
            .to_spec()
            .unwrap();
        let env: std::collections::BTreeMap<_, _> = spec.env.into_iter().collect();
        assert_eq!(env["LANG"], canonical_values::LOCALE);
        assert_eq!(env["LC_ALL"], canonical_values::LOCALE);
        assert_eq!(env["TZ"], canonical_values::TIMEZONE);
        assert_eq!(spec.hostname, canonical_values::HOSTNAME);
    }
}
