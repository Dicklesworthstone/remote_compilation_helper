//! Reliability-doctor reason-code catalog (`RCH-Rnnn`).
//!
//! This module mirrors the [`super::catalog::ErrorCode`] pattern but for the
//! `rch doctor --reliability` diagnostics surface. Every diagnostic emitted
//! by the reliability doctor carries one of these variants. The CLI/JSON
//! representation is a stable `RCH-Rnnn` string, so agents and dashboards
//! can branch on the code without parsing free-form snake_case strings.
//!
//! # Code Ranges
//!
//! | Range      | Category              | Description                            |
//! |------------|-----------------------|----------------------------------------|
//! | R001-R099  | Topology              | Worker config + daemon worker capacity |
//! | R100-R199  | DiskPressure          | Worker disk-pressure tiers + telemetry |
//! | R200-R299  | ProcessTriage         | Cancellation cleanup + process debt    |
//! | R300-R399  | RepoConvergence       | Worker repo-state convergence          |
//! | R400-R499  | HelperCompatibility   | rsync / ssh / cargo / zstd availability |
//! | R500-R599  | RolloutPosture        | self-healing config flags              |
//! | R600-R699  | SchemaCompatibility   | Cross-binary schema-version drift      |
//!
//! Discipline:
//! - Variant identifiers are CamelCase.
//! - Each variant has a fixed `RCH-Rnnn` code returned by [`ReliabilityReasonCode::code`].
//! - Each variant has a category (per the table above) for analytics grouping.
//! - Each variant declares whether its remediation requires a daemon restart
//!   via [`ReliabilityReasonCode::requires_restart`] (consumed by the
//!   reliability doctor's `requires_restart` field on `RemediationStep`).
//! - Each variant carries a one-line `remediation_hint` for the diagnostic's
//!   default suggestion text.
//!
//! Adding a new variant requires:
//! 1. Pick the next free code in the right range.
//! 2. Add the variant to the enum below.
//! 3. Add an arm to every `match self` block (Rust's exhaustiveness check
//!    will not let you forget — that's the whole point of the enum).
//! 4. The unit tests in this module enforce uniqueness, format, and
//!    range-membership at `cargo test` time.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Stable category groups for reliability reason codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReliabilityCategoryKind {
    Topology,
    DiskPressure,
    ProcessTriage,
    RepoConvergence,
    HelperCompatibility,
    RolloutPosture,
    SchemaCompatibility,
}

/// One reason code per emitted reliability diagnostic. Serializes to its
/// canonical `RCH-Rnnn` string form via [`Serialize`]; deserializes the same
/// form via [`Deserialize`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReliabilityReasonCode {
    // ---- Topology (R001-R099) ----
    /// Workers configuration could not be loaded.
    WorkersConfigUnreadable,
    /// No workers configured (every build runs locally).
    NoWorkersConfigured,
    /// Workers are configured (Pass).
    WorkersConfigured,
    /// Daemon status surface is unavailable.
    DaemonStatusUnavailable,
    /// Daemon has no registered workers.
    DaemonHasNoWorkers,
    /// Every worker is unhealthy.
    AllWorkersUnhealthy,
    /// Some workers are healthy, some are not.
    PartialWorkerCapacity,
    /// All workers are healthy (Pass).
    WorkersHealthy,
    /// A worker's circuit breaker is open.
    WorkerCircuitOpen,
    /// A worker is unreachable / offline / failed.
    WorkerUnreachable,
    /// A worker is degraded (half-open circuit or not-ready).
    WorkerDegraded,
    /// A worker is ready (Pass).
    WorkerReady,
    /// A worker reported an unrecognized `ready_status` value (defensive parse).
    WorkerStatusUnrecognized,
    /// A worker reported an unrecognized `circuit_state` value (defensive parse).
    WorkerCircuitStateUnrecognized,

    // ---- DiskPressure (R100-R199) ----
    /// Disk-pressure surface is unavailable.
    DiskPressureUnavailable,
    /// Worker disk pressure has reached critical.
    WorkerDiskPressureCritical,
    /// Worker disk pressure has reached the warning threshold.
    WorkerDiskPressureWarning,
    /// Worker disk pressure is healthy (Pass).
    WorkerDiskPressureHealthy,
    /// Worker is missing fresh disk telemetry.
    WorkerDiskPressureTelemetryGap,
    /// No workers reported disk-pressure telemetry (Info; common for empty fleets).
    DiskPressureNoWorkers,

    // ---- ProcessTriage (R200-R299) ----
    /// Process-debt surface is unavailable.
    ProcessDebtUnavailable,
    /// Cancellation cleanup is healthy (Pass).
    CancellationCleanupHealthy,
    /// Cancellation cleanup was skipped (no jobs to triage).
    CancellationCleanupSkipped,
    /// Cancellation cleanup is degraded (some warnings).
    CancellationCleanupDegraded,
    /// Cancellation cleanup is failing.
    CancellationCleanupFailed,

    // ---- RepoConvergence (R300-R399) ----
    /// Repo-convergence surface is unavailable.
    RepoConvergenceUnavailable,
    /// One or more workers failed repo convergence.
    RepoConvergenceFailed,
    /// Workers are drifting / stale on repo convergence.
    RepoConvergenceDrift,
    /// No workers reported repo-convergence records (Info).
    RepoConvergenceNoWorkers,
    /// All workers are repo-converged (Pass).
    RepoConvergenceReady,
    /// A specific worker's repo state is not ready.
    WorkerRepoNotReady,

    // ---- HelperCompatibility (R400-R499) ----
    /// A required helper binary is available (Pass).
    HelperAvailable,
    /// A required helper binary is missing.
    HelperMissing,
    /// The helper compatibility probe itself did not complete.
    HelperProbeUnavailable,

    // ---- RolloutPosture (R500-R599) ----
    /// `self_healing.hook_starts_daemon` is enabled (Pass).
    HookAutoStartEnabled,
    /// `self_healing.hook_starts_daemon` is disabled.
    HookAutoStartDisabled,
    /// `self_healing.daemon_installs_hooks` is enabled (Pass).
    DaemonHookRepairEnabled,
    /// `self_healing.daemon_installs_hooks` is disabled.
    DaemonHookRepairDisabled,
    /// Configuration could not be loaded.
    ConfigLoadFailed,
    /// Unified status surface is compiled in (Pass).
    StatusSurfaceAvailable,
    /// Repo-convergence status endpoint is wired into the CLI (Pass).
    RepoConvergenceSurfaceAvailable,
    /// Disk-pressure fields are wired into worker status (Pass).
    DiskPressureSurfaceAvailable,

    // ---- SchemaCompatibility (R600-R699) ----
    /// Schema versions are compatible (Pass).
    SchemaCompatible,
    /// Schema versions are incompatible.
    SchemaIncompatible,
}

impl ReliabilityReasonCode {
    /// The CamelCase variant identifier as a static string. Used by
    /// `rch error explain` to render a human-readable name alongside
    /// the `RCH-Rnnn` code.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::WorkersConfigUnreadable => "WorkersConfigUnreadable",
            Self::NoWorkersConfigured => "NoWorkersConfigured",
            Self::WorkersConfigured => "WorkersConfigured",
            Self::DaemonStatusUnavailable => "DaemonStatusUnavailable",
            Self::DaemonHasNoWorkers => "DaemonHasNoWorkers",
            Self::AllWorkersUnhealthy => "AllWorkersUnhealthy",
            Self::PartialWorkerCapacity => "PartialWorkerCapacity",
            Self::WorkersHealthy => "WorkersHealthy",
            Self::WorkerCircuitOpen => "WorkerCircuitOpen",
            Self::WorkerUnreachable => "WorkerUnreachable",
            Self::WorkerDegraded => "WorkerDegraded",
            Self::WorkerReady => "WorkerReady",
            Self::WorkerStatusUnrecognized => "WorkerStatusUnrecognized",
            Self::WorkerCircuitStateUnrecognized => "WorkerCircuitStateUnrecognized",
            Self::DiskPressureUnavailable => "DiskPressureUnavailable",
            Self::WorkerDiskPressureCritical => "WorkerDiskPressureCritical",
            Self::WorkerDiskPressureWarning => "WorkerDiskPressureWarning",
            Self::WorkerDiskPressureHealthy => "WorkerDiskPressureHealthy",
            Self::WorkerDiskPressureTelemetryGap => "WorkerDiskPressureTelemetryGap",
            Self::DiskPressureNoWorkers => "DiskPressureNoWorkers",
            Self::ProcessDebtUnavailable => "ProcessDebtUnavailable",
            Self::CancellationCleanupHealthy => "CancellationCleanupHealthy",
            Self::CancellationCleanupSkipped => "CancellationCleanupSkipped",
            Self::CancellationCleanupDegraded => "CancellationCleanupDegraded",
            Self::CancellationCleanupFailed => "CancellationCleanupFailed",
            Self::RepoConvergenceUnavailable => "RepoConvergenceUnavailable",
            Self::RepoConvergenceFailed => "RepoConvergenceFailed",
            Self::RepoConvergenceDrift => "RepoConvergenceDrift",
            Self::RepoConvergenceNoWorkers => "RepoConvergenceNoWorkers",
            Self::RepoConvergenceReady => "RepoConvergenceReady",
            Self::WorkerRepoNotReady => "WorkerRepoNotReady",
            Self::HelperAvailable => "HelperAvailable",
            Self::HelperMissing => "HelperMissing",
            Self::HelperProbeUnavailable => "HelperProbeUnavailable",
            Self::HookAutoStartEnabled => "HookAutoStartEnabled",
            Self::HookAutoStartDisabled => "HookAutoStartDisabled",
            Self::DaemonHookRepairEnabled => "DaemonHookRepairEnabled",
            Self::DaemonHookRepairDisabled => "DaemonHookRepairDisabled",
            Self::ConfigLoadFailed => "ConfigLoadFailed",
            Self::StatusSurfaceAvailable => "StatusSurfaceAvailable",
            Self::RepoConvergenceSurfaceAvailable => "RepoConvergenceSurfaceAvailable",
            Self::DiskPressureSurfaceAvailable => "DiskPressureSurfaceAvailable",
            Self::SchemaCompatible => "SchemaCompatible",
            Self::SchemaIncompatible => "SchemaIncompatible",
        }
    }

    /// The canonical `RCH-Rnnn` code string for this variant.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            // R001-R099 — Topology
            Self::WorkersConfigUnreadable => "RCH-R001",
            Self::NoWorkersConfigured => "RCH-R002",
            Self::WorkersConfigured => "RCH-R003",
            Self::DaemonStatusUnavailable => "RCH-R004",
            Self::DaemonHasNoWorkers => "RCH-R005",
            Self::AllWorkersUnhealthy => "RCH-R006",
            Self::PartialWorkerCapacity => "RCH-R007",
            Self::WorkersHealthy => "RCH-R008",
            Self::WorkerCircuitOpen => "RCH-R009",
            Self::WorkerUnreachable => "RCH-R010",
            Self::WorkerDegraded => "RCH-R011",
            Self::WorkerReady => "RCH-R012",
            Self::WorkerStatusUnrecognized => "RCH-R013",
            Self::WorkerCircuitStateUnrecognized => "RCH-R014",

            // R100-R199 — DiskPressure
            Self::DiskPressureUnavailable => "RCH-R100",
            Self::WorkerDiskPressureCritical => "RCH-R101",
            Self::WorkerDiskPressureWarning => "RCH-R102",
            Self::WorkerDiskPressureHealthy => "RCH-R103",
            Self::WorkerDiskPressureTelemetryGap => "RCH-R104",
            Self::DiskPressureNoWorkers => "RCH-R105",

            // R200-R299 — ProcessTriage
            Self::ProcessDebtUnavailable => "RCH-R200",
            Self::CancellationCleanupHealthy => "RCH-R201",
            Self::CancellationCleanupSkipped => "RCH-R202",
            Self::CancellationCleanupDegraded => "RCH-R203",
            Self::CancellationCleanupFailed => "RCH-R204",

            // R300-R399 — RepoConvergence
            Self::RepoConvergenceUnavailable => "RCH-R300",
            Self::RepoConvergenceFailed => "RCH-R301",
            Self::RepoConvergenceDrift => "RCH-R302",
            Self::RepoConvergenceNoWorkers => "RCH-R303",
            Self::RepoConvergenceReady => "RCH-R304",
            Self::WorkerRepoNotReady => "RCH-R305",

            // R400-R499 — HelperCompatibility
            Self::HelperAvailable => "RCH-R400",
            Self::HelperMissing => "RCH-R401",
            Self::HelperProbeUnavailable => "RCH-R402",

            // R500-R599 — RolloutPosture
            Self::HookAutoStartEnabled => "RCH-R500",
            Self::HookAutoStartDisabled => "RCH-R501",
            Self::DaemonHookRepairEnabled => "RCH-R502",
            Self::DaemonHookRepairDisabled => "RCH-R503",
            Self::ConfigLoadFailed => "RCH-R504",
            Self::StatusSurfaceAvailable => "RCH-R505",
            Self::RepoConvergenceSurfaceAvailable => "RCH-R506",
            Self::DiskPressureSurfaceAvailable => "RCH-R507",

            // R600-R699 — SchemaCompatibility
            Self::SchemaCompatible => "RCH-R600",
            Self::SchemaIncompatible => "RCH-R601",
        }
    }

    /// The category this variant belongs to.
    #[must_use]
    pub const fn category(self) -> ReliabilityCategoryKind {
        use ReliabilityCategoryKind as C;
        match self {
            Self::WorkersConfigUnreadable
            | Self::NoWorkersConfigured
            | Self::WorkersConfigured
            | Self::DaemonStatusUnavailable
            | Self::DaemonHasNoWorkers
            | Self::AllWorkersUnhealthy
            | Self::PartialWorkerCapacity
            | Self::WorkersHealthy
            | Self::WorkerCircuitOpen
            | Self::WorkerUnreachable
            | Self::WorkerDegraded
            | Self::WorkerReady
            | Self::WorkerStatusUnrecognized
            | Self::WorkerCircuitStateUnrecognized => C::Topology,

            Self::DiskPressureUnavailable
            | Self::WorkerDiskPressureCritical
            | Self::WorkerDiskPressureWarning
            | Self::WorkerDiskPressureHealthy
            | Self::WorkerDiskPressureTelemetryGap
            | Self::DiskPressureNoWorkers => C::DiskPressure,

            Self::ProcessDebtUnavailable
            | Self::CancellationCleanupHealthy
            | Self::CancellationCleanupSkipped
            | Self::CancellationCleanupDegraded
            | Self::CancellationCleanupFailed => C::ProcessTriage,

            Self::RepoConvergenceUnavailable
            | Self::RepoConvergenceFailed
            | Self::RepoConvergenceDrift
            | Self::RepoConvergenceNoWorkers
            | Self::RepoConvergenceReady
            | Self::WorkerRepoNotReady => C::RepoConvergence,

            Self::HelperAvailable | Self::HelperMissing | Self::HelperProbeUnavailable => {
                C::HelperCompatibility
            }

            Self::HookAutoStartEnabled
            | Self::HookAutoStartDisabled
            | Self::DaemonHookRepairEnabled
            | Self::DaemonHookRepairDisabled
            | Self::ConfigLoadFailed
            | Self::StatusSurfaceAvailable
            | Self::RepoConvergenceSurfaceAvailable
            | Self::DiskPressureSurfaceAvailable => C::RolloutPosture,

            Self::SchemaCompatible | Self::SchemaIncompatible => C::SchemaCompatibility,
        }
    }

    /// Whether the configured remediation requires a process restart for the
    /// fix to take effect. Consumed by the reliability doctor when building
    /// `RemediationStep::requires_restart` (sibling bead `2s99h.15`).
    ///
    /// Policy:
    /// - `true` when the fix changes a flag/state read at daemon startup, OR
    ///   when the underlying subsystem caches state at process start.
    /// - `false` when the fix is purely external (e.g., disk space, key
    ///   permissions) OR when the daemon hot-reloads the relevant state.
    #[must_use]
    pub const fn requires_restart(self) -> bool {
        match self {
            // Topology — daemon parses workers.toml at startup; no SIGHUP yet.
            Self::WorkersConfigUnreadable
            | Self::NoWorkersConfigured
            | Self::DaemonStatusUnavailable
            | Self::DaemonHasNoWorkers => true,
            Self::WorkersConfigured | Self::WorkersHealthy | Self::WorkerReady => false,
            // Worker-level conditions are upstream; no rch restart fixes them.
            Self::AllWorkersUnhealthy
            | Self::PartialWorkerCapacity
            | Self::WorkerCircuitOpen
            | Self::WorkerUnreachable
            | Self::WorkerDegraded
            | Self::WorkerStatusUnrecognized
            | Self::WorkerCircuitStateUnrecognized => false,

            // Disk pressure is external — operator cleans up disk; daemon picks
            // up the new free-space numbers on next probe.
            Self::DiskPressureUnavailable
            | Self::WorkerDiskPressureCritical
            | Self::WorkerDiskPressureWarning
            | Self::WorkerDiskPressureHealthy
            | Self::WorkerDiskPressureTelemetryGap
            | Self::DiskPressureNoWorkers => false,

            // Process-triage stale subprocess cleanup may require daemon restart
            // to clear pgid handles.
            Self::ProcessDebtUnavailable | Self::CancellationCleanupFailed => true,
            Self::CancellationCleanupHealthy
            | Self::CancellationCleanupSkipped
            | Self::CancellationCleanupDegraded => false,

            // Repo-convergence checks are read-only; remediation is git-side.
            Self::RepoConvergenceUnavailable
            | Self::RepoConvergenceFailed
            | Self::RepoConvergenceDrift
            | Self::RepoConvergenceNoWorkers
            | Self::RepoConvergenceReady
            | Self::WorkerRepoNotReady => false,

            // Helper install (cargo install / package manager) doesn't require
            // daemon restart.
            Self::HelperAvailable | Self::HelperMissing | Self::HelperProbeUnavailable => false,

            // Rollout posture flags are cached at startup.
            Self::HookAutoStartEnabled => false,
            Self::HookAutoStartDisabled => true,
            Self::DaemonHookRepairEnabled => false,
            Self::DaemonHookRepairDisabled => true,
            Self::ConfigLoadFailed => false,
            Self::StatusSurfaceAvailable
            | Self::RepoConvergenceSurfaceAvailable
            | Self::DiskPressureSurfaceAvailable => false,

            // Schema versions are pinned at compile/bind time; mismatch
            // requires a fresh process.
            Self::SchemaCompatible => false,
            Self::SchemaIncompatible => true,
        }
    }

    /// One-line operator-facing remediation hint. Used as the default
    /// suggestion text when the diagnostic doesn't override it.
    #[must_use]
    pub const fn remediation_hint(self) -> &'static str {
        match self {
            Self::WorkersConfigUnreadable => {
                "Inspect ~/.config/rch/workers.toml for a parse error."
            }
            Self::NoWorkersConfigured => "Run `rch workers add <host>` to register a worker.",
            Self::WorkersConfigured => "No action needed.",
            Self::DaemonStatusUnavailable => "Start the daemon with `rch daemon start` and retry.",
            Self::DaemonHasNoWorkers => "Run `rch workers add <host>` to register a worker.",
            Self::AllWorkersUnhealthy => {
                "Run `rch workers probe --all` to diagnose worker connectivity."
            }
            Self::PartialWorkerCapacity => {
                "Run `rch workers list --json` to identify the unhealthy worker."
            }
            Self::WorkersHealthy => "No action needed.",
            Self::WorkerCircuitOpen => {
                "Run `rch workers reset-circuit <worker>` once the underlying issue is fixed."
            }
            Self::WorkerUnreachable => "Verify SSH connectivity with `rch workers probe <worker>`.",
            Self::WorkerDegraded => {
                "Run `rch workers probe <worker>` to refresh worker health state."
            }
            Self::WorkerReady => "No action needed.",
            Self::WorkerStatusUnrecognized => {
                "Daemon and rch versions may have drifted; reinstall both binaries."
            }
            Self::WorkerCircuitStateUnrecognized => {
                "Daemon and rch versions may have drifted; reinstall both binaries."
            }
            Self::DiskPressureUnavailable => "Start the daemon with `rch daemon start` and retry.",
            Self::WorkerDiskPressureCritical => {
                "Run `rch worker disk-cleanup --worker <name>` immediately."
            }
            Self::WorkerDiskPressureWarning => {
                "Plan a `rch worker disk-cleanup --worker <name>` cycle."
            }
            Self::WorkerDiskPressureHealthy => "No action needed.",
            Self::WorkerDiskPressureTelemetryGap => {
                "Run `rch workers probe <worker>` to refresh telemetry."
            }
            Self::DiskPressureNoWorkers => "No action needed.",
            Self::ProcessDebtUnavailable => "Start the daemon with `rch daemon start` and retry.",
            Self::CancellationCleanupHealthy => "No action needed.",
            Self::CancellationCleanupSkipped => "No action needed.",
            Self::CancellationCleanupDegraded => {
                "Run `rch status --jobs --json` to inspect process-triage state."
            }
            Self::CancellationCleanupFailed => {
                "Restart the daemon with `rch daemon restart` to reset stale pgid handles."
            }
            Self::RepoConvergenceUnavailable => {
                "Start the daemon with `rch daemon start` and retry."
            }
            Self::RepoConvergenceFailed => "Run `rch repo sync --all` to drive convergence.",
            Self::RepoConvergenceDrift => "Run `rch repo sync --all` to refresh worker state.",
            Self::RepoConvergenceNoWorkers => "No action needed.",
            Self::RepoConvergenceReady => "No action needed.",
            Self::WorkerRepoNotReady => "Run `rch repo sync --worker <name>` to converge.",
            Self::HelperAvailable => "No action needed.",
            Self::HelperMissing => "Install the missing helper via the system package manager.",
            Self::HelperProbeUnavailable => {
                "Rerun the helper probe after checking for stuck local helper subprocesses."
            }
            Self::HookAutoStartEnabled => "No action needed.",
            Self::HookAutoStartDisabled => {
                "Run `rch config set self_healing.hook_starts_daemon true`."
            }
            Self::DaemonHookRepairEnabled => "No action needed.",
            Self::DaemonHookRepairDisabled => {
                "Run `rch config set self_healing.daemon_installs_hooks true`."
            }
            Self::ConfigLoadFailed => "Run `rch config doctor --json` to diagnose.",
            Self::StatusSurfaceAvailable
            | Self::RepoConvergenceSurfaceAvailable
            | Self::DiskPressureSurfaceAvailable => "No action needed.",
            Self::SchemaCompatible => "No action needed.",
            Self::SchemaIncompatible => {
                "Upgrade rch / rchd / rch-wkr binaries to the same release."
            }
        }
    }

    /// Every variant of this enum, useful for exhaustive iteration in tests.
    pub const ALL: &'static [ReliabilityReasonCode] = &[
        Self::WorkersConfigUnreadable,
        Self::NoWorkersConfigured,
        Self::WorkersConfigured,
        Self::DaemonStatusUnavailable,
        Self::DaemonHasNoWorkers,
        Self::AllWorkersUnhealthy,
        Self::PartialWorkerCapacity,
        Self::WorkersHealthy,
        Self::WorkerCircuitOpen,
        Self::WorkerUnreachable,
        Self::WorkerDegraded,
        Self::WorkerReady,
        Self::WorkerStatusUnrecognized,
        Self::WorkerCircuitStateUnrecognized,
        Self::DiskPressureUnavailable,
        Self::WorkerDiskPressureCritical,
        Self::WorkerDiskPressureWarning,
        Self::WorkerDiskPressureHealthy,
        Self::WorkerDiskPressureTelemetryGap,
        Self::DiskPressureNoWorkers,
        Self::ProcessDebtUnavailable,
        Self::CancellationCleanupHealthy,
        Self::CancellationCleanupSkipped,
        Self::CancellationCleanupDegraded,
        Self::CancellationCleanupFailed,
        Self::RepoConvergenceUnavailable,
        Self::RepoConvergenceFailed,
        Self::RepoConvergenceDrift,
        Self::RepoConvergenceNoWorkers,
        Self::RepoConvergenceReady,
        Self::WorkerRepoNotReady,
        Self::HelperAvailable,
        Self::HelperMissing,
        Self::HelperProbeUnavailable,
        Self::HookAutoStartEnabled,
        Self::HookAutoStartDisabled,
        Self::DaemonHookRepairEnabled,
        Self::DaemonHookRepairDisabled,
        Self::ConfigLoadFailed,
        Self::StatusSurfaceAvailable,
        Self::RepoConvergenceSurfaceAvailable,
        Self::DiskPressureSurfaceAvailable,
        Self::SchemaCompatible,
        Self::SchemaIncompatible,
    ];
}

impl fmt::Display for ReliabilityReasonCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl Serialize for ReliabilityReasonCode {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.code())
    }
}

impl<'de> Deserialize<'de> for ReliabilityReasonCode {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(d)?;
        Self::from_code_str(&raw).ok_or_else(|| {
            serde::de::Error::custom(format!("unknown reliability reason code {raw:?}"))
        })
    }
}

impl ReliabilityReasonCode {
    /// Reverse-lookup helper for deserialization.
    #[must_use]
    pub fn from_code_str(code: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|c| c.code() == code)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_reliability_reason_codes_unique() {
        let mut seen = HashSet::new();
        for &c in ReliabilityReasonCode::ALL {
            assert!(
                seen.insert(c.code()),
                "duplicate code {} for variant {:?}",
                c.code(),
                c
            );
        }
        assert_eq!(seen.len(), ReliabilityReasonCode::ALL.len());
    }

    #[test]
    fn test_reliability_reason_codes_format() {
        for &c in ReliabilityReasonCode::ALL {
            let code = c.code();
            assert!(
                code.starts_with("RCH-R")
                    && code[5..].len() == 3
                    && code[5..].chars().all(|ch| ch.is_ascii_digit()),
                "invalid code format {code} for {c:?}"
            );
        }
    }

    #[test]
    fn test_reliability_reason_codes_in_documented_ranges() {
        for &c in ReliabilityReasonCode::ALL {
            let n: u32 = c.code()[5..].parse().expect("3-digit numeric");
            let cat = c.category();
            let expected_range = match cat {
                ReliabilityCategoryKind::Topology => 1..=99,
                ReliabilityCategoryKind::DiskPressure => 100..=199,
                ReliabilityCategoryKind::ProcessTriage => 200..=299,
                ReliabilityCategoryKind::RepoConvergence => 300..=399,
                ReliabilityCategoryKind::HelperCompatibility => 400..=499,
                ReliabilityCategoryKind::RolloutPosture => 500..=599,
                ReliabilityCategoryKind::SchemaCompatibility => 600..=699,
            };
            assert!(
                expected_range.contains(&n),
                "{c:?} code {} (n={n}) not in expected range {:?} for category {:?}",
                c.code(),
                expected_range,
                cat
            );
        }
    }

    #[test]
    fn test_reliability_reason_codes_serde_roundtrip() {
        for &c in ReliabilityReasonCode::ALL {
            let s = serde_json::to_string(&c).unwrap();
            let d: ReliabilityReasonCode = serde_json::from_str(&s).unwrap();
            assert_eq!(c, d, "round-trip mismatch for {c:?}");
            // Also confirm the on-the-wire form is the RCH-Rnnn string.
            let expected = format!("\"{}\"", c.code());
            assert_eq!(s, expected);
        }
    }

    #[test]
    fn test_reliability_reason_codes_remediation_non_empty() {
        for &c in ReliabilityReasonCode::ALL {
            let hint = c.remediation_hint();
            assert!(!hint.is_empty(), "empty remediation hint for {c:?}");
        }
    }

    #[test]
    fn test_unknown_code_deserialize_fails_clearly() {
        let r: Result<ReliabilityReasonCode, _> = serde_json::from_str("\"RCH-R999\"");
        let err = r.expect_err("RCH-R999 should not deserialize");
        let msg = err.to_string();
        assert!(
            msg.contains("RCH-R999"),
            "error should name the unknown code, got: {msg}"
        );
    }

    #[test]
    fn test_display_matches_code() {
        for &c in ReliabilityReasonCode::ALL {
            assert_eq!(format!("{c}"), c.code().to_string());
        }
    }

    #[test]
    fn test_requires_restart_explicit_for_every_reason() {
        // Rust's exhaustive match enforces this; the test exists to catch a
        // future "_ => false" wildcard from regressing the discipline.
        for &c in ReliabilityReasonCode::ALL {
            // Just call it; if there's a panic-on-miss, this catches it.
            let _ = c.requires_restart();
        }
    }

    /// Pinned policy table mirroring the [bead body's table for
    /// `2s99h.15`](https://example.invalid). The implementation
    /// [`ReliabilityReasonCode::requires_restart`] is the canonical authority;
    /// this table is duplicate state used to:
    /// 1. Detect implementation drift (reviewer sees both edits in the diff).
    /// 2. Provide a paste-ready reference table for documentation.
    ///
    /// Adding a new variant requires updating BOTH the impl AND this table —
    /// surfacing the rationale in code review. The
    /// [`test_requires_restart_table_matches_impl`] test enforces the match.
    const REQUIRES_RESTART_TABLE: &[(ReliabilityReasonCode, bool)] = &[
        // Topology
        (ReliabilityReasonCode::WorkersConfigUnreadable, true),
        (ReliabilityReasonCode::NoWorkersConfigured, true),
        (ReliabilityReasonCode::WorkersConfigured, false),
        (ReliabilityReasonCode::DaemonStatusUnavailable, true),
        (ReliabilityReasonCode::DaemonHasNoWorkers, true),
        (ReliabilityReasonCode::AllWorkersUnhealthy, false),
        (ReliabilityReasonCode::PartialWorkerCapacity, false),
        (ReliabilityReasonCode::WorkersHealthy, false),
        (ReliabilityReasonCode::WorkerCircuitOpen, false),
        (ReliabilityReasonCode::WorkerUnreachable, false),
        (ReliabilityReasonCode::WorkerDegraded, false),
        (ReliabilityReasonCode::WorkerReady, false),
        (ReliabilityReasonCode::WorkerStatusUnrecognized, false),
        (ReliabilityReasonCode::WorkerCircuitStateUnrecognized, false),
        // DiskPressure
        (ReliabilityReasonCode::DiskPressureUnavailable, false),
        (ReliabilityReasonCode::WorkerDiskPressureCritical, false),
        (ReliabilityReasonCode::WorkerDiskPressureWarning, false),
        (ReliabilityReasonCode::WorkerDiskPressureHealthy, false),
        (ReliabilityReasonCode::WorkerDiskPressureTelemetryGap, false),
        (ReliabilityReasonCode::DiskPressureNoWorkers, false),
        // ProcessTriage
        (ReliabilityReasonCode::ProcessDebtUnavailable, true),
        (ReliabilityReasonCode::CancellationCleanupHealthy, false),
        (ReliabilityReasonCode::CancellationCleanupSkipped, false),
        (ReliabilityReasonCode::CancellationCleanupDegraded, false),
        (ReliabilityReasonCode::CancellationCleanupFailed, true),
        // RepoConvergence
        (ReliabilityReasonCode::RepoConvergenceUnavailable, false),
        (ReliabilityReasonCode::RepoConvergenceFailed, false),
        (ReliabilityReasonCode::RepoConvergenceDrift, false),
        (ReliabilityReasonCode::RepoConvergenceNoWorkers, false),
        (ReliabilityReasonCode::RepoConvergenceReady, false),
        (ReliabilityReasonCode::WorkerRepoNotReady, false),
        // HelperCompatibility
        (ReliabilityReasonCode::HelperAvailable, false),
        (ReliabilityReasonCode::HelperMissing, false),
        (ReliabilityReasonCode::HelperProbeUnavailable, false),
        // RolloutPosture
        (ReliabilityReasonCode::HookAutoStartEnabled, false),
        (ReliabilityReasonCode::HookAutoStartDisabled, true),
        (ReliabilityReasonCode::DaemonHookRepairEnabled, false),
        (ReliabilityReasonCode::DaemonHookRepairDisabled, true),
        (ReliabilityReasonCode::ConfigLoadFailed, false),
        (ReliabilityReasonCode::StatusSurfaceAvailable, false),
        (
            ReliabilityReasonCode::RepoConvergenceSurfaceAvailable,
            false,
        ),
        (ReliabilityReasonCode::DiskPressureSurfaceAvailable, false),
        // SchemaCompatibility
        (ReliabilityReasonCode::SchemaCompatible, false),
        (ReliabilityReasonCode::SchemaIncompatible, true),
    ];

    #[test]
    fn test_requires_restart_table_matches_impl() {
        // Every entry in the pinned table must agree with the impl AND
        // every variant must appear in the table (in the same order as
        // ALL_COMPONENTS). Editing requires_restart() without updating the
        // table — or vice versa — triggers a clear failure.
        assert_eq!(
            REQUIRES_RESTART_TABLE.len(),
            ReliabilityReasonCode::ALL.len(),
            "REQUIRES_RESTART_TABLE has {} entries but {} variants exist. \
             Add or remove the corresponding entry when changing the variant set.",
            REQUIRES_RESTART_TABLE.len(),
            ReliabilityReasonCode::ALL.len()
        );

        for (i, ((variant, expected), &impl_variant)) in REQUIRES_RESTART_TABLE
            .iter()
            .zip(ReliabilityReasonCode::ALL.iter())
            .enumerate()
        {
            assert_eq!(
                *variant, impl_variant,
                "Position {i}: REQUIRES_RESTART_TABLE has {variant:?} but ALL has {impl_variant:?}. \
                 Tables must be in identical order — easier diff review.",
            );
            let actual = variant.requires_restart();
            assert_eq!(
                *expected, actual,
                "Policy mismatch for {variant:?}: table says {expected}, impl says {actual}. \
                 Update BOTH or NEITHER.",
            );
        }
    }

    #[test]
    fn test_requires_restart_consistency_with_remediation_hint() {
        // Heuristic: if the remediation hint mentions "restart", the variant
        // SHOULD have requires_restart=true. Catches drift between the
        // operator-facing hint and the policy bool. (Limited to the obvious
        // case — no false-positive on hints that mention "rch daemon
        // restart" only as a remediation command for a non-restart variant.)
        for &c in ReliabilityReasonCode::ALL {
            let hint = c.remediation_hint().to_lowercase();
            // Only flag the case where hint says "restart" but bool says false.
            // The reverse (bool=true, no "restart" in hint) is fine since the
            // hint may use a different idiom (e.g., "reinstall both binaries").
            if hint.contains("restart") {
                assert!(
                    c.requires_restart(),
                    "Variant {c:?} hint mentions 'restart' but requires_restart() returns false. \
                     Either update the hint to NOT say 'restart' or set requires_restart=true."
                );
            }
        }
    }
}
