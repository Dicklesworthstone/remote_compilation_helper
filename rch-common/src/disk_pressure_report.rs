//! Per-worker disk / inode / target-root / cargo-home / log pressure report for
//! `rch doctor` and status (bd-session-history-remediation-ocv9i.11.4).
//!
//! Session history showed two recurring confusions operators hit under disk
//! pressure:
//!
//! 1. **No single place to see pressure.** Disk %, inodes, the cargo home, the
//!    target root, the sync root, and log growth were scattered or absent, so a
//!    capacity collapse was hard to attribute.
//! 2. **Worker filesystem errors misread as product compile failures.** A
//!    `No space left on device` during an offloaded build is a *worker /
//!    environment* failure, not the project failing to compile — yet it
//!    surfaced as a build error and sent agents debugging their own code.
//!
//! This module provides the pure, testable core for both:
//! [`assess_root`] / [`WorkerDiskPressureReport`] classify each filesystem
//! dimension into a [`PressureLevel`] (with `Unknown` for missing metrics or a
//! telemetry gap), and [`classify_exec_failure`] separates a worker/environment
//! disk failure from a genuine product compile failure — defaulting an ENOSPC
//! to worker/environment *unless real compiler diagnostics prove otherwise*.
//!
//! Rendering this in the `rch doctor` CLI and feeding it from live worker facts
//! is the surface/daemon wiring; this module is the shared assessment contract
//! the doctor view, status, metrics, and dashboards all key off.

use serde::{Deserialize, Serialize};

use crate::telemetry_freshness::FreshnessVerdict;
use crate::worker_facts::DiskRootFacts;

/// Pressure severity for one filesystem dimension.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PressureLevel {
    /// Comfortable headroom.
    Ok,
    /// Approaching a threshold — worth attention.
    Warning,
    /// At/over the critical threshold — action needed.
    Critical,
    /// Cannot assess (metric absent, or telemetry too stale to trust).
    Unknown,
}

impl PressureLevel {
    /// Stable lowercase token.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            PressureLevel::Ok => "ok",
            PressureLevel::Warning => "warning",
            PressureLevel::Critical => "critical",
            PressureLevel::Unknown => "unknown",
        }
    }

    /// Severity rank for aggregation. `Unknown` outranks `Ok` (a missing metric
    /// is more concerning than a healthy one) but not a known `Warning`/`Critical`.
    #[must_use]
    const fn rank(self) -> u8 {
        match self {
            PressureLevel::Ok => 0,
            PressureLevel::Unknown => 1,
            PressureLevel::Warning => 2,
            PressureLevel::Critical => 3,
        }
    }

    /// The worse (higher-rank) of two levels.
    #[must_use]
    pub fn worse(self, other: PressureLevel) -> PressureLevel {
        if other.rank() > self.rank() {
            other
        } else {
            self
        }
    }
}

/// Which RCH-relevant filesystem a root represents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiskRootKind {
    /// The pooled/per-job Rust target root.
    TargetRoot,
    /// The cargo home (registry/cache).
    CargoHome,
    /// The upload/sync staging root.
    SyncRoot,
    /// RCH log directory.
    Log,
    /// The temp root builds land under.
    TempRoot,
    /// Any other tracked root.
    Other,
}

impl DiskRootKind {
    /// Stable lowercase token.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            DiskRootKind::TargetRoot => "target_root",
            DiskRootKind::CargoHome => "cargo_home",
            DiskRootKind::SyncRoot => "sync_root",
            DiskRootKind::Log => "log",
            DiskRootKind::TempRoot => "temp_root",
            DiskRootKind::Other => "other",
        }
    }
}

/// Thresholds for classifying pressure. Byte thresholds are percent-of-total
/// available; inode thresholds are absolute available counts.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PressureThresholds {
    pub warning_avail_pct: f64,
    pub critical_avail_pct: f64,
    pub warning_avail_inodes: u64,
    pub critical_avail_inodes: u64,
}

impl Default for PressureThresholds {
    fn default() -> Self {
        Self {
            warning_avail_pct: 15.0,
            critical_avail_pct: 5.0,
            warning_avail_inodes: 100_000,
            critical_avail_inodes: 10_000,
        }
    }
}

/// Assessed pressure for one filesystem root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootPressure {
    pub kind: DiskRootKind,
    pub path: String,
    /// Byte-capacity pressure.
    pub bytes: PressureLevel,
    /// Inode-capacity pressure.
    pub inodes: PressureLevel,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub available_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub available_inodes: Option<u64>,
}

impl RootPressure {
    /// The worse of this root's byte and inode pressure.
    #[must_use]
    pub fn worst(&self) -> PressureLevel {
        self.bytes.worse(self.inodes)
    }
}

/// Assess one root. `facts == None` (the metric was never collected) yields
/// `Unknown` for both dimensions, so "missing disk metrics" is distinct from a
/// healthy `Ok`. A zero `total_bytes` is also `Unknown` (df gave no usable
/// figure); zero available inodes is treated as exhaustion (`Critical`).
#[must_use]
pub fn assess_root(
    kind: DiskRootKind,
    facts: Option<&DiskRootFacts>,
    thresholds: &PressureThresholds,
) -> RootPressure {
    let Some(facts) = facts else {
        return RootPressure {
            kind,
            path: String::new(),
            bytes: PressureLevel::Unknown,
            inodes: PressureLevel::Unknown,
            available_bytes: None,
            total_bytes: None,
            available_inodes: None,
        };
    };

    let bytes = if facts.total_bytes == 0 {
        PressureLevel::Unknown
    } else {
        // available as a percent of total.
        let pct = (facts.available_bytes as f64 / facts.total_bytes as f64) * 100.0;
        if pct <= thresholds.critical_avail_pct {
            PressureLevel::Critical
        } else if pct <= thresholds.warning_avail_pct {
            PressureLevel::Warning
        } else {
            PressureLevel::Ok
        }
    };

    let inodes = if facts.available_inodes < thresholds.critical_avail_inodes {
        PressureLevel::Critical
    } else if facts.available_inodes < thresholds.warning_avail_inodes {
        PressureLevel::Warning
    } else {
        PressureLevel::Ok
    };

    RootPressure {
        kind,
        path: facts.path.clone(),
        bytes,
        inodes,
        available_bytes: Some(facts.available_bytes),
        total_bytes: Some(facts.total_bytes),
        available_inodes: Some(facts.available_inodes),
    }
}

/// A per-worker disk-pressure report for `rch doctor`/status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerDiskPressureReport {
    pub worker_id: String,
    /// Telemetry freshness for the worker's metrics; a stale/unknown verdict
    /// caps confidence in the levels below.
    pub telemetry: FreshnessVerdict,
    pub roots: Vec<RootPressure>,
}

impl WorkerDiskPressureReport {
    /// Worst pressure across all roots. When telemetry is not usable and nothing
    /// is already `Critical`, the worst is at least `Unknown` — the figures
    /// can't be trusted, so the report must not read as a confident `Ok`.
    #[must_use]
    pub fn worst(&self) -> PressureLevel {
        let mut worst = self
            .roots
            .iter()
            .fold(PressureLevel::Ok, |acc, r| acc.worse(r.worst()));
        if !self.telemetry.is_usable() && worst != PressureLevel::Critical {
            worst = worst.worse(PressureLevel::Unknown);
        }
        worst
    }

    /// Whether any root is at critical pressure.
    #[must_use]
    pub fn has_critical(&self) -> bool {
        self.roots
            .iter()
            .any(|r| r.worst() == PressureLevel::Critical)
    }

    /// Human-readable summary line.
    #[must_use]
    pub fn render(&self) -> String {
        format!(
            "worker {} disk pressure: {} (telemetry={}, {} root(s))",
            self.worker_id,
            self.worst().as_str(),
            if self.telemetry.is_usable() {
                "ok"
            } else {
                "stale"
            },
            self.roots.len(),
        )
    }
}

/// Classification of a failed offloaded execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecFailureClass {
    /// A worker/environment failure (e.g. disk full) — NOT the project's code.
    WorkerEnvironment,
    /// A genuine product compile failure proven by compiler diagnostics.
    ProductCompile,
    /// Neither signal present — cannot attribute.
    Indeterminate,
}

impl ExecFailureClass {
    /// Stable lowercase token.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            ExecFailureClass::WorkerEnvironment => "worker_environment",
            ExecFailureClass::ProductCompile => "product_compile",
            ExecFailureClass::Indeterminate => "indeterminate",
        }
    }
}

/// Whether `stderr` mentions an out-of-space / quota condition.
#[must_use]
pub fn mentions_disk_full(stderr: &str) -> bool {
    let s = stderr.to_ascii_lowercase();
    s.contains("no space left on device")
        || s.contains("enospc")
        || s.contains("disk quota exceeded")
}

/// Whether `stderr` carries a genuine rustc/cargo *compiler* diagnostic — a
/// coded error (`error[E0001]`), the abort tail, or "could not compile … due
/// to". Deliberately NOT a bare `error:` line, because a disk-write failure
/// prints `error: failed to write … No space left on device`, which is an
/// environment failure, not a compile error.
#[must_use]
pub fn mentions_compiler_diagnostic(stderr: &str) -> bool {
    let s = stderr.to_ascii_lowercase();
    // `error[E0XXX]` coded diagnostic.
    if let Some(idx) = s.find("error[e") {
        let rest = &s[idx + "error[e".len()..];
        if rest.chars().next().is_some_and(|c| c.is_ascii_digit()) {
            return true;
        }
    }
    s.contains("aborting due to") || s.contains("could not compile")
}

/// Classify a failed execution's stderr. An out-of-space condition defaults to
/// [`ExecFailureClass::WorkerEnvironment`] unless real compiler diagnostics
/// prove the build genuinely failed to compile.
#[must_use]
pub fn classify_exec_failure(stderr: &str) -> ExecFailureClass {
    let disk_full = mentions_disk_full(stderr);
    let compiler = mentions_compiler_diagnostic(stderr);
    match (disk_full, compiler) {
        // ENOSPC + real compiler diagnostics: the diagnostics prove otherwise.
        (true, true) => ExecFailureClass::ProductCompile,
        // ENOSPC with no compiler diagnostics: worker/environment failure.
        (true, false) => ExecFailureClass::WorkerEnvironment,
        // No disk issue, real diagnostics: a product compile failure.
        (false, true) => ExecFailureClass::ProductCompile,
        // Neither signal: cannot attribute.
        (false, false) => ExecFailureClass::Indeterminate,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts(path: &str, total: u64, avail: u64, inodes: u64) -> DiskRootFacts {
        DiskRootFacts {
            path: path.to_string(),
            total_bytes: total,
            available_bytes: avail,
            available_inodes: inodes,
        }
    }

    fn th() -> PressureThresholds {
        PressureThresholds::default()
    }

    // --- Pressure levels per dimension --------------------------------------

    #[test]
    fn critical_pressure_when_bytes_nearly_full() {
        // 2% available <= 5% critical threshold.
        let r = assess_root(
            DiskRootKind::TargetRoot,
            Some(&facts("/tmp/rch", 100_000_000, 2_000_000, 5_000_000)),
            &th(),
        );
        assert_eq!(r.bytes, PressureLevel::Critical);
        assert_eq!(r.worst(), PressureLevel::Critical);
    }

    #[test]
    fn warning_pressure_in_the_warning_band() {
        // 10% available: below 15% warning, above 5% critical.
        let r = assess_root(
            DiskRootKind::CargoHome,
            Some(&facts("/home/rch/.cargo", 100, 10, 5_000_000)),
            &th(),
        );
        assert_eq!(r.bytes, PressureLevel::Warning);
    }

    #[test]
    fn ok_pressure_with_headroom() {
        let r = assess_root(
            DiskRootKind::SyncRoot,
            Some(&facts("/tmp/rch/sync", 100, 80, 5_000_000)),
            &th(),
        );
        assert_eq!(r.worst(), PressureLevel::Ok);
    }

    #[test]
    fn missing_disk_metrics_are_unknown_not_ok() {
        let r = assess_root(DiskRootKind::TargetRoot, None, &th());
        assert_eq!(r.bytes, PressureLevel::Unknown);
        assert_eq!(r.inodes, PressureLevel::Unknown);
        assert!(r.available_bytes.is_none());
        // A zero-total df line is equally unassessable.
        let z = assess_root(
            DiskRootKind::TargetRoot,
            Some(&facts("/x/y", 0, 0, 0)),
            &th(),
        );
        assert_eq!(z.bytes, PressureLevel::Unknown);
    }

    #[test]
    fn target_root_inode_exhaustion_is_critical() {
        // Plenty of bytes, but no inodes left.
        let r = assess_root(
            DiskRootKind::TargetRoot,
            Some(&facts("/tmp/rch", 100_000, 90_000, 0)),
            &th(),
        );
        assert_eq!(r.bytes, PressureLevel::Ok);
        assert_eq!(r.inodes, PressureLevel::Critical);
        assert_eq!(r.worst(), PressureLevel::Critical);
    }

    #[test]
    fn log_pressure_drives_worker_worst() {
        let report = WorkerDiskPressureReport {
            worker_id: "css".to_string(),
            telemetry: FreshnessVerdict::Fresh,
            roots: vec![
                assess_root(
                    DiskRootKind::TargetRoot,
                    Some(&facts("/tmp/rch", 100, 90, 5_000_000)),
                    &th(),
                ),
                assess_root(
                    DiskRootKind::Log,
                    Some(&facts("/var/log/rch", 100, 3, 5_000_000)),
                    &th(),
                ),
            ],
        };
        assert!(report.has_critical());
        assert_eq!(report.worst(), PressureLevel::Critical);
    }

    // --- Telemetry gap ------------------------------------------------------

    #[test]
    fn telemetry_gap_caps_confidence_at_unknown() {
        // All roots Ok, but the telemetry is stale: the report must not read Ok.
        let report = WorkerDiskPressureReport {
            worker_id: "bil".to_string(),
            telemetry: FreshnessVerdict::Stale,
            roots: vec![assess_root(
                DiskRootKind::TargetRoot,
                Some(&facts("/tmp/rch", 100, 90, 5_000_000)),
                &th(),
            )],
        };
        assert_eq!(report.worst(), PressureLevel::Unknown);
        // A genuine critical still wins over the telemetry-gap floor.
        let crit = WorkerDiskPressureReport {
            worker_id: "bil".to_string(),
            telemetry: FreshnessVerdict::Unknown,
            roots: vec![assess_root(
                DiskRootKind::TargetRoot,
                Some(&facts("/tmp/rch", 100, 1, 5_000_000)),
                &th(),
            )],
        };
        assert_eq!(crit.worst(), PressureLevel::Critical);
    }

    // --- Worker filesystem error vs product compile failure -----------------

    #[test]
    fn enospc_without_compiler_diagnostics_is_worker_environment() {
        let stderr = "error: failed to write to `/tmp/rch/target/x.o`: No space left on device";
        assert_eq!(
            classify_exec_failure(stderr),
            ExecFailureClass::WorkerEnvironment,
            "a disk-write failure is not the project failing to compile"
        );
    }

    #[test]
    fn enospc_with_real_compiler_diagnostics_is_product_compile() {
        // Real rustc coded diagnostic proves the code genuinely failed to compile.
        let stderr =
            "error[E0308]: mismatched types\n  --> src/lib.rs:1:1\nNo space left on device";
        assert_eq!(
            classify_exec_failure(stderr),
            ExecFailureClass::ProductCompile
        );
    }

    #[test]
    fn real_compile_error_alone_is_product_compile() {
        let stderr = "error[E0425]: cannot find value `x`\nerror: aborting due to 1 previous error";
        assert_eq!(
            classify_exec_failure(stderr),
            ExecFailureClass::ProductCompile
        );
        assert!(mentions_compiler_diagnostic(stderr));
    }

    #[test]
    fn could_not_compile_tail_counts_as_diagnostic() {
        assert!(mentions_compiler_diagnostic(
            "error: could not compile `acme` due to 2 previous errors"
        ));
    }

    #[test]
    fn neither_signal_is_indeterminate() {
        assert_eq!(
            classify_exec_failure("connection reset by peer"),
            ExecFailureClass::Indeterminate
        );
    }

    #[test]
    fn bare_error_line_is_not_a_compiler_diagnostic() {
        // `error:` without a code/abort tail must not be mistaken for a compile
        // diagnostic — otherwise ENOSPC's "error: failed to write" would be
        // misclassified as a product compile failure.
        assert!(!mentions_compiler_diagnostic(
            "error: failed to write output: No space left on device"
        ));
    }

    // --- Serde / contract ---------------------------------------------------

    #[test]
    fn report_serializes_with_stable_tokens() {
        let report = WorkerDiskPressureReport {
            worker_id: "css".to_string(),
            telemetry: FreshnessVerdict::Fresh,
            roots: vec![assess_root(
                DiskRootKind::TargetRoot,
                Some(&facts("/tmp/rch", 100, 1, 0)),
                &th(),
            )],
        };
        let value = serde_json::to_value(&report).unwrap();
        assert_eq!(value["roots"][0]["kind"], "target_root");
        assert_eq!(value["roots"][0]["bytes"], "critical");
        assert_eq!(value["roots"][0]["inodes"], "critical");
        let back: WorkerDiskPressureReport = serde_json::from_value(value).unwrap();
        assert_eq!(back, report);
    }

    #[test]
    fn pressure_level_worse_aggregation() {
        assert_eq!(
            PressureLevel::Ok.worse(PressureLevel::Warning),
            PressureLevel::Warning
        );
        assert_eq!(
            PressureLevel::Critical.worse(PressureLevel::Unknown),
            PressureLevel::Critical
        );
        assert_eq!(
            PressureLevel::Ok.worse(PressureLevel::Unknown),
            PressureLevel::Unknown
        );
    }
}
