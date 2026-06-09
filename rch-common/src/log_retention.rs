//! Daemon log rotation + doctor log-pressure reporting
//! (bd-session-history-remediation-ocv9i.14.3).
//!
//! RCH's own logs must never *become* the disk-pressure problem session history
//! was trying to diagnose. This module bounds `daemon.log` / `daemon.err` by
//! size with a fixed number of rotated generations, surfaces current log sizes
//! for `rch doctor`/status, and emits remediation guidance that respects the
//! project's no-destructive-command norms (it suggests the managed `rch` action,
//! never a raw `rm`).
//!
//! Two layers, both safe by construction:
//! - [`plan_log_rotation`] is a **pure** decision over a directory listing: it
//!   classifies each entry as a managed active log, a managed rotated
//!   generation, or an **unmanaged** file that must never be touched, and
//!   decides Keep / Rotate / Prune accordingly.
//! - [`rotate_logs`] performs that plan against a real directory using only
//!   renames/removals of files RCH owns (`daemon.log`, `daemon.err`, and their
//!   `*.N` generations) — an unmanaged file in the same dir is reported but
//!   never moved or deleted.
//!
//! [`assess_log_pressure`] folds the directory's managed total into a
//! [`PressureLevel`] for the doctor surface, with [`log_remediation_guidance`]
//! producing norm-respecting advice.

use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::disk_pressure_report::PressureLevel;

/// The active daemon log basenames RCH owns and rotates.
pub const MANAGED_LOG_NAMES: &[&str] = &["daemon.log", "daemon.err"];

/// Size/retention policy for the managed daemon logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LogRetentionPolicy {
    /// Rotate an active log once it exceeds this many bytes.
    pub max_file_bytes: u64,
    /// Rotated generations to retain per log (oldest beyond this are pruned).
    pub keep_rotated: usize,
    /// Managed total (active + rotated) at/above which pressure is `Warning`.
    pub warn_total_bytes: u64,
    /// Managed total at/above which pressure is `Critical`.
    pub critical_total_bytes: u64,
}

impl Default for LogRetentionPolicy {
    fn default() -> Self {
        Self {
            max_file_bytes: 16 * 1024 * 1024, // 16 MiB per active log
            keep_rotated: 3,
            warn_total_bytes: 64 * 1024 * 1024, // 64 MiB of logs
            critical_total_bytes: 256 * 1024 * 1024, // 256 MiB of logs
        }
    }
}

/// Whether `name` is one of the managed active log basenames.
#[must_use]
pub fn is_managed_active_log(name: &str) -> bool {
    MANAGED_LOG_NAMES.contains(&name)
}

/// If `name` is a rotated generation of a managed log (`daemon.log.2`), return
/// `(base, generation)`. Generation is a positive integer.
#[must_use]
pub fn managed_rotated_generation(name: &str) -> Option<(&'static str, usize)> {
    for base in MANAGED_LOG_NAMES {
        if let Some(suffix) = name.strip_prefix(&format!("{base}.")) {
            // Suffix must be a bare positive integer (no `.gz`, no extra dots).
            if let Ok(generation) = suffix.parse::<usize>()
                && generation >= 1
            {
                return Some((base, generation));
            }
        }
    }
    None
}

/// The action planned for one directory entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogAction {
    /// A managed file within retention — leave it.
    Keep,
    /// A managed active log over the size limit — rotate it.
    Rotate,
    /// A managed rotated generation beyond `keep_rotated` — prune it.
    Prune,
    /// Not an RCH-managed log — report only; never touch.
    SkipUnmanaged,
}

impl LogAction {
    /// Stable lowercase token.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            LogAction::Keep => "keep",
            LogAction::Rotate => "rotate",
            LogAction::Prune => "prune",
            LogAction::SkipUnmanaged => "skip_unmanaged",
        }
    }
}

/// One directory entry the planner/rotator considered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogFile {
    pub name: String,
    pub bytes: u64,
}

/// The per-entry plan for a directory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogFileDecision {
    pub name: String,
    pub bytes: u64,
    pub action: LogAction,
}

/// The result of planning a directory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogRotationPlan {
    pub decisions: Vec<LogFileDecision>,
    /// Total bytes of managed logs (active + rotated).
    pub managed_total_bytes: u64,
    /// Total bytes of unmanaged files seen (reported, untouched).
    pub unmanaged_total_bytes: u64,
}

impl LogRotationPlan {
    /// Names decided for a given action.
    #[must_use]
    pub fn names_for(&self, action: LogAction) -> Vec<&str> {
        self.decisions
            .iter()
            .filter(|d| d.action == action)
            .map(|d| d.name.as_str())
            .collect()
    }
}

/// Plan rotation for a directory listing. Pure — no I/O. Classifies every entry
/// and decides Keep/Rotate/Prune/SkipUnmanaged. Unmanaged files are never
/// actioned (only reported), and managed rotated generations beyond
/// `keep_rotated` are pruned (oldest = highest generation).
#[must_use]
pub fn plan_log_rotation(files: &[LogFile], policy: &LogRetentionPolicy) -> LogRotationPlan {
    let mut decisions = Vec::with_capacity(files.len());
    let mut managed_total_bytes = 0u64;
    let mut unmanaged_total_bytes = 0u64;

    for file in files {
        let action = if is_managed_active_log(&file.name) {
            managed_total_bytes = managed_total_bytes.saturating_add(file.bytes);
            if file.bytes > policy.max_file_bytes {
                LogAction::Rotate
            } else {
                LogAction::Keep
            }
        } else if let Some((_, generation)) = managed_rotated_generation(&file.name) {
            managed_total_bytes = managed_total_bytes.saturating_add(file.bytes);
            // After a rotation the active becomes `.1`, so a generation strictly
            // greater than keep_rotated will fall off — prune it now.
            if generation > policy.keep_rotated {
                LogAction::Prune
            } else {
                LogAction::Keep
            }
        } else {
            unmanaged_total_bytes = unmanaged_total_bytes.saturating_add(file.bytes);
            LogAction::SkipUnmanaged
        };
        decisions.push(LogFileDecision {
            name: file.name.clone(),
            bytes: file.bytes,
            action,
        });
    }

    LogRotationPlan {
        decisions,
        managed_total_bytes,
        unmanaged_total_bytes,
    }
}

/// What a real rotation pass did.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogRotationReceipt {
    /// Active logs that were rotated (active -> `.1`, generations shifted up).
    pub rotated: Vec<String>,
    /// Rotated generations pruned (beyond `keep_rotated`).
    pub pruned: Vec<String>,
    /// Unmanaged files seen and deliberately left untouched.
    pub skipped_unmanaged: Vec<String>,
    /// Bytes reclaimed by pruning old generations.
    pub pruned_bytes: u64,
}

/// Rotate the managed logs in `dir` per `policy`, doing real filesystem work but
/// touching only RCH-owned files. For each active log over the size limit:
/// existing generations shift up (`daemon.log.1` -> `.2`, …), generations past
/// `keep_rotated` are removed, the active log becomes `.1`, and a fresh empty
/// active log is recreated. Unmanaged files are reported but never moved or
/// deleted.
///
/// Errors are surfaced (not swallowed) so the daemon can log-and-continue; a
/// best-effort caller should treat failure as "rotation deferred", never as a
/// reason to delete anything by hand.
pub fn rotate_logs(dir: &Path, policy: &LogRetentionPolicy) -> std::io::Result<LogRotationReceipt> {
    let mut receipt = LogRotationReceipt::default();

    // Snapshot the directory once.
    let mut entries: Vec<(String, u64)> = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        let bytes = entry.metadata().map(|m| m.len()).unwrap_or(0);
        entries.push((name, bytes));
    }

    // Record unmanaged files (never touched).
    for (name, _) in &entries {
        if !is_managed_active_log(name) && managed_rotated_generation(name).is_none() {
            receipt.skipped_unmanaged.push(name.clone());
        }
    }

    for base in MANAGED_LOG_NAMES {
        let active = dir.join(base);
        let over_limit = entries
            .iter()
            .find(|(n, _)| n == base)
            .is_some_and(|(_, b)| *b > policy.max_file_bytes);
        if !over_limit {
            continue;
        }

        // Prune the oldest generation that would fall off, then shift up.
        let oldest = dir.join(format!("{base}.{}", policy.keep_rotated));
        if let Ok(meta) = fs::metadata(&oldest) {
            receipt.pruned_bytes = receipt.pruned_bytes.saturating_add(meta.len());
            fs::remove_file(&oldest)?;
            receipt
                .pruned
                .push(format!("{base}.{}", policy.keep_rotated));
        }
        // Shift remaining generations up: .(N-1) -> .N, down to .1 -> .2.
        for generation in (1..policy.keep_rotated).rev() {
            let from = dir.join(format!("{base}.{generation}"));
            if from.exists() {
                fs::rename(&from, dir.join(format!("{base}.{}", generation + 1)))?;
            }
        }
        // Active -> .1, then recreate an empty active log.
        fs::rename(&active, dir.join(format!("{base}.1")))?;
        fs::File::create(&active)?;
        receipt.rotated.push((*base).to_string());
    }

    Ok(receipt)
}

/// Fold a managed-log total into a doctor pressure level.
#[must_use]
pub fn assess_log_pressure(managed_total_bytes: u64, policy: &LogRetentionPolicy) -> PressureLevel {
    if managed_total_bytes >= policy.critical_total_bytes {
        PressureLevel::Critical
    } else if managed_total_bytes >= policy.warn_total_bytes {
        PressureLevel::Warning
    } else {
        PressureLevel::Ok
    }
}

/// Norm-respecting remediation guidance for a log-pressure level. Never suggests
/// a destructive raw command; points at the managed rotation path instead.
#[must_use]
pub fn log_remediation_guidance(level: PressureLevel) -> &'static str {
    match level {
        PressureLevel::Ok => "log sizes are within retention limits; no action needed",
        PressureLevel::Warning => {
            "daemon logs are growing; rotation will bound them on the next daemon cycle (managed, non-destructive)"
        }
        PressureLevel::Critical => {
            "daemon logs are large; rotation will reclaim space on the next cycle. Do NOT delete log files by hand — RCH rotates only its own daemon.log/daemon.err generations"
        }
        PressureLevel::Unknown => {
            "log sizes could not be determined; check the daemon log directory path"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn small_policy() -> LogRetentionPolicy {
        LogRetentionPolicy {
            max_file_bytes: 100,
            keep_rotated: 2,
            warn_total_bytes: 500,
            critical_total_bytes: 1_000,
        }
    }

    // --- Pure plan ----------------------------------------------------------

    #[test]
    fn rotate_by_size_only_when_over_limit() {
        let files = vec![
            LogFile {
                name: "daemon.log".into(),
                bytes: 150,
            }, // over 100 -> rotate
            LogFile {
                name: "daemon.err".into(),
                bytes: 50,
            }, // under -> keep
        ];
        let plan = plan_log_rotation(&files, &small_policy());
        assert_eq!(plan.names_for(LogAction::Rotate), vec!["daemon.log"]);
        assert_eq!(plan.names_for(LogAction::Keep), vec!["daemon.err"]);
    }

    #[test]
    fn preserve_recent_generations_prune_old() {
        let files = vec![
            LogFile {
                name: "daemon.log.1".into(),
                bytes: 10,
            }, // keep (<= keep_rotated=2)
            LogFile {
                name: "daemon.log.2".into(),
                bytes: 10,
            }, // keep
            LogFile {
                name: "daemon.log.3".into(),
                bytes: 10,
            }, // prune (>2)
        ];
        let plan = plan_log_rotation(&files, &small_policy());
        assert_eq!(
            plan.names_for(LogAction::Keep),
            vec!["daemon.log.1", "daemon.log.2"]
        );
        assert_eq!(plan.names_for(LogAction::Prune), vec!["daemon.log.3"]);
    }

    #[test]
    fn unmanaged_files_are_reported_never_actioned() {
        let files = vec![
            LogFile {
                name: "daemon.log".into(),
                bytes: 999,
            }, // managed, rotate
            LogFile {
                name: "someone_elses.log".into(),
                bytes: 999,
            },
            LogFile {
                name: "notes.txt".into(),
                bytes: 10,
            },
        ];
        let plan = plan_log_rotation(&files, &small_policy());
        let unmanaged = plan.names_for(LogAction::SkipUnmanaged);
        assert!(unmanaged.contains(&"someone_elses.log"));
        assert!(unmanaged.contains(&"notes.txt"));
        assert_eq!(plan.unmanaged_total_bytes, 1_009);
        // Unmanaged never appears in rotate/prune.
        assert!(!plan.names_for(LogAction::Rotate).contains(&"notes.txt"));
        assert!(
            !plan
                .names_for(LogAction::Prune)
                .contains(&"someone_elses.log")
        );
    }

    #[test]
    fn managed_classification_rules() {
        assert!(is_managed_active_log("daemon.log"));
        assert!(is_managed_active_log("daemon.err"));
        assert!(!is_managed_active_log("daemon.log.1"));
        assert_eq!(
            managed_rotated_generation("daemon.err.2"),
            Some(("daemon.err", 2))
        );
        assert_eq!(
            managed_rotated_generation("daemon.log.1"),
            Some(("daemon.log", 1))
        );
        // Not a bare integer generation => unmanaged.
        assert_eq!(managed_rotated_generation("daemon.log.1.gz"), None);
        assert_eq!(managed_rotated_generation("daemon.log.old"), None);
        assert_eq!(managed_rotated_generation("other.log.1"), None);
    }

    // --- Real filesystem rotation ------------------------------------------

    fn write_file(dir: &Path, name: &str, bytes: usize) {
        let mut f = fs::File::create(dir.join(name)).unwrap();
        f.write_all(&vec![b'x'; bytes]).unwrap();
    }

    #[test]
    fn rotate_logs_shifts_generations_and_preserves_recent() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path();
        write_file(p, "daemon.log", 200); // over 100 -> rotate
        write_file(p, "daemon.log.1", 10); // -> .2
        write_file(p, "daemon.log.2", 10); // -> would be .3, pruned (keep_rotated=2)
        write_file(p, "daemon.err", 10); // under -> untouched

        let receipt = rotate_logs(p, &small_policy()).unwrap();
        assert_eq!(receipt.rotated, vec!["daemon.log"]);
        assert!(receipt.pruned.contains(&"daemon.log.2".to_string()));

        // Active recreated empty; .1 is the just-rotated 200-byte log; .2 is the
        // previous .1; .3 must NOT exist (pruned/never created beyond keep).
        assert_eq!(fs::metadata(p.join("daemon.log")).unwrap().len(), 0);
        assert_eq!(fs::metadata(p.join("daemon.log.1")).unwrap().len(), 200);
        assert_eq!(fs::metadata(p.join("daemon.log.2")).unwrap().len(), 10);
        assert!(!p.join("daemon.log.3").exists());
        // daemon.err under the limit was left alone.
        assert_eq!(fs::metadata(p.join("daemon.err")).unwrap().len(), 10);
    }

    #[test]
    fn rotate_logs_never_touches_unmanaged_files() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path();
        write_file(p, "daemon.log", 200);
        write_file(p, "important_unmanaged.db", 999);
        write_file(p, "user_notes.txt", 5);

        let receipt = rotate_logs(p, &small_policy()).unwrap();
        // Unmanaged files reported and still present, unchanged.
        assert!(
            receipt
                .skipped_unmanaged
                .contains(&"important_unmanaged.db".to_string())
        );
        assert!(
            receipt
                .skipped_unmanaged
                .contains(&"user_notes.txt".to_string())
        );
        assert_eq!(
            fs::metadata(p.join("important_unmanaged.db"))
                .unwrap()
                .len(),
            999
        );
        assert_eq!(fs::metadata(p.join("user_notes.txt")).unwrap().len(), 5);
    }

    #[test]
    fn rotate_logs_noop_when_under_limit() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path();
        write_file(p, "daemon.log", 10);
        let receipt = rotate_logs(p, &small_policy()).unwrap();
        assert!(receipt.rotated.is_empty());
        assert!(!p.join("daemon.log.1").exists());
    }

    // --- Pressure + guidance ------------------------------------------------

    #[test]
    fn log_pressure_levels() {
        let p = small_policy();
        assert_eq!(assess_log_pressure(100, &p), PressureLevel::Ok);
        assert_eq!(assess_log_pressure(600, &p), PressureLevel::Warning);
        assert_eq!(assess_log_pressure(2_000, &p), PressureLevel::Critical);
    }

    #[test]
    fn guidance_never_suggests_destructive_commands() {
        for level in [
            PressureLevel::Ok,
            PressureLevel::Warning,
            PressureLevel::Critical,
            PressureLevel::Unknown,
        ] {
            let g = log_remediation_guidance(level);
            assert!(!g.contains("rm "), "guidance must not suggest rm: {g}");
            assert!(!g.contains("rm -rf"));
        }
        assert!(log_remediation_guidance(PressureLevel::Critical).contains("Do NOT delete"));
    }

    #[test]
    fn plan_serializes_with_stable_tokens() {
        let files = vec![LogFile {
            name: "daemon.log".into(),
            bytes: 200,
        }];
        let plan = plan_log_rotation(&files, &small_policy());
        let value = serde_json::to_value(&plan).unwrap();
        assert_eq!(value["decisions"][0]["action"], "rotate");
        let back: LogRotationPlan = serde_json::from_value(value).unwrap();
        assert_eq!(back, plan);
    }
}
