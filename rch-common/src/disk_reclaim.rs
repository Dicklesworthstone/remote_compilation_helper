//! Safe disk-reclaim receipts with active-build protection
//! (bd-session-history-remediation-ocv9i.11.3).
//!
//! Under disk pressure RCH may reclaim space, but session history showed the
//! danger of an over-eager reaper: clipping a live build's target dir, or
//! deleting something outside RCH's own roots. This module makes reclaim
//! **receipt-driven** — every candidate gets an explicit, auditable decision
//! before anything is deleted — and bakes in two hard safety invariants:
//!
//! 1. **Managed-root bounding.** Reclaim is only ever planned inside an
//!    RCH-managed root, and only for paths that pass the shared safe-path guard
//!    ([`crate::stale_target_reap::is_safe_reap_path`]). An unmanaged or unsafe
//!    path is recorded as skipped, never reclaimed.
//! 2. **Active-build protection.** A path covered by an active build/heartbeat
//!    is protected and never reclaimed — even under critical pressure.
//!
//! [`plan_reclaim`] is a **pure** function over candidate facts and a
//! [`ReclaimPolicy`]; it produces a [`ReclaimReceipt`] listing every per-path
//! decision, the planned bytes/inodes, and the protected/unmanaged sets. The
//! daemon performs the actual deletion and calls [`ReclaimReceipt::finalize`]
//! with the measured bytes/inodes, then journals the receipt as an
//! [`IncidentEvent`] via [`ReclaimReceipt::to_incident_event`]. The safety
//! invariants are provable here without touching the filesystem.

use serde::{Deserialize, Serialize};

use crate::incident::{
    ControlState, IncidentEvent, IncidentEventType, IncidentReasonCode, IncidentSource,
    SelectedMode,
};
use crate::stale_target_reap::{idle_minutes_from_hours, is_safe_reap_path};

/// What kind of reclaimable thing a candidate is. Distinguishing these lets the
/// receipt explain *what* was freed and keep operator-only cleanup separate from
/// automatic reclaim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReclaimCategory {
    /// A stale per-job/pooled Rust target dir.
    StaleTargetDir,
    /// A stale cargo home (registry/cache) RCH provisioned.
    StaleCargoHome,
    /// A rotatable RCH log file/dir.
    LogRotation,
    /// Cleanup that requires an operator decision; never auto-reclaimed.
    OperatorRequiredManual,
}

impl ReclaimCategory {
    /// Stable lowercase token.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            ReclaimCategory::StaleTargetDir => "stale_target_dir",
            ReclaimCategory::StaleCargoHome => "stale_cargo_home",
            ReclaimCategory::LogRotation => "log_rotation",
            ReclaimCategory::OperatorRequiredManual => "operator_required_manual",
        }
    }
}

/// Why a candidate was NOT reclaimed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReclaimSkipReason {
    /// Protected: an active build/heartbeat covers this path.
    ActiveBuild,
    /// Outside every RCH-managed root — must never be touched.
    UnmanagedRoot,
    /// Failed the safe-path guard (root, `..`, shell metacharacters, …).
    UnsafePath,
    /// Within the conservative idle window — a warm cache to preserve.
    NotStale,
    /// Requires manual operator cleanup; surfaced but not auto-reclaimed.
    OperatorRequired,
}

impl ReclaimSkipReason {
    /// Stable lowercase token.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            ReclaimSkipReason::ActiveBuild => "active_build",
            ReclaimSkipReason::UnmanagedRoot => "unmanaged_root",
            ReclaimSkipReason::UnsafePath => "unsafe_path",
            ReclaimSkipReason::NotStale => "not_stale",
            ReclaimSkipReason::OperatorRequired => "operator_required",
        }
    }
}

/// The decision for one candidate path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "decision")]
pub enum ReclaimDecision {
    /// Reclaim this path (counts toward planned bytes/inodes).
    Reclaim,
    /// Skip this path, with the reason.
    Skip { reason: ReclaimSkipReason },
}

impl ReclaimDecision {
    /// Whether this decision reclaims the path.
    #[must_use]
    pub fn is_reclaim(self) -> bool {
        matches!(self, ReclaimDecision::Reclaim)
    }
}

/// A reclaim candidate: facts about one path the caller is considering. Plain
/// data so the plan is pure and unit-testable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReclaimCandidate {
    /// Absolute path.
    pub path: String,
    /// What kind of thing it is.
    pub category: ReclaimCategory,
    /// Size on disk (bytes).
    pub bytes: u64,
    /// Inode count.
    pub inodes: u64,
    /// Minutes since the path last saw activity.
    pub idle_minutes: u64,
    /// An active build/heartbeat currently covers this path.
    pub active_build: bool,
}

/// Policy bounding what may be reclaimed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReclaimPolicy {
    /// RCH-managed roots; reclaim is only ever planned inside one of these.
    pub managed_roots: Vec<String>,
    /// Conservative idle window — paths idle for less are preserved.
    pub min_idle_minutes: u64,
}

impl ReclaimPolicy {
    /// Build a policy from managed roots and an `idle_hours` setting, applying
    /// the shared 1h floor so a misconfiguration can never reclaim a live cache.
    #[must_use]
    pub fn new(managed_roots: Vec<String>, idle_hours: u32) -> Self {
        Self {
            managed_roots,
            min_idle_minutes: idle_minutes_from_hours(idle_hours),
        }
    }

    /// Whether `path` lies within a managed root (exact root or a descendant).
    #[must_use]
    pub fn is_within_managed_root(&self, path: &str) -> bool {
        self.managed_roots.iter().any(|root| {
            let root = root.trim_end_matches('/');
            !root.is_empty() && (path == root || path.starts_with(&format!("{root}/")))
        })
    }
}

/// Decide a single candidate against the policy. Pure and total.
///
/// Precedence enforces safety outermost-first: the safe-path guard, then
/// managed-root bounding, then active-build protection (paramount — even under
/// critical pressure), then operator-required (reported, never auto-reclaimed),
/// then the conservative staleness window.
#[must_use]
pub fn decide_candidate(candidate: &ReclaimCandidate, policy: &ReclaimPolicy) -> ReclaimDecision {
    let skip = |reason| ReclaimDecision::Skip { reason };
    if !is_safe_reap_path(&candidate.path) {
        return skip(ReclaimSkipReason::UnsafePath);
    }
    if !policy.is_within_managed_root(&candidate.path) {
        return skip(ReclaimSkipReason::UnmanagedRoot);
    }
    if candidate.active_build {
        return skip(ReclaimSkipReason::ActiveBuild);
    }
    if candidate.category == ReclaimCategory::OperatorRequiredManual {
        return skip(ReclaimSkipReason::OperatorRequired);
    }
    if candidate.idle_minutes < policy.min_idle_minutes {
        return skip(ReclaimSkipReason::NotStale);
    }
    ReclaimDecision::Reclaim
}

/// The auditable decision for one path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathReceipt {
    pub path: String,
    pub category: ReclaimCategory,
    #[serde(flatten)]
    pub decision: ReclaimDecision,
    pub bytes: u64,
    pub inodes: u64,
}

/// The receipt for a planned (and later performed) reclaim pass.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReclaimReceipt {
    /// Managed roots reclaim was bounded to.
    pub managed_roots: Vec<String>,
    /// Conservative idle window used.
    pub min_idle_minutes: u64,
    /// Per-path decisions, in candidate order.
    pub paths: Vec<PathReceipt>,
    /// Sum of bytes for paths decided `Reclaim`.
    pub planned_bytes: u64,
    /// Sum of inodes for paths decided `Reclaim`.
    pub planned_inodes: u64,
    /// Bytes actually freed (filled by the daemon after deletion).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actual_bytes: Option<u64>,
    /// Inodes actually freed (filled by the daemon after deletion).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actual_inodes: Option<u64>,
}

impl ReclaimReceipt {
    /// Paths decided `Reclaim` — exactly what the daemon may delete.
    #[must_use]
    pub fn reclaimable_paths(&self) -> Vec<&str> {
        self.paths
            .iter()
            .filter(|p| p.decision.is_reclaim())
            .map(|p| p.path.as_str())
            .collect()
    }

    /// Paths skipped for a given reason (e.g. active build, unmanaged root).
    #[must_use]
    pub fn skipped_for(&self, reason: ReclaimSkipReason) -> Vec<&str> {
        self.paths
            .iter()
            .filter(|p| p.decision == ReclaimDecision::Skip { reason })
            .map(|p| p.path.as_str())
            .collect()
    }

    /// Paths protected because an active build covers them.
    #[must_use]
    pub fn protected_active(&self) -> Vec<&str> {
        self.skipped_for(ReclaimSkipReason::ActiveBuild)
    }

    /// Record the bytes/inodes actually freed after the daemon performed the
    /// reclaim.
    pub fn finalize(&mut self, actual_bytes: u64, actual_inodes: u64) {
        self.actual_bytes = Some(actual_bytes);
        self.actual_inodes = Some(actual_inodes);
    }

    /// A journal/incident record for this receipt, keyed `DiskFull`. Carries the
    /// salient accounting in `details` (no raw paths in the wire schema's
    /// fingerprint field — the command fingerprint identifies the pass).
    #[must_use]
    pub fn to_incident_event(
        &self,
        project_id: impl Into<String>,
        occurred_at_unix_ms: u64,
    ) -> IncidentEvent {
        let reclaimable = self.reclaimable_paths().len();
        let protected = self.protected_active().len();
        let unmanaged = self.skipped_for(ReclaimSkipReason::UnmanagedRoot).len();
        let mut event = IncidentEvent::new(
            IncidentEventType::WorkerLifecycle,
            IncidentReasonCode::DiskFull,
            IncidentSource::Daemon,
            project_id,
            "disk_reclaim",
            SelectedMode::Local,
            true,
            occurred_at_unix_ms,
        )
        .with_control(ControlState {
            target_dir_policy: Some("reclaim".to_string()),
            ..ControlState::default()
        })
        .with_detail("planned_bytes", self.planned_bytes.to_string())
        .with_detail("planned_inodes", self.planned_inodes.to_string())
        .with_detail("reclaimable", reclaimable.to_string())
        .with_detail("protected_active", protected.to_string())
        .with_detail("skipped_unmanaged", unmanaged.to_string());
        if let Some(actual) = self.actual_bytes {
            event = event.with_detail("actual_bytes", actual.to_string());
        }
        if let Some(actual) = self.actual_inodes {
            event = event.with_detail("actual_inodes", actual.to_string());
        }
        event
    }

    /// Human-readable summary line.
    #[must_use]
    pub fn render(&self) -> String {
        format!(
            "reclaim: {} path(s) reclaimable, {} planned bytes, {} protected (active), {} unmanaged-skipped",
            self.reclaimable_paths().len(),
            self.planned_bytes,
            self.protected_active().len(),
            self.skipped_for(ReclaimSkipReason::UnmanagedRoot).len(),
        )
    }
}

/// Plan a reclaim pass: decide every candidate and total the planned savings.
/// Pure — performs no I/O and deletes nothing.
#[must_use]
pub fn plan_reclaim(candidates: &[ReclaimCandidate], policy: &ReclaimPolicy) -> ReclaimReceipt {
    let mut paths = Vec::with_capacity(candidates.len());
    let mut planned_bytes = 0u64;
    let mut planned_inodes = 0u64;
    for candidate in candidates {
        let decision = decide_candidate(candidate, policy);
        if decision.is_reclaim() {
            planned_bytes = planned_bytes.saturating_add(candidate.bytes);
            planned_inodes = planned_inodes.saturating_add(candidate.inodes);
        }
        paths.push(PathReceipt {
            path: candidate.path.clone(),
            category: candidate.category,
            decision,
            bytes: candidate.bytes,
            inodes: candidate.inodes,
        });
    }
    ReclaimReceipt {
        managed_roots: policy.managed_roots.clone(),
        min_idle_minutes: policy.min_idle_minutes,
        paths,
        planned_bytes,
        planned_inodes,
        actual_bytes: None,
        actual_inodes: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> ReclaimPolicy {
        // 12h idle window, managed roots under /tmp/rch and /data/rch.
        ReclaimPolicy::new(
            vec!["/tmp/rch".to_string(), "/data/rch/pool".to_string()],
            12,
        )
    }

    fn candidate(path: &str, category: ReclaimCategory) -> ReclaimCandidate {
        ReclaimCandidate {
            path: path.to_string(),
            category,
            bytes: 1_000,
            inodes: 10,
            idle_minutes: 10_000, // very stale by default
            active_build: false,
        }
    }

    // --- The two safety invariants the bead requires proven -----------------

    #[test]
    fn no_active_build_path_is_reclaimed_even_under_critical_pressure() {
        // Aggressive policy (zero idle window = "critical pressure"): an active
        // build path is STILL protected.
        let aggressive = ReclaimPolicy {
            managed_roots: vec!["/tmp/rch".to_string()],
            min_idle_minutes: 0,
        };
        let mut c = candidate(
            "/tmp/rch/proj/.rch-target-w-job-1-2-0",
            ReclaimCategory::StaleTargetDir,
        );
        c.active_build = true;
        let receipt = plan_reclaim(&[c], &aggressive);
        assert!(
            receipt.reclaimable_paths().is_empty(),
            "active build must not be reclaimed"
        );
        assert_eq!(receipt.protected_active().len(), 1);
        assert_eq!(receipt.planned_bytes, 0);
    }

    #[test]
    fn no_unmanaged_path_is_touched() {
        // A stale, non-active path OUTSIDE managed roots is never reclaimed.
        let c = candidate("/home/user/project/target", ReclaimCategory::StaleTargetDir);
        let receipt = plan_reclaim(&[c], &policy());
        assert!(receipt.reclaimable_paths().is_empty());
        assert_eq!(
            receipt.skipped_for(ReclaimSkipReason::UnmanagedRoot).len(),
            1
        );
    }

    #[test]
    fn unsafe_paths_are_rejected_before_anything_else() {
        for bad in [
            "/tmp/rch/../etc/passwd",
            "/tmp/rch/$(whoami)",
            "/", // root
            "relative/path",
        ] {
            let c = candidate(bad, ReclaimCategory::StaleTargetDir);
            let receipt = plan_reclaim(&[c], &policy());
            assert!(
                receipt.reclaimable_paths().is_empty(),
                "unsafe path reclaimed: {bad}"
            );
            assert_eq!(
                receipt.skipped_for(ReclaimSkipReason::UnsafePath).len(),
                1,
                "expected unsafe-path skip for {bad}"
            );
        }
    }

    // --- Category distinction + conservative staleness ----------------------

    #[test]
    fn distinguishes_reclaimable_categories_from_operator_required() {
        let candidates = vec![
            candidate(
                "/tmp/rch/p/.rch-target-w-job-1-2-0",
                ReclaimCategory::StaleTargetDir,
            ),
            candidate("/tmp/rch/cargo-home-stale", ReclaimCategory::StaleCargoHome),
            candidate("/tmp/rch/logs/old", ReclaimCategory::LogRotation),
            candidate(
                "/tmp/rch/mystery-bigdir",
                ReclaimCategory::OperatorRequiredManual,
            ),
        ];
        let receipt = plan_reclaim(&candidates, &policy());
        // Three auto-reclaimable categories are planned; operator-required is not.
        assert_eq!(receipt.reclaimable_paths().len(), 3);
        assert_eq!(
            receipt
                .skipped_for(ReclaimSkipReason::OperatorRequired)
                .len(),
            1
        );
        assert_eq!(receipt.planned_bytes, 3_000);
        assert_eq!(receipt.planned_inodes, 30);
    }

    #[test]
    fn conservative_staleness_preserves_warm_caches() {
        // Within the idle window (managed, not active) => preserved as NotStale.
        let mut c = candidate(
            "/tmp/rch/p/.rch-target-w-job-1-2-0",
            ReclaimCategory::StaleTargetDir,
        );
        c.idle_minutes = 5; // far below 12h floor
        let receipt = plan_reclaim(&[c], &policy());
        assert!(receipt.reclaimable_paths().is_empty());
        assert_eq!(receipt.skipped_for(ReclaimSkipReason::NotStale).len(), 1);
    }

    #[test]
    fn idle_floor_is_applied_even_with_zero_hours_config() {
        // ReclaimPolicy::new applies the shared 1h floor, so a 0-hour config
        // still preserves a 30-min-idle cache.
        let p = ReclaimPolicy::new(vec!["/tmp/rch".to_string()], 0);
        assert_eq!(p.min_idle_minutes, 60);
        let mut c = candidate(
            "/tmp/rch/p/.rch-target-w-job-1-2-0",
            ReclaimCategory::StaleTargetDir,
        );
        c.idle_minutes = 30;
        let receipt = plan_reclaim(&[c], &p);
        assert!(receipt.reclaimable_paths().is_empty());
    }

    // --- Accounting, finalize, journal --------------------------------------

    #[test]
    fn planned_totals_count_only_reclaimable() {
        let candidates = vec![
            candidate(
                "/tmp/rch/p/.rch-target-w-job-1-2-0",
                ReclaimCategory::StaleTargetDir,
            ), // reclaim
            {
                let mut a = candidate(
                    "/tmp/rch/active/.rch-target-w-job-9-9-0",
                    ReclaimCategory::StaleTargetDir,
                );
                a.active_build = true; // skipped
                a.bytes = 9_999;
                a
            },
            candidate("/elsewhere/junk", ReclaimCategory::StaleTargetDir), // unmanaged
        ];
        let receipt = plan_reclaim(&candidates, &policy());
        assert_eq!(
            receipt.planned_bytes, 1_000,
            "only the one reclaimable path counts"
        );
    }

    #[test]
    fn finalize_records_actual_freed() {
        let c = candidate(
            "/tmp/rch/p/.rch-target-w-job-1-2-0",
            ReclaimCategory::StaleTargetDir,
        );
        let mut receipt = plan_reclaim(&[c], &policy());
        assert_eq!(receipt.actual_bytes, None);
        receipt.finalize(950, 9);
        assert_eq!(receipt.actual_bytes, Some(950));
        assert_eq!(receipt.actual_inodes, Some(9));
    }

    #[test]
    fn journal_event_is_diskfull_with_accounting() {
        let candidates = vec![
            candidate(
                "/tmp/rch/p/.rch-target-w-job-1-2-0",
                ReclaimCategory::StaleTargetDir,
            ),
            {
                let mut a = candidate(
                    "/tmp/rch/active/.rch-target-w-job-9-9-0",
                    ReclaimCategory::StaleTargetDir,
                );
                a.active_build = true;
                a
            },
        ];
        let mut receipt = plan_reclaim(&candidates, &policy());
        receipt.finalize(1_000, 10);
        let event = receipt.to_incident_event("proj-1", 1_700_000_000_000);
        assert_eq!(event.reason_code, IncidentReasonCode::DiskFull);
        assert_eq!(event.event_type, IncidentEventType::WorkerLifecycle);
        assert_eq!(
            event.details.get("planned_bytes").map(String::as_str),
            Some("1000")
        );
        assert_eq!(
            event.details.get("protected_active").map(String::as_str),
            Some("1")
        );
        assert_eq!(
            event.details.get("actual_bytes").map(String::as_str),
            Some("1000")
        );
    }

    // --- Serde / contract ---------------------------------------------------

    #[test]
    fn receipt_serializes_with_stable_decision_tokens() {
        let candidates = vec![
            candidate(
                "/tmp/rch/p/.rch-target-w-job-1-2-0",
                ReclaimCategory::StaleTargetDir,
            ),
            candidate("/elsewhere/x", ReclaimCategory::LogRotation),
        ];
        let receipt = plan_reclaim(&candidates, &policy());
        let value = serde_json::to_value(&receipt).unwrap();
        assert_eq!(value["paths"][0]["decision"], "reclaim");
        assert_eq!(value["paths"][0]["category"], "stale_target_dir");
        assert_eq!(value["paths"][1]["decision"], "skip");
        assert_eq!(value["paths"][1]["reason"], "unmanaged_root");
        // actual_* omitted before finalize.
        assert!(value.get("actual_bytes").is_none());
        // Round-trips losslessly.
        let back: ReclaimReceipt = serde_json::from_value(value).unwrap();
        assert_eq!(back, receipt);
    }

    #[test]
    fn managed_root_membership_is_boundary_safe() {
        let p = policy();
        assert!(p.is_within_managed_root("/tmp/rch"));
        assert!(p.is_within_managed_root("/tmp/rch/sub/dir"));
        // A sibling that merely shares a prefix string is NOT inside the root.
        assert!(!p.is_within_managed_root("/tmp/rch-evil/x"));
        assert!(!p.is_within_managed_root("/tmp/rchx"));
        assert!(!p.is_within_managed_root("/data/rch/poolside")); // not /data/rch/pool[/...]
        assert!(p.is_within_managed_root("/data/rch/pool/abc"));
    }
}
