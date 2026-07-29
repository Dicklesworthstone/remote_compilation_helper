//! Fleet status report: desired/live grouping + dominant-problem summary +
//! absence alerts (bd-session-history-remediation-ocv9i.2.2).
//!
//! [`crate::fleet_diff`] already classifies each worker into a
//! [`WorkerDiffState`] and explains a capacity collapse in one line. This module
//! adds the two pieces `rch status --fleet` needs on top of that grouping:
//!
//! 1. A **dominant problem class** ([`FleetProblemClass`]) — a single label that
//!    answers "is this fleet problem cloud disappearance, local overload, disk
//!    pressure, missing capability, admin intent, or daemon/config drift?", so an
//!    operator gets the *category* of failure, not just per-worker rows.
//! 2. **Absence alerts** — workers absent from live eligibility longer than a
//!    policy window, surfaced as threshold-based warnings.
//!
//! Both are pure functions of [`FleetWorkerSignal`] inputs (the per-worker
//! observation plus a few extra signals), so the whole report is deterministic
//! and golden-testable; the CLI gathers the signals from config + daemon status
//! + the bypass store and renders the result.

use serde::{Deserialize, Serialize};

use crate::fleet_diff::{
    FleetDiff, WorkerDiffState, WorkerObservation, build_fleet_diff, derive_worker_diff,
};

/// Default policy window after which a worker absent from live eligibility is
/// flagged (5 minutes).
pub const DEFAULT_ABSENCE_THRESHOLD_SECS: u64 = 300;

/// The dominant class of fleet problem, for a one-line operator summary.
///
/// When the fleet is usable this is [`FleetProblemClass::Healthy`]; otherwise it
/// names the single category that best explains why capacity is constrained.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FleetProblemClass {
    /// At least one worker is ready with spare capacity.
    Healthy,
    /// Workers configured but missing/unreachable — the cloud hosts vanished.
    CloudDisappearance,
    /// Ready workers exist but all are at full slot capacity — overload, not absence.
    LocalOverload,
    /// Workers quarantined or critical because of disk/inode pressure.
    DiskPressure,
    /// Workers in the pool but lacking trustworthy capability facts or
    /// admissibility for the work.
    MissingCapability,
    /// Workers explicitly admin-disabled — operator intent, not a fault.
    AdminIntent,
    /// Config and the daemon pool disagree (recovered-not-rejoined / orphan).
    DaemonConfigDrift,
}

impl FleetProblemClass {
    /// Stable lowercase token (matches the serde form).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::CloudDisappearance => "cloud_disappearance",
            Self::LocalOverload => "local_overload",
            Self::DiskPressure => "disk_pressure",
            Self::MissingCapability => "missing_capability",
            Self::AdminIntent => "admin_intent",
            Self::DaemonConfigDrift => "daemon_config_drift",
        }
    }

    /// Operator-facing label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::CloudDisappearance => "cloud disappearance (hosts missing/unreachable)",
            Self::LocalOverload => "overload (all ready workers at capacity)",
            Self::DiskPressure => "disk/inode pressure",
            Self::MissingCapability => "missing capability / not admissible",
            Self::AdminIntent => "admin intent (operator-disabled)",
            Self::DaemonConfigDrift => "daemon/config drift",
        }
    }
}

/// Per-worker signals beyond the desired/live diff, used to classify the
/// dominant fleet problem and raise absence alerts. Plain data so the
/// classification stays pure and unit-testable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FleetWorkerSignal {
    /// The desired/live observation (drives the [`WorkerDiffState`]).
    pub observation: WorkerObservation,
    /// Worker is under warning/critical disk (or inode) pressure.
    pub disk_pressure: bool,
    /// Worker is usable but has no free slots (drives overload classification).
    pub slots_saturated: bool,
    /// Seconds the worker has been absent from live eligibility, if known
    /// (e.g. from the age of its offline alert). Drives absence alerts.
    pub absent_secs: Option<u64>,
}

impl FleetWorkerSignal {
    /// A signal carrying just an observation, with no extra pressure/absence
    /// information.
    #[must_use]
    pub fn from_observation(observation: WorkerObservation) -> Self {
        Self {
            observation,
            disk_pressure: false,
            slots_saturated: false,
            absent_secs: None,
        }
    }
}

/// A worker absent from live eligibility longer than the policy window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AbsenceAlert {
    /// Worker id.
    pub worker_id: String,
    /// Why it is out of play.
    pub state: WorkerDiffState,
    /// How long it has been absent, in seconds.
    pub absent_secs: u64,
    /// The policy window it exceeded, in seconds.
    pub threshold_secs: u64,
}

/// Whole-fleet status: the desired/live grouping diff plus the dominant problem
/// class and any absence alerts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetStatusReport {
    /// Per-worker grouping + counts + capacity-collapse explanation.
    pub diff: FleetDiff,
    /// The single category that best explains the fleet's state.
    pub problem_class: FleetProblemClass,
    /// One-line human summary of the dominant problem.
    pub problem_summary: String,
    /// Workers absent from live eligibility longer than the policy window,
    /// newest-absence... longest-absence first.
    pub absence_alerts: Vec<AbsenceAlert>,
    /// The policy window used for absence alerts, in seconds.
    pub absence_threshold_secs: u64,
}

impl FleetStatusReport {
    /// Whether any worker tripped the absence policy window.
    #[must_use]
    pub fn has_absence_warnings(&self) -> bool {
        !self.absence_alerts.is_empty()
    }

    /// Whether the fleet has collapsed to zero usable workers.
    #[must_use]
    pub fn capacity_collapsed(&self) -> bool {
        self.diff.capacity_collapsed()
    }
}

/// Compute the fleet status report from per-worker signals.
///
/// Pure and deterministic: the grouping comes from [`build_fleet_diff`], the
/// problem class from [`classify_fleet_problem`], and absence alerts from any
/// non-ready worker whose known absence meets `absence_threshold_secs`.
#[must_use]
pub fn compute_fleet_status(
    signals: &[FleetWorkerSignal],
    absence_threshold_secs: u64,
) -> FleetStatusReport {
    let observations: Vec<WorkerObservation> =
        signals.iter().map(|s| s.observation.clone()).collect();
    let diff = build_fleet_diff(&observations);

    let mut absence_alerts: Vec<AbsenceAlert> = signals
        .iter()
        .filter_map(|s| {
            let state = derive_worker_diff(&s.observation);
            let secs = s.absent_secs?;
            (!state.is_usable() && secs >= absence_threshold_secs).then(|| AbsenceAlert {
                worker_id: s.observation.worker_id.clone(),
                state,
                absent_secs: secs,
                threshold_secs: absence_threshold_secs,
            })
        })
        .collect();
    // Longest-absent first; ties broken by id for determinism.
    absence_alerts.sort_by(|a, b| {
        b.absent_secs
            .cmp(&a.absent_secs)
            .then_with(|| a.worker_id.cmp(&b.worker_id))
    });

    let (problem_class, problem_summary) = classify_fleet_problem(&diff, signals);

    FleetStatusReport {
        diff,
        problem_class,
        problem_summary,
        absence_alerts,
        absence_threshold_secs,
    }
}

/// Classify the dominant fleet problem from the diff and per-worker signals.
///
/// When at least one worker is ready, the fleet is [`FleetProblemClass::Healthy`]
/// unless every ready worker is at full slot capacity, which is
/// [`FleetProblemClass::LocalOverload`]. On a capacity collapse, each absent
/// worker contributes to one problem dimension and the dominant dimension wins,
/// with a fixed precedence breaking ties:
/// admin intent > disk pressure > cloud disappearance > missing capability >
/// daemon/config drift.
#[must_use]
pub fn classify_fleet_problem(
    diff: &FleetDiff,
    signals: &[FleetWorkerSignal],
) -> (FleetProblemClass, String) {
    let total = diff.workers.len();
    if total == 0 {
        return (
            FleetProblemClass::Healthy,
            "no workers configured".to_string(),
        );
    }

    if diff.ready_workers > 0 {
        let saturated_ready = signals
            .iter()
            .filter(|s| derive_worker_diff(&s.observation).is_usable() && s.slots_saturated)
            .count();
        if saturated_ready == diff.ready_workers {
            return (
                FleetProblemClass::LocalOverload,
                format!(
                    "{}/{total} worker(s) ready but all at full slot capacity (overload)",
                    diff.ready_workers
                ),
            );
        }
        return (
            FleetProblemClass::Healthy,
            format!("{}/{total} worker(s) ready", diff.ready_workers),
        );
    }

    // Capacity collapse: attribute each absent worker to exactly one dimension.
    let mut admin = 0usize;
    let mut disk = 0usize;
    let mut cloud = 0usize;
    let mut capability = 0usize;
    let mut drift = 0usize;
    for s in signals {
        match derive_worker_diff(&s.observation) {
            WorkerDiffState::Ready => {}
            WorkerDiffState::AdminDisabled => admin += 1,
            WorkerDiffState::RecoveredNotRejoined | WorkerDiffState::Unconfigured => drift += 1,
            WorkerDiffState::FactsUnknown | WorkerDiffState::CommandIneligible => capability += 1,
            WorkerDiffState::TemporarilyBypassed
            | WorkerDiffState::Unreachable
            | WorkerDiffState::MissingFromFleet => {
                // Disk-flagged absences are a disk problem; otherwise the host
                // is gone/flaky (cloud disappearance).
                if s.disk_pressure {
                    disk += 1;
                } else {
                    cloud += 1;
                }
            }
        }
    }

    // Highest count wins; iteration order encodes the tie-break precedence.
    let scored = [
        (FleetProblemClass::AdminIntent, admin),
        (FleetProblemClass::DiskPressure, disk),
        (FleetProblemClass::CloudDisappearance, cloud),
        (FleetProblemClass::MissingCapability, capability),
        (FleetProblemClass::DaemonConfigDrift, drift),
    ];
    let mut best = (FleetProblemClass::Healthy, 0usize);
    for (class, n) in scored {
        if n > best.1 {
            best = (class, n);
        }
    }
    let (class, n) = best;
    let summary = format!(
        "0/{total} ready — {} ({n} worker(s)); {}",
        class.label(),
        diff.explanation
    );
    (class, summary)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ready(id: &str) -> WorkerObservation {
        WorkerObservation::ready(id)
    }

    fn sig(obs: WorkerObservation) -> FleetWorkerSignal {
        FleetWorkerSignal::from_observation(obs)
    }

    #[test]
    fn problem_class_tokens_are_stable() {
        assert_eq!(
            FleetProblemClass::CloudDisappearance.as_str(),
            "cloud_disappearance"
        );
        let json = serde_json::to_string(&FleetProblemClass::DiskPressure).unwrap();
        assert_eq!(json, "\"disk_pressure\"");
    }

    #[test]
    fn healthy_when_a_ready_worker_has_headroom() {
        let report = compute_fleet_status(&[sig(ready("a"))], DEFAULT_ABSENCE_THRESHOLD_SECS);
        assert_eq!(report.problem_class, FleetProblemClass::Healthy);
        assert_eq!(report.diff.ready_workers, 1);
        assert!(!report.has_absence_warnings());
    }

    #[test]
    fn overload_when_all_ready_workers_saturated() {
        let mut s = sig(ready("a"));
        s.slots_saturated = true;
        let report = compute_fleet_status(&[s], DEFAULT_ABSENCE_THRESHOLD_SECS);
        assert_eq!(report.problem_class, FleetProblemClass::LocalOverload);
        assert!(report.problem_summary.contains("overload"));
    }

    #[test]
    fn not_overload_when_some_ready_worker_has_headroom() {
        let mut a = sig(ready("a"));
        a.slots_saturated = true;
        let b = sig(ready("b")); // has headroom
        let report = compute_fleet_status(&[a, b], DEFAULT_ABSENCE_THRESHOLD_SECS);
        assert_eq!(report.problem_class, FleetProblemClass::Healthy);
    }

    #[test]
    fn admin_intent_dominates_collapse() {
        let mut a = ready("a");
        a.admin_disabled = true;
        let mut b = ready("b");
        b.admin_disabled = true;
        let mut c = ready("c");
        c.reachable = false; // unreachable -> cloud
        let report =
            compute_fleet_status(&[sig(a), sig(b), sig(c)], DEFAULT_ABSENCE_THRESHOLD_SECS);
        assert!(report.capacity_collapsed());
        assert_eq!(report.problem_class, FleetProblemClass::AdminIntent);
        assert!(report.problem_summary.contains("admin intent"));
    }

    #[test]
    fn disk_pressure_classified_from_bypass_signal() {
        let mut a = ready("a");
        a.temporarily_bypassed = true;
        let mut sa = sig(a);
        sa.disk_pressure = true;
        let mut b = ready("b");
        b.temporarily_bypassed = true;
        let mut sb = sig(b);
        sb.disk_pressure = true;
        let report = compute_fleet_status(&[sa, sb], DEFAULT_ABSENCE_THRESHOLD_SECS);
        assert_eq!(report.problem_class, FleetProblemClass::DiskPressure);
    }

    #[test]
    fn cloud_disappearance_when_hosts_missing() {
        let mut a = ready("a");
        a.in_daemon_pool = false;
        a.reachable = false; // missing_from_fleet
        let mut b = ready("b");
        b.reachable = false; // unreachable
        let report = compute_fleet_status(&[sig(a), sig(b)], DEFAULT_ABSENCE_THRESHOLD_SECS);
        assert_eq!(report.problem_class, FleetProblemClass::CloudDisappearance);
    }

    #[test]
    fn daemon_config_drift_when_recovered_not_rejoined() {
        let mut a = ready("a");
        a.in_daemon_pool = false;
        a.reachable = true; // recovered_not_rejoined
        let mut b = ready("b");
        b.configured = false; // unconfigured orphan
        let report = compute_fleet_status(&[sig(a), sig(b)], DEFAULT_ABSENCE_THRESHOLD_SECS);
        assert_eq!(report.problem_class, FleetProblemClass::DaemonConfigDrift);
    }

    #[test]
    fn missing_capability_when_facts_or_admissibility_fail() {
        let mut a = ready("a");
        a.facts_known = false;
        let mut b = ready("b");
        b.command_admissible = false;
        let report = compute_fleet_status(&[sig(a), sig(b)], DEFAULT_ABSENCE_THRESHOLD_SECS);
        assert_eq!(report.problem_class, FleetProblemClass::MissingCapability);
    }

    #[test]
    fn absence_alerts_respect_threshold_and_sort_longest_first() {
        let mut a = ready("a");
        a.reachable = false;
        let mut sa = sig(a);
        sa.absent_secs = Some(1000); // over threshold

        let mut b = ready("b");
        b.reachable = false;
        let mut sb = sig(b);
        sb.absent_secs = Some(60); // under threshold

        let mut c = ready("c");
        c.reachable = false;
        let mut sc = sig(c);
        sc.absent_secs = Some(500); // over threshold

        let report = compute_fleet_status(&[sa, sb, sc], 300);
        assert!(report.has_absence_warnings());
        let ids: Vec<&str> = report
            .absence_alerts
            .iter()
            .map(|x| x.worker_id.as_str())
            .collect();
        // Only a (1000s) and c (500s), longest first.
        assert_eq!(ids, vec!["a", "c"]);
        assert_eq!(report.absence_alerts[0].absent_secs, 1000);
        assert_eq!(report.absence_alerts[0].threshold_secs, 300);
    }

    #[test]
    fn ready_worker_never_raises_absence_alert() {
        let mut s = sig(ready("a"));
        s.absent_secs = Some(99_999); // even with a huge value, ready != absent
        let report = compute_fleet_status(&[s], 300);
        assert!(!report.has_absence_warnings());
    }

    #[test]
    fn empty_fleet_is_healthy_with_no_alerts() {
        let report = compute_fleet_status(&[], DEFAULT_ABSENCE_THRESHOLD_SECS);
        assert_eq!(report.problem_class, FleetProblemClass::Healthy);
        assert_eq!(report.problem_summary, "no workers configured");
        assert!(!report.has_absence_warnings());
    }

    #[test]
    fn report_serializes_with_stable_shape() {
        let mut a = ready("a");
        a.admin_disabled = true;
        let report = compute_fleet_status(&[sig(a)], DEFAULT_ABSENCE_THRESHOLD_SECS);
        let value = serde_json::to_value(&report).unwrap();
        assert_eq!(value["problem_class"], "admin_intent");
        assert_eq!(value["diff"]["state_counts"]["admin_disabled"], 1);
        assert_eq!(value["absence_threshold_secs"], 300);
        assert!(value["absence_alerts"].as_array().unwrap().is_empty());
        let back: FleetStatusReport = serde_json::from_value(value).unwrap();
        assert_eq!(back, report);
    }
}
