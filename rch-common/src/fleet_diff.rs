//! Desired-state inventory and live-eligibility diff
//! (bd-session-history-remediation-ocv9i.2.1).
//!
//! Session history showed operators chasing a capacity collapse across three
//! disjoint surfaces — `workers.toml` (what's configured), the daemon's
//! in-memory pool (what joined), and status (what's healthy) — with no single
//! view that says *why* there are zero usable workers for a command. This module
//! is that view: it diffs the **desired** fleet against the **live** state
//! across every dimension that can take a worker out of play (not in the pool,
//! unreachable, admin-disabled, temporarily bypassed, stale facts, or admissible
//! for everything *except this command*), and explains the collapse in one
//! [`FleetDiff`].
//!
//! [`derive_worker_diff`] is the pure per-worker classifier; [`build_fleet_diff`]
//! aggregates and counts, so the report stands alone without reading the config,
//! the daemon log, and status separately.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// One worker's observed state across the desired/live dimensions. Plain data so
/// the classification is pure and unit-testable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerObservation {
    pub worker_id: String,
    /// Present in `workers.toml` (desired).
    pub configured: bool,
    /// Present in the daemon's in-memory pool (joined).
    pub in_daemon_pool: bool,
    /// Answering probes right now.
    pub reachable: bool,
    /// Administratively disabled.
    pub admin_disabled: bool,
    /// Under a temporary bypass (e.g. disk pressure) expected to recover.
    pub temporarily_bypassed: bool,
    /// Last-known capability facts are present and fresh enough to trust.
    pub facts_known: bool,
    /// Admissible for the *selected command* (capability-checked).
    pub command_admissible: bool,
}

impl WorkerObservation {
    /// A fully-ready worker (all dimensions green) — a base for tests/builders.
    #[must_use]
    pub fn ready(worker_id: impl Into<String>) -> Self {
        Self {
            worker_id: worker_id.into(),
            configured: true,
            in_daemon_pool: true,
            reachable: true,
            admin_disabled: false,
            temporarily_bypassed: false,
            facts_known: true,
            command_admissible: true,
        }
    }
}

/// The single diagnosis for one worker, explaining whether — and why not — it
/// can run the selected command right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerDiffState {
    /// Usable for the command right now.
    Ready,
    /// Configured but absent from the daemon pool and unreachable — never joined
    /// (or fell out and is down).
    MissingFromFleet,
    /// Reachable again but not back in the daemon pool — recovered, not rejoined.
    RecoveredNotRejoined,
    /// Administratively disabled.
    AdminDisabled,
    /// Temporarily bypassed; expected to recover.
    TemporarilyBypassed,
    /// In the pool but not answering probes.
    Unreachable,
    /// No trustworthy capability facts.
    FactsUnknown,
    /// Healthy and in the pool, but not admissible for THIS command.
    CommandIneligible,
    /// Present in the live pool but not in the desired config (an orphan).
    Unconfigured,
}

impl WorkerDiffState {
    /// Stable lowercase token.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            WorkerDiffState::Ready => "ready",
            WorkerDiffState::MissingFromFleet => "missing_from_fleet",
            WorkerDiffState::RecoveredNotRejoined => "recovered_not_rejoined",
            WorkerDiffState::AdminDisabled => "admin_disabled",
            WorkerDiffState::TemporarilyBypassed => "temporarily_bypassed",
            WorkerDiffState::Unreachable => "unreachable",
            WorkerDiffState::FactsUnknown => "facts_unknown",
            WorkerDiffState::CommandIneligible => "command_ineligible",
            WorkerDiffState::Unconfigured => "unconfigured",
        }
    }

    /// Whether a worker in this state can run the command now.
    #[must_use]
    pub fn is_usable(self) -> bool {
        matches!(self, WorkerDiffState::Ready)
    }
}

/// Classify one worker's diff state. Pure and total.
///
/// Precedence (the most fundamental reason a worker is out of play, first):
/// admin-disabled (an explicit operator choice) → temporarily-bypassed →
/// configured-but-not-pooled (missing vs recovered-not-rejoined, by
/// reachability) → in-pool-but-unreachable → present-but-unconfigured →
/// facts-unknown → command-ineligible → ready.
#[must_use]
pub fn derive_worker_diff(obs: &WorkerObservation) -> WorkerDiffState {
    if obs.admin_disabled {
        return WorkerDiffState::AdminDisabled;
    }
    if obs.temporarily_bypassed {
        return WorkerDiffState::TemporarilyBypassed;
    }
    if obs.configured && !obs.in_daemon_pool {
        return if obs.reachable {
            WorkerDiffState::RecoveredNotRejoined
        } else {
            WorkerDiffState::MissingFromFleet
        };
    }
    if obs.in_daemon_pool && !obs.reachable {
        return WorkerDiffState::Unreachable;
    }
    if !obs.configured && obs.in_daemon_pool {
        return WorkerDiffState::Unconfigured;
    }
    if !obs.facts_known {
        return WorkerDiffState::FactsUnknown;
    }
    if !obs.command_admissible {
        return WorkerDiffState::CommandIneligible;
    }
    WorkerDiffState::Ready
}

/// One worker's row in the fleet diff.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerDiffRow {
    pub worker_id: String,
    pub state: WorkerDiffState,
}

/// The whole-fleet desired-vs-live diff with a capacity-collapse explanation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetDiff {
    pub workers: Vec<WorkerDiffRow>,
    /// Count per diff state (only non-zero entries), for the explanation.
    pub state_counts: BTreeMap<String, usize>,
    /// Workers usable for the command right now.
    pub ready_workers: usize,
    /// One-line capacity-collapse explanation.
    pub explanation: String,
}

impl FleetDiff {
    /// Whether the fleet has collapsed to zero usable workers.
    #[must_use]
    pub fn capacity_collapsed(&self) -> bool {
        self.ready_workers == 0 && !self.workers.is_empty()
    }

    /// Count of workers in a given state.
    #[must_use]
    pub fn count(&self, state: WorkerDiffState) -> usize {
        self.state_counts.get(state.as_str()).copied().unwrap_or(0)
    }
}

/// Build the fleet diff from per-worker observations.
#[must_use]
pub fn build_fleet_diff(observations: &[WorkerObservation]) -> FleetDiff {
    let mut workers = Vec::with_capacity(observations.len());
    let mut state_counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut ready_workers = 0;
    for obs in observations {
        let state = derive_worker_diff(obs);
        if state.is_usable() {
            ready_workers += 1;
        }
        *state_counts.entry(state.as_str().to_string()).or_insert(0) += 1;
        workers.push(WorkerDiffRow {
            worker_id: obs.worker_id.clone(),
            state,
        });
    }

    let explanation = if observations.is_empty() {
        "no workers configured".to_string()
    } else if ready_workers > 0 {
        format!("{ready_workers}/{} worker(s) ready", observations.len())
    } else {
        // Capacity collapse: name the dominant non-ready reasons inline so an
        // operator never has to cross-reference config/log/status.
        let mut parts: Vec<String> = state_counts
            .iter()
            .map(|(state, n)| format!("{state}={n}"))
            .collect();
        parts.sort();
        format!(
            "0/{} ready — capacity collapse: {}",
            observations.len(),
            parts.join(", ")
        )
    };

    FleetDiff {
        workers,
        state_counts,
        ready_workers,
        explanation,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- The four required scenarios ----------------------------------------

    #[test]
    fn missing_configured_worker() {
        // Configured in workers.toml but absent from the pool and unreachable.
        let mut obs = WorkerObservation::ready("css");
        obs.in_daemon_pool = false;
        obs.reachable = false;
        assert_eq!(derive_worker_diff(&obs), WorkerDiffState::MissingFromFleet);
    }

    #[test]
    fn recovered_but_not_rejoined_worker() {
        // Reachable again, but the daemon hasn't re-admitted it to the pool.
        let mut obs = WorkerObservation::ready("css");
        obs.in_daemon_pool = false;
        obs.reachable = true;
        assert_eq!(
            derive_worker_diff(&obs),
            WorkerDiffState::RecoveredNotRejoined
        );
    }

    #[test]
    fn admin_disabled_worker() {
        let mut obs = WorkerObservation::ready("css");
        obs.admin_disabled = true;
        // Admin-disabled outranks every other condition.
        obs.reachable = false;
        obs.in_daemon_pool = false;
        assert_eq!(derive_worker_diff(&obs), WorkerDiffState::AdminDisabled);
    }

    #[test]
    fn healthy_worker_rejected_only_for_a_specific_command_capability() {
        // In the pool, reachable, facts known — but not admissible for THIS
        // command. The crucial distinction from an unhealthy/absent worker.
        let mut obs = WorkerObservation::ready("css");
        obs.command_admissible = false;
        assert_eq!(derive_worker_diff(&obs), WorkerDiffState::CommandIneligible);
    }

    // --- Other dimensions + precedence --------------------------------------

    #[test]
    fn temporary_bypass_and_unreachable_and_unconfigured() {
        let mut bypass = WorkerObservation::ready("a");
        bypass.temporarily_bypassed = true;
        assert_eq!(
            derive_worker_diff(&bypass),
            WorkerDiffState::TemporarilyBypassed
        );

        let mut unreachable = WorkerObservation::ready("b");
        unreachable.reachable = false; // still in pool
        assert_eq!(
            derive_worker_diff(&unreachable),
            WorkerDiffState::Unreachable
        );

        let mut orphan = WorkerObservation::ready("c");
        orphan.configured = false; // in pool but not configured
        assert_eq!(derive_worker_diff(&orphan), WorkerDiffState::Unconfigured);
    }

    #[test]
    fn ready_when_all_green() {
        assert_eq!(
            derive_worker_diff(&WorkerObservation::ready("css")),
            WorkerDiffState::Ready
        );
    }

    // --- Aggregate explanation ----------------------------------------------

    #[test]
    fn fleet_diff_explains_capacity_collapse() {
        // Three configured workers, all out of play for different reasons —
        // exactly the cross-surface confusion this report collapses into one line.
        let mut admin = WorkerObservation::ready("a");
        admin.admin_disabled = true;
        let mut unreachable = WorkerObservation::ready("b");
        unreachable.reachable = false;
        let mut ineligible = WorkerObservation::ready("c");
        ineligible.command_admissible = false;

        let diff = build_fleet_diff(&[admin, unreachable, ineligible]);
        assert_eq!(diff.ready_workers, 0);
        assert!(diff.capacity_collapsed());
        assert_eq!(diff.count(WorkerDiffState::AdminDisabled), 1);
        assert_eq!(diff.count(WorkerDiffState::Unreachable), 1);
        assert_eq!(diff.count(WorkerDiffState::CommandIneligible), 1);
        assert!(diff.explanation.contains("capacity collapse"));
        assert!(diff.explanation.contains("admin_disabled=1"));
        assert!(diff.explanation.contains("command_ineligible=1"));
    }

    #[test]
    fn fleet_diff_reports_ready_count() {
        let diff = build_fleet_diff(&[WorkerObservation::ready("a"), {
            let mut b = WorkerObservation::ready("b");
            b.command_admissible = false;
            b
        }]);
        assert_eq!(diff.ready_workers, 1);
        assert!(!diff.capacity_collapsed());
        assert!(diff.explanation.contains("1/2 worker(s) ready"));
    }

    #[test]
    fn empty_fleet_is_explained() {
        let diff = build_fleet_diff(&[]);
        assert_eq!(diff.ready_workers, 0);
        assert!(!diff.capacity_collapsed());
        assert!(diff.explanation.contains("no workers configured"));
    }

    #[test]
    fn fleet_diff_serializes_with_stable_tokens() {
        let diff = build_fleet_diff(&[{
            let mut a = WorkerObservation::ready("a");
            a.admin_disabled = true;
            a
        }]);
        let value = serde_json::to_value(&diff).unwrap();
        assert_eq!(value["workers"][0]["state"], "admin_disabled");
        assert_eq!(value["state_counts"]["admin_disabled"], 1);
        let back: FleetDiff = serde_json::from_value(value).unwrap();
        assert_eq!(back, diff);
    }
}
