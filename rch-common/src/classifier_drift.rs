//! Classifier drift detection and bounded refresh
//! (bd-session-history-remediation-ocv9i.6.3).
//!
//! Session history captured a subtle placement-integrity failure: the fleet had
//! healthy *free* slots, yet RCH ran the build locally — not because of capacity
//! or pressure, but because **stale classifier state** mis-decided the command
//! until a refresh corrected it. That must be reported distinctly from "no
//! capacity" and "critical pressure", or operators chase the wrong cause.
//!
//! This module is the pure detection + bounded-refresh contract:
//! [`assess_drift`] decides whether a local choice was genuine or a drift
//! (chose-local *with* healthy free slots, where a classifier refresh changes
//! the placement toward remote), classifies it [`DriftKind::Transient`] (refresh
//! restored remote placement) vs [`DriftKind::Persistent`] (refresh could not),
//! and records the before/after classification + selected-worker
//! [`ClassificationTransition`]. [`refresh_allowed`] bounds refresh attempts.
//! A persistent drift maps to [`AdmissionRejectionCategory::ClassifierLocalDrift`]
//! and is the distinct reason proof mode fails on.

use serde::{Deserialize, Serialize};

use crate::admission_rejection::AdmissionRejectionCategory;

/// The before/after picture across a classifier refresh.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClassificationTransition {
    /// Whether the command classified as compilation BEFORE the refresh.
    pub compilation_before: bool,
    /// Whether it classifies as compilation AFTER the refresh.
    pub compilation_after: bool,
    /// Worker selected before the refresh (`None` = ran/would run local).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker_before: Option<String>,
    /// Worker selected after the refresh (`None` = still local).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker_after: Option<String>,
}

impl ClassificationTransition {
    /// Whether the refresh changed the placement picture at all.
    #[must_use]
    pub fn changed(&self) -> bool {
        self.compilation_before != self.compilation_after || self.worker_before != self.worker_after
    }

    /// Whether remote placement is possible after the refresh.
    #[must_use]
    pub fn remote_after(&self) -> bool {
        self.worker_after.is_some()
    }
}

/// Observable inputs for drift detection. Plain data; pure assessment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriftObservation {
    /// RCH chose (or would choose) local execution.
    pub chose_local: bool,
    /// Healthy, free build slots available across the fleet at decision time.
    /// Non-zero means the local choice was NOT capacity-bound.
    pub healthy_free_slots: u32,
    /// The before/after classifier transition across a refresh.
    pub transition: ClassificationTransition,
}

/// The drift classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DriftKind {
    /// No drift — local was legitimate (genuinely non-compilation) or the choice
    /// was capacity-bound (reported separately as no-capacity/pressure).
    NoDrift,
    /// Drift detected and a classifier refresh restored remote placement.
    Transient,
    /// Drift detected but a refresh could NOT restore remote placement — proof
    /// mode must fail with a distinct reason.
    Persistent,
}

impl DriftKind {
    /// Stable lowercase token.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            DriftKind::NoDrift => "no_drift",
            DriftKind::Transient => "transient",
            DriftKind::Persistent => "persistent",
        }
    }
}

/// The drift report for admission/proof surfaces.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DriftReport {
    pub kind: DriftKind,
    /// Healthy free slots observed (echoed so the report proves the local choice
    /// was not capacity-bound).
    pub healthy_free_slots: u32,
    pub transition: ClassificationTransition,
    /// Refresh attempts performed to reach this state.
    pub refresh_attempts: u32,
    pub detail: String,
}

impl DriftReport {
    /// Whether drift was detected (transient or persistent).
    #[must_use]
    pub fn is_drift(&self) -> bool {
        !matches!(self.kind, DriftKind::NoDrift)
    }

    /// The admission-rejection category for a drift (for aggregation via 6.2).
    #[must_use]
    pub fn rejection_category(&self) -> Option<AdmissionRejectionCategory> {
        self.is_drift()
            .then_some(AdmissionRejectionCategory::ClassifierLocalDrift)
    }

    /// Whether this drift must fail proof mode with a distinct reason — true
    /// only for a persistent drift (refresh could not restore remote placement).
    #[must_use]
    pub fn blocks_proof(&self) -> bool {
        matches!(self.kind, DriftKind::Persistent)
    }
}

/// Assess classifier drift. Pure and total.
///
/// Drift requires ALL of: the command ran/would run local, healthy free slots
/// existed (so it was not capacity-bound), and the refresh moved the picture
/// toward remote (classification flipped to compilation, or a worker became
/// selectable). If after the refresh a worker is selectable it is `Transient`
/// (restored); if the picture shifted toward remote but no worker is yet
/// selectable it is `Persistent`. Everything else is `NoDrift`.
#[must_use]
pub fn assess_drift(obs: &DriftObservation, refresh_attempts: u32) -> DriftReport {
    let t = &obs.transition;
    let drift = obs.chose_local
        && obs.healthy_free_slots > 0
        && t.changed()
        && (t.compilation_after || t.remote_after());

    let kind = if !drift {
        DriftKind::NoDrift
    } else if t.remote_after() {
        DriftKind::Transient
    } else {
        DriftKind::Persistent
    };

    let detail = match kind {
        DriftKind::NoDrift if obs.chose_local && obs.healthy_free_slots == 0 => {
            "local choice was capacity-bound (no free slots), not classifier drift".to_string()
        }
        DriftKind::NoDrift => "no classifier drift; local choice was legitimate".to_string(),
        DriftKind::Transient => format!(
            "classifier drift: ran local despite {} free slot(s); refresh restored remote placement on {}",
            obs.healthy_free_slots,
            t.worker_after.as_deref().unwrap_or("a worker"),
        ),
        DriftKind::Persistent => format!(
            "classifier drift: ran local despite {} free slot(s); refresh could NOT restore remote placement",
            obs.healthy_free_slots,
        ),
    };

    DriftReport {
        kind,
        healthy_free_slots: obs.healthy_free_slots,
        transition: t.clone(),
        refresh_attempts,
        detail,
    }
}

/// Bounded-refresh budget so a misclassification can trigger at most a fixed
/// number of refreshes (a refresh storm is itself a failure mode).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RefreshBudget {
    pub max_attempts: u32,
}

impl Default for RefreshBudget {
    fn default() -> Self {
        Self { max_attempts: 2 }
    }
}

/// Whether another classifier refresh is permitted given attempts already done.
#[must_use]
pub fn refresh_allowed(attempts_done: u32, budget: &RefreshBudget) -> bool {
    attempts_done < budget.max_attempts
}

#[cfg(test)]
mod tests {
    use super::*;

    fn transition(
        before: bool,
        after: bool,
        worker_before: Option<&str>,
        worker_after: Option<&str>,
    ) -> ClassificationTransition {
        ClassificationTransition {
            compilation_before: before,
            compilation_after: after,
            worker_before: worker_before.map(str::to_string),
            worker_after: worker_after.map(str::to_string),
        }
    }

    #[test]
    fn the_session_history_case_is_transient_drift() {
        // Fleet had free slots; ran local; refresh flips classification to
        // compilation and a worker becomes selectable.
        let obs = DriftObservation {
            chose_local: true,
            healthy_free_slots: 3,
            transition: transition(false, true, None, Some("css")),
        };
        let report = assess_drift(&obs, 1);
        assert_eq!(report.kind, DriftKind::Transient);
        assert!(report.is_drift());
        assert_eq!(
            report.rejection_category(),
            Some(AdmissionRejectionCategory::ClassifierLocalDrift)
        );
        assert!(!report.blocks_proof(), "transient drift was restored");
        assert!(report.detail.contains("free slot"));
    }

    #[test]
    fn capacity_bound_local_is_not_drift() {
        // Ran local but NO free slots => capacity-bound, reported separately.
        let obs = DriftObservation {
            chose_local: true,
            healthy_free_slots: 0,
            transition: transition(true, true, None, Some("css")),
        };
        let report = assess_drift(&obs, 0);
        assert_eq!(report.kind, DriftKind::NoDrift);
        assert!(!report.is_drift());
        assert!(report.detail.contains("capacity-bound"));
    }

    #[test]
    fn persistent_drift_blocks_proof() {
        // Free slots; ran local; refresh flips classification to compilation but
        // STILL no worker selectable => refresh could not restore remote.
        let obs = DriftObservation {
            chose_local: true,
            healthy_free_slots: 2,
            transition: transition(false, true, None, None),
        };
        let report = assess_drift(&obs, 2);
        assert_eq!(report.kind, DriftKind::Persistent);
        assert!(report.blocks_proof());
        assert_eq!(
            report.rejection_category(),
            Some(AdmissionRejectionCategory::ClassifierLocalDrift)
        );
    }

    #[test]
    fn going_remote_is_never_drift() {
        let obs = DriftObservation {
            chose_local: false,
            healthy_free_slots: 4,
            transition: transition(true, true, Some("css"), Some("css")),
        };
        assert_eq!(assess_drift(&obs, 0).kind, DriftKind::NoDrift);
    }

    #[test]
    fn genuinely_non_compilation_local_is_not_drift() {
        // Free slots, ran local, and refresh changes NOTHING toward remote =>
        // local was legitimately correct.
        let obs = DriftObservation {
            chose_local: true,
            healthy_free_slots: 5,
            transition: transition(false, false, None, None),
        };
        let report = assess_drift(&obs, 1);
        assert_eq!(report.kind, DriftKind::NoDrift);
        assert!(!report.is_drift());
        assert!(report.rejection_category().is_none());
    }

    #[test]
    fn drift_is_separate_from_capacity_and_pressure() {
        // Drift uses its own category (ClassifierLocalDrift), never
        // InsufficientSlots/CriticalPressure.
        let obs = DriftObservation {
            chose_local: true,
            healthy_free_slots: 1,
            transition: transition(false, true, None, Some("w")),
        };
        let cat = assess_drift(&obs, 1).rejection_category().unwrap();
        assert_eq!(cat, AdmissionRejectionCategory::ClassifierLocalDrift);
        assert_ne!(cat, AdmissionRejectionCategory::InsufficientSlots);
        assert_ne!(cat, AdmissionRejectionCategory::CriticalPressure);
    }

    #[test]
    fn bounded_refresh_stops_at_budget() {
        let budget = RefreshBudget { max_attempts: 2 };
        assert!(refresh_allowed(0, &budget));
        assert!(refresh_allowed(1, &budget));
        assert!(!refresh_allowed(2, &budget));
        assert!(!refresh_allowed(3, &budget));
        assert_eq!(RefreshBudget::default().max_attempts, 2);
    }

    #[test]
    fn transition_records_before_after() {
        let t = transition(false, true, None, Some("css"));
        assert!(t.changed());
        assert!(t.remote_after());
        assert!(!t.compilation_before);
        assert!(t.compilation_after);
    }

    #[test]
    fn report_serializes_with_stable_tokens() {
        let obs = DriftObservation {
            chose_local: true,
            healthy_free_slots: 3,
            transition: transition(false, true, None, Some("css")),
        };
        let report = assess_drift(&obs, 1);
        let value = serde_json::to_value(&report).unwrap();
        assert_eq!(value["kind"], "transient");
        assert_eq!(value["healthy_free_slots"], 3);
        assert_eq!(value["transition"]["worker_after"], "css");
        let back: DriftReport = serde_json::from_value(value).unwrap();
        assert_eq!(back, report);
    }
}
