//! Admission rejection aggregation with a stable reason vocabulary
//! (bd-session-history-remediation-ocv9i.6.2).
//!
//! When a command finds no admissible worker, an agent needs to know *why* in
//! aggregate — not a single opaque "no admissible workers", but a breakdown that
//! separates **global worker health** (the worker is unusable for anything right
//! now) from **command-specific admissibility** (this worker can't run *this*
//! command) from **project policy** (the worker was excluded by configuration).
//!
//! This module is that aggregation contract. [`AdmissionRejectionCategory`] is
//! the stable, exhaustive vocabulary the session-history report enumerates;
//! each maps to a [`RejectionClass`] and (where the registry has a 1:1 code) an
//! [`IncidentReasonCode`], so the aggregation reuses the existing incident
//! registry and selection/eligibility diagnostics rather than inventing a
//! parallel path. [`aggregate_rejections`] folds per-candidate categories into
//! an [`AdmissionRejectionSummary`] with per-category counts and per-class
//! subtotals.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::incident::IncidentReasonCode;

/// Which broad concern a rejection belongs to. Separating these is the bead's
/// core requirement: an agent must tell "the fleet is unhealthy" apart from
/// "this command needs something the fleet lacks" apart from "policy excluded
/// the worker".
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RejectionClass {
    /// The worker is unusable right now regardless of the command.
    WorkerHealth,
    /// The worker can't run *this* command (missing capability / classifier).
    CommandAdmissibility,
    /// Configuration/policy excluded the worker.
    ProjectPolicy,
}

impl RejectionClass {
    /// Stable lowercase token.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            RejectionClass::WorkerHealth => "worker_health",
            RejectionClass::CommandAdmissibility => "command_admissibility",
            RejectionClass::ProjectPolicy => "project_policy",
        }
    }
}

/// The stable, exhaustive vocabulary of admission-rejection reasons. Ordered for
/// deterministic aggregation output. Distinguishes missing runtime / toolchain /
/// Rust target (which the coarse [`IncidentReasonCode::MissingRuntimeToolchainTarget`]
/// collapses) because operators count them separately.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionRejectionCategory {
    CriticalPressure,
    InsufficientSlots,
    CircuitOpen,
    TelemetryStale,
    HardPreflight,
    MissingRuntime,
    MissingToolchain,
    MissingRustTarget,
    OsArchMismatch,
    ClassifierLocalDrift,
    ActiveProjectExclusion,
    ProjectExcluded,
}

impl AdmissionRejectionCategory {
    /// Every category in stable declaration order (for coverage + iteration).
    pub const ALL: &'static [AdmissionRejectionCategory] = &[
        Self::CriticalPressure,
        Self::InsufficientSlots,
        Self::CircuitOpen,
        Self::TelemetryStale,
        Self::HardPreflight,
        Self::MissingRuntime,
        Self::MissingToolchain,
        Self::MissingRustTarget,
        Self::OsArchMismatch,
        Self::ClassifierLocalDrift,
        Self::ActiveProjectExclusion,
        Self::ProjectExcluded,
    ];

    /// Stable lowercase token (matches the serde representation).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CriticalPressure => "critical_pressure",
            Self::InsufficientSlots => "insufficient_slots",
            Self::CircuitOpen => "circuit_open",
            Self::TelemetryStale => "telemetry_stale",
            Self::HardPreflight => "hard_preflight",
            Self::MissingRuntime => "missing_runtime",
            Self::MissingToolchain => "missing_toolchain",
            Self::MissingRustTarget => "missing_rust_target",
            Self::OsArchMismatch => "os_arch_mismatch",
            Self::ClassifierLocalDrift => "classifier_local_drift",
            Self::ActiveProjectExclusion => "active_project_exclusion",
            Self::ProjectExcluded => "project_excluded",
        }
    }

    /// The broad class this category belongs to.
    #[must_use]
    pub fn class(self) -> RejectionClass {
        match self {
            Self::CriticalPressure
            | Self::InsufficientSlots
            | Self::CircuitOpen
            | Self::TelemetryStale => RejectionClass::WorkerHealth,
            Self::HardPreflight
            | Self::MissingRuntime
            | Self::MissingToolchain
            | Self::MissingRustTarget
            | Self::OsArchMismatch
            | Self::ClassifierLocalDrift => RejectionClass::CommandAdmissibility,
            Self::ActiveProjectExclusion | Self::ProjectExcluded => RejectionClass::ProjectPolicy,
        }
    }

    /// The closest stable incident reason code, reusing the existing registry.
    /// The three missing-* runtime categories all map to the coarse
    /// [`IncidentReasonCode::MissingRuntimeToolchainTarget`]; `ProjectExcluded`
    /// reuses the active-project-exclusion code (the registry has one exclusion
    /// reason).
    #[must_use]
    pub fn incident_reason(self) -> IncidentReasonCode {
        match self {
            Self::CriticalPressure => IncidentReasonCode::CriticalPressure,
            Self::InsufficientSlots => IncidentReasonCode::InsufficientSlots,
            Self::CircuitOpen => IncidentReasonCode::CircuitOpen,
            Self::TelemetryStale => IncidentReasonCode::TelemetryStale,
            Self::HardPreflight => IncidentReasonCode::HardPreflight,
            Self::MissingRuntime | Self::MissingToolchain | Self::MissingRustTarget => {
                IncidentReasonCode::MissingRuntimeToolchainTarget
            }
            Self::OsArchMismatch => IncidentReasonCode::OsArchMismatch,
            Self::ClassifierLocalDrift => IncidentReasonCode::QueueAmbiguity,
            Self::ActiveProjectExclusion | Self::ProjectExcluded => {
                IncidentReasonCode::ActiveProjectExclusion
            }
        }
    }

    /// Map an existing incident reason code to a category where it is
    /// unambiguous. Returns `None` for
    /// [`IncidentReasonCode::MissingRuntimeToolchainTarget`] (the caller must
    /// pick `MissingRuntime`/`MissingToolchain`/`MissingRustTarget` from the
    /// specific failure) and for codes with no admission-rejection meaning.
    #[must_use]
    pub fn from_incident_reason(code: IncidentReasonCode) -> Option<Self> {
        Some(match code {
            IncidentReasonCode::CriticalPressure => Self::CriticalPressure,
            IncidentReasonCode::InsufficientSlots => Self::InsufficientSlots,
            IncidentReasonCode::CircuitOpen => Self::CircuitOpen,
            IncidentReasonCode::TelemetryStale => Self::TelemetryStale,
            IncidentReasonCode::HardPreflight => Self::HardPreflight,
            IncidentReasonCode::OsArchMismatch => Self::OsArchMismatch,
            IncidentReasonCode::ActiveProjectExclusion => Self::ActiveProjectExclusion,
            // Ambiguous (3-way split) or not an admission rejection.
            _ => return None,
        })
    }
}

/// One candidate worker's rejection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CandidateRejection {
    pub worker_id: String,
    pub category: AdmissionRejectionCategory,
}

/// Aggregated admission rejection diagnostics for a command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdmissionRejectionSummary {
    /// Total candidate workers considered.
    pub total_candidates: usize,
    /// How many were rejected.
    pub rejected: usize,
    /// Count of rejected workers per category (only non-zero entries).
    pub by_category: BTreeMap<String, usize>,
    /// Count of rejected workers per broad class (only non-zero entries).
    pub by_class: BTreeMap<String, usize>,
}

impl AdmissionRejectionSummary {
    /// Whether every candidate was rejected (no worker could run the command).
    #[must_use]
    pub fn all_rejected(&self) -> bool {
        self.total_candidates > 0 && self.rejected == self.total_candidates
    }

    /// Rejections attributable to a class.
    #[must_use]
    pub fn class_count(&self, class: RejectionClass) -> usize {
        self.by_class.get(class.as_str()).copied().unwrap_or(0)
    }

    /// Human-readable summary that separates worker health from command
    /// admissibility from project policy.
    #[must_use]
    pub fn render(&self) -> String {
        let mut parts: Vec<String> = self
            .by_category
            .iter()
            .map(|(cat, n)| format!("{cat}={n}"))
            .collect();
        parts.sort();
        format!(
            "{}/{} candidates rejected (health={}, command={}, policy={}): {}",
            self.rejected,
            self.total_candidates,
            self.class_count(RejectionClass::WorkerHealth),
            self.class_count(RejectionClass::CommandAdmissibility),
            self.class_count(RejectionClass::ProjectPolicy),
            parts.join(", "),
        )
    }
}

/// Aggregate per-candidate rejections into a summary. `total_candidates` is the
/// full candidate set (so the caller can express "3 of 5 rejected"); the
/// rejections slice is one entry per rejected candidate.
#[must_use]
pub fn aggregate_rejections(
    total_candidates: usize,
    rejections: &[CandidateRejection],
) -> AdmissionRejectionSummary {
    let mut by_category: BTreeMap<String, usize> = BTreeMap::new();
    let mut by_class: BTreeMap<String, usize> = BTreeMap::new();
    for rejection in rejections {
        *by_category
            .entry(rejection.category.as_str().to_string())
            .or_insert(0) += 1;
        *by_class
            .entry(rejection.category.class().as_str().to_string())
            .or_insert(0) += 1;
    }
    AdmissionRejectionSummary {
        total_candidates,
        rejected: rejections.len(),
        by_category,
        by_class,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rej(worker: &str, category: AdmissionRejectionCategory) -> CandidateRejection {
        CandidateRejection {
            worker_id: worker.to_string(),
            category,
        }
    }

    #[test]
    fn aggregates_counts_per_category() {
        let rejections = vec![
            rej("a", AdmissionRejectionCategory::CriticalPressure),
            rej("b", AdmissionRejectionCategory::CriticalPressure),
            rej("c", AdmissionRejectionCategory::MissingRustTarget),
        ];
        let summary = aggregate_rejections(4, &rejections);
        assert_eq!(summary.total_candidates, 4);
        assert_eq!(summary.rejected, 3);
        assert_eq!(summary.by_category.get("critical_pressure"), Some(&2));
        assert_eq!(summary.by_category.get("missing_rust_target"), Some(&1));
        assert!(!summary.all_rejected());
    }

    #[test]
    fn separates_global_health_from_command_admissibility_and_policy() {
        let rejections = vec![
            rej("a", AdmissionRejectionCategory::CriticalPressure), // health
            rej("b", AdmissionRejectionCategory::CircuitOpen),      // health
            rej("c", AdmissionRejectionCategory::MissingToolchain), // command
            rej("d", AdmissionRejectionCategory::OsArchMismatch),   // command
            rej("e", AdmissionRejectionCategory::ProjectExcluded),  // policy
        ];
        let summary = aggregate_rejections(5, &rejections);
        assert!(summary.all_rejected());
        assert_eq!(summary.class_count(RejectionClass::WorkerHealth), 2);
        assert_eq!(summary.class_count(RejectionClass::CommandAdmissibility), 2);
        assert_eq!(summary.class_count(RejectionClass::ProjectPolicy), 1);
    }

    #[test]
    fn the_twelve_categories_are_distinct_and_classified() {
        assert_eq!(AdmissionRejectionCategory::ALL.len(), 12);
        let mut tokens: Vec<&str> = AdmissionRejectionCategory::ALL
            .iter()
            .map(|c| c.as_str())
            .collect();
        tokens.sort_unstable();
        let before = tokens.len();
        tokens.dedup();
        assert_eq!(before, tokens.len(), "duplicate category tokens");
        // Every category has a class and an incident reason.
        for c in AdmissionRejectionCategory::ALL {
            let _ = c.class();
            let _ = c.incident_reason();
        }
    }

    #[test]
    fn missing_runtime_split_maps_to_coarse_incident_code() {
        // The three runtime categories collapse to the registry's single code.
        for c in [
            AdmissionRejectionCategory::MissingRuntime,
            AdmissionRejectionCategory::MissingToolchain,
            AdmissionRejectionCategory::MissingRustTarget,
        ] {
            assert_eq!(
                c.incident_reason(),
                IncidentReasonCode::MissingRuntimeToolchainTarget
            );
        }
    }

    #[test]
    fn from_incident_reason_is_unambiguous_or_none() {
        // 1:1 codes round-trip.
        assert_eq!(
            AdmissionRejectionCategory::from_incident_reason(IncidentReasonCode::CircuitOpen),
            Some(AdmissionRejectionCategory::CircuitOpen)
        );
        assert_eq!(
            AdmissionRejectionCategory::from_incident_reason(IncidentReasonCode::OsArchMismatch),
            Some(AdmissionRejectionCategory::OsArchMismatch)
        );
        // The collapsed runtime code is ambiguous => None (caller must refine).
        assert_eq!(
            AdmissionRejectionCategory::from_incident_reason(
                IncidentReasonCode::MissingRuntimeToolchainTarget
            ),
            None
        );
        // A non-admission code => None.
        assert_eq!(
            AdmissionRejectionCategory::from_incident_reason(IncidentReasonCode::DiskFull),
            None
        );
    }

    #[test]
    fn empty_rejections_is_no_rejection() {
        let summary = aggregate_rejections(3, &[]);
        assert_eq!(summary.rejected, 0);
        assert!(!summary.all_rejected());
        assert!(summary.by_category.is_empty());
        assert_eq!(summary.class_count(RejectionClass::WorkerHealth), 0);
    }

    #[test]
    fn summary_serializes_with_stable_tokens_and_round_trips() {
        let rejections = vec![
            rej("a", AdmissionRejectionCategory::TelemetryStale),
            rej("b", AdmissionRejectionCategory::MissingRuntime),
        ];
        let summary = aggregate_rejections(2, &rejections);
        let value = serde_json::to_value(&summary).unwrap();
        assert_eq!(value["by_category"]["telemetry_stale"], 1);
        assert_eq!(value["by_category"]["missing_runtime"], 1);
        assert_eq!(value["by_class"]["worker_health"], 1);
        assert_eq!(value["by_class"]["command_admissibility"], 1);
        let back: AdmissionRejectionSummary = serde_json::from_value(value).unwrap();
        assert_eq!(back, summary);
    }

    #[test]
    fn render_separates_classes() {
        let summary = aggregate_rejections(
            2,
            &[
                rej("a", AdmissionRejectionCategory::CriticalPressure),
                rej("b", AdmissionRejectionCategory::MissingRustTarget),
            ],
        );
        let line = summary.render();
        assert!(line.contains("health=1"));
        assert!(line.contains("command=1"));
        assert!(line.contains("2/2 candidates rejected"));
    }
}
