//! N/N-1 rolling-upgrade rules + the upgrade matrix suite (bead
//! T009; plan §107; composes J002 negotiation, the R009 doctor, and
//! its own drain/rollback/migration/canary gates).
//!
//! The rules a rolling upgrade must obey:
//!
//! - every layer (wrapper contract, ATP transport, RABS application)
//!   upgrades INDEPENDENTLY, and every intermediate fleet state must
//!   either negotiate (N/N-1) or refuse typed — never misbehave;
//! - a worker replacement whose new version cannot negotiate with
//!   the version its in-flight clients speak requires DRAIN first
//!   (typed refusal carrying the in-flight count); a compatible
//!   replacement may go live immediately;
//! - rollback is admissible only to a version the current
//!   coordinator still speaks — rolling back PAST the compatibility
//!   floor is refused, not attempted;
//! - a DB migration applies only with a backup taken AND a clean
//!   differential check (each absence is its own typed refusal);
//! - canaries gate promotion: the required success count with ZERO
//!   failures promotes; any failure rolls back regardless of how
//!   many successes accumulated.
//!
//! Key/projection epochs are SEPARATE from all of this: no type in
//! this module (or the doctor's `NodeReport`) carries an epoch — an
//! application upgrade cannot invalidate cache keys by construction;
//! epochs move only by explicit F002 epoch bumps.

use crate::version_negotiation::{Negotiation, VersionHello, VersionRange, negotiate};

/// Replacement admission for a worker upgrade.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Replacement {
    /// Old and new overlap: clients keep working mid-replacement.
    LiveReplace,
    /// The worker was already drained: replace freely.
    ReplaceAfterDrain,
}

/// Typed upgrade refusals.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpgradeRefusal {
    /// Incompatible replacement with jobs still in flight.
    DrainRequired {
        /// Jobs that must finish or migrate first.
        in_flight: u32,
    },
    /// Rollback target is below the coordinator's floor.
    RollbackPastCompatibilityFloor {
        /// The refused target version.
        target: u32,
        /// The coordinator's minimum.
        floor: u32,
    },
    /// Migration without a backup.
    MigrationBackupMissing,
    /// Migration without a clean differential check.
    MigrationDifferentialNotClean,
}

/// Admit a worker replacement.
///
/// # Errors
/// [`UpgradeRefusal::DrainRequired`] when the new version cannot
/// negotiate with what in-flight clients speak and jobs remain.
pub fn admit_replacement(
    old: &VersionHello,
    new: &VersionHello,
    in_flight: u32,
) -> Result<Replacement, UpgradeRefusal> {
    match negotiate(old, new) {
        Negotiation::Agreed { .. } => Ok(Replacement::LiveReplace),
        Negotiation::Refused(_) => {
            if in_flight > 0 {
                Err(UpgradeRefusal::DrainRequired { in_flight })
            } else {
                Ok(Replacement::ReplaceAfterDrain)
            }
        }
    }
}

/// Admit a rollback to `target` under a coordinator's range.
///
/// # Errors
/// [`UpgradeRefusal::RollbackPastCompatibilityFloor`] when the
/// target is below what the coordinator still speaks.
pub const fn admit_rollback(target: u32, coordinator: VersionRange) -> Result<u32, UpgradeRefusal> {
    if target < coordinator.minimum_compatible {
        return Err(UpgradeRefusal::RollbackPastCompatibilityFloor {
            target,
            floor: coordinator.minimum_compatible,
        });
    }
    Ok(target)
}

/// Admit a DB migration.
///
/// # Errors
/// A typed refusal for a missing backup or an unclean differential.
pub const fn admit_migration(
    backup_taken: bool,
    differential_clean: bool,
) -> Result<(), UpgradeRefusal> {
    if !backup_taken {
        return Err(UpgradeRefusal::MigrationBackupMissing);
    }
    if !differential_clean {
        return Err(UpgradeRefusal::MigrationDifferentialNotClean);
    }
    Ok(())
}

/// Canary verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanaryDecision {
    /// Enough clean canaries: promote the upgrade fleet-wide.
    Promote,
    /// A canary failed (or too few ran): roll back.
    RollBack,
}

/// Judge canary results: `required` successes, ZERO failures.
#[must_use]
pub fn canary_verdict(results: &[bool], required: u32) -> CanaryDecision {
    let successes = u32::try_from(results.iter().filter(|r| **r).count()).unwrap_or(u32::MAX);
    let any_failure = results.iter().any(|r| !*r);
    if any_failure || successes < required {
        CanaryDecision::RollBack
    } else {
        CanaryDecision::Promote
    }
}

// ============================================================================
// Bead R012: operator rollback + canary orchestration + 14 feature modes
// ============================================================================

use crate::descriptor::ActionClass;
use crate::serving::TrustEvidenceTier;

/// The 14 rollout feature modes (bead R012; plan Part XVII / Part XXIII).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RabsFeatureMode {
    /// RABS completely disabled; stock RCH path only.
    Off,
    /// Record invocation corpus only; no key computation or remote execution.
    RecordOnly,
    /// Compute action keys in shadow alongside stock execution.
    ShadowKey,
    /// Execute shadow attempts and compare against stock path without serving.
    ShadowExecute,
    /// Serve verified third-party dependency compiles (`RustcDependencyCompile`).
    ServeDependencies,
    /// Serve selected workspace crates in addition to dependencies.
    ServeSelectedWorkspace,
    /// Serve all eligible cacheable compile actions.
    ServeAllEligible,
    /// Run coordinator remote-control plane in shadow alongside stock RCH.
    RemoteControlShadow,
    /// Enable native ATP control-plane sessions.
    NativeAtpControl,
    /// Enable native ATP data-plane object transfer.
    NativeAtpData,
    /// Enable bounded speculative execution on slack capacity.
    SpeculationEnabled,
    /// Enable cached test execution for eligible deterministic suites.
    TestsEnabled,
    /// Enable lineage-verified incremental filesystem snapshots.
    IncrementalSnapshotsEnabled,
    /// Require remote RABS execution (refuse silent local fallback except fail-open emergencies).
    RequireRemote,
}

/// Complete registry of the 14 RABS rollout feature modes (bead R012).
pub const ALL_FEATURE_MODES: [RabsFeatureMode; 14] = [
    RabsFeatureMode::Off,
    RabsFeatureMode::RecordOnly,
    RabsFeatureMode::ShadowKey,
    RabsFeatureMode::ShadowExecute,
    RabsFeatureMode::ServeDependencies,
    RabsFeatureMode::ServeSelectedWorkspace,
    RabsFeatureMode::ServeAllEligible,
    RabsFeatureMode::RemoteControlShadow,
    RabsFeatureMode::NativeAtpControl,
    RabsFeatureMode::NativeAtpData,
    RabsFeatureMode::SpeculationEnabled,
    RabsFeatureMode::TestsEnabled,
    RabsFeatureMode::IncrementalSnapshotsEnabled,
    RabsFeatureMode::RequireRemote,
];

impl RabsFeatureMode {
    /// Canonical CLI/config token for this feature mode.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::RecordOnly => "record-only",
            Self::ShadowKey => "shadow-key",
            Self::ShadowExecute => "shadow-execute",
            Self::ServeDependencies => "serve-dependencies",
            Self::ServeSelectedWorkspace => "serve-selected-workspace",
            Self::ServeAllEligible => "serve-all-eligible",
            Self::RemoteControlShadow => "remote-control-shadow",
            Self::NativeAtpControl => "native-atp-control",
            Self::NativeAtpData => "native-atp-data",
            Self::SpeculationEnabled => "speculation-enabled",
            Self::TestsEnabled => "tests-enabled",
            Self::IncrementalSnapshotsEnabled => "incremental-snapshots-enabled",
            Self::RequireRemote => "require-remote",
        }
    }

    /// Parse a feature mode from its canonical CLI/config token.
    #[must_use]
    pub fn from_token(token: &str) -> Option<Self> {
        ALL_FEATURE_MODES.into_iter().find(|m| m.as_str() == token)
    }
}

/// Independent override scope for feature-mode control (per repo, action class, worker, or trust tier).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FeatureModeScope {
    /// Repository identifier override.
    Repo(String),
    /// Action class override.
    ActionClass(ActionClass),
    /// Worker node ID override.
    Worker(u64),
    /// Trust evidence tier override.
    TrustTier(TrustEvidenceTier),
}

/// Scoped feature-mode matrix with one-command rollback history (bead R012).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopedFeatureModeMatrix {
    /// Global default mode.
    pub default_mode: RabsFeatureMode,
    /// Prior global mode preserved for one-command rollback.
    pub prior_default_mode: RabsFeatureMode,
    /// Scoped overrides evaluated in specificity order (Worker -> TrustTier -> ActionClass -> Repo).
    pub overrides: Vec<(FeatureModeScope, RabsFeatureMode)>,
    /// Snapshot of overrides prior to the most recent promotion/edit.
    pub prior_overrides: Vec<(FeatureModeScope, RabsFeatureMode)>,
}

impl Default for ScopedFeatureModeMatrix {
    fn default() -> Self {
        Self {
            default_mode: RabsFeatureMode::Off,
            prior_default_mode: RabsFeatureMode::Off,
            overrides: Vec::new(),
            prior_overrides: Vec::new(),
        }
    }
}

impl ScopedFeatureModeMatrix {
    /// Transition the global mode while checkpointing current state for one-command rollback.
    pub fn transition_default_mode(&mut self, next_mode: RabsFeatureMode) {
        self.prior_default_mode = self.default_mode;
        self.prior_overrides.clone_from(&self.overrides);
        self.default_mode = next_mode;
    }

    /// Set or replace a scoped feature-mode override while preserving rollback state.
    pub fn set_scoped_override(&mut self, scope: FeatureModeScope, mode: RabsFeatureMode) {
        self.prior_default_mode = self.default_mode;
        self.prior_overrides.clone_from(&self.overrides);
        if let Some((_, existing)) = self.overrides.iter_mut().find(|(s, _)| *s == scope) {
            *existing = mode;
        } else {
            self.overrides.push((scope, mode));
        }
    }

    /// Resolve the effective feature mode for a `(repo, action_class, worker_id, trust_tier)` tuple.
    #[must_use]
    pub fn resolve(
        &self,
        repo: &str,
        action_class: ActionClass,
        worker_id: u64,
        trust_tier: TrustEvidenceTier,
    ) -> RabsFeatureMode {
        for (scope, mode) in &self.overrides {
            if matches!(scope, FeatureModeScope::Worker(id) if *id == worker_id) {
                return *mode;
            }
        }
        for (scope, mode) in &self.overrides {
            if matches!(scope, FeatureModeScope::TrustTier(t) if *t == trust_tier) {
                return *mode;
            }
        }
        for (scope, mode) in &self.overrides {
            if matches!(scope, FeatureModeScope::ActionClass(c) if *c == action_class) {
                return *mode;
            }
        }
        for (scope, mode) in &self.overrides {
            if matches!(scope, FeatureModeScope::Repo(r) if r == repo) {
                return *mode;
            }
        }
        self.default_mode
    }

    /// Execute a one-command rollback to the prior global mode and scoped override snapshot.
    pub fn execute_one_command_rollback(&mut self) -> RabsFeatureMode {
        self.default_mode = self.prior_default_mode;
        self.overrides.clone_from(&self.prior_overrides);
        self.default_mode
    }
}

/// Incident classes that immediately quarantine the canary and trigger rollback (bead R012).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanaryIncidentTrigger {
    /// Sandbox/process/temp cleanup leak or orphan detected.
    CleanupIncident,
    /// CAS object digest mismatch or corruption detected.
    CorruptionIncident,
    /// Worker or peer cryptographic identity mismatch detected.
    IdentityIncident,
    /// Output or semantic divergence vs baseline RCH path detected.
    DivergenceIncident,
    /// Canary latency exceeded the allowed regression ceiling vs baseline RCH path.
    PerformanceRegression,
}

/// One differential perf/correctness sample comparing canary execution against current RCH path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CanaryComparisonSample {
    /// Action class executed on the canary path.
    pub action_class: ActionClass,
    /// Baseline RCH execution latency in milliseconds.
    pub baseline_rch_latency_ms: u64,
    /// Canary RABS execution latency in milliseconds.
    pub canary_rabs_latency_ms: u64,
    /// Whether outputs and exit semantics matched the baseline RCH path.
    pub correctness_matched: bool,
    /// Whether any cleanup leak occurred.
    pub cleanup_incident: bool,
    /// Whether any CAS corruption occurred.
    pub corruption_incident: bool,
    /// Whether any worker identity mismatch occurred.
    pub identity_incident: bool,
    /// Whether any semantic divergence occurred.
    pub divergence_incident: bool,
}

/// Outcome of canary orchestration evaluation (bead R012).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CanaryOrchestrationOutcome {
    /// Canary succeeded with low-risk dependency routing and clean perf/correctness; promoted.
    Promoted {
        /// Newly active feature mode after promotion.
        promoted_to: RabsFeatureMode,
        /// Number of verified canary samples evaluated.
        samples_evaluated: usize,
    },
    /// Canary quarantined and rolled back to the prior mode in one command.
    QuarantinedAndRolledBack {
        /// Trigger that caused quarantine and rollback.
        trigger: CanaryIncidentTrigger,
        /// Restored feature mode after one-command rollback.
        restored_mode: RabsFeatureMode,
        /// Quarantined canary worker IDs.
        quarantined_workers: Vec<u64>,
    },
}

/// Canary coordinator + worker cohort orchestrator (bead R012).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanaryOrchestrator {
    /// Designated canary coordinator ID.
    pub canary_coordinator_id: u64,
    /// Designated canary worker IDs.
    pub canary_worker_ids: Vec<u64>,
    /// Quarantined worker IDs removed from scheduling on canary incident.
    pub quarantined_worker_ids: Vec<u64>,
    /// Maximum allowed canary latency ratio in permille of baseline (`1050` = +5%).
    pub max_latency_ratio_permille: u32,
    /// Minimum required clean samples before promotion.
    pub min_required_samples: usize,
    /// Scoped feature-mode matrix governed by this orchestrator.
    pub mode_matrix: ScopedFeatureModeMatrix,
}

impl CanaryOrchestrator {
    /// Whether an action + worker pair should route through the canary lane first.
    ///
    /// Low-risk third-party dependency compiles (`RustcDependencyCompile`) on designated
    /// non-quarantined canary workers are routed first.
    #[must_use]
    pub fn should_route_to_canary(&self, action_class: ActionClass, worker_id: u64) -> bool {
        action_class == ActionClass::RustcDependencyCompile
            && self.canary_worker_ids.contains(&worker_id)
            && !self.quarantined_worker_ids.contains(&worker_id)
    }

    /// Evaluate canary comparison samples and either promote to `target_mode` or quarantine
    /// the canary cohort and execute a one-command rollback.
    pub fn evaluate_and_orchestrate(
        &mut self,
        samples: &[CanaryComparisonSample],
        target_mode: RabsFeatureMode,
    ) -> CanaryOrchestrationOutcome {
        let mut baseline_sum_ms = 0_u64;
        let mut canary_sum_ms = 0_u64;

        for sample in samples {
            let trigger = if sample.cleanup_incident {
                Some(CanaryIncidentTrigger::CleanupIncident)
            } else if sample.corruption_incident {
                Some(CanaryIncidentTrigger::CorruptionIncident)
            } else if sample.identity_incident {
                Some(CanaryIncidentTrigger::IdentityIncident)
            } else if sample.divergence_incident || !sample.correctness_matched {
                Some(CanaryIncidentTrigger::DivergenceIncident)
            } else {
                None
            };
            if let Some(trigger) = trigger {
                return self.quarantine_and_rollback(trigger);
            }
            baseline_sum_ms = baseline_sum_ms.saturating_add(sample.baseline_rch_latency_ms);
            canary_sum_ms = canary_sum_ms.saturating_add(sample.canary_rabs_latency_ms);
        }

        if samples.len() < self.min_required_samples {
            return self.quarantine_and_rollback(CanaryIncidentTrigger::PerformanceRegression);
        }

        if baseline_sum_ms > 0
            && canary_sum_ms.saturating_mul(1_000)
                > baseline_sum_ms.saturating_mul(u64::from(self.max_latency_ratio_permille))
        {
            return self.quarantine_and_rollback(CanaryIncidentTrigger::PerformanceRegression);
        }

        self.mode_matrix.transition_default_mode(target_mode);
        CanaryOrchestrationOutcome::Promoted {
            promoted_to: target_mode,
            samples_evaluated: samples.len(),
        }
    }

    /// Quarantine canary workers and execute a one-command rollback to the prior mode.
    pub fn quarantine_and_rollback(
        &mut self,
        trigger: CanaryIncidentTrigger,
    ) -> CanaryOrchestrationOutcome {
        for &worker_id in &self.canary_worker_ids {
            if !self.quarantined_worker_ids.contains(&worker_id) {
                self.quarantined_worker_ids.push(worker_id);
            }
        }
        let restored_mode = self.mode_matrix.execute_one_command_rollback();
        CanaryOrchestrationOutcome::QuarantinedAndRolledBack {
            trigger,
            restored_mode,
            quarantined_workers: self.quarantined_worker_ids.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compat_doctor::{NodeReport, diagnose};

    /// Hello at application version `v` (N-1 floor), transport 2.
    fn hello(v: u32) -> VersionHello {
        VersionHello {
            transport: VersionRange {
                minimum_compatible: 1,
                current: 2,
            },
            application: VersionRange {
                minimum_compatible: v.saturating_sub(1).max(1),
                current: v,
            },
        }
    }

    fn node(node_id: u64, app: u32) -> NodeReport {
        NodeReport {
            node_id,
            hello: hello(app),
            schema_fingerprint: 0xFEED,
            wrapper_contract: 4,
        }
    }

    #[test]
    fn the_upgrade_matrix_is_green_through_every_intermediate_state() {
        // THE acceptance matrix: coordinator/edge/worker at every
        // N/N-1 combination of application v5/v6 — all nine
        // intermediate fleet states negotiate and diagnose healthy;
        // any node at N-2 (v4) refuses or flags.
        for coordinator_v in [5, 6] {
            for edge_v in [5, 6] {
                for worker_v in [5, 6] {
                    let coordinator = node(0, coordinator_v);
                    let fleet = [node(1, edge_v), node(2, worker_v)];
                    let report = diagnose(&coordinator, &fleet);
                    assert!(
                        report.healthy(),
                        "N/N-1 state ({coordinator_v},{edge_v},{worker_v}) must be green: \
                         {:?}",
                        report.findings
                    );
                }
            }
        }
        // N-2 in the mix: the doctor flags it (matrix edge).
        let report = diagnose(&node(0, 6), &[node(1, 4)]);
        assert!(!report.healthy(), "v6 coordinator + v4 node is not green");
    }

    #[test]
    fn incompatible_worker_replacement_requires_drain() {
        // Old worker speaks 4..=5; the replacement dropped v5 support
        // entirely (7..=8): in-flight clients would strand.
        let old = hello(5);
        let incompatible = VersionHello {
            transport: old.transport,
            application: VersionRange {
                minimum_compatible: 7,
                current: 8,
            },
        };
        assert_eq!(
            admit_replacement(&old, &incompatible, 12),
            Err(UpgradeRefusal::DrainRequired { in_flight: 12 })
        );
        // Drained: replacement admissible.
        assert_eq!(
            admit_replacement(&old, &incompatible, 0),
            Ok(Replacement::ReplaceAfterDrain)
        );
        // A compatible N/N-1 replacement goes live with jobs in
        // flight — live wrappers survive the upgrade.
        assert_eq!(
            admit_replacement(&hello(5), &hello(6), 12),
            Ok(Replacement::LiveReplace)
        );
    }

    #[test]
    fn rollback_stops_at_the_compatibility_floor() {
        let coordinator = VersionRange {
            minimum_compatible: 5,
            current: 6,
        };
        assert_eq!(admit_rollback(5, coordinator), Ok(5), "N-1 rollback fine");
        assert_eq!(
            admit_rollback(4, coordinator),
            Err(UpgradeRefusal::RollbackPastCompatibilityFloor {
                target: 4,
                floor: 5
            })
        );
    }

    #[test]
    fn migrations_require_backup_and_clean_differential() {
        assert_eq!(
            admit_migration(false, true),
            Err(UpgradeRefusal::MigrationBackupMissing)
        );
        assert_eq!(
            admit_migration(true, false),
            Err(UpgradeRefusal::MigrationDifferentialNotClean)
        );
        assert_eq!(admit_migration(true, true), Ok(()));
    }

    #[test]
    fn canaries_promote_only_clean_and_sufficient() {
        assert_eq!(
            canary_verdict(&[true, true, true], 3),
            CanaryDecision::Promote
        );
        // One failure rolls back regardless of successes.
        assert_eq!(
            canary_verdict(&[true, true, true, false], 3),
            CanaryDecision::RollBack
        );
        // Too few canaries is not promotion.
        assert_eq!(canary_verdict(&[true, true], 3), CanaryDecision::RollBack);
        assert_eq!(canary_verdict(&[], 1), CanaryDecision::RollBack);
    }

    #[test]
    fn key_and_projection_epochs_are_separate_from_upgrades() {
        // Structural: NO type in the upgrade path carries an epoch —
        // NodeReport's exhaustive destructure proves an application
        // upgrade has no epoch field to touch. Epochs move only by
        // explicit F002 bumps in the descriptor.
        let NodeReport {
            node_id: _,
            hello: _,
            schema_fingerprint: _,
            wrapper_contract: _,
        } = node(1, 6); // a new field lands here for review first
    }

    #[test]
    fn r012_canary_orchestration_feature_modes_and_one_command_rollback_rehearsed() {
        assert_eq!(ALL_FEATURE_MODES.len(), 14);
        for mode in ALL_FEATURE_MODES {
            assert_eq!(RabsFeatureMode::from_token(mode.as_str()), Some(mode));
        }

        let mut matrix = ScopedFeatureModeMatrix {
            default_mode: RabsFeatureMode::ShadowExecute,
            prior_default_mode: RabsFeatureMode::ShadowKey,
            overrides: Vec::new(),
            prior_overrides: Vec::new(),
        };
        matrix.set_scoped_override(
            FeatureModeScope::Repo("repo-alpha".to_owned()),
            RabsFeatureMode::ServeDependencies,
        );
        matrix.set_scoped_override(
            FeatureModeScope::ActionClass(ActionClass::RustcWorkspaceCompile),
            RabsFeatureMode::ServeSelectedWorkspace,
        );
        matrix.set_scoped_override(
            FeatureModeScope::TrustTier(TrustEvidenceTier::ReproducibleCrossWorker),
            RabsFeatureMode::ServeAllEligible,
        );
        matrix.set_scoped_override(FeatureModeScope::Worker(99), RabsFeatureMode::RecordOnly);

        // Specificity order: Worker -> TrustTier -> ActionClass -> Repo -> default.
        assert_eq!(
            matrix.resolve(
                "repo-alpha",
                ActionClass::RustcWorkspaceCompile,
                99,
                TrustEvidenceTier::ReproducibleCrossWorker,
            ),
            RabsFeatureMode::RecordOnly
        );
        assert_eq!(
            matrix.resolve(
                "repo-alpha",
                ActionClass::RustcWorkspaceCompile,
                10,
                TrustEvidenceTier::ReproducibleCrossWorker,
            ),
            RabsFeatureMode::ServeAllEligible
        );
        assert_eq!(
            matrix.resolve(
                "repo-alpha",
                ActionClass::RustcWorkspaceCompile,
                10,
                TrustEvidenceTier::ShadowMatched,
            ),
            RabsFeatureMode::ServeSelectedWorkspace
        );
        assert_eq!(
            matrix.resolve(
                "repo-alpha",
                ActionClass::RustcDependencyCompile,
                10,
                TrustEvidenceTier::ShadowMatched,
            ),
            RabsFeatureMode::ServeDependencies
        );

        let mut orchestrator = CanaryOrchestrator {
            canary_coordinator_id: 1,
            canary_worker_ids: vec![101, 102],
            quarantined_worker_ids: Vec::new(),
            max_latency_ratio_permille: 1_050,
            min_required_samples: 2,
            mode_matrix: matrix,
        };

        // Low-risk dependency compiles on canary workers route first; workspace compiles do not.
        assert!(orchestrator.should_route_to_canary(ActionClass::RustcDependencyCompile, 101));
        assert!(!orchestrator.should_route_to_canary(ActionClass::RustcWorkspaceCompile, 101));
        assert!(!orchestrator.should_route_to_canary(ActionClass::RustcDependencyCompile, 202));

        // Clean canary samples promote to ServeDependencies.
        let clean_samples = [
            CanaryComparisonSample {
                action_class: ActionClass::RustcDependencyCompile,
                baseline_rch_latency_ms: 400,
                canary_rabs_latency_ms: 360,
                correctness_matched: true,
                cleanup_incident: false,
                corruption_incident: false,
                identity_incident: false,
                divergence_incident: false,
            },
            CanaryComparisonSample {
                action_class: ActionClass::RustcDependencyCompile,
                baseline_rch_latency_ms: 500,
                canary_rabs_latency_ms: 450,
                correctness_matched: true,
                cleanup_incident: false,
                corruption_incident: false,
                identity_incident: false,
                divergence_incident: false,
            },
        ];
        assert_eq!(
            orchestrator
                .evaluate_and_orchestrate(&clean_samples, RabsFeatureMode::ServeDependencies),
            CanaryOrchestrationOutcome::Promoted {
                promoted_to: RabsFeatureMode::ServeDependencies,
                samples_evaluated: 2,
            }
        );
        assert_eq!(
            orchestrator.mode_matrix.default_mode,
            RabsFeatureMode::ServeDependencies
        );

        // Next canary wave encounters a divergence incident -> immediate quarantine + one-command rollback.
        let divergence_samples = [CanaryComparisonSample {
            action_class: ActionClass::RustcDependencyCompile,
            baseline_rch_latency_ms: 400,
            canary_rabs_latency_ms: 350,
            correctness_matched: false,
            cleanup_incident: false,
            corruption_incident: false,
            identity_incident: false,
            divergence_incident: true,
        }];
        assert_eq!(
            orchestrator
                .evaluate_and_orchestrate(&divergence_samples, RabsFeatureMode::ServeAllEligible,),
            CanaryOrchestrationOutcome::QuarantinedAndRolledBack {
                trigger: CanaryIncidentTrigger::DivergenceIncident,
                restored_mode: RabsFeatureMode::ShadowExecute,
                quarantined_workers: vec![101, 102],
            }
        );
        assert_eq!(
            orchestrator.mode_matrix.default_mode,
            RabsFeatureMode::ShadowExecute
        );
        // Quarantined canary workers are no longer routed canary work.
        assert!(!orchestrator.should_route_to_canary(ActionClass::RustcDependencyCompile, 101));
    }
}
