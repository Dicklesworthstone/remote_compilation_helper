//! Real-fleet smoke and soak validation profile planning
//! (bd-session-history-remediation-ocv9i.16.6).
//!
//! Mock-worker E2E proves logic in CI; operators also need a controlled way to
//! verify an ACTUAL worker fleet after deploy, after disk-pressure recovery,
//! after a fleet update, and before trusting proof results. This module is the
//! pure, deterministic foundation for that profile: given what the environment
//! looks like (workers configured? can remote execution proceed? dry-run? which
//! worker/scenarios requested?), it decides WHICH scenarios run, which SKIP (and
//! why), and which are EXPECTED to refuse (proof-mode fail-closed) — the bead's
//! "profile planning and skip/refusal logic" unit-test target.
//!
//! The actual SSH execution of each scenario, the `rch self-test` CLI flags
//! (`--dry-run`/`--worker`/`--all`/`--timeout`/`--json`), and mock-SSH
//! integration live in the rch consumer; this layer stays pure and exhaustively
//! testable (same house style as [`crate::fleet_provenance`]). It also defines
//! the structured [`SmokeProfileEvent`] JSONL record operators attach to bead
//! close reasons.

use serde::{Deserialize, Serialize};

/// Stable reason-code tokens for skip/refusal planning outcomes.
///
/// Append-only: dashboards, the validation matrix, and the JSONL log key off
/// these exact strings.
pub mod reason_code {
    /// No real workers are configured, so a real-fleet scenario is skipped.
    pub const NO_REAL_WORKERS: &str = "smoke_no_real_workers";
    /// `--dry-run`: the scenario is planned but not executed.
    pub const DRY_RUN: &str = "smoke_dry_run";
    /// The proof-mode refusal scenario cannot be exercised because remote
    /// execution IS available (nothing to refuse).
    pub const REMOTE_AVAILABLE: &str = "smoke_remote_available";
    /// The proof-mode refusal scenario is expected to fail closed because
    /// remote execution is unavailable.
    pub const PROOF_REFUSAL_EXPECTED: &str = "smoke_proof_refusal_expected";
    /// The scenario was filtered out because a single `--worker` was selected
    /// and this scenario is fleet-wide.
    pub const NOT_SELECTED: &str = "smoke_not_selected";
}

/// The bounded set of checks a real-fleet smoke/soak run performs, in run order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SmokeScenario {
    /// Daemon Unix socket is reachable and responds.
    DaemonReachable,
    /// Desired vs live fleet inventory is consistent.
    DesiredVsLiveFleet,
    /// Worker capabilities probe as the EXACT configured user/path.
    WorkerCapabilitiesExactUserPath,
    /// Disk and inode admission headroom on the worker build root.
    DiskInodeAdmission,
    /// A tiny `cargo check`/`test` canary builds remotely.
    CargoCanary,
    /// Artifacts are retrieved under the effective target dir.
    ArtifactRetrieval,
    /// A queued job can be attached to and cancelled.
    QueueAttachCancel,
    /// Proof-mode refuses (fail-closed) when remote execution is unavailable.
    ProofModeRefusal,
}

impl SmokeScenario {
    /// Every scenario in stable run order.
    pub const ALL: &'static [SmokeScenario] = &[
        Self::DaemonReachable,
        Self::DesiredVsLiveFleet,
        Self::WorkerCapabilitiesExactUserPath,
        Self::DiskInodeAdmission,
        Self::CargoCanary,
        Self::ArtifactRetrieval,
        Self::QueueAttachCancel,
        Self::ProofModeRefusal,
    ];

    /// Stable token for logs / JSONL.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DaemonReachable => "daemon_reachable",
            Self::DesiredVsLiveFleet => "desired_vs_live_fleet",
            Self::WorkerCapabilitiesExactUserPath => "worker_capabilities_exact_user_path",
            Self::DiskInodeAdmission => "disk_inode_admission",
            Self::CargoCanary => "cargo_canary",
            Self::ArtifactRetrieval => "artifact_retrieval",
            Self::QueueAttachCancel => "queue_attach_cancel",
            Self::ProofModeRefusal => "proof_mode_refusal",
        }
    }

    /// Whether the scenario needs a live worker to execute. `DaemonReachable`
    /// (a local daemon check) and `ProofModeRefusal` (which asserts a fail-closed
    /// refusal — it needs the ABSENCE of an available remote, not a live worker)
    /// do not; every scenario that probes or builds on a worker does. This is
    /// what makes the real-fleet validation "skipped" when no workers exist.
    #[must_use]
    pub const fn requires_real_worker(self) -> bool {
        !matches!(self, Self::DaemonReachable | Self::ProofModeRefusal)
    }
}

/// Whether this is a one-pass smoke run or a bounded repeated soak run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileMode {
    /// One pass over the scenarios.
    Smoke,
    /// Bounded, repeated passes (the repetition is the consumer's job; the
    /// plan is identical per pass).
    Soak,
}

/// Inputs that determine the plan. All booleans/values are observed by the
/// consumer (config + daemon state) and passed in so planning stays pure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmokeProfileInputs {
    /// At least one real worker is configured.
    pub workers_configured: bool,
    /// Remote execution can currently proceed (a worker is admissible). When
    /// false, the proof-mode refusal scenario is exercised; when true it cannot
    /// be (nothing to refuse).
    pub remote_execution_available: bool,
    /// `--dry-run`: plan only, execute nothing.
    pub dry_run: bool,
    /// Smoke (one pass) vs soak (repeated).
    pub mode: ProfileMode,
    /// A single `--worker` target; `None` means all configured workers.
    pub selected_worker: Option<String>,
}

impl SmokeProfileInputs {
    /// The common "no workers configured" case (e.g. a fresh dev box): every
    /// real-worker scenario is skipped (so `overall_skipped` is true), though the
    /// local daemon check and the proof-mode refusal still run.
    #[must_use]
    pub fn no_workers() -> Self {
        Self {
            workers_configured: false,
            remote_execution_available: false,
            dry_run: false,
            mode: ProfileMode::Smoke,
            selected_worker: None,
        }
    }
}

/// The planned action for one scenario.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum ScenarioAction {
    /// Execute the scenario against a real worker.
    Run,
    /// Plan only; do not execute (`--dry-run`).
    DryRun,
    /// Skip with a stable reason.
    Skip { reason_code: String, detail: String },
    /// Execute and assert that it fails closed (proof-mode refusal).
    ExpectRefusal { reason_code: String, detail: String },
}

impl ScenarioAction {
    /// Whether the consumer will actually perform SSH work for this scenario.
    #[must_use]
    pub fn is_executed(&self) -> bool {
        matches!(self, Self::Run | Self::ExpectRefusal { .. })
    }

    /// Stable status token for the JSONL event.
    #[must_use]
    pub fn status_token(&self) -> &'static str {
        match self {
            Self::Run => "run",
            Self::DryRun => "dry_run",
            Self::Skip { .. } => "skip",
            Self::ExpectRefusal { .. } => "expect_refusal",
        }
    }

    /// Reason-code token, if any.
    #[must_use]
    pub fn reason_code(&self) -> Option<&str> {
        match self {
            Self::Run | Self::DryRun => None,
            Self::Skip { reason_code, .. } | Self::ExpectRefusal { reason_code, .. } => {
                Some(reason_code.as_str())
            }
        }
    }
}

/// One scenario paired with its planned action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlannedScenario {
    pub scenario: SmokeScenario,
    pub action: ScenarioAction,
}

/// The full plan for a smoke/soak run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SmokeProfilePlan {
    pub mode: ProfileMode,
    pub selected_worker: Option<String>,
    pub scenarios: Vec<PlannedScenario>,
    /// True when no real-WORKER scenario executed — i.e. the real-fleet
    /// validation was skipped (e.g. no workers configured, or a full
    /// `--dry-run`). The local daemon-reachability and proof-mode-refusal checks
    /// may still have run; this flags specifically that the fleet was not
    /// exercised, so the consumer reports a clean SKIP rather than a pass/fail.
    pub overall_skipped: bool,
}

impl SmokeProfilePlan {
    /// Count of scenarios the consumer will actually execute.
    #[must_use]
    pub fn executed_count(&self) -> usize {
        self.scenarios
            .iter()
            .filter(|p| p.action.is_executed())
            .count()
    }
}

/// Plan a smoke/soak run from observed inputs. Pure and total.
///
/// Per-scenario decision (first match wins):
/// 1. A real-worker scenario with no workers configured -> `Skip(no_real_workers)`.
/// 2. The proof-mode refusal scenario: when remote execution is available ->
///    `Skip(remote_available)` (cannot exercise); otherwise ->
///    `ExpectRefusal(proof_refusal_expected)` (even under dry-run, since asserting
///    the refusal does not run a remote build).
/// 3. `--dry-run` -> `DryRun`.
/// 4. A `--worker`-scoped run drops the fleet-wide `DesiredVsLiveFleet` scenario
///    -> `Skip(not_selected)`.
/// 5. Otherwise -> `Run`.
#[must_use]
pub fn plan_smoke_profile(inputs: &SmokeProfileInputs) -> SmokeProfilePlan {
    let scenarios = SmokeScenario::ALL
        .iter()
        .map(|&scenario| PlannedScenario {
            scenario,
            action: plan_scenario(scenario, inputs),
        })
        .collect::<Vec<_>>();

    // The real-fleet validation is "skipped" when no scenario that genuinely
    // needs a live worker executed — even if the local daemon check and the
    // proof-mode refusal still ran. The consumer reports a clean SKIP (not a
    // pass/fail) for fleet validation in that case.
    let overall_skipped = !scenarios
        .iter()
        .any(|p| p.scenario.requires_real_worker() && p.action.is_executed());

    SmokeProfilePlan {
        mode: inputs.mode,
        selected_worker: inputs.selected_worker.clone(),
        scenarios,
        overall_skipped,
    }
}

fn plan_scenario(scenario: SmokeScenario, inputs: &SmokeProfileInputs) -> ScenarioAction {
    // The proof-mode refusal scenario is special: it asserts a fail-closed
    // refusal rather than running a build, so it is decided before the
    // dry-run/worker gates and independently of whether workers are configured.
    if scenario == SmokeScenario::ProofModeRefusal {
        if inputs.remote_execution_available {
            return ScenarioAction::Skip {
                reason_code: reason_code::REMOTE_AVAILABLE.to_string(),
                detail: "remote execution is available, so proof-mode refusal cannot be exercised"
                    .to_string(),
            };
        }
        return ScenarioAction::ExpectRefusal {
            reason_code: reason_code::PROOF_REFUSAL_EXPECTED.to_string(),
            detail: "remote execution is unavailable; proof-mode must fail closed".to_string(),
        };
    }

    if scenario.requires_real_worker() && !inputs.workers_configured {
        return ScenarioAction::Skip {
            reason_code: reason_code::NO_REAL_WORKERS.to_string(),
            detail: "no real workers configured; real-fleet scenario skipped".to_string(),
        };
    }

    // A single-worker run cannot attribute the fleet-wide desired-vs-live check
    // to one worker.
    if inputs.selected_worker.is_some() && scenario == SmokeScenario::DesiredVsLiveFleet {
        return ScenarioAction::Skip {
            reason_code: reason_code::NOT_SELECTED.to_string(),
            detail: "fleet-wide scenario skipped under a single --worker selection".to_string(),
        };
    }

    if inputs.dry_run {
        return ScenarioAction::DryRun;
    }

    ScenarioAction::Run
}

/// A single structured JSONL event the consumer emits per scenario, carrying the
/// bead's exact field set so operators can attach the log to a Beads close
/// reason and CI can self-validate it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SmokeProfileEvent {
    /// Correlates every event of one profile run.
    pub run_id: String,
    /// Owning bead id.
    pub bead_id: String,
    /// Worker the event pertains to (`None` for daemon-only scenarios).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker_id: Option<String>,
    /// Scenario token (`SmokeScenario::as_str`).
    pub scenario: String,
    /// Lifecycle event: `planned` | `started` | `passed` | `failed` |
    /// `skipped` | `refused`.
    pub event: String,
    /// Outcome token: `run` | `dry_run` | `skip` | `expect_refusal` | `ok` |
    /// `fail`.
    pub status: String,
    /// Stable reason-code token, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<String>,
    /// Redacted command fingerprint, if the scenario ran a command.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command_fingerprint: Option<String>,
    /// Duration of the scenario in milliseconds.
    pub duration_ms: u64,
    /// Effective remote target dir, if applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_target_dir: Option<String>,
    /// Short artifact summary (e.g. file/byte counts), if applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_summary: Option<String>,
}

impl SmokeProfileEvent {
    /// A `planned` event derived from a [`PlannedScenario`] — the consumer emits
    /// one per scenario before execution so a dry-run still produces a complete,
    /// auditable JSONL trace.
    #[must_use]
    pub fn planned(
        run_id: impl Into<String>,
        bead_id: impl Into<String>,
        worker_id: Option<String>,
        planned: &PlannedScenario,
    ) -> Self {
        Self {
            run_id: run_id.into(),
            bead_id: bead_id.into(),
            worker_id: worker_id.filter(|_| planned.scenario.requires_real_worker()),
            scenario: planned.scenario.as_str().to_string(),
            event: "planned".to_string(),
            status: planned.action.status_token().to_string(),
            reason_code: planned.action.reason_code().map(ToString::to_string),
            command_fingerprint: None,
            duration_ms: 0,
            remote_target_dir: None,
            artifact_summary: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full_fleet() -> SmokeProfileInputs {
        SmokeProfileInputs {
            workers_configured: true,
            remote_execution_available: true,
            dry_run: false,
            mode: ProfileMode::Smoke,
            selected_worker: None,
        }
    }

    fn action_for(plan: &SmokeProfilePlan, scenario: SmokeScenario) -> &ScenarioAction {
        &plan
            .scenarios
            .iter()
            .find(|p| p.scenario == scenario)
            .expect("scenario present")
            .action
    }

    #[test]
    fn plan_covers_every_scenario_once_in_order() {
        let plan = plan_smoke_profile(&full_fleet());
        let got: Vec<_> = plan.scenarios.iter().map(|p| p.scenario).collect();
        assert_eq!(got, SmokeScenario::ALL.to_vec());
    }

    #[test]
    fn no_workers_skips_all_real_scenarios_and_marks_overall_skipped() {
        let plan = plan_smoke_profile(&SmokeProfileInputs::no_workers());
        // Daemon reachability still runs (it needs no worker); with remote
        // unavailable, proof refusal is EXPECTED. Every real-worker scenario
        // skips for lack of workers.
        assert_eq!(
            action_for(&plan, SmokeScenario::DaemonReachable),
            &ScenarioAction::Run
        );
        match action_for(&plan, SmokeScenario::CargoCanary) {
            ScenarioAction::Skip { reason_code, .. } => {
                assert_eq!(reason_code, super::reason_code::NO_REAL_WORKERS);
            }
            other => panic!("expected Skip(no_real_workers), got {other:?}"),
        }
        assert!(matches!(
            action_for(&plan, SmokeScenario::ProofModeRefusal),
            ScenarioAction::ExpectRefusal { .. }
        ));
        // No real-worker scenario executed -> the real-fleet validation is
        // skipped, even though the daemon and proof-refusal checks ran.
        assert!(plan.overall_skipped);
    }

    #[test]
    fn daemon_reachability_runs_even_with_no_workers_and_remote_available() {
        // No workers, but remote somehow available: daemon reachability still
        // runs, proof refusal is skipped (nothing to refuse), every per-worker
        // scenario skips. Exactly one scenario executes (the daemon check), but
        // since it needs no worker the real-fleet validation is still skipped.
        let inputs = SmokeProfileInputs {
            workers_configured: false,
            remote_execution_available: true,
            dry_run: false,
            mode: ProfileMode::Smoke,
            selected_worker: None,
        };
        let plan = plan_smoke_profile(&inputs);
        assert_eq!(
            action_for(&plan, SmokeScenario::DaemonReachable),
            &ScenarioAction::Run
        );
        assert!(matches!(
            action_for(&plan, SmokeScenario::ProofModeRefusal),
            ScenarioAction::Skip { .. }
        ));
        assert_eq!(plan.executed_count(), 1);
        // Only the (worker-less) daemon check ran -> real-fleet validation skipped.
        assert!(plan.overall_skipped);
    }

    #[test]
    fn full_dry_run_with_remote_available_executes_nothing() {
        // Dry-run plans every scenario but executes none; with remote available
        // proof refusal is skipped too -> overall_skipped is true.
        let inputs = SmokeProfileInputs {
            dry_run: true,
            remote_execution_available: true,
            ..full_fleet()
        };
        let plan = plan_smoke_profile(&inputs);
        assert_eq!(plan.executed_count(), 0);
        assert!(plan.overall_skipped);
    }

    #[test]
    fn dry_run_marks_buildy_scenarios_dry_but_still_asserts_proof_refusal() {
        let inputs = SmokeProfileInputs {
            dry_run: true,
            remote_execution_available: false,
            ..full_fleet()
        };
        let plan = plan_smoke_profile(&inputs);
        assert_eq!(
            action_for(&plan, SmokeScenario::CargoCanary),
            &ScenarioAction::DryRun
        );
        assert_eq!(
            action_for(&plan, SmokeScenario::DaemonReachable),
            &ScenarioAction::DryRun
        );
        // Proof refusal is asserted even under dry-run (it does not run a build).
        assert!(matches!(
            action_for(&plan, SmokeScenario::ProofModeRefusal),
            ScenarioAction::ExpectRefusal { .. }
        ));
    }

    #[test]
    fn proof_refusal_skipped_when_remote_available() {
        let plan = plan_smoke_profile(&full_fleet());
        match action_for(&plan, SmokeScenario::ProofModeRefusal) {
            ScenarioAction::Skip { reason_code, .. } => {
                assert_eq!(reason_code, super::reason_code::REMOTE_AVAILABLE);
            }
            other => panic!("expected Skip(remote_available), got {other:?}"),
        }
    }

    #[test]
    fn single_worker_selection_skips_fleet_wide_scenario() {
        let inputs = SmokeProfileInputs {
            selected_worker: Some("css".to_string()),
            ..full_fleet()
        };
        let plan = plan_smoke_profile(&inputs);
        match action_for(&plan, SmokeScenario::DesiredVsLiveFleet) {
            ScenarioAction::Skip { reason_code, .. } => {
                assert_eq!(reason_code, super::reason_code::NOT_SELECTED);
            }
            other => panic!("expected Skip(not_selected), got {other:?}"),
        }
        // Per-worker scenarios still run.
        assert_eq!(
            action_for(&plan, SmokeScenario::CargoCanary),
            &ScenarioAction::Run
        );
        assert_eq!(plan.selected_worker.as_deref(), Some("css"));
    }

    #[test]
    fn full_fleet_runs_all_per_worker_scenarios() {
        let plan = plan_smoke_profile(&full_fleet());
        assert_eq!(
            action_for(&plan, SmokeScenario::CargoCanary),
            &ScenarioAction::Run
        );
        assert_eq!(
            action_for(&plan, SmokeScenario::ArtifactRetrieval),
            &ScenarioAction::Run
        );
        assert_eq!(
            action_for(&plan, SmokeScenario::QueueAttachCancel),
            &ScenarioAction::Run
        );
        // 7 run scenarios + proof refusal skipped (remote available) = 7 executed.
        assert_eq!(plan.executed_count(), 7);
    }

    #[test]
    fn soak_mode_is_carried_into_the_plan() {
        let inputs = SmokeProfileInputs {
            mode: ProfileMode::Soak,
            ..full_fleet()
        };
        let plan = plan_smoke_profile(&inputs);
        assert_eq!(plan.mode, ProfileMode::Soak);
    }

    #[test]
    fn planned_event_carries_fields_and_omits_worker_for_daemon_scenario() {
        let plan = plan_smoke_profile(&full_fleet());
        let daemon = plan
            .scenarios
            .iter()
            .find(|p| p.scenario == SmokeScenario::DaemonReachable)
            .unwrap();
        let ev = SmokeProfileEvent::planned("run-1", "bd-...-16.6", Some("css".into()), daemon);
        // Daemon scenario is not worker-scoped, so worker_id is dropped.
        assert_eq!(ev.worker_id, None);
        assert_eq!(ev.scenario, "daemon_reachable");
        assert_eq!(ev.event, "planned");
        assert_eq!(ev.status, "run");

        let canary = plan
            .scenarios
            .iter()
            .find(|p| p.scenario == SmokeScenario::CargoCanary)
            .unwrap();
        let ev2 = SmokeProfileEvent::planned("run-1", "bd-...-16.6", Some("css".into()), canary);
        assert_eq!(ev2.worker_id.as_deref(), Some("css"));
    }

    #[test]
    fn event_serde_roundtrip_is_stable() {
        let ev = SmokeProfileEvent {
            run_id: "run-2".into(),
            bead_id: "bd-...-16.6".into(),
            worker_id: Some("hz1".into()),
            scenario: "cargo_canary".into(),
            event: "passed".into(),
            status: "ok".into(),
            reason_code: None,
            command_fingerprint: Some("cargo check".into()),
            duration_ms: 1234,
            remote_target_dir: Some("/tmp/rch/proj_hash".into()),
            artifact_summary: Some("5 files, 4.8MB".into()),
        };
        let json = serde_json::to_string(&ev).unwrap();
        let back: SmokeProfileEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(ev, back);
    }

    #[test]
    fn scenario_tokens_are_unique_and_stable() {
        let mut seen = std::collections::HashSet::new();
        for s in SmokeScenario::ALL {
            assert!(seen.insert(s.as_str()), "duplicate token {}", s.as_str());
        }
        assert_eq!(SmokeScenario::DaemonReachable.as_str(), "daemon_reachable");
    }
}
