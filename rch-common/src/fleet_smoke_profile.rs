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
/// Per-scenario decision, in the order the implementation checks them (first
/// match wins; the guards are mutually exclusive, so the order only documents
/// intent):
/// 1. The proof-mode refusal scenario: when remote execution is available ->
///    `Skip(remote_available)` (cannot exercise); otherwise ->
///    `ExpectRefusal(proof_refusal_expected)` (even under dry-run, since asserting
///    the refusal does not run a remote build).
/// 2. A real-worker scenario with no workers configured -> `Skip(no_real_workers)`.
/// 3. A `--worker`-scoped run drops the fleet-wide `DesiredVsLiveFleet` scenario
///    -> `Skip(not_selected)`.
/// 4. `--dry-run` -> `DryRun`.
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

    /// A `started` event emitted immediately before the consumer executes a
    /// scenario against a worker (live runner only — a dry-run never starts).
    /// `worker_id` is preserved only for scenarios that pertain to a worker.
    #[must_use]
    pub fn started(
        run_id: impl Into<String>,
        bead_id: impl Into<String>,
        worker_id: Option<String>,
        scenario: SmokeScenario,
    ) -> Self {
        Self {
            run_id: run_id.into(),
            bead_id: bead_id.into(),
            worker_id: worker_id.filter(|_| scenario.requires_real_worker()),
            scenario: scenario.as_str().to_string(),
            event: "started".to_string(),
            status: "run".to_string(),
            reason_code: None,
            command_fingerprint: None,
            duration_ms: 0,
            remote_target_dir: None,
            artifact_summary: None,
        }
    }

    /// A terminal `passed`/`failed` outcome event after the consumer executed a
    /// scenario. `passed` selects the `passed`/`ok` vs `failed`/`fail`
    /// event/status tokens; `reason_code` carries the failure reason (`None` on
    /// success); `command_fingerprint` is the redacted command that ran, if any.
    #[must_use]
    #[allow(clippy::too_many_arguments)] // one param per JSONL field the outcome carries
    pub fn outcome(
        run_id: impl Into<String>,
        bead_id: impl Into<String>,
        worker_id: Option<String>,
        scenario: SmokeScenario,
        passed: bool,
        reason_code: Option<String>,
        command_fingerprint: Option<String>,
        duration_ms: u64,
    ) -> Self {
        Self {
            run_id: run_id.into(),
            bead_id: bead_id.into(),
            worker_id: worker_id.filter(|_| scenario.requires_real_worker()),
            scenario: scenario.as_str().to_string(),
            event: if passed { "passed" } else { "failed" }.to_string(),
            status: if passed { "ok" } else { "fail" }.to_string(),
            // A passing scenario never carries a failure reason.
            reason_code: reason_code.filter(|_| !passed),
            command_fingerprint,
            duration_ms,
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

    #[test]
    fn scenario_action_variants_round_trip() {
        // The internally-tagged `ScenarioAction` must round-trip every variant,
        // including the UNIT variants (Run/DryRun) — a classic serde footgun for
        // `#[serde(tag = ...)]` enums.
        let variants = [
            ScenarioAction::Run,
            ScenarioAction::DryRun,
            ScenarioAction::Skip {
                reason_code: reason_code::NO_REAL_WORKERS.to_string(),
                detail: "d".to_string(),
            },
            ScenarioAction::ExpectRefusal {
                reason_code: reason_code::PROOF_REFUSAL_EXPECTED.to_string(),
                detail: "d".to_string(),
            },
        ];
        for action in variants {
            let json = serde_json::to_string(&action).unwrap();
            let back: ScenarioAction = serde_json::from_str(&json).unwrap();
            assert_eq!(action, back, "round-trip failed for {json}");
        }
        // The unit variant carries the snake_case action tag and nothing else.
        assert_eq!(
            serde_json::to_string(&ScenarioAction::Run).unwrap(),
            "{\"action\":\"run\"}"
        );
    }

    #[test]
    fn started_event_marks_run_and_scopes_worker() {
        let ev = SmokeProfileEvent::started(
            "run-3",
            "bd-...-16.6",
            Some("css".into()),
            SmokeScenario::WorkerCapabilitiesExactUserPath,
        );
        assert_eq!(ev.event, "started");
        assert_eq!(ev.status, "run");
        assert_eq!(ev.scenario, "worker_capabilities_exact_user_path");
        assert_eq!(ev.worker_id.as_deref(), Some("css"));
        assert_eq!(ev.duration_ms, 0);
        assert!(ev.reason_code.is_none());
        // A worker-id passed for a daemon-only scenario is dropped.
        let daemon = SmokeProfileEvent::started(
            "run-3",
            "bd-...-16.6",
            Some("css".into()),
            SmokeScenario::DaemonReachable,
        );
        assert_eq!(daemon.worker_id, None);
    }

    #[test]
    fn outcome_passed_drops_reason_and_sets_ok_tokens() {
        let ev = SmokeProfileEvent::outcome(
            "run-4",
            "bd-...-16.6",
            Some("hz1".into()),
            SmokeScenario::DiskInodeAdmission,
            true,
            // A stray reason code on a pass must be dropped.
            Some("disk_pressure_critical".into()),
            Some("df -Pk".into()),
            42,
        );
        assert_eq!(ev.event, "passed");
        assert_eq!(ev.status, "ok");
        assert_eq!(ev.reason_code, None);
        assert_eq!(ev.command_fingerprint.as_deref(), Some("df -Pk"));
        assert_eq!(ev.duration_ms, 42);
        assert_eq!(ev.worker_id.as_deref(), Some("hz1"));
    }

    #[test]
    fn outcome_failed_keeps_reason_and_sets_fail_tokens() {
        let ev = SmokeProfileEvent::outcome(
            "run-5",
            "bd-...-16.6",
            Some("hz1".into()),
            SmokeScenario::WorkerCapabilitiesExactUserPath,
            false,
            Some("wrong_user_path_worker_binary".into()),
            None,
            7,
        );
        assert_eq!(ev.event, "failed");
        assert_eq!(ev.status, "fail");
        assert_eq!(
            ev.reason_code.as_deref(),
            Some("wrong_user_path_worker_binary")
        );
        assert_eq!(ev.duration_ms, 7);
    }

    #[test]
    fn full_plan_round_trips() {
        // A whole plan (with mixed action variants across the 8 scenarios) must
        // survive a serde round-trip for `rch self-test --json`.
        let plan = plan_smoke_profile(&SmokeProfileInputs::no_workers());
        let json = serde_json::to_string(&plan).unwrap();
        let back: SmokeProfilePlan = serde_json::from_str(&json).unwrap();
        assert_eq!(plan, back);
    }
}
