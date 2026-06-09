//! Stuck-wrapper recovery: reattach / cancel / recover decisions
//! (bd-session-history-remediation-ocv9i.10.3).
//!
//! Session history showed local `rch exec` wrappers left blocked forever while
//! the remote side had already finished, vanished, been abandoned, or never made
//! it past admission — with no structured signal telling the agent what to do.
//! Building on the durable job identity (10.1) and the queue wait/stream/no-start
//! contract (10.2), this module answers the recovery question:
//!
//! > Given what we can observe about a job, is the local wrapper stuck, and if
//! > so which *safe* action (attach / cancel / recover) resolves it?
//!
//! The cardinal rule mirrors the queue contract: an agent must never be left
//! guessing. [`classify_stuck_wrapper`] is a **pure, total** function over
//! observable [`WrapperState`] signals, so the state machine is unit-tested
//! without a live daemon. [`diagnose_stuck_wrapper`] wraps it into a
//! [`StuckWrapperWarning`] — the structured JSON/human envelope that names the
//! stuck class, the recommended [`RecoveryAction`], the ledger-mappable
//! [`IncidentReasonCode`], and the exact safe commands offered to the agent.
//!
//! Wiring the `rch jobs attach|cancel|recover` CLI verbs and the daemon-side
//! cancel/reattach RPCs onto this contract is the follow-on integration layer;
//! this module establishes the decision contract both the client surface and the
//! incident ledger correlate against.

use serde::{Deserialize, Serialize};

use crate::incident::IncidentReasonCode;
use crate::job_identity::{JobIdentity, JobLifecycleState};

/// Observable signals about a job and its local wrapper, used to decide whether
/// the wrapper is stuck. Plain data so the classification is pure and total.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WrapperState {
    /// The remote lifecycle state correlated from job identity + heartbeat
    /// (see [`crate::job_identity::derive_job_lifecycle_state`]).
    pub job_state: JobLifecycleState,
    /// The local wrapper is still blocked (waiting/streaming) and has not exited.
    pub local_wrapper_waiting: bool,
    /// The daemon no longer recognizes the remote build id (it restarted or
    /// evicted the job), so there is no live stream to reattach to.
    pub remote_absent: bool,
    /// The job was admitted but its slot reservation/transport failed, so it can
    /// neither run nor be cleanly attached.
    pub reservation_failed_after_admission: bool,
    /// The build finished successfully but its artifacts were never retrieved
    /// to the local tree.
    pub artifacts_pending: bool,
}

impl WrapperState {
    /// A waiting wrapper over a job in `job_state` with no anomaly flags set.
    /// Anomaly signals (`remote_absent`, `reservation_failed_after_admission`,
    /// `artifacts_pending`) default to false; set them with the builders.
    #[must_use]
    pub fn waiting(job_state: JobLifecycleState) -> Self {
        Self {
            job_state,
            local_wrapper_waiting: true,
            remote_absent: false,
            reservation_failed_after_admission: false,
            artifacts_pending: false,
        }
    }

    /// The daemon lost track of this job (restart/eviction).
    #[must_use]
    pub fn remote_absent(mut self) -> Self {
        self.remote_absent = true;
        self
    }

    /// Slot reservation/transport failed after the job was admitted.
    #[must_use]
    pub fn reservation_failed(mut self) -> Self {
        self.reservation_failed_after_admission = true;
        self
    }

    /// Build finished but artifacts have not been retrieved.
    #[must_use]
    pub fn artifacts_pending(mut self) -> Self {
        self.artifacts_pending = true;
        self
    }

    /// The wrapper already resolved (no longer blocked).
    #[must_use]
    pub fn not_waiting(mut self) -> Self {
        self.local_wrapper_waiting = false;
        self
    }
}

/// Why a local wrapper is (or isn't) stuck. Derived purely from [`WrapperState`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StuckClass {
    /// Not stuck — the remote job is healthy (queued/running, fresh) and the
    /// wrapper is legitimately waiting, or the wrapper already resolved.
    NotStuck,
    /// The remote build finished but the local wrapper is still waiting and has
    /// not collected its result (e.g. the stream dropped before completion).
    RemoteFinishedLocalWaiting,
    /// The build finished successfully but artifact retrieval never completed —
    /// stuck *after* build success.
    ArtifactRetrievalStuck,
    /// The job was admitted but its slot reservation/transport failed; it can
    /// neither run nor be attached.
    ReservationFailedAfterAdmission,
    /// The daemon no longer recognizes the remote build id (restart/eviction),
    /// so the wrapper cannot reattach to a live job.
    DaemonForgotJob,
    /// The job was admitted/started but its heartbeat went stale with no
    /// completion — presumed dead.
    Abandoned,
    /// The wrapper is waiting on a command that never made it past admission.
    NeverAdmitted,
}

impl StuckClass {
    /// Stable lowercase token (matches the serde representation).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            StuckClass::NotStuck => "not_stuck",
            StuckClass::RemoteFinishedLocalWaiting => "remote_finished_local_waiting",
            StuckClass::ArtifactRetrievalStuck => "artifact_retrieval_stuck",
            StuckClass::ReservationFailedAfterAdmission => "reservation_failed_after_admission",
            StuckClass::DaemonForgotJob => "daemon_forgot_job",
            StuckClass::Abandoned => "abandoned",
            StuckClass::NeverAdmitted => "never_admitted",
        }
    }

    /// Whether this class represents a stuck wrapper needing intervention.
    #[must_use]
    pub fn is_stuck(self) -> bool {
        !matches!(self, StuckClass::NotStuck)
    }

    /// The single safe action RCH recommends for this class.
    ///
    /// - **Attach**: the remote side resolved cleanly; collect its result.
    /// - **Recover**: re-drive an incomplete step (re-probe a forgotten job,
    ///   re-retrieve artifacts).
    /// - **Cancel**: stop a wrapper whose job is dead, unreservable, or never
    ///   admitted — nothing useful can be reattached.
    /// - **NoneNeeded**: healthy; keep waiting.
    #[must_use]
    pub fn recommended_action(self) -> RecoveryAction {
        match self {
            StuckClass::NotStuck => RecoveryAction::NoneNeeded,
            StuckClass::RemoteFinishedLocalWaiting => RecoveryAction::Attach,
            StuckClass::ArtifactRetrievalStuck | StuckClass::DaemonForgotJob => {
                RecoveryAction::Recover
            }
            StuckClass::ReservationFailedAfterAdmission
            | StuckClass::Abandoned
            | StuckClass::NeverAdmitted => RecoveryAction::Cancel,
        }
    }

    /// The ledger reason code for this class, so a stuck-state warning is
    /// recordable in the incident ledger (4.2). Artifact-retrieval stalls map to
    /// [`IncidentReasonCode::ArtifactMiss`]; the identity/correlation classes map
    /// to [`IncidentReasonCode::QueueAmbiguity`]. A healthy wrapper has none.
    #[must_use]
    pub fn reason_code(self) -> Option<IncidentReasonCode> {
        match self {
            StuckClass::NotStuck => None,
            StuckClass::ArtifactRetrievalStuck => Some(IncidentReasonCode::ArtifactMiss),
            StuckClass::RemoteFinishedLocalWaiting
            | StuckClass::ReservationFailedAfterAdmission
            | StuckClass::DaemonForgotJob
            | StuckClass::Abandoned
            | StuckClass::NeverAdmitted => Some(IncidentReasonCode::QueueAmbiguity),
        }
    }

    /// Operator-facing one-line explanation.
    #[must_use]
    pub fn detail(self) -> &'static str {
        match self {
            StuckClass::NotStuck => "wrapper is waiting on a healthy job; no recovery needed",
            StuckClass::RemoteFinishedLocalWaiting => {
                "remote build finished while the local wrapper was still waiting; attach to collect the result"
            }
            StuckClass::ArtifactRetrievalStuck => {
                "build succeeded but artifact retrieval is stuck; recover to re-retrieve artifacts"
            }
            StuckClass::ReservationFailedAfterAdmission => {
                "job was admitted but its reservation failed; cancel to release it cleanly"
            }
            StuckClass::DaemonForgotJob => {
                "daemon no longer recognizes this job (likely restarted); recover to re-resolve its state"
            }
            StuckClass::Abandoned => {
                "job heartbeat went stale with no completion; presumed dead — cancel"
            }
            StuckClass::NeverAdmitted => {
                "wrapper is waiting on a command that never passed admission; cancel to stop waiting"
            }
        }
    }
}

/// The safe action RCH recommends for a stuck local wrapper.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryAction {
    /// Wrapper is healthy — keep waiting; nothing to recover.
    NoneNeeded,
    /// The remote side resolved; attach to collect its result/output.
    Attach,
    /// Stop a wrapper whose remote job is dead, absent, or unreservable.
    Cancel,
    /// Re-drive an incomplete step (re-probe, re-retrieve artifacts).
    Recover,
}

impl RecoveryAction {
    /// Stable lowercase token (matches the serde representation).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            RecoveryAction::NoneNeeded => "none_needed",
            RecoveryAction::Attach => "attach",
            RecoveryAction::Cancel => "cancel",
            RecoveryAction::Recover => "recover",
        }
    }
}

/// The safe recovery commands offered to an agent for a stuck wrapper. Each is a
/// stable command string the agent can run verbatim; absent verbs are omitted.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OfferedCommands {
    /// Collect the result of a job that already resolved remotely.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attach: Option<String>,
    /// Release / stop a job and unblock the wrapper.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cancel: Option<String>,
    /// Re-drive an incomplete step.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recover: Option<String>,
}

impl OfferedCommands {
    /// Build the offered verbs for an action, keyed off the always-present local
    /// wrapper id. The recommended verb is always offered; `cancel` is offered
    /// as a universal escape hatch for any stuck class, and `recover` is offered
    /// alongside `cancel` so a presumed-dead job can also be re-driven.
    #[must_use]
    fn for_action(action: RecoveryAction, handle: &str) -> Self {
        let cmd = |verb: &str| format!("rch jobs {verb} {handle}");
        match action {
            RecoveryAction::NoneNeeded => Self::default(),
            RecoveryAction::Attach => Self {
                attach: Some(cmd("attach")),
                cancel: Some(cmd("cancel")),
                recover: None,
            },
            RecoveryAction::Recover => Self {
                attach: None,
                cancel: Some(cmd("cancel")),
                recover: Some(cmd("recover")),
            },
            RecoveryAction::Cancel => Self {
                attach: None,
                cancel: Some(cmd("cancel")),
                recover: Some(cmd("recover")),
            },
        }
    }
}

/// The structured stuck-state warning surfaced to agents (JSON) and operators
/// (`render`). Recordable in the incident ledger via [`StuckWrapperWarning::reason_code`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StuckWrapperWarning {
    /// Identity of the affected job (local wrapper id always present).
    pub job: JobIdentity,
    /// Whether the wrapper is stuck at all.
    pub stuck: bool,
    /// The classified stuck state.
    pub class: StuckClass,
    /// The single recommended safe action.
    pub recommended_action: RecoveryAction,
    /// Ledger reason code (`RCH-Innn`), absent when not stuck.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<IncidentReasonCode>,
    /// The safe commands offered to the agent.
    pub offered: OfferedCommands,
    /// Operator-/agent-facing explanation.
    pub detail: String,
}

impl StuckWrapperWarning {
    /// Human-readable one-line summary.
    #[must_use]
    pub fn render(&self) -> String {
        format!(
            "stuck-wrapper: {} (action={}, job={}) — {}",
            self.class.as_str(),
            self.recommended_action.as_str(),
            self.job.local_wrapper_id,
            self.detail,
        )
    }
}

/// Classify whether — and why — a local wrapper is stuck. Pure and total.
///
/// Precedence (most authoritative first):
/// 1. A wrapper that is no longer waiting has already resolved → `NotStuck`.
/// 2. A recorded completion is authoritative (mirrors the lifecycle-state
///    precedence where `completed` wins): collect the result, or — if artifacts
///    never came back — re-drive retrieval.
/// 3. An admitted-but-unreservable job can neither run nor attach.
/// 4. A job the daemon forgot (restart/eviction) cannot be reattached live.
/// 5. Otherwise classify by lifecycle: abandoned, never-admitted, or a healthy
///    queued/running wait.
#[must_use]
pub fn classify_stuck_wrapper(state: &WrapperState) -> StuckClass {
    if !state.local_wrapper_waiting {
        return StuckClass::NotStuck;
    }
    if state.job_state == JobLifecycleState::Finished {
        return if state.artifacts_pending {
            StuckClass::ArtifactRetrievalStuck
        } else {
            StuckClass::RemoteFinishedLocalWaiting
        };
    }
    if state.reservation_failed_after_admission {
        return StuckClass::ReservationFailedAfterAdmission;
    }
    if state.remote_absent {
        return StuckClass::DaemonForgotJob;
    }
    match state.job_state {
        JobLifecycleState::Abandoned => StuckClass::Abandoned,
        JobLifecycleState::FailedBeforeAdmission => StuckClass::NeverAdmitted,
        // Present daemon, fresh heartbeat, not finished: a legitimate wait.
        JobLifecycleState::Queued | JobLifecycleState::Running => StuckClass::NotStuck,
        // Handled above; kept total without a wildcard.
        JobLifecycleState::Finished => StuckClass::NotStuck,
    }
}

/// Diagnose a stuck wrapper into a structured, ledger-mappable warning with the
/// recommended action and the safe commands offered to the agent.
#[must_use]
pub fn diagnose_stuck_wrapper(job: &JobIdentity, state: &WrapperState) -> StuckWrapperWarning {
    let class = classify_stuck_wrapper(state);
    let recommended_action = class.recommended_action();
    StuckWrapperWarning {
        job: job.clone(),
        stuck: class.is_stuck(),
        class,
        recommended_action,
        reason_code: class.reason_code(),
        offered: OfferedCommands::for_action(recommended_action, &job.local_wrapper_id),
        detail: class.detail().to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// All stuck classes, for exhaustive coverage checks.
    const ALL_CLASSES: &[StuckClass] = &[
        StuckClass::NotStuck,
        StuckClass::RemoteFinishedLocalWaiting,
        StuckClass::ArtifactRetrievalStuck,
        StuckClass::ReservationFailedAfterAdmission,
        StuckClass::DaemonForgotJob,
        StuckClass::Abandoned,
        StuckClass::NeverAdmitted,
    ];

    fn admitted_job() -> JobIdentity {
        let mut id = JobIdentity::new_local();
        id.admit(42);
        id
    }

    // --- The four scenarios the bead requires ------------------------------

    #[test]
    fn scenario_daemon_restart_recommends_recover() {
        // Daemon restarted and lost the job from memory; the wrapper is still
        // waiting on a job that was running.
        let state = WrapperState::waiting(JobLifecycleState::Running).remote_absent();
        let warning = diagnose_stuck_wrapper(&admitted_job(), &state);
        assert_eq!(warning.class, StuckClass::DaemonForgotJob);
        assert_eq!(warning.recommended_action, RecoveryAction::Recover);
        assert!(warning.stuck);
        assert_eq!(warning.reason_code, Some(IncidentReasonCode::QueueAmbiguity));
        assert!(warning.offered.recover.is_some());
        assert!(warning.offered.cancel.is_some());
    }

    #[test]
    fn scenario_remote_completed_before_local_stream_recommends_attach() {
        // The remote build finished while the local stream had dropped; the
        // wrapper is still waiting. Attach to collect the (clean) result.
        let state = WrapperState::waiting(JobLifecycleState::Finished);
        let warning = diagnose_stuck_wrapper(&admitted_job(), &state);
        assert_eq!(warning.class, StuckClass::RemoteFinishedLocalWaiting);
        assert_eq!(warning.recommended_action, RecoveryAction::Attach);
        assert!(warning.offered.attach.is_some());
        assert!(warning.offered.recover.is_none());
    }

    #[test]
    fn scenario_abandoned_job_recommends_cancel() {
        // Admitted/started job whose heartbeat went stale with no completion.
        let state = WrapperState::waiting(JobLifecycleState::Abandoned);
        let warning = diagnose_stuck_wrapper(&admitted_job(), &state);
        assert_eq!(warning.class, StuckClass::Abandoned);
        assert_eq!(warning.recommended_action, RecoveryAction::Cancel);
        assert!(warning.offered.cancel.is_some());
        // A dead job can also be re-driven from scratch.
        assert!(warning.offered.recover.is_some());
    }

    #[test]
    fn scenario_artifact_retrieval_stuck_after_success_recommends_recover() {
        // Build finished successfully but artifacts never came back.
        let state = WrapperState::waiting(JobLifecycleState::Finished).artifacts_pending();
        let warning = diagnose_stuck_wrapper(&admitted_job(), &state);
        assert_eq!(warning.class, StuckClass::ArtifactRetrievalStuck);
        assert_eq!(warning.recommended_action, RecoveryAction::Recover);
        assert_eq!(warning.reason_code, Some(IncidentReasonCode::ArtifactMiss));
        assert!(warning.offered.recover.is_some());
    }

    // --- Reservation failure after admission -------------------------------

    #[test]
    fn reservation_failed_after_admission_recommends_cancel() {
        // "If reservation fails after queue admission, RCH must cancel or
        // reattach cleanly."
        let state = WrapperState::waiting(JobLifecycleState::Queued).reservation_failed();
        let warning = diagnose_stuck_wrapper(&admitted_job(), &state);
        assert_eq!(
            warning.class,
            StuckClass::ReservationFailedAfterAdmission
        );
        assert_eq!(warning.recommended_action, RecoveryAction::Cancel);
        assert!(warning.offered.cancel.is_some());
    }

    // --- Non-stuck and precedence ------------------------------------------

    #[test]
    fn healthy_running_wrapper_is_not_stuck() {
        let state = WrapperState::waiting(JobLifecycleState::Running);
        let warning = diagnose_stuck_wrapper(&admitted_job(), &state);
        assert_eq!(warning.class, StuckClass::NotStuck);
        assert!(!warning.stuck);
        assert_eq!(warning.recommended_action, RecoveryAction::NoneNeeded);
        assert_eq!(warning.reason_code, None);
        assert_eq!(warning.offered, OfferedCommands::default());
    }

    #[test]
    fn queued_wrapper_is_not_stuck() {
        let state = WrapperState::waiting(JobLifecycleState::Queued);
        assert_eq!(classify_stuck_wrapper(&state), StuckClass::NotStuck);
    }

    #[test]
    fn resolved_wrapper_is_never_stuck_regardless_of_signals() {
        // A wrapper that already exited is not stuck even with alarming signals.
        let state = WrapperState::waiting(JobLifecycleState::Abandoned)
            .remote_absent()
            .reservation_failed()
            .not_waiting();
        assert_eq!(classify_stuck_wrapper(&state), StuckClass::NotStuck);
    }

    #[test]
    fn finished_takes_precedence_over_daemon_forgot() {
        // A recorded completion is authoritative even if the daemon evicted the
        // job from memory: collect the result rather than re-resolve.
        let state = WrapperState::waiting(JobLifecycleState::Finished).remote_absent();
        assert_eq!(
            classify_stuck_wrapper(&state),
            StuckClass::RemoteFinishedLocalWaiting
        );
    }

    #[test]
    fn finished_with_pending_artifacts_takes_precedence_over_reservation_failure() {
        let state = WrapperState::waiting(JobLifecycleState::Finished)
            .artifacts_pending()
            .reservation_failed();
        assert_eq!(
            classify_stuck_wrapper(&state),
            StuckClass::ArtifactRetrievalStuck
        );
    }

    #[test]
    fn never_admitted_wrapper_recommends_cancel() {
        let state = WrapperState::waiting(JobLifecycleState::FailedBeforeAdmission);
        let warning = diagnose_stuck_wrapper(&JobIdentity::new_local(), &state);
        assert_eq!(warning.class, StuckClass::NeverAdmitted);
        assert_eq!(warning.recommended_action, RecoveryAction::Cancel);
    }

    #[test]
    fn reservation_failure_outranks_abandoned_and_remote_absent() {
        // An explicit reservation failure is more actionable than a stale
        // heartbeat or a forgotten job.
        let state = WrapperState::waiting(JobLifecycleState::Abandoned)
            .reservation_failed()
            .remote_absent();
        assert_eq!(
            classify_stuck_wrapper(&state),
            StuckClass::ReservationFailedAfterAdmission
        );
    }

    // --- Contract invariants -----------------------------------------------

    #[test]
    fn only_not_stuck_needs_no_action_and_has_no_reason() {
        for &class in ALL_CLASSES {
            let needs_action = class.recommended_action() != RecoveryAction::NoneNeeded;
            assert_eq!(
                class.is_stuck(),
                needs_action,
                "{} stuck/action mismatch",
                class.as_str()
            );
            assert_eq!(
                class.is_stuck(),
                class.reason_code().is_some(),
                "{} stuck/reason mismatch",
                class.as_str()
            );
        }
    }

    #[test]
    fn offered_commands_match_recommended_action() {
        for &class in ALL_CLASSES {
            let offered = OfferedCommands::for_action(class.recommended_action(), "rchw-x");
            match class.recommended_action() {
                RecoveryAction::NoneNeeded => assert_eq!(offered, OfferedCommands::default()),
                RecoveryAction::Attach => {
                    assert!(offered.attach.is_some(), "{}", class.as_str());
                    assert!(offered.cancel.is_some());
                }
                RecoveryAction::Recover | RecoveryAction::Cancel => {
                    assert!(offered.cancel.is_some(), "{}", class.as_str());
                    assert!(offered.recover.is_some());
                }
            }
        }
    }

    #[test]
    fn offered_commands_reference_the_job_handle() {
        let job = admitted_job();
        let state = WrapperState::waiting(JobLifecycleState::Finished);
        let warning = diagnose_stuck_wrapper(&job, &state);
        let attach = warning.offered.attach.expect("attach offered");
        assert!(attach.contains(&job.local_wrapper_id));
        assert!(attach.starts_with("rch jobs attach "));
    }

    #[test]
    fn warning_serializes_with_stable_tokens() {
        let state = WrapperState::waiting(JobLifecycleState::Finished).artifacts_pending();
        let warning = diagnose_stuck_wrapper(&admitted_job(), &state);
        let value = serde_json::to_value(&warning).expect("serialize");
        assert_eq!(value["class"], "artifact_retrieval_stuck");
        assert_eq!(value["recommended_action"], "recover");
        assert_eq!(value["stuck"], true);
        assert_eq!(value["reason_code"], "RCH-I014");
        // Round-trips losslessly.
        let back: StuckWrapperWarning = serde_json::from_value(value).expect("deserialize");
        assert_eq!(back, warning);
    }

    #[test]
    fn not_stuck_warning_omits_reason_code_on_the_wire() {
        let state = WrapperState::waiting(JobLifecycleState::Running);
        let warning = diagnose_stuck_wrapper(&admitted_job(), &state);
        let value = serde_json::to_value(&warning).expect("serialize");
        assert!(value.get("reason_code").is_none(), "None must be omitted");
    }

    #[test]
    fn render_is_human_readable() {
        let job = admitted_job();
        let state = WrapperState::waiting(JobLifecycleState::Abandoned);
        let line = diagnose_stuck_wrapper(&job, &state).render();
        assert!(line.contains("abandoned"));
        assert!(line.contains("action=cancel"));
        assert!(line.contains(&job.local_wrapper_id));
    }

    #[test]
    fn class_tokens_are_unique() {
        let mut tokens: Vec<&str> = ALL_CLASSES.iter().map(|c| c.as_str()).collect();
        tokens.sort_unstable();
        let before = tokens.len();
        tokens.dedup();
        assert_eq!(before, tokens.len(), "duplicate stuck-class tokens");
    }
}
