//! Retire phantom builds that no cancellation can confirm.
//!
//! A build whose wrapper died on this dispatcher, on a worker that can no
//! longer be asked (administratively disabled, unreachable, or never
//! answering), kept its durable ownership forever: the stuck detector's
//! automatic cancellation is deferred while the worker is disabled, an
//! operator `rch jobs cancel` fails on the unanswered remote kill, and every
//! `rch daemon restart --drain` waited on it. Three such builds on one
//! Windows worker were 12 to 21 days old on 2026-11-10 and blocked every
//! drain and the nightly update's daemon restart on two dispatchers.
//!
//! Forgetting is not termination authority. It requires proof that the
//! original wrapper exited here, and then either a worker answer that nothing
//! runs under the build's process record, or silence far beyond every remote
//! lifetime cap (the in-session watchdog and the worker orphan reaper). The
//! terminal record keeps the decision: exit 130 with cancellation metadata
//! whose reason code is `phantom_build_forgotten`.

use super::{
    ABANDONED_BEFORE_REMOTE_AFTER, ABANDONED_UNLAUNCHED_AFTER, CancelReason, CancellationAttempt,
    CancellationOrchestrator, CancellationRecord, CancellationState, WrapperProcessState,
    cancellation_transport_endpoint, remote_answer_can_confirm, worker_health_for_history,
    wrapper_process_state,
};
use crate::DaemonContext;
use crate::api::CancelBuildResponse;
use crate::history::ActiveBuildState;
use rch_common::{BuildCancellationMetadata, WorkerId};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, warn};

/// An exited wrapper silent this long no longer waits on this daemon. It
/// matches the dead-wrapper rule for client leases in restart admission.
pub(crate) const ORPHANED_BUILD_SILENCE: Duration = Duration::from_secs(15 * 60);

/// An operator may forget an orphan its worker cannot answer for after this.
pub(crate) const FORGET_UNCONFIRMED_AFTER: Duration = Duration::from_secs(24 * 3600);

/// The stuck detector forgets an unanswerable orphan on its own after this.
pub(crate) const AUTOMATIC_FORGET_AFTER: Duration = Duration::from_secs(72 * 3600);

/// Reason code recorded on a forgotten build's terminal record.
pub(crate) const FORGOTTEN_REASON_CODE: &str = "phantom_build_forgotten";

/// Who asked for a phantom build to be forgotten.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForgetOrigin {
    /// `rch jobs forget <build-id>`: may ask the worker once.
    Operator,
    /// The stuck detector after an automatic cancellation could not finish.
    /// It never dials the worker, so administrative disable stays honored.
    Automatic,
}

impl ForgetOrigin {
    fn label(self) -> &'static str {
        match self {
            Self::Operator => "operator",
            Self::Automatic => "automatic",
        }
    }

    fn unconfirmed_after(self) -> Duration {
        match self {
            Self::Operator => FORGET_UNCONFIRMED_AFTER,
            Self::Automatic => AUTOMATIC_FORGET_AFTER,
        }
    }

    fn reason(self) -> CancelReason {
        match self {
            Self::Operator => CancelReason::User,
            Self::Automatic => CancelReason::StuckDetector,
        }
    }
}

/// How long a build has been silent since its original wrapper exited here.
/// `None` while that wrapper runs or its identity cannot be verified.
pub(crate) fn orphaned_silence(build: &ActiveBuildState, now: Instant) -> Option<Duration> {
    (wrapper_process_state(build.hook_pid, build.hook_process_identity.as_deref())
        == WrapperProcessState::Exited)
        .then(|| {
            now.saturating_duration_since(build.started_at_mono)
                .min(now.saturating_duration_since(build.last_heartbeat_mono))
        })
}

/// Nobody on this dispatcher waits for this build any more. Its durable
/// ownership survives a daemon restart, so a drain need not wait for it.
pub(crate) fn is_orphaned_build(build: &ActiveBuildState, now: Instant) -> bool {
    orphaned_silence(build, now).is_some_and(|silence| silence >= ORPHANED_BUILD_SILENCE)
}

/// What the worker said about the build's process record, if it was asked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RemoteAnswer {
    /// Not asked: an automatic forget, or no record path/admitted endpoint.
    NotAsked,
    /// The worker killed the group or proved the record gone.
    Confirmed,
    /// Asked, but no authenticated receipt arrived.
    Unconfirmed,
}

impl RemoteAnswer {
    fn describe(self) -> &'static str {
        match self {
            Self::NotAsked => "worker not asked",
            Self::Confirmed => "worker confirmed nothing runs under the build",
            Self::Unconfirmed => "worker did not confirm",
        }
    }
}

fn hours(duration: Duration) -> u64 {
    duration.as_secs().div_ceil(3600)
}

/// Ok carries the evidence that authorizes forgetting; Err the refusal.
fn forget_decision(
    origin: ForgetOrigin,
    silence: Duration,
    remote: RemoteAnswer,
) -> Result<String, String> {
    if silence < ORPHANED_BUILD_SILENCE {
        return Err(format!(
            "the wrapper exited but the build was active {}s ago; it can be forgotten after \
             {}s of silence",
            silence.as_secs(),
            ORPHANED_BUILD_SILENCE.as_secs()
        ));
    }
    if remote == RemoteAnswer::Confirmed {
        return Ok(format!(
            "wrapper exited, silent {}s, {}",
            silence.as_secs(),
            remote.describe()
        ));
    }
    let after = origin.unconfirmed_after();
    if silence >= after {
        return Ok(format!(
            "wrapper exited, silent {}h (past the {}h {} limit), {}",
            silence.as_secs() / 3600,
            hours(after),
            origin.label(),
            remote.describe()
        ));
    }
    Err(format!(
        "{}; without that answer a build can be forgotten after {}h of silence ({}h remaining)",
        remote.describe(),
        hours(after),
        hours(after.saturating_sub(silence))
    ))
}

fn response(
    status: &str,
    build_id: u64,
    build: Option<&ActiveBuildState>,
    message: String,
    slots_released: u32,
) -> CancelBuildResponse {
    CancelBuildResponse {
        status: status.to_string(),
        build_id,
        worker_id: build.map(|build| build.worker_id.clone()),
        project_id: build.map(|build| build.project_id.clone()),
        message: Some(message),
        slots_released,
    }
}

/// Activity or reassignment since the decision was made voids it.
fn same_owner(planned: &ActiveBuildState, current: &ActiveBuildState) -> bool {
    planned.worker_id == current.worker_id
        && planned.local_wrapper_id == current.local_wrapper_id
        && planned.hook_pid == current.hook_pid
        && planned.hook_process_identity == current.hook_process_identity
        && planned.remote_pgid_file == current.remote_pgid_file
        && planned.last_heartbeat_mono == current.last_heartbeat_mono
        && planned.slots == current.slots
}

impl CancellationOrchestrator {
    /// Forget an orphaned build (see the module documentation).
    pub async fn forget_build(
        &self,
        ctx: &DaemonContext,
        build_id: u64,
        origin: ForgetOrigin,
    ) -> CancelBuildResponse {
        self.forget_build_at(ctx, build_id, origin, Instant::now())
            .await
    }

    /// `now` dates only the silence judgement; transport keeps real time.
    pub(crate) async fn forget_build_at(
        &self,
        ctx: &DaemonContext,
        build_id: u64,
        origin: ForgetOrigin,
        now: Instant,
    ) -> CancelBuildResponse {
        // Share the cancellation admission map: a forget never races a
        // cancellation (or another forget) of the same build.
        let (record, attempt) = {
            let mut active = self
                .active
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            if let Some(existing) = active.get(&build_id) {
                return CancelBuildResponse {
                    status: "cancelling".to_string(),
                    build_id,
                    worker_id: Some(existing.worker_id.clone()),
                    project_id: None,
                    message: Some(format!(
                        "Cancellation already in progress (state: {}); retry after it settles",
                        existing.state
                    )),
                    slots_released: 0,
                };
            }
            let Some(build) = ctx.history.active_build(build_id) else {
                return response(
                    "error",
                    build_id,
                    None,
                    "Build not found or already completed".to_string(),
                    0,
                );
            };
            let record = CancellationRecord {
                build_id,
                worker_id: build.worker_id.clone(),
                worker_endpoint: build.worker_endpoint.clone(),
                state: CancellationState::Requested,
                reason: origin.reason(),
                requested_at: Instant::now(),
                completed_at: None,
                escalation_count: 0,
                remote_kill_attempted: false,
                remote_kill_confirmed: false,
                remote_record_absent: false,
                cleanup_ok: true,
                slots: build.slots,
                slots_released: 0,
                hook_pid: build.hook_pid,
                hook_process_identity: build.hook_process_identity.clone(),
                remote_pgid_file: build.remote_pgid_file.clone(),
                abandoned_unlaunched: false,
            };
            active.insert(build_id, record.clone());
            (
                record,
                CancellationAttempt {
                    build_id,
                    active: Arc::clone(&self.active),
                },
            )
        };
        let owner = self.clone();
        let context = ctx.clone();
        // A dropped caller must not strand an admitted finalization.
        let operation = tokio::spawn(async move {
            let _attempt = attempt;
            owner.forget_claimed(&context, record, origin, now).await
        });
        match operation.await {
            Ok(response) => response,
            Err(error) => {
                warn!(build_id, %error, "Forget task ended unexpectedly");
                response(
                    "failed",
                    build_id,
                    None,
                    "Forget task ended unexpectedly; check active history before retrying"
                        .to_string(),
                    0,
                )
            }
        }
    }

    async fn forget_claimed(
        &self,
        ctx: &DaemonContext,
        mut record: CancellationRecord,
        origin: ForgetOrigin,
        now: Instant,
    ) -> CancelBuildResponse {
        let build_id = record.build_id;
        let Some(planned) = ctx.history.active_build(build_id) else {
            return response(
                "error",
                build_id,
                None,
                "Build completed before the forget started".to_string(),
                0,
            );
        };
        let Some(silence) = orphaned_silence(&planned, now) else {
            return response(
                "refused",
                build_id,
                Some(&planned),
                format!(
                    "wrapper pid {} is running or unverified on this dispatcher; only an \
                     orphaned build can be forgotten. Cancel a live build with `rch cancel` or \
                     `rch jobs cancel`",
                    planned.hook_pid
                ),
                0,
            );
        };
        // Do not dial the worker when not even a confirmation would suffice.
        if let Err(refusal) = forget_decision(origin, silence, RemoteAnswer::Confirmed) {
            return response("refused", build_id, Some(&planned), refusal, 0);
        }

        // An operator asks the worker once: it stops any remnant of the
        // group, or reports the record gone. That answer proves absence
        // only after the abandoned-reservation silence. The automatic path
        // never dials, and neither path accuses the worker if it is mute.
        let mut remote = RemoteAnswer::NotAsked;
        if origin == ForgetOrigin::Operator
            && remote_answer_can_confirm(&record)
            && cancellation_transport_endpoint(&record).is_some()
        {
            let record_proof_after = if planned.remote_command_started() {
                ABANDONED_UNLAUNCHED_AFTER
            } else {
                ABANDONED_BEFORE_REMOTE_AFTER
            };
            record.abandoned_unlaunched = silence >= record_proof_after;
            record.state = CancellationState::RemoteKillSent;
            remote = match self.cancellation_deadline() {
                Some(deadline) if self.try_remote_kill(&mut record, deadline).await => {
                    RemoteAnswer::Confirmed
                }
                _ => RemoteAnswer::Unconfirmed,
            };
        }
        let proof = match forget_decision(origin, silence, remote) {
            Ok(proof) => proof,
            Err(refusal) => {
                debug!(build_id, %refusal, "Forget refused; ownership retained");
                return response("refused", build_id, Some(&planned), refusal, 0);
            }
        };

        // Serialize with completion/release reports and revalidate.
        let release = ctx.history.lock_releases().await;
        let Some(current) = ctx
            .history
            .active_build(build_id)
            .filter(|current| same_owner(&planned, current))
        else {
            return response(
                "refused",
                build_id,
                Some(&planned),
                "the build completed or reported activity while the forget was deciding; \
                 nothing was forgotten"
                    .to_string(),
                0,
            );
        };
        let worker_health = self
            .capture_worker_health_snapshot(ctx, &current.worker_id)
            .await;
        let mut decision_path = vec!["requested".to_string(), "orphan_verified".to_string()];
        if record.remote_kill_attempted {
            decision_path.push("remote_kill_sent".to_string());
        }
        decision_path.push("forgotten".to_string());
        let cancellation = BuildCancellationMetadata {
            operation_id: format!("forget-{build_id}"),
            origin: origin.label().to_string(),
            reason_code: FORGOTTEN_REASON_CODE.to_string(),
            decision_path,
            escalation_stage: if record.remote_kill_attempted {
                "remote_kill"
            } else {
                "none"
            }
            .to_string(),
            escalation_count: 0,
            remote_kill_attempted: record.remote_kill_attempted,
            cleanup_ok: true,
            history_cancelled: true,
            final_state: "forgotten".to_string(),
            worker_health: worker_health.as_ref().map(worker_health_for_history),
        };
        let completed = ctx.history.complete_durable(
            current.id,
            &current.worker_id,
            current.local_wrapper_id.as_deref(),
            crate::history::BuildCompletion {
                exit_code: 130,
                duration_ms: None,
                bytes_transferred: None,
                disk_peak_output_bytes: None,
                disk_observation: None,
                timing: None,
                cancellation: Some(cancellation),
            },
        );
        let state = match completed {
            Ok(Some((state, _))) => state,
            Ok(None) => {
                return response(
                    "error",
                    build_id,
                    Some(&current),
                    "Build already completed".to_string(),
                    0,
                );
            }
            Err(error) => {
                warn!(build_id, %error, "Unable to persist a forgotten build; ownership retained");
                return response(
                    "failed",
                    build_id,
                    Some(&current),
                    format!("Unable to persist the forget ({error}); ownership retained"),
                    0,
                );
            }
        };
        ctx.pool
            .release_slots(&WorkerId::new(&state.worker_id), state.slots)
            .await;
        drop(release);
        if !cfg!(test) {
            let location = match state.location {
                rch_common::BuildLocation::Remote => "remote",
                rch_common::BuildLocation::Local => "local",
            };
            crate::metrics::dec_active_builds(location);
            crate::metrics::inc_build_total("cancelled", location);
        }
        warn!(
            build_id,
            worker_id = %state.worker_id,
            project_id = %state.project_id,
            local_wrapper_id = ?state.local_wrapper_id,
            started_at = %state.started_at,
            last_heartbeat_at = %state.last_heartbeat_at,
            slots = state.slots,
            origin = origin.label(),
            %proof,
            "Forgot phantom build; slots released and terminal record retained"
        );
        self.events.emit(
            "build_forgotten",
            &serde_json::json!({
                "operation_id": format!("forget-{build_id}"),
                "build_id": build_id,
                "worker_id": state.worker_id,
                "project_id": state.project_id,
                "local_wrapper_id": state.local_wrapper_id,
                "origin": origin.label(),
                "reason_code": FORGOTTEN_REASON_CODE,
                "silence_secs": silence.as_secs(),
                "remote_kill_attempted": record.remote_kill_attempted,
                "remote_kill_confirmed": record.remote_kill_confirmed,
                "slots_released": state.slots,
                "proof": proof,
            }),
        );
        if let Some(endpoint) = state.worker_endpoint.as_ref() {
            crate::bypass_recovery_service::request_recovery_after_settlement(
                &ctx.pool,
                ctx.bypass_store.as_deref(),
                endpoint,
            )
            .await;
        }
        response(
            "forgotten",
            build_id,
            Some(&state),
            format!(
                "Forgot build {build_id} ({proof}); released {} slot(s); terminal record kept \
                 with reason {FORGOTTEN_REASON_CODE}",
                state.slots
            ),
            state.slots,
        )
    }
}

#[cfg(test)]
mod tests;
