//! Background cleanup for active builds with dead hooks.

use crate::{
    DaemonContext,
    history::{QueuedBuildState, StuckDetectorSnapshot, WrapperCancellation},
};
use std::path::Path;
use std::time::{Duration, Instant};
use tokio::time::{MissedTickBehavior, interval};
use tracing::{debug, warn};

const HEARTBEAT_STALE_SECS: u64 = 20;
/// Silence from a LIVE hook that corroborates a progress stall. The hook beats every 5 s, but on
/// a loaded host the hook, this daemon, or both can be descheduled for tens of seconds, and a
/// compile of one large crate emits no progress for many minutes. On 2026-09-28 a healthy
/// 16-minute `cargo test` compile in Execute was cancelled at `hb_age: 23` with
/// `progress_age: 740` while this daemon's own log lagged the event by 12 s. A dead hook still
/// needs only [`HEARTBEAT_STALE_SECS`].
const LIVE_HOOK_HEARTBEAT_STALE_SECS: u64 = 120;
const PROGRESS_STALE_SECS: u64 = 90;
const RECENT_PROGRESS_GRACE_SECS: u64 = 15;
const MIN_BUILD_AGE_SECS: u64 = 30;
const TRIAGE_BUDGET_MS: u64 = 50;
const REMEDIATION_CONFIDENCE_THRESHOLD: f64 = 0.85;
const RECOVERED_QUEUE_PROBES_PER_TICK: usize = 16;

/// Restored queue rows have no surviving socket handler to retire them when
/// their client exits. Leave live or unprovable owners available for explicit
/// recovery, but do not let dead owners permanently consume the queue limit.
#[derive(Default)]
struct RecoveredQueueCleanup {
    after_id: Option<u64>,
}

impl RecoveredQueueCleanup {
    fn check(&mut self, context: &DaemonContext) {
        if context.history.ownership_failed() {
            return;
        }
        let rows = context.history.queued_builds();
        let start = self
            .after_id
            .and_then(|id| rows.iter().position(|row| row.id > id))
            .unwrap_or(0);
        let mut changed = false;
        // Rotate by durable ID: a live prefix cannot starve a dead tail. Bound
        // process probes and durable writes, including on an unlimited queue.
        for candidate in rows
            .iter()
            .skip(start)
            .chain(rows.iter().take(start))
            .filter(|row| row.recovered)
            .take(RECOVERED_QUEUE_PROBES_PER_TICK)
        {
            self.after_id = Some(candidate.id);
            let Some(row) = context.history.queued_build(candidate.id) else {
                continue;
            };
            let Some(reason) = recovered_queue_owner_gone(&row) else {
                continue;
            };
            match retire_recovered_queue_owner(context, &row) {
                Ok(true) => {
                    changed = true;
                    context.events.emit(
                        "recovered_queue_owner_retired",
                        &serde_json::json!({
                            "queue_id_text": row.id.to_string(),
                            "project_id": row.project_id,
                            "reason": reason,
                        }),
                    );
                }
                Ok(false) => {}
                Err(error) => {
                    warn!(queue_id = row.id, %error, "Recovered queue retirement not committed");
                    // The store itself closes admission on uncertain writes.
                    // Never continue as if an unacknowledged departure succeeded.
                    break;
                }
            }
        }
        if changed {
            context.history.update_queue_estimates();
            rch_telemetry::remediation::set_queue_depth(context.history.queue_depth());
        }
    }
}

/// No signal is sent. ESRCH proves absence. Linux's boot ID/start ticks also
/// prove replacement; formatted `ps` timestamps on other platforms do not.
/// Permission errors and missing identity are not death.
fn recovered_queue_owner_gone(row: &QueuedBuildState) -> Option<&'static str> {
    if !row.recovered || row.hook_pid <= 1 {
        return None;
    }
    #[cfg(unix)]
    {
        use nix::{errno::Errno, sys::signal::kill, unistd::Pid};

        let pid = i32::try_from(row.hook_pid).ok()?;
        match kill(Pid::from_raw(pid), None) {
            Err(Errno::ESRCH) => Some("queued_owner_exited"),
            Ok(()) | Err(Errno::EPERM) => {
                #[cfg(target_os = "linux")]
                {
                    let recorded = row.hook_process_identity.as_deref()?;
                    let observed = crate::history::process_identity(row.hook_pid)?;
                    (observed != recorded).then_some("queued_owner_replaced")
                }
                #[cfg(not(target_os = "linux"))]
                {
                    None
                }
            }
            Err(_) => None,
        }
    }
    #[cfg(not(unix))]
    {
        None
    }
}

fn retire_recovered_queue_owner(
    context: &DaemonContext,
    row: &QueuedBuildState,
) -> std::io::Result<bool> {
    if !row.recovered {
        return Ok(false);
    }
    if let Some(wrapper) = row.local_wrapper_id.as_deref() {
        // This competes with admission under the history ownership lock. An
        // active/completed result is NOT permission to cancel that execution.
        // No worker connection is opened and no slots are released here.
        Ok(matches!(
            context.history.cancel_wrapper(wrapper)?,
            WrapperCancellation::BeforeStart
        ))
    } else {
        // Anonymous legacy rows have no delayed wrapper identity to fence.
        // Remove by their durable queue ID, never by a reusable PID.
        context.history.finish_queued_build(row.id, None)?;
        Ok(context.history.queued_build(row.id).is_none())
    }
}

/// A delayed observer cannot distinguish a stalled client from a client whose
/// heartbeat task was paused with it. Allow one normal heartbeat window to
/// collect new evidence, without changing the recorded heartbeat or progress.
#[derive(Default)]
struct ObservationWindow {
    last_observed: Option<Instant>,
    recover_until: Option<Instant>,
    startup_until: Option<Instant>,
}

impl ObservationWindow {
    /// A restored timestamp includes daemon downtime, when no heartbeat could
    /// be accepted. Give surviving builds one observation window to reattach.
    /// This deadline belongs to the observer, not each build or each sweep.
    fn for_startup(now: Instant) -> Self {
        Self {
            last_observed: Some(now),
            recover_until: None,
            startup_until: Some(now + Duration::from_secs(HEARTBEAT_STALE_SECS)),
        }
    }

    fn recovering_build(&mut self, now: Instant, recovered: bool) -> bool {
        self.recovering(now)
            || (recovered && self.startup_until.is_some_and(|deadline| now < deadline))
    }

    fn recovering(&mut self, now: Instant) -> bool {
        let window = Duration::from_secs(HEARTBEAT_STALE_SECS);
        let delayed = self.last_observed.is_some_and(|previous| {
            now.checked_duration_since(previous).unwrap_or_default() >= window
        });
        // A second delayed observation must not extend an existing grace.
        if delayed && self.recover_until.is_none() {
            self.recover_until = Some(now + window);
            warn!("Stuck detector observation delayed; awaiting fresh heartbeat evidence");
        }
        self.last_observed = Some(now);
        if self.recover_until.is_some_and(|deadline| now < deadline) {
            return true;
        }
        self.recover_until = None;
        false
    }
}

fn duration_millis_u64(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

#[derive(Debug, Clone, Copy)]
struct StuckEvidenceInput {
    hook_alive: bool,
    progress_stall_remediable_phase: bool,
    heartbeat_age_secs: u64,
    progress_age_secs: u64,
    build_age_secs: u64,
    slots_owned: u32,
    has_worker_binding: bool,
}

#[derive(Debug, Clone, Copy)]
struct StuckEvidence {
    hook_alive: bool,
    heartbeat_stale: bool,
    progress_stale: bool,
    remediable_progress_stale: bool,
    heartbeat_age_secs: u64,
    progress_age_secs: u64,
    build_age_secs: u64,
    slots_owned: u32,
    has_worker_binding: bool,
    confidence: f64,
}

impl StuckEvidence {
    fn should_remediate_after_observation(self, recovering: bool) -> bool {
        // Observer recovery never extends the absolute lifetime cap.
        (!recovering || self.build_age_secs > 86400) && self.should_remediate()
    }

    fn should_remediate(self) -> bool {
        let hard_timeout = self.build_age_secs > 86400; // 24 hours
        let dead_hook_evidence = !self.hook_alive && self.heartbeat_stale;
        let phase_stall_evidence = self.remediable_progress_stale;

        hard_timeout
            || (self.build_age_secs >= MIN_BUILD_AGE_SECS
                && self.slots_owned > 0
                && self.has_worker_binding
                && (dead_hook_evidence || phase_stall_evidence)
                && self.confidence >= REMEDIATION_CONFIDENCE_THRESHOLD)
    }
}

fn score_stuck_evidence(input: StuckEvidenceInput) -> StuckEvidence {
    let heartbeat_stale = input.heartbeat_age_secs >= HEARTBEAT_STALE_SECS;
    let progress_stale = input.progress_age_secs >= PROGRESS_STALE_SECS;
    let progress_recent = input.progress_age_secs <= RECENT_PROGRESS_GRACE_SECS;
    let progress_stall_corroborated =
        !input.hook_alive || input.heartbeat_age_secs >= LIVE_HOOK_HEARTBEAT_STALE_SECS;
    let remediable_progress_stale = input.progress_stall_remediable_phase
        && progress_stale
        && !progress_recent
        && progress_stall_corroborated;

    // Missing heartbeats are only one signal; remediation needs multiple corroborating signals.
    let mut confidence: f64 = 0.0;
    if !input.hook_alive {
        confidence += 0.60;
    }
    if heartbeat_stale {
        confidence += 0.25;
    }
    if progress_stale {
        confidence += 0.15;
    }
    if remediable_progress_stale {
        confidence += 0.65;
    }
    if progress_recent {
        confidence = (confidence - 0.20).max(0.0);
    }
    if input.slots_owned > 0 {
        confidence += 0.05;
    }
    if input.has_worker_binding {
        confidence += 0.05;
    }
    if input.build_age_secs < MIN_BUILD_AGE_SECS {
        confidence = (confidence - 0.25).max(0.0);
    }
    let confidence = confidence.clamp(0.0, 1.0);

    StuckEvidence {
        hook_alive: input.hook_alive,
        heartbeat_stale,
        progress_stale,
        remediable_progress_stale,
        heartbeat_age_secs: input.heartbeat_age_secs,
        progress_age_secs: input.progress_age_secs,
        build_age_secs: input.build_age_secs,
        slots_owned: input.slots_owned,
        has_worker_binding: input.has_worker_binding,
        confidence,
    }
}

fn is_progress_stall_remediable_phase(phase: &rch_common::BuildHeartbeatPhase) -> bool {
    matches!(
        phase,
        rch_common::BuildHeartbeatPhase::SyncUp
            | rch_common::BuildHeartbeatPhase::Execute
            | rch_common::BuildHeartbeatPhase::SyncDown
            | rch_common::BuildHeartbeatPhase::Finalize
    )
}

pub struct ActiveBuildCleanup {
    context: DaemonContext,
}

/// Owns the task that can cancel builds, not the unrelated worker-pruning task.
/// A plain JoinHandle allowed shutdown to stop the wrong background service.
/// Keep this type distinct so that mistake cannot satisfy the shutdown API.
#[must_use = "retain the active-build cleanup task until daemon shutdown"]
pub struct ActiveBuildCleanupTask {
    task: tokio::task::JoinHandle<()>,
}

impl Drop for ActiveBuildCleanupTask {
    fn drop(&mut self) {
        // Early startup failure or an abandoned shutdown future must not
        // detach the observer. Normal shutdown also joins it below.
        self.task.abort();
    }
}

/// Join the cancellation task before any potentially slow shutdown work.
/// Once socket admission ends, missed heartbeats are no longer evidence that
/// a client or its worker has stopped making progress.
pub async fn stop_before_shutdown(
    cleanup_handle: &mut Option<ActiveBuildCleanupTask>,
    shutdown: impl std::future::Future<Output = ()>,
) {
    if let Some(mut handle) = cleanup_handle.take() {
        handle.task.abort();
        if let Err(error) = (&mut handle.task).await
            && !error.is_cancelled()
        {
            warn!(%error, "Cleanup task failed while stopping daemon");
        }
    }
    shutdown.await;
}

impl ActiveBuildCleanup {
    pub fn new(context: DaemonContext) -> Self {
        Self { context }
    }

    pub fn start(self) -> ActiveBuildCleanupTask {
        ActiveBuildCleanupTask {
            task: tokio::spawn(async move {
                let mut ticker = interval(Duration::from_secs(5));
                ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
                let mut observation = ObservationWindow::for_startup(Instant::now());
                let mut recovered_queue = RecoveredQueueCleanup::default();
                loop {
                    ticker.tick().await;
                    // This must also run when there are no active builds.
                    recovered_queue.check(&self.context);
                    self.check_active_builds_observed(&mut observation).await;
                }
            }),
        }
    }

    #[cfg(test)]
    async fn check_active_builds(&self) {
        self.check_active_builds_observed(&mut ObservationWindow::default())
            .await;
    }

    async fn check_active_builds_observed(&self, observation: &mut ObservationWindow) {
        let triage_started = Instant::now();
        observation.recovering(triage_started);
        let active_builds = self.context.history.active_builds();
        if active_builds.is_empty() {
            return;
        }
        let active_build_count = active_builds.len();

        for candidate in active_builds {
            // Cancellation of a previous candidate can await remote I/O. Never
            // reuse the sweep's old heartbeat snapshot after that await.
            let Some(build) = self.context.history.active_build(candidate.id) else {
                continue;
            };
            let now = Instant::now();
            let recovering = observation.recovering_build(now, build.recovered);
            let hook_alive = build.hook_pid == 0 || is_process_alive(build.hook_pid);
            let heartbeat_age_secs = now
                .checked_duration_since(build.last_heartbeat_mono)
                .unwrap_or_default()
                .as_secs();
            let progress_age_secs = now
                .checked_duration_since(build.last_progress_mono)
                .unwrap_or_default()
                .as_secs();
            let build_age_secs = now
                .checked_duration_since(build.started_at_mono)
                .unwrap_or_default()
                .as_secs();
            let slots_owned = build.slots;
            let has_worker_binding = !build.worker_id.is_empty();
            let evidence = score_stuck_evidence(StuckEvidenceInput {
                hook_alive,
                progress_stall_remediable_phase: is_progress_stall_remediable_phase(
                    &build.heartbeat_phase,
                ),
                heartbeat_age_secs,
                progress_age_secs,
                build_age_secs,
                slots_owned,
                has_worker_binding,
            });
            let _ = self.context.history.record_stuck_detector_snapshot(
                build.id,
                StuckDetectorSnapshot {
                    hook_alive: evidence.hook_alive,
                    heartbeat_stale: evidence.heartbeat_stale,
                    progress_stale: evidence.progress_stale,
                    confidence: evidence.confidence,
                    build_age_secs: evidence.build_age_secs,
                    slots_owned: evidence.slots_owned,
                },
            );

            // Preserve the absolute lifetime cap even during observer recovery.
            if !evidence.should_remediate_after_observation(recovering) {
                if !evidence.hook_alive || evidence.heartbeat_stale || evidence.progress_stale {
                    debug!(
                        build_id = build.id,
                        project_id = %build.project_id,
                        worker_id = %build.worker_id,
                        phase = ?build.heartbeat_phase,
                        hook_alive = evidence.hook_alive,
                        heartbeat_stale = evidence.heartbeat_stale,
                        progress_stale = evidence.progress_stale,
                        remediable_progress_stale = evidence.remediable_progress_stale,
                        hb_age = evidence.heartbeat_age_secs,
                        progress_age = evidence.progress_age_secs,
                        build_age = evidence.build_age_secs,
                        slots = evidence.slots_owned,
                        confidence = evidence.confidence,
                        "Build retained by stuck detector"
                    );
                }
                continue;
            }

            warn!(
                build_id = build.id,
                project_id = %build.project_id,
                worker_id = %build.worker_id,
                phase = ?build.heartbeat_phase,
                hook_alive = evidence.hook_alive,
                heartbeat_stale = evidence.heartbeat_stale,
                progress_stale = evidence.progress_stale,
                remediable_progress_stale = evidence.remediable_progress_stale,
                hb_age = evidence.heartbeat_age_secs,
                progress_age = evidence.progress_age_secs,
                build_age = evidence.build_age_secs,
                slots = evidence.slots_owned,
                confidence = evidence.confidence,
                decision = "cancel",
                reason = "stuck_detector",
                "Cleaning up build due to high-confidence stuck evidence"
            );

            // Delegate to CancellationOrchestrator for deterministic cleanup.
            let _ = self
                .context
                .cancellation
                .cancel_build(
                    &self.context,
                    build.id,
                    crate::cancellation::CancelReason::StuckDetector,
                    false,
                )
                .await;
        }

        let elapsed_ms = duration_millis_u64(triage_started.elapsed());
        if elapsed_ms > TRIAGE_BUDGET_MS {
            warn!(
                "Stuck detector triage loop exceeded budget: {}ms > {}ms (active_builds={})",
                elapsed_ms, TRIAGE_BUDGET_MS, active_build_count
            );
            self.context.events.emit(
                "stuck_detector_budget_exceeded",
                &serde_json::json!({
                    "elapsed_ms": elapsed_ms,
                    "budget_ms": TRIAGE_BUDGET_MS,
                    "active_builds": active_build_count,
                }),
            );
        }
    }
}

fn is_process_alive(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }

    // Check /proc first (Linux only) - efficient check without syscall overhead
    if cfg!(target_os = "linux") {
        return Path::new(&format!("/proc/{}", pid)).exists();
    }

    // Fallback to kill -0 for other Unix systems
    std::process::Command::new("kill")
        .arg("-0")
        .arg(pid.to_string())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use rch_common::BuildHeartbeatPhase;
    use rch_common::test_guard;

    #[cfg(unix)]
    mod recovered_queue {
        use super::*;
        use crate::history::BuildHistory;
        use std::sync::Arc;

        struct Owner(std::process::Child);

        impl Owner {
            fn start() -> Self {
                Self(
                    std::process::Command::new("/bin/sleep")
                        .arg("60")
                        .spawn()
                        .unwrap(),
                )
            }

            fn stop(&mut self) {
                self.0.kill().unwrap();
                self.0.wait().unwrap();
            }
        }

        impl Drop for Owner {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }

        fn context(path: &Path) -> DaemonContext {
            let mut context = crate::test_daemon_context(crate::workers::WorkerPool::new());
            context.history = Arc::new(BuildHistory::new(10).with_persistence(path.to_owned()));
            context
        }

        fn enqueue(context: &DaemonContext, pid: u32, wrapper: Option<&str>) -> QueuedBuildState {
            context
                .history
                .enqueue_build(
                    "queue-recovery".into(),
                    "cargo check".into(),
                    pid,
                    2,
                    wrapper.map(str::to_owned),
                )
                .unwrap()
        }

        fn restart(context: &mut DaemonContext, path: &Path) {
            context.history = Arc::new(BuildHistory::load_from_file(path, 10).unwrap());
        }

        #[tokio::test]
        async fn background_task_retires_dead_queue_owners_without_active_builds() {
            let root = tempfile::tempdir().unwrap();
            let path = root.path().join("history.jsonl");
            let mut context = context(&path);
            let mut dead = Owner::start();
            let mut live = Owner::start();
            let gone = enqueue(&context, dead.0.id(), Some("dead-owner"));
            let anonymous = enqueue(&context, dead.0.id(), None);
            let kept = enqueue(&context, live.0.id(), Some("live-owner"));
            let unknown = enqueue(&context, 0, Some("unknown-owner"));
            restart(&mut context, &path);
            let before = serde_json::to_value(context.history.queued_build(kept.id)).unwrap();
            dead.stop();
            let mut task = Some(ActiveBuildCleanup::new(context.clone()).start());
            tokio::time::timeout(Duration::from_secs(3), async {
                while context.history.queued_build(gone.id).is_some()
                    || context.history.queued_build(anonymous.id).is_some()
                {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("the actual observer must reap a queue-only daemon");
            stop_before_shutdown(&mut task, async {}).await;
            assert!(context.history.wrapper_cancelled("dead-owner"));
            assert_eq!(context.history.queue_depth(), 2);
            assert!(context.history.active_builds().is_empty());
            assert!(context.pool.is_empty());
            assert_eq!(
                serde_json::to_value(context.history.queued_build(kept.id)).unwrap(),
                before
            );
            assert!(context.history.queued_build(unknown.id).is_some());
            assert!(live.0.try_wait().unwrap().is_none());
            restart(&mut context, &path);
            assert_eq!(context.history.queue_depth(), 2);
            assert!(context.history.wrapper_cancelled("dead-owner"));
            assert!(context.history.queued_build(gone.id).is_none());
        }

        #[tokio::test]
        async fn live_missing_and_replaced_identity_are_distinguished_without_signalling() {
            let root = tempfile::tempdir().unwrap();
            let path = root.path().join("history.jsonl");
            let context = context(&path);
            let mut owner = Owner::start();
            let mut row = enqueue(&context, owner.0.id(), Some("owner"));
            assert!(
                recovered_queue_owner_gone(&row).is_none(),
                "live waiter owns normal cleanup"
            );
            row.recovered = true;
            assert!(recovered_queue_owner_gone(&row).is_none());
            row.hook_process_identity = None;
            assert!(
                recovered_queue_owner_gone(&row).is_none(),
                "unknown is not dead"
            );
            // Model a different incarnation, not actual operating-system PID reuse.
            #[cfg(target_os = "linux")]
            {
                let actual = crate::history::process_identity(owner.0.id()).unwrap();
                row.hook_process_identity = Some(format!("{actual}-prior"));
                assert_eq!(
                    recovered_queue_owner_gone(&row),
                    Some("queued_owner_replaced")
                );
            }
            assert!(owner.0.try_wait().unwrap().is_none());
            for pid in [0, 1, u32::MAX] {
                row.hook_pid = pid;
                assert!(recovered_queue_owner_gone(&row).is_none());
            }
            row.hook_pid = owner.0.id();
            row.hook_process_identity = None;
            owner.stop();
            assert_eq!(
                recovered_queue_owner_gone(&row),
                Some("queued_owner_exited")
            );
            row.recovered = false;
            assert!(recovered_queue_owner_gone(&row).is_none());
        }

        #[tokio::test]
        async fn stale_queue_observation_cannot_cancel_an_admitted_build_or_release_slots() {
            let root = tempfile::tempdir().unwrap();
            let path = root.path().join("history.jsonl");
            let mut context = context(&path);
            let mut owner = Owner::start();
            let queued = enqueue(&context, owner.0.id(), Some("admitted-owner"));
            restart(&mut context, &path);
            let stale = context.history.queued_build(queued.id).unwrap();
            owner.stop();
            assert!(recovered_queue_owner_gone(&stale).is_some());
            // Model admission winning between the process probe and retirement.
            let id = rch_common::WorkerId::new("reserved-worker");
            context
                .pool
                .add_worker(rch_common::WorkerConfig {
                    id: id.clone(),
                    total_slots: 4,
                    ..Default::default()
                })
                .await;
            let worker = context.pool.get(&id).await.unwrap();
            assert!(worker.reserve_slots(2).await);
            let active = context
                .history
                .try_start_active_build_with_wrapper(
                    queued.project_id,
                    id.to_string(),
                    queued.command,
                    queued.hook_pid,
                    queued.local_wrapper_id,
                    2,
                    rch_common::BuildLocation::Remote,
                )
                .unwrap()
                .unwrap();
            assert!(!retire_recovered_queue_owner(&context, &stale).unwrap());
            assert!(context.history.active_build(active.id).is_some());
            assert!(!context.history.wrapper_cancelled("admitted-owner"));
            assert_eq!(worker.used_slots(), 2);
            assert!(!context.history.has_terminal_build(active.id));
        }

        #[tokio::test]
        async fn failed_retirement_keeps_visibility_and_original_durable_evidence() {
            let root = tempfile::tempdir().unwrap();
            let path = root.path().join("history.jsonl");
            let mut context = context(&path);
            let mut owner = Owner::start();
            let row = enqueue(&context, owner.0.id(), Some("failed-owner"));
            let original = std::fs::read(path.with_extension("ownership.json")).unwrap();
            let blocker = root.path().join("not-a-directory");
            std::fs::write(&blocker, "retained test evidence").unwrap();
            context.history = Arc::new(
                BuildHistory::load_from_file(&path, 10)
                    .unwrap()
                    .with_persistence(blocker.join("history.jsonl")),
            );
            owner.stop();
            let mut reaper = RecoveredQueueCleanup::default();
            reaper.check(&context);
            assert!(context.history.ownership_failed());
            assert!(context.history.queued_build(row.id).is_some());
            assert!(!context.history.wrapper_cancelled("failed-owner"));
            reaper.check(&context);
            assert!(context.history.queued_build(row.id).is_some());
            // Loading may advance the counter, so compare the row after reopening
            // rather than attributing that legitimate rewrite to failed cleanup.
            let reopened = BuildHistory::load_from_file(&path, 10).unwrap();
            assert!(reopened.queued_build(row.id).is_some());
            let original: serde_json::Value = serde_json::from_slice(&original).unwrap();
            assert_eq!(
                serde_json::to_value(reopened.queued_build(row.id).unwrap()).unwrap(),
                original["queued"][0]
            );
            assert!(!reopened.wrapper_cancelled("failed-owner"));
        }

        #[tokio::test]
        async fn bounded_recovery_scan_advances_past_a_live_prefix() {
            let root = tempfile::tempdir().unwrap();
            let path = root.path().join("history.jsonl");
            let mut context = context(&path);
            let mut owner = Owner::start();
            for i in 0..RECOVERED_QUEUE_PROBES_PER_TICK {
                enqueue(&context, std::process::id(), Some(&format!("keeper-{i}")));
            }
            let dead = enqueue(&context, owner.0.id(), Some("dead-tail"));
            restart(&mut context, &path);
            owner.stop();
            let mut reaper = RecoveredQueueCleanup::default();
            reaper.check(&context);
            assert!(
                context.history.queued_build(dead.id).is_some(),
                "first batch is bounded"
            );
            reaper.check(&context);
            assert!(
                context.history.queued_build(dead.id).is_none(),
                "live prefix must not starve tail"
            );
            assert_eq!(
                context.history.queue_depth(),
                RECOVERED_QUEUE_PROBES_PER_TICK
            );
            assert!(context.history.wrapper_cancelled("dead-tail"));
            assert!(context.history.active_builds().is_empty());
        }
    }

    #[tokio::test]
    async fn dropping_cleanup_task_cancels_actual_background_observer() {
        let context = crate::test_daemon_context(crate::workers::WorkerPool::new());
        let history = std::sync::Arc::downgrade(&context.history);
        let task = ActiveBuildCleanup::new(context).start();
        tokio::task::yield_now().await;
        assert!(
            history.upgrade().is_some(),
            "running observer owns its context"
        );
        drop(task);
        tokio::time::timeout(Duration::from_secs(2), async {
            while history.upgrade().is_some() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("dropping the handle must cancel, not detach, the real observer");
    }

    #[tokio::test]
    async fn shutdown_joins_active_cleanup_not_unrelated_maintenance() {
        let context = crate::test_daemon_context(crate::workers::WorkerPool::new());
        let history = std::sync::Arc::downgrade(&context.history);
        let mut cleanup = Some(ActiveBuildCleanup::new(context).start());
        let maintenance = tokio::spawn(std::future::pending::<()>());
        tokio::task::yield_now().await;
        assert!(history.upgrade().is_some());
        stop_before_shutdown(&mut cleanup, async {
            assert!(
                history.upgrade().is_none(),
                "join before polling shutdown work"
            );
            assert!(!maintenance.is_finished(), "do not substitute another task");
        })
        .await;
        assert!(cleanup.is_none());
        // A repeated stop still performs the caller's shutdown work.
        let mut ran = false;
        stop_before_shutdown(&mut cleanup, async { ran = true }).await;
        assert!(ran);
        maintenance.abort();
        assert!(maintenance.await.unwrap_err().is_cancelled());
    }

    #[tokio::test]
    async fn abandoning_slow_shutdown_cannot_leave_cleanup_running() {
        let context = crate::test_daemon_context(crate::workers::WorkerPool::new());
        let history = std::sync::Arc::downgrade(&context.history);
        let mut cleanup = Some(ActiveBuildCleanup::new(context).start());
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let mut stopping = Box::pin(stop_before_shutdown(&mut cleanup, async move {
            entered_tx.send(()).unwrap();
            std::future::pending::<()>().await;
        }));
        tokio::time::timeout(Duration::from_secs(2), async {
            tokio::select! {
                _ = &mut stopping => panic!("slow shutdown must still be pending"),
                result = entered_rx => result.expect("shutdown work entered"),
            }
        })
        .await
        .expect("cleanup must finish before entering slow shutdown work");
        drop(stopping);
        assert!(cleanup.is_none());
        assert!(
            history.upgrade().is_none(),
            "observer cannot survive abandoned shutdown"
        );
    }

    #[test]
    fn startup_grace_applies_only_to_recovered_builds_and_expires_at_the_boundary() {
        let start = Instant::now();
        let mut observation = ObservationWindow::for_startup(start);
        for seconds in [0, 5, 10, 19, 20, 21, 25] {
            let now = start + Duration::from_secs(seconds);
            assert!(!observation.recovering_build(now, false));
            assert_eq!(
                observation.recovering_build(now, true),
                seconds < HEARTBEAT_STALE_SECS
            );
        }
        // A recovered build seen later does not get another startup window.
        assert!(!observation.recovering_build(start + Duration::from_secs(30), true));
        assert_eq!(
            observation.startup_until,
            Some(start + Duration::from_secs(20))
        );
    }

    #[test]
    fn startup_grace_never_rewrites_evidence_or_extends_the_absolute_lifetime_cap() {
        let start = Instant::now();
        let mut observation = ObservationWindow::for_startup(start);
        let grace = observation.recovering_build(start, true);
        assert!(grace);
        for (age, expected) in [(1600, false), (86400, false), (86401, true)] {
            let evidence = score_stuck_evidence(StuckEvidenceInput {
                hook_alive: true,
                progress_stall_remediable_phase: true,
                heartbeat_age_secs: 120,
                progress_age_secs: 120,
                build_age_secs: age,
                slots_owned: 1,
                has_worker_binding: true,
            });
            assert!(
                evidence.should_remediate(),
                "negative control without recovery grace"
            );
            assert_eq!(evidence.should_remediate_after_observation(grace), expected);
            assert_eq!(evidence.heartbeat_age_secs, 120);
            assert_eq!(evidence.progress_age_secs, 120);
        }
    }

    #[test]
    fn later_observer_pause_does_not_restart_the_startup_deadline() {
        let start = Instant::now();
        let mut observation = ObservationWindow::for_startup(start);
        for seconds in [0, 10, 20, 25] {
            observation.recovering_build(start + Duration::from_secs(seconds), true);
        }
        let deadline = observation.startup_until;
        // A genuine later observer pause retains its existing separate grace.
        assert!(observation.recovering_build(start + Duration::from_secs(65), false));
        assert_eq!(observation.startup_until, deadline);
        assert!(!observation.recovering_build(start + Duration::from_secs(105), true));
        assert_eq!(observation.startup_until, deadline);
    }

    #[test]
    fn observer_normal_cadence_and_cold_start_preserve_stuck_decisions() {
        let start = Instant::now();
        let mut observation = ObservationWindow::default();
        for seconds in [0, 5, 10, 15, 20, 25, 30] {
            assert!(!observation.recovering(start + Duration::from_secs(seconds)));
            for hook_alive in [false, true] {
                assert!(
                    score_stuck_evidence(StuckEvidenceInput {
                        hook_alive,
                        progress_stall_remediable_phase: true,
                        heartbeat_age_secs: 445,
                        progress_age_secs: 515,
                        build_age_secs: 1600,
                        slots_owned: 1,
                        has_worker_binding: true,
                    })
                    .should_remediate()
                );
            }
        }
    }

    #[test]
    fn observer_pause_grants_one_bounded_window_without_faking_progress() {
        let start = Instant::now();
        let mut observation = ObservationWindow::default();
        assert!(!observation.recovering(start));
        let resumed = start + Duration::from_millis(441_361);
        assert!(observation.recovering(resumed));
        assert!(observation.recovering(resumed + Duration::from_secs(19)));
        assert!(!observation.recovering(resumed + Duration::from_secs(20)));
        // A resumed live hook sends a real heartbeat, even if its compiler is
        // still quiet. A dead hook and a live-but-stalled hook remain actionable.
        for (hook_alive, heartbeat_age_secs, expected) in
            [(true, 0, false), (false, 465, true), (true, 465, true)]
        {
            let evidence = score_stuck_evidence(StuckEvidenceInput {
                hook_alive,
                progress_stall_remediable_phase: true,
                heartbeat_age_secs,
                progress_age_secs: 535,
                build_age_secs: 1620,
                slots_owned: 1,
                has_worker_binding: true,
            });
            assert_eq!(evidence.should_remediate(), expected);
        }
    }

    #[test]
    fn observer_gap_during_cancellation_is_detected_and_cannot_extend_grace() {
        let start = Instant::now();
        let mut observation = ObservationWindow::default();
        assert!(!observation.recovering(start));
        // These observations are candidates in one sweep, not ticker calls.
        assert!(!observation.recovering(start + Duration::from_millis(1)));
        let after_cancellation = start + Duration::from_secs(441);
        assert!(observation.recovering(after_cancellation));
        // Another delayed cancellation consumes, rather than renews, the grace.
        assert!(!observation.recovering(after_cancellation + Duration::from_secs(40)));
        assert!(!observation.recovering(after_cancellation + Duration::from_secs(45)));
    }

    #[test]
    fn observer_recovery_preserves_absolute_lifetime_cap() {
        for (age, expected) in [(86400, false), (86401, true)] {
            let evidence = score_stuck_evidence(StuckEvidenceInput {
                hook_alive: true,
                progress_stall_remediable_phase: true,
                heartbeat_age_secs: 445,
                progress_age_secs: 515,
                build_age_secs: age,
                slots_owned: 1,
                has_worker_binding: true,
            });
            assert_eq!(evidence.should_remediate_after_observation(true), expected);
            assert!(evidence.should_remediate_after_observation(false));
        }
    }

    // Isolate the transport override from other tests. The substitute SSH runs
    // the actual cancellation command locally; it never invents a receipt.
    #[cfg(target_os = "linux")]
    async fn isolated_cleanup_transport(test: &str) -> Option<std::path::PathBuf> {
        const ROOT: &str = "RCH_CLEANUP_TEST_ROOT";
        if let Some(root) = std::env::var_os(ROOT) {
            return Some(root.into());
        }
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap().keep();
        let ssh = root.join("ssh");
        std::fs::write(
            &ssh,
            "#!/bin/sh\nfor arg do command=$arg; done\nexec /bin/sh -c \"$command\"\n",
        )
        .unwrap();
        std::fs::set_permissions(&ssh, std::fs::Permissions::from_mode(0o700)).unwrap();
        let output = tokio::time::timeout(
            Duration::from_secs(240),
            tokio::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", test, "--nocapture"])
                .env(ROOT, &root)
                .env("PATH", format!("{}:/usr/bin:/bin", root.display()))
                .kill_on_drop(true)
                .output(),
        )
        .await
        .expect("isolated cleanup test timed out")
        .unwrap();
        assert!(
            output.status.success(),
            "isolated cleanup failed: {output:?}"
        );
        assert!(
            root.join("completed").is_file(),
            "child test did not finish"
        );
        None
    }

    #[cfg(target_os = "linux")]
    async fn cleanup_worker_context(id: &str, slots: u32) -> DaemonContext {
        let pool = crate::workers::WorkerPool::new();
        let config = rch_common::WorkerConfig {
            id: rch_common::WorkerId::new(id),
            total_slots: slots,
            ..Default::default()
        };
        pool.add_worker(config).await;
        assert!(
            pool.get(&rch_common::WorkerId::new(id))
                .await
                .unwrap()
                .reserve_slots(slots)
                .await
        );
        crate::test_daemon_context(pool)
    }

    /// Admit like production selection does: with the worker's endpoint, so
    /// cancellation can target the admitted SSH coordinates (60ee09f).
    async fn admit_remote_build(
        context: &DaemonContext,
        project: String,
        worker: &str,
        hook_pid: u32,
        wrapper: Option<String>,
    ) -> crate::history::ActiveBuildState {
        let endpoint = context
            .pool
            .get(&rch_common::WorkerId::new(worker))
            .await
            .unwrap()
            .endpoint_snapshot()
            .await;
        context
            .history
            .try_start_active_build_with_waiter(
                project,
                worker.into(),
                "sleep 180".into(),
                hook_pid,
                wrapper,
                1,
                rch_common::BuildLocation::Remote,
                None,
                crate::disk_pressure::DiskHeadroomAdmission::default(),
                Some(endpoint),
            )
            .unwrap()
            .unwrap()
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn restarted_observer_allows_reattachment_then_reaps_a_still_stale_job() {
        use crate::history::{ActiveBuildState, BuildHistory};
        use std::os::unix::process::CommandExt;
        use std::sync::Arc;

        let Some(root) = isolated_cleanup_transport(
            "cleanup::tests::restarted_observer_allows_reattachment_then_reaps_a_still_stale_job",
        )
        .await
        else {
            return;
        };
        struct QuietJob(std::process::Child);
        impl Drop for QuietJob {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let mut jobs: Vec<_> = (0..2)
            .map(|_| {
                QuietJob(
                    std::process::Command::new("/bin/sleep")
                        .arg("180")
                        .process_group(0)
                        .spawn()
                        .unwrap(),
                )
            })
            .collect();
        let mut context = cleanup_worker_context("restart-observer-worker", 2).await;
        let path = root.join("history.jsonl");
        context.history = Arc::new(BuildHistory::new(10).with_persistence(path.clone()));
        let heartbeat = |build: &ActiveBuildState| rch_common::BuildHeartbeatRequest {
            build_id: build.id,
            worker_id: rch_common::WorkerId::new(&build.worker_id),
            hook_pid: Some(build.hook_pid),
            local_wrapper_id: build.local_wrapper_id.clone(),
            remote_pgid_file: Some(
                root.join(format!("{}.pgid", build.hook_pid))
                    .to_string_lossy()
                    .into_owned(),
            ),
            phase: BuildHeartbeatPhase::Execute,
            detail: None,
            progress_counter: None,
            progress_percent: None,
        };
        let mut builds = Vec::new();
        for (index, job) in jobs.iter().enumerate() {
            std::fs::write(
                root.join(format!("{}.pgid", job.0.id())),
                job.0.id().to_string(),
            )
            .unwrap();
            let build = admit_remote_build(
                &context,
                format!("restart-observer-{index}"),
                "restart-observer-worker",
                job.0.id(),
                Some(format!("restart-wrapper-{index}")),
            )
            .await;
            builds.push(
                context
                    .history
                    .record_build_heartbeat(heartbeat(&build))
                    .unwrap(),
            );
        }

        // Model downtime in durable timestamps, then use the production loader.
        // This is not a native kill/restart or an elapsed-time qualification.
        let ownership = path.with_extension("ownership.json");
        let mut snapshot: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&ownership).unwrap()).unwrap();
        let old = (chrono::Utc::now() - chrono::Duration::seconds(120)).to_rfc3339();
        for row in snapshot["active"].as_array_mut().unwrap() {
            for field in ["started_at", "last_heartbeat_at", "last_progress_at"] {
                row[field] = serde_json::json!(&old);
            }
        }
        std::fs::write(&ownership, serde_json::to_vec(&snapshot).unwrap()).unwrap();
        context.history = Arc::new(BuildHistory::load_from_file(&path, 10).unwrap());
        let before: Vec<_> = builds
            .iter()
            .map(|build| context.history.active_build(build.id).unwrap())
            .collect();
        assert!(before.iter().all(|build| build.recovered));
        let cleanup = ActiveBuildCleanup::new(context.clone());
        let mut observation = ObservationWindow::for_startup(Instant::now());
        cleanup.check_active_builds_observed(&mut observation).await;
        for (build, job) in before.iter().zip(&mut jobs) {
            let retained = context.history.active_build(build.id).unwrap();
            assert_eq!(retained.last_heartbeat_mono, build.last_heartbeat_mono);
            assert_eq!(retained.last_progress_mono, build.last_progress_mono);
            assert!(retained.detector_heartbeat_stale);
            assert!(job.0.try_wait().unwrap().is_none());
        }

        // A real reattachment heartbeat rescues one owner. Explicitly expire
        // only the observer's test deadline; do not fabricate client progress.
        context
            .history
            .record_build_heartbeat(heartbeat(&builds[0]))
            .unwrap();
        observation.startup_until = Some(Instant::now());
        cleanup.check_active_builds_observed(&mut observation).await;
        assert!(context.history.active_build(builds[0].id).is_some());
        assert!(jobs[0].0.try_wait().unwrap().is_none());
        assert!(context.history.active_build(builds[1].id).is_none());
        assert!(jobs[1].0.try_wait().unwrap().is_some());
        assert_eq!(
            context
                .pool
                .get(&rch_common::WorkerId::new("restart-observer-worker"))
                .await
                .unwrap()
                .used_slots(),
            1,
        );
        std::fs::write(root.join("completed"), "ok").unwrap();
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn observer_recovery_retains_resuming_job_and_reaps_real_stale_jobs() {
        use std::os::unix::process::CommandExt;
        let Some(root) = isolated_cleanup_transport(
            "cleanup::tests::observer_recovery_retains_resuming_job_and_reaps_real_stale_jobs",
        )
        .await
        else {
            return;
        };
        struct QuietJob(std::process::Child);
        impl Drop for QuietJob {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let mut jobs: Vec<_> = (0..3)
            .map(|_| {
                QuietJob(
                    std::process::Command::new("sleep")
                        .arg("180")
                        .process_group(0)
                        .spawn()
                        .unwrap(),
                )
            })
            .collect();
        let context = cleanup_worker_context("observer-worker", 3).await;
        for job in &jobs {
            std::fs::write(
                root.join(format!("{}.pgid", job.0.id())),
                job.0.id().to_string(),
            )
            .unwrap();
        }
        let heartbeat = |id, pid| rch_common::BuildHeartbeatRequest {
            build_id: id,
            worker_id: rch_common::WorkerId::new("observer-worker"),
            hook_pid: Some(pid),
            local_wrapper_id: None,
            remote_pgid_file: Some(
                root.join(format!("{pid}.pgid"))
                    .to_string_lossy()
                    .into_owned(),
            ),
            phase: BuildHeartbeatPhase::Execute,
            detail: None,
            progress_counter: None,
            progress_percent: None,
        };
        let mut builds = Vec::new();
        for (index, job) in jobs.iter().enumerate() {
            let build = admit_remote_build(
                &context,
                format!("observer-recovery-{index}"),
                "observer-worker",
                job.0.id(),
                None,
            )
            .await;
            context
                .history
                .record_build_heartbeat(heartbeat(build.id, job.0.id()))
                .unwrap();
            builds.push(context.history.active_build(build.id).unwrap());
        }
        let mut observation = ObservationWindow::default();
        assert!(!observation.recovering(Instant::now()));
        // Real history uses std::time::Instant: age actual children and actual
        // heartbeats past both production stale thresholds without forging them.
        tokio::time::sleep(Duration::from_secs(PROGRESS_STALE_SECS + 6)).await;
        jobs[2].0.kill().unwrap();
        // Keep the exited leader unreaped until confirmation so its PID/PGID
        // cannot be reused for an unrelated process while cancellation runs.
        let cleanup = ActiveBuildCleanup::new(context.clone());
        cleanup.check_active_builds_observed(&mut observation).await;
        for build in &builds {
            let retained = context.history.active_build(build.id).unwrap();
            assert_eq!(retained.last_heartbeat_mono, build.last_heartbeat_mono);
            assert_eq!(retained.last_progress_mono, build.last_progress_mono);
        }
        assert!(jobs[0].0.try_wait().unwrap().is_none());
        assert!(jobs[1].0.try_wait().unwrap().is_none());
        assert!(observation.recover_until.is_some());
        assert_eq!(
            context
                .pool
                .get(&rch_common::WorkerId::new("observer-worker"))
                .await
                .unwrap()
                .used_slots(),
            3
        );
        // Past the recovery window, and past the live-hook silence limit for jobs[1].
        tokio::time::sleep(Duration::from_secs(
            (LIVE_HOOK_HEARTBEAT_STALE_SECS - PROGRESS_STALE_SECS).max(HEARTBEAT_STALE_SECS) + 1,
        ))
        .await;
        context
            .history
            .record_build_heartbeat(heartbeat(builds[0].id, jobs[0].0.id()))
            .unwrap();
        cleanup.check_active_builds_observed(&mut observation).await;
        assert!(context.history.active_build(builds[0].id).is_some());
        assert!(jobs[0].0.try_wait().unwrap().is_none());
        for index in [1, 2] {
            assert!(context.history.active_build(builds[index].id).is_none());
            assert!(jobs[index].0.try_wait().unwrap().is_some());
        }
        assert_eq!(
            context
                .pool
                .get(&rch_common::WorkerId::new("observer-worker"))
                .await
                .unwrap()
                .used_slots(),
            1
        );
        std::fs::write(root.join("completed"), "ok").unwrap();
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn shutdown_retains_live_quiet_job_while_normal_stale_cleanup_still_runs() {
        use std::os::unix::process::CommandExt;
        let Some(root) = isolated_cleanup_transport(
            "cleanup::tests::shutdown_retains_live_quiet_job_while_normal_stale_cleanup_still_runs",
        )
        .await
        else {
            return;
        };
        struct QuietJob(std::process::Child);
        impl Drop for QuietJob {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let mut job = QuietJob(
            std::process::Command::new("sleep")
                .arg("180")
                .process_group(0)
                .spawn()
                .unwrap(),
        );
        let context = cleanup_worker_context("shutdown-test-unbound-worker", 1).await;
        let pgid_file = root.join("shutdown.pgid");
        std::fs::write(&pgid_file, job.0.id().to_string()).unwrap();
        let build = admit_remote_build(
            &context,
            "shutdown-quiet-job".into(),
            "shutdown-test-unbound-worker",
            job.0.id(),
            None,
        )
        .await;
        context
            .history
            .record_build_heartbeat(rch_common::BuildHeartbeatRequest {
                build_id: build.id,
                worker_id: rch_common::WorkerId::new("shutdown-test-unbound-worker"),
                hook_pid: Some(job.0.id()),
                local_wrapper_id: None,
                remote_pgid_file: Some(pgid_file.to_string_lossy().into_owned()),
                phase: BuildHeartbeatPhase::Execute,
                detail: None,
                progress_counter: None,
                progress_percent: None,
            })
            .unwrap();
        let mut cleanup = Some(ActiveBuildCleanup::new(context.clone()).start());
        // Let the real cleanup loop inspect the fresh live job once.
        tokio::task::yield_now().await;
        stop_before_shutdown(&mut cleanup, async {
            // Real elapsed time matters: history uses std::time::Instant, not
            // Tokio's virtual clock. This spans every production stale limit, a live hook's too.
            tokio::time::sleep(Duration::from_secs(LIVE_HOOK_HEARTBEAT_STALE_SECS + 6)).await;
            assert!(job.0.try_wait().unwrap().is_none());
            assert!(context.history.active_build(build.id).is_some());
            assert_eq!(
                context
                    .pool
                    .get(&rch_common::WorkerId::new("shutdown-test-unbound-worker"))
                    .await
                    .unwrap()
                    .used_slots(),
                1
            );
        })
        .await;
        assert!(cleanup.is_none());
        // Negative control: the same now-stale record is still remediated by
        // normal cleanup. Shutdown must not weaken its evidence thresholds.
        ActiveBuildCleanup::new(context.clone())
            .check_active_builds()
            .await;
        assert!(context.history.active_build(build.id).is_none());
        assert!(job.0.try_wait().unwrap().is_some());
        assert_eq!(
            context
                .pool
                .get(&rch_common::WorkerId::new("shutdown-test-unbound-worker"))
                .await
                .unwrap()
                .used_slots(),
            0
        );
        std::fs::write(root.join("completed"), "ok").unwrap();
    }

    #[test]
    fn test_duration_millis_u64_saturates() {
        let _guard = test_guard!();
        assert_eq!(duration_millis_u64(Duration::from_secs(u64::MAX)), u64::MAX);
    }

    fn heartbeat_phase_strategy() -> impl Strategy<Value = BuildHeartbeatPhase> {
        prop_oneof![
            Just(BuildHeartbeatPhase::SyncUp),
            Just(BuildHeartbeatPhase::Execute),
            Just(BuildHeartbeatPhase::SyncDown),
            Just(BuildHeartbeatPhase::Finalize),
        ]
    }

    #[test]
    fn test_score_stuck_evidence_high_confidence_for_dead_hook_and_stale_heartbeat() {
        let _guard = test_guard!();
        let evidence = score_stuck_evidence(StuckEvidenceInput {
            hook_alive: false,
            progress_stall_remediable_phase: true,
            heartbeat_age_secs: HEARTBEAT_STALE_SECS + 5,
            progress_age_secs: PROGRESS_STALE_SECS + 10,
            build_age_secs: MIN_BUILD_AGE_SECS + 45,
            slots_owned: 4,
            has_worker_binding: true,
        });

        assert!(evidence.heartbeat_stale);
        assert!(evidence.progress_stale);
        assert!(evidence.should_remediate());
    }

    #[test]
    fn test_score_stuck_evidence_temporary_heartbeat_drop_does_not_trigger_remediation() {
        let _guard = test_guard!();
        let evidence = score_stuck_evidence(StuckEvidenceInput {
            hook_alive: true,
            progress_stall_remediable_phase: false,
            heartbeat_age_secs: HEARTBEAT_STALE_SECS + 2,
            progress_age_secs: 4,
            build_age_secs: MIN_BUILD_AGE_SECS + 10,
            slots_owned: 4,
            has_worker_binding: true,
        });

        assert!(evidence.heartbeat_stale);
        assert!(!evidence.should_remediate());
        assert!(evidence.confidence < REMEDIATION_CONFIDENCE_THRESHOLD);
    }

    #[test]
    fn test_score_stuck_evidence_missing_heartbeat_is_insufficient_without_hook_failure() {
        let _guard = test_guard!();
        let evidence = score_stuck_evidence(StuckEvidenceInput {
            hook_alive: true,
            progress_stall_remediable_phase: false,
            heartbeat_age_secs: HEARTBEAT_STALE_SECS + 60,
            progress_age_secs: PROGRESS_STALE_SECS + 60,
            build_age_secs: MIN_BUILD_AGE_SECS + 90,
            slots_owned: 2,
            has_worker_binding: true,
        });

        assert!(evidence.heartbeat_stale);
        assert!(evidence.progress_stale);
        assert!(!evidence.should_remediate());
    }

    #[test]
    fn test_score_stuck_evidence_execute_progress_stall_retains_fresh_live_hook() {
        let _guard = test_guard!();
        let evidence = score_stuck_evidence(StuckEvidenceInput {
            hook_alive: true,
            progress_stall_remediable_phase: true,
            heartbeat_age_secs: 1,
            progress_age_secs: PROGRESS_STALE_SECS + 60,
            build_age_secs: MIN_BUILD_AGE_SECS + 90,
            slots_owned: 2,
            has_worker_binding: true,
        });

        assert!(!evidence.heartbeat_stale);
        assert!(evidence.progress_stale);
        assert!(!evidence.remediable_progress_stale);
        assert!(!evidence.should_remediate());
        assert!(evidence.confidence < REMEDIATION_CONFIDENCE_THRESHOLD);
    }

    #[test]
    fn test_score_stuck_evidence_execute_progress_stall_remediates_silent_live_hook() {
        let _guard = test_guard!();
        let evidence = score_stuck_evidence(StuckEvidenceInput {
            hook_alive: true,
            progress_stall_remediable_phase: true,
            heartbeat_age_secs: LIVE_HOOK_HEARTBEAT_STALE_SECS + 1,
            progress_age_secs: PROGRESS_STALE_SECS + 60,
            build_age_secs: MIN_BUILD_AGE_SECS + 90,
            slots_owned: 2,
            has_worker_binding: true,
        });

        assert!(evidence.heartbeat_stale);
        assert!(evidence.progress_stale);
        assert!(evidence.remediable_progress_stale);
        assert!(evidence.should_remediate());
    }

    #[test]
    fn test_score_stuck_evidence_one_late_heartbeat_from_live_hook_retains_silent_compile() {
        let _guard = test_guard!();
        // The exact evidence of the 2026-09-28 20:32:23Z cancellation of a healthy build on hz4:
        // a live hook whose heartbeat was 23 s old while rustc compiled one crate silently.
        let observed = StuckEvidenceInput {
            hook_alive: true,
            progress_stall_remediable_phase: true,
            heartbeat_age_secs: 23,
            progress_age_secs: 740,
            build_age_secs: 996,
            slots_owned: 6,
            has_worker_binding: true,
        };
        let evidence = score_stuck_evidence(observed);

        assert!(evidence.heartbeat_stale);
        assert!(evidence.progress_stale);
        assert!(!evidence.remediable_progress_stale);
        assert!(!evidence.should_remediate());
        assert!(evidence.confidence < REMEDIATION_CONFIDENCE_THRESHOLD);

        // The same silence from a DEAD hook is still remediated at once.
        let dead = score_stuck_evidence(StuckEvidenceInput {
            hook_alive: false,
            ..observed
        });
        assert!(dead.should_remediate());
    }

    #[test]
    fn test_score_stuck_evidence_sync_down_progress_stall_retains_fresh_live_hook() {
        let _guard = test_guard!();
        assert!(is_progress_stall_remediable_phase(
            &rch_common::BuildHeartbeatPhase::SyncDown
        ));

        let evidence = score_stuck_evidence(StuckEvidenceInput {
            hook_alive: true,
            progress_stall_remediable_phase: true,
            heartbeat_age_secs: 1,
            progress_age_secs: PROGRESS_STALE_SECS + 60,
            build_age_secs: MIN_BUILD_AGE_SECS + 90,
            slots_owned: 2,
            has_worker_binding: true,
        });

        assert!(!evidence.heartbeat_stale);
        assert!(evidence.progress_stale);
        assert!(!evidence.remediable_progress_stale);
        assert!(!evidence.should_remediate());
    }

    #[test]
    fn test_score_stuck_evidence_unremediable_progress_stall_retains_live_hook() {
        let _guard = test_guard!();
        let evidence = score_stuck_evidence(StuckEvidenceInput {
            hook_alive: true,
            progress_stall_remediable_phase: false,
            heartbeat_age_secs: 1,
            progress_age_secs: PROGRESS_STALE_SECS + 60,
            build_age_secs: MIN_BUILD_AGE_SECS + 90,
            slots_owned: 2,
            has_worker_binding: true,
        });

        assert!(!evidence.heartbeat_stale);
        assert!(evidence.progress_stale);
        assert!(!evidence.remediable_progress_stale);
        assert!(!evidence.should_remediate());
    }

    #[test]
    fn test_score_stuck_evidence_recent_progress_reduces_confidence() {
        let _guard = test_guard!();
        let evidence = score_stuck_evidence(StuckEvidenceInput {
            hook_alive: false,
            progress_stall_remediable_phase: true,
            heartbeat_age_secs: HEARTBEAT_STALE_SECS + 1,
            progress_age_secs: RECENT_PROGRESS_GRACE_SECS,
            build_age_secs: MIN_BUILD_AGE_SECS + 30,
            slots_owned: 6,
            has_worker_binding: true,
        });

        assert!(!evidence.should_remediate());
        assert!(evidence.confidence < REMEDIATION_CONFIDENCE_THRESHOLD);
    }

    #[test]
    fn test_score_stuck_evidence_short_lived_build_is_not_remediated() {
        let _guard = test_guard!();
        let evidence = score_stuck_evidence(StuckEvidenceInput {
            hook_alive: false,
            progress_stall_remediable_phase: true,
            heartbeat_age_secs: HEARTBEAT_STALE_SECS + 30,
            progress_age_secs: PROGRESS_STALE_SECS + 30,
            build_age_secs: MIN_BUILD_AGE_SECS - 1,
            slots_owned: 4,
            has_worker_binding: true,
        });

        assert!(!evidence.should_remediate());
    }

    #[test]
    fn test_score_stuck_evidence_without_slot_ownership_is_not_remediated() {
        let _guard = test_guard!();
        let evidence = score_stuck_evidence(StuckEvidenceInput {
            hook_alive: false,
            progress_stall_remediable_phase: true,
            heartbeat_age_secs: HEARTBEAT_STALE_SECS + 30,
            progress_age_secs: PROGRESS_STALE_SECS + 30,
            build_age_secs: MIN_BUILD_AGE_SECS + 30,
            slots_owned: 0,
            has_worker_binding: true,
        });

        assert!(!evidence.should_remediate());
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(512))]

        #[test]
        fn stuck_detector_phase_classification_accepts_known_heartbeat_phases(
            phase in heartbeat_phase_strategy(),
        ) {
            let _guard = test_guard!();
            prop_assert!(is_progress_stall_remediable_phase(&phase));
        }

        #[test]
        fn stuck_detector_scoring_is_bounded_and_fail_closed_before_hard_timeout(
            phase in heartbeat_phase_strategy(),
            hook_alive in any::<bool>(),
            heartbeat_age_secs in 0u64..=600,
            progress_age_secs in 0u64..=600,
            build_age_secs in 0u64..=86_400,
            slots_owned in 0u32..=64,
            has_worker_binding in any::<bool>(),
        ) {
            let _guard = test_guard!();
            let phase_remediable = is_progress_stall_remediable_phase(&phase);
            let evidence = score_stuck_evidence(StuckEvidenceInput {
                hook_alive,
                progress_stall_remediable_phase: phase_remediable,
                heartbeat_age_secs,
                progress_age_secs,
                build_age_secs,
                slots_owned,
                has_worker_binding,
            });

            prop_assert_eq!(evidence.heartbeat_stale, heartbeat_age_secs >= HEARTBEAT_STALE_SECS);
            prop_assert_eq!(evidence.progress_stale, progress_age_secs >= PROGRESS_STALE_SECS);
            prop_assert_eq!(
                evidence.remediable_progress_stale,
                phase_remediable
                    && progress_age_secs >= PROGRESS_STALE_SECS
                    && progress_age_secs > RECENT_PROGRESS_GRACE_SECS
                    && (!hook_alive || heartbeat_age_secs >= LIVE_HOOK_HEARTBEAT_STALE_SECS)
            );
            prop_assert!(evidence.confidence.is_finite());
            prop_assert!((0.0..=1.0).contains(&evidence.confidence));

            if evidence.should_remediate() {
                prop_assert!(build_age_secs >= MIN_BUILD_AGE_SECS);
                prop_assert!(slots_owned > 0);
                prop_assert!(has_worker_binding);
                prop_assert!(evidence.confidence >= REMEDIATION_CONFIDENCE_THRESHOLD);
                prop_assert!(
                    (!hook_alive && evidence.heartbeat_stale) || evidence.remediable_progress_stale
                );
            }
        }
    }
}
