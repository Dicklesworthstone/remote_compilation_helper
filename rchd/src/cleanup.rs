//! Background cleanup for active builds with dead hooks.

use crate::{DaemonContext, history::StuckDetectorSnapshot};
use std::path::Path;
use std::time::{Duration, Instant};
use tokio::time::{MissedTickBehavior, interval};
use tracing::{debug, warn};

const HEARTBEAT_STALE_SECS: u64 = 20;
const PROGRESS_STALE_SECS: u64 = 90;
const RECENT_PROGRESS_GRACE_SECS: u64 = 15;
const MIN_BUILD_AGE_SECS: u64 = 30;
const TRIAGE_BUDGET_MS: u64 = 50;
const REMEDIATION_CONFIDENCE_THRESHOLD: f64 = 0.85;

/// A delayed observer cannot distinguish a stalled client from a client whose
/// heartbeat task was paused with it. Allow one normal heartbeat window to
/// collect new evidence, without changing the recorded heartbeat or progress.
#[derive(Default)]
struct ObservationWindow {
    last_observed: Option<Instant>,
    recover_until: Option<Instant>,
}

impl ObservationWindow {
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
    let progress_stall_corroborated = !input.hook_alive || heartbeat_stale;
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

/// Join the cancellation task before any potentially slow shutdown work.
/// Once socket admission ends, missed heartbeats are no longer evidence that
/// a client or its worker has stopped making progress.
pub async fn stop_before_shutdown(
    cleanup_handle: &mut Option<tokio::task::JoinHandle<()>>,
    shutdown: impl std::future::Future<Output = ()>,
) {
    if let Some(handle) = cleanup_handle.take() {
        handle.abort();
        if let Err(error) = handle.await
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

    pub fn start(self) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut ticker = interval(Duration::from_secs(5));
            ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
            let mut observation = ObservationWindow::default();
            loop {
                ticker.tick().await;
                self.check_active_builds_observed(&mut observation).await;
            }
        })
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
            let recovering = observation.recovering(now);
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
        let builds: Vec<_> = jobs
            .iter()
            .enumerate()
            .map(|(index, job)| {
                let build = context.history.start_active_build(
                    format!("observer-recovery-{index}"),
                    "observer-worker".into(),
                    "sleep 180".into(),
                    job.0.id(),
                    1,
                    rch_common::BuildLocation::Remote,
                );
                context
                    .history
                    .record_build_heartbeat(heartbeat(build.id, job.0.id()))
                    .unwrap();
                context.history.active_build(build.id).unwrap()
            })
            .collect();
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
        tokio::time::sleep(Duration::from_secs(HEARTBEAT_STALE_SECS + 1)).await;
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
        let build = context.history.start_active_build(
            "shutdown-quiet-job".into(),
            "shutdown-test-unbound-worker".into(),
            "sleep 180".into(),
            job.0.id(),
            1,
            rch_common::BuildLocation::Remote,
        );
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
            // Tokio's virtual clock. This spans both production stale limits.
            tokio::time::sleep(Duration::from_secs(PROGRESS_STALE_SECS + 6)).await;
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
    fn test_score_stuck_evidence_execute_progress_stall_remediates_stale_heartbeat() {
        let _guard = test_guard!();
        let evidence = score_stuck_evidence(StuckEvidenceInput {
            hook_alive: true,
            progress_stall_remediable_phase: true,
            heartbeat_age_secs: HEARTBEAT_STALE_SECS + 1,
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
                    && (!hook_alive || evidence.heartbeat_stale)
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
