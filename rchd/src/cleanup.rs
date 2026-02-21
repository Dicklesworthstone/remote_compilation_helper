//! Background cleanup for active builds with dead hooks.

use crate::{DaemonContext, history::StuckDetectorSnapshot};
use std::path::Path;
use std::time::{Duration, Instant};
use tokio::time::interval;
use tracing::{debug, warn};

const HEARTBEAT_STALE_SECS: u64 = 20;
const PROGRESS_STALE_SECS: u64 = 90;
const RECENT_PROGRESS_GRACE_SECS: u64 = 15;
const MIN_BUILD_AGE_SECS: u64 = 30;
const TRIAGE_BUDGET_MS: u64 = 50;
const REMEDIATION_CONFIDENCE_THRESHOLD: f64 = 0.85;

#[derive(Debug, Clone, Copy)]
struct StuckEvidenceInput {
    hook_alive: bool,
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
    heartbeat_age_secs: u64,
    progress_age_secs: u64,
    build_age_secs: u64,
    slots_owned: u32,
    has_worker_binding: bool,
    confidence: f64,
}

impl StuckEvidence {
    fn should_remediate(self) -> bool {
        let hard_timeout = self.build_age_secs > 86400; // 24 hours

        hard_timeout || (self.build_age_secs >= MIN_BUILD_AGE_SECS
            && self.slots_owned > 0
            && self.has_worker_binding
            && !self.hook_alive
            && self.heartbeat_stale
            && self.confidence >= REMEDIATION_CONFIDENCE_THRESHOLD)
    }
}

fn score_stuck_evidence(input: StuckEvidenceInput) -> StuckEvidence {
    let heartbeat_stale = input.heartbeat_age_secs >= HEARTBEAT_STALE_SECS;
    let progress_stale = input.progress_age_secs >= PROGRESS_STALE_SECS;
    let progress_recent = input.progress_age_secs <= RECENT_PROGRESS_GRACE_SECS;

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
        heartbeat_age_secs: input.heartbeat_age_secs,
        progress_age_secs: input.progress_age_secs,
        build_age_secs: input.build_age_secs,
        slots_owned: input.slots_owned,
        has_worker_binding: input.has_worker_binding,
        confidence,
    }
}

pub struct ActiveBuildCleanup {
    context: DaemonContext,
}

impl ActiveBuildCleanup {
    pub fn new(context: DaemonContext) -> Self {
        Self { context }
    }

    pub fn start(self) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut ticker = interval(Duration::from_secs(5));
            loop {
                ticker.tick().await;
                self.check_active_builds().await;
            }
        })
    }

    async fn check_active_builds(&self) {
        let triage_started = Instant::now();
        let active_builds = self.context.history.active_builds();
        if active_builds.is_empty() {
            return;
        }
        let active_build_count = active_builds.len();

        let now = Instant::now();
        for build in active_builds {
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

            if !evidence.should_remediate() {
                if !evidence.hook_alive || evidence.heartbeat_stale || evidence.progress_stale {
                    debug!(
                        "Build {} retained (hook_alive={}, hb_age={}s, progress_age={}s, build_age={}s, slots={}, confidence={:.2})",
                        build.id,
                        evidence.hook_alive,
                        evidence.heartbeat_age_secs,
                        evidence.progress_age_secs,
                        evidence.build_age_secs,
                        evidence.slots_owned,
                        evidence.confidence
                    );
                }
                continue;
            }

            warn!(
                "Cleaning up build {} (project: {}) due to high-confidence stuck evidence (hook_alive={}, hb_age={}s, progress_age={}s, build_age={}s, slots={}, confidence={:.2})",
                build.id,
                build.project_id,
                evidence.hook_alive,
                evidence.heartbeat_age_secs,
                evidence.progress_age_secs,
                evidence.build_age_secs,
                evidence.slots_owned,
                evidence.confidence
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

        let elapsed_ms = triage_started.elapsed().as_millis() as u64;
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
    use rch_common::test_guard;

    #[test]
    fn test_score_stuck_evidence_high_confidence_for_dead_hook_and_stale_heartbeat() {
        let _guard = test_guard!();
        let evidence = score_stuck_evidence(StuckEvidenceInput {
            hook_alive: false,
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
    fn test_score_stuck_evidence_recent_progress_reduces_confidence() {
        let _guard = test_guard!();
        let evidence = score_stuck_evidence(StuckEvidenceInput {
            hook_alive: false,
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
            heartbeat_age_secs: HEARTBEAT_STALE_SECS + 30,
            progress_age_secs: PROGRESS_STALE_SECS + 30,
            build_age_secs: MIN_BUILD_AGE_SECS + 30,
            slots_owned: 0,
            has_worker_binding: true,
        });

        assert!(!evidence.should_remediate());
    }
}
