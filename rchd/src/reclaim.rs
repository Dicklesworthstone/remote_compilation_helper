//! Safe disk-space reclaim actions with active-build protection.
//!
//! This module implements prioritized cleanup/reclaim logic that protects
//! active build artifacts and high-value caches while reclaiming sufficient
//! space. It integrates with the disk pressure monitor and build history
//! to make safe, auditable reclaim decisions.
//!
//! # Safety Guarantees
//!
//! - Reclaim never targets active build workdirs.
//! - Protected cache regions are excluded via denylist.
//! - Candidates are ranked by safety/value with deterministic ordering.
//! - Bounded action budgets prevent over-deletion.
//! - Dry-run mode provides preview without side effects.

#![allow(dead_code)] // Initial integration; consumers land in follow-on beads.

use crate::disk_pressure::{PressureAssessment, PressureState};
use crate::history::{ActiveBuildState, BuildHistory};
use crate::workers::{WorkerPool, WorkerState};
use rch_common::{SshClient, SshOptions, WorkerId, WorkerStatus};
use serde::Serialize;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

// =========================================================================
// Configuration
// =========================================================================

/// Reclaim feature mode (from ADR-006).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReclaimMode {
    /// Helper not invoked; reclaim actions skipped.
    Disabled,
    /// Collect diagnostics and dry-run only; no destructive actions.
    #[default]
    Observe,
    /// Apply reclaim under safety policy.
    Enforce,
}

/// Configuration for safe reclaim operations.
#[derive(Debug, Clone)]
pub struct ReclaimConfig {
    /// Feature mode.
    pub mode: ReclaimMode,
    /// Maximum bytes to reclaim per operation.
    pub max_reclaim_bytes: u64,
    /// Maximum directories to remove per operation.
    pub max_reclaim_dirs: u32,
    /// Time budget for a single reclaim operation.
    pub timeout: Duration,
    /// Minimum time a directory must be idle before reclaim (minutes).
    pub min_idle_minutes: u64,
    /// Protected path prefixes (relative to remote_base) that must never be reclaimed.
    pub protected_prefixes: Vec<String>,
    /// Remote base directory for RCH caches.
    pub remote_base: String,
}

impl Default for ReclaimConfig {
    fn default() -> Self {
        Self {
            mode: ReclaimMode::Observe,
            max_reclaim_bytes: 50 * 1024 * 1024 * 1024, // 50 GB
            max_reclaim_dirs: 100,
            timeout: Duration::from_secs(120),
            min_idle_minutes: 10,
            protected_prefixes: vec![],
            remote_base: "/tmp/rch".to_string(),
        }
    }
}

// =========================================================================
// Safety Gate
// =========================================================================

/// Outcome of a safety gate check.
#[derive(Debug, Clone, Serialize)]
pub struct SafetyGateResult {
    /// Whether reclaim is permitted.
    pub permitted: bool,
    /// Reason code for diagnostics.
    pub reason_code: String,
    /// Active build IDs on this worker (empty if none).
    pub active_build_ids: Vec<u64>,
    /// Active build project IDs on this worker.
    pub active_project_ids: Vec<String>,
    /// Total slots in use by active builds.
    pub slots_in_use: u32,
}

/// Check whether a reclaim operation is safe for the given worker.
///
/// Returns a gate result indicating whether reclaim may proceed and why.
pub fn check_safety_gate(
    worker_id: &WorkerId,
    history: &BuildHistory,
    _worker_state: &WorkerState,
) -> SafetyGateResult {
    let active_builds = history.active_builds();
    let worker_builds: Vec<&ActiveBuildState> = active_builds
        .iter()
        .filter(|b| b.worker_id == worker_id.as_str())
        .collect();

    if worker_builds.is_empty() {
        return SafetyGateResult {
            permitted: true,
            reason_code: "no_active_builds".to_string(),
            active_build_ids: vec![],
            active_project_ids: vec![],
            slots_in_use: 0,
        };
    }

    let active_build_ids: Vec<u64> = worker_builds.iter().map(|b| b.id).collect();
    let active_project_ids: Vec<String> =
        worker_builds.iter().map(|b| b.project_id.clone()).collect();
    let slots_in_use: u32 = worker_builds.iter().map(|b| b.slots).sum();

    SafetyGateResult {
        permitted: false,
        reason_code: "active_builds_present".to_string(),
        active_build_ids,
        active_project_ids,
        slots_in_use,
    }
}

// =========================================================================
// Reclaim Candidate Ranking
// =========================================================================

/// A candidate directory for reclaim, ranked by safety/value.
#[derive(Debug, Clone, Serialize)]
pub struct ReclaimCandidate {
    /// Absolute path on the worker.
    pub path: String,
    /// Estimated size in bytes.
    pub size_bytes: u64,
    /// Age of most recent file modification in minutes.
    pub idle_minutes: u64,
    /// Deterministic sort key (higher = more reclaimable).
    pub reclaim_priority: u64,
    /// Whether this candidate is protected by policy.
    pub is_protected: bool,
}

/// Outcome of a reclaim operation.
#[derive(Debug, Clone, Serialize)]
pub struct ReclaimResult {
    /// Worker that was targeted.
    pub worker_id: WorkerId,
    /// Whether reclaim was executed (false for dry-run or blocked).
    pub executed: bool,
    /// Whether the operation was a dry-run.
    pub dry_run: bool,
    /// Safety gate outcome.
    pub safety_gate: SafetyGateResult,
    /// Pressure state that triggered reclaim.
    pub trigger_pressure: PressureState,
    /// Number of directories removed (or would-be-removed in dry-run).
    pub dirs_removed: u32,
    /// Bytes freed (or estimated in dry-run).
    pub bytes_freed: u64,
    /// Disk free GB before reclaim.
    pub disk_free_before_gb: Option<f64>,
    /// Disk free GB after reclaim.
    pub disk_free_after_gb: Option<f64>,
    /// Duration of the reclaim operation.
    pub duration: Duration,
    /// Error message if reclaim failed.
    pub error: Option<String>,
    /// Reason reclaim was blocked (if not executed).
    pub blocked_reason: Option<String>,
}

/// Aggregate stats for a reclaim cycle across workers.
#[derive(Debug, Default, Clone, Serialize)]
pub struct ReclaimCycleStats {
    /// Workers evaluated for reclaim.
    pub workers_evaluated: u32,
    /// Workers where reclaim was executed.
    pub workers_reclaimed: u32,
    /// Workers skipped (safety gate blocked).
    pub workers_blocked: u32,
    /// Workers skipped (pressure healthy).
    pub workers_healthy: u32,
    /// Errors during reclaim.
    pub errors: u32,
    /// Total bytes freed.
    pub total_bytes_freed: u64,
    /// Total directories removed.
    pub total_dirs_removed: u32,
}

// =========================================================================
// Reclaim Command Builder
// =========================================================================

/// Build the shell command for safe reclaim on a worker.
///
/// The generated script:
/// 1. Enumerates candidate directories under `remote_base`
/// 2. Skips protected paths and recently-active directories
/// 3. Sorts by modification time (oldest first) for deterministic ordering
/// 4. Removes up to `max_dirs` directories, tracking freed space
/// 5. Stops when `max_freed_kb` budget is exhausted or disk is healthy
/// 6. Emits a structured metrics line for parsing
fn build_reclaim_command(
    escaped_base: &str,
    min_idle_minutes: u64,
    max_dirs: u32,
    max_freed_kb: u64,
    threshold_kb: u64,
    dry_run: bool,
    protected_patterns: &[String],
) -> String {
    let protected_checks = if protected_patterns.is_empty() {
        String::new()
    } else {
        let cases: Vec<String> = protected_patterns
            .iter()
            .map(|p| format!("\"$base\"/{}*) continue ;;", p))
            .collect();
        format!("case \"$dir\" in {cases} esac; ", cases = cases.join(" "))
    };

    let remove_action = if dry_run {
        "dry_removed=$((dry_removed + 1))"
    } else {
        "rm -rf \"$dir\" 2>/dev/null || true; removed=$((removed + 1))"
    };

    format!(
        "set -u; \
         base={base}; \
         min_idle_minutes={min_idle_minutes}; \
         max_dirs={max_dirs}; \
         max_freed_kb={max_freed_kb}; \
         threshold_kb={threshold_kb}; \
         if [ ! -d \"$base\" ]; then echo 'RCH_RECLAIM_METRICS removed=0 dry_removed=0 freed_kb=0 before_kb=0 after_kb=0 candidates=0 protected=0'; exit 0; fi; \
         before_kb=$(df -Pk \"$base\" 2>/dev/null | awk 'NR==2 {{print $4}}'); \
         if [ -z \"$before_kb\" ]; then before_kb=0; fi; \
         removed=0; dry_removed=0; freed_kb=0; candidates=0; protected=0; \
         tmpfile=$(mktemp /tmp/rch-reclaim.XXXXXX); \
         find \"$base\" -mindepth 2 -maxdepth 2 -type d -printf '%T@ %p\\n' 2>/dev/null \
           | sort -n | sed 's/^[^ ]* //' > \"$tmpfile\"; \
         while IFS= read -r dir; do \
           [ -z \"$dir\" ] && continue; \
           [ ! -d \"$dir\" ] && continue; \
           case \"$dir\" in \"$base\"/*) ;; *) continue ;; esac; \
           {protected_checks}\
           candidates=$((candidates + 1)); \
           recent_active=$(find \"$dir\" -type f -mmin -\"$min_idle_minutes\" -print -quit 2>/dev/null || true); \
           if [ -n \"$recent_active\" ]; then protected=$((protected + 1)); continue; fi; \
           size_kb=$(du -sk \"$dir\" 2>/dev/null | awk '{{print $1}}'); \
           if [ -z \"$size_kb\" ]; then size_kb=0; fi; \
           {remove_action}; \
           freed_kb=$((freed_kb + size_kb)); \
           if [ $((removed + dry_removed)) -ge \"$max_dirs\" ]; then break; fi; \
           if [ \"$freed_kb\" -ge \"$max_freed_kb\" ]; then break; fi; \
           current_kb=$(df -Pk \"$base\" 2>/dev/null | awk 'NR==2 {{print $4}}'); \
           if [ -n \"$current_kb\" ] && [ \"$current_kb\" -ge \"$threshold_kb\" ]; then break; fi; \
         done < \"$tmpfile\"; \
         rm -f \"$tmpfile\"; \
         after_kb=$(df -Pk \"$base\" 2>/dev/null | awk 'NR==2 {{print $4}}'); \
         if [ -z \"$after_kb\" ]; then after_kb=0; fi; \
         printf 'RCH_RECLAIM_METRICS removed=%s dry_removed=%s freed_kb=%s before_kb=%s after_kb=%s candidates=%s protected=%s\\n' \
           \"$removed\" \"$dry_removed\" \"$freed_kb\" \"$before_kb\" \"$after_kb\" \"$candidates\" \"$protected\"",
        base = escaped_base,
        min_idle_minutes = min_idle_minutes,
        max_dirs = max_dirs,
        max_freed_kb = max_freed_kb,
        threshold_kb = threshold_kb,
        protected_checks = protected_checks,
        remove_action = remove_action,
    )
}

/// Parsed metrics from a reclaim command.
#[derive(Debug, Clone)]
struct ReclaimMetrics {
    removed: u32,
    dry_removed: u32,
    freed_bytes: u64,
    free_before_gb: f64,
    free_after_gb: f64,
    candidates: u32,
    protected: u32,
}

fn parse_reclaim_metrics(stdout: &str) -> Option<ReclaimMetrics> {
    let line = stdout.lines().find(|l| l.contains("RCH_RECLAIM_METRICS"))?;

    let mut removed = None;
    let mut dry_removed = None;
    let mut freed_kb = None;
    let mut before_kb = None;
    let mut after_kb = None;
    let mut candidates = None;
    let mut protected = None;

    for token in line.split_whitespace().skip(1) {
        let (key, value) = token.split_once('=')?;
        match key {
            "removed" => removed = value.parse::<u32>().ok(),
            "dry_removed" => dry_removed = value.parse::<u32>().ok(),
            "freed_kb" => freed_kb = value.parse::<u64>().ok(),
            "before_kb" => before_kb = value.parse::<u64>().ok(),
            "after_kb" => after_kb = value.parse::<u64>().ok(),
            "candidates" => candidates = value.parse::<u32>().ok(),
            "protected" => protected = value.parse::<u32>().ok(),
            _ => {}
        }
    }

    Some(ReclaimMetrics {
        removed: removed.unwrap_or(0),
        dry_removed: dry_removed.unwrap_or(0),
        freed_bytes: freed_kb.unwrap_or(0).saturating_mul(1024),
        free_before_gb: before_kb.unwrap_or(0) as f64 / (1024.0 * 1024.0),
        free_after_gb: after_kb.unwrap_or(0) as f64 / (1024.0 * 1024.0),
        candidates: candidates.unwrap_or(0),
        protected: protected.unwrap_or(0),
    })
}

// =========================================================================
// Reclaim Executor
// =========================================================================

/// Executes safe reclaim operations on workers under disk pressure.
pub struct ReclaimExecutor {
    pool: WorkerPool,
    history: Arc<BuildHistory>,
    config: ReclaimConfig,
    ssh_options: SshOptions,
}

impl ReclaimExecutor {
    /// Create a new reclaim executor.
    pub fn new(pool: WorkerPool, history: Arc<BuildHistory>, config: ReclaimConfig) -> Self {
        Self {
            pool,
            history,
            config,
            ssh_options: SshOptions::default(),
        }
    }

    /// Evaluate and optionally execute reclaim on a single worker.
    ///
    /// The decision flow:
    /// 1. Check pressure state — skip if healthy
    /// 2. Run safety gate — block if active builds present
    /// 3. In observe mode, execute dry-run; in enforce mode, execute real reclaim
    /// 4. Return auditable result with before/after evidence
    pub async fn evaluate_worker(
        &self,
        worker_state: &WorkerState,
    ) -> anyhow::Result<ReclaimResult> {
        let start = Instant::now();
        let config = worker_state.config.read().await.clone();
        let worker_id = config.id.clone();
        let assessment = worker_state.pressure_assessment().await;

        // Step 1: Check if pressure warrants reclaim
        if assessment.state == PressureState::Healthy {
            return Ok(ReclaimResult {
                worker_id,
                executed: false,
                dry_run: false,
                safety_gate: SafetyGateResult {
                    permitted: true,
                    reason_code: "pressure_healthy".to_string(),
                    active_build_ids: vec![],
                    active_project_ids: vec![],
                    slots_in_use: 0,
                },
                trigger_pressure: assessment.state,
                dirs_removed: 0,
                bytes_freed: 0,
                disk_free_before_gb: assessment.disk_free_gb,
                disk_free_after_gb: assessment.disk_free_gb,
                duration: start.elapsed(),
                error: None,
                blocked_reason: Some("pressure_healthy".to_string()),
            });
        }

        // Step 2: Check safety gate
        let gate = check_safety_gate(&worker_id, &self.history, worker_state);

        if !gate.permitted {
            warn!(
                worker = %worker_id,
                reason = %gate.reason_code,
                active_builds = ?gate.active_build_ids,
                slots_in_use = gate.slots_in_use,
                pressure = %assessment.state,
                "Reclaim blocked by safety gate (E217)"
            );
            return Ok(ReclaimResult {
                worker_id,
                executed: false,
                dry_run: false,
                safety_gate: gate,
                trigger_pressure: assessment.state,
                dirs_removed: 0,
                bytes_freed: 0,
                disk_free_before_gb: assessment.disk_free_gb,
                disk_free_after_gb: assessment.disk_free_gb,
                duration: start.elapsed(),
                error: None,
                blocked_reason: Some("active_builds_present".to_string()),
            });
        }

        // Step 3: Check feature mode
        if self.config.mode == ReclaimMode::Disabled {
            debug!(worker = %worker_id, "Reclaim disabled by feature flag");
            return Ok(ReclaimResult {
                worker_id,
                executed: false,
                dry_run: false,
                safety_gate: gate,
                trigger_pressure: assessment.state,
                dirs_removed: 0,
                bytes_freed: 0,
                disk_free_before_gb: assessment.disk_free_gb,
                disk_free_after_gb: assessment.disk_free_gb,
                duration: start.elapsed(),
                error: None,
                blocked_reason: Some("reclaim_disabled".to_string()),
            });
        }

        let dry_run = self.config.mode == ReclaimMode::Observe;

        // Step 4: Execute reclaim
        self.execute_reclaim(worker_state, &assessment, &gate, dry_run, start)
            .await
    }

    async fn execute_reclaim(
        &self,
        worker_state: &WorkerState,
        assessment: &PressureAssessment,
        gate: &SafetyGateResult,
        dry_run: bool,
        start: Instant,
    ) -> anyhow::Result<ReclaimResult> {
        let config = worker_state.config.read().await.clone();
        let worker_id = config.id.clone();

        let escaped_base =
            rch_common::ssh_utils::shell_escape_path_with_home(&self.config.remote_base)
                .ok_or_else(|| {
                    anyhow::anyhow!("Invalid remote_base: contains control characters")
                })?;

        let threshold_kb = (self.config.max_reclaim_bytes / 1024).max(1);
        let max_freed_kb = self.config.max_reclaim_bytes / 1024;

        let cmd = build_reclaim_command(
            escaped_base.as_ref(),
            self.config.min_idle_minutes,
            self.config.max_reclaim_dirs,
            max_freed_kb,
            threshold_kb,
            dry_run,
            &self.config.protected_prefixes,
        );

        info!(
            worker = %worker_id,
            dry_run,
            pressure = %assessment.state,
            mode = ?self.config.mode,
            max_dirs = self.config.max_reclaim_dirs,
            min_idle_minutes = self.config.min_idle_minutes,
            "Starting reclaim operation"
        );

        let mut ssh_client = SshClient::new(config.clone(), self.ssh_options.clone());
        ssh_client.connect().await?;

        let result = ssh_client.execute(&cmd).await?;
        let duration = start.elapsed();

        let metrics = parse_reclaim_metrics(&result.stdout);

        if result.exit_code != 0 {
            let error_msg = format!(
                "Reclaim command failed: exit={} stderr={}",
                result.exit_code,
                result.stderr.trim()
            );
            warn!(
                worker = %worker_id,
                exit_code = result.exit_code,
                "Reclaim command failed (E215)"
            );
            return Ok(ReclaimResult {
                worker_id,
                executed: !dry_run,
                dry_run,
                safety_gate: gate.clone(),
                trigger_pressure: assessment.state,
                dirs_removed: 0,
                bytes_freed: 0,
                disk_free_before_gb: metrics.as_ref().map(|m| m.free_before_gb),
                disk_free_after_gb: metrics.as_ref().map(|m| m.free_after_gb),
                duration,
                error: Some(error_msg),
                blocked_reason: None,
            });
        }

        let dirs_removed = metrics
            .as_ref()
            .map(|m| if dry_run { m.dry_removed } else { m.removed })
            .unwrap_or(0);
        let bytes_freed = metrics.as_ref().map(|m| m.freed_bytes).unwrap_or(0);

        info!(
            worker = %worker_id,
            dry_run,
            dirs_removed,
            bytes_freed_mb = bytes_freed / (1024 * 1024),
            candidates = metrics.as_ref().map(|m| m.candidates).unwrap_or(0),
            protected_skipped = metrics.as_ref().map(|m| m.protected).unwrap_or(0),
            free_before_gb = metrics.as_ref().map(|m| m.free_before_gb).unwrap_or(-1.0),
            free_after_gb = metrics.as_ref().map(|m| m.free_after_gb).unwrap_or(-1.0),
            duration_ms = duration.as_millis() as u64,
            "Reclaim operation completed"
        );

        Ok(ReclaimResult {
            worker_id,
            executed: !dry_run,
            dry_run,
            safety_gate: gate.clone(),
            trigger_pressure: assessment.state,
            dirs_removed,
            bytes_freed,
            disk_free_before_gb: metrics.as_ref().map(|m| m.free_before_gb),
            disk_free_after_gb: metrics.as_ref().map(|m| m.free_after_gb),
            duration,
            error: None,
            blocked_reason: None,
        })
    }

    /// Run a reclaim evaluation cycle across all workers.
    pub async fn run_cycle(&self) -> ReclaimCycleStats {
        let mut stats = ReclaimCycleStats::default();
        let workers = self.pool.all_workers().await;

        for worker_state in workers {
            stats.workers_evaluated += 1;
            let worker_id = worker_state.config.read().await.id.clone();

            // Skip unhealthy workers (can't SSH to reclaim)
            let status = worker_state.status().await;
            if status != WorkerStatus::Healthy {
                debug!(worker = %worker_id, status = ?status, "Skipping non-healthy worker for reclaim");
                continue;
            }

            match self.evaluate_worker(&worker_state).await {
                Ok(result) => {
                    if result.blocked_reason.as_deref() == Some("pressure_healthy") {
                        stats.workers_healthy += 1;
                    } else if result.blocked_reason.is_some() {
                        stats.workers_blocked += 1;
                    } else if result.error.is_some() {
                        stats.errors += 1;
                    } else {
                        stats.workers_reclaimed += 1;
                        stats.total_bytes_freed += result.bytes_freed;
                        stats.total_dirs_removed += result.dirs_removed;
                    }
                }
                Err(e) => {
                    warn!(worker = %worker_id, error = %e, "Reclaim evaluation failed");
                    stats.errors += 1;
                }
            }
        }

        if stats.workers_reclaimed > 0 || stats.errors > 0 || stats.workers_blocked > 0 {
            info!(
                evaluated = stats.workers_evaluated,
                reclaimed = stats.workers_reclaimed,
                blocked = stats.workers_blocked,
                healthy = stats.workers_healthy,
                errors = stats.errors,
                freed_mb = stats.total_bytes_freed / (1024 * 1024),
                dirs_removed = stats.total_dirs_removed,
                "Reclaim cycle completed"
            );
        }

        stats
    }
}

// =========================================================================
// Tests
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::disk_pressure::PressureConfidence;
    use crate::workers::WorkerPool;
    use rch_common::{BuildLocation, WorkerConfig, test_guard};

    fn create_test_worker_config(id: &str) -> WorkerConfig {
        WorkerConfig {
            id: WorkerId::new(id),
            host: "test.example.com".to_string(),
            user: "testuser".to_string(),
            identity_file: "/home/test/.ssh/id_rsa".to_string(),
            total_slots: 8,
            priority: 50,
            tags: vec![],
        }
    }

    fn make_critical_assessment() -> PressureAssessment {
        PressureAssessment {
            state: PressureState::Critical,
            confidence: PressureConfidence::High,
            reason_code: "disk_free_below_critical_gb".to_string(),
            policy_rule: "test".to_string(),
            disk_free_gb: Some(5.0),
            disk_total_gb: Some(200.0),
            ..PressureAssessment::default()
        }
    }

    fn make_healthy_assessment() -> PressureAssessment {
        PressureAssessment {
            state: PressureState::Healthy,
            confidence: PressureConfidence::High,
            reason_code: "pressure_healthy".to_string(),
            policy_rule: "test".to_string(),
            disk_free_gb: Some(80.0),
            disk_total_gb: Some(200.0),
            ..PressureAssessment::default()
        }
    }

    // =====================================================================
    // Safety Gate Tests
    // =====================================================================

    #[test]
    fn safety_gate_permits_when_no_active_builds() {
        let _guard = test_guard!();
        let history = BuildHistory::new(10);
        let config = create_test_worker_config("worker-1");
        let worker_state = WorkerState::new(config);
        let worker_id = WorkerId::new("worker-1");

        let result = check_safety_gate(&worker_id, &history, &worker_state);

        assert!(result.permitted);
        assert_eq!(result.reason_code, "no_active_builds");
        assert!(result.active_build_ids.is_empty());
        assert_eq!(result.slots_in_use, 0);
    }

    #[test]
    fn safety_gate_blocks_when_active_build_on_worker() {
        let _guard = test_guard!();
        let history = BuildHistory::new(10);

        // Start an active build on worker-1
        history.start_active_build(
            "project-a".to_string(),
            "worker-1".to_string(),
            "cargo build".to_string(),
            1001,
            4,
            BuildLocation::Remote,
        );

        let config = create_test_worker_config("worker-1");
        let worker_state = WorkerState::new(config);
        let worker_id = WorkerId::new("worker-1");

        let result = check_safety_gate(&worker_id, &history, &worker_state);

        assert!(!result.permitted);
        assert_eq!(result.reason_code, "active_builds_present");
        assert_eq!(result.active_build_ids.len(), 1);
        assert_eq!(result.active_project_ids, vec!["project-a"]);
        assert_eq!(result.slots_in_use, 4);
    }

    #[test]
    fn safety_gate_permits_when_active_build_on_different_worker() {
        let _guard = test_guard!();
        let history = BuildHistory::new(10);

        // Active build on worker-2, not worker-1
        history.start_active_build(
            "project-b".to_string(),
            "worker-2".to_string(),
            "cargo test".to_string(),
            1002,
            8,
            BuildLocation::Remote,
        );

        let config = create_test_worker_config("worker-1");
        let worker_state = WorkerState::new(config);
        let worker_id = WorkerId::new("worker-1");

        let result = check_safety_gate(&worker_id, &history, &worker_state);

        assert!(result.permitted);
        assert_eq!(result.reason_code, "no_active_builds");
    }

    #[test]
    fn safety_gate_blocks_with_multiple_active_builds() {
        let _guard = test_guard!();
        let history = BuildHistory::new(10);

        // Two active builds on same worker
        history.start_active_build(
            "proj-a".to_string(),
            "worker-1".to_string(),
            "cargo build".to_string(),
            1001,
            2,
            BuildLocation::Remote,
        );
        history.start_active_build(
            "proj-b".to_string(),
            "worker-1".to_string(),
            "cargo test".to_string(),
            1002,
            4,
            BuildLocation::Remote,
        );

        let config = create_test_worker_config("worker-1");
        let worker_state = WorkerState::new(config);
        let worker_id = WorkerId::new("worker-1");

        let result = check_safety_gate(&worker_id, &history, &worker_state);

        assert!(!result.permitted);
        assert_eq!(result.active_build_ids.len(), 2);
        assert_eq!(result.slots_in_use, 6);
    }

    #[test]
    fn safety_gate_permits_after_build_completes() {
        let _guard = test_guard!();
        let history = BuildHistory::new(10);

        // Start and finish a build
        let build = history.start_active_build(
            "proj-a".to_string(),
            "worker-1".to_string(),
            "cargo build".to_string(),
            1001,
            4,
            BuildLocation::Remote,
        );
        history.finish_active_build(build.id, 0, Some(1000), None, None);

        let config = create_test_worker_config("worker-1");
        let worker_state = WorkerState::new(config);
        let worker_id = WorkerId::new("worker-1");

        let result = check_safety_gate(&worker_id, &history, &worker_state);

        assert!(result.permitted);
        assert_eq!(result.reason_code, "no_active_builds");
    }

    // =====================================================================
    // Reclaim Command Tests
    // =====================================================================

    #[test]
    fn reclaim_command_contains_safety_checks() {
        let _guard = test_guard!();
        let cmd = build_reclaim_command("'/tmp/rch'", 10, 50, 51200, 10240, false, &[]);

        // Base-path confinement
        assert!(cmd.contains("case \"$dir\" in \"$base\"/*)"));
        // Active file check
        assert!(cmd.contains("-mmin -\"$min_idle_minutes\""));
        // Budget limits
        assert!(cmd.contains("max_dirs=50"));
        assert!(cmd.contains("max_freed_kb=51200"));
        // Metrics marker
        assert!(cmd.contains("RCH_RECLAIM_METRICS"));
    }

    #[test]
    fn reclaim_command_dry_run_does_not_delete() {
        let _guard = test_guard!();
        let cmd = build_reclaim_command("'/tmp/rch'", 10, 50, 51200, 10240, true, &[]);

        // Dry-run increments dry_removed, not rm -rf
        assert!(cmd.contains("dry_removed=$((dry_removed + 1))"));
        // Should NOT contain rm -rf in the loop action
        // The only rm -rf should be in the non-dry-run path (which isn't present)
        // and the tmpfile cleanup
        let lines_with_rmrf: Vec<&str> = cmd
            .split(';')
            .filter(|s| {
                s.contains("rm -rf") && !s.contains("tmpfile") && !s.contains("$candidates")
            })
            .collect();
        assert!(
            lines_with_rmrf.is_empty(),
            "Dry-run should not rm -rf directories"
        );
    }

    #[test]
    fn reclaim_command_includes_protected_patterns() {
        let _guard = test_guard!();
        let protected = vec![".cache/".to_string(), ".toolchains/".to_string()];
        let cmd = build_reclaim_command("'/tmp/rch'", 10, 50, 51200, 10240, false, &protected);

        assert!(cmd.contains(".cache/"));
        assert!(cmd.contains(".toolchains/"));
        assert!(cmd.contains("continue"));
    }

    #[test]
    fn reclaim_command_handles_empty_base() {
        let _guard = test_guard!();
        let cmd = build_reclaim_command("'/tmp/rch'", 10, 50, 51200, 10240, false, &[]);

        // Should exit cleanly if base doesn't exist
        assert!(cmd.contains("if [ ! -d \"$base\" ]"));
        assert!(cmd.contains("exit 0"));
    }

    // =====================================================================
    // Metrics Parsing Tests
    // =====================================================================

    #[test]
    fn parse_reclaim_metrics_success() {
        let _guard = test_guard!();
        let stdout = "noise\nRCH_RECLAIM_METRICS removed=3 dry_removed=0 freed_kb=2048 before_kb=8192 after_kb=10240 candidates=10 protected=2\n";
        let metrics = parse_reclaim_metrics(stdout).expect("should parse");

        assert_eq!(metrics.removed, 3);
        assert_eq!(metrics.dry_removed, 0);
        assert_eq!(metrics.freed_bytes, 2048 * 1024);
        assert!((metrics.free_before_gb - (8192.0 / (1024.0 * 1024.0))).abs() < f64::EPSILON);
        assert!((metrics.free_after_gb - (10240.0 / (1024.0 * 1024.0))).abs() < f64::EPSILON);
        assert_eq!(metrics.candidates, 10);
        assert_eq!(metrics.protected, 2);
    }

    #[test]
    fn parse_reclaim_metrics_dry_run() {
        let _guard = test_guard!();
        let stdout = "RCH_RECLAIM_METRICS removed=0 dry_removed=5 freed_kb=4096 before_kb=8192 after_kb=8192 candidates=8 protected=1\n";
        let metrics = parse_reclaim_metrics(stdout).expect("should parse");

        assert_eq!(metrics.removed, 0);
        assert_eq!(metrics.dry_removed, 5);
        assert_eq!(metrics.freed_bytes, 4096 * 1024);
    }

    #[test]
    fn parse_reclaim_metrics_missing_line() {
        let _guard = test_guard!();
        let stdout = "no metrics here\n";
        assert!(parse_reclaim_metrics(stdout).is_none());
    }

    // =====================================================================
    // Configuration Tests
    // =====================================================================

    #[test]
    fn reclaim_config_defaults() {
        let _guard = test_guard!();
        let config = ReclaimConfig::default();

        assert_eq!(config.mode, ReclaimMode::Observe);
        assert_eq!(config.max_reclaim_bytes, 50 * 1024 * 1024 * 1024);
        assert_eq!(config.max_reclaim_dirs, 100);
        assert_eq!(config.timeout, Duration::from_secs(120));
        assert_eq!(config.min_idle_minutes, 10);
        assert!(config.protected_prefixes.is_empty());
        assert_eq!(config.remote_base, "/tmp/rch");
    }

    #[test]
    fn reclaim_mode_default_is_observe() {
        let _guard = test_guard!();
        assert_eq!(ReclaimMode::default(), ReclaimMode::Observe);
    }

    #[test]
    fn reclaim_mode_serialization() {
        let _guard = test_guard!();
        assert_eq!(
            serde_json::to_string(&ReclaimMode::Disabled).unwrap(),
            "\"disabled\""
        );
        assert_eq!(
            serde_json::to_string(&ReclaimMode::Observe).unwrap(),
            "\"observe\""
        );
        assert_eq!(
            serde_json::to_string(&ReclaimMode::Enforce).unwrap(),
            "\"enforce\""
        );
    }

    // =====================================================================
    // ReclaimResult Tests
    // =====================================================================

    #[test]
    fn reclaim_result_serialization() {
        let _guard = test_guard!();
        let result = ReclaimResult {
            worker_id: WorkerId::new("w1"),
            executed: true,
            dry_run: false,
            safety_gate: SafetyGateResult {
                permitted: true,
                reason_code: "no_active_builds".to_string(),
                active_build_ids: vec![],
                active_project_ids: vec![],
                slots_in_use: 0,
            },
            trigger_pressure: PressureState::Critical,
            dirs_removed: 5,
            bytes_freed: 1024 * 1024 * 100,
            disk_free_before_gb: Some(5.0),
            disk_free_after_gb: Some(15.0),
            duration: Duration::from_secs(3),
            error: None,
            blocked_reason: None,
        };

        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["executed"], true);
        assert_eq!(json["dirs_removed"], 5);
        assert_eq!(json["trigger_pressure"], "critical");
    }

    // =====================================================================
    // Cycle Stats Tests
    // =====================================================================

    #[test]
    fn reclaim_cycle_stats_default() {
        let _guard = test_guard!();
        let stats = ReclaimCycleStats::default();

        assert_eq!(stats.workers_evaluated, 0);
        assert_eq!(stats.workers_reclaimed, 0);
        assert_eq!(stats.workers_blocked, 0);
        assert_eq!(stats.workers_healthy, 0);
        assert_eq!(stats.errors, 0);
        assert_eq!(stats.total_bytes_freed, 0);
        assert_eq!(stats.total_dirs_removed, 0);
    }

    // =====================================================================
    // Executor Integration Tests (no SSH, logic-only)
    // =====================================================================

    #[tokio::test]
    async fn executor_skips_healthy_worker() {
        let pool = WorkerPool::new();
        let config = create_test_worker_config("healthy-worker");
        pool.add_worker(config).await;

        let worker = pool.get(&WorkerId::new("healthy-worker")).await.unwrap();
        worker
            .set_pressure_assessment(make_healthy_assessment())
            .await;

        let history = Arc::new(BuildHistory::new(10));
        let reclaim_config = ReclaimConfig::default();
        let executor = ReclaimExecutor::new(pool, history, reclaim_config);

        let result = executor.evaluate_worker(&worker).await.unwrap();

        assert!(!result.executed);
        assert_eq!(result.blocked_reason.as_deref(), Some("pressure_healthy"));
        assert_eq!(result.dirs_removed, 0);
    }

    #[tokio::test]
    async fn executor_blocks_when_active_builds() {
        let pool = WorkerPool::new();
        let config = create_test_worker_config("busy-worker");
        pool.add_worker(config).await;

        let worker = pool.get(&WorkerId::new("busy-worker")).await.unwrap();
        worker
            .set_pressure_assessment(make_critical_assessment())
            .await;

        let history = Arc::new(BuildHistory::new(10));
        history.start_active_build(
            "proj-x".to_string(),
            "busy-worker".to_string(),
            "cargo build".to_string(),
            2001,
            4,
            BuildLocation::Remote,
        );

        let reclaim_config = ReclaimConfig::default();
        let executor = ReclaimExecutor::new(pool, history, reclaim_config);

        let result = executor.evaluate_worker(&worker).await.unwrap();

        assert!(!result.executed);
        assert!(!result.safety_gate.permitted);
        assert_eq!(
            result.blocked_reason.as_deref(),
            Some("active_builds_present")
        );
    }

    #[tokio::test]
    async fn executor_respects_disabled_mode() {
        let pool = WorkerPool::new();
        let config = create_test_worker_config("disabled-worker");
        pool.add_worker(config).await;

        let worker = pool.get(&WorkerId::new("disabled-worker")).await.unwrap();
        worker
            .set_pressure_assessment(make_critical_assessment())
            .await;

        let history = Arc::new(BuildHistory::new(10));
        let reclaim_config = ReclaimConfig {
            mode: ReclaimMode::Disabled,
            ..Default::default()
        };
        let executor = ReclaimExecutor::new(pool, history, reclaim_config);

        let result = executor.evaluate_worker(&worker).await.unwrap();

        assert!(!result.executed);
        assert_eq!(result.blocked_reason.as_deref(), Some("reclaim_disabled"));
    }

    #[tokio::test]
    async fn cycle_counts_healthy_workers() {
        let pool = WorkerPool::new();
        let c1 = create_test_worker_config("w1");
        let c2 = create_test_worker_config("w2");
        pool.add_worker(c1).await;
        pool.add_worker(c2).await;

        // Both healthy
        for id in ["w1", "w2"] {
            let w = pool.get(&WorkerId::new(id)).await.unwrap();
            w.set_pressure_assessment(make_healthy_assessment()).await;
        }

        let history = Arc::new(BuildHistory::new(10));
        let executor = ReclaimExecutor::new(pool, history, ReclaimConfig::default());

        let stats = executor.run_cycle().await;

        assert_eq!(stats.workers_evaluated, 2);
        assert_eq!(stats.workers_healthy, 2);
        assert_eq!(stats.workers_reclaimed, 0);
        assert_eq!(stats.workers_blocked, 0);
    }

    #[tokio::test]
    async fn cycle_counts_blocked_workers() {
        let pool = WorkerPool::new();
        let c1 = create_test_worker_config("w1");
        pool.add_worker(c1).await;

        let w = pool.get(&WorkerId::new("w1")).await.unwrap();
        w.set_pressure_assessment(make_critical_assessment()).await;

        let history = Arc::new(BuildHistory::new(10));
        history.start_active_build(
            "proj".to_string(),
            "w1".to_string(),
            "cargo build".to_string(),
            3001,
            4,
            BuildLocation::Remote,
        );

        let executor = ReclaimExecutor::new(pool, history, ReclaimConfig::default());
        let stats = executor.run_cycle().await;

        assert_eq!(stats.workers_evaluated, 1);
        assert_eq!(stats.workers_blocked, 1);
        assert_eq!(stats.workers_reclaimed, 0);
    }
}
