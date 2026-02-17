//! Disk-pressure monitoring and ballast policy evaluation.
//!
//! This module computes normalized worker pressure states from daemon-visible
//! evidence and stores per-worker policy decisions for scheduler consumption.

#![allow(dead_code)] // Initial integration surface; additional consumers land in follow-on beads.

use crate::telemetry::TelemetryStore;
use crate::workers::{WorkerPool, WorkerState};
use chrono::Utc;
use rch_common::WorkerCapabilities;
use rch_telemetry::protocol::ReceivedTelemetry;
use serde::Serialize;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::interval;
use tracing::{debug, info, warn};

/// Normalized disk-pressure state used by scheduling and status surfaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PressureState {
    Healthy,
    Warning,
    Critical,
    TelemetryGap,
}

impl std::fmt::Display for PressureState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = match self {
            Self::Healthy => "healthy",
            Self::Warning => "warning",
            Self::Critical => "critical",
            Self::TelemetryGap => "telemetry_gap",
        };
        write!(f, "{value}")
    }
}

/// Confidence score for pressure decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PressureConfidence {
    High,
    Medium,
    Low,
}

impl std::fmt::Display for PressureConfidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = match self {
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
        };
        write!(f, "{value}")
    }
}

/// Policy decision stored on a worker for downstream scheduler consumption.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PressureAssessment {
    /// Normalized pressure state.
    pub state: PressureState,
    /// Confidence of the decision.
    pub confidence: PressureConfidence,
    /// Stable reason code for diagnostics and tests.
    pub reason_code: String,
    /// Name of policy rule that triggered the decision.
    pub policy_rule: String,
    /// Free disk space in GB from worker capabilities.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disk_free_gb: Option<f64>,
    /// Total disk space in GB from worker capabilities.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disk_total_gb: Option<f64>,
    /// Free disk ratio (0.0-1.0) when both free+total are known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disk_free_ratio: Option<f64>,
    /// Disk I/O utilization percentage when telemetry is available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disk_io_util_pct: Option<f64>,
    /// Memory pressure score when telemetry is available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_pressure: Option<f64>,
    /// Age of last telemetry sample in seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub telemetry_age_secs: Option<u64>,
    /// Whether telemetry sample is fresh per policy threshold.
    pub telemetry_fresh: bool,
    /// Epoch milliseconds when this policy decision was evaluated.
    pub evaluated_at_unix_ms: i64,
}

impl Default for PressureAssessment {
    fn default() -> Self {
        Self {
            state: PressureState::TelemetryGap,
            confidence: PressureConfidence::Low,
            reason_code: "pressure_not_evaluated".to_string(),
            policy_rule: "default_uninitialized".to_string(),
            disk_free_gb: None,
            disk_total_gb: None,
            disk_free_ratio: None,
            disk_io_util_pct: None,
            memory_pressure: None,
            telemetry_age_secs: None,
            telemetry_fresh: false,
            evaluated_at_unix_ms: current_unix_ms(),
        }
    }
}

/// Policy thresholds for pressure classification.
#[derive(Debug, Clone)]
pub struct DiskPressurePolicyConfig {
    /// Poll cadence for monitor evaluations.
    pub poll_interval: Duration,
    /// Telemetry older than this is considered stale.
    pub telemetry_stale_after: Duration,
    /// Warning free-disk threshold.
    pub warning_free_gb: f64,
    /// Critical free-disk threshold.
    pub critical_free_gb: f64,
    /// Warning free-ratio threshold.
    pub warning_free_ratio: f64,
    /// Critical free-ratio threshold.
    pub critical_free_ratio: f64,
    /// Warning disk I/O saturation threshold.
    pub warning_disk_io_util_pct: f64,
    /// Critical disk I/O saturation threshold.
    pub critical_disk_io_util_pct: f64,
    /// Warning memory pressure threshold.
    pub warning_memory_pressure: f64,
    /// Critical memory pressure threshold.
    pub critical_memory_pressure: f64,
}

impl Default for DiskPressurePolicyConfig {
    fn default() -> Self {
        Self {
            poll_interval: Duration::from_secs(30),
            telemetry_stale_after: Duration::from_secs(90),
            warning_free_gb: 25.0,
            critical_free_gb: 10.0,
            warning_free_ratio: 0.12,
            critical_free_ratio: 0.05,
            warning_disk_io_util_pct: 85.0,
            critical_disk_io_util_pct: 95.0,
            warning_memory_pressure: 80.0,
            critical_memory_pressure: 92.0,
        }
    }
}

/// Background monitor that computes and stores pressure assessments on workers.
pub struct DiskPressureMonitor {
    pool: WorkerPool,
    telemetry: Arc<TelemetryStore>,
    config: DiskPressurePolicyConfig,
}

impl DiskPressureMonitor {
    /// Create a new monitor.
    pub fn new(
        pool: WorkerPool,
        telemetry: Arc<TelemetryStore>,
        config: DiskPressurePolicyConfig,
    ) -> Self {
        Self {
            pool,
            telemetry,
            config,
        }
    }

    /// Start periodic pressure evaluation.
    pub fn start(self) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut ticker = interval(self.config.poll_interval);
            loop {
                ticker.tick().await;
                if let Err(e) = self.evaluate_once().await {
                    warn!("Disk pressure monitor cycle failed: {e}");
                }
            }
        })
    }

    async fn evaluate_once(&self) -> anyhow::Result<()> {
        let workers = self.pool.all_workers().await;
        for worker in workers {
            self.evaluate_worker(worker).await;
        }
        Ok(())
    }

    async fn evaluate_worker(&self, worker: Arc<WorkerState>) {
        let worker_id = worker.config.read().await.id.to_string();
        let capabilities = worker.capabilities().await;
        let telemetry = self.telemetry.latest(worker_id.as_str());
        let next = evaluate_pressure_policy(&capabilities, telemetry.as_ref(), &self.config);
        let prev = worker.pressure_assessment().await;

        let state_changed = prev.state != next.state;
        let confidence_changed = prev.confidence != next.confidence;
        let reason_changed = prev.reason_code != next.reason_code;

        worker.set_pressure_assessment(next.clone()).await;

        if state_changed
            || confidence_changed
            || reason_changed
            || next.state != PressureState::Healthy
        {
            let disk_free_gb = next.disk_free_gb.unwrap_or(-1.0);
            let disk_total_gb = next.disk_total_gb.unwrap_or(-1.0);
            let disk_free_ratio = next.disk_free_ratio.unwrap_or(-1.0);
            let disk_io_util_pct = next.disk_io_util_pct.unwrap_or(-1.0);
            let memory_pressure = next.memory_pressure.unwrap_or(-1.0);
            let telemetry_age_secs = next.telemetry_age_secs.unwrap_or(u64::MAX);

            match next.state {
                PressureState::Critical => warn!(
                    worker = %worker_id,
                    pressure_state = %next.state,
                    confidence = %next.confidence,
                    reason_code = %next.reason_code,
                    policy_rule = %next.policy_rule,
                    disk_free_gb,
                    disk_total_gb,
                    disk_free_ratio,
                    disk_io_util_pct,
                    memory_pressure,
                    telemetry_age_secs,
                    "Disk pressure policy decision"
                ),
                PressureState::Warning | PressureState::TelemetryGap => info!(
                    worker = %worker_id,
                    pressure_state = %next.state,
                    confidence = %next.confidence,
                    reason_code = %next.reason_code,
                    policy_rule = %next.policy_rule,
                    disk_free_gb,
                    disk_total_gb,
                    disk_free_ratio,
                    disk_io_util_pct,
                    memory_pressure,
                    telemetry_age_secs,
                    "Disk pressure policy decision"
                ),
                PressureState::Healthy => debug!(
                    worker = %worker_id,
                    pressure_state = %next.state,
                    confidence = %next.confidence,
                    reason_code = %next.reason_code,
                    policy_rule = %next.policy_rule,
                    disk_free_gb,
                    disk_total_gb,
                    disk_free_ratio,
                    disk_io_util_pct,
                    memory_pressure,
                    telemetry_age_secs,
                    "Disk pressure policy decision"
                ),
            }
        }
    }
}

/// Evaluate pressure policy from capabilities + latest telemetry.
pub fn evaluate_pressure_policy(
    capabilities: &WorkerCapabilities,
    latest: Option<&ReceivedTelemetry>,
    config: &DiskPressurePolicyConfig,
) -> PressureAssessment {
    let disk_free_gb = capabilities.disk_free_gb;
    let disk_total_gb = capabilities.disk_total_gb;
    let disk_free_ratio = match (disk_free_gb, disk_total_gb) {
        (Some(free), Some(total)) if total > 0.0 => Some((free / total).clamp(0.0, 1.0)),
        _ => None,
    };

    let now = Utc::now();
    let telemetry_age_secs = latest.map(|entry| {
        let age = now.signed_duration_since(entry.received_at).num_seconds();
        if age <= 0 { 0 } else { age as u64 }
    });
    let telemetry_fresh = telemetry_age_secs
        .map(|age| age <= config.telemetry_stale_after.as_secs())
        .unwrap_or(false);

    let memory_pressure = latest.map(|entry| entry.telemetry.memory.pressure_score);
    let disk_io_util_pct = latest.and_then(|entry| {
        entry
            .telemetry
            .disk
            .as_ref()
            .map(|disk| disk.max_io_utilization_pct)
    });

    let (state, confidence, reason_code, policy_rule) =
        if disk_free_gb.is_none() || disk_total_gb.is_none() {
            (
                PressureState::TelemetryGap,
                PressureConfidence::Low,
                "disk_metrics_unavailable".to_string(),
                "fail_open_missing_disk_metrics".to_string(),
            )
        } else if telemetry_fresh {
            classify_with_fresh_telemetry(
                disk_free_gb.unwrap_or_default(),
                disk_free_ratio.unwrap_or_default(),
                disk_io_util_pct,
                memory_pressure,
                config,
            )
        } else {
            classify_without_fresh_telemetry(
                disk_free_gb.unwrap_or_default(),
                disk_free_ratio.unwrap_or_default(),
                config,
            )
        };

    PressureAssessment {
        state,
        confidence,
        reason_code,
        policy_rule,
        disk_free_gb,
        disk_total_gb,
        disk_free_ratio,
        disk_io_util_pct,
        memory_pressure,
        telemetry_age_secs,
        telemetry_fresh,
        evaluated_at_unix_ms: current_unix_ms(),
    }
}

fn classify_with_fresh_telemetry(
    disk_free_gb: f64,
    disk_free_ratio: f64,
    disk_io_util_pct: Option<f64>,
    memory_pressure: Option<f64>,
    config: &DiskPressurePolicyConfig,
) -> (PressureState, PressureConfidence, String, String) {
    if disk_free_gb <= config.critical_free_gb {
        return (
            PressureState::Critical,
            PressureConfidence::High,
            "disk_free_below_critical_gb".to_string(),
            "disk_free_gb<=critical_free_gb".to_string(),
        );
    }
    if disk_free_ratio <= config.critical_free_ratio {
        return (
            PressureState::Critical,
            PressureConfidence::High,
            "disk_ratio_below_critical".to_string(),
            "disk_free_ratio<=critical_free_ratio".to_string(),
        );
    }
    if disk_io_util_pct
        .map(|util| {
            util >= config.critical_disk_io_util_pct && disk_free_gb <= config.warning_free_gb
        })
        .unwrap_or(false)
    {
        return (
            PressureState::Critical,
            PressureConfidence::High,
            "disk_io_saturated_with_low_headroom".to_string(),
            "disk_io>=critical && disk_free_gb<=warning_free_gb".to_string(),
        );
    }

    if disk_free_gb <= config.warning_free_gb {
        return (
            PressureState::Warning,
            PressureConfidence::High,
            "disk_free_below_warning_gb".to_string(),
            "disk_free_gb<=warning_free_gb".to_string(),
        );
    }
    if disk_free_ratio <= config.warning_free_ratio {
        return (
            PressureState::Warning,
            PressureConfidence::High,
            "disk_ratio_below_warning".to_string(),
            "disk_free_ratio<=warning_free_ratio".to_string(),
        );
    }
    if disk_io_util_pct
        .map(|util| util >= config.warning_disk_io_util_pct)
        .unwrap_or(false)
    {
        return (
            PressureState::Warning,
            PressureConfidence::High,
            "disk_io_high".to_string(),
            "disk_io>=warning_disk_io_util_pct".to_string(),
        );
    }
    if memory_pressure
        .map(|pressure| pressure >= config.critical_memory_pressure)
        .unwrap_or(false)
    {
        return (
            PressureState::Warning,
            PressureConfidence::High,
            "memory_pressure_critical".to_string(),
            "memory_pressure>=critical_memory_pressure".to_string(),
        );
    }
    if memory_pressure
        .map(|pressure| pressure >= config.warning_memory_pressure)
        .unwrap_or(false)
    {
        return (
            PressureState::Warning,
            PressureConfidence::High,
            "memory_pressure_warning".to_string(),
            "memory_pressure>=warning_memory_pressure".to_string(),
        );
    }

    (
        PressureState::Healthy,
        PressureConfidence::High,
        "pressure_healthy".to_string(),
        "all_pressure_rules_within_threshold".to_string(),
    )
}

fn classify_without_fresh_telemetry(
    disk_free_gb: f64,
    disk_free_ratio: f64,
    config: &DiskPressurePolicyConfig,
) -> (PressureState, PressureConfidence, String, String) {
    if disk_free_gb <= config.critical_free_gb || disk_free_ratio <= config.critical_free_ratio {
        return (
            PressureState::Critical,
            PressureConfidence::Medium,
            "disk_critical_without_fresh_telemetry".to_string(),
            "disk_threshold_breach_without_telemetry".to_string(),
        );
    }
    if disk_free_gb <= config.warning_free_gb || disk_free_ratio <= config.warning_free_ratio {
        return (
            PressureState::Warning,
            PressureConfidence::Medium,
            "disk_warning_without_fresh_telemetry".to_string(),
            "disk_warning_threshold_without_telemetry".to_string(),
        );
    }

    (
        PressureState::TelemetryGap,
        PressureConfidence::Low,
        "telemetry_unavailable".to_string(),
        "fail_open_telemetry_gap".to_string(),
    )
}

fn current_unix_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as i64)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration as ChronoDuration;
    use rch_telemetry::collect::cpu::{CpuTelemetry, LoadAverage};
    use rch_telemetry::collect::disk::{DiskMetrics, DiskTelemetry};
    use rch_telemetry::collect::memory::MemoryTelemetry;
    use rch_telemetry::protocol::{TelemetrySource, WorkerTelemetry};

    fn test_capabilities(free_gb: f64, total_gb: f64) -> WorkerCapabilities {
        let mut caps = WorkerCapabilities::new();
        caps.disk_free_gb = Some(free_gb);
        caps.disk_total_gb = Some(total_gb);
        caps
    }

    fn test_received_telemetry(
        disk_io_util_pct: f64,
        memory_pressure: f64,
        age_secs: i64,
    ) -> ReceivedTelemetry {
        let cpu = CpuTelemetry {
            timestamp: Utc::now(),
            overall_percent: 12.0,
            per_core_percent: vec![12.0],
            num_cores: 8,
            load_average: LoadAverage {
                one_min: 0.6,
                five_min: 0.5,
                fifteen_min: 0.4,
                running_processes: 1,
                total_processes: 100,
            },
            psi: None,
        };

        let memory = MemoryTelemetry {
            timestamp: Utc::now(),
            total_gb: 64.0,
            available_gb: 32.0,
            used_percent: 50.0,
            pressure_score: memory_pressure,
            swap_used_gb: 0.0,
            dirty_mb: 0.0,
            psi: None,
        };

        let disk = DiskTelemetry::from_metrics(
            vec![DiskMetrics {
                device: "nvme0n1".to_string(),
                io_utilization_pct: disk_io_util_pct,
                ..DiskMetrics::default()
            }],
            None,
        );

        let telemetry =
            WorkerTelemetry::new("worker-1".to_string(), cpu, memory, Some(disk), None, 25);
        let mut received = ReceivedTelemetry::new(telemetry, TelemetrySource::SshPoll);
        received.received_at = Utc::now() - ChronoDuration::seconds(age_secs);
        received
    }

    #[test]
    fn pressure_policy_marks_healthy_with_fresh_safe_metrics() {
        let caps = test_capabilities(60.0, 200.0);
        let telemetry = test_received_telemetry(30.0, 40.0, 5);
        let cfg = DiskPressurePolicyConfig::default();

        let result = evaluate_pressure_policy(&caps, Some(&telemetry), &cfg);
        assert_eq!(result.state, PressureState::Healthy);
        assert_eq!(result.confidence, PressureConfidence::High);
        assert_eq!(result.reason_code, "pressure_healthy");
    }

    #[test]
    fn pressure_policy_marks_warning_with_fresh_warning_headroom() {
        let caps = test_capabilities(18.0, 200.0);
        let telemetry = test_received_telemetry(50.0, 40.0, 5);
        let cfg = DiskPressurePolicyConfig::default();

        let result = evaluate_pressure_policy(&caps, Some(&telemetry), &cfg);
        assert_eq!(result.state, PressureState::Warning);
        assert_eq!(result.confidence, PressureConfidence::High);
        assert_eq!(result.reason_code, "disk_free_below_warning_gb");
    }

    #[test]
    fn pressure_policy_marks_critical_with_fresh_critical_headroom() {
        let caps = test_capabilities(8.0, 200.0);
        let telemetry = test_received_telemetry(40.0, 30.0, 5);
        let cfg = DiskPressurePolicyConfig::default();

        let result = evaluate_pressure_policy(&caps, Some(&telemetry), &cfg);
        assert_eq!(result.state, PressureState::Critical);
        assert_eq!(result.confidence, PressureConfidence::High);
        assert_eq!(result.reason_code, "disk_free_below_critical_gb");
    }

    #[test]
    fn pressure_policy_marks_telemetry_gap_when_telemetry_is_stale() {
        let caps = test_capabilities(80.0, 200.0);
        let telemetry = test_received_telemetry(25.0, 35.0, 600);
        let cfg = DiskPressurePolicyConfig::default();

        let result = evaluate_pressure_policy(&caps, Some(&telemetry), &cfg);
        assert_eq!(result.state, PressureState::TelemetryGap);
        assert_eq!(result.confidence, PressureConfidence::Low);
        assert_eq!(result.reason_code, "telemetry_unavailable");
        assert!(!result.telemetry_fresh);
    }

    #[test]
    fn pressure_policy_marks_critical_even_without_fresh_telemetry_when_disk_is_low() {
        let caps = test_capabilities(4.0, 200.0);
        let telemetry = test_received_telemetry(20.0, 35.0, 600);
        let cfg = DiskPressurePolicyConfig::default();

        let result = evaluate_pressure_policy(&caps, Some(&telemetry), &cfg);
        assert_eq!(result.state, PressureState::Critical);
        assert_eq!(result.confidence, PressureConfidence::Medium);
        assert_eq!(result.reason_code, "disk_critical_without_fresh_telemetry");
    }

    #[test]
    fn pressure_policy_marks_telemetry_gap_when_disk_metrics_missing() {
        let caps = WorkerCapabilities::new();
        let cfg = DiskPressurePolicyConfig::default();

        let result = evaluate_pressure_policy(&caps, None, &cfg);
        assert_eq!(result.state, PressureState::TelemetryGap);
        assert_eq!(result.confidence, PressureConfidence::Low);
        assert_eq!(result.reason_code, "disk_metrics_unavailable");
    }
}
