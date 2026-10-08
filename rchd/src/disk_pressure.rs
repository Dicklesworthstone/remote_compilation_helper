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
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
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
    /// Free GB on the filesystem holding build trees, when the worker reports
    /// it separately from the tightest mount (GH #78). Sizes capacity only;
    /// `state` is still classified from `disk_free_gb`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub build_disk_free_gb: Option<f64>,
    /// Total GB of the filesystem reported in `build_disk_free_gb`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub build_disk_total_gb: Option<f64>,
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
            build_disk_free_gb: None,
            build_disk_total_gb: None,
            disk_io_util_pct: None,
            memory_pressure: None,
            telemetry_age_secs: None,
            telemetry_fresh: false,
            evaluated_at_unix_ms: current_unix_ms(),
        }
    }
}

impl PressureAssessment {
    /// `(free_gb, total_gb, free_ratio)` of the disk that bounds how many
    /// builds fit: the build disk when reported, else the tightest mount.
    ///
    /// Pressure asks "is any mount a build touches about to fill?" and must
    /// include a small tmpfs `/tmp`. Capacity asks "how many build trees fit?"
    /// and must not: `/tmp` holds none of them (GH #78). Without a build-disk
    /// sample (an older `rch-wkr`) this is the tightest mount, the previous
    /// and more conservative behaviour.
    pub fn capacity_disk(&self) -> (Option<f64>, Option<f64>, Option<f64>) {
        match self.build_disk_free_gb {
            Some(free) => {
                let total = self.build_disk_total_gb;
                let ratio = total
                    .filter(|total| total.is_finite() && *total > 0.0)
                    .map(|total| (free / total).clamp(0.0, 1.0));
                (Some(free), total, ratio)
            }
            None => (self.disk_free_gb, self.disk_total_gb, self.disk_free_ratio),
        }
    }

    /// Free GB on the capacity disk; see [`Self::capacity_disk`].
    pub fn capacity_free_gb(&self) -> Option<f64> {
        self.capacity_disk().0
    }
}

/// A live capability probe's capacity sample. This is never serialized or
/// refreshed by CPU telemetry, pressure reevaluation, or daemon restoration.
#[derive(Debug, Clone)]
pub struct DiskCapacityObservation {
    worker_id: String,
    free_gib: u64,
    observed_at: Instant,
    generation: u64,
    current_generation: Arc<AtomicU64>,
}

impl DiskCapacityObservation {
    pub(crate) fn from_capabilities(
        worker_id: String,
        capabilities: &WorkerCapabilities,
        generation: u64,
        current_generation: Arc<AtomicU64>,
        observed_at: Instant,
    ) -> Option<Self> {
        // Pressure may describe /tmp instead of build storage. Older workers
        // without an explicit complete build-root sample cannot prove this
        // opt-in contract, even if their generic disk report looks healthy.
        let (Some(free), Some(total)) = (
            capabilities.build_disk_free_gb,
            capabilities.build_disk_total_gb,
        ) else {
            return None;
        };
        if !free.is_finite() || !total.is_finite() || total <= 0.0 || free < 0.0 || free > total {
            return None;
        }
        Some(Self {
            worker_id,
            // Worker df probes divide KiB by 1024²: these legacy *_gb fields
            // carry GiB. Round down rather than granting fractional headroom.
            free_gib: free.floor() as u64,
            observed_at,
            generation,
            current_generation,
        })
    }

    /// Free build-disk GiB, only while this sample is the worker's current,
    /// unexpired probe. Footprint learning must not start from stale space.
    pub(crate) fn current_free_gib(&self, worker_id: &str) -> Option<u64> {
        (self.worker_id == worker_id
            && self.observed_at.elapsed()
                <= DiskPressurePolicyConfig::default().telemetry_stale_after
            && self.current_generation.load(Ordering::Acquire) == self.generation)
            .then_some(self.free_gib)
    }

    pub(crate) fn observed_at(&self) -> Instant {
        self.observed_at
    }

    #[cfg(test)]
    pub(crate) fn fixture(worker_id: &str, free_gib: f64, age: Duration) -> Self {
        let mut sample = Self::from_capabilities(
            worker_id.to_owned(),
            &WorkerCapabilities {
                build_disk_free_gb: Some(free_gib),
                build_disk_total_gb: Some(free_gib.max(1.0)),
                ..Default::default()
            },
            1,
            Arc::new(AtomicU64::new(1)),
            Instant::now(),
        )
        .unwrap();
        sample.observed_at = Instant::now() - age;
        sample
    }
}

/// Explicit additional build space, including the operator's margin. Active
/// reservations remain whole even when observed free space has already fallen;
/// that conservative double counting avoids treating consumed bytes as a release.
#[derive(Debug, Clone, Default)]
pub struct DiskHeadroomAdmission {
    pub requested_gib: u32,
    pub capacity: Option<DiskCapacityObservation>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DiskHeadroomRejection {
    Unknown,
    Stale,
    Insufficient { free_gib: u64, required_gib: u64 },
}

impl DiskHeadroomRejection {
    pub(crate) fn reason_code(self) -> &'static str {
        match self {
            Self::Unknown => "disk_headroom_unknown",
            Self::Stale => "disk_headroom_stale",
            Self::Insufficient { .. } => "disk_headroom_insufficient",
        }
    }
}

impl std::fmt::Display for DiskHeadroomRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unknown => f.write_str("declared disk headroom requires a valid live capacity sample and durable budget accounting"),
            Self::Stale => f.write_str("declared disk headroom capacity sample expired, was superseded, or requires a probe after budget release"),
            Self::Insufficient { free_gib, required_gib } => write!(f, "declared disk headroom requires {required_gib} GiB including active reservations; worker reported {free_gib} GiB free"),
        }
    }
}

impl DiskHeadroomAdmission {
    #[cfg(test)]
    pub(crate) fn check(
        &self,
        worker_id: &str,
        reserved_gib: u64,
    ) -> Result<(), DiskHeadroomRejection> {
        self.check_after_completion(worker_id, reserved_gib, None)
    }

    /// Releasing a budget does not imply its bytes became free. A new probe
    /// must start strictly after completion before its capacity can fund
    /// another declared build, including probes still in flight at completion.
    pub(crate) fn check_after_completion(
        &self,
        worker_id: &str,
        reserved_gib: u64,
        capacity_after: Option<Instant>,
    ) -> Result<(), DiskHeadroomRejection> {
        if self.requested_gib == 0 {
            return Ok(());
        }
        let capacity = self
            .capacity
            .as_ref()
            .filter(|sample| sample.worker_id == worker_id)
            .ok_or(DiskHeadroomRejection::Unknown)?;
        if capacity.observed_at.elapsed()
            > DiskPressurePolicyConfig::default().telemetry_stale_after
            || capacity.current_generation.load(Ordering::Acquire) != capacity.generation
            || capacity_after.is_some_and(|cutoff| capacity.observed_at <= cutoff)
        {
            return Err(DiskHeadroomRejection::Stale);
        }
        let required_gib = reserved_gib.checked_add(u64::from(self.requested_gib));
        if required_gib.is_none_or(|required| required > capacity.free_gib) {
            return Err(DiskHeadroomRejection::Insufficient {
                free_gib: capacity.free_gib,
                required_gib: required_gib.unwrap_or(u64::MAX),
            });
        }
        Ok(())
    }
}

/// Convert free disk into a concurrent-slot budget without changing the
/// operator's configured CPU ceiling. Existing reservations are tracked separately.
#[derive(Debug, Clone, Copy)]
pub struct DiskSlotPolicy {
    floor_gb: f64,
    gb_per_slot: f64,
}

impl From<&rch_common::SelectionConfig> for DiskSlotPolicy {
    fn from(config: &rch_common::SelectionConfig) -> Self {
        Self {
            floor_gb: config.min_free_gb.unwrap_or(0.0).max(0.0),
            gb_per_slot: if config.disk_gb_per_slot.is_finite() && config.disk_gb_per_slot > 0.0 {
                config.disk_gb_per_slot
            } else {
                rch_common::SelectionConfig::default().disk_gb_per_slot
            },
        }
    }
}

impl DiskSlotPolicy {
    /// Continuous disk credit, from zero at the reserve floor to full credit
    /// above 25% free (or one slot's budget above the floor on small disks).
    /// Missing measurements stay neutral; admission handles telemetry gaps.
    pub fn headroom(&self, pressure: &PressureAssessment) -> f64 {
        let (free_gb, total_gb, ratio) = pressure.capacity_disk();
        let ratio = ratio.filter(|ratio| ratio.is_finite() && (0.0..=1.0).contains(ratio));
        let Some(free_gb) = free_gb.filter(|free| free.is_finite()) else {
            return ratio.map_or(1.0, |ratio| (ratio / 0.25).clamp(0.0, 1.0));
        };
        if free_gb <= self.floor_gb {
            return 0.0;
        }
        let total_gb = total_gb
            .filter(|total| total.is_finite() && *total > 0.0)
            .or_else(|| {
                ratio
                    .filter(|ratio| *ratio > 0.0)
                    .map(|ratio| free_gb / ratio)
            })
            .filter(|total| total.is_finite());
        let comfort_gb = total_gb
            .map_or(0.0, |total| total * 0.25)
            .max(self.floor_gb + self.gb_per_slot);
        ((free_gb - self.floor_gb) / (comfort_gb - self.floor_gb)).clamp(0.0, 1.0)
    }

    pub fn effective_slots(&self, configured: u32, pressure: &PressureAssessment) -> u32 {
        let Some(free_gb) = pressure.capacity_free_gb().filter(|free| free.is_finite()) else {
            return configured;
        };
        let disk_slots = ((free_gb - self.floor_gb).max(0.0) / self.gb_per_slot).floor();
        configured.min(disk_slots as u32)
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
    /// Receives build-disk probes for footprint learning (bd-wv746).
    history: Option<Arc<crate::history::BuildHistory>>,
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
            history: None,
        }
    }

    /// Feed each worker's current build-disk probe to running builds there.
    #[must_use]
    pub fn with_build_history(mut self, history: Arc<crate::history::BuildHistory>) -> Self {
        self.history = Some(history);
        self
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
        let endpoint = worker.endpoint_snapshot().await;
        // This evaluation is local. Keep its observations and publication on
        // one endpoint, so a retarget cannot inherit an old pressure verdict.
        let Some(_endpoint_guard) = worker.lock_current_endpoint(&endpoint).await else {
            return;
        };
        let worker_id = endpoint.config.id.to_string();
        if let Some(history) = &self.history
            && let Some(sample) = worker.disk_capacity_observation().await
            && let Some(free_gib) = sample.current_free_gib(&worker_id)
        {
            history.observe_build_disk(&worker_id, free_gib, sample.observed_at());
        }
        let capabilities = worker.capabilities().await;
        let telemetry = self.telemetry.latest_for_endpoint(&endpoint);
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
            // -1 = "never received", consistent with the other unknown-value
            // sentinels above (previously u64::MAX, which rendered as
            // 18446744073709551615 in logs/status).
            let telemetry_age_secs = next
                .telemetry_age_secs
                .and_then(|age| i64::try_from(age).ok())
                .unwrap_or(-1);

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
        (Some(free), Some(total)) if total > 0.0 && free.is_finite() => {
            Some((free / total).clamp(0.0, 1.0))
        }
        _ => None,
    };
    // A zero-total or non-finite build sample is a failed probe; drop it so
    // capacity falls back to the tightest mount instead of trusting junk.
    let (build_disk_free_gb, build_disk_total_gb) = match (
        capabilities.build_disk_free_gb,
        capabilities.build_disk_total_gb,
    ) {
        (Some(free), Some(total)) if free.is_finite() && total.is_finite() && total > 0.0 => {
            (Some(free.max(0.0)), Some(total))
        }
        _ => (None, None),
    };

    let now = Utc::now();
    let telemetry_age_secs = latest.map(|entry| {
        let age = now.signed_duration_since(entry.received_at).num_seconds();
        if age <= 0 { 0 } else { age as u64 }
    });
    let telemetry_fresh = telemetry_age_secs
        .map(|age| age <= config.telemetry_stale_after.as_secs())
        .unwrap_or(false);

    let memory_pressure = latest.map(|entry| entry.telemetry.memory.admission_pressure());
    let disk_io_util_pct = latest.and_then(|entry| {
        entry
            .telemetry
            .disk
            .as_ref()
            .map(|disk| disk.max_io_utilization_pct)
    });

    // A zero or non-finite reading is a failed probe, not a full disk: it
    // must not classify as critical via a defaulted 0.0 ratio.
    let (state, confidence, reason_code, policy_rule) =
        if disk_free_ratio.is_none() || disk_total_gb.is_some_and(|total| !total.is_finite()) {
            (
                PressureState::TelemetryGap,
                PressureConfidence::Low,
                "disk_metrics_unavailable".to_string(),
                "fail_open_missing_disk_metrics".to_string(),
            )
        } else if telemetry_fresh {
            classify_with_fresh_telemetry(
                disk_free_gb.unwrap_or_default(),
                disk_total_gb.unwrap_or_default(),
                disk_free_ratio.unwrap_or_default(),
                disk_io_util_pct,
                memory_pressure,
                config,
            )
        } else {
            classify_without_fresh_telemetry(
                disk_free_gb.unwrap_or_default(),
                disk_total_gb.unwrap_or_default(),
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
        build_disk_free_gb,
        build_disk_total_gb,
        disk_io_util_pct,
        memory_pressure,
        telemetry_age_secs,
        telemetry_fresh,
        evaluated_at_unix_ms: current_unix_ms(),
    }
}

/// Whether the absolute free-GB thresholds are meaningful for this
/// filesystem. A mount whose TOTAL size is in the same ballpark as the
/// thresholds (e.g. a half-of-RAM tmpfs /tmp reported as the worst mount)
/// can never satisfy `free > warning_free_gb`, so the absolute rules would
/// pin it at warning/critical forever even when it is nearly empty. Such
/// small filesystems are judged by the ratio rules alone; anything at least
/// twice the warning threshold gets the full rule set.
fn absolute_gb_thresholds_apply(disk_total_gb: f64, config: &DiskPressurePolicyConfig) -> bool {
    disk_total_gb >= 2.0 * config.warning_free_gb
}

fn classify_with_fresh_telemetry(
    disk_free_gb: f64,
    disk_total_gb: f64,
    disk_free_ratio: f64,
    disk_io_util_pct: Option<f64>,
    memory_pressure: Option<f64>,
    config: &DiskPressurePolicyConfig,
) -> (PressureState, PressureConfidence, String, String) {
    let absolute_gb = absolute_gb_thresholds_apply(disk_total_gb, config);
    if absolute_gb && disk_free_gb <= config.critical_free_gb {
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
            util >= config.critical_disk_io_util_pct
                && (!absolute_gb || disk_free_gb <= config.warning_free_gb)
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
    if memory_pressure
        .map(|pressure| pressure >= config.critical_memory_pressure)
        .unwrap_or(false)
    {
        return (
            PressureState::Critical,
            PressureConfidence::High,
            "memory_pressure_critical".to_string(),
            "memory_pressure>=critical_memory_pressure".to_string(),
        );
    }

    if absolute_gb && disk_free_gb <= config.warning_free_gb {
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
    disk_total_gb: f64,
    disk_free_ratio: f64,
    config: &DiskPressurePolicyConfig,
) -> (PressureState, PressureConfidence, String, String) {
    let absolute_gb = absolute_gb_thresholds_apply(disk_total_gb, config);
    if (absolute_gb && disk_free_gb <= config.critical_free_gb)
        || disk_free_ratio <= config.critical_free_ratio
    {
        return (
            PressureState::Critical,
            PressureConfidence::Medium,
            "disk_critical_without_fresh_telemetry".to_string(),
            "disk_threshold_breach_without_telemetry".to_string(),
        );
    }
    if (absolute_gb && disk_free_gb <= config.warning_free_gb)
        || disk_free_ratio <= config.warning_free_ratio
    {
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
    use rch_telemetry::collect::memory::{MemoryPressureStall, MemoryTelemetry};
    use rch_telemetry::protocol::{TelemetrySource, WorkerTelemetry};

    #[test]
    fn disk_budget_completion_requires_strictly_newer_probe_start() {
        let sample = DiskCapacityObservation::fixture("worker", 100.0, Duration::ZERO);
        let observed_at = sample.observed_at;
        let disk = DiskHeadroomAdmission {
            requested_gib: 80,
            capacity: Some(sample),
        };
        for cutoff in [observed_at, observed_at + Duration::from_nanos(1)] {
            assert_eq!(
                disk.check_after_completion("worker", 0, Some(cutoff)),
                Err(DiskHeadroomRejection::Stale)
            );
        }
        assert!(
            disk.check_after_completion("worker", 0, Some(observed_at - Duration::from_nanos(1)),)
                .is_ok()
        );
        assert!(
            DiskHeadroomAdmission::default()
                .check_after_completion("worker", u64::MAX, Some(observed_at))
                .is_ok()
        );
    }

    #[test]
    fn declared_disk_budget_requires_valid_recent_same_worker_capacity() {
        let admission = |free, age| DiskHeadroomAdmission {
            requested_gib: 64,
            capacity: Some(DiskCapacityObservation::fixture("worker", free, age)),
        };
        assert!(matches!(
            admission(51.0, Duration::ZERO).check("worker", 0),
            Err(DiskHeadroomRejection::Insufficient { .. })
        ));
        assert!(admission(64.0, Duration::ZERO).check("worker", 0).is_ok());
        assert!(admission(64.9, Duration::ZERO).check("worker", 1).is_err());
        assert!(admission(80.0, Duration::ZERO).check("worker", 16).is_ok());
        assert!(admission(80.0, Duration::ZERO).check("worker", 17).is_err());
        assert_eq!(
            admission(80.0, Duration::from_secs(91)).check("worker", 0),
            Err(DiskHeadroomRejection::Stale)
        );
        assert_eq!(
            admission(80.0, Duration::ZERO).check("other", 0),
            Err(DiskHeadroomRejection::Unknown)
        );
        assert!(
            admission(80.0, Duration::ZERO)
                .check("worker", u64::MAX)
                .is_err()
        );
        assert!(
            DiskHeadroomAdmission::default()
                .check("worker", u64::MAX)
                .is_ok()
        );
        assert_eq!(
            DiskHeadroomAdmission {
                requested_gib: 1,
                capacity: None
            }
            .check("worker", 0),
            Err(DiskHeadroomRejection::Unknown)
        );
        let snapshot = admission(80.0, Duration::ZERO);
        snapshot
            .capacity
            .as_ref()
            .unwrap()
            .current_generation
            .fetch_add(1, Ordering::Release);
        assert_eq!(
            snapshot.check("worker", 0),
            Err(DiskHeadroomRejection::Stale)
        );
    }

    #[test]
    fn declared_disk_budget_rejects_invalid_or_partial_build_sample() {
        for (free, total) in [
            (None, None),
            (None, Some(100.0)),
            (Some(100.0), None),
            (Some(f64::NAN), Some(100.0)),
            (Some(100.0), Some(f64::INFINITY)),
            (Some(-1.0), Some(100.0)),
            (Some(101.0), Some(100.0)),
            (Some(0.0), Some(0.0)),
        ] {
            let caps = WorkerCapabilities {
                build_disk_free_gb: free,
                build_disk_total_gb: total,
                disk_free_gb: Some(1_000.0),
                disk_total_gb: Some(2_000.0),
                ..Default::default()
            };
            assert!(
                DiskCapacityObservation::from_capabilities(
                    "worker".into(),
                    &caps,
                    1,
                    Arc::new(AtomicU64::new(1)),
                    Instant::now()
                )
                .is_none(),
                "{caps:?}"
            );
        }
    }

    #[test]
    fn disk_headroom_tracks_floor_comfort_and_recovery() {
        let policy = DiskSlotPolicy::from(&rch_common::SelectionConfig::default());
        for (free, expected) in [
            (0.0, 0.0),
            (10.0, 0.0),
            (55.0, 0.5),
            (100.0, 1.0),
            (200.0, 1.0),
        ] {
            let pressure = PressureAssessment {
                disk_free_gb: Some(free),
                disk_total_gb: Some(400.0),
                ..Default::default()
            };
            assert!((policy.headroom(&pressure) - expected).abs() < f64::EPSILON);
        }
        let policy = DiskSlotPolicy::from(&rch_common::SelectionConfig {
            min_free_gb: Some(5.0),
            disk_gb_per_slot: 2.5,
            ..Default::default()
        });
        let pressure = PressureAssessment {
            disk_free_gb: Some(6.25),
            disk_total_gb: Some(20.0),
            ..Default::default()
        };
        assert_eq!(policy.headroom(&pressure), 0.5);
    }

    #[test]
    fn disk_headroom_handles_partial_and_invalid_measurements() {
        let policy = DiskSlotPolicy::from(&rch_common::SelectionConfig::default());
        assert_eq!(policy.headroom(&PressureAssessment::default()), 1.0);
        for (free, total, ratio, expected) in [
            (Some(55.0), None, Some(0.1375), 0.5),
            (Some(15.0), None, None, 0.5),
            (None, None, Some(0.125), 0.5),
            (None, None, Some(0.0), 0.0),
            (Some(f64::NAN), Some(f64::INFINITY), Some(f64::NAN), 1.0),
            (None, None, Some(-1.0), 1.0),
        ] {
            let pressure = PressureAssessment {
                disk_free_gb: free,
                disk_total_gb: total,
                disk_free_ratio: ratio,
                ..Default::default()
            };
            assert!((policy.headroom(&pressure) - expected).abs() < 1e-12);
        }
    }

    fn caps_with_build_disk(tmp: (f64, f64), build: Option<(f64, f64)>) -> WorkerCapabilities {
        let mut caps = test_capabilities(tmp.0, tmp.1);
        caps.build_disk_free_gb = build.map(|(free, _)| free);
        caps.build_disk_total_gb = build.map(|(_, total)| total);
        caps
    }

    #[test]
    fn slot_capacity_is_sized_from_the_build_disk_not_a_small_tmpfs() {
        // GH #78 devbox: 16 GB tmpfs /tmp is the tightest mount (89.5% free)
        // while the 1.9 TB build disk has 1.7 TB free. Defaults: 10 GB floor,
        // 10 GB per slot.
        let policy = DiskSlotPolicy::from(&rch_common::SelectionConfig::default());
        let config = DiskPressurePolicyConfig::default();
        let caps = caps_with_build_disk((13.9, 15.5), Some((1700.0, 1900.0)));
        let pressure = evaluate_pressure_policy(&caps, None, &config);
        assert_eq!(pressure.disk_free_gb, Some(13.9), "pressure keeps /tmp");
        assert!(
            !matches!(
                pressure.state,
                PressureState::Critical | PressureState::Warning
            ),
            "{:?}",
            pressure.state
        );
        assert_eq!(policy.effective_slots(14, &pressure), 14);
        assert_eq!(policy.headroom(&pressure), 1.0);

        // A small build disk still derates: floor((25 - 10) / 10) = 1.
        let caps = caps_with_build_disk((13.9, 15.5), Some((25.0, 100.0)));
        let pressure = evaluate_pressure_policy(&caps, None, &config);
        assert_eq!(policy.effective_slots(14, &pressure), 1);

        // Without a build sample (older rch-wkr) capacity falls back to the
        // tightest mount, the previous behaviour.
        let caps = caps_with_build_disk((13.9, 15.5), None);
        let pressure = evaluate_pressure_policy(&caps, None, &config);
        assert_eq!(pressure.capacity_free_gb(), Some(13.9));
        assert_eq!(policy.effective_slots(14, &pressure), 0);

        // A junk build sample is a failed probe, not a disk: fall back.
        for junk in [(f64::NAN, 1900.0), (1700.0, 0.0), (1700.0, f64::INFINITY)] {
            let caps = caps_with_build_disk((13.9, 15.5), Some(junk));
            let pressure = evaluate_pressure_policy(&caps, None, &config);
            assert_eq!(pressure.build_disk_free_gb, None, "{junk:?}");
            assert_eq!(policy.effective_slots(14, &pressure), 0, "{junk:?}");
        }
    }

    #[test]
    fn full_tmp_is_still_critical_pressure_with_an_ample_build_disk() {
        // bd-lvbax: a full /tmp breaks scp/mktemp regardless of the data disk.
        let config = DiskPressurePolicyConfig::default();
        let caps = caps_with_build_disk((0.2, 15.5), Some((1700.0, 1900.0)));
        let pressure = evaluate_pressure_policy(&caps, None, &config);
        assert_eq!(pressure.state, PressureState::Critical);
        assert_eq!(pressure.capacity_free_gb(), Some(1700.0));
    }

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

    #[tokio::test]
    async fn replacement_pressure_requires_its_own_bound_telemetry() {
        let pool = WorkerPool::new();
        let config = rch_common::WorkerConfig {
            id: rch_common::WorkerId::new("worker-1"),
            host: "old.host".to_string(),
            user: "builder".to_string(),
            identity_file: "/test/key".to_string(),
            total_slots: 8,
            priority: 100,
            tags: Vec::new(),
            tools: Vec::new(),
        };
        pool.add_worker(config.clone()).await;
        let worker = pool.get(&config.id).await.unwrap();
        let telemetry = Arc::new(TelemetryStore::new(Duration::from_secs(300), None));
        let monitor =
            DiskPressureMonitor::new(pool, telemetry.clone(), DiskPressurePolicyConfig::default());
        let sample = test_received_telemetry(30.0, 40.0, 0).telemetry;
        let before = worker.endpoint_snapshot().await;
        worker
            .set_capabilities(test_capabilities(60.0, 200.0))
            .await;
        telemetry.ingest_for_endpoint(sample.clone(), TelemetrySource::SshPoll, &before);
        monitor.evaluate_worker(worker.clone()).await;
        assert_eq!(
            worker.pressure_assessment().await.state,
            PressureState::Healthy
        );

        let mut replacement = config;
        replacement.host = "replacement.host".to_string();
        assert!(worker.update_config(replacement).await);
        // Even freshly verified replacement disk capacity cannot make the old
        // endpoint's memory/IO telemetry valid for admission.
        worker
            .set_capabilities(test_capabilities(60.0, 200.0))
            .await;
        telemetry.ingest(sample.clone(), TelemetrySource::Piggyback);
        monitor.evaluate_worker(worker.clone()).await;
        assert_eq!(
            worker.pressure_assessment().await.state,
            PressureState::TelemetryGap
        );

        let current = worker.endpoint_snapshot().await;
        telemetry.ingest_for_endpoint(sample, TelemetrySource::SshPoll, &current);
        monitor.evaluate_worker(worker.clone()).await;
        assert_eq!(
            worker.pressure_assessment().await.state,
            PressureState::Healthy
        );
    }

    /// A nearly-empty small filesystem (a half-of-RAM tmpfs /tmp reported as
    /// the worst mount) must not trip the absolute free-GB thresholds it can
    /// never satisfy — ratio rules govern small mounts.
    #[test]
    fn small_tmpfs_nearly_empty_is_healthy_with_fresh_telemetry() {
        let caps = test_capabilities(15.9, 16.0);
        let telemetry = test_received_telemetry(30.0, 40.0, 5);
        let cfg = DiskPressurePolicyConfig::default();
        let assessment = evaluate_pressure_policy(&caps, Some(&telemetry), &cfg);
        assert_eq!(assessment.state, PressureState::Healthy);
        assert_eq!(assessment.reason_code, "pressure_healthy");
    }

    #[test]
    fn small_tmpfs_nearly_empty_is_gap_not_warning_without_telemetry() {
        let caps = test_capabilities(15.9, 16.0);
        let cfg = DiskPressurePolicyConfig::default();
        let assessment = evaluate_pressure_policy(&caps, None, &cfg);
        assert_eq!(assessment.state, PressureState::TelemetryGap);
        assert_eq!(assessment.reason_code, "telemetry_unavailable");
    }

    /// bd-lvbax regression: a genuinely full small /tmp must still go
    /// critical (via the ratio rule) — the size gate must not fail open.
    #[test]
    fn small_tmpfs_actually_full_is_critical_by_ratio() {
        let caps = test_capabilities(0.1, 3.8);
        let telemetry = test_received_telemetry(30.0, 40.0, 5);
        let cfg = DiskPressurePolicyConfig::default();
        let assessment = evaluate_pressure_policy(&caps, Some(&telemetry), &cfg);
        assert_eq!(assessment.state, PressureState::Critical);
        assert_eq!(assessment.reason_code, "disk_ratio_below_critical");

        let stale = evaluate_pressure_policy(&caps, None, &cfg);
        assert_eq!(stale.state, PressureState::Critical);
        assert_eq!(stale.reason_code, "disk_critical_without_fresh_telemetry");
    }

    /// Large disks keep the absolute free-GB rules unchanged.
    #[test]
    fn large_disk_absolute_gb_thresholds_still_fire() {
        let cfg = DiskPressurePolicyConfig::default();
        let telemetry = test_received_telemetry(30.0, 40.0, 5);

        let critical =
            evaluate_pressure_policy(&test_capabilities(8.0, 500.0), Some(&telemetry), &cfg);
        assert_eq!(critical.state, PressureState::Critical);
        assert_eq!(critical.reason_code, "disk_free_below_critical_gb");

        // 20G free of 300G is 6.7% — above the 5% critical ratio, so only the
        // absolute warning threshold can fire here.
        let warning =
            evaluate_pressure_policy(&test_capabilities(20.0, 300.0), Some(&telemetry), &cfg);
        assert_eq!(warning.state, PressureState::Warning);
        assert_eq!(warning.reason_code, "disk_free_below_warning_gb");

        // Boundary: exactly 2x warning_free_gb counts as large.
        let boundary = evaluate_pressure_policy(
            &test_capabilities(20.0, 2.0 * cfg.warning_free_gb),
            Some(&telemetry),
            &cfg,
        );
        assert_eq!(boundary.state, PressureState::Warning);
        assert_eq!(boundary.reason_code, "disk_free_below_warning_gb");
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
    fn pressure_policy_marks_critical_with_fresh_critical_memory_pressure() {
        let caps = test_capabilities(80.0, 200.0);
        let telemetry = test_received_telemetry(20.0, 95.0, 5);
        let cfg = DiskPressurePolicyConfig::default();

        let result = evaluate_pressure_policy(&caps, Some(&telemetry), &cfg);
        assert_eq!(result.state, PressureState::Critical);
        assert_eq!(result.confidence, PressureConfidence::High);
        assert_eq!(result.reason_code, "memory_pressure_critical");
    }

    #[test]
    fn pressure_policy_does_not_mask_critical_memory_with_warning_disk_headroom() {
        let caps = test_capabilities(18.0, 200.0);
        let telemetry = test_received_telemetry(90.0, 95.0, 5);
        let cfg = DiskPressurePolicyConfig::default();

        let result = evaluate_pressure_policy(&caps, Some(&telemetry), &cfg);
        assert_eq!(result.state, PressureState::Critical);
        assert_eq!(result.reason_code, "memory_pressure_critical");
    }

    #[test]
    fn pressure_policy_marks_warning_with_fresh_warning_memory_pressure() {
        let caps = test_capabilities(80.0, 200.0);
        let telemetry = test_received_telemetry(20.0, 85.0, 5);
        let cfg = DiskPressurePolicyConfig::default();

        let result = evaluate_pressure_policy(&caps, Some(&telemetry), &cfg);
        assert_eq!(result.state, PressureState::Warning);
        assert_eq!(result.reason_code, "memory_pressure_warning");
    }

    /// A worker thrashing on swap with RAM that still looks "available" must be
    /// gated by its memory stall, not waved through on the utilization score.
    /// Utilization 78.7 = vmi1264463 on 2026-09-24 (58.7% used + full swap);
    /// planted negative: the same worker with its measured healthy PSI later
    /// that day stays admitted.
    #[test]
    fn pressure_policy_gates_on_sustained_memory_stall_below_utilization_threshold() {
        let caps = test_capabilities(80.0, 200.0);
        let cfg = DiskPressurePolicyConfig::default();

        let mut thrashing = test_received_telemetry(20.0, 78.7, 5);
        thrashing.telemetry.memory.psi = Some(MemoryPressureStall {
            some_avg60: 24.58,
            full_avg60: 12.0,
            ..MemoryPressureStall::default()
        });
        let result = evaluate_pressure_policy(&caps, Some(&thrashing), &cfg);
        assert_eq!(result.state, PressureState::Critical);
        assert_eq!(result.reason_code, "memory_pressure_critical");

        let mut recovered = test_received_telemetry(20.0, 78.7, 5);
        recovered.telemetry.memory.psi = Some(MemoryPressureStall {
            some_avg60: 0.13,
            full_avg60: 0.13,
            ..MemoryPressureStall::default()
        });
        let result = evaluate_pressure_policy(&caps, Some(&recovered), &cfg);
        assert_ne!(result.state, PressureState::Critical);
        assert!(
            !result.reason_code.starts_with("memory_pressure"),
            "{}",
            result.reason_code
        );
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

    #[test]
    fn pressure_policy_treats_zero_total_or_nan_free_as_a_telemetry_gap() {
        let cfg = DiskPressurePolicyConfig::default();
        for (free, total) in [(10.0, 0.0), (f64::NAN, 100.0), (10.0, f64::NAN)] {
            let mut caps = WorkerCapabilities::new();
            caps.disk_free_gb = Some(free);
            caps.disk_total_gb = Some(total);
            let result = evaluate_pressure_policy(&caps, None, &cfg);
            assert_eq!(result.state, PressureState::TelemetryGap, "{free}/{total}");
            assert_eq!(result.reason_code, "disk_metrics_unavailable");
        }
    }
}
