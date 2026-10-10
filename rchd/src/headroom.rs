//! Predictive disk headroom estimator and per-build space reservation model.
//!
//! Computes minimum required free space with confidence bands so the scheduler
//! can reject or deprioritize workers likely to run out of space mid-build.
//! Uses historical transfer sizes per project when available; falls back to
//! conservative heuristics otherwise.
//!
//! # Reservation Model
//!
//! Each in-flight build claims a reservation from the worker's available headroom.
//! This prevents over-committing shared disks under concurrency.
//!
//! # Confidence Bands
//!
//! The estimator reports a `min`, `expected`, and `max` headroom requirement.
//! The scheduler uses `min` for soft scoring penalties and `expected` for
//! hard admission decisions.

#![allow(dead_code)] // Initial integration; consumers land in follow-on beads.

use crate::history::BuildHistory;
use rch_common::{BuildLocation, WorkerId};
use serde::Serialize;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info};

// =========================================================================
// Configuration
// =========================================================================

/// Configuration for the headroom estimator.
#[derive(Debug, Clone)]
pub struct HeadroomConfig {
    /// Default estimated build size when no historical data is available (GB).
    pub default_build_size_gb: f64,
    /// Safety multiplier applied to estimates (e.g. 1.5 = 50% overhead margin).
    pub safety_multiplier: f64,
    /// Maximum number of historical builds to sample per project.
    pub max_sample_size: usize,
    /// Minimum free space that must remain after reservation (GB).
    pub floor_free_gb: f64,
    /// Whether to use historical transfer sizes for estimation.
    pub use_historical_data: bool,
}

impl Default for HeadroomConfig {
    fn default() -> Self {
        Self {
            default_build_size_gb: 5.0,
            safety_multiplier: 1.5,
            max_sample_size: 20,
            floor_free_gb: 10.0,
            use_historical_data: true,
        }
    }
}

// =========================================================================
// Estimation Types
// =========================================================================

/// Confidence band for a headroom estimate.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct HeadroomEstimate {
    /// Minimum expected build size (GB) — optimistic.
    pub min_gb: f64,
    /// Expected build size (GB) — central estimate.
    pub expected_gb: f64,
    /// Maximum expected build size (GB) — conservative.
    pub max_gb: f64,
    /// Confidence level (0.0-1.0) based on data quality.
    pub confidence: f64,
    /// Number of historical samples used.
    pub sample_count: usize,
    /// Whether a fallback heuristic was used.
    pub is_fallback: bool,
}

/// Decision outcome from headroom admission check.
#[derive(Debug, Clone, Serialize)]
pub struct HeadroomDecision {
    /// Worker being evaluated.
    pub worker_id: WorkerId,
    /// Whether the worker has sufficient headroom.
    pub sufficient: bool,
    /// Estimated build headroom requirement.
    pub estimate: HeadroomEstimate,
    /// Worker's current free disk space (GB).
    pub disk_free_gb: f64,
    /// Currently reserved space on the worker (GB).
    pub reserved_gb: f64,
    /// Effective free space after reservations (GB).
    pub effective_free_gb: f64,
    /// Floor free space that must be maintained (GB).
    pub floor_gb: f64,
    /// Reason code for diagnostics.
    pub reason_code: String,
    /// Decision path for auditing.
    pub decision_path: String,
}

/// Reservation for an in-flight build's estimated disk usage.
#[derive(Debug, Clone)]
struct Reservation {
    /// Build ID holding this reservation.
    build_id: u64,
    /// Worker ID where space is reserved.
    worker_id: WorkerId,
    /// Reserved space (GB).
    reserved_gb: f64,
    /// Project ID for correlation.
    project_id: String,
}

// =========================================================================
// Headroom Estimator
// =========================================================================

/// Predictive disk headroom estimator.
///
/// Computes per-build space requirements and manages concurrent reservations
/// to prevent over-committing worker disks.
pub struct HeadroomEstimator {
    history: Arc<BuildHistory>,
    config: HeadroomConfig,
    /// Active reservations indexed by build_id.
    reservations: Arc<RwLock<HashMap<u64, Reservation>>>,
}

impl HeadroomEstimator {
    /// Create a new headroom estimator.
    pub fn new(history: Arc<BuildHistory>, config: HeadroomConfig) -> Self {
        Self {
            history,
            config,
            reservations: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Estimate headroom required for a build of the given project.
    ///
    /// Uses historical transfer sizes when available; falls back to the
    /// configured default when no data exists.
    pub fn estimate_build_headroom(&self, project_id: &str) -> HeadroomEstimate {
        if !self.config.use_historical_data {
            return self.fallback_estimate();
        }

        let builds = self
            .history
            .by_project(project_id, self.config.max_sample_size);
        let transfer_sizes: Vec<f64> = builds
            .iter()
            .filter(|b| b.location == BuildLocation::Remote && b.exit_code == 0)
            .filter_map(|b| b.bytes_transferred)
            .map(|bytes| bytes as f64 / (1024.0 * 1024.0 * 1024.0)) // Convert to GB
            .collect();

        if transfer_sizes.is_empty() {
            return self.fallback_estimate();
        }

        let n = transfer_sizes.len();
        let mean = transfer_sizes.iter().sum::<f64>() / n as f64;

        // Compute standard deviation for confidence bands
        let variance = if n > 1 {
            transfer_sizes
                .iter()
                .map(|x| (x - mean).powi(2))
                .sum::<f64>()
                / (n - 1) as f64
        } else {
            0.0
        };
        let std_dev = variance.sqrt();

        // Apply safety multiplier to get expected requirement
        let expected = mean * self.config.safety_multiplier;
        let min = (mean - std_dev).max(0.1) * self.config.safety_multiplier;
        let max = (mean + 2.0 * std_dev) * self.config.safety_multiplier;

        // Confidence based on sample size (saturates at ~10 samples)
        let confidence = 1.0 - (1.0 / (n as f64 + 1.0));

        HeadroomEstimate {
            min_gb: min,
            expected_gb: expected,
            max_gb: max,
            confidence,
            sample_count: n,
            is_fallback: false,
        }
    }

    /// Fallback estimate when no historical data is available.
    fn fallback_estimate(&self) -> HeadroomEstimate {
        let default = self.config.default_build_size_gb;
        HeadroomEstimate {
            min_gb: default * 0.5,
            expected_gb: default * self.config.safety_multiplier,
            max_gb: default * self.config.safety_multiplier * 2.0,
            confidence: 0.2, // Low confidence without data
            sample_count: 0,
            is_fallback: true,
        }
    }

    /// Check if a worker has sufficient headroom for a build.
    ///
    /// Accounts for existing reservations to prevent over-committing
    /// shared disk space under concurrency.
    pub async fn check_headroom(
        &self,
        worker_id: &WorkerId,
        project_id: &str,
        disk_free_gb: f64,
    ) -> HeadroomDecision {
        let estimate = self.estimate_build_headroom(project_id);
        let reserved = self.total_reserved_for_worker(worker_id).await;
        let effective_free = disk_free_gb - reserved;
        let required = estimate.expected_gb + self.config.floor_free_gb;

        let sufficient = effective_free >= required;

        let (reason_code, decision_path) = if sufficient {
            (
                "headroom_sufficient".to_string(),
                format!(
                    "effective_free({:.2}GB) >= required({:.2}GB) [estimate={:.2}GB + floor={:.2}GB]",
                    effective_free, required, estimate.expected_gb, self.config.floor_free_gb
                ),
            )
        } else {
            (
                "headroom_insufficient".to_string(),
                format!(
                    "effective_free({:.2}GB) < required({:.2}GB) [estimate={:.2}GB + floor={:.2}GB, reserved={:.2}GB]",
                    effective_free,
                    required,
                    estimate.expected_gb,
                    self.config.floor_free_gb,
                    reserved
                ),
            )
        };

        debug!(
            worker = %worker_id,
            project = project_id,
            sufficient,
            disk_free_gb,
            reserved_gb = reserved,
            effective_free_gb = effective_free,
            estimate_expected_gb = estimate.expected_gb,
            estimate_confidence = estimate.confidence,
            sample_count = estimate.sample_count,
            is_fallback = estimate.is_fallback,
            "Headroom check"
        );

        HeadroomDecision {
            worker_id: worker_id.clone(),
            sufficient,
            estimate,
            disk_free_gb,
            reserved_gb: reserved,
            effective_free_gb: effective_free,
            floor_gb: self.config.floor_free_gb,
            reason_code,
            decision_path,
        }
    }

    /// Create a reservation for a build about to start.
    ///
    /// Returns the reserved space in GB.
    pub async fn reserve(&self, build_id: u64, worker_id: &WorkerId, project_id: &str) -> f64 {
        let estimate = self.estimate_build_headroom(project_id);
        let reserved_gb = estimate.expected_gb;

        let reservation = Reservation {
            build_id,
            worker_id: worker_id.clone(),
            reserved_gb,
            project_id: project_id.to_string(),
        };

        info!(
            build_id,
            worker = %worker_id,
            project = project_id,
            reserved_gb,
            "Created headroom reservation"
        );

        self.reservations
            .write()
            .await
            .insert(build_id, reservation);
        reserved_gb
    }

    /// Release a reservation when a build completes.
    pub async fn release(&self, build_id: u64) -> Option<f64> {
        let reservation = self.reservations.write().await.remove(&build_id)?;

        debug!(
            build_id,
            worker = %reservation.worker_id,
            released_gb = reservation.reserved_gb,
            "Released headroom reservation"
        );

        Some(reservation.reserved_gb)
    }

    /// Get total reserved space for a specific worker.
    pub async fn total_reserved_for_worker(&self, worker_id: &WorkerId) -> f64 {
        self.reservations
            .read()
            .await
            .values()
            .filter(|r| &r.worker_id == worker_id)
            .map(|r| r.reserved_gb)
            .sum()
    }

    /// Get all active reservations summary.
    pub async fn reservation_summary(&self) -> Vec<(u64, WorkerId, f64, String)> {
        self.reservations
            .read()
            .await
            .values()
            .map(|r| {
                (
                    r.build_id,
                    r.worker_id.clone(),
                    r.reserved_gb,
                    r.project_id.clone(),
                )
            })
            .collect()
    }

    /// Get the number of active reservations.
    pub async fn reservation_count(&self) -> usize {
        self.reservations.read().await.len()
    }

    /// Compute a headroom score for worker selection scoring (0.0-1.0).
    ///
    /// Returns 1.0 if the worker has ample headroom (>2x required),
    /// scales linearly down to 0.0 at the minimum threshold.
    pub async fn headroom_score(
        &self,
        worker_id: &WorkerId,
        project_id: &str,
        disk_free_gb: f64,
    ) -> f64 {
        let estimate = self.estimate_build_headroom(project_id);
        let reserved = self.total_reserved_for_worker(worker_id).await;
        let effective_free = disk_free_gb - reserved;
        let required = estimate.expected_gb + self.config.floor_free_gb;

        if required <= 0.0 {
            return 1.0;
        }

        // Score: ratio of effective free to required, capped at [0.0, 1.0]
        // At 2x required headroom, score = 1.0
        // At exactly required, score = 0.5
        // Below required, score approaches 0.0
        let ratio = effective_free / required;
        (ratio / 2.0).clamp(0.0, 1.0)
    }
}

// =========================================================================
// Learned build footprints (bd-wv746)
// =========================================================================

/// Samples retained per (project, command class).
const FOOTPRINT_SAMPLES: usize = 8;
/// A footprint older than this no longer describes the project.
const FOOTPRINT_MAX_AGE_SECS: i64 = 30 * 24 * 60 * 60;
/// Growth below this is measurement noise (free space is sampled in whole GiB).
const FOOTPRINT_MIN_GROWTH_GIB: f64 = 1.0;

/// Key a footprint by project and command class. `cargo test --all-features`
/// can need 10x the space of `cargo check` in the same project, so the
/// classifier kind is part of the identity; unclassified commands share one.
pub fn footprint_key(project_id: &str, command: &str) -> String {
    let kind = rch_common::classify_command(command)
        .kind
        .map_or_else(|| "other".to_string(), |kind| format!("{kind:?}"));
    format!("{project_id}\u{1f}{kind}")
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, serde::Deserialize)]
struct FootprintSample {
    growth_gib: f64,
    observed_unix: i64,
}

/// Observed build-filesystem growth of recent remote builds.
///
/// A sample is the drop in a worker's free build-disk space between the
/// admission-time probe and the lowest probe seen while the build ran. It is
/// only taken when no other build this daemon admitted shared the worker, so
/// the growth is attributable to the one build. Other dispatchers' builds can
/// still inflate it; cache cleanup can deflate it. The estimate is therefore
/// used to steer placement between workers, never to refuse a build.
#[derive(Debug, Default, Serialize, serde::Deserialize)]
pub struct FootprintBook {
    #[serde(default)]
    entries: HashMap<String, VecDeque<FootprintSample>>,
}

impl FootprintBook {
    /// Load a persisted book. A missing or unreadable file is an empty book:
    /// footprints are advisory and are relearned from the next builds.
    pub fn load(path: &std::path::Path) -> Self {
        match std::fs::read(path) {
            Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_else(|error| {
                tracing::warn!(path = %path.display(), %error, "ignoring unreadable footprint book");
                Self::default()
            }),
            Err(_) => Self::default(),
        }
    }

    /// Persist with write-then-rename so a crash leaves the old book intact.
    pub fn persist(&self, path: &std::path::Path) -> std::io::Result<()> {
        let staged = path.with_extension(format!("tmp.{}", std::process::id()));
        std::fs::write(&staged, serde_json::to_vec(self)?)?;
        std::fs::rename(&staged, path)
    }

    /// Record one observed growth. Returns whether the book changed.
    pub fn record(&mut self, key: &str, growth_gib: f64, now_unix: i64) -> bool {
        if !growth_gib.is_finite() || growth_gib < FOOTPRINT_MIN_GROWTH_GIB {
            return false;
        }
        let samples = self.entries.entry(key.to_string()).or_default();
        if samples.len() >= FOOTPRINT_SAMPLES {
            samples.pop_front();
        }
        samples.push_back(FootprintSample {
            growth_gib,
            observed_unix: now_unix,
        });
        true
    }

    /// The largest unexpired growth for this key. The maximum (not the mean)
    /// is deliberate: an incremental rebuild grows a warm pool by little, but
    /// the next placement may land on a worker without that pool.
    pub fn estimate_gib(&self, key: &str, now_unix: i64) -> Option<f64> {
        self.entries
            .get(key)?
            .iter()
            .filter(|sample| {
                now_unix.saturating_sub(sample.observed_unix) <= FOOTPRINT_MAX_AGE_SECS
            })
            .map(|sample| sample.growth_gib)
            .reduce(f64::max)
    }

    /// Drop expired samples and empty keys.
    pub fn prune(&mut self, now_unix: i64) {
        for samples in self.entries.values_mut() {
            samples.retain(|sample| {
                now_unix.saturating_sub(sample.observed_unix) <= FOOTPRINT_MAX_AGE_SECS
            });
        }
        self.entries.retain(|_, samples| !samples.is_empty());
    }
}

/// Space a worker should have before taking a build with a learned footprint:
/// the footprint plus 10% (at least 5 GiB), so the build does not end with the
/// disk at zero bytes.
pub fn footprint_requirement_gib(footprint_gib: f64) -> f64 {
    footprint_gib + (footprint_gib * 0.1).max(5.0)
}

// =========================================================================
// Tests
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use rch_common::{BuildRecord, test_guard};

    fn make_remote_build(id: u64, project_id: &str, bytes_transferred: u64) -> BuildRecord {
        BuildRecord {
            id,
            started_at: "2026-01-01T00:00:00Z".to_string(),
            completed_at: "2026-01-01T00:01:00Z".to_string(),
            project_id: project_id.to_string(),
            worker_id: Some("worker-1".to_string()),
            command: "cargo build".to_string(),
            exit_code: 0,
            duration_ms: 60000,
            location: BuildLocation::Remote,
            bytes_transferred: Some(bytes_transferred),
            timing: None,
            cancellation: None,
        }
    }

    fn make_local_build(id: u64, project_id: &str) -> BuildRecord {
        BuildRecord {
            id,
            started_at: "2026-01-01T00:00:00Z".to_string(),
            completed_at: "2026-01-01T00:01:00Z".to_string(),
            project_id: project_id.to_string(),
            worker_id: None,
            command: "cargo build".to_string(),
            exit_code: 0,
            duration_ms: 120000,
            location: BuildLocation::Local,
            bytes_transferred: None,
            timing: None,
            cancellation: None,
        }
    }

    // =====================================================================
    // Configuration Tests
    // =====================================================================

    #[test]
    fn config_defaults() {
        let _guard = test_guard!();
        let config = HeadroomConfig::default();

        assert!((config.default_build_size_gb - 5.0).abs() < f64::EPSILON);
        assert!((config.safety_multiplier - 1.5).abs() < f64::EPSILON);
        assert_eq!(config.max_sample_size, 20);
        assert!((config.floor_free_gb - 10.0).abs() < f64::EPSILON);
        assert!(config.use_historical_data);
    }

    // =====================================================================
    // Estimation Tests
    // =====================================================================

    #[test]
    fn estimate_fallback_when_no_history() {
        let _guard = test_guard!();
        let history = Arc::new(BuildHistory::new(10));
        let config = HeadroomConfig::default();
        let estimator = HeadroomEstimator::new(history, config);

        let estimate = estimator.estimate_build_headroom("unknown-project");

        assert!(estimate.is_fallback);
        assert_eq!(estimate.sample_count, 0);
        assert!(estimate.confidence < 0.3);
        // Default 5GB * 0.5 = 2.5 min, 5.0 * 1.5 = 7.5 expected
        assert!((estimate.min_gb - 2.5).abs() < f64::EPSILON);
        assert!((estimate.expected_gb - 7.5).abs() < f64::EPSILON);
    }

    #[test]
    fn estimate_fallback_when_historical_disabled() {
        let _guard = test_guard!();
        let history = Arc::new(BuildHistory::new(10));

        // Add a build record that should be ignored
        history.record(make_remote_build(1, "proj-a", 1024 * 1024 * 1024));

        let config = HeadroomConfig {
            use_historical_data: false,
            ..Default::default()
        };
        let estimator = HeadroomEstimator::new(history, config);

        let estimate = estimator.estimate_build_headroom("proj-a");

        assert!(estimate.is_fallback);
        assert_eq!(estimate.sample_count, 0);
    }

    #[test]
    fn estimate_from_single_build() {
        let _guard = test_guard!();
        let history = Arc::new(BuildHistory::new(10));

        // 2 GB transfer
        let two_gb = 2 * 1024 * 1024 * 1024_u64;
        history.record(make_remote_build(1, "proj-a", two_gb));

        let config = HeadroomConfig::default();
        let estimator = HeadroomEstimator::new(history, config);

        let estimate = estimator.estimate_build_headroom("proj-a");

        assert!(!estimate.is_fallback);
        assert_eq!(estimate.sample_count, 1);
        // Mean = 2GB, expected = 2 * 1.5 = 3.0
        assert!((estimate.expected_gb - 3.0).abs() < 0.01);
        // Confidence with 1 sample: 1 - 1/(1+1) = 0.5
        assert!((estimate.confidence - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn estimate_from_multiple_builds() {
        let _guard = test_guard!();
        let history = Arc::new(BuildHistory::new(10));

        let one_gb = 1024 * 1024 * 1024_u64;
        // Add 5 builds: 1GB, 2GB, 3GB, 2GB, 2GB
        history.record(make_remote_build(1, "proj-b", one_gb));
        history.record(make_remote_build(2, "proj-b", 2 * one_gb));
        history.record(make_remote_build(3, "proj-b", 3 * one_gb));
        history.record(make_remote_build(4, "proj-b", 2 * one_gb));
        history.record(make_remote_build(5, "proj-b", 2 * one_gb));

        let config = HeadroomConfig::default();
        let estimator = HeadroomEstimator::new(history, config);

        let estimate = estimator.estimate_build_headroom("proj-b");

        assert!(!estimate.is_fallback);
        assert_eq!(estimate.sample_count, 5);
        // Mean = (1+2+3+2+2)/5 = 2.0, expected = 2.0 * 1.5 = 3.0
        assert!((estimate.expected_gb - 3.0).abs() < 0.01);
        assert!(estimate.min_gb < estimate.expected_gb);
        assert!(estimate.max_gb > estimate.expected_gb);
        // Confidence with 5 samples: 1 - 1/6 = 0.833
        assert!(estimate.confidence > 0.8);
    }

    #[test]
    fn estimate_ignores_local_builds() {
        let _guard = test_guard!();
        let history = Arc::new(BuildHistory::new(10));

        // Only local builds — should fallback
        history.record(make_local_build(1, "proj-c"));
        history.record(make_local_build(2, "proj-c"));

        let config = HeadroomConfig::default();
        let estimator = HeadroomEstimator::new(history, config);

        let estimate = estimator.estimate_build_headroom("proj-c");

        assert!(estimate.is_fallback);
        assert_eq!(estimate.sample_count, 0);
    }

    #[test]
    fn estimate_ignores_failed_builds() {
        let _guard = test_guard!();
        let history = Arc::new(BuildHistory::new(10));

        let one_gb = 1024 * 1024 * 1024_u64;
        // Add a successful build
        history.record(make_remote_build(1, "proj-d", one_gb));

        // Add a failed build (should be ignored)
        let mut failed = make_remote_build(2, "proj-d", 10 * one_gb);
        failed.exit_code = 1;
        history.record(failed);

        let config = HeadroomConfig::default();
        let estimator = HeadroomEstimator::new(history, config);

        let estimate = estimator.estimate_build_headroom("proj-d");

        assert_eq!(estimate.sample_count, 1);
        // Only uses the 1GB successful build
        assert!((estimate.expected_gb - 1.5).abs() < 0.01);
    }

    #[test]
    fn estimate_isolates_projects() {
        let _guard = test_guard!();
        let history = Arc::new(BuildHistory::new(10));

        let one_gb = 1024 * 1024 * 1024_u64;
        history.record(make_remote_build(1, "small-proj", one_gb));
        history.record(make_remote_build(2, "big-proj", 10 * one_gb));

        let config = HeadroomConfig::default();
        let estimator = HeadroomEstimator::new(history, config);

        let small_est = estimator.estimate_build_headroom("small-proj");
        let big_est = estimator.estimate_build_headroom("big-proj");

        assert!((small_est.expected_gb - 1.5).abs() < 0.01);
        assert!((big_est.expected_gb - 15.0).abs() < 0.01);
    }

    // =====================================================================
    // Headroom Decision Tests
    // =====================================================================

    #[tokio::test]
    async fn check_headroom_sufficient() {
        let history = Arc::new(BuildHistory::new(10));
        let one_gb = 1024 * 1024 * 1024_u64;
        history.record(make_remote_build(1, "proj-e", 2 * one_gb));

        let config = HeadroomConfig::default();
        let estimator = HeadroomEstimator::new(history, config);

        let decision = estimator
            .check_headroom(&WorkerId::new("w1"), "proj-e", 50.0)
            .await;

        assert!(decision.sufficient);
        assert_eq!(decision.reason_code, "headroom_sufficient");
        assert!((decision.disk_free_gb - 50.0).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn check_headroom_insufficient() {
        let history = Arc::new(BuildHistory::new(10));
        let ten_gb = 10 * 1024 * 1024 * 1024_u64;
        history.record(make_remote_build(1, "big-proj", ten_gb));

        let config = HeadroomConfig::default();
        let estimator = HeadroomEstimator::new(history, config);

        // Only 5GB free, but estimate = 10*1.5=15GB + 10GB floor = 25GB required
        let decision = estimator
            .check_headroom(&WorkerId::new("w1"), "big-proj", 5.0)
            .await;

        assert!(!decision.sufficient);
        assert_eq!(decision.reason_code, "headroom_insufficient");
    }

    // =====================================================================
    // Reservation Tests
    // =====================================================================

    #[tokio::test]
    async fn reserve_and_release() {
        let history = Arc::new(BuildHistory::new(10));
        let one_gb = 1024 * 1024 * 1024_u64;
        history.record(make_remote_build(1, "proj-f", 2 * one_gb));

        let config = HeadroomConfig::default();
        let estimator = HeadroomEstimator::new(history, config);

        // Reserve for build 100
        let reserved = estimator.reserve(100, &WorkerId::new("w1"), "proj-f").await;
        assert!(reserved > 0.0);
        assert_eq!(estimator.reservation_count().await, 1);

        // Check total reserved
        let total = estimator
            .total_reserved_for_worker(&WorkerId::new("w1"))
            .await;
        assert!((total - reserved).abs() < f64::EPSILON);

        // Release
        let released = estimator.release(100).await;
        assert_eq!(released, Some(reserved));
        assert_eq!(estimator.reservation_count().await, 0);
    }

    #[tokio::test]
    async fn reservations_reduce_effective_headroom() {
        let history = Arc::new(BuildHistory::new(10));
        let one_gb = 1024 * 1024 * 1024_u64;
        history.record(make_remote_build(1, "proj-g", 2 * one_gb));

        let config = HeadroomConfig::default();
        let estimator = HeadroomEstimator::new(history, config);

        // Without reservation: 50GB free, need ~13GB (3GB estimate + 10GB floor)
        let decision1 = estimator
            .check_headroom(&WorkerId::new("w1"), "proj-g", 50.0)
            .await;
        assert!(decision1.sufficient);

        // Add reservations to eat up headroom
        estimator.reserve(200, &WorkerId::new("w1"), "proj-g").await;
        estimator.reserve(201, &WorkerId::new("w1"), "proj-g").await;
        estimator.reserve(202, &WorkerId::new("w1"), "proj-g").await;
        estimator.reserve(203, &WorkerId::new("w1"), "proj-g").await;
        estimator.reserve(204, &WorkerId::new("w1"), "proj-g").await;
        estimator.reserve(205, &WorkerId::new("w1"), "proj-g").await;
        estimator.reserve(206, &WorkerId::new("w1"), "proj-g").await;
        estimator.reserve(207, &WorkerId::new("w1"), "proj-g").await;
        estimator.reserve(208, &WorkerId::new("w1"), "proj-g").await;
        estimator.reserve(209, &WorkerId::new("w1"), "proj-g").await;

        // 10 reservations * 3GB each = 30GB reserved
        // effective_free = 50 - 30 = 20GB
        // required = 3GB + 10GB = 13GB
        // Still sufficient but with reduced margin
        let decision2 = estimator
            .check_headroom(&WorkerId::new("w1"), "proj-g", 50.0)
            .await;
        assert!(decision2.sufficient);
        assert!(decision2.reserved_gb > 25.0); // At least 25GB reserved

        // Add more to push over the edge
        for i in 210..220 {
            estimator.reserve(i, &WorkerId::new("w1"), "proj-g").await;
        }

        // Now 20 reservations * 3GB = 60GB reserved, but only 50GB free
        // effective_free = 50 - 60 = -10GB — not sufficient
        let decision3 = estimator
            .check_headroom(&WorkerId::new("w1"), "proj-g", 50.0)
            .await;
        assert!(!decision3.sufficient);
    }

    #[tokio::test]
    async fn reservations_are_per_worker() {
        let history = Arc::new(BuildHistory::new(10));
        let one_gb = 1024 * 1024 * 1024_u64;
        history.record(make_remote_build(1, "proj-h", 2 * one_gb));

        let config = HeadroomConfig::default();
        let estimator = HeadroomEstimator::new(history, config);

        // Reserve on w1
        estimator.reserve(300, &WorkerId::new("w1"), "proj-h").await;

        // w2 should have zero reservations
        let w2_reserved = estimator
            .total_reserved_for_worker(&WorkerId::new("w2"))
            .await;
        assert!((w2_reserved - 0.0).abs() < f64::EPSILON);

        // w1 should have the reservation
        let w1_reserved = estimator
            .total_reserved_for_worker(&WorkerId::new("w1"))
            .await;
        assert!(w1_reserved > 0.0);
    }

    #[tokio::test]
    async fn release_nonexistent_returns_none() {
        let history = Arc::new(BuildHistory::new(10));
        let config = HeadroomConfig::default();
        let estimator = HeadroomEstimator::new(history, config);

        let result = estimator.release(999).await;
        assert!(result.is_none());
    }

    // =====================================================================
    // Headroom Score Tests
    // =====================================================================

    #[tokio::test]
    async fn headroom_score_ample_space() {
        let history = Arc::new(BuildHistory::new(10));
        let one_gb = 1024 * 1024 * 1024_u64;
        history.record(make_remote_build(1, "proj-i", one_gb));

        let config = HeadroomConfig::default();
        let estimator = HeadroomEstimator::new(history, config);

        // 100GB free, need ~11.5GB (1.5GB estimate + 10GB floor)
        // ratio = 100/11.5 ≈ 8.7, score = 8.7/2 capped at 1.0
        let score = estimator
            .headroom_score(&WorkerId::new("w1"), "proj-i", 100.0)
            .await;
        assert!((score - 1.0).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn headroom_score_tight_space() {
        let history = Arc::new(BuildHistory::new(10));
        let five_gb = 5 * 1024 * 1024 * 1024_u64;
        history.record(make_remote_build(1, "proj-j", five_gb));

        let config = HeadroomConfig::default();
        let estimator = HeadroomEstimator::new(history, config);

        // 20GB free, need ~17.5GB (7.5GB estimate + 10GB floor)
        // ratio = 20/17.5 ≈ 1.14, score = 1.14/2 ≈ 0.57
        let score = estimator
            .headroom_score(&WorkerId::new("w1"), "proj-j", 20.0)
            .await;
        assert!(score > 0.4);
        assert!(score < 0.7);
    }

    #[tokio::test]
    async fn headroom_score_zero_when_insufficient() {
        let history = Arc::new(BuildHistory::new(10));
        let ten_gb = 10 * 1024 * 1024 * 1024_u64;
        history.record(make_remote_build(1, "proj-k", ten_gb));

        let config = HeadroomConfig::default();
        let estimator = HeadroomEstimator::new(history, config);

        // 5GB free, need ~25GB (15GB estimate + 10GB floor)
        // ratio = 5/25 = 0.2, score = 0.2/2 = 0.1
        let score = estimator
            .headroom_score(&WorkerId::new("w1"), "proj-k", 5.0)
            .await;
        assert!(score < 0.15);
    }

    // =====================================================================
    // Reservation Summary Tests
    // =====================================================================

    #[tokio::test]
    async fn reservation_summary_empty() {
        let history = Arc::new(BuildHistory::new(10));
        let config = HeadroomConfig::default();
        let estimator = HeadroomEstimator::new(history, config);

        let summary = estimator.reservation_summary().await;
        assert!(summary.is_empty());
    }

    #[tokio::test]
    async fn reservation_summary_with_entries() {
        let history = Arc::new(BuildHistory::new(10));
        let config = HeadroomConfig::default();
        let estimator = HeadroomEstimator::new(history, config);

        estimator.reserve(400, &WorkerId::new("w1"), "proj-a").await;
        estimator.reserve(401, &WorkerId::new("w2"), "proj-b").await;

        let summary = estimator.reservation_summary().await;
        assert_eq!(summary.len(), 2);
    }

    // =====================================================================
    // Learned footprint tests (bd-wv746)
    // =====================================================================

    #[test]
    fn footprint_key_separates_command_classes_and_projects() {
        let test = footprint_key("fgdb", "cargo test --all-features");
        assert_eq!(test, footprint_key("fgdb", "cargo test -p core"));
        assert_ne!(test, footprint_key("fgdb", "cargo check --workspace"));
        assert_ne!(test, footprint_key("other", "cargo test --all-features"));
        assert_eq!(
            footprint_key("fgdb", "echo hi"),
            footprint_key("fgdb", "ls -la")
        );
    }

    #[test]
    fn footprint_estimate_is_the_largest_unexpired_sample() {
        let mut book = FootprintBook::default();
        let now = 1_800_000_000;
        assert_eq!(book.estimate_gib("k", now), None);
        // Sub-GiB growth is noise in whole-GiB probes; non-finite is junk.
        assert!(!book.record("k", 0.5, now));
        assert!(!book.record("k", f64::NAN, now));
        assert!(!book.record("k", f64::INFINITY, now));
        assert_eq!(book.estimate_gib("k", now), None);

        assert!(book.record("k", 64.0, now - FOOTPRINT_MAX_AGE_SECS - 1));
        assert!(book.record("k", 3.0, now));
        assert!(book.record("k", 12.0, now));
        // The 64 GiB sample expired; a warm 3 GiB rebuild does not hide 12.
        assert_eq!(book.estimate_gib("k", now), Some(12.0));
        assert_eq!(
            book.estimate_gib("k", now - FOOTPRINT_MAX_AGE_SECS),
            Some(64.0)
        );

        book.prune(now);
        assert_eq!(book.entries["k"].len(), 2);
        book.prune(now + 2 * FOOTPRINT_MAX_AGE_SECS);
        assert!(book.entries.is_empty());
    }

    #[test]
    fn footprint_book_keeps_a_bounded_window() {
        let mut book = FootprintBook::default();
        let now = 1_800_000_000;
        book.record("k", 100.0, now);
        for growth in 0..FOOTPRINT_SAMPLES {
            book.record("k", 2.0 + growth as f64, now);
        }
        assert_eq!(book.entries["k"].len(), FOOTPRINT_SAMPLES);
        // The oldest (100 GiB) sample rolled out of the window.
        assert_eq!(
            book.estimate_gib("k", now),
            Some(1.0 + FOOTPRINT_SAMPLES as f64)
        );
    }

    #[test]
    fn footprint_book_round_trips_and_tolerates_corruption() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("history.footprints.json");
        assert!(FootprintBook::load(&path).entries.is_empty());

        let mut book = FootprintBook::default();
        book.record("k", 40.0, 1_800_000_000);
        book.persist(&path).unwrap();
        let loaded = FootprintBook::load(&path);
        assert_eq!(loaded.estimate_gib("k", 1_800_000_000), Some(40.0));

        std::fs::write(&path, b"{not json").unwrap();
        assert!(FootprintBook::load(&path).entries.is_empty());
    }

    #[test]
    fn footprint_requirement_adds_a_margin() {
        assert!((footprint_requirement_gib(64.0) - 70.4).abs() < 1e-9);
        assert!((footprint_requirement_gib(10.0) - 15.0).abs() < 1e-9);
    }
}
