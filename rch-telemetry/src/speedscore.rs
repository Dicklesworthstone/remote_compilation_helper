//! SpeedScore calculation and normalization engine.
//!
//! This module provides the core SpeedScore calculation that combines individual
//! benchmark results into a unified worker performance score. The SpeedScore
//! enables simple comparison between workers for job assignment.
//!
//! ## Design Philosophy
//!
//! Raw benchmark values vary by orders of magnitude (CPU in ops/sec, disk in MB/s,
//! latency in ms). Reference-relative curves map them to 0-100 without clipping
//! ordinary fast machines to the same score. Reference points are midpoints, not
//! hardware limits. Only usable measurements participate in the weighted total;
//! a failed or unmeasured component is not evidence of a slow worker.
//!
//! ## Weights
//!
//! Weights are optimized for compilation workloads:
//! - CPU: 30% - Compilation is CPU-intensive
//! - Memory: 15% - Large projects need memory bandwidth
//! - Disk: 20% - I/O for sources and artifacts
//! - Network: 15% - Transfer overhead to/from worker
//! - Compilation: 20% - Real-world compilation benchmark

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::{debug, info};

use crate::benchmarks::{
    CompilationBenchmarkResult, CpuBenchmarkResult, DiskBenchmarkResult, MemoryBenchmarkResult,
    NetworkBenchmarkResult,
};

/// Current version of the SpeedScore algorithm.
/// Increment when calculation methodology changes to invalidate cached scores.
pub const SPEEDSCORE_VERSION: u32 = 2;

/// Snapshot of system conditions at benchmark time.
///
/// Used for drift detection: comparing current telemetry against conditions
/// that were present when the benchmark ran. Without this context, drift
/// detection cannot distinguish "worker is idle" from "worker conditions changed".
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkConditions {
    /// CPU utilization percentage at benchmark time (0-100).
    pub cpu_percent: f64,
    /// Memory usage percentage at benchmark time (0-100).
    pub memory_used_percent: f64,
    /// 1-minute load average at benchmark time.
    pub load_1m: f64,
}

/// Unified SpeedScore combining all benchmark components.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpeedScore {
    /// Overall score (0-100).
    pub total: f64,

    /// CPU component score (0-100).
    pub cpu_score: f64,
    /// Memory component score (0-100).
    pub memory_score: f64,
    /// Disk I/O component score (0-100).
    pub disk_score: f64,
    /// Network component score (0-100).
    pub network_score: f64,
    /// Compilation component score (0-100).
    pub compilation_score: f64,

    /// Effective weights used for this calculation. Unavailable components have
    /// zero weight; all weights are zero when no usable weighted evidence exists.
    pub weights: SpeedScoreWeights,

    /// Timestamp when the score was calculated.
    pub calculated_at: DateTime<Utc>,

    /// Algorithm version for cache invalidation.
    pub version: u32,

    /// System conditions at the time the benchmark was run.
    ///
    /// `None` for scores calculated before this field was introduced,
    /// or when telemetry was unavailable during benchmarking.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub benchmark_conditions: Option<BenchmarkConditions>,
}

impl Default for SpeedScore {
    fn default() -> Self {
        Self {
            total: 0.0,
            cpu_score: 0.0,
            memory_score: 0.0,
            disk_score: 0.0,
            network_score: 0.0,
            compilation_score: 0.0,
            weights: SpeedScoreWeights::default(),
            calculated_at: Utc::now(),
            version: SPEEDSCORE_VERSION,
            benchmark_conditions: None,
        }
    }
}

impl SpeedScore {
    /// Calculate SpeedScore from individual benchmark results.
    ///
    /// Uses default weights optimized for compilation workloads.
    pub fn calculate(results: &BenchmarkResults) -> Self {
        Self::calculate_with_weights(results, &SpeedScoreWeights::default())
    }

    /// Calculate SpeedScore with custom weights.
    pub fn calculate_with_weights(results: &BenchmarkResults, weights: &SpeedScoreWeights) -> Self {
        // Some(default()) is how several failed/absent sub-benchmarks are
        // represented. Do not give those records a share of the denominator.
        let usable = results.usable();
        let results = &usable;
        debug!(
            cpu_present = results.cpu.is_some(),
            memory_present = results.memory.is_some(),
            disk_present = results.disk.is_some(),
            network_present = results.network.is_some(),
            compilation_present = results.compilation.is_some(),
            "Calculating SpeedScore from usable benchmark results"
        );

        let cpu_score = results.cpu.as_ref().map(normalize_cpu).unwrap_or(0.0);
        let memory_score = results.memory.as_ref().map(normalize_memory).unwrap_or(0.0);
        let disk_score = results.disk.as_ref().map(normalize_disk).unwrap_or(0.0);
        let network_score = results
            .network
            .as_ref()
            .map(normalize_network)
            .unwrap_or(0.0);
        let compilation_score = results
            .compilation
            .as_ref()
            .map(normalize_compilation)
            .unwrap_or(0.0);

        let (total, effective_weights) = calculate_weighted_total(
            cpu_score,
            memory_score,
            disk_score,
            network_score,
            compilation_score,
            weights,
            results,
        );

        info!(
            total = format!("{:.1}", total),
            cpu = format!("{:.1}", cpu_score),
            memory = format!("{:.1}", memory_score),
            disk = format!("{:.1}", disk_score),
            network = format!("{:.1}", network_score),
            compilation = format!("{:.1}", compilation_score),
            "SpeedScore calculated"
        );

        Self {
            total,
            cpu_score,
            memory_score,
            disk_score,
            network_score,
            compilation_score,
            weights: effective_weights,
            calculated_at: Utc::now(),
            version: SPEEDSCORE_VERSION,
            benchmark_conditions: None,
        }
    }

    /// Check if this score is outdated (different algorithm version).
    pub fn is_outdated(&self) -> bool {
        self.version != SPEEDSCORE_VERSION
    }

    /// Attach system conditions that were observed during the benchmark.
    pub fn with_conditions(mut self, conditions: BenchmarkConditions) -> Self {
        self.benchmark_conditions = Some(conditions);
        self
    }

    /// Get a human-readable rating based on the total score.
    pub fn rating(&self) -> &'static str {
        match self.total {
            x if x >= 90.0 => "Excellent",
            x if x >= 75.0 => "Very Good",
            x if x >= 60.0 => "Good",
            x if x >= 45.0 => "Average",
            x if x >= 30.0 => "Below Average",
            _ => "Poor",
        }
    }
}

/// Weights for each SpeedScore component.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub struct SpeedScoreWeights {
    /// CPU weight (0.0-1.0).
    pub cpu: f64,
    /// Memory weight (0.0-1.0).
    pub memory: f64,
    /// Disk I/O weight (0.0-1.0).
    pub disk: f64,
    /// Network weight (0.0-1.0).
    pub network: f64,
    /// Compilation weight (0.0-1.0).
    pub compilation: f64,
}

impl Default for SpeedScoreWeights {
    fn default() -> Self {
        Self {
            cpu: 0.30,
            memory: 0.15,
            disk: 0.20,
            network: 0.15,
            compilation: 0.20,
        }
    }
}

impl SpeedScoreWeights {
    /// Create weights optimized for CPU-bound workloads.
    pub fn cpu_heavy() -> Self {
        Self {
            cpu: 0.45,
            memory: 0.15,
            disk: 0.10,
            network: 0.10,
            compilation: 0.20,
        }
    }

    /// Create weights optimized for I/O-bound workloads.
    pub fn io_heavy() -> Self {
        Self {
            cpu: 0.20,
            memory: 0.10,
            disk: 0.35,
            network: 0.15,
            compilation: 0.20,
        }
    }

    /// Create weights optimized for network-intensive workloads.
    pub fn network_heavy() -> Self {
        Self {
            cpu: 0.20,
            memory: 0.10,
            disk: 0.15,
            network: 0.35,
            compilation: 0.20,
        }
    }

    /// Validate finite, nonnegative weights that sum to 1.0 (within tolerance).
    pub fn is_valid(&self) -> bool {
        let values = self.as_array();
        values.iter().all(|w| w.is_finite() && *w >= 0.0)
            && (values.iter().sum::<f64>() - 1.0).abs() < 0.001
    }

    /// Normalize finite positive weights to sum to 1.0.
    /// Invalid weights are excluded; no usable weights falls back to defaults.
    pub fn normalize(&self) -> Self {
        let normalized = normalize_weights(self.as_array());
        if normalized.iter().all(|w| *w == 0.0) {
            Self::default()
        } else {
            Self::from_array(normalized)
        }
    }

    fn as_array(&self) -> [f64; 5] {
        [
            self.cpu,
            self.memory,
            self.disk,
            self.network,
            self.compilation,
        ]
    }

    fn from_array(values: [f64; 5]) -> Self {
        Self {
            cpu: values[0],
            memory: values[1],
            disk: values[2],
            network: values[3],
            compilation: values[4],
        }
    }
}

/// Collection of all benchmark results for SpeedScore calculation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BenchmarkResults {
    /// CPU benchmark result.
    pub cpu: Option<CpuBenchmarkResult>,
    /// Memory benchmark result.
    pub memory: Option<MemoryBenchmarkResult>,
    /// Disk benchmark result.
    pub disk: Option<DiskBenchmarkResult>,
    /// Network benchmark result.
    pub network: Option<NetworkBenchmarkResult>,
    /// Compilation benchmark result.
    pub compilation: Option<CompilationBenchmarkResult>,
}

impl BenchmarkResults {
    /// Create a new empty results collection.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set CPU benchmark result.
    pub fn with_cpu(mut self, result: CpuBenchmarkResult) -> Self {
        self.cpu = Some(result);
        self
    }

    /// Set memory benchmark result.
    pub fn with_memory(mut self, result: MemoryBenchmarkResult) -> Self {
        self.memory = Some(result);
        self
    }

    /// Set disk benchmark result.
    pub fn with_disk(mut self, result: DiskBenchmarkResult) -> Self {
        self.disk = Some(result);
        self
    }

    /// Set network benchmark result.
    pub fn with_network(mut self, result: NetworkBenchmarkResult) -> Self {
        self.network = Some(result);
        self
    }

    /// Set compilation benchmark result.
    pub fn with_compilation(mut self, result: CompilationBenchmarkResult) -> Self {
        self.compilation = Some(result);
        self
    }

    /// Check if all benchmark results are present.
    pub fn is_complete(&self) -> bool {
        self.cpu.is_some()
            && self.memory.is_some()
            && self.disk.is_some()
            && self.network.is_some()
            && self.compilation.is_some()
    }

    /// Count how many benchmark results are present.
    pub fn component_count(&self) -> usize {
        let mut count = 0;
        if self.cpu.is_some() {
            count += 1;
        }
        if self.memory.is_some() {
            count += 1;
        }
        if self.disk.is_some() {
            count += 1;
        }
        if self.network.is_some() {
            count += 1;
        }
        if self.compilation.is_some() {
            count += 1;
        }
        count
    }

    /// Preserve raw records for diagnostics, but use only measured evidence for
    /// placement. Zero timings/throughputs are missing, not perfect latency or
    /// failed-machine scores. A partial compound measurement is also excluded.
    fn usable(&self) -> Self {
        Self {
            cpu: self
                .cpu
                .as_ref()
                .filter(|r| positive_finite(r.ops_per_second))
                .cloned(),
            memory: self
                .memory
                .as_ref()
                .filter(|r| {
                    positive_finite(r.seq_bandwidth_gbps) && positive_finite(r.random_latency_ns)
                })
                .cloned(),
            disk: self
                .disk
                .as_ref()
                .filter(|r| {
                    positive_finite(r.seq_read_mbps)
                        && positive_finite(r.seq_write_mbps)
                        && positive_finite(r.random_read_iops)
                })
                .cloned(),
            network: self
                .network
                .as_ref()
                .filter(|r| {
                    positive_finite(r.upload_mbps)
                        && positive_finite(r.download_mbps)
                        && positive_finite(r.latency_ms)
                })
                .cloned(),
            compilation: self
                .compilation
                .as_ref()
                .filter(|r| r.release_build_ms > 0 || positive_finite(r.score))
                .cloned(),
        }
    }
}

// ============================================================================
// Normalization Functions
// ============================================================================

/// Midpoints for the actual benchmark workloads, not advertised hardware limits.
/// At a midpoint the score is 50; doubling throughput (or halving latency)
/// scores 66.7. In particular, the single-thread memory loop is not a measure
/// of aggregate DIMM bandwidth, and the reference crate often builds in <3 s.
mod reference {
    pub const CPU_OPS: f64 = 250_000.0;
    pub const MEMORY_GBPS: f64 = 4.0;
    pub const MEMORY_LATENCY_NS: f64 = 100.0;
    pub const DISK_MBPS: f64 = 1000.0;
    pub const DISK_IOPS: f64 = 100_000.0;
    pub const NETWORK_MBPS: f64 = 1000.0;
    pub const NETWORK_LATENCY_MS: f64 = 10.0;
    pub const COMPILE_MS: f64 = 3000.0;
    pub const COMPILE_SCORE: f64 = 1000.0;
}

fn positive_finite(value: f64) -> bool {
    value.is_finite() && value > 0.0
}

/// Smooth, bounded, monotone normalization. Divide before adding so even a
/// finite f64::MAX measurement cannot overflow a value + reference expression.
fn reference_score(value: f64, midpoint: f64, higher_is_better: bool) -> f64 {
    if !positive_finite(value) || !positive_finite(midpoint) {
        return 0.0;
    }
    let ratio = if higher_is_better {
        midpoint / value
    } else {
        value / midpoint
    };
    100.0 / (1.0 + ratio)
}

/// Normalize a value to 0-100 scale using fixed endpoints.
/// Retained for callers/tests of the endpoint convention, not worker scoring.
#[cfg(test)]
fn normalize(value: f64, low_ref: f64, high_ref: f64, higher_is_better: bool) -> f64 {
    if low_ref == high_ref {
        return 50.0;
    }
    let normalized = if higher_is_better {
        (value - low_ref) / (high_ref - low_ref)
    } else {
        (low_ref - value) / (low_ref - high_ref)
    };
    (normalized * 100.0).clamp(0.0, 100.0)
}

/// Normalize CPU throughput, not the benchmark's differently-scaled composite
/// score (whose matrix term saturated the old 2000-point ceiling everywhere).
fn normalize_cpu(result: &CpuBenchmarkResult) -> f64 {
    reference_score(result.ops_per_second, reference::CPU_OPS, true)
}

fn normalize_memory(result: &MemoryBenchmarkResult) -> f64 {
    reference_score(result.seq_bandwidth_gbps, reference::MEMORY_GBPS, true) * 0.6
        + reference_score(
            result.random_latency_ns,
            reference::MEMORY_LATENCY_NS,
            false,
        ) * 0.4
}

fn normalize_disk(result: &DiskBenchmarkResult) -> f64 {
    let sequential = (reference_score(result.seq_read_mbps, reference::DISK_MBPS, true)
        + reference_score(result.seq_write_mbps, reference::DISK_MBPS, true))
        / 2.0;
    sequential * 0.5 + reference_score(result.random_read_iops, reference::DISK_IOPS, true) * 0.5
}

fn normalize_network(result: &NetworkBenchmarkResult) -> f64 {
    let throughput = (reference_score(result.upload_mbps, reference::NETWORK_MBPS, true)
        + reference_score(result.download_mbps, reference::NETWORK_MBPS, true))
        / 2.0;
    throughput * 0.6
        + reference_score(result.latency_ms, reference::NETWORK_LATENCY_MS, false) * 0.4
}

fn normalize_compilation(result: &CompilationBenchmarkResult) -> f64 {
    if result.release_build_ms == 0 {
        // Debug-only/incremental-only benchmark configurations still supply
        // their measured composite score. A default failure has score == 0
        // and is removed by usable(), rather than taking a share of the total.
        return reference_score(result.score, reference::COMPILE_SCORE, true);
    }
    reference_score(result.release_build_ms as f64, reference::COMPILE_MS, false)
}

/// Normalize only finite, positive weights, without overflowing their sum.
fn normalize_weights(weights: [f64; 5]) -> [f64; 5] {
    let max = weights
        .iter()
        .copied()
        .filter(|w| positive_finite(*w))
        .fold(0.0, f64::max);
    if max == 0.0 {
        return [0.0; 5];
    }
    let scaled = weights.map(|w| if positive_finite(w) { w / max } else { 0.0 });
    let sum: f64 = scaled.iter().sum();
    scaled.map(|w| w / sum)
}

/// Calculate weighted total with adjustment for missing components.
fn calculate_weighted_total(
    cpu_score: f64,
    memory_score: f64,
    disk_score: f64,
    network_score: f64,
    compilation_score: f64,
    weights: &SpeedScoreWeights,
    results: &BenchmarkResults,
) -> (f64, SpeedScoreWeights) {
    let present = [
        results.cpu.is_some(),
        results.memory.is_some(),
        results.disk.is_some(),
        results.network.is_some(),
        results.compilation.is_some(),
    ];
    let mut active = weights.as_array();
    for (weight, present) in active.iter_mut().zip(present) {
        if !present {
            *weight = 0.0;
        }
    }
    let effective = normalize_weights(active);
    let scores = [
        cpu_score,
        memory_score,
        disk_score,
        network_score,
        compilation_score,
    ];
    let total: f64 = scores
        .into_iter()
        .zip(effective)
        .filter(|(_, weight)| *weight > 0.0)
        .map(|(score, weight)| score * weight)
        .sum();
    (
        total.clamp(0.0, 100.0),
        SpeedScoreWeights::from_array(effective),
    )
}

/// Convenience function to calculate SpeedScore from benchmark results.
pub fn calculate_speedscore(results: &BenchmarkResults) -> SpeedScore {
    SpeedScore::calculate(results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use tracing::Level;
    use tracing_subscriber::fmt;

    fn init_test_logging() {
        let _ = fmt()
            .with_max_level(Level::DEBUG)
            .with_test_writer()
            .try_init();
    }

    #[test]
    fn test_normalize_higher_is_better() {
        init_test_logging();
        info!("TEST START: test_normalize_higher_is_better");

        // Value at low ref should be 0
        let score = normalize(100.0, 100.0, 1000.0, true);
        info!("INPUT: value=100, low=100, high=1000, higher_is_better=true");
        info!("RESULT: score = {}", score);
        assert!((score - 0.0).abs() < 0.1);
        info!("VERIFY: Value at low reference = 0");

        // Value at high ref should be 100
        let score = normalize(1000.0, 100.0, 1000.0, true);
        info!("INPUT: value=1000, low=100, high=1000");
        info!("RESULT: score = {}", score);
        assert!((score - 100.0).abs() < 0.1);
        info!("VERIFY: Value at high reference = 100");

        // Value in middle should be ~50
        let score = normalize(550.0, 100.0, 1000.0, true);
        info!("INPUT: value=550, low=100, high=1000");
        info!("RESULT: score = {}", score);
        assert!((score - 50.0).abs() < 0.1);
        info!("VERIFY: Value in middle = 50");

        info!("TEST PASS: test_normalize_higher_is_better");
    }

    #[test]
    fn test_normalize_lower_is_better() {
        init_test_logging();
        info!("TEST START: test_normalize_lower_is_better");

        // Value at high ref (bad) should be 0
        let score = normalize(100.0, 100.0, 10.0, false);
        info!("INPUT: value=100, low=100, high=10, higher_is_better=false");
        info!("RESULT: score = {}", score);
        assert!((score - 0.0).abs() < 0.1);
        info!("VERIFY: Value at bad reference = 0");

        // Value at low ref (good) should be 100
        let score = normalize(10.0, 100.0, 10.0, false);
        info!("INPUT: value=10, low=100, high=10");
        info!("RESULT: score = {}", score);
        assert!((score - 100.0).abs() < 0.1);
        info!("VERIFY: Value at good reference = 100");

        info!("TEST PASS: test_normalize_lower_is_better");
    }

    #[test]
    fn test_normalize_clamps_to_bounds() {
        init_test_logging();
        info!("TEST START: test_normalize_clamps_to_bounds");

        // Value below low ref should clamp to 0
        let score = normalize(50.0, 100.0, 1000.0, true);
        info!("INPUT: value=50 (below low ref 100)");
        info!("RESULT: score = {}", score);
        assert_eq!(score, 0.0);
        info!("VERIFY: Clamped to 0");

        // Value above high ref should clamp to 100
        let score = normalize(2000.0, 100.0, 1000.0, true);
        info!("INPUT: value=2000 (above high ref 1000)");
        info!("RESULT: score = {}", score);
        assert_eq!(score, 100.0);
        info!("VERIFY: Clamped to 100");

        info!("TEST PASS: test_normalize_clamps_to_bounds");
    }

    #[test]
    fn test_normalize_equal_refs_returns_midpoint() {
        init_test_logging();
        info!("TEST START: test_normalize_equal_refs_returns_midpoint");

        let score = normalize(42.0, 10.0, 10.0, true);
        info!("INPUT: value=42, low=10, high=10 (equal refs)");
        info!("RESULT: score = {}", score);

        assert!((score - 50.0).abs() < 0.001);
        info!("VERIFY: Equal refs return midpoint 50");

        info!("TEST PASS: test_normalize_equal_refs_returns_midpoint");
    }

    #[test]
    fn test_speedscore_weights_default() {
        init_test_logging();
        info!("TEST START: test_speedscore_weights_default");

        let weights = SpeedScoreWeights::default();
        info!("INPUT: SpeedScoreWeights::default()");
        info!(
            "RESULT: cpu={}, memory={}, disk={}, network={}, compilation={}",
            weights.cpu, weights.memory, weights.disk, weights.network, weights.compilation
        );

        assert!(weights.is_valid());
        info!("VERIFY: Default weights sum to 1.0");

        assert_eq!(weights.cpu, 0.30);
        assert_eq!(weights.memory, 0.15);
        assert_eq!(weights.disk, 0.20);
        assert_eq!(weights.network, 0.15);
        assert_eq!(weights.compilation, 0.20);

        info!("TEST PASS: test_speedscore_weights_default");
    }

    #[test]
    fn test_speedscore_weights_normalize() {
        init_test_logging();
        info!("TEST START: test_speedscore_weights_normalize");

        let weights = SpeedScoreWeights {
            cpu: 3.0,
            memory: 1.5,
            disk: 2.0,
            network: 1.5,
            compilation: 2.0,
        };
        info!("INPUT: Non-normalized weights (sum = 10.0)");

        let normalized = weights.normalize();
        info!(
            "RESULT: normalized cpu={}, memory={}, disk={}",
            normalized.cpu, normalized.memory, normalized.disk
        );

        assert!(normalized.is_valid());
        assert!((normalized.cpu - 0.30).abs() < 0.001);
        info!("VERIFY: Normalized weights sum to 1.0");

        info!("TEST PASS: test_speedscore_weights_normalize");
    }

    #[test]
    fn test_speedscore_weights_zero_sum_fallback() {
        init_test_logging();
        info!("TEST START: test_speedscore_weights_zero_sum_fallback");

        let weights = SpeedScoreWeights {
            cpu: 0.0,
            memory: 0.0,
            disk: 0.0,
            network: 0.0,
            compilation: 0.0,
        };

        let normalized = weights.normalize();
        info!(
            "RESULT: normalized cpu={}, memory={}, disk={}, network={}, compilation={}",
            normalized.cpu,
            normalized.memory,
            normalized.disk,
            normalized.network,
            normalized.compilation
        );

        assert_eq!(normalized, SpeedScoreWeights::default());
        info!("VERIFY: Zero-sum weights fall back to default");

        info!("TEST PASS: test_speedscore_weights_zero_sum_fallback");
    }

    #[test]
    fn test_benchmark_results_builder() {
        init_test_logging();
        info!("TEST START: test_benchmark_results_builder");

        let results = BenchmarkResults::new()
            .with_cpu(CpuBenchmarkResult::default())
            .with_memory(MemoryBenchmarkResult::default());

        info!("INPUT: BenchmarkResults with CPU and memory, missing disk/network/compilation");
        info!("RESULT: component_count = {}", results.component_count());

        assert!(!results.is_complete());
        assert_eq!(results.component_count(), 2);
        info!("VERIFY: 2 components present, not complete");

        info!("TEST PASS: test_benchmark_results_builder");
    }

    #[test]
    fn test_speedscore_calculation_empty() {
        init_test_logging();
        info!("TEST START: test_speedscore_calculation_empty");

        let results = BenchmarkResults::new();
        let score = SpeedScore::calculate(&results);

        info!("INPUT: Empty BenchmarkResults");
        info!("RESULT: total = {}", score.total);

        assert_eq!(score.total, 0.0);
        assert_eq!(score.version, SPEEDSCORE_VERSION);
        info!("VERIFY: Empty results produce 0 score");

        info!("TEST PASS: test_speedscore_calculation_empty");
    }

    #[test]
    fn test_speedscore_calculation_partial() {
        init_test_logging();
        info!("TEST START: test_speedscore_calculation_partial");

        let cpu_result = CpuBenchmarkResult {
            score: 1000.0, // Reference score
            ops_per_second: 1_000_000.0,
            ..Default::default()
        };

        let results = BenchmarkResults::new().with_cpu(cpu_result);
        let score = SpeedScore::calculate(&results);

        info!("INPUT: BenchmarkResults with only CPU (score=1000, ops=1M)");
        info!(
            "RESULT: total={}, cpu_score={}",
            score.total, score.cpu_score
        );

        assert!(score.total > 0.0);
        assert!(score.cpu_score > 0.0);
        assert_eq!(score.memory_score, 0.0);
        info!("VERIFY: Partial results produce valid score");

        info!("TEST PASS: test_speedscore_calculation_partial");
    }

    #[test]
    fn test_speedscore_single_component_matches_cpu_score() {
        init_test_logging();
        info!("TEST START: test_speedscore_single_component_matches_cpu_score");

        let cpu_result = CpuBenchmarkResult {
            score: 1200.0,
            ops_per_second: 2_000_000.0,
            ..Default::default()
        };

        let results = BenchmarkResults::new().with_cpu(cpu_result);
        let score = SpeedScore::calculate(&results);

        let expected_cpu = normalize_cpu(results.cpu.as_ref().unwrap());
        info!("INPUT: CPU-only results");
        info!(
            "RESULT: total={:.4}, cpu_score={:.4}, expected_cpu={:.4}",
            score.total, score.cpu_score, expected_cpu
        );

        assert!((score.total - expected_cpu).abs() < 0.001);
        info!("VERIFY: Total equals CPU score when only CPU present");

        info!("TEST PASS: test_speedscore_single_component_matches_cpu_score");
    }

    #[test]
    fn test_speedscore_calculation_full() {
        init_test_logging();
        info!("TEST START: test_speedscore_calculation_full");

        let results = BenchmarkResults::new()
            .with_cpu(CpuBenchmarkResult {
                score: 1000.0,
                ops_per_second: 5_000_000.0,
                ..Default::default()
            })
            .with_memory(MemoryBenchmarkResult {
                score: 1000.0,
                seq_bandwidth_gbps: 50.0,
                random_latency_ns: 100.0,
                ..Default::default()
            })
            .with_disk(DiskBenchmarkResult {
                score: 1000.0,
                seq_read_mbps: 2500.0,
                seq_write_mbps: 2000.0,
                random_read_iops: 100_000.0,
                ..Default::default()
            })
            .with_network(NetworkBenchmarkResult {
                score: 75.0,
                upload_mbps: 500.0,
                download_mbps: 800.0,
                latency_ms: 10.0,
                ..Default::default()
            })
            .with_compilation(CompilationBenchmarkResult {
                score: 1000.0,
                release_build_ms: 8000,
                ..Default::default()
            });

        let score = SpeedScore::calculate(&results);

        info!("INPUT: Full BenchmarkResults with all components");
        info!(
            "RESULT: total={:.1}, cpu={:.1}, memory={:.1}, disk={:.1}, network={:.1}, compilation={:.1}",
            score.total,
            score.cpu_score,
            score.memory_score,
            score.disk_score,
            score.network_score,
            score.compilation_score
        );

        assert!(score.total > 0.0 && score.total <= 100.0);
        assert!(score.cpu_score > 0.0);
        assert!(score.memory_score > 0.0);
        assert!(score.disk_score > 0.0);
        assert!(score.network_score > 0.0);
        assert!(score.compilation_score > 0.0);
        info!("VERIFY: All component scores positive and total in range");

        info!("TEST PASS: test_speedscore_calculation_full");
    }

    #[test]
    fn test_speedscore_rating() {
        init_test_logging();
        info!("TEST START: test_speedscore_rating");

        let cases = [
            (95.0, "Excellent"),
            (80.0, "Very Good"),
            (65.0, "Good"),
            (50.0, "Average"),
            (35.0, "Below Average"),
            (20.0, "Poor"),
        ];

        for (total, expected) in cases {
            let score = SpeedScore {
                total,
                ..Default::default()
            };
            assert_eq!(score.rating(), expected);
        }

        info!("VERIFY: All rating thresholds work correctly");
        info!("TEST PASS: test_speedscore_rating");
    }

    #[test]
    fn test_speedscore_serialization() {
        init_test_logging();
        info!("TEST START: test_speedscore_serialization");

        let score = SpeedScore {
            total: 75.5,
            cpu_score: 80.0,
            memory_score: 70.0,
            disk_score: 75.0,
            network_score: 72.0,
            compilation_score: 78.0,
            weights: SpeedScoreWeights::default(),
            calculated_at: Utc::now(),
            version: SPEEDSCORE_VERSION,
            benchmark_conditions: None,
        };

        let json = serde_json::to_string(&score).expect("serialization should succeed");
        info!("RESULT: Serialized to JSON (len={})", json.len());

        let deser: SpeedScore =
            serde_json::from_str(&json).expect("deserialization should succeed");

        assert_eq!(score.total, deser.total);
        assert_eq!(score.cpu_score, deser.cpu_score);
        assert_eq!(score.version, deser.version);
        info!("VERIFY: Serialization roundtrip successful");

        info!("TEST PASS: test_speedscore_serialization");
    }

    #[test]
    fn test_speedscore_outdated() {
        init_test_logging();
        info!("TEST START: test_speedscore_outdated");

        let current = SpeedScore::default();
        assert!(!current.is_outdated());
        info!("VERIFY: Current version not outdated");

        let old = SpeedScore {
            version: 0,
            ..Default::default()
        };
        assert!(old.is_outdated());
        info!("VERIFY: Old version is outdated");

        info!("TEST PASS: test_speedscore_outdated");
    }

    #[test]
    fn test_speedscore_bounds() {
        init_test_logging();
        info!("TEST START: test_speedscore_bounds");

        // Extreme high values should still produce 0-100 score
        let results = BenchmarkResults::new()
            .with_cpu(CpuBenchmarkResult {
                score: 99999.0,
                ops_per_second: 999_999_999.0,
                ..Default::default()
            })
            .with_memory(MemoryBenchmarkResult {
                seq_bandwidth_gbps: 9999.0,
                random_latency_ns: 0.1,
                ..Default::default()
            });

        let score = SpeedScore::calculate(&results);
        info!("INPUT: Extreme high benchmark values");
        info!("RESULT: total={}, cpu={}", score.total, score.cpu_score);

        assert!(score.total >= 0.0 && score.total <= 100.0);
        assert!(score.cpu_score >= 0.0 && score.cpu_score <= 100.0);
        info!("VERIFY: Scores clamped to 0-100 range");

        // Extreme low values
        let results = BenchmarkResults::new().with_cpu(CpuBenchmarkResult {
            score: 0.0,
            ops_per_second: 0.0,
            ..Default::default()
        });

        let score = SpeedScore::calculate(&results);
        info!("INPUT: Extreme low benchmark values");
        info!("RESULT: total={}", score.total);

        assert!(score.total >= 0.0 && score.total <= 100.0);
        info!("VERIFY: Low values still produce valid scores");

        info!("TEST PASS: test_speedscore_bounds");
    }

    #[test]
    fn test_effective_weights_for_missing_components() {
        init_test_logging();
        info!("TEST START: test_effective_weights_for_missing_components");

        let results = BenchmarkResults::new()
            .with_cpu(placeholder_cpu())
            .with_memory(placeholder_memory());

        let weights = SpeedScoreWeights::default();
        let (total, effective) =
            calculate_weighted_total(60.0, 40.0, 10.0, 10.0, 10.0, &weights, &results);

        let active_sum = weights.cpu + weights.memory;
        let expected_cpu = weights.cpu / active_sum;
        let expected_memory = weights.memory / active_sum;

        info!("RESULT: total={:.2}, effective={:?}", total, effective);

        assert!((effective.cpu - expected_cpu).abs() < 0.001);
        assert!((effective.memory - expected_memory).abs() < 0.001);
        assert_eq!(effective.disk, 0.0);
        assert_eq!(effective.network, 0.0);
        assert_eq!(effective.compilation, 0.0);

        info!("VERIFY: Effective weights normalized to present components");
        info!("TEST PASS: test_effective_weights_for_missing_components");
    }

    #[test]
    fn test_compilation_normalize_uses_score_when_release_missing() {
        init_test_logging();
        info!("TEST START: test_compilation_normalize_uses_score_when_release_missing");

        let compilation = CompilationBenchmarkResult {
            score: 1500.0,
            release_build_ms: 0,
            ..Default::default()
        };

        let expected = reference_score(compilation.score, reference::COMPILE_SCORE, true);
        let actual = normalize_compilation(&compilation);

        info!("RESULT: expected={:.4}, actual={:.4}", expected, actual);

        assert!((expected - actual).abs() < 0.001);
        info!("VERIFY: Fallback to score when release_build_ms == 0");

        info!("TEST PASS: test_compilation_normalize_uses_score_when_release_missing");
    }

    #[test]
    fn fleet_cpu_and_sub_three_second_compiles_do_not_saturate() {
        let cpu = |ops| {
            SpeedScore::calculate(&BenchmarkResults::new().with_cpu(CpuBenchmarkResult {
                score: 50_000.0,
                ops_per_second: ops,
                ..Default::default()
            }))
            .cpu_score
        };
        // bd-uerk9: these throughputs previously both scored approximately 70.
        assert!(cpu(423_898.0) - cpu(130_000.0) > 20.0);
        assert!(cpu(423_898.0) < 100.0);

        let compile = |ms| {
            normalize_compilation(&CompilationBenchmarkResult {
                release_build_ms: ms,
                ..Default::default()
            })
        };
        assert!(compile(1836) > compile(2500));
        assert!(compile(2500) > compile(3000));
        assert!(compile(1836) < 100.0);
        assert_eq!(compile(3000), 50.0);
    }

    #[test]
    fn memory_and_fast_disk_measurements_keep_their_ordering() {
        let memory = |bandwidth| {
            normalize_memory(&MemoryBenchmarkResult {
                seq_bandwidth_gbps: bandwidth,
                random_latency_ns: 100.0,
                ..Default::default()
            })
        };
        assert!(memory(4.0) > memory(2.0));
        assert!(memory(2.0) > memory(1.0));

        let disk = |throughput| {
            normalize_disk(&DiskBenchmarkResult {
                seq_read_mbps: throughput,
                seq_write_mbps: throughput,
                random_read_iops: 600_000.0,
                ..Default::default()
            })
        };
        assert!(disk(30_000.0) > disk(15_700.0));
        assert!(disk(15_700.0) > disk(6000.0));
        assert!(disk(30_000.0) < 100.0);
    }

    #[test]
    fn failed_components_do_not_dilute_measured_evidence() {
        let baseline = BenchmarkResults::new().with_cpu(placeholder_cpu());
        let expected = SpeedScore::calculate(&baseline);
        let with_failures = baseline
            .with_memory(MemoryBenchmarkResult::default())
            .with_disk(DiskBenchmarkResult::default())
            .with_network(NetworkBenchmarkResult::default())
            .with_compilation(CompilationBenchmarkResult::default());
        let actual = SpeedScore::calculate(&with_failures);
        assert_eq!(actual.total, expected.total);
        assert_eq!(actual.weights.cpu, 1.0);
        assert_eq!(actual.weights.network, 0.0);
        assert_eq!(actual.weights.compilation, 0.0);
        assert_eq!(actual.network_score, 0.0);
        // Raw diagnostic records are not discarded by calculation.
        assert!(with_failures.is_complete());
    }

    #[test]
    fn malformed_measurements_are_missing_not_nan_or_perfect_scores() {
        for bad in [0.0, -1.0, f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            let results = BenchmarkResults::new()
                .with_cpu(CpuBenchmarkResult {
                    score: 1000.0,
                    ops_per_second: bad,
                    ..Default::default()
                })
                .with_network(NetworkBenchmarkResult {
                    upload_mbps: 500.0,
                    download_mbps: 800.0,
                    latency_ms: bad,
                    ..Default::default()
                });
            let score = SpeedScore::calculate(&results);
            assert_eq!(score.total, 0.0);
            assert_eq!(total_weight_sum(score.weights), 0.0);
            assert!(serde_json::to_string(&score).is_ok());
        }
    }

    #[test]
    fn custom_weights_cannot_overflow_or_turn_negative_evidence_positive() {
        let results = BenchmarkResults::new()
            .with_cpu(placeholder_cpu())
            .with_memory(placeholder_memory());
        let huge = SpeedScoreWeights {
            cpu: f64::MAX,
            memory: f64::MAX,
            disk: f64::NAN,
            network: -1.0,
            compilation: f64::INFINITY,
        };
        assert!(!huge.is_valid());
        assert!(huge.normalize().is_valid());
        let score = SpeedScore::calculate_with_weights(&results, &huge);
        assert!(score.total.is_finite());
        assert_eq!(score.weights.cpu, 0.5);
        assert_eq!(score.weights.memory, 0.5);
        assert_eq!(score.total, (score.cpu_score + score.memory_score) / 2.0);
        let empty =
            SpeedScore::calculate_with_weights(&results, &SpeedScoreWeights::from_array([0.0; 5]));
        assert_eq!(empty.total, 0.0);
        assert_eq!(total_weight_sum(empty.weights), 0.0);
    }

    #[test]
    fn version_one_scores_are_not_comparable_to_current_calibration() {
        let old = SpeedScore {
            version: 1,
            ..Default::default()
        };
        assert!(old.is_outdated());
        assert!(!SpeedScore::calculate(&BenchmarkResults::new()).is_outdated());
    }

    fn total_weight_sum(weights: SpeedScoreWeights) -> f64 {
        weights.cpu + weights.memory + weights.disk + weights.network + weights.compilation
    }

    fn placeholder_cpu() -> CpuBenchmarkResult {
        CpuBenchmarkResult {
            score: 1000.0,
            ops_per_second: 1_000_000.0,
            ..Default::default()
        }
    }

    fn placeholder_memory() -> MemoryBenchmarkResult {
        MemoryBenchmarkResult {
            seq_bandwidth_gbps: 50.0,
            random_latency_ns: 100.0,
            ..Default::default()
        }
    }

    fn placeholder_disk() -> DiskBenchmarkResult {
        DiskBenchmarkResult {
            seq_read_mbps: 2500.0,
            seq_write_mbps: 2000.0,
            random_read_iops: 100_000.0,
            ..Default::default()
        }
    }

    fn placeholder_network() -> NetworkBenchmarkResult {
        NetworkBenchmarkResult {
            upload_mbps: 500.0,
            download_mbps: 800.0,
            latency_ms: 10.0,
            ..Default::default()
        }
    }

    fn placeholder_compilation() -> CompilationBenchmarkResult {
        CompilationBenchmarkResult {
            release_build_ms: 8000,
            score: 1000.0,
            ..Default::default()
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        #[test]
        fn prop_normalize_in_bounds(
            value in -1.0e9f64..1.0e9f64,
            low in -1.0e6f64..1.0e6f64,
            high in -1.0e6f64..1.0e6f64,
            higher_is_better in any::<bool>(),
        ) {
            init_test_logging();
            info!("TEST START: prop_normalize_in_bounds");

            let score = normalize(value, low, high, higher_is_better);

            prop_assert!(score >= 0.0);
            prop_assert!(score <= 100.0);
            info!("TEST PASS: prop_normalize_in_bounds");
        }

        #[test]
        fn prop_reference_score_is_monotone(
            value in 0.001f64..1.0e9f64,
            factor in 1.0f64..10.0f64,
        ) {
            let before = reference_score(value, reference::CPU_OPS, true);
            let after = reference_score(value * factor, reference::CPU_OPS, true);
            prop_assert!(after >= before);
            prop_assert!(after <= 100.0);
            let slower = reference_score(value * factor, reference::COMPILE_MS, false);
            let faster = reference_score(value, reference::COMPILE_MS, false);
            prop_assert!(faster >= slower);
            prop_assert!(slower >= 0.0);
        }

        #[test]
        fn prop_weighted_total_in_bounds(
            cpu_score in 0.0f64..100.0f64,
            memory_score in 0.0f64..100.0f64,
            disk_score in 0.0f64..100.0f64,
            network_score in 0.0f64..100.0f64,
            compilation_score in 0.0f64..100.0f64,
            cpu_present in any::<bool>(),
            memory_present in any::<bool>(),
            disk_present in any::<bool>(),
            network_present in any::<bool>(),
            compilation_present in any::<bool>(),
        ) {
            init_test_logging();
            info!("TEST START: prop_weighted_total_in_bounds");

            let mut results = BenchmarkResults::new();
            if cpu_present {
                results.cpu = Some(placeholder_cpu());
            }
            if memory_present {
                results.memory = Some(placeholder_memory());
            }
            if disk_present {
                results.disk = Some(placeholder_disk());
            }
            if network_present {
                results.network = Some(placeholder_network());
            }
            if compilation_present {
                results.compilation = Some(placeholder_compilation());
            }

            let weights = SpeedScoreWeights::default();
            let (total, effective) = calculate_weighted_total(
                cpu_score,
                memory_score,
                disk_score,
                network_score,
                compilation_score,
                &weights,
                &results,
            );

            prop_assert!(total >= 0.0);
            prop_assert!(total <= 100.0);

            let sum = total_weight_sum(effective);
            let expected_sum = if results.component_count() == 0 { 0.0 } else { 1.0 };
            prop_assert!((sum - expected_sum).abs() < 0.001);
            info!("TEST PASS: prop_weighted_total_in_bounds");
        }
    }
}
