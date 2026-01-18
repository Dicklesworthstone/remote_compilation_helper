//! SpeedScore calculation and normalization engine.
//!
//! This module provides the core SpeedScore calculation that combines individual
//! benchmark results into a unified worker performance score. The SpeedScore
//! enables simple comparison between workers for job assignment.
//!
//! ## Design Philosophy
//!
//! Raw benchmark values vary by orders of magnitude (CPU in ops/sec, disk in MB/s,
//! latency in ms). We normalize everything to a 0-100 scale before weighting,
//! ensuring each component contributes proportionally to the final score.
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
pub const SPEEDSCORE_VERSION: u32 = 1;

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

    /// Weights used for this calculation.
    pub weights: SpeedScoreWeights,

    /// Timestamp when the score was calculated.
    pub calculated_at: DateTime<Utc>,

    /// Algorithm version for cache invalidation.
    pub version: u32,
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
        debug!(
            cpu_present = results.cpu.is_some(),
            memory_present = results.memory.is_some(),
            disk_present = results.disk.is_some(),
            network_present = results.network.is_some(),
            compilation_present = results.compilation.is_some(),
            "Calculating SpeedScore from benchmark results"
        );

        // Normalize each component to 0-100
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

        // Calculate weighted total, adjusting weights for missing components
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
        }
    }

    /// Check if this score is outdated (different algorithm version).
    pub fn is_outdated(&self) -> bool {
        self.version != SPEEDSCORE_VERSION
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

    /// Validate that weights sum to 1.0 (within tolerance).
    pub fn is_valid(&self) -> bool {
        let sum = self.cpu + self.memory + self.disk + self.network + self.compilation;
        (sum - 1.0).abs() < 0.001
    }

    /// Normalize weights to sum to 1.0.
    pub fn normalize(&self) -> Self {
        let sum = self.cpu + self.memory + self.disk + self.network + self.compilation;
        if sum == 0.0 {
            return Self::default();
        }
        Self {
            cpu: self.cpu / sum,
            memory: self.memory / sum,
            disk: self.disk / sum,
            network: self.network / sum,
            compilation: self.compilation / sum,
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
}

// ============================================================================
// Normalization Functions
// ============================================================================

/// Reference points for normalization (calibrated for 2024-2026 hardware).
mod reference {
    // CPU: ops_per_second
    pub const CPU_LOW: f64 = 100_000.0; // Poor (old/slow hardware)
    pub const CPU_HIGH: f64 = 10_000_000.0; // Excellent (fast modern hardware)

    // Memory: bandwidth in GB/s
    pub const MEMORY_LOW: f64 = 5.0; // DDR3 or slow
    pub const MEMORY_HIGH: f64 = 100.0; // DDR5 high-end

    // Disk: sequential throughput in MB/s
    pub const DISK_SEQ_LOW: f64 = 100.0; // HDD
    pub const DISK_SEQ_HIGH: f64 = 5000.0; // NVMe SSD

    // Disk: random IOPS
    pub const DISK_IOPS_LOW: f64 = 1000.0; // HDD
    pub const DISK_IOPS_HIGH: f64 = 500_000.0; // NVMe SSD

    // Network: throughput in Mbps
    pub const NETWORK_LOW: f64 = 100.0; // 100 Mbps
    pub const NETWORK_HIGH: f64 = 10_000.0; // 10 Gbps

    // Network: latency in ms (inverted - lower is better)
    pub const LATENCY_HIGH: f64 = 100.0; // Poor (high latency = low score)
    pub const LATENCY_LOW: f64 = 1.0; // Excellent (low latency = high score)

    // Compilation: release build time in ms (inverted - lower is better)
    pub const COMPILE_SLOW: f64 = 30_000.0; // 30 seconds (slow)
    pub const COMPILE_FAST: f64 = 3_000.0; // 3 seconds (fast)
}

/// Normalize a value to 0-100 scale.
///
/// # Arguments
/// * `value` - The raw benchmark value
/// * `low_ref` - Value that maps to score 0 (poor performance)
/// * `high_ref` - Value that maps to score 100 (excellent performance)
/// * `higher_is_better` - If true, higher values = higher scores
fn normalize(value: f64, low_ref: f64, high_ref: f64, higher_is_better: bool) -> f64 {
    if low_ref == high_ref {
        return 50.0; // Avoid division by zero
    }

    let normalized = if higher_is_better {
        // Higher value = higher score
        // low_ref maps to 0, high_ref maps to 100
        (value - low_ref) / (high_ref - low_ref)
    } else {
        // Lower value = higher score
        // low_ref (the bad high value) maps to 0
        // high_ref (the good low value) maps to 100
        (low_ref - value) / (low_ref - high_ref)
    };

    (normalized * 100.0).clamp(0.0, 100.0)
}

/// Normalize CPU benchmark result to 0-100.
fn normalize_cpu(result: &CpuBenchmarkResult) -> f64 {
    // Use the pre-calculated score and normalize it
    // CPU benchmark score is already designed to be ~1000 for reference hardware
    // Normalize to 0-100: 0 = score 0, 100 = score 2000
    let score_normalized = normalize(result.score, 0.0, 2000.0, true);

    // Also factor in ops_per_second for finer granularity
    let ops_normalized = normalize(
        result.ops_per_second,
        reference::CPU_LOW,
        reference::CPU_HIGH,
        true,
    );

    // Combine: 70% from pre-calculated score, 30% from ops/sec
    score_normalized * 0.7 + ops_normalized * 0.3
}

/// Normalize memory benchmark result to 0-100.
fn normalize_memory(result: &MemoryBenchmarkResult) -> f64 {
    // Bandwidth is the primary metric
    let bandwidth_score = normalize(
        result.seq_bandwidth_gbps,
        reference::MEMORY_LOW,
        reference::MEMORY_HIGH,
        true,
    );

    // Random access latency (lower is better)
    // Typical range: 50ns (excellent) to 200ns (poor)
    let latency_score = normalize(result.random_latency_ns, 200.0, 50.0, false);

    // Combine: 60% bandwidth, 40% latency
    bandwidth_score * 0.6 + latency_score * 0.4
}

/// Normalize disk benchmark result to 0-100.
fn normalize_disk(result: &DiskBenchmarkResult) -> f64 {
    // Sequential read/write average
    let seq_avg = (result.seq_read_mbps + result.seq_write_mbps) / 2.0;
    let seq_score = normalize(
        seq_avg,
        reference::DISK_SEQ_LOW,
        reference::DISK_SEQ_HIGH,
        true,
    );

    // Random IOPS
    let iops_score = normalize(
        result.random_read_iops,
        reference::DISK_IOPS_LOW,
        reference::DISK_IOPS_HIGH,
        true,
    );

    // Combine: 50% sequential, 50% random
    seq_score * 0.5 + iops_score * 0.5
}

/// Normalize network benchmark result to 0-100.
fn normalize_network(result: &NetworkBenchmarkResult) -> f64 {
    // Throughput average (upload + download)
    let throughput_avg = (result.upload_mbps + result.download_mbps) / 2.0;
    let throughput_score = normalize(
        throughput_avg,
        reference::NETWORK_LOW,
        reference::NETWORK_HIGH,
        true,
    );

    // Latency (lower is better)
    let latency_score = normalize(
        result.latency_ms,
        reference::LATENCY_HIGH,
        reference::LATENCY_LOW,
        false,
    );

    // Combine: 60% throughput, 40% latency
    throughput_score * 0.6 + latency_score * 0.4
}

/// Normalize compilation benchmark result to 0-100.
fn normalize_compilation(result: &CompilationBenchmarkResult) -> f64 {
    // Release build time is the primary metric (lower is better)
    if result.release_build_ms == 0 {
        // Use pre-calculated score if no release build data
        return normalize(result.score, 0.0, 2000.0, true);
    }

    // Lower compile time = higher score
    normalize(
        result.release_build_ms as f64,
        reference::COMPILE_SLOW,
        reference::COMPILE_FAST,
        false,
    )
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
    // Collect active weights
    let mut active_weight_sum = 0.0;
    let mut weighted_score_sum = 0.0;

    if results.cpu.is_some() {
        active_weight_sum += weights.cpu;
        weighted_score_sum += cpu_score * weights.cpu;
    }
    if results.memory.is_some() {
        active_weight_sum += weights.memory;
        weighted_score_sum += memory_score * weights.memory;
    }
    if results.disk.is_some() {
        active_weight_sum += weights.disk;
        weighted_score_sum += disk_score * weights.disk;
    }
    if results.network.is_some() {
        active_weight_sum += weights.network;
        weighted_score_sum += network_score * weights.network;
    }
    if results.compilation.is_some() {
        active_weight_sum += weights.compilation;
        weighted_score_sum += compilation_score * weights.compilation;
    }

    // Calculate final score, normalizing by active weight sum
    let total = if active_weight_sum > 0.0 {
        weighted_score_sum / active_weight_sum * 100.0 / 100.0
    } else {
        0.0
    };

    // Return effective weights (normalized to active components)
    let effective_weights = if active_weight_sum > 0.0 {
        SpeedScoreWeights {
            cpu: if results.cpu.is_some() {
                weights.cpu / active_weight_sum
            } else {
                0.0
            },
            memory: if results.memory.is_some() {
                weights.memory / active_weight_sum
            } else {
                0.0
            },
            disk: if results.disk.is_some() {
                weights.disk / active_weight_sum
            } else {
                0.0
            },
            network: if results.network.is_some() {
                weights.network / active_weight_sum
            } else {
                0.0
            },
            compilation: if results.compilation.is_some() {
                weights.compilation / active_weight_sum
            } else {
                0.0
            },
        }
    } else {
        *weights
    };

    (total.clamp(0.0, 100.0), effective_weights)
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
            prop_assert!((sum - 1.0).abs() < 0.001);
            info!("TEST PASS: prop_weighted_total_in_bounds");
        }
    }
}
