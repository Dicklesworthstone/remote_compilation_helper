//! Memory benchmark implementation for measuring worker memory subsystem performance.
//!
//! This module provides a pure-Rust memory benchmark that measures:
//! - **Sequential bandwidth**: Raw memory throughput with large contiguous buffers
//! - **Random access latency**: Cache/memory hierarchy efficiency via pointer chasing
//! - **Allocation throughput**: Allocator performance under load
//!
//! Memory performance significantly impacts compilation workloads:
//! - Large projects allocate gigabytes during compilation
//! - Incremental compilation benefits from fast cache access
//! - Workers with slow memory should be scored lower

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::hint::black_box;
use std::time::Instant;
use tracing::{debug, info};

/// Result of a memory benchmark run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryBenchmarkResult {
    /// Normalized score (higher = better). Reference baseline = 1000.
    pub score: f64,
    /// Sequential read/write bandwidth in GB/s.
    pub seq_bandwidth_gbps: f64,
    /// Random access latency in nanoseconds.
    pub random_latency_ns: f64,
    /// Allocation operations per second.
    pub alloc_ops_per_second: f64,
    /// Total duration of the benchmark in milliseconds.
    pub duration_ms: u64,
    /// Timestamp when the benchmark was taken.
    pub timestamp: DateTime<Utc>,
}

impl Default for MemoryBenchmarkResult {
    fn default() -> Self {
        Self {
            score: 0.0,
            seq_bandwidth_gbps: 0.0,
            random_latency_ns: 0.0,
            alloc_ops_per_second: 0.0,
            duration_ms: 0,
            timestamp: Utc::now(),
        }
    }
}

/// Memory benchmark runner with configurable parameters.
#[derive(Debug, Clone)]
pub struct MemoryBenchmark {
    /// Size of buffer for sequential bandwidth test (bytes).
    pub seq_buffer_size: usize,
    /// Size of buffer for random access test (elements, each 8 bytes).
    pub random_buffer_elements: usize,
    /// Number of iterations for random access benchmark.
    pub random_iterations: usize,
    /// Number of allocation cycles for allocation benchmark.
    pub alloc_iterations: usize,
    /// Whether to perform a warmup run before measurement.
    pub warmup: bool,
}

impl Default for MemoryBenchmark {
    fn default() -> Self {
        Self {
            seq_buffer_size: 256 * 1024 * 1024,      // 256 MB
            random_buffer_elements: 8 * 1024 * 1024, // 64 MB (8M * 8 bytes)
            random_iterations: 10_000_000,
            alloc_iterations: 100_000,
            warmup: true,
        }
    }
}

impl MemoryBenchmark {
    /// Create a new memory benchmark with default settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the buffer size for sequential bandwidth test.
    #[must_use]
    pub fn with_seq_buffer_size(mut self, size: usize) -> Self {
        self.seq_buffer_size = size;
        self
    }

    /// Set the element count for random access test.
    #[must_use]
    pub fn with_random_buffer_elements(mut self, elements: usize) -> Self {
        self.random_buffer_elements = elements;
        self
    }

    /// Set the number of random access iterations.
    #[must_use]
    pub fn with_random_iterations(mut self, iterations: usize) -> Self {
        self.random_iterations = iterations;
        self
    }

    /// Set the number of allocation iterations.
    #[must_use]
    pub fn with_alloc_iterations(mut self, iterations: usize) -> Self {
        self.alloc_iterations = iterations;
        self
    }

    /// Enable or disable warmup run.
    #[must_use]
    pub fn with_warmup(mut self, warmup: bool) -> Self {
        self.warmup = warmup;
        self
    }

    /// Run the memory benchmark and return results.
    ///
    /// This runs all three memory benchmark components and combines
    /// their scores into an overall memory performance score.
    pub fn run(&self) -> MemoryBenchmarkResult {
        debug!(
            seq_buffer_size = self.seq_buffer_size,
            random_buffer_elements = self.random_buffer_elements,
            random_iterations = self.random_iterations,
            alloc_iterations = self.alloc_iterations,
            warmup = self.warmup,
            "Starting memory benchmark"
        );

        let start = Instant::now();

        // Warmup run (not counted)
        if self.warmup {
            debug!("Running warmup iteration");
            let _ = sequential_bandwidth_benchmark(self.seq_buffer_size / 16);
            let _ = random_access_latency_benchmark(
                self.random_buffer_elements / 16,
                self.random_iterations / 100,
            );
            let _ = allocation_benchmark(self.alloc_iterations / 10);
        }

        // Run individual benchmarks
        let seq_bandwidth = sequential_bandwidth_benchmark(self.seq_buffer_size);
        debug!(
            seq_bandwidth_gbps = seq_bandwidth,
            "Sequential bandwidth complete"
        );

        let random_latency =
            random_access_latency_benchmark(self.random_buffer_elements, self.random_iterations);
        debug!(
            random_latency_ns = random_latency,
            "Random access latency complete"
        );

        let alloc_ops = allocation_benchmark(self.alloc_iterations);
        debug!(
            alloc_ops_per_second = alloc_ops,
            "Allocation benchmark complete"
        );

        let duration = start.elapsed();
        let duration_ms = duration.as_millis() as u64;

        // Calculate weighted score
        // Bandwidth most important for compilation (60%)
        // Latency affects incremental builds (25%)
        // Allocation affects many small objects (15%)
        let score = calculate_memory_score(seq_bandwidth, random_latency, alloc_ops);

        let result = MemoryBenchmarkResult {
            score,
            seq_bandwidth_gbps: seq_bandwidth,
            random_latency_ns: random_latency,
            alloc_ops_per_second: alloc_ops,
            duration_ms,
            timestamp: Utc::now(),
        };

        debug!(
            score = result.score,
            seq_bandwidth_gbps = result.seq_bandwidth_gbps,
            random_latency_ns = result.random_latency_ns,
            alloc_ops_per_second = result.alloc_ops_per_second,
            duration_ms = result.duration_ms,
            "Memory benchmark completed"
        );

        result
    }

    /// Run the benchmark multiple times and return the median result.
    ///
    /// This provides more stable results by:
    /// 1. Running a warmup (if enabled)
    /// 2. Running `runs` benchmark iterations
    /// 3. Returning the median result by score
    pub fn run_stable(&self, runs: u32) -> MemoryBenchmarkResult {
        if runs == 0 {
            return MemoryBenchmarkResult::default();
        }

        info!(
            runs,
            seq_buffer_size = self.seq_buffer_size,
            random_buffer_elements = self.random_buffer_elements,
            "Running stable memory benchmark"
        );

        let mut results: Vec<MemoryBenchmarkResult> = Vec::with_capacity(runs as usize);

        for run in 0..runs {
            let result = self.run();
            debug!(
                run = run + 1,
                score = result.score,
                "Benchmark run completed"
            );
            results.push(result);
        }

        // Sort by score and return median
        results.sort_by(|a, b| {
            a.score
                .partial_cmp(&b.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        let median_idx = results.len() / 2;
        let median_result = results.remove(median_idx);

        info!(
            score = median_result.score,
            duration_ms = median_result.duration_ms,
            "Stable memory benchmark completed"
        );

        median_result
    }
}

/// Calculate the combined memory benchmark score.
///
/// Weights:
/// - Sequential bandwidth: 60% (most important for large compilation)
/// - Random latency: 25% (affects incremental builds)
/// - Allocation throughput: 15% (affects many small objects)
fn calculate_memory_score(seq_bandwidth_gbps: f64, random_latency_ns: f64, alloc_ops: f64) -> f64 {
    // Bandwidth score: baseline 10 GB/s = 1000 points
    let bandwidth_score = seq_bandwidth_gbps * 100.0;

    // Latency score: lower is better, baseline 50ns = 1000 points
    // Score = 50000 / latency (so 50ns = 1000, 100ns = 500, 25ns = 2000)
    let latency_score = if random_latency_ns > 0.0 {
        50_000.0 / random_latency_ns
    } else {
        0.0
    };

    // Allocation score: baseline 1M ops/sec = 1000 points
    let alloc_score = alloc_ops / 1000.0;

    // Weighted combination
    bandwidth_score * 0.6 + latency_score * 0.25 + alloc_score * 0.15
}

/// Sequential bandwidth benchmark: read/write large contiguous buffer.
///
/// This benchmark exercises:
/// - Raw memory throughput
/// - Prefetcher effectiveness
/// - Memory controller bandwidth
///
/// Returns bandwidth in GB/s.
pub fn sequential_bandwidth_benchmark(buffer_size: usize) -> f64 {
    if buffer_size == 0 {
        return 0.0;
    }

    // Allocate buffer (this also warms up the pages)
    let mut buffer = vec![0u8; buffer_size];

    let start = Instant::now();

    // Write pass - use pattern that can't be easily optimized away
    for (i, byte) in buffer.iter_mut().enumerate() {
        *byte = (i & 0xFF) as u8;
    }

    // Read pass with dependency chain
    let mut sum = 0u64;
    for byte in buffer.iter() {
        sum = sum.wrapping_add(*byte as u64);
    }

    let duration = start.elapsed();

    // Prevent optimization
    black_box(sum);

    // Calculate bandwidth (read + write = 2x buffer size)
    let bytes_processed = (buffer_size * 2) as f64;
    bytes_processed / duration.as_secs_f64() / 1_000_000_000.0
}

/// Random access latency benchmark: pointer chasing through shuffled array.
///
/// This benchmark exercises:
/// - Cache/memory hierarchy efficiency
/// - TLB performance
/// - Memory latency (not bandwidth)
///
/// Returns average latency per access in nanoseconds.
pub fn random_access_latency_benchmark(buffer_elements: usize, iterations: usize) -> f64 {
    if buffer_elements < 2 || iterations == 0 {
        return 0.0;
    }

    // Create index array and shuffle using Fisher-Yates
    let mut buffer: Vec<usize> = (0..buffer_elements).collect();

    // Simple LCG for deterministic shuffle
    let mut rng_state = 12345u64;
    for i in (1..buffer_elements).rev() {
        rng_state = rng_state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1);
        let j = (rng_state as usize) % (i + 1);
        buffer.swap(i, j);
    }

    // Create pointer chase: chase[buffer[i]] = buffer[i+1]
    let mut chase = vec![0usize; buffer_elements];
    for i in 0..buffer_elements - 1 {
        chase[buffer[i]] = buffer[i + 1];
    }
    chase[buffer[buffer_elements - 1]] = buffer[0]; // Close the loop

    // Measure chase time
    let start = Instant::now();
    let mut idx = 0usize;
    for _ in 0..iterations {
        idx = chase[idx];
    }
    let duration = start.elapsed();

    // Prevent optimization
    black_box(idx);

    // Calculate average latency in nanoseconds
    duration.as_nanos() as f64 / iterations as f64
}

/// Allocation stress benchmark: many allocations of varying sizes.
///
/// This benchmark exercises:
/// - Allocator performance
/// - Memory fragmentation handling
/// - System call overhead (when allocator requests pages)
///
/// Note: Uses safe Rust (Vec/Box) instead of raw alloc/dealloc.
///
/// Returns operations (alloc + use + drop) per second.
pub fn allocation_benchmark(iterations: usize) -> f64 {
    if iterations == 0 {
        return 0.0;
    }

    const SIZES: [usize; 5] = [64, 256, 1024, 4096, 16384];

    let start = Instant::now();

    for i in 0..iterations {
        let size = SIZES[i % SIZES.len()];

        // Allocate, use, and drop
        let mut v: Vec<u8> = Vec::with_capacity(size);
        v.push(0xAA);
        // Vec dropped here
        black_box(v);
    }

    let duration = start.elapsed();

    iterations as f64 / duration.as_secs_f64()
}

/// Convenience function to run the default memory benchmark.
pub fn run_memory_benchmark() -> MemoryBenchmarkResult {
    MemoryBenchmark::default().run()
}

/// Convenience function to run a stable memory benchmark with default settings.
pub fn run_memory_benchmark_stable() -> MemoryBenchmarkResult {
    MemoryBenchmark::default().run_stable(3)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tracing::Level;
    use tracing_subscriber::fmt;

    fn init_test_logging() {
        let _ = fmt()
            .with_max_level(Level::DEBUG)
            .with_test_writer()
            .try_init();
    }

    #[test]
    fn test_sequential_bandwidth_positive() {
        init_test_logging();
        info!("TEST START: test_sequential_bandwidth_positive");

        // Use smaller buffer for faster test
        info!("INPUT: sequential_bandwidth_benchmark() on 16MB buffer");
        let gbps = sequential_bandwidth_benchmark(16 * 1024 * 1024);
        info!("RESULT: Sequential bandwidth = {} GB/s", gbps);

        assert!(gbps > 0.1); // At least 100 MB/s
        info!("VERIFY: Bandwidth {} GB/s exceeds minimum 0.1 GB/s", gbps);

        info!("TEST PASS: test_sequential_bandwidth_positive");
    }

    #[test]
    fn test_sequential_bandwidth_scales_with_size() {
        init_test_logging();
        info!("TEST START: test_sequential_bandwidth_scales_with_size");

        let small = sequential_bandwidth_benchmark(1024 * 1024); // 1 MiB
        let large = sequential_bandwidth_benchmark(16 * 1024 * 1024);

        info!(
            "RESULT: small buffer = {} GB/s, large buffer = {} GB/s",
            small, large
        );

        // Both should produce valid bandwidth measurements
        assert!(small > 0.0);
        assert!(large > 0.0);

        info!("VERIFY: Both sizes produce valid bandwidth measurements");
        info!("TEST PASS: test_sequential_bandwidth_scales_with_size");
    }

    #[test]
    fn test_sequential_bandwidth_zero_size() {
        init_test_logging();
        info!("TEST START: test_sequential_bandwidth_zero_size");

        let gbps = sequential_bandwidth_benchmark(0);
        assert_eq!(gbps, 0.0);
        info!("RESULT: Zero size returns 0.0 GB/s");

        info!("TEST PASS: test_sequential_bandwidth_zero_size");
    }

    #[test]
    fn test_random_latency_reasonable() {
        init_test_logging();
        info!("TEST START: test_random_latency_reasonable");

        // Smaller buffer and fewer iterations for faster test
        info!("INPUT: random_access_latency_benchmark() with 1M element working set");
        let latency_ns = random_access_latency_benchmark(1024 * 1024, 1_000_000);
        info!("RESULT: Random access latency = {} ns", latency_ns);

        assert!(latency_ns > 1.0); // At least 1ns (not optimized away)
        assert!(latency_ns < 10_000.0); // Less than 10us (reasonable for any system)
        info!(
            "VERIFY: Latency {} ns is within reasonable range [1ns, 10000ns]",
            latency_ns
        );

        info!("TEST PASS: test_random_latency_reasonable");
    }

    #[test]
    fn test_random_latency_edge_cases() {
        init_test_logging();
        info!("TEST START: test_random_latency_edge_cases");

        assert_eq!(random_access_latency_benchmark(0, 1000), 0.0);
        assert_eq!(random_access_latency_benchmark(1, 1000), 0.0);
        assert_eq!(random_access_latency_benchmark(1000, 0), 0.0);

        info!("RESULT: Edge cases return 0.0");
        info!("TEST PASS: test_random_latency_edge_cases");
    }

    #[test]
    fn test_allocation_throughput() {
        init_test_logging();
        info!("TEST START: test_allocation_throughput");

        info!("INPUT: allocation_benchmark() with 10k allocations");
        let ops_per_sec = allocation_benchmark(10_000);
        info!("RESULT: Allocation throughput = {} ops/sec", ops_per_sec);

        assert!(ops_per_sec > 1_000.0); // At least 1k allocs/sec
        info!(
            "VERIFY: Throughput {} exceeds minimum 1k ops/sec",
            ops_per_sec
        );

        info!("TEST PASS: test_allocation_throughput");
    }

    #[test]
    fn test_allocation_zero_iterations() {
        init_test_logging();
        info!("TEST START: test_allocation_zero_iterations");

        let ops = allocation_benchmark(0);
        assert_eq!(ops, 0.0);
        info!("RESULT: Zero iterations returns 0.0");

        info!("TEST PASS: test_allocation_zero_iterations");
    }

    #[test]
    fn test_memory_benchmark_score() {
        init_test_logging();
        info!("TEST START: test_memory_benchmark_score");

        // Use smaller parameters for faster test
        let benchmark = MemoryBenchmark::new()
            .with_seq_buffer_size(8 * 1024 * 1024) // 8MB
            .with_random_buffer_elements(256 * 1024) // 2MB
            .with_random_iterations(100_000)
            .with_alloc_iterations(10_000)
            .with_warmup(false);

        info!("INPUT: run_memory_benchmark() with small parameters");
        let result = benchmark.run();
        info!(
            "RESULT: score={}, seq_bw={}GB/s, latency={}ns, alloc={}ops/s",
            result.score,
            result.seq_bandwidth_gbps,
            result.random_latency_ns,
            result.alloc_ops_per_second
        );

        assert!(result.score > 0.0);
        info!("VERIFY: Combined score {} is positive", result.score);

        info!("TEST PASS: test_memory_benchmark_score");
    }

    #[test]
    fn test_score_calculation() {
        init_test_logging();
        info!("TEST START: test_score_calculation");

        // Test with known values
        // 10 GB/s bandwidth, 50ns latency, 1M allocs/sec should = ~1000 points each component
        let score = calculate_memory_score(10.0, 50.0, 1_000_000.0);
        info!("INPUT: 10GB/s bandwidth, 50ns latency, 1M allocs/sec");
        info!("RESULT: score = {}", score);

        // Expected: 1000*0.6 + 1000*0.25 + 1000*0.15 = 1000
        assert!(score > 900.0 && score < 1100.0);
        info!("VERIFY: Score {} is near expected 1000", score);

        info!("TEST PASS: test_score_calculation");
    }

    #[test]
    fn test_score_calculation_edge_cases() {
        init_test_logging();
        info!("TEST START: test_score_calculation_edge_cases");

        // Zero latency should not cause division by zero
        let score = calculate_memory_score(10.0, 0.0, 1_000_000.0);
        assert!(score.is_finite());
        info!("RESULT: Zero latency handled gracefully, score = {}", score);

        info!("TEST PASS: test_score_calculation_edge_cases");
    }

    #[test]
    fn test_benchmark_builder_pattern() {
        init_test_logging();
        info!("TEST START: test_benchmark_builder_pattern");

        let benchmark = MemoryBenchmark::new()
            .with_seq_buffer_size(1024)
            .with_random_buffer_elements(512)
            .with_random_iterations(100)
            .with_alloc_iterations(50)
            .with_warmup(false);

        assert_eq!(benchmark.seq_buffer_size, 1024);
        assert_eq!(benchmark.random_buffer_elements, 512);
        assert_eq!(benchmark.random_iterations, 100);
        assert_eq!(benchmark.alloc_iterations, 50);
        assert!(!benchmark.warmup);

        info!("VERIFY: Builder pattern sets all parameters correctly");
        info!("TEST PASS: test_benchmark_builder_pattern");
    }

    #[test]
    fn test_benchmark_completes_quickly() {
        init_test_logging();
        info!("TEST START: test_benchmark_completes_quickly");

        // Use reduced parameters for reasonable test time
        let benchmark = MemoryBenchmark::new()
            .with_seq_buffer_size(32 * 1024 * 1024) // 32MB
            .with_random_buffer_elements(1024 * 1024) // 8MB
            .with_random_iterations(1_000_000)
            .with_alloc_iterations(10_000)
            .with_warmup(false);

        info!("INPUT: run benchmark with moderate parameters");
        let start = Instant::now();
        let result = benchmark.run();
        let elapsed = start.elapsed();

        info!("RESULT: completed in {:?}, score={}", elapsed, result.score);

        // Should complete in reasonable time (allow more than CPU benchmark)
        assert!(elapsed < Duration::from_secs(30));
        info!("VERIFY: Completed in {:?}, under 30s threshold", elapsed);

        info!("TEST PASS: test_benchmark_completes_quickly");
    }

    #[test]
    fn test_stable_benchmark_handles_zero_runs() {
        init_test_logging();
        info!("TEST START: test_stable_benchmark_handles_zero_runs");

        let benchmark = MemoryBenchmark::new();
        let result = benchmark.run_stable(0);

        assert_eq!(result.score, 0.0);
        assert_eq!(result.duration_ms, 0);
        info!("VERIFY: Zero runs returns default result");

        info!("TEST PASS: test_stable_benchmark_handles_zero_runs");
    }

    #[test]
    fn test_result_serialization() {
        init_test_logging();
        info!("TEST START: test_result_serialization");

        let result = MemoryBenchmarkResult {
            score: 1234.5,
            seq_bandwidth_gbps: 15.5,
            random_latency_ns: 45.2,
            alloc_ops_per_second: 1_500_000.0,
            duration_ms: 3500,
            timestamp: Utc::now(),
        };

        let json = serde_json::to_string(&result).expect("serialization should succeed");
        info!("RESULT: serialized to JSON (len={})", json.len());

        let deser: MemoryBenchmarkResult =
            serde_json::from_str(&json).expect("deserialization should succeed");

        assert_eq!(result.score, deser.score);
        assert_eq!(result.seq_bandwidth_gbps, deser.seq_bandwidth_gbps);
        assert_eq!(result.random_latency_ns, deser.random_latency_ns);
        info!("VERIFY: Serialization roundtrip successful");

        info!("TEST PASS: test_result_serialization");
    }

    #[test]
    fn test_warmup_runs() {
        init_test_logging();
        info!("TEST START: test_warmup_runs");

        let benchmark_with = MemoryBenchmark::new()
            .with_seq_buffer_size(4 * 1024 * 1024)
            .with_random_buffer_elements(128 * 1024)
            .with_random_iterations(50_000)
            .with_alloc_iterations(5_000)
            .with_warmup(true);

        let benchmark_without = MemoryBenchmark::new()
            .with_seq_buffer_size(4 * 1024 * 1024)
            .with_random_buffer_elements(128 * 1024)
            .with_random_iterations(50_000)
            .with_alloc_iterations(5_000)
            .with_warmup(false);

        let result_with = benchmark_with.run();
        let result_without = benchmark_without.run();

        // Both should produce valid results
        assert!(result_with.score > 0.0);
        assert!(result_without.score > 0.0);

        info!(
            "RESULT: with_warmup score={}, without_warmup score={}",
            result_with.score, result_without.score
        );
        info!("VERIFY: Both configurations produce valid results");

        info!("TEST PASS: test_warmup_runs");
    }

    #[test]
    fn test_pointer_chase_deterministic() {
        init_test_logging();
        info!("TEST START: test_pointer_chase_deterministic");

        // Same parameters should produce same (or very similar) results
        let latency1 = random_access_latency_benchmark(10_000, 100_000);
        let latency2 = random_access_latency_benchmark(10_000, 100_000);

        info!(
            "RESULT: run1 latency = {} ns, run2 latency = {} ns",
            latency1, latency2
        );

        // Allow some variance due to system noise, but should be close
        let ratio = if latency1 > latency2 {
            latency1 / latency2
        } else {
            latency2 / latency1
        };

        assert!(ratio < 2.0); // Within 2x of each other
        info!(
            "VERIFY: Latency ratio {} is within acceptable variance",
            ratio
        );

        info!("TEST PASS: test_pointer_chase_deterministic");
    }
}
