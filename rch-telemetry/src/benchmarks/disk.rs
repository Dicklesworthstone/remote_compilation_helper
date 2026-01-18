//! Disk I/O benchmark implementation for measuring worker storage performance.
//!
//! This module provides a pure-Rust disk I/O benchmark that measures:
//! - **Sequential write throughput**: Simulates writing compilation artifacts
//! - **Sequential read throughput**: Simulates reading source files
//! - **Random read IOPS**: Simulates incremental cache lookups
//! - **fsync latency**: Measures durability overhead
//!
//! Disk I/O significantly impacts compilation workloads:
//! - Reading source files and dependencies
//! - Writing incremental compilation caches
//! - Building and linking final binaries
//!
//! Workers with slow disks bottleneck the entire build pipeline.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::time::Instant;
use tempfile::TempDir;
use tracing::{debug, info};

/// Result of a disk I/O benchmark run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskBenchmarkResult {
    /// Normalized score (higher = better). Reference baseline = 1000.
    pub score: f64,
    /// Sequential write throughput in MB/s.
    pub seq_write_mbps: f64,
    /// Sequential read throughput in MB/s.
    pub seq_read_mbps: f64,
    /// Random read IOPS (4KB reads).
    pub random_read_iops: f64,
    /// Average fsync latency in milliseconds.
    pub fsync_latency_ms: f64,
    /// Total duration of the benchmark in milliseconds.
    pub duration_ms: u64,
    /// Timestamp when the benchmark was taken.
    pub timestamp: DateTime<Utc>,
}

impl Default for DiskBenchmarkResult {
    fn default() -> Self {
        Self {
            score: 0.0,
            seq_write_mbps: 0.0,
            seq_read_mbps: 0.0,
            random_read_iops: 0.0,
            fsync_latency_ms: 0.0,
            duration_ms: 0,
            timestamp: Utc::now(),
        }
    }
}

/// Disk I/O benchmark runner with configurable parameters.
#[derive(Debug, Clone)]
pub struct DiskBenchmark {
    /// Size in bytes for sequential write/read tests.
    pub seq_size: usize,
    /// Block size for sequential I/O operations.
    pub block_size: usize,
    /// Number of random 4KB reads to perform.
    pub random_reads: usize,
    /// Size of file for random read test.
    pub random_file_size: usize,
    /// Number of fsync iterations.
    pub fsync_iterations: usize,
    /// Whether to perform a warmup run before measurement.
    pub warmup: bool,
}

impl Default for DiskBenchmark {
    fn default() -> Self {
        Self {
            seq_size: 128 * 1024 * 1024, // 128 MB (reduced from 256 for faster tests)
            block_size: 64 * 1024,       // 64 KB blocks
            random_reads: 5000,          // 5000 random reads
            random_file_size: 64 * 1024 * 1024, // 64 MB file for random reads
            fsync_iterations: 50,        // 50 fsync operations
            warmup: true,
        }
    }
}

impl DiskBenchmark {
    /// Create a new disk benchmark with default settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the size for sequential I/O tests.
    #[must_use]
    pub fn with_seq_size(mut self, size: usize) -> Self {
        self.seq_size = size;
        self
    }

    /// Set the block size for sequential I/O.
    #[must_use]
    pub fn with_block_size(mut self, size: usize) -> Self {
        self.block_size = size;
        self
    }

    /// Set the number of random reads.
    #[must_use]
    pub fn with_random_reads(mut self, reads: usize) -> Self {
        self.random_reads = reads;
        self
    }

    /// Set the random file size.
    #[must_use]
    pub fn with_random_file_size(mut self, size: usize) -> Self {
        self.random_file_size = size;
        self
    }

    /// Set the number of fsync iterations.
    #[must_use]
    pub fn with_fsync_iterations(mut self, iterations: usize) -> Self {
        self.fsync_iterations = iterations;
        self
    }

    /// Enable or disable warmup run.
    #[must_use]
    pub fn with_warmup(mut self, warmup: bool) -> Self {
        self.warmup = warmup;
        self
    }

    /// Run the disk benchmark and return results.
    ///
    /// This creates a temporary directory, runs all benchmark components,
    /// and calculates an overall disk performance score.
    pub fn run(&self) -> DiskBenchmarkResult {
        debug!(
            seq_size = self.seq_size,
            block_size = self.block_size,
            random_reads = self.random_reads,
            random_file_size = self.random_file_size,
            fsync_iterations = self.fsync_iterations,
            warmup = self.warmup,
            "Starting disk benchmark"
        );

        // Create temporary directory for benchmark files
        let temp_dir = match TempDir::new() {
            Ok(dir) => dir,
            Err(e) => {
                debug!(error = %e, "Failed to create temp directory");
                return DiskBenchmarkResult::default();
            }
        };
        let dir = temp_dir.path();

        let start = Instant::now();

        // Warmup run (not counted)
        if self.warmup {
            debug!("Running warmup iteration");
            let _ = sequential_write_benchmark(dir, self.seq_size / 16, self.block_size);
            let _ = sequential_read_benchmark(dir, self.seq_size / 16, self.block_size);
            let _ = random_read_benchmark(dir, self.random_file_size / 8, self.random_reads / 10);
            let _ = fsync_benchmark(dir, self.fsync_iterations / 5);
        }

        // Run individual benchmarks
        let seq_write = sequential_write_benchmark(dir, self.seq_size, self.block_size);
        debug!(seq_write_mbps = seq_write, "Sequential write complete");

        let seq_read = sequential_read_benchmark(dir, self.seq_size, self.block_size);
        debug!(seq_read_mbps = seq_read, "Sequential read complete");

        let random_iops = random_read_benchmark(dir, self.random_file_size, self.random_reads);
        debug!(random_read_iops = random_iops, "Random read complete");

        let fsync_latency = fsync_benchmark(dir, self.fsync_iterations);
        debug!(fsync_latency_ms = fsync_latency, "fsync benchmark complete");

        let duration = start.elapsed();
        let duration_ms = duration.as_millis() as u64;

        // Calculate weighted score
        let score = calculate_disk_score(seq_write, seq_read, random_iops, fsync_latency);

        let result = DiskBenchmarkResult {
            score,
            seq_write_mbps: seq_write,
            seq_read_mbps: seq_read,
            random_read_iops: random_iops,
            fsync_latency_ms: fsync_latency,
            duration_ms,
            timestamp: Utc::now(),
        };

        debug!(
            score = result.score,
            seq_write_mbps = result.seq_write_mbps,
            seq_read_mbps = result.seq_read_mbps,
            random_read_iops = result.random_read_iops,
            fsync_latency_ms = result.fsync_latency_ms,
            duration_ms = result.duration_ms,
            "Disk benchmark completed"
        );

        result
    }

    /// Run the benchmark multiple times and return the median result.
    ///
    /// This provides more stable results by:
    /// 1. Running a warmup (if enabled)
    /// 2. Running `runs` benchmark iterations
    /// 3. Returning the median result by score
    pub fn run_stable(&self, runs: u32) -> DiskBenchmarkResult {
        if runs == 0 {
            return DiskBenchmarkResult::default();
        }

        info!(
            runs,
            seq_size = self.seq_size,
            random_reads = self.random_reads,
            "Running stable disk benchmark"
        );

        let mut results: Vec<DiskBenchmarkResult> = Vec::with_capacity(runs as usize);

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
            "Stable disk benchmark completed"
        );

        median_result
    }
}

/// Calculate the combined disk benchmark score.
///
/// Weights:
/// - Sequential read: 40% (most important for reading source files)
/// - Sequential write: 30% (writing artifacts)
/// - Random read IOPS: 20% (incremental compilation cache)
/// - fsync latency: 10% (durability overhead, lower is better)
fn calculate_disk_score(
    seq_write_mbps: f64,
    seq_read_mbps: f64,
    random_iops: f64,
    fsync_latency_ms: f64,
) -> f64 {
    // Read score: baseline 500 MB/s = 1000 points
    let read_score = seq_read_mbps * 2.0;

    // Write score: baseline 500 MB/s = 1000 points
    let write_score = seq_write_mbps * 2.0;

    // Random IOPS score: baseline 10000 IOPS = 1000 points
    let iops_score = random_iops / 10.0;

    // fsync score: lower is better, baseline 10ms = 1000 points
    // Score = 10000 / latency (so 10ms = 1000, 20ms = 500, 5ms = 2000)
    let fsync_score = if fsync_latency_ms > 0.0 {
        10_000.0 / fsync_latency_ms
    } else {
        0.0
    };

    // Weighted combination
    read_score * 0.4 + write_score * 0.3 + iops_score * 0.2 + fsync_score * 0.1
}

/// Sequential write benchmark: write large file in blocks.
///
/// Returns throughput in MB/s.
pub fn sequential_write_benchmark(dir: &Path, total_size: usize, block_size: usize) -> f64 {
    if total_size == 0 || block_size == 0 {
        return 0.0;
    }

    let path = dir.join("seq_write_test");
    let mut file = match File::create(&path) {
        Ok(f) => f,
        Err(e) => {
            debug!(error = %e, "Failed to create write test file");
            return 0.0;
        }
    };

    // Create block buffer with pattern (not all zeros to avoid sparse file optimization)
    let block: Vec<u8> = (0..block_size).map(|i| (i & 0xFF) as u8).collect();

    let start = Instant::now();
    let mut written = 0;
    while written < total_size {
        let to_write = std::cmp::min(block_size, total_size - written);
        if file.write_all(&block[..to_write]).is_err() {
            break;
        }
        written += to_write;
    }

    // Ensure data is written to disk
    if file.sync_all().is_err() {
        debug!("Failed to sync write test file");
    }
    let duration = start.elapsed();

    // Cleanup
    drop(file);
    let _ = fs::remove_file(&path);

    (written as f64 / 1_048_576.0) / duration.as_secs_f64()
}

/// Sequential read benchmark: read large file in blocks.
///
/// Returns throughput in MB/s.
pub fn sequential_read_benchmark(dir: &Path, total_size: usize, block_size: usize) -> f64 {
    if total_size == 0 || block_size == 0 {
        return 0.0;
    }

    let path = dir.join("seq_read_test");

    // First create the test file
    let test_data: Vec<u8> = (0..total_size).map(|i| (i & 0xFF) as u8).collect();
    if fs::write(&path, &test_data).is_err() {
        debug!("Failed to create read test file");
        return 0.0;
    }

    // Drop the write reference and reopen for reading
    let mut file = match File::open(&path) {
        Ok(f) => f,
        Err(e) => {
            debug!(error = %e, "Failed to open read test file");
            let _ = fs::remove_file(&path);
            return 0.0;
        }
    };

    let mut buffer = vec![0u8; block_size];

    let start = Instant::now();
    let mut total_read = 0;
    loop {
        match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => total_read += n,
            Err(_) => break,
        }
    }
    let duration = start.elapsed();

    // Cleanup
    drop(file);
    let _ = fs::remove_file(&path);

    (total_read as f64 / 1_048_576.0) / duration.as_secs_f64()
}

/// Random read benchmark: 4KB reads at random offsets.
///
/// Returns IOPS (I/O operations per second).
pub fn random_read_benchmark(dir: &Path, file_size: usize, num_reads: usize) -> f64 {
    if file_size < 4096 || num_reads == 0 {
        return 0.0;
    }

    let path = dir.join("random_read_test");

    // Create test file
    let test_data: Vec<u8> = (0..file_size).map(|i| (i & 0xFF) as u8).collect();
    if fs::write(&path, &test_data).is_err() {
        debug!("Failed to create random read test file");
        return 0.0;
    }

    let mut file = match File::open(&path) {
        Ok(f) => f,
        Err(e) => {
            debug!(error = %e, "Failed to open random read test file");
            let _ = fs::remove_file(&path);
            return 0.0;
        }
    };

    let file_size = file_size as u64;
    let mut buffer = [0u8; 4096]; // 4KB reads

    // Generate deterministic random offsets using LCG
    let mut rng_state = 54321u64;
    let max_offset = file_size.saturating_sub(4096);
    let offsets: Vec<u64> = (0..num_reads)
        .map(|_| {
            rng_state = rng_state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            if max_offset > 0 {
                (rng_state % max_offset) & !4095 // Align to 4KB
            } else {
                0
            }
        })
        .collect();

    let start = Instant::now();
    let mut successful_reads = 0;
    for &offset in &offsets {
        if file.seek(SeekFrom::Start(offset)).is_ok() && file.read_exact(&mut buffer).is_ok() {
            successful_reads += 1;
        }
    }
    let duration = start.elapsed();

    // Cleanup
    drop(file);
    let _ = fs::remove_file(&path);

    successful_reads as f64 / duration.as_secs_f64()
}

/// fsync latency benchmark: measure time to durably write small data.
///
/// Returns average latency in milliseconds per fsync.
pub fn fsync_benchmark(dir: &Path, iterations: usize) -> f64 {
    if iterations == 0 {
        return 0.0;
    }

    let path = dir.join("fsync_test");
    let mut file = match OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&path)
    {
        Ok(f) => f,
        Err(e) => {
            debug!(error = %e, "Failed to create fsync test file");
            return 0.0;
        }
    };

    let data = vec![0xDD_u8; 4096]; // 4KB write per fsync

    let start = Instant::now();
    for _ in 0..iterations {
        if file.write_all(&data).is_err() {
            break;
        }
        if file.sync_all().is_err() {
            break;
        }
    }
    let duration = start.elapsed();

    // Cleanup
    drop(file);
    let _ = fs::remove_file(&path);

    (duration.as_secs_f64() * 1000.0) / iterations as f64
}

/// Convenience function to run the default disk benchmark.
pub fn run_disk_benchmark() -> DiskBenchmarkResult {
    DiskBenchmark::default().run()
}

/// Convenience function to run a stable disk benchmark with default settings.
pub fn run_disk_benchmark_stable() -> DiskBenchmarkResult {
    DiskBenchmark::default().run_stable(3)
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
    fn test_sequential_write_throughput() {
        init_test_logging();
        info!("TEST START: test_sequential_write_throughput");

        let temp_dir = TempDir::new().unwrap();
        // Use smaller size for faster test
        info!("INPUT: sequential_write_benchmark() with 16MB file");
        let mbps = sequential_write_benchmark(temp_dir.path(), 16 * 1024 * 1024, 64 * 1024);
        info!("RESULT: Sequential write throughput = {} MB/s", mbps);

        assert!(mbps > 10.0); // At least 10 MB/s
        info!(
            "VERIFY: Write throughput {} MB/s exceeds minimum 10 MB/s",
            mbps
        );

        info!("TEST PASS: test_sequential_write_throughput");
    }

    #[test]
    fn test_sequential_read_throughput() {
        init_test_logging();
        info!("TEST START: test_sequential_read_throughput");

        let temp_dir = TempDir::new().unwrap();
        info!("INPUT: sequential_read_benchmark() with 16MB file");
        let mbps = sequential_read_benchmark(temp_dir.path(), 16 * 1024 * 1024, 64 * 1024);
        info!("RESULT: Sequential read throughput = {} MB/s", mbps);

        assert!(mbps > 10.0); // At least 10 MB/s
        info!("VERIFY: Read throughput {} MB/s exceeds minimum", mbps);

        info!("TEST PASS: test_sequential_read_throughput");
    }

    #[test]
    fn test_random_read_iops() {
        init_test_logging();
        info!("TEST START: test_random_read_iops");

        let temp_dir = TempDir::new().unwrap();
        // Use smaller file and fewer reads for faster test
        info!("INPUT: random_read_benchmark() with 8MB file, 1000 random 4KB reads");
        let iops = random_read_benchmark(temp_dir.path(), 8 * 1024 * 1024, 1000);
        info!("RESULT: Random read IOPS = {}", iops);

        assert!(iops > 100.0); // At least 100 IOPS
        info!("VERIFY: Random IOPS {} exceeds minimum 100", iops);

        info!("TEST PASS: test_random_read_iops");
    }

    #[test]
    fn test_fsync_latency() {
        init_test_logging();
        info!("TEST START: test_fsync_latency");

        let temp_dir = TempDir::new().unwrap();
        info!("INPUT: fsync_benchmark() with 20 iterations");
        let latency_ms = fsync_benchmark(temp_dir.path(), 20);
        info!("RESULT: fsync latency = {} ms", latency_ms);

        assert!(latency_ms > 0.0);
        assert!(latency_ms < 500.0); // Less than 500ms (allow for slow CI)
        info!(
            "VERIFY: fsync latency {} ms within reasonable range",
            latency_ms
        );

        info!("TEST PASS: test_fsync_latency");
    }

    #[test]
    fn test_sequential_write_zero_size() {
        init_test_logging();
        info!("TEST START: test_sequential_write_zero_size");

        let temp_dir = TempDir::new().unwrap();
        let mbps = sequential_write_benchmark(temp_dir.path(), 0, 64 * 1024);
        assert_eq!(mbps, 0.0);
        info!("RESULT: Zero size returns 0.0 MB/s");

        info!("TEST PASS: test_sequential_write_zero_size");
    }

    #[test]
    fn test_sequential_read_zero_size() {
        init_test_logging();
        info!("TEST START: test_sequential_read_zero_size");

        let temp_dir = TempDir::new().unwrap();
        let mbps = sequential_read_benchmark(temp_dir.path(), 0, 64 * 1024);
        assert_eq!(mbps, 0.0);
        info!("RESULT: Zero size returns 0.0 MB/s");

        info!("TEST PASS: test_sequential_read_zero_size");
    }

    #[test]
    fn test_random_read_edge_cases() {
        init_test_logging();
        info!("TEST START: test_random_read_edge_cases");

        let temp_dir = TempDir::new().unwrap();

        // File too small
        assert_eq!(random_read_benchmark(temp_dir.path(), 1000, 100), 0.0);
        // Zero reads
        assert_eq!(random_read_benchmark(temp_dir.path(), 1024 * 1024, 0), 0.0);

        info!("RESULT: Edge cases return 0.0");
        info!("TEST PASS: test_random_read_edge_cases");
    }

    #[test]
    fn test_fsync_zero_iterations() {
        init_test_logging();
        info!("TEST START: test_fsync_zero_iterations");

        let temp_dir = TempDir::new().unwrap();
        let latency = fsync_benchmark(temp_dir.path(), 0);
        assert_eq!(latency, 0.0);
        info!("RESULT: Zero iterations returns 0.0");

        info!("TEST PASS: test_fsync_zero_iterations");
    }

    #[test]
    fn test_disk_benchmark_score() {
        init_test_logging();
        info!("TEST START: test_disk_benchmark_score");

        // Use smaller parameters for faster test
        let benchmark = DiskBenchmark::new()
            .with_seq_size(8 * 1024 * 1024) // 8MB
            .with_block_size(64 * 1024)
            .with_random_reads(500)
            .with_random_file_size(4 * 1024 * 1024) // 4MB
            .with_fsync_iterations(10)
            .with_warmup(false);

        info!("INPUT: run_disk_benchmark() with small parameters");
        let result = benchmark.run();
        info!(
            "RESULT: score={}, write={}MB/s, read={}MB/s, iops={}, fsync={}ms",
            result.score,
            result.seq_write_mbps,
            result.seq_read_mbps,
            result.random_read_iops,
            result.fsync_latency_ms
        );

        assert!(result.score > 0.0);
        info!("VERIFY: Combined score {} is positive", result.score);

        info!("TEST PASS: test_disk_benchmark_score");
    }

    #[test]
    fn test_score_calculation() {
        init_test_logging();
        info!("TEST START: test_score_calculation");

        // Test with known values
        // 500 MB/s write, 500 MB/s read, 10k IOPS, 10ms fsync = ~1000 points each
        let score = calculate_disk_score(500.0, 500.0, 10_000.0, 10.0);
        info!("INPUT: 500MB/s write, 500MB/s read, 10k IOPS, 10ms fsync");
        info!("RESULT: score = {}", score);

        // Expected: 1000*0.3 + 1000*0.4 + 1000*0.2 + 1000*0.1 = 1000
        assert!(score > 900.0 && score < 1100.0);
        info!("VERIFY: Score {} is near expected 1000", score);

        info!("TEST PASS: test_score_calculation");
    }

    #[test]
    fn test_score_calculation_edge_cases() {
        init_test_logging();
        info!("TEST START: test_score_calculation_edge_cases");

        // Zero fsync latency should not cause division by zero
        let score = calculate_disk_score(500.0, 500.0, 10_000.0, 0.0);
        assert!(score.is_finite());
        info!(
            "RESULT: Zero fsync latency handled gracefully, score = {}",
            score
        );

        info!("TEST PASS: test_score_calculation_edge_cases");
    }

    #[test]
    fn test_benchmark_builder_pattern() {
        init_test_logging();
        info!("TEST START: test_benchmark_builder_pattern");

        let benchmark = DiskBenchmark::new()
            .with_seq_size(1024 * 1024)
            .with_block_size(4096)
            .with_random_reads(100)
            .with_random_file_size(512 * 1024)
            .with_fsync_iterations(5)
            .with_warmup(false);

        assert_eq!(benchmark.seq_size, 1024 * 1024);
        assert_eq!(benchmark.block_size, 4096);
        assert_eq!(benchmark.random_reads, 100);
        assert_eq!(benchmark.random_file_size, 512 * 1024);
        assert_eq!(benchmark.fsync_iterations, 5);
        assert!(!benchmark.warmup);

        info!("VERIFY: Builder pattern sets all parameters correctly");
        info!("TEST PASS: test_benchmark_builder_pattern");
    }

    #[test]
    fn test_benchmark_completes_quickly() {
        init_test_logging();
        info!("TEST START: test_benchmark_completes_quickly");

        // Use reduced parameters for reasonable test time
        let benchmark = DiskBenchmark::new()
            .with_seq_size(16 * 1024 * 1024) // 16MB
            .with_block_size(64 * 1024)
            .with_random_reads(1000)
            .with_random_file_size(8 * 1024 * 1024) // 8MB
            .with_fsync_iterations(20)
            .with_warmup(false);

        info!("INPUT: run benchmark with moderate parameters");
        let start = Instant::now();
        let result = benchmark.run();
        let elapsed = start.elapsed();

        info!("RESULT: completed in {:?}, score={}", elapsed, result.score);

        // Should complete in reasonable time
        assert!(elapsed < Duration::from_secs(30));
        info!("VERIFY: Completed in {:?}, under 30s threshold", elapsed);

        info!("TEST PASS: test_benchmark_completes_quickly");
    }

    #[test]
    fn test_stable_benchmark_handles_zero_runs() {
        init_test_logging();
        info!("TEST START: test_stable_benchmark_handles_zero_runs");

        let benchmark = DiskBenchmark::new();
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

        let result = DiskBenchmarkResult {
            score: 1234.5,
            seq_write_mbps: 450.0,
            seq_read_mbps: 550.0,
            random_read_iops: 12000.0,
            fsync_latency_ms: 8.5,
            duration_ms: 5000,
            timestamp: Utc::now(),
        };

        let json = serde_json::to_string(&result).expect("serialization should succeed");
        info!("RESULT: serialized to JSON (len={})", json.len());

        let deser: DiskBenchmarkResult =
            serde_json::from_str(&json).expect("deserialization should succeed");

        assert_eq!(result.score, deser.score);
        assert_eq!(result.seq_write_mbps, deser.seq_write_mbps);
        assert_eq!(result.seq_read_mbps, deser.seq_read_mbps);
        assert_eq!(result.random_read_iops, deser.random_read_iops);
        assert_eq!(result.fsync_latency_ms, deser.fsync_latency_ms);
        info!("VERIFY: Serialization roundtrip successful");

        info!("TEST PASS: test_result_serialization");
    }

    #[test]
    fn test_warmup_runs() {
        init_test_logging();
        info!("TEST START: test_warmup_runs");

        let benchmark_with = DiskBenchmark::new()
            .with_seq_size(4 * 1024 * 1024)
            .with_random_reads(200)
            .with_random_file_size(2 * 1024 * 1024)
            .with_fsync_iterations(5)
            .with_warmup(true);

        let benchmark_without = DiskBenchmark::new()
            .with_seq_size(4 * 1024 * 1024)
            .with_random_reads(200)
            .with_random_file_size(2 * 1024 * 1024)
            .with_fsync_iterations(5)
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
    fn test_cleanup_happens() {
        init_test_logging();
        info!("TEST START: test_cleanup_happens");

        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path();

        // Run benchmarks
        let _ = sequential_write_benchmark(path, 1024 * 1024, 4096);
        let _ = sequential_read_benchmark(path, 1024 * 1024, 4096);
        let _ = random_read_benchmark(path, 1024 * 1024, 100);
        let _ = fsync_benchmark(path, 5);

        // Check that test files were cleaned up
        assert!(!path.join("seq_write_test").exists());
        assert!(!path.join("seq_read_test").exists());
        assert!(!path.join("random_read_test").exists());
        assert!(!path.join("fsync_test").exists());

        info!("VERIFY: All test files were cleaned up");
        info!("TEST PASS: test_cleanup_happens");
    }

    #[test]
    fn test_throughput_scales_with_size() {
        init_test_logging();
        info!("TEST START: test_throughput_scales_with_size");

        let temp_dir = TempDir::new().unwrap();

        let small_write = sequential_write_benchmark(temp_dir.path(), 1024 * 1024, 64 * 1024);
        let large_write = sequential_write_benchmark(temp_dir.path(), 8 * 1024 * 1024, 64 * 1024);

        info!(
            "RESULT: small buffer = {} MB/s, large buffer = {} MB/s",
            small_write, large_write
        );

        // Both should produce valid throughput measurements
        assert!(small_write > 0.0);
        assert!(large_write > 0.0);

        info!("VERIFY: Both sizes produce valid throughput measurements");
        info!("TEST PASS: test_throughput_scales_with_size");
    }

    #[test]
    fn test_benchmark_stability() {
        init_test_logging();
        info!("TEST START: test_benchmark_stability");

        // Use smaller parameters for faster test
        let benchmark = DiskBenchmark::new()
            .with_seq_size(4 * 1024 * 1024) // 4MB
            .with_block_size(64 * 1024)
            .with_random_reads(200)
            .with_random_file_size(2 * 1024 * 1024) // 2MB
            .with_fsync_iterations(5)
            .with_warmup(true);

        info!("INPUT: run_disk_benchmark_stable() (3 runs + warmup)");
        let result = benchmark.run_stable(3);
        info!("RESULT: stable score = {}", result.score);

        // Run again to check variance
        let result2 = benchmark.run_stable(3);
        let variance = if result.score > 0.0 {
            ((result.score - result2.score) / result.score).abs()
        } else {
            0.0
        };
        info!(
            "RESULT: second run score = {}, variance = {:.2}%",
            result2.score,
            variance * 100.0
        );

        // Allow up to 100% variance in tests (CI and concurrent tests can be noisy).
        // Production target is <10% but test environments vary significantly
        // due to concurrent processes, I/O contention, and shared runners.
        assert!(variance < 1.0);
        info!(
            "VERIFY: Benchmark variance {:.2}% is within acceptable range",
            variance * 100.0
        );

        info!("TEST PASS: test_benchmark_stability");
    }
}
