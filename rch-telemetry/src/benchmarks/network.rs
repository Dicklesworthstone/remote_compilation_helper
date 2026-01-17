//! Network benchmark implementation for measuring worker network performance.
//!
//! This module provides a network benchmark that measures actual SSH-based transfer
//! performance between the daemon and remote workers. It tests:
//! - **Upload throughput**: rsync transfer speed to the worker
//! - **Download throughput**: rsync transfer speed from the worker
//! - **SSH latency**: Round-trip time for SSH commands
//!
//! Network performance directly impacts remote compilation time:
//! - Source files and dependencies must be transferred TO the worker
//! - Compiled artifacts (binaries, object files) come back FROM the worker
//! - A worker with excellent CPU but poor network may be slower overall

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::Path;
use std::process::Stdio;
use std::time::Instant;
use tempfile::NamedTempFile;
use tokio::process::Command;
use tracing::{debug, info, trace, warn};

/// Result of a network benchmark run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkBenchmarkResult {
    /// Normalized score (higher = better). Reference baseline = 1000.
    pub score: f64,
    /// Upload throughput in Mbps (megabits per second).
    pub upload_mbps: f64,
    /// Download throughput in Mbps (megabits per second).
    pub download_mbps: f64,
    /// SSH round-trip latency in milliseconds (median).
    pub latency_ms: f64,
    /// Latency jitter (standard deviation) in milliseconds.
    pub jitter_ms: f64,
    /// SSH version string from the remote host.
    pub ssh_version: String,
    /// Total duration of the benchmark in milliseconds.
    pub duration_ms: u64,
    /// Timestamp when the benchmark was taken.
    pub timestamp: DateTime<Utc>,
}

impl Default for NetworkBenchmarkResult {
    fn default() -> Self {
        Self {
            score: 0.0,
            upload_mbps: 0.0,
            download_mbps: 0.0,
            latency_ms: 0.0,
            jitter_ms: 0.0,
            ssh_version: String::new(),
            duration_ms: 0,
            timestamp: Utc::now(),
        }
    }
}

impl NetworkBenchmarkResult {
    /// Calculate normalized network score (0-100).
    ///
    /// Reference points calibrated for 2024-2026 hardware/networks:
    /// - Upload/Download: 10 Mbps = 0, 1 Gbps = 100
    /// - Latency: Lower is better, 1ms = 100, 100ms = 0
    ///
    /// Weights:
    /// - Upload: 35% (source files typically smaller)
    /// - Download: 40% (artifacts often larger)
    /// - Latency: 25% (affects incremental sync operations)
    pub fn calculate_score(&self) -> f64 {
        let upload_score = normalize(self.upload_mbps, 10.0, 1000.0);
        let download_score = normalize(self.download_mbps, 10.0, 1000.0);
        // Latency score: lower is better. 1ms = 100, 100ms = 0
        // Use inverse scoring: 100 - normalized_latency
        let latency_score = if self.latency_ms > 0.0 {
            100.0 - normalize(self.latency_ms, 1.0, 100.0)
        } else {
            100.0 // Zero latency = perfect score
        };

        let score = upload_score * 0.35 + download_score * 0.40 + latency_score * 0.25;
        score.clamp(0.0, 100.0)
    }
}

/// Normalize a value to a 0-100 scale.
fn normalize(value: f64, low: f64, high: f64) -> f64 {
    ((value - low) / (high - low) * 100.0).clamp(0.0, 100.0)
}

/// Worker connection configuration for network benchmarks.
#[derive(Debug, Clone)]
pub struct WorkerConnection {
    /// SSH hostname or IP address.
    pub host: String,
    /// SSH username.
    pub user: String,
    /// Path to SSH private key.
    pub identity_file: String,
    /// Worker identifier (for logging and temp file naming).
    pub worker_id: String,
}

impl WorkerConnection {
    /// Create a new worker connection configuration.
    pub fn new(host: &str, user: &str, identity_file: &str, worker_id: &str) -> Self {
        Self {
            host: host.to_string(),
            user: user.to_string(),
            identity_file: identity_file.to_string(),
            worker_id: worker_id.to_string(),
        }
    }

    /// Get the SSH destination string (user@host).
    pub fn destination(&self) -> String {
        format!("{}@{}", self.user, self.host)
    }
}

/// Network benchmark runner with configurable parameters.
#[derive(Debug, Clone)]
pub struct NetworkBenchmark {
    /// Worker connection details.
    worker: WorkerConnection,
    /// Size of test payload in megabytes.
    pub payload_size_mb: usize,
    /// Number of latency samples to take.
    pub latency_samples: usize,
    /// Timeout for the entire benchmark in seconds.
    pub timeout_secs: u64,
    /// Whether to perform a warmup connection before measurement.
    pub warmup: bool,
}

impl NetworkBenchmark {
    /// Create a new network benchmark for a worker.
    pub fn new(worker: WorkerConnection) -> Self {
        Self {
            worker,
            payload_size_mb: 10,
            latency_samples: 10,
            timeout_secs: 120,
            warmup: true,
        }
    }

    /// Create a benchmark for testing (no actual SSH connection).
    #[cfg(test)]
    pub fn new_for_test(payload_size_mb: usize) -> Self {
        Self {
            worker: WorkerConnection::new("localhost", "test", "/dev/null", "test-worker"),
            payload_size_mb,
            latency_samples: 5,
            timeout_secs: 60,
            warmup: false,
        }
    }

    /// Set the payload size in megabytes.
    #[must_use]
    pub fn with_payload_size_mb(mut self, size: usize) -> Self {
        self.payload_size_mb = size;
        self
    }

    /// Set the number of latency samples.
    #[must_use]
    pub fn with_latency_samples(mut self, samples: usize) -> Self {
        self.latency_samples = samples;
        self
    }

    /// Set the timeout in seconds.
    #[must_use]
    pub fn with_timeout_secs(mut self, timeout: u64) -> Self {
        self.timeout_secs = timeout;
        self
    }

    /// Enable or disable warmup connection.
    #[must_use]
    pub fn with_warmup(mut self, warmup: bool) -> Self {
        self.warmup = warmup;
        self
    }

    /// Run the network benchmark and return results.
    ///
    /// This runs all three network benchmark components:
    /// 1. Upload throughput test (rsync to worker)
    /// 2. Download throughput test (rsync from worker)
    /// 3. Latency test (SSH echo commands)
    pub async fn run(&self) -> Result<NetworkBenchmarkResult, NetworkBenchmarkError> {
        debug!(
            worker = %self.worker.worker_id,
            payload_size_mb = self.payload_size_mb,
            latency_samples = self.latency_samples,
            timeout_secs = self.timeout_secs,
            warmup = self.warmup,
            "Starting network benchmark"
        );

        let start = Instant::now();

        // Warmup: establish connection
        if self.warmup {
            debug!("Running warmup connection");
            self.warmup_connection().await?;
        }

        // Step 1: Generate test payload
        let payload = self.generate_test_payload()?;
        debug!(size_mb = self.payload_size_mb, "Generated test payload");

        // Step 2: Upload test (daemon → worker)
        let upload_mbps = self.measure_upload(payload.path()).await?;
        info!(upload_mbps = %format!("{:.2}", upload_mbps), "Upload test complete");

        // Step 3: Download test (worker → daemon)
        let download_mbps = self.measure_download().await?;
        info!(download_mbps = %format!("{:.2}", download_mbps), "Download test complete");

        // Step 4: Latency test
        let (latency_ms, jitter_ms) = self.measure_latency().await?;
        info!(
            latency_ms = %format!("{:.2}", latency_ms),
            jitter_ms = %format!("{:.2}", jitter_ms),
            "Latency test complete"
        );

        // Get SSH version
        let ssh_version = self.get_ssh_version().await.unwrap_or_default();

        // Cleanup remote temp files
        if let Err(e) = self.cleanup_remote().await {
            warn!("Failed to cleanup remote temp files: {}", e);
        }

        let duration = start.elapsed();
        let duration_ms = duration.as_millis() as u64;

        let mut result = NetworkBenchmarkResult {
            score: 0.0,
            upload_mbps,
            download_mbps,
            latency_ms,
            jitter_ms,
            ssh_version,
            duration_ms,
            timestamp: Utc::now(),
        };

        // Calculate the combined score
        result.score = result.calculate_score();

        debug!(
            score = result.score,
            upload_mbps = result.upload_mbps,
            download_mbps = result.download_mbps,
            latency_ms = result.latency_ms,
            jitter_ms = result.jitter_ms,
            duration_ms = result.duration_ms,
            "Network benchmark completed"
        );

        Ok(result)
    }

    /// Run the benchmark multiple times and return the median result.
    ///
    /// This provides more stable results by:
    /// 1. Running a warmup (if enabled)
    /// 2. Running `runs` benchmark iterations
    /// 3. Returning the median result by score
    pub async fn run_stable(
        &self,
        runs: u32,
    ) -> Result<NetworkBenchmarkResult, NetworkBenchmarkError> {
        if runs == 0 {
            return Ok(NetworkBenchmarkResult::default());
        }

        info!(
            runs,
            worker = %self.worker.worker_id,
            payload_size_mb = self.payload_size_mb,
            "Running stable network benchmark"
        );

        let mut results: Vec<NetworkBenchmarkResult> = Vec::with_capacity(runs as usize);

        for run in 0..runs {
            let result = self.run().await?;
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
            "Stable network benchmark completed"
        );

        Ok(median_result)
    }

    /// Perform a warmup SSH connection to establish the control master.
    async fn warmup_connection(&self) -> Result<(), NetworkBenchmarkError> {
        let output = Command::new("ssh")
            .args(self.ssh_base_args())
            .arg(self.worker.destination())
            .arg("echo")
            .arg("warmup")
            .output()
            .await
            .map_err(|e| {
                NetworkBenchmarkError::SshError(format!("Failed to run SSH warmup: {}", e))
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(NetworkBenchmarkError::ConnectionFailed(format!(
                "SSH warmup failed: {}",
                stderr
            )));
        }

        Ok(())
    }

    /// Generate a test payload file with random data.
    fn generate_test_payload(&self) -> Result<NamedTempFile, NetworkBenchmarkError> {
        let mut file = NamedTempFile::new().map_err(|e| {
            NetworkBenchmarkError::IoError(format!("Failed to create temp file: {}", e))
        })?;

        let size_bytes = self.payload_size_mb * 1024 * 1024;
        let mut rng = fastrand::Rng::new();
        let mut buffer = vec![0u8; 65536]; // 64KB chunks
        let mut written = 0usize;

        while written < size_bytes {
            rng.fill(&mut buffer);
            let to_write = (size_bytes - written).min(buffer.len());
            file.write_all(&buffer[..to_write]).map_err(|e| {
                NetworkBenchmarkError::IoError(format!("Failed to write payload: {}", e))
            })?;
            written += to_write;
        }

        file.flush().map_err(|e| {
            NetworkBenchmarkError::IoError(format!("Failed to flush payload: {}", e))
        })?;

        Ok(file)
    }

    /// Get the base SSH arguments used for all SSH commands.
    fn ssh_base_args(&self) -> Vec<String> {
        let mut args = vec![
            "-o".to_string(),
            "BatchMode=yes".to_string(),
            "-o".to_string(),
            "StrictHostKeyChecking=accept-new".to_string(),
            "-o".to_string(),
            "ConnectTimeout=10".to_string(),
        ];

        // Add identity file if it exists
        let identity_path = shellexpand::tilde(&self.worker.identity_file);
        if Path::new(identity_path.as_ref()).exists() {
            args.push("-i".to_string());
            args.push(identity_path.to_string());
        }

        args
    }

    /// Get the remote temp file path for this benchmark.
    fn remote_temp_path(&self) -> String {
        format!("/tmp/rch_netbench_{}", self.worker.worker_id)
    }

    /// Measure upload throughput via rsync.
    async fn measure_upload(&self, payload_path: &Path) -> Result<f64, NetworkBenchmarkError> {
        let remote_path = self.remote_temp_path();

        let start = Instant::now();

        let output = Command::new("rsync")
            .arg("-e")
            .arg(format!("ssh {}", self.ssh_base_args().join(" ")))
            .arg("--compress-level=0") // No compression for accurate bandwidth measurement
            .arg("--timeout=60")
            .arg(payload_path.to_str().unwrap())
            .arg(format!("{}:{}", self.worker.destination(), remote_path))
            .stderr(Stdio::piped())
            .stdout(Stdio::piped())
            .output()
            .await
            .map_err(|e| {
                NetworkBenchmarkError::RsyncError(format!("Failed to run rsync upload: {}", e))
            })?;

        let duration = start.elapsed();

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(NetworkBenchmarkError::RsyncError(format!(
                "Upload failed: {}",
                stderr
            )));
        }

        // Calculate bandwidth in Mbps
        let bytes = std::fs::metadata(payload_path)
            .map_err(|e| {
                NetworkBenchmarkError::IoError(format!("Failed to get payload size: {}", e))
            })?
            .len() as f64;
        let mbps = (bytes * 8.0) / duration.as_secs_f64() / 1_000_000.0;

        Ok(mbps)
    }

    /// Measure download throughput via rsync.
    async fn measure_download(&self) -> Result<f64, NetworkBenchmarkError> {
        let remote_path = self.remote_temp_path();
        let local_temp = NamedTempFile::new().map_err(|e| {
            NetworkBenchmarkError::IoError(format!("Failed to create temp file: {}", e))
        })?;

        let start = Instant::now();

        let output = Command::new("rsync")
            .arg("-e")
            .arg(format!("ssh {}", self.ssh_base_args().join(" ")))
            .arg("--compress-level=0")
            .arg("--timeout=60")
            .arg(format!("{}:{}", self.worker.destination(), remote_path))
            .arg(local_temp.path().to_str().unwrap())
            .stderr(Stdio::piped())
            .stdout(Stdio::piped())
            .output()
            .await
            .map_err(|e| {
                NetworkBenchmarkError::RsyncError(format!("Failed to run rsync download: {}", e))
            })?;

        let duration = start.elapsed();

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(NetworkBenchmarkError::RsyncError(format!(
                "Download failed: {}",
                stderr
            )));
        }

        // Calculate bandwidth in Mbps
        let bytes = std::fs::metadata(local_temp.path())
            .map_err(|e| {
                NetworkBenchmarkError::IoError(format!("Failed to get downloaded file size: {}", e))
            })?
            .len() as f64;
        let mbps = (bytes * 8.0) / duration.as_secs_f64() / 1_000_000.0;

        Ok(mbps)
    }

    /// Measure SSH latency with multiple samples.
    async fn measure_latency(&self) -> Result<(f64, f64), NetworkBenchmarkError> {
        let mut latencies: Vec<f64> = Vec::with_capacity(self.latency_samples);

        for i in 0..self.latency_samples {
            let start = Instant::now();

            let output = Command::new("ssh")
                .args(self.ssh_base_args())
                .arg(self.worker.destination())
                .arg("echo")
                .arg("ping")
                .output()
                .await
                .map_err(|e| {
                    NetworkBenchmarkError::SshError(format!("Failed to run latency test: {}", e))
                })?;

            let latency = start.elapsed().as_secs_f64() * 1000.0;

            if output.status.success() {
                latencies.push(latency);
                trace!(sample = i, latency_ms = %format!("{:.2}", latency), "Latency sample");
            } else {
                warn!(sample = i, "Latency sample failed");
            }
        }

        if latencies.is_empty() {
            return Err(NetworkBenchmarkError::LatencyTestFailed(
                "All latency samples failed".to_string(),
            ));
        }

        // Calculate median and jitter (standard deviation)
        let (median, jitter) = calculate_latency_stats(&latencies);

        Ok((median, jitter))
    }

    /// Get the SSH version from the remote host.
    async fn get_ssh_version(&self) -> Result<String, NetworkBenchmarkError> {
        let output = Command::new("ssh")
            .args(self.ssh_base_args())
            .arg(self.worker.destination())
            .arg("ssh")
            .arg("-V")
            .stderr(Stdio::piped())
            .stdout(Stdio::piped())
            .output()
            .await
            .map_err(|e| {
                NetworkBenchmarkError::SshError(format!("Failed to get SSH version: {}", e))
            })?;

        // SSH -V typically outputs to stderr
        let version = String::from_utf8_lossy(&output.stderr)
            .lines()
            .next()
            .unwrap_or("")
            .to_string();

        Ok(version)
    }

    /// Cleanup remote temp files.
    async fn cleanup_remote(&self) -> Result<(), NetworkBenchmarkError> {
        let remote_path = self.remote_temp_path();

        let output = Command::new("ssh")
            .args(self.ssh_base_args())
            .arg(self.worker.destination())
            .arg("rm")
            .arg("-f")
            .arg(&remote_path)
            .output()
            .await
            .map_err(|e| {
                NetworkBenchmarkError::SshError(format!("Failed to cleanup remote: {}", e))
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            debug!("Cleanup warning: {}", stderr);
        }

        Ok(())
    }
}

/// Calculate median and standard deviation (jitter) from latency samples.
pub fn calculate_latency_stats(samples: &[f64]) -> (f64, f64) {
    if samples.is_empty() {
        return (0.0, 0.0);
    }

    // Sort for median
    let mut sorted = samples.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let median = sorted[sorted.len() / 2];

    // Calculate jitter (standard deviation)
    let mean = samples.iter().sum::<f64>() / samples.len() as f64;
    let variance = samples.iter().map(|l| (l - mean).powi(2)).sum::<f64>() / samples.len() as f64;
    let jitter = variance.sqrt();

    (median, jitter)
}

/// Errors that can occur during network benchmarking.
#[derive(Debug, thiserror::Error)]
pub enum NetworkBenchmarkError {
    #[error("SSH connection failed: {0}")]
    ConnectionFailed(String),

    #[error("SSH command error: {0}")]
    SshError(String),

    #[error("Rsync transfer error: {0}")]
    RsyncError(String),

    #[error("Latency test failed: {0}")]
    LatencyTestFailed(String),

    #[error("I/O error: {0}")]
    IoError(String),

    #[error("Timeout: benchmark exceeded {0} seconds")]
    Timeout(u64),
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing::Level;
    use tracing_subscriber::fmt;

    fn init_test_logging() {
        let _ = fmt()
            .with_max_level(Level::DEBUG)
            .with_test_writer()
            .try_init();
    }

    #[test]
    fn test_network_score_calculation() {
        init_test_logging();
        info!("TEST START: test_network_score_calculation");

        // High-speed network
        let fast = NetworkBenchmarkResult {
            upload_mbps: 800.0,
            download_mbps: 900.0,
            latency_ms: 5.0,
            jitter_ms: 1.0,
            ssh_version: "OpenSSH_9.0".into(),
            ..Default::default()
        };
        info!("INPUT: Fast network - upload=800Mbps, download=900Mbps, latency=5ms");
        let fast_score = fast.calculate_score();
        info!("RESULT: Score = {}", fast_score);
        assert!(
            fast_score > 65.0,
            "Fast network should score > 65, got {}",
            fast_score
        );
        info!("VERIFY: Fast network scores > 65");

        // Slow network
        let slow = NetworkBenchmarkResult {
            upload_mbps: 50.0,
            download_mbps: 100.0,
            latency_ms: 100.0,
            jitter_ms: 20.0,
            ssh_version: "OpenSSH_9.0".into(),
            ..Default::default()
        };
        info!("INPUT: Slow network - upload=50Mbps, download=100Mbps, latency=100ms");
        let slow_score = slow.calculate_score();
        info!("RESULT: Score = {}", slow_score);
        assert!(
            slow_score < 30.0,
            "Slow network should score < 30, got {}",
            slow_score
        );
        info!("VERIFY: Slow network scores < 30");

        assert!(
            fast_score > slow_score,
            "Fast network should score higher than slow"
        );
        info!("VERIFY: Fast network score > slow network score");
        info!("TEST PASS: test_network_score_calculation");
    }

    #[test]
    fn test_network_score_edge_cases() {
        init_test_logging();
        info!("TEST START: test_network_score_edge_cases");

        // Zero latency should not cause issues
        let zero_latency = NetworkBenchmarkResult {
            upload_mbps: 100.0,
            download_mbps: 100.0,
            latency_ms: 0.0,
            ..Default::default()
        };
        let score = zero_latency.calculate_score();
        assert!(
            score.is_finite(),
            "Zero latency should produce finite score"
        );
        info!("RESULT: Zero latency handled gracefully, score = {}", score);

        // Very high values should clamp to 100
        let extreme = NetworkBenchmarkResult {
            upload_mbps: 10000.0,
            download_mbps: 10000.0,
            latency_ms: 0.1,
            ..Default::default()
        };
        let extreme_score = extreme.calculate_score();
        assert!(extreme_score <= 100.0, "Score should be clamped to 100");
        info!("RESULT: Extreme values clamped, score = {}", extreme_score);

        info!("TEST PASS: test_network_score_edge_cases");
    }

    #[test]
    fn test_latency_statistics() {
        init_test_logging();
        info!("TEST START: test_latency_statistics");

        let samples = vec![10.0, 12.0, 11.0, 15.0, 10.0, 11.0, 12.0, 10.0, 13.0, 11.0];
        info!("INPUT: Latency samples = {:?}", samples);
        let (median, jitter) = calculate_latency_stats(&samples);
        info!("RESULT: median={}ms, jitter={}ms", median, jitter);

        // Sorted: [10, 10, 10, 11, 11, 11, 12, 12, 13, 15]
        // Median (index 5) = 11
        assert!(
            (median - 11.0).abs() < 0.1,
            "Median should be ~11ms, got {}",
            median
        );
        info!("VERIFY: Median ~11ms");

        // Jitter should be reasonable for this dataset
        assert!(
            jitter > 0.0 && jitter < 5.0,
            "Jitter should be small, got {}",
            jitter
        );
        info!("VERIFY: Jitter < 5ms");

        info!("TEST PASS: test_latency_statistics");
    }

    #[test]
    fn test_latency_statistics_empty() {
        init_test_logging();
        info!("TEST START: test_latency_statistics_empty");

        let (median, jitter) = calculate_latency_stats(&[]);
        assert_eq!(median, 0.0);
        assert_eq!(jitter, 0.0);
        info!("RESULT: Empty samples return (0, 0)");

        info!("TEST PASS: test_latency_statistics_empty");
    }

    #[test]
    fn test_latency_statistics_single() {
        init_test_logging();
        info!("TEST START: test_latency_statistics_single");

        let (median, jitter) = calculate_latency_stats(&[42.0]);
        assert_eq!(median, 42.0);
        assert_eq!(jitter, 0.0);
        info!("RESULT: Single sample returns (42, 0)");

        info!("TEST PASS: test_latency_statistics_single");
    }

    #[test]
    fn test_normalize_function() {
        init_test_logging();
        info!("TEST START: test_normalize_function");

        // Value at low end
        assert_eq!(normalize(10.0, 10.0, 100.0), 0.0);
        // Value at high end
        assert_eq!(normalize(100.0, 10.0, 100.0), 100.0);
        // Value in middle
        assert!((normalize(55.0, 10.0, 100.0) - 50.0).abs() < 0.1);
        // Value below low (clamped)
        assert_eq!(normalize(5.0, 10.0, 100.0), 0.0);
        // Value above high (clamped)
        assert_eq!(normalize(200.0, 10.0, 100.0), 100.0);

        info!("TEST PASS: test_normalize_function");
    }

    #[test]
    fn test_worker_connection() {
        init_test_logging();
        info!("TEST START: test_worker_connection");

        let conn = WorkerConnection::new("192.168.1.100", "ubuntu", "~/.ssh/id_rsa", "worker-1");
        assert_eq!(conn.destination(), "ubuntu@192.168.1.100");
        assert_eq!(conn.host, "192.168.1.100");
        assert_eq!(conn.user, "ubuntu");
        assert_eq!(conn.identity_file, "~/.ssh/id_rsa");
        assert_eq!(conn.worker_id, "worker-1");

        info!("TEST PASS: test_worker_connection");
    }

    #[test]
    fn test_benchmark_builder_pattern() {
        init_test_logging();
        info!("TEST START: test_benchmark_builder_pattern");

        let conn = WorkerConnection::new("host", "user", "key", "id");
        let benchmark = NetworkBenchmark::new(conn)
            .with_payload_size_mb(20)
            .with_latency_samples(15)
            .with_timeout_secs(180)
            .with_warmup(false);

        assert_eq!(benchmark.payload_size_mb, 20);
        assert_eq!(benchmark.latency_samples, 15);
        assert_eq!(benchmark.timeout_secs, 180);
        assert!(!benchmark.warmup);

        info!("VERIFY: Builder pattern sets all parameters correctly");
        info!("TEST PASS: test_benchmark_builder_pattern");
    }

    #[test]
    fn test_result_serialization() {
        init_test_logging();
        info!("TEST START: test_result_serialization");

        let result = NetworkBenchmarkResult {
            score: 75.5,
            upload_mbps: 500.0,
            download_mbps: 600.0,
            latency_ms: 10.0,
            jitter_ms: 2.0,
            ssh_version: "OpenSSH_9.0".to_string(),
            duration_ms: 5000,
            timestamp: Utc::now(),
        };

        let json = serde_json::to_string(&result).expect("serialization should succeed");
        info!("RESULT: serialized to JSON (len={})", json.len());

        let deser: NetworkBenchmarkResult =
            serde_json::from_str(&json).expect("deserialization should succeed");

        assert_eq!(result.score, deser.score);
        assert_eq!(result.upload_mbps, deser.upload_mbps);
        assert_eq!(result.download_mbps, deser.download_mbps);
        assert_eq!(result.latency_ms, deser.latency_ms);
        assert_eq!(result.jitter_ms, deser.jitter_ms);
        assert_eq!(result.ssh_version, deser.ssh_version);
        info!("VERIFY: Serialization roundtrip successful");

        info!("TEST PASS: test_result_serialization");
    }

    #[test]
    fn test_payload_generation() {
        init_test_logging();
        info!("TEST START: test_payload_generation");

        let benchmark = NetworkBenchmark::new_for_test(1); // 1 MB
        info!("INPUT: Generate 1MB test payload");
        let payload = benchmark.generate_test_payload().unwrap();
        let size = std::fs::metadata(payload.path()).unwrap().len();
        info!("RESULT: Generated file of {} bytes", size);
        assert_eq!(size, 1 * 1024 * 1024);
        info!("VERIFY: Payload is exactly 1MB");

        info!("TEST PASS: test_payload_generation");
    }

    #[test]
    fn test_payload_generation_large() {
        init_test_logging();
        info!("TEST START: test_payload_generation_large");

        let benchmark = NetworkBenchmark::new_for_test(10); // 10 MB
        info!("INPUT: Generate 10MB test payload");
        let payload = benchmark.generate_test_payload().unwrap();
        let size = std::fs::metadata(payload.path()).unwrap().len();
        info!("RESULT: Generated file of {} bytes", size);
        assert_eq!(size, 10 * 1024 * 1024);
        info!("VERIFY: Payload is exactly 10MB");

        info!("TEST PASS: test_payload_generation_large");
    }

    #[test]
    fn test_result_default() {
        init_test_logging();
        info!("TEST START: test_result_default");

        let result = NetworkBenchmarkResult::default();
        assert_eq!(result.score, 0.0);
        assert_eq!(result.upload_mbps, 0.0);
        assert_eq!(result.download_mbps, 0.0);
        assert_eq!(result.latency_ms, 0.0);
        assert_eq!(result.jitter_ms, 0.0);
        assert!(result.ssh_version.is_empty());

        info!("VERIFY: Default result has all zero values");
        info!("TEST PASS: test_result_default");
    }

    #[test]
    fn test_ssh_base_args() {
        init_test_logging();
        info!("TEST START: test_ssh_base_args");

        let conn = WorkerConnection::new("host", "user", "/nonexistent/key", "id");
        let benchmark = NetworkBenchmark::new(conn);
        let args = benchmark.ssh_base_args();

        // Should contain BatchMode=yes and StrictHostKeyChecking
        assert!(args.contains(&"BatchMode=yes".to_string()));
        assert!(args.contains(&"StrictHostKeyChecking=accept-new".to_string()));
        info!("VERIFY: SSH base args contain required options");

        info!("TEST PASS: test_ssh_base_args");
    }

    #[test]
    fn test_remote_temp_path() {
        init_test_logging();
        info!("TEST START: test_remote_temp_path");

        let conn = WorkerConnection::new("host", "user", "key", "my-worker-42");
        let benchmark = NetworkBenchmark::new(conn);
        let path = benchmark.remote_temp_path();

        assert_eq!(path, "/tmp/rch_netbench_my-worker-42");
        info!("VERIFY: Remote temp path uses worker ID");

        info!("TEST PASS: test_remote_temp_path");
    }

    // Integration test placeholder - requires actual SSH connection
    // This would be run with a real worker in CI or manual testing
    #[tokio::test]
    #[ignore = "Requires real SSH connection to worker"]
    async fn test_network_benchmark_real_worker() {
        init_test_logging();
        info!("TEST START: test_network_benchmark_real_worker");

        // This test requires a real worker configured in the environment
        // Set RCH_TEST_WORKER_HOST, RCH_TEST_WORKER_USER, RCH_TEST_WORKER_KEY
        let host = std::env::var("RCH_TEST_WORKER_HOST").expect("RCH_TEST_WORKER_HOST not set");
        let user = std::env::var("RCH_TEST_WORKER_USER").unwrap_or_else(|_| "ubuntu".to_string());
        let key =
            std::env::var("RCH_TEST_WORKER_KEY").unwrap_or_else(|_| "~/.ssh/id_rsa".to_string());

        let conn = WorkerConnection::new(&host, &user, &key, "test-worker");
        let benchmark = NetworkBenchmark::new(conn)
            .with_payload_size_mb(5)
            .with_latency_samples(5)
            .with_warmup(true);

        info!("INPUT: Running network benchmark against worker '{}'", host);
        let result = benchmark.run().await.unwrap();

        info!(
            "RESULT: upload={}Mbps, download={}Mbps, latency={}ms, jitter={}ms, score={}",
            result.upload_mbps,
            result.download_mbps,
            result.latency_ms,
            result.jitter_ms,
            result.score
        );

        assert!(result.upload_mbps > 0.0);
        assert!(result.download_mbps > 0.0);
        assert!(result.latency_ms > 0.0);
        assert!(result.score >= 0.0 && result.score <= 100.0);

        info!("VERIFY: All metrics positive, score in valid range");
        info!("TEST PASS: test_network_benchmark_real_worker");
    }
}
