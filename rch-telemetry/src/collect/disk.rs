//! Disk I/O metrics collection from /proc/diskstats.
//!
//! Reads Linux /proc/diskstats to track I/O throughput, latency indicators,
//! and utilization for worker health monitoring.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Instant;
use thiserror::Error;
use tracing::{debug, warn};

/// Errors that can occur during disk metrics collection.
#[derive(Error, Debug)]
pub enum DiskError {
    #[error("failed to read /proc/diskstats: {0}")]
    ReadError(#[from] std::io::Error),

    #[error("failed to parse /proc/diskstats: {0}")]
    ParseError(String),

    #[error("device '{0}' not found in stats")]
    DeviceNotFound(String),
}

/// Raw disk statistics parsed from /proc/diskstats.
///
/// Fields correspond to kernel documentation:
/// <https://www.kernel.org/doc/Documentation/ABI/testing/procfs-diskstats>
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DiskStats {
    /// Device name (e.g., "sda", "nvme0n1").
    pub device: String,
    /// Number of reads completed.
    pub reads_completed: u64,
    /// Number of reads merged.
    pub reads_merged: u64,
    /// Number of sectors read.
    pub sectors_read: u64,
    /// Time spent reading (ms).
    pub time_reading_ms: u64,
    /// Number of writes completed.
    pub writes_completed: u64,
    /// Number of writes merged.
    pub writes_merged: u64,
    /// Number of sectors written.
    pub sectors_written: u64,
    /// Time spent writing (ms).
    pub time_writing_ms: u64,
    /// I/O operations currently in progress.
    pub io_in_progress: u64,
    /// Time spent doing I/O (ms).
    pub time_io_ms: u64,
    /// Weighted time spent doing I/O (ms).
    pub weighted_time_io_ms: u64,
    /// Timestamp when stats were read.
    #[serde(skip)]
    pub timestamp: Option<Instant>,
}

impl DiskStats {
    /// Read disk statistics from /proc/diskstats.
    pub fn read_from_proc() -> Result<HashMap<String, Self>, DiskError> {
        let content = std::fs::read_to_string("/proc/diskstats")?;
        Self::parse(&content)
    }

    /// Parse /proc/diskstats content.
    ///
    /// Format (kernel 4.18+):
    /// ```text
    /// major minor name rd_ios rd_merges rd_sectors rd_ticks wr_ios wr_merges wr_sectors wr_ticks in_flight io_ticks time_in_queue
    /// ```
    pub fn parse(content: &str) -> Result<HashMap<String, Self>, DiskError> {
        let timestamp = Instant::now();
        let mut devices = HashMap::new();

        for line in content.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 14 {
                continue; // Skip malformed lines or partitions with minimal stats
            }

            let device = parts[2].to_string();

            // Skip partitions (e.g., sda1) if we have the whole disk (sda)
            // We want whole disks or nvme namespaces, not partitions
            if device
                .chars()
                .last()
                .map(|c| c.is_ascii_digit())
                .unwrap_or(false)
                && !device.starts_with("nvme")
                && !device.starts_with("loop")
            {
                // This is likely a partition (sda1, sdb2, etc.) - skip
                continue;
            }

            // Skip loop devices
            if device.starts_with("loop") {
                continue;
            }

            let stats = Self {
                device: device.clone(),
                reads_completed: parts[3].parse().unwrap_or(0),
                reads_merged: parts[4].parse().unwrap_or(0),
                sectors_read: parts[5].parse().unwrap_or(0),
                time_reading_ms: parts[6].parse().unwrap_or(0),
                writes_completed: parts[7].parse().unwrap_or(0),
                writes_merged: parts[8].parse().unwrap_or(0),
                sectors_written: parts[9].parse().unwrap_or(0),
                time_writing_ms: parts[10].parse().unwrap_or(0),
                io_in_progress: parts[11].parse().unwrap_or(0),
                time_io_ms: parts[12].parse().unwrap_or(0),
                weighted_time_io_ms: parts[13].parse().unwrap_or(0),
                timestamp: Some(timestamp),
            };

            devices.insert(device, stats);
        }

        Ok(devices)
    }

    /// Calculate total bytes read (sectors are 512 bytes each).
    pub fn bytes_read(&self) -> u64 {
        self.sectors_read * 512
    }

    /// Calculate total bytes written.
    pub fn bytes_written(&self) -> u64 {
        self.sectors_written * 512
    }
}

/// Derived disk metrics calculated from delta between two snapshots.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DiskMetrics {
    /// Device name.
    pub device: String,
    /// Read throughput in MB/s.
    pub read_throughput_mbps: f64,
    /// Write throughput in MB/s.
    pub write_throughput_mbps: f64,
    /// I/O utilization percentage (0-100).
    /// Time spent doing I/O as percentage of elapsed time.
    pub io_utilization_pct: f64,
    /// Average queue depth (weighted time / active time).
    pub avg_queue_depth: f64,
    /// Average read latency in ms (if reads occurred).
    pub read_latency_ms: Option<f64>,
    /// Average write latency in ms (if writes occurred).
    pub write_latency_ms: Option<f64>,
    /// Total IOPS (reads + writes per second).
    pub iops: f64,
}

impl DiskMetrics {
    /// Calculate derived metrics from two snapshots.
    pub fn from_delta(prev: &DiskStats, curr: &DiskStats, elapsed_ms: u64) -> Self {
        if elapsed_ms == 0 {
            return Self {
                device: curr.device.clone(),
                ..Default::default()
            };
        }

        let elapsed_secs = elapsed_ms as f64 / 1000.0;

        // Throughput: bytes delta / elapsed time
        let bytes_read_delta = curr.bytes_read().saturating_sub(prev.bytes_read());
        let bytes_written_delta = curr.bytes_written().saturating_sub(prev.bytes_written());

        let read_throughput_mbps = (bytes_read_delta as f64 / 1_048_576.0) / elapsed_secs;
        let write_throughput_mbps = (bytes_written_delta as f64 / 1_048_576.0) / elapsed_secs;

        // I/O utilization: time spent doing I/O as percentage of elapsed time
        let time_io_delta = curr.time_io_ms.saturating_sub(prev.time_io_ms);
        let io_utilization_pct = (time_io_delta as f64 / elapsed_ms as f64) * 100.0;

        // Average queue depth: weighted time / active time
        let weighted_time_delta = curr
            .weighted_time_io_ms
            .saturating_sub(prev.weighted_time_io_ms);
        let avg_queue_depth = if time_io_delta > 0 {
            weighted_time_delta as f64 / time_io_delta as f64
        } else {
            0.0
        };

        // Read latency: time spent reading / number of reads
        let reads_delta = curr.reads_completed.saturating_sub(prev.reads_completed);
        let time_reading_delta = curr.time_reading_ms.saturating_sub(prev.time_reading_ms);
        let read_latency_ms = if reads_delta > 0 {
            Some(time_reading_delta as f64 / reads_delta as f64)
        } else {
            None
        };

        // Write latency: time spent writing / number of writes
        let writes_delta = curr.writes_completed.saturating_sub(prev.writes_completed);
        let time_writing_delta = curr.time_writing_ms.saturating_sub(prev.time_writing_ms);
        let write_latency_ms = if writes_delta > 0 {
            Some(time_writing_delta as f64 / writes_delta as f64)
        } else {
            None
        };

        // Total IOPS
        let total_ios = reads_delta + writes_delta;
        let iops = total_ios as f64 / elapsed_secs;

        Self {
            device: curr.device.clone(),
            read_throughput_mbps,
            write_throughput_mbps,
            io_utilization_pct: io_utilization_pct.min(100.0),
            avg_queue_depth,
            read_latency_ms,
            write_latency_ms,
            iops,
        }
    }
}

/// File descriptor statistics from /proc/sys/fs/file-nr.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FileDescriptorStats {
    /// Number of allocated file descriptors.
    pub allocated: u64,
    /// Maximum number of file descriptors.
    pub max: u64,
    /// Percentage of file descriptors in use.
    pub used_pct: f64,
}

impl FileDescriptorStats {
    /// Read file descriptor statistics from /proc/sys/fs/file-nr.
    pub fn read_from_proc() -> Result<Self, DiskError> {
        let content = std::fs::read_to_string("/proc/sys/fs/file-nr")?;
        Self::parse(&content)
    }

    /// Parse /proc/sys/fs/file-nr content.
    ///
    /// Format: `allocated  free  max`
    /// Note: 'free' is always 0 on modern kernels (unused).
    pub fn parse(content: &str) -> Result<Self, DiskError> {
        let parts: Vec<&str> = content.split_whitespace().collect();
        if parts.len() < 3 {
            return Err(DiskError::ParseError(
                "file-nr has fewer than 3 fields".to_string(),
            ));
        }

        let allocated: u64 = parts[0]
            .parse()
            .map_err(|_| DiskError::ParseError("invalid allocated count".to_string()))?;
        let max: u64 = parts[2]
            .parse()
            .map_err(|_| DiskError::ParseError("invalid max count".to_string()))?;

        let used_pct = if max > 0 {
            (allocated as f64 / max as f64) * 100.0
        } else {
            0.0
        };

        Ok(Self {
            allocated,
            max,
            used_pct,
        })
    }
}

/// Aggregated disk telemetry snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskTelemetry {
    /// Timestamp of the telemetry collection.
    pub timestamp: DateTime<Utc>,
    /// Per-device metrics.
    pub devices: Vec<DiskMetrics>,
    /// Aggregated read throughput across all devices (MB/s).
    pub total_read_throughput_mbps: f64,
    /// Aggregated write throughput across all devices (MB/s).
    pub total_write_throughput_mbps: f64,
    /// Maximum I/O utilization across all devices.
    pub max_io_utilization_pct: f64,
    /// File descriptor statistics.
    pub fd_stats: Option<FileDescriptorStats>,
}

impl DiskTelemetry {
    /// Create telemetry from device metrics.
    pub fn from_metrics(devices: Vec<DiskMetrics>, fd_stats: Option<FileDescriptorStats>) -> Self {
        let total_read_throughput_mbps: f64 = devices.iter().map(|d| d.read_throughput_mbps).sum();
        let total_write_throughput_mbps: f64 =
            devices.iter().map(|d| d.write_throughput_mbps).sum();
        let max_io_utilization_pct = devices
            .iter()
            .map(|d| d.io_utilization_pct)
            .fold(0.0_f64, |a, b| a.max(b));

        let telemetry = Self {
            timestamp: Utc::now(),
            devices,
            total_read_throughput_mbps,
            total_write_throughput_mbps,
            max_io_utilization_pct,
            fd_stats,
        };

        debug!(
            read_mbps = %telemetry.total_read_throughput_mbps,
            write_mbps = %telemetry.total_write_throughput_mbps,
            max_util_pct = %telemetry.max_io_utilization_pct,
            device_count = %telemetry.devices.len(),
            "Disk telemetry collected"
        );

        // Warn on high I/O utilization
        if telemetry.max_io_utilization_pct > 80.0 {
            warn!(
                utilization = %telemetry.max_io_utilization_pct,
                "Worker disk I/O saturated"
            );
        }

        // Warn on high file descriptor usage
        if let Some(ref fd) = telemetry.fd_stats
            && fd.used_pct > 80.0
        {
            warn!(
                fd_used_pct = %fd.used_pct,
                fd_allocated = fd.allocated,
                "High file descriptor usage"
            );
        }

        telemetry
    }
}

/// Collector that maintains state for delta calculations.
pub struct DiskCollector {
    /// Previous snapshot for delta calculation.
    prev_stats: Option<HashMap<String, DiskStats>>,
    /// Timestamp of previous snapshot.
    prev_timestamp: Option<Instant>,
}

impl Default for DiskCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl DiskCollector {
    /// Create a new disk collector.
    pub fn new() -> Self {
        Self {
            prev_stats: None,
            prev_timestamp: None,
        }
    }

    /// Collect disk telemetry.
    ///
    /// On first call, only initializes state and returns empty metrics.
    /// Subsequent calls calculate deltas from previous snapshot.
    pub fn collect(&mut self) -> Result<Option<DiskTelemetry>, DiskError> {
        let curr_stats = DiskStats::read_from_proc()?;
        let curr_timestamp = Instant::now();
        let fd_stats = FileDescriptorStats::read_from_proc().ok();

        let result = if let (Some(prev_stats), Some(prev_timestamp)) =
            (&self.prev_stats, self.prev_timestamp)
        {
            let elapsed_ms = curr_timestamp.duration_since(prev_timestamp).as_millis() as u64;

            let mut device_metrics = Vec::new();
            for (device, curr) in &curr_stats {
                if let Some(prev) = prev_stats.get(device) {
                    let metrics = DiskMetrics::from_delta(prev, curr, elapsed_ms);
                    device_metrics.push(metrics);
                }
            }

            Some(DiskTelemetry::from_metrics(device_metrics, fd_stats))
        } else {
            // First call - no previous data to calculate delta
            debug!("Disk collector initialized, first sample collected");
            None
        };

        // Store current as previous for next collection
        self.prev_stats = Some(curr_stats);
        self.prev_timestamp = Some(curr_timestamp);

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing::info;
    use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

    fn init_test_logging() {
        let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("debug"));
        let _ = tracing_subscriber::registry()
            .with(
                fmt::layer()
                    .with_test_writer()
                    .with_target(true)
                    .with_file(true)
                    .with_line_number(true)
                    .with_thread_ids(true)
                    .json(),
            )
            .with(filter)
            .try_init();
    }

    #[test]
    fn test_parse_proc_diskstats() {
        init_test_logging();
        info!("TEST START: test_parse_proc_diskstats");

        let sample = r#"   8       0 sda 12345 6789 1000000 50000 5432 2100 500000 25000 0 30000 75000 0 0 0 0
   8       1 sda1 10000 5000 800000 40000 4000 1800 400000 20000 0 25000 60000 0 0 0 0
 259       0 nvme0n1 50000 0 2000000 100000 30000 0 1500000 80000 2 120000 180000 0 0 0 0"#;

        info!("INPUT: sample /proc/diskstats with 3 devices");

        let stats = DiskStats::parse(sample).expect("parsing should succeed");

        info!(
            device_count = stats.len(),
            devices = ?stats.keys().collect::<Vec<_>>(),
            "RESULT: parsed disk stats"
        );

        // Should have sda and nvme0n1 (sda1 is a partition, should be skipped)
        assert!(stats.contains_key("sda"));
        assert!(stats.contains_key("nvme0n1"));
        assert!(!stats.contains_key("sda1")); // Partition should be skipped

        let sda = stats.get("sda").unwrap();
        assert_eq!(sda.reads_completed, 12345);
        assert_eq!(sda.sectors_read, 1000000);
        assert_eq!(sda.time_io_ms, 30000);

        let nvme = stats.get("nvme0n1").unwrap();
        assert_eq!(nvme.reads_completed, 50000);
        assert_eq!(nvme.io_in_progress, 2);

        info!("TEST PASS: test_parse_proc_diskstats");
    }

    #[test]
    fn test_parse_diskstats_with_loop_devices() {
        init_test_logging();
        info!("TEST START: test_parse_diskstats_with_loop_devices");

        let sample = r#"   8       0 sda 12345 6789 1000000 50000 5432 2100 500000 25000 0 30000 75000 0 0 0 0
   7       0 loop0 100 0 200 10 0 0 0 0 0 5 5 0 0 0 0
   7       1 loop1 50 0 100 5 0 0 0 0 0 2 2 0 0 0 0"#;

        info!("INPUT: sample with loop devices");

        let stats = DiskStats::parse(sample).expect("parsing should succeed");

        info!(device_count = stats.len(), "RESULT: parsed disk stats");

        // Loop devices should be skipped
        assert!(stats.contains_key("sda"));
        assert!(!stats.contains_key("loop0"));
        assert!(!stats.contains_key("loop1"));

        info!("TEST PASS: test_parse_diskstats_with_loop_devices");
    }

    #[test]
    fn test_bytes_calculation() {
        init_test_logging();
        info!("TEST START: test_bytes_calculation");

        let stats = DiskStats {
            device: "sda".to_string(),
            sectors_read: 2048,    // 2048 * 512 = 1 MB
            sectors_written: 4096, // 4096 * 512 = 2 MB
            ..Default::default()
        };

        info!(
            sectors_read = stats.sectors_read,
            sectors_written = stats.sectors_written,
            "INPUT: disk stats"
        );

        let bytes_read = stats.bytes_read();
        let bytes_written = stats.bytes_written();

        info!(
            bytes_read = bytes_read,
            bytes_written = bytes_written,
            "RESULT: calculated bytes"
        );

        assert_eq!(bytes_read, 1_048_576); // 1 MB
        assert_eq!(bytes_written, 2_097_152); // 2 MB

        info!("TEST PASS: test_bytes_calculation");
    }

    #[test]
    fn test_metrics_from_delta() {
        init_test_logging();
        info!("TEST START: test_metrics_from_delta");

        let prev = DiskStats {
            device: "sda".to_string(),
            reads_completed: 1000,
            sectors_read: 100_000,
            time_reading_ms: 5000,
            writes_completed: 500,
            sectors_written: 50_000,
            time_writing_ms: 2500,
            time_io_ms: 6000,
            weighted_time_io_ms: 12000,
            ..Default::default()
        };

        let curr = DiskStats {
            device: "sda".to_string(),
            reads_completed: 1100,      // +100 reads
            sectors_read: 200_000,      // +100,000 sectors = 51.2 MB
            time_reading_ms: 5500,      // +500ms = 5ms/read
            writes_completed: 550,      // +50 writes
            sectors_written: 60_000,    // +10,000 sectors = 5.12 MB
            time_writing_ms: 2750,      // +250ms = 5ms/write
            time_io_ms: 7000,           // +1000ms
            weighted_time_io_ms: 14000, // +2000ms
            ..Default::default()
        };

        let elapsed_ms = 1000; // 1 second

        info!(
            elapsed_ms = elapsed_ms,
            reads_delta = 100,
            sectors_read_delta = 100000,
            "INPUT: stats delta over 1 second"
        );

        let metrics = DiskMetrics::from_delta(&prev, &curr, elapsed_ms);

        info!(
            read_mbps = metrics.read_throughput_mbps,
            write_mbps = metrics.write_throughput_mbps,
            io_util_pct = metrics.io_utilization_pct,
            queue_depth = metrics.avg_queue_depth,
            read_latency_ms = ?metrics.read_latency_ms,
            write_latency_ms = ?metrics.write_latency_ms,
            iops = metrics.iops,
            "RESULT: calculated metrics"
        );

        // Read throughput: 100,000 sectors * 512 bytes / 1 second / 1MB = ~48.8 MB/s
        assert!(
            (metrics.read_throughput_mbps - 48.828125).abs() < 0.1,
            "read throughput mismatch: {}",
            metrics.read_throughput_mbps
        );

        // Write throughput: 10,000 sectors * 512 bytes / 1 second / 1MB = ~4.88 MB/s
        assert!(
            (metrics.write_throughput_mbps - 4.8828125).abs() < 0.1,
            "write throughput mismatch: {}",
            metrics.write_throughput_mbps
        );

        // I/O utilization: 1000ms / 1000ms * 100 = 100%
        assert!(
            (metrics.io_utilization_pct - 100.0).abs() < 0.1,
            "io utilization mismatch: {}",
            metrics.io_utilization_pct
        );

        // Queue depth: 2000ms / 1000ms = 2.0
        assert!(
            (metrics.avg_queue_depth - 2.0).abs() < 0.1,
            "queue depth mismatch: {}",
            metrics.avg_queue_depth
        );

        // Read latency: 500ms / 100 reads = 5ms
        assert_eq!(metrics.read_latency_ms, Some(5.0));

        // Write latency: 250ms / 50 writes = 5ms
        assert_eq!(metrics.write_latency_ms, Some(5.0));

        // IOPS: (100 + 50) / 1 = 150
        assert!(
            (metrics.iops - 150.0).abs() < 0.1,
            "iops mismatch: {}",
            metrics.iops
        );

        info!("TEST PASS: test_metrics_from_delta");
    }

    #[test]
    fn test_metrics_zero_elapsed() {
        init_test_logging();
        info!("TEST START: test_metrics_zero_elapsed");

        let stats = DiskStats {
            device: "sda".to_string(),
            ..Default::default()
        };

        info!("INPUT: zero elapsed time");

        let metrics = DiskMetrics::from_delta(&stats, &stats, 0);

        info!(
            read_mbps = metrics.read_throughput_mbps,
            "RESULT: metrics with zero elapsed"
        );

        // Should return zeros without panic (division by zero protection)
        assert_eq!(metrics.read_throughput_mbps, 0.0);
        assert_eq!(metrics.write_throughput_mbps, 0.0);
        assert_eq!(metrics.io_utilization_pct, 0.0);

        info!("TEST PASS: test_metrics_zero_elapsed");
    }

    #[test]
    fn test_metrics_no_io() {
        init_test_logging();
        info!("TEST START: test_metrics_no_io");

        let prev = DiskStats {
            device: "sda".to_string(),
            reads_completed: 100,
            writes_completed: 50,
            ..Default::default()
        };

        // No change in I/O counts
        let curr = prev.clone();
        let elapsed_ms = 1000;

        info!("INPUT: no I/O activity in interval");

        let metrics = DiskMetrics::from_delta(&prev, &curr, elapsed_ms);

        info!(
            read_latency = ?metrics.read_latency_ms,
            write_latency = ?metrics.write_latency_ms,
            "RESULT: latency should be None with no I/O"
        );

        // With no reads/writes, latency should be None
        assert_eq!(metrics.read_latency_ms, None);
        assert_eq!(metrics.write_latency_ms, None);

        info!("TEST PASS: test_metrics_no_io");
    }

    #[test]
    fn test_parse_file_nr() {
        init_test_logging();
        info!("TEST START: test_parse_file_nr");

        let sample = "12345\t0\t9223372036854775807\n";

        info!("INPUT: sample file-nr content");

        let fd = FileDescriptorStats::parse(sample).expect("parsing should succeed");

        info!(
            allocated = fd.allocated,
            max = fd.max,
            used_pct = fd.used_pct,
            "RESULT: parsed file descriptor stats"
        );

        assert_eq!(fd.allocated, 12345);
        assert_eq!(fd.max, 9223372036854775807);
        assert!(fd.used_pct < 0.001); // Extremely small percentage

        info!("TEST PASS: test_parse_file_nr");
    }

    #[test]
    fn test_parse_file_nr_high_usage() {
        init_test_logging();
        info!("TEST START: test_parse_file_nr_high_usage");

        let sample = "80000\t0\t100000\n";

        info!("INPUT: high fd usage (80%)");

        let fd = FileDescriptorStats::parse(sample).expect("parsing should succeed");

        info!(
            allocated = fd.allocated,
            max = fd.max,
            used_pct = fd.used_pct,
            "RESULT: parsed file descriptor stats"
        );

        assert_eq!(fd.allocated, 80000);
        assert_eq!(fd.max, 100000);
        assert!((fd.used_pct - 80.0).abs() < 0.1);

        info!("TEST PASS: test_parse_file_nr_high_usage");
    }

    #[test]
    fn test_parse_file_nr_malformed() {
        init_test_logging();
        info!("TEST START: test_parse_file_nr_malformed");

        let sample = "12345\t0\n"; // Missing max field

        info!("INPUT: malformed file-nr");

        let result = FileDescriptorStats::parse(sample);

        assert!(result.is_err());
        info!("RESULT: got expected error");

        info!("TEST PASS: test_parse_file_nr_malformed");
    }

    #[test]
    fn test_telemetry_aggregation() {
        init_test_logging();
        info!("TEST START: test_telemetry_aggregation");

        let metrics = vec![
            DiskMetrics {
                device: "sda".to_string(),
                read_throughput_mbps: 100.0,
                write_throughput_mbps: 50.0,
                io_utilization_pct: 80.0,
                avg_queue_depth: 2.0,
                read_latency_ms: Some(5.0),
                write_latency_ms: Some(3.0),
                iops: 5000.0,
            },
            DiskMetrics {
                device: "sdb".to_string(),
                read_throughput_mbps: 200.0,
                write_throughput_mbps: 100.0,
                io_utilization_pct: 60.0,
                avg_queue_depth: 1.5,
                read_latency_ms: Some(3.0),
                write_latency_ms: Some(2.0),
                iops: 8000.0,
            },
        ];

        info!("INPUT: metrics from 2 devices");

        let telemetry = DiskTelemetry::from_metrics(metrics, None);

        info!(
            total_read_mbps = telemetry.total_read_throughput_mbps,
            total_write_mbps = telemetry.total_write_throughput_mbps,
            max_util_pct = telemetry.max_io_utilization_pct,
            "RESULT: aggregated telemetry"
        );

        // Total read: 100 + 200 = 300 MB/s
        assert!((telemetry.total_read_throughput_mbps - 300.0).abs() < 0.1);

        // Total write: 50 + 100 = 150 MB/s
        assert!((telemetry.total_write_throughput_mbps - 150.0).abs() < 0.1);

        // Max utilization: max(80, 60) = 80%
        assert!((telemetry.max_io_utilization_pct - 80.0).abs() < 0.1);

        info!("TEST PASS: test_telemetry_aggregation");
    }

    #[test]
    fn test_io_utilization_capped_at_100() {
        init_test_logging();
        info!("TEST START: test_io_utilization_capped_at_100");

        let prev = DiskStats {
            device: "sda".to_string(),
            time_io_ms: 0,
            ..Default::default()
        };

        let curr = DiskStats {
            device: "sda".to_string(),
            time_io_ms: 2000, // 2000ms of I/O in 1000ms elapsed = 200%
            ..Default::default()
        };

        let metrics = DiskMetrics::from_delta(&prev, &curr, 1000);

        info!(
            io_util_pct = metrics.io_utilization_pct,
            "RESULT: I/O utilization should be capped"
        );

        // Should be capped at 100%
        assert!((metrics.io_utilization_pct - 100.0).abs() < 0.01);

        info!("TEST PASS: test_io_utilization_capped_at_100");
    }

    #[test]
    fn test_serialization_roundtrip() {
        init_test_logging();
        info!("TEST START: test_serialization_roundtrip");

        let stats = DiskStats {
            device: "sda".to_string(),
            reads_completed: 12345,
            reads_merged: 6789,
            sectors_read: 1000000,
            time_reading_ms: 50000,
            writes_completed: 5432,
            writes_merged: 2100,
            sectors_written: 500000,
            time_writing_ms: 25000,
            io_in_progress: 5,
            time_io_ms: 30000,
            weighted_time_io_ms: 75000,
            timestamp: None,
        };

        let json = serde_json::to_string(&stats).expect("serialization should succeed");
        info!(json_len = json.len(), "RESULT: serialized to JSON");

        let deser: DiskStats = serde_json::from_str(&json).expect("deserialization should succeed");

        assert_eq!(stats.device, deser.device);
        assert_eq!(stats.reads_completed, deser.reads_completed);
        assert_eq!(stats.sectors_written, deser.sectors_written);

        info!("TEST PASS: test_serialization_roundtrip");
    }
}
