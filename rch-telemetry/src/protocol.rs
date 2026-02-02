//! Telemetry protocol structures for worker-daemon communication.
//!
//! This module defines the wire format for transmitting telemetry data from
//! workers to the daemon via SSH (piggyback or poll).

use chrono::{DateTime, Utc};
use rch_common::CompilationKind;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::collect::cpu::CpuTelemetry;
use crate::collect::disk::DiskTelemetry;
use crate::collect::memory::MemoryTelemetry;
use crate::collect::network::NetworkTelemetry;

/// Protocol version for telemetry format compatibility.
pub const TELEMETRY_PROTOCOL_VERSION: u32 = 1;

/// Marker used to identify telemetry data piggybacked with build output.
pub const PIGGYBACK_MARKER: &str = "---RCH-TELEMETRY---";

/// Unified telemetry snapshot from a worker.
///
/// Combines CPU, memory, disk, and network metrics into a single payload
/// for transmission to the daemon.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerTelemetry {
    /// Protocol version for format compatibility.
    pub version: u32,
    /// Unique identifier for the worker.
    pub worker_id: String,
    /// Timestamp when telemetry was collected.
    pub timestamp: DateTime<Utc>,
    /// CPU telemetry (utilization, load average, PSI).
    pub cpu: CpuTelemetry,
    /// Memory telemetry (usage, pressure, swap).
    pub memory: MemoryTelemetry,
    /// Disk telemetry (throughput, utilization, file descriptors).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disk: Option<DiskTelemetry>,
    /// Network telemetry (throughput, errors, drops).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<NetworkTelemetry>,
    /// Collection duration in milliseconds.
    pub collection_duration_ms: u64,
}

impl WorkerTelemetry {
    /// Create a new telemetry payload.
    pub fn new(
        worker_id: String,
        cpu: CpuTelemetry,
        memory: MemoryTelemetry,
        disk: Option<DiskTelemetry>,
        network: Option<NetworkTelemetry>,
        collection_duration_ms: u64,
    ) -> Self {
        Self {
            version: TELEMETRY_PROTOCOL_VERSION,
            worker_id,
            timestamp: Utc::now(),
            cpu,
            memory,
            disk,
            network,
            collection_duration_ms,
        }
    }

    /// Serialize to JSON for transmission.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Serialize to pretty JSON (for debugging).
    pub fn to_json_pretty(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Deserialize from JSON.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Format as piggybacked output (for embedding in build job responses).
    pub fn to_piggyback(&self) -> Result<String, serde_json::Error> {
        Ok(format!("{}\n{}", PIGGYBACK_MARKER, self.to_json()?))
    }

    /// Check if this telemetry is compatible with the current protocol version.
    pub fn is_compatible(&self) -> bool {
        self.version == TELEMETRY_PROTOCOL_VERSION
    }

    /// Get a summary of the telemetry for logging.
    pub fn summary(&self) -> TelemetrySummary {
        TelemetrySummary {
            worker_id: self.worker_id.clone(),
            timestamp: self.timestamp,
            cpu_percent: self.cpu.overall_percent,
            memory_percent: self.memory.used_percent,
            memory_pressure: self.memory.pressure_score,
            disk_io_percent: self.disk.as_ref().map(|d| d.max_io_utilization_pct),
            network_throughput_mbps: self.network.as_ref().map(|n| n.total_throughput_mbps),
            load_1m: self.cpu.load_average.one_min,
        }
    }
}

/// Compact summary of telemetry for logging and quick inspection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetrySummary {
    pub worker_id: String,
    pub timestamp: DateTime<Utc>,
    pub cpu_percent: f64,
    pub memory_percent: f64,
    pub memory_pressure: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disk_io_percent: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_throughput_mbps: Option<f64>,
    pub load_1m: f64,
}

impl std::fmt::Display for TelemetrySummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[{}] CPU: {:.1}%, Mem: {:.1}% (pressure: {:.1}), Load: {:.2}",
            self.worker_id,
            self.cpu_percent,
            self.memory_percent,
            self.memory_pressure,
            self.load_1m,
        )?;

        if let Some(disk) = self.disk_io_percent {
            write!(f, ", Disk I/O: {:.1}%", disk)?;
        }
        if let Some(net) = self.network_throughput_mbps {
            write!(f, ", Net: {:.1} Mbps", net)?;
        }

        Ok(())
    }
}

/// Record of a completed test run for telemetry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestRunRecord {
    /// Project identifier.
    pub project_id: String,
    /// Worker identifier that executed the test.
    pub worker_id: String,
    /// Full command executed.
    pub command: String,
    /// Classification kind label (e.g., cargo_test, cargo_nextest).
    pub kind: String,
    /// Exit code from the test run.
    pub exit_code: i32,
    /// Duration in milliseconds.
    pub duration_ms: u64,
    /// When the test run completed.
    pub completed_at: DateTime<Utc>,
}

impl TestRunRecord {
    /// Create a new test run record from a compilation kind.
    pub fn new(
        project_id: String,
        worker_id: String,
        command: String,
        kind: CompilationKind,
        exit_code: i32,
        duration_ms: u64,
    ) -> Self {
        Self {
            project_id,
            worker_id,
            command,
            kind: compilation_kind_label(kind),
            exit_code,
            duration_ms,
            completed_at: Utc::now(),
        }
    }

    /// Serialize to JSON for transmission.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Deserialize from JSON.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
}

/// Aggregate stats for recent test runs.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TestRunStats {
    pub total_runs: u64,
    pub passed_runs: u64,
    pub failed_runs: u64,
    pub build_error_runs: u64,
    pub avg_duration_ms: u64,
    #[serde(default)]
    pub runs_by_kind: HashMap<String, u64>,
}

impl TestRunStats {
    /// Add a test run record into the aggregate stats.
    pub fn record(&mut self, record: &TestRunRecord) {
        let total_duration =
            self.avg_duration_ms.saturating_mul(self.total_runs) + record.duration_ms;
        self.total_runs = self.total_runs.saturating_add(1);
        self.avg_duration_ms = total_duration / self.total_runs;

        match record.exit_code {
            0 => self.passed_runs = self.passed_runs.saturating_add(1),
            101 => self.failed_runs = self.failed_runs.saturating_add(1),
            1 => self.build_error_runs = self.build_error_runs.saturating_add(1),
            _ => self.failed_runs = self.failed_runs.saturating_add(1),
        }

        *self.runs_by_kind.entry(record.kind.clone()).or_insert(0) += 1;
    }
}

fn compilation_kind_label(kind: CompilationKind) -> String {
    serde_json::to_value(kind)
        .ok()
        .and_then(|value| value.as_str().map(|s| s.to_string()))
        .unwrap_or_else(|| format!("{:?}", kind))
}

/// Result of extracting piggybacked telemetry from build output.
#[derive(Debug, Clone)]
pub struct PiggybackExtraction {
    /// The build output with telemetry marker removed.
    pub build_output: String,
    /// The extracted telemetry, if present and valid.
    pub telemetry: Option<WorkerTelemetry>,
    /// Error message if telemetry extraction failed.
    pub extraction_error: Option<String>,
}

/// Extract piggybacked telemetry from build job output.
///
/// Looks for the telemetry marker and parses the JSON following it.
/// Returns the clean build output and the extracted telemetry.
pub fn extract_piggybacked_telemetry(output: &str) -> PiggybackExtraction {
    if let Some(marker_pos) = output.rfind(PIGGYBACK_MARKER) {
        let build_output = output[..marker_pos].trim_end().to_string();
        let telemetry_start = marker_pos + PIGGYBACK_MARKER.len();
        let telemetry_json = output[telemetry_start..].trim();

        match WorkerTelemetry::from_json(telemetry_json) {
            Ok(telemetry) => PiggybackExtraction {
                build_output,
                telemetry: Some(telemetry),
                extraction_error: None,
            },
            Err(e) => PiggybackExtraction {
                build_output,
                telemetry: None,
                extraction_error: Some(format!("Failed to parse telemetry: {}", e)),
            },
        }
    } else {
        // No telemetry marker found
        PiggybackExtraction {
            build_output: output.to_string(),
            telemetry: None,
            extraction_error: None,
        }
    }
}

/// Telemetry transmission status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TelemetrySource {
    /// Telemetry received via piggyback with build job response.
    Piggyback,
    /// Telemetry fetched via dedicated SSH poll.
    SshPoll,
    /// Telemetry requested on-demand (manual refresh).
    OnDemand,
}

impl std::fmt::Display for TelemetrySource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TelemetrySource::Piggyback => write!(f, "piggyback"),
            TelemetrySource::SshPoll => write!(f, "ssh-poll"),
            TelemetrySource::OnDemand => write!(f, "on-demand"),
        }
    }
}

/// Telemetry with metadata about how it was received.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceivedTelemetry {
    /// The telemetry data.
    pub telemetry: WorkerTelemetry,
    /// How the telemetry was received.
    pub source: TelemetrySource,
    /// When the telemetry was received by the daemon.
    pub received_at: DateTime<Utc>,
}

impl ReceivedTelemetry {
    /// Create a new received telemetry record.
    pub fn new(telemetry: WorkerTelemetry, source: TelemetrySource) -> Self {
        Self {
            telemetry,
            source,
            received_at: Utc::now(),
        }
    }

    /// Age of the telemetry data in seconds.
    pub fn age_secs(&self) -> i64 {
        (Utc::now() - self.telemetry.timestamp).num_seconds()
    }

    /// Time since received by daemon in seconds.
    pub fn since_received_secs(&self) -> i64 {
        (Utc::now() - self.received_at).num_seconds()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collect::cpu::{CpuPressureStall, LoadAverage};

    fn make_test_cpu_telemetry() -> CpuTelemetry {
        CpuTelemetry {
            timestamp: Utc::now(),
            overall_percent: 45.5,
            per_core_percent: vec![40.0, 50.0, 45.0, 47.0],
            num_cores: 4,
            load_average: LoadAverage {
                one_min: 2.4,
                five_min: 1.8,
                fifteen_min: 1.5,
                running_processes: 2,
                total_processes: 128,
            },
            psi: Some(CpuPressureStall {
                some_avg10: 1.5,
                some_avg60: 1.2,
                some_avg300: 0.8,
            }),
        }
    }

    fn make_test_memory_telemetry() -> MemoryTelemetry {
        MemoryTelemetry {
            timestamp: Utc::now(),
            total_gb: 16.0,
            available_gb: 8.0,
            used_percent: 50.0,
            pressure_score: 55.0,
            swap_used_gb: 0.5,
            dirty_mb: 10.0,
            psi: None,
        }
    }

    fn make_test_worker_telemetry() -> WorkerTelemetry {
        WorkerTelemetry::new(
            "worker-1".to_string(),
            make_test_cpu_telemetry(),
            make_test_memory_telemetry(),
            None,
            None,
            50,
        )
    }

    #[test]
    fn test_worker_telemetry_serialization() {
        let telemetry = make_test_worker_telemetry();

        // Serialize to JSON
        let json = telemetry.to_json().unwrap();
        assert!(json.contains("worker-1"));
        assert!(json.contains("45.5"));

        // Deserialize back
        let parsed = WorkerTelemetry::from_json(&json).unwrap();
        assert_eq!(parsed.worker_id, "worker-1");
        assert!((parsed.cpu.overall_percent - 45.5).abs() < 0.01);
        assert_eq!(parsed.version, TELEMETRY_PROTOCOL_VERSION);
    }

    #[test]
    fn test_worker_telemetry_pretty_json() {
        let telemetry = make_test_worker_telemetry();
        let pretty = telemetry.to_json_pretty().unwrap();
        assert!(pretty.contains('\n'));
        assert!(pretty.contains("  ")); // Indentation
    }

    #[test]
    fn test_telemetry_summary() {
        let telemetry = make_test_worker_telemetry();
        let summary = telemetry.summary();

        assert_eq!(summary.worker_id, "worker-1");
        assert!((summary.cpu_percent - 45.5).abs() < 0.01);
        assert!((summary.memory_percent - 50.0).abs() < 0.01);
        assert!(summary.disk_io_percent.is_none());
        assert!(summary.network_throughput_mbps.is_none());

        // Test display
        let display = summary.to_string();
        assert!(display.contains("worker-1"));
        assert!(display.contains("CPU: 45.5%"));
    }

    #[test]
    fn test_piggyback_format() {
        let telemetry = make_test_worker_telemetry();
        let piggyback = telemetry.to_piggyback().unwrap();

        assert!(piggyback.starts_with(PIGGYBACK_MARKER));
        assert!(piggyback.contains("worker-1"));
    }

    #[test]
    fn test_extract_piggybacked_telemetry() {
        let telemetry = make_test_worker_telemetry();
        let build_output = "Compiling foo v0.1.0\n   Finished release target(s) in 42.5s";
        let combined = format!("{}\n{}", build_output, telemetry.to_piggyback().unwrap());

        let extraction = extract_piggybacked_telemetry(&combined);
        assert!(extraction.telemetry.is_some());
        assert!(extraction.extraction_error.is_none());
        assert_eq!(extraction.build_output, build_output);

        let extracted = extraction.telemetry.unwrap();
        assert_eq!(extracted.worker_id, "worker-1");
    }

    #[test]
    fn test_extract_piggybacked_no_telemetry() {
        let output = "Compiling foo v0.1.0\n   Finished release target(s) in 42.5s";
        let extraction = extract_piggybacked_telemetry(output);

        assert!(extraction.telemetry.is_none());
        assert!(extraction.extraction_error.is_none());
        assert_eq!(extraction.build_output, output);
    }

    #[test]
    fn test_extract_piggybacked_invalid_json() {
        let output = format!("Build output\n{}\n{{invalid json}}", PIGGYBACK_MARKER);
        let extraction = extract_piggybacked_telemetry(&output);

        assert!(extraction.telemetry.is_none());
        assert!(extraction.extraction_error.is_some());
        assert_eq!(extraction.build_output, "Build output");
    }

    #[test]
    fn test_extract_piggybacked_uses_last_marker() {
        let telemetry = make_test_worker_telemetry();
        let build_output = format!("Build output\n{}\nnoise\nmore output", PIGGYBACK_MARKER);
        let combined = format!("{}\n{}", build_output, telemetry.to_piggyback().unwrap());

        let extraction = extract_piggybacked_telemetry(&combined);
        assert!(extraction.telemetry.is_some());
        assert!(extraction.extraction_error.is_none());
        assert_eq!(extraction.build_output, build_output);
    }

    #[test]
    fn test_telemetry_version_compatibility() {
        let telemetry = make_test_worker_telemetry();
        assert!(telemetry.is_compatible());
        assert_eq!(telemetry.version, TELEMETRY_PROTOCOL_VERSION);
    }

    #[test]
    fn test_telemetry_source_display() {
        assert_eq!(TelemetrySource::Piggyback.to_string(), "piggyback");
        assert_eq!(TelemetrySource::SshPoll.to_string(), "ssh-poll");
        assert_eq!(TelemetrySource::OnDemand.to_string(), "on-demand");
    }

    #[test]
    fn test_received_telemetry() {
        let telemetry = make_test_worker_telemetry();
        let received = ReceivedTelemetry::new(telemetry, TelemetrySource::SshPoll);

        assert_eq!(received.source, TelemetrySource::SshPoll);
        assert!(received.age_secs() >= 0);
        assert!(received.since_received_secs() >= 0);
    }

    // ========================
    // TestRunRecord tests
    // ========================

    #[test]
    fn test_run_record_serialization_roundtrip() {
        let record = TestRunRecord {
            project_id: "my-project".to_string(),
            worker_id: "worker-1".to_string(),
            command: "cargo test --release".to_string(),
            kind: "cargo_test".to_string(),
            exit_code: 0,
            duration_ms: 12345,
            completed_at: Utc::now(),
        };

        let json = record.to_json().unwrap();
        let parsed = TestRunRecord::from_json(&json).unwrap();

        assert_eq!(parsed.project_id, "my-project");
        assert_eq!(parsed.worker_id, "worker-1");
        assert_eq!(parsed.command, "cargo test --release");
        assert_eq!(parsed.kind, "cargo_test");
        assert_eq!(parsed.exit_code, 0);
        assert_eq!(parsed.duration_ms, 12345);
    }

    #[test]
    fn test_run_record_new_from_compilation_kind() {
        use rch_common::CompilationKind;

        let record = TestRunRecord::new(
            "proj-1".to_string(),
            "worker-2".to_string(),
            "cargo nextest run".to_string(),
            CompilationKind::CargoNextest,
            0,
            5000,
        );

        assert_eq!(record.project_id, "proj-1");
        assert_eq!(record.worker_id, "worker-2");
        assert!(record.kind.contains("Nextest") || record.kind.contains("nextest"));
        assert_eq!(record.exit_code, 0);
        assert_eq!(record.duration_ms, 5000);
    }

    #[test]
    fn test_run_record_various_exit_codes() {
        // Test success (0)
        let success = TestRunRecord {
            project_id: "p".to_string(),
            worker_id: "w".to_string(),
            command: "cmd".to_string(),
            kind: "test".to_string(),
            exit_code: 0,
            duration_ms: 100,
            completed_at: Utc::now(),
        };
        let json = success.to_json().unwrap();
        assert!(json.contains("\"exit_code\":0"));

        // Test failure (101 - Rust test failure)
        let failure = TestRunRecord {
            exit_code: 101,
            ..success.clone()
        };
        let json = failure.to_json().unwrap();
        assert!(json.contains("\"exit_code\":101"));

        // Test build error (1)
        let build_err = TestRunRecord {
            exit_code: 1,
            ..success.clone()
        };
        let json = build_err.to_json().unwrap();
        assert!(json.contains("\"exit_code\":1"));
    }

    // ========================
    // TestRunStats tests
    // ========================

    #[test]
    fn test_run_stats_default_is_empty() {
        let stats = TestRunStats::default();
        assert_eq!(stats.total_runs, 0);
        assert_eq!(stats.passed_runs, 0);
        assert_eq!(stats.failed_runs, 0);
        assert_eq!(stats.build_error_runs, 0);
        assert_eq!(stats.avg_duration_ms, 0);
        assert!(stats.runs_by_kind.is_empty());
    }

    #[test]
    fn test_run_stats_record_passed() {
        let mut stats = TestRunStats::default();
        let record = TestRunRecord {
            project_id: "p".to_string(),
            worker_id: "w".to_string(),
            command: "cargo test".to_string(),
            kind: "cargo_test".to_string(),
            exit_code: 0,
            duration_ms: 1000,
            completed_at: Utc::now(),
        };

        stats.record(&record);

        assert_eq!(stats.total_runs, 1);
        assert_eq!(stats.passed_runs, 1);
        assert_eq!(stats.failed_runs, 0);
        assert_eq!(stats.build_error_runs, 0);
        assert_eq!(stats.avg_duration_ms, 1000);
        assert_eq!(stats.runs_by_kind.get("cargo_test"), Some(&1));
    }

    #[test]
    fn test_run_stats_record_failed() {
        let mut stats = TestRunStats::default();
        let record = TestRunRecord {
            project_id: "p".to_string(),
            worker_id: "w".to_string(),
            command: "cargo test".to_string(),
            kind: "cargo_test".to_string(),
            exit_code: 101, // Rust test failure
            duration_ms: 500,
            completed_at: Utc::now(),
        };

        stats.record(&record);

        assert_eq!(stats.total_runs, 1);
        assert_eq!(stats.passed_runs, 0);
        assert_eq!(stats.failed_runs, 1);
        assert_eq!(stats.build_error_runs, 0);
    }

    #[test]
    fn test_run_stats_record_build_error() {
        let mut stats = TestRunStats::default();
        let record = TestRunRecord {
            project_id: "p".to_string(),
            worker_id: "w".to_string(),
            command: "cargo test".to_string(),
            kind: "cargo_test".to_string(),
            exit_code: 1, // Build error
            duration_ms: 200,
            completed_at: Utc::now(),
        };

        stats.record(&record);

        assert_eq!(stats.total_runs, 1);
        assert_eq!(stats.passed_runs, 0);
        assert_eq!(stats.failed_runs, 0);
        assert_eq!(stats.build_error_runs, 1);
    }

    #[test]
    fn test_run_stats_record_other_exit_code() {
        let mut stats = TestRunStats::default();
        let record = TestRunRecord {
            project_id: "p".to_string(),
            worker_id: "w".to_string(),
            command: "cargo test".to_string(),
            kind: "cargo_test".to_string(),
            exit_code: 137, // SIGKILL
            duration_ms: 300,
            completed_at: Utc::now(),
        };

        stats.record(&record);

        // Other exit codes count as failed
        assert_eq!(stats.total_runs, 1);
        assert_eq!(stats.failed_runs, 1);
    }

    #[test]
    fn test_run_stats_multiple_records_avg_duration() {
        let mut stats = TestRunStats::default();

        for duration in [1000, 2000, 3000] {
            let record = TestRunRecord {
                project_id: "p".to_string(),
                worker_id: "w".to_string(),
                command: "cargo test".to_string(),
                kind: "cargo_test".to_string(),
                exit_code: 0,
                duration_ms: duration,
                completed_at: Utc::now(),
            };
            stats.record(&record);
        }

        assert_eq!(stats.total_runs, 3);
        assert_eq!(stats.passed_runs, 3);
        assert_eq!(stats.avg_duration_ms, 2000); // (1000+2000+3000)/3
    }

    #[test]
    fn test_run_stats_multiple_kinds() {
        let mut stats = TestRunStats::default();

        let kinds = ["cargo_test", "cargo_test", "cargo_nextest", "cargo_build"];
        for kind in kinds {
            let record = TestRunRecord {
                project_id: "p".to_string(),
                worker_id: "w".to_string(),
                command: "cmd".to_string(),
                kind: kind.to_string(),
                exit_code: 0,
                duration_ms: 100,
                completed_at: Utc::now(),
            };
            stats.record(&record);
        }

        assert_eq!(stats.total_runs, 4);
        assert_eq!(stats.runs_by_kind.get("cargo_test"), Some(&2));
        assert_eq!(stats.runs_by_kind.get("cargo_nextest"), Some(&1));
        assert_eq!(stats.runs_by_kind.get("cargo_build"), Some(&1));
    }

    #[test]
    fn test_run_stats_serialization_roundtrip() {
        let mut stats = TestRunStats {
            total_runs: 10,
            passed_runs: 7,
            failed_runs: 2,
            build_error_runs: 1,
            avg_duration_ms: 1500,
            ..Default::default()
        };
        stats.runs_by_kind.insert("cargo_test".to_string(), 8);
        stats.runs_by_kind.insert("cargo_nextest".to_string(), 2);

        let json = serde_json::to_string(&stats).unwrap();
        let parsed: TestRunStats = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.total_runs, 10);
        assert_eq!(parsed.passed_runs, 7);
        assert_eq!(parsed.failed_runs, 2);
        assert_eq!(parsed.build_error_runs, 1);
        assert_eq!(parsed.avg_duration_ms, 1500);
        assert_eq!(parsed.runs_by_kind.get("cargo_test"), Some(&8));
    }

    // ========================
    // Protocol version tests
    // ========================

    #[test]
    fn test_protocol_version_is_one() {
        assert_eq!(TELEMETRY_PROTOCOL_VERSION, 1);
    }

    #[test]
    fn test_worker_telemetry_incompatible_version() {
        let mut telemetry = make_test_worker_telemetry();
        assert!(telemetry.is_compatible());

        // Simulate receiving telemetry from a future version
        telemetry.version = TELEMETRY_PROTOCOL_VERSION + 1;
        assert!(!telemetry.is_compatible());

        // Old version also incompatible
        telemetry.version = 0;
        assert!(!telemetry.is_compatible());
    }

    #[test]
    fn test_protocol_backward_compatibility_missing_optional_fields() {
        // Simulate JSON from an older version that doesn't have optional fields
        let minimal_json = r#"{
            "version": 1,
            "worker_id": "legacy-worker",
            "timestamp": "2025-01-01T00:00:00Z",
            "cpu": {
                "timestamp": "2025-01-01T00:00:00Z",
                "overall_percent": 50.0,
                "per_core_percent": [50.0],
                "num_cores": 1,
                "load_average": {
                    "one_min": 1.0,
                    "five_min": 0.8,
                    "fifteen_min": 0.5,
                    "running_processes": 1,
                    "total_processes": 100
                },
                "psi": null
            },
            "memory": {
                "timestamp": "2025-01-01T00:00:00Z",
                "total_gb": 8.0,
                "available_gb": 4.0,
                "used_percent": 50.0,
                "pressure_score": 50.0,
                "swap_used_gb": 0.0,
                "dirty_mb": 0.0,
                "psi": null
            },
            "collection_duration_ms": 100
        }"#;

        let parsed = WorkerTelemetry::from_json(minimal_json).unwrap();
        assert_eq!(parsed.worker_id, "legacy-worker");
        assert!(parsed.disk.is_none());
        assert!(parsed.network.is_none());
        assert!(parsed.is_compatible());
    }

    #[test]
    fn test_piggyback_marker_constant() {
        assert_eq!(PIGGYBACK_MARKER, "---RCH-TELEMETRY---");
    }

    // ========================
    // TelemetrySummary tests
    // ========================

    #[test]
    fn test_telemetry_summary_serialization_roundtrip() {
        let summary = TelemetrySummary {
            worker_id: "w1".to_string(),
            timestamp: Utc::now(),
            cpu_percent: 45.0,
            memory_percent: 60.0,
            memory_pressure: 55.0,
            disk_io_percent: Some(30.0),
            network_throughput_mbps: Some(100.0),
            load_1m: 2.5,
        };

        let json = serde_json::to_string(&summary).unwrap();
        let parsed: TelemetrySummary = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.worker_id, "w1");
        assert!((parsed.cpu_percent - 45.0).abs() < 0.01);
        assert_eq!(parsed.disk_io_percent, Some(30.0));
        assert_eq!(parsed.network_throughput_mbps, Some(100.0));
    }

    #[test]
    fn test_telemetry_summary_display_with_all_fields() {
        let summary = TelemetrySummary {
            worker_id: "w1".to_string(),
            timestamp: Utc::now(),
            cpu_percent: 45.0,
            memory_percent: 60.0,
            memory_pressure: 55.0,
            disk_io_percent: Some(30.0),
            network_throughput_mbps: Some(100.0),
            load_1m: 2.5,
        };

        let display = summary.to_string();
        assert!(display.contains("w1"));
        assert!(display.contains("CPU: 45.0%"));
        assert!(display.contains("Mem: 60.0%"));
        assert!(display.contains("Disk I/O: 30.0%"));
        assert!(display.contains("Net: 100.0 Mbps"));
    }

    #[test]
    fn test_telemetry_summary_display_without_optional_fields() {
        let summary = TelemetrySummary {
            worker_id: "w1".to_string(),
            timestamp: Utc::now(),
            cpu_percent: 45.0,
            memory_percent: 60.0,
            memory_pressure: 55.0,
            disk_io_percent: None,
            network_throughput_mbps: None,
            load_1m: 2.5,
        };

        let display = summary.to_string();
        assert!(display.contains("w1"));
        assert!(display.contains("CPU: 45.0%"));
        assert!(!display.contains("Disk I/O"));
        assert!(!display.contains("Net:"));
    }

    // ========================
    // TelemetrySource tests
    // ========================

    #[test]
    fn test_telemetry_source_equality() {
        assert_eq!(TelemetrySource::Piggyback, TelemetrySource::Piggyback);
        assert_ne!(TelemetrySource::Piggyback, TelemetrySource::SshPoll);
        assert_ne!(TelemetrySource::SshPoll, TelemetrySource::OnDemand);
    }

    #[test]
    fn test_telemetry_source_serialization_roundtrip() {
        for source in [
            TelemetrySource::Piggyback,
            TelemetrySource::SshPoll,
            TelemetrySource::OnDemand,
        ] {
            let json = serde_json::to_string(&source).unwrap();
            let parsed: TelemetrySource = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, source);
        }
    }

    // ========================
    // ReceivedTelemetry tests
    // ========================

    #[test]
    fn test_received_telemetry_serialization_roundtrip() {
        let telemetry = make_test_worker_telemetry();
        let received = ReceivedTelemetry::new(telemetry, TelemetrySource::Piggyback);

        let json = serde_json::to_string(&received).unwrap();
        let parsed: ReceivedTelemetry = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.source, TelemetrySource::Piggyback);
        assert_eq!(parsed.telemetry.worker_id, "worker-1");
    }

    #[test]
    fn test_received_telemetry_all_sources() {
        let telemetry = make_test_worker_telemetry();

        for source in [
            TelemetrySource::Piggyback,
            TelemetrySource::SshPoll,
            TelemetrySource::OnDemand,
        ] {
            let received = ReceivedTelemetry::new(telemetry.clone(), source);
            assert_eq!(received.source, source);
        }
    }

    // ========================
    // PiggybackExtraction tests
    // ========================

    #[test]
    fn test_piggyback_extraction_empty_output() {
        let extraction = extract_piggybacked_telemetry("");
        assert!(extraction.telemetry.is_none());
        assert!(extraction.extraction_error.is_none());
        assert_eq!(extraction.build_output, "");
    }

    #[test]
    fn test_piggyback_extraction_whitespace_handling() {
        let telemetry = make_test_worker_telemetry();
        let build_output = "Build output with trailing spaces   \n\n";
        let combined = format!("{}{}", build_output, telemetry.to_piggyback().unwrap());

        let extraction = extract_piggybacked_telemetry(&combined);
        assert!(extraction.telemetry.is_some());
        // Build output should have trailing whitespace trimmed
        assert!(!extraction.build_output.ends_with(' '));
        assert!(!extraction.build_output.ends_with('\n'));
    }
}
