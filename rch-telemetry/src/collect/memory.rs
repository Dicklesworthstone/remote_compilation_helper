//! Memory metrics collection from /proc/meminfo.
//!
//! Reads Linux /proc/meminfo to track available memory, usage patterns,
//! and memory pressure for worker health monitoring.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;
use tracing::{debug, warn};

/// Errors that can occur during memory metrics collection.
#[derive(Error, Debug)]
pub enum MemoryError {
    #[error("failed to read /proc/meminfo: {0}")]
    ReadError(#[from] std::io::Error),

    #[error("failed to parse /proc/meminfo: missing required field '{0}'")]
    MissingField(String),

    #[error("failed to parse value for field '{field}': {value}")]
    ParseError { field: String, value: String },
}

/// Raw memory information parsed from /proc/meminfo.
///
/// All values are in kilobytes (kB) as reported by the kernel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryInfo {
    /// Total usable RAM (physical minus reserved).
    pub total_kb: u64,
    /// Free memory (not in use at all).
    pub free_kb: u64,
    /// Available memory for new allocations (kernel estimate).
    /// This is the best indicator of usable memory.
    pub available_kb: u64,
    /// Memory used for block device buffers.
    pub buffers_kb: u64,
    /// Memory used for file caching.
    pub cached_kb: u64,
    /// Total swap space.
    pub swap_total_kb: u64,
    /// Free swap space.
    pub swap_free_kb: u64,
    /// Memory waiting to be written to disk.
    pub dirty_kb: u64,
    /// Memory currently being written to disk.
    pub writeback_kb: u64,
}

impl MemoryInfo {
    /// Read memory information from /proc/meminfo.
    pub fn read_from_proc() -> Result<Self, MemoryError> {
        let content = std::fs::read_to_string("/proc/meminfo")?;
        Self::parse(&content)
    }

    /// Parse /proc/meminfo content.
    pub fn parse(content: &str) -> Result<Self, MemoryError> {
        let mut map: HashMap<String, u64> = HashMap::new();

        for line in content.lines() {
            if let Some((key, value)) = line.split_once(':') {
                // Value format: "    12345 kB" or "    12345"
                let value_str = value.trim().trim_end_matches(" kB").trim();
                if let Ok(kb) = value_str.parse::<u64>() {
                    map.insert(key.to_string(), kb);
                }
            }
        }

        // Extract required fields
        let total_kb = *map
            .get("MemTotal")
            .ok_or_else(|| MemoryError::MissingField("MemTotal".to_string()))?;

        let free_kb = *map
            .get("MemFree")
            .ok_or_else(|| MemoryError::MissingField("MemFree".to_string()))?;

        // MemAvailable may not exist on very old kernels (< 3.14)
        // Fall back to Free + Buffers + Cached estimate
        let available_kb = map.get("MemAvailable").copied().unwrap_or_else(|| {
            let buffers = map.get("Buffers").copied().unwrap_or(0);
            let cached = map.get("Cached").copied().unwrap_or(0);
            debug!(
                "MemAvailable not found, estimating from Free + Buffers + Cached: {} + {} + {}",
                free_kb, buffers, cached
            );
            free_kb + buffers + cached
        });

        Ok(Self {
            total_kb,
            free_kb,
            available_kb,
            buffers_kb: map.get("Buffers").copied().unwrap_or(0),
            cached_kb: map.get("Cached").copied().unwrap_or(0),
            swap_total_kb: map.get("SwapTotal").copied().unwrap_or(0),
            swap_free_kb: map.get("SwapFree").copied().unwrap_or(0),
            dirty_kb: map.get("Dirty").copied().unwrap_or(0),
            writeback_kb: map.get("Writeback").copied().unwrap_or(0),
        })
    }

    /// Total memory in use (total - available).
    pub fn used_kb(&self) -> u64 {
        self.total_kb.saturating_sub(self.available_kb)
    }

    /// Percentage of memory in use (0-100).
    pub fn used_percent(&self) -> f64 {
        if self.total_kb == 0 {
            return 0.0;
        }
        (self.used_kb() as f64 / self.total_kb as f64) * 100.0
    }

    /// Memory pressure score (0-100, higher = more pressure).
    ///
    /// Accounts for:
    /// - Base memory usage percentage
    /// - Swap usage (indicates memory pressure)
    /// - Dirty pages (pending writes causing I/O pressure)
    pub fn pressure_score(&self) -> f64 {
        let base = self.used_percent();

        // Add pressure for swap usage (up to +20 points)
        let swap_used = self.swap_total_kb.saturating_sub(self.swap_free_kb);
        let swap_pressure = if self.swap_total_kb > 0 {
            (swap_used as f64 / self.swap_total_kb as f64) * 20.0
        } else {
            0.0
        };

        // Add pressure for dirty pages (up to +5 points per GB)
        // Large dirty pages indicate pending I/O that could cause stalls
        let dirty_gb = self.dirty_kb as f64 / 1_048_576.0;
        let dirty_pressure = (dirty_gb * 5.0).min(10.0);

        (base + swap_pressure + dirty_pressure).min(100.0)
    }

    /// Estimated available memory for new allocations in GB.
    pub fn available_gb(&self) -> f64 {
        self.available_kb as f64 / 1_048_576.0
    }

    /// Total memory in GB.
    pub fn total_gb(&self) -> f64 {
        self.total_kb as f64 / 1_048_576.0
    }

    /// Swap used in GB.
    pub fn swap_used_gb(&self) -> f64 {
        let swap_used = self.swap_total_kb.saturating_sub(self.swap_free_kb);
        swap_used as f64 / 1_048_576.0
    }
}

/// Pressure Stall Information from /proc/pressure/memory (Linux 4.20+).
///
/// PSI tracks the percentage of time tasks were stalled waiting for memory.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MemoryPressureStall {
    /// Percentage of time at least one task was stalled (10s average).
    pub some_avg10: f64,
    /// Percentage of time at least one task was stalled (60s average).
    pub some_avg60: f64,
    /// Percentage of time at least one task was stalled (300s average).
    pub some_avg300: f64,
    /// Percentage of time ALL tasks were stalled (10s average).
    pub full_avg10: f64,
    /// Percentage of time ALL tasks were stalled (60s average).
    pub full_avg60: f64,
    /// Percentage of time ALL tasks were stalled (300s average).
    pub full_avg300: f64,
}

impl MemoryPressureStall {
    /// Read PSI data from /proc/pressure/memory.
    ///
    /// Returns `None` if PSI is not available (kernel < 4.20).
    pub fn read_from_proc() -> Option<Self> {
        let content = match std::fs::read_to_string("/proc/pressure/memory") {
            Ok(c) => c,
            Err(e) => {
                debug!("PSI not available: {}", e);
                return None;
            }
        };
        Self::parse(&content)
    }

    /// Parse /proc/pressure/memory content.
    ///
    /// Format:
    /// ```text
    /// some avg10=0.00 avg60=0.00 avg300=0.00 total=0
    /// full avg10=0.00 avg60=0.00 avg300=0.00 total=0
    /// ```
    pub fn parse(content: &str) -> Option<Self> {
        let mut result = Self::default();

        for line in content.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.is_empty() {
                continue;
            }

            let prefix = parts[0];
            for part in &parts[1..] {
                if let Some((key, value)) = part.split_once('=')
                    && let Ok(v) = value.parse::<f64>()
                {
                    match (prefix, key) {
                        ("some", "avg10") => result.some_avg10 = v,
                        ("some", "avg60") => result.some_avg60 = v,
                        ("some", "avg300") => result.some_avg300 = v,
                        ("full", "avg10") => result.full_avg10 = v,
                        ("full", "avg60") => result.full_avg60 = v,
                        ("full", "avg300") => result.full_avg300 = v,
                        _ => {}
                    }
                }
            }
        }

        Some(result)
    }
}

/// Aggregated memory telemetry snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryTelemetry {
    /// Timestamp of the telemetry collection.
    pub timestamp: DateTime<Utc>,
    /// Total system memory in GB.
    pub total_gb: f64,
    /// Available memory for new allocations in GB.
    pub available_gb: f64,
    /// Percentage of memory in use (0-100).
    pub used_percent: f64,
    /// Memory pressure score (0-100).
    pub pressure_score: f64,
    /// Swap used in GB.
    pub swap_used_gb: f64,
    /// Dirty pages in MB.
    pub dirty_mb: f64,
    /// PSI data if available (Linux 4.20+).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub psi: Option<MemoryPressureStall>,
}

impl MemoryTelemetry {
    /// Collect memory telemetry from the system.
    pub fn collect() -> Result<Self, MemoryError> {
        let info = MemoryInfo::read_from_proc()?;
        let psi = MemoryPressureStall::read_from_proc();

        let telemetry = Self {
            timestamp: Utc::now(),
            total_gb: info.total_gb(),
            available_gb: info.available_gb(),
            used_percent: info.used_percent(),
            pressure_score: info.pressure_score(),
            swap_used_gb: info.swap_used_gb(),
            dirty_mb: info.dirty_kb as f64 / 1024.0,
            psi,
        };

        debug!(
            total_gb = %telemetry.total_gb,
            available_gb = %telemetry.available_gb,
            used_pct = %telemetry.used_percent,
            pressure = %telemetry.pressure_score,
            swap_gb = %telemetry.swap_used_gb,
            "Memory telemetry collected"
        );

        // Warn on high pressure
        if telemetry.pressure_score > 80.0 {
            warn!(
                pressure = %telemetry.pressure_score,
                available_gb = %telemetry.available_gb,
                "Worker under memory pressure"
            );
        }

        Ok(telemetry)
    }

    /// Create telemetry from raw MemoryInfo (useful for testing).
    pub fn from_info(info: &MemoryInfo, psi: Option<MemoryPressureStall>) -> Self {
        Self {
            timestamp: Utc::now(),
            total_gb: info.total_gb(),
            available_gb: info.available_gb(),
            used_percent: info.used_percent(),
            pressure_score: info.pressure_score(),
            swap_used_gb: info.swap_used_gb(),
            dirty_mb: info.dirty_kb as f64 / 1024.0,
            psi,
        }
    }

    /// Collect memory telemetry on macOS without `/proc`.
    ///
    /// Sources: `sysctl hw.memsize` (total RAM), `vm_stat` (page counts for
    /// the available-memory estimate), `sysctl vm.swapusage` (swap). The
    /// numbers are normalized into a [`MemoryInfo`] so the pressure-score
    /// formula is byte-for-byte the same one Linux workers use.
    pub fn collect_darwin() -> Result<Self, MemoryError> {
        let total_bytes: u64 =
            darwin_command_output(&["/usr/sbin/sysctl", "sysctl"], &["-n", "hw.memsize"])?
                .trim()
                .parse()
                .map_err(|_| MemoryError::MissingField("hw.memsize".to_string()))?;

        let vm_stat_raw = darwin_command_output(&["/usr/bin/vm_stat", "vm_stat"], &[])?;
        let available_bytes = parse_darwin_vm_stat_available_bytes(&vm_stat_raw)
            .ok_or_else(|| MemoryError::MissingField("vm_stat pages".to_string()))?;

        let swapusage_raw =
            darwin_command_output(&["/usr/sbin/sysctl", "sysctl"], &["-n", "vm.swapusage"])?;
        let (swap_total_kb, swap_used_kb) =
            parse_darwin_swapusage_kb(&swapusage_raw).unwrap_or((0, 0));

        let info = MemoryInfo {
            total_kb: total_bytes / 1024,
            free_kb: available_bytes / 1024,
            available_kb: available_bytes / 1024,
            buffers_kb: 0,
            cached_kb: 0,
            swap_total_kb,
            swap_free_kb: swap_total_kb.saturating_sub(swap_used_kb),
            // Darwin exposes no meaningful equivalent of Linux dirty/writeback
            // page counters through these interfaces; report zero rather than
            // fabricate.
            dirty_kb: 0,
            writeback_kb: 0,
        };

        let telemetry = Self::from_info(&info, None);

        debug!(
            total_gb = %telemetry.total_gb,
            available_gb = %telemetry.available_gb,
            used_pct = %telemetry.used_percent,
            pressure = %telemetry.pressure_score,
            swap_gb = %telemetry.swap_used_gb,
            "Memory telemetry collected (darwin)"
        );

        Ok(telemetry)
    }
}

/// Run a command (first existing candidate path wins) and return stdout.
fn darwin_command_output(programs: &[&str], args: &[&str]) -> Result<String, MemoryError> {
    for program in programs {
        match std::process::Command::new(program).args(args).output() {
            Ok(output) if output.status.success() => {
                return Ok(String::from_utf8_lossy(&output.stdout).into_owned());
            }
            Ok(output) => {
                return Err(MemoryError::ParseError {
                    field: (*program).to_string(),
                    value: format!("exited with status {}", output.status),
                });
            }
            Err(_) => continue,
        }
    }
    Err(MemoryError::MissingField(format!(
        "command not found: {}",
        programs.join(" / ")
    )))
}

/// Parse `vm_stat` output into an available-memory estimate in bytes.
///
/// `vm_stat` reports page counts with the page size in its header:
///
/// ```text
/// Mach Virtual Memory Statistics: (page size of 16384 bytes)
/// Pages free:                              137494.
/// Pages inactive:                          294370.
/// Pages speculative:                        56521.
/// Pages purgeable:                          21353.
/// ```
///
/// Available ≈ (free + inactive + speculative + purgeable) × page size, the
/// same shape as the kernel's `MemAvailable` estimate on Linux (memory that
/// can be handed to new allocations without swapping).
pub fn parse_darwin_vm_stat_available_bytes(content: &str) -> Option<u64> {
    let mut page_size: u64 = 0;
    let mut free: u64 = 0;
    let mut inactive: u64 = 0;
    let mut speculative: u64 = 0;
    let mut purgeable: u64 = 0;
    let mut found_free = false;

    for line in content.lines() {
        if line.contains("page size of") {
            page_size = line
                .split("page size of")
                .nth(1)?
                .split_whitespace()
                .next()?
                .parse()
                .ok()?;
            continue;
        }
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let value: u64 = match value.trim().trim_end_matches('.').parse() {
            Ok(v) => v,
            Err(_) => continue,
        };
        match key.trim() {
            "Pages free" => {
                free = value;
                found_free = true;
            }
            "Pages inactive" => inactive = value,
            "Pages speculative" => speculative = value,
            "Pages purgeable" => purgeable = value,
            _ => {}
        }
    }

    if page_size == 0 || !found_free {
        return None;
    }
    Some((free + inactive + speculative + purgeable).saturating_mul(page_size))
}

/// Parse `sysctl -n vm.swapusage` output into (total_kb, used_kb).
///
/// Format: `total = 2048.00M  used = 1120.75M  free = 927.25M  (encrypted)`.
pub fn parse_darwin_swapusage_kb(content: &str) -> Option<(u64, u64)> {
    fn value_kb(content: &str, key: &str) -> Option<u64> {
        let after = content.split(key).nth(1)?.split('=').nth(1)?;
        let token = after.split_whitespace().next()?;
        let (number, unit) = token.split_at(token.len().saturating_sub(1));
        let number: f64 = number.parse().ok()?;
        let kb = match unit {
            "K" => number,
            "M" => number * 1024.0,
            "G" => number * 1024.0 * 1024.0,
            "T" => number * 1024.0 * 1024.0 * 1024.0,
            // Unit-less means bytes.
            _ => token.parse::<f64>().ok()? / 1024.0,
        };
        Some(kb.max(0.0) as u64)
    }

    let total = value_kb(content, "total")?;
    let used = value_kb(content, "used")?;
    Some((total, used))
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
    fn test_parse_proc_meminfo() {
        init_test_logging();
        info!("TEST START: test_parse_proc_meminfo");

        let sample = r#"MemTotal:       16384000 kB
MemFree:         8192000 kB
MemAvailable:   10240000 kB
Buffers:          512000 kB
Cached:          2048000 kB
SwapTotal:       4096000 kB
SwapFree:        4096000 kB
Dirty:             12345 kB
Writeback:             0 kB"#;

        info!("INPUT: sample /proc/meminfo with 9 fields");

        let mem = MemoryInfo::parse(sample).expect("parsing should succeed");

        info!(
            total_kb = mem.total_kb,
            available_kb = mem.available_kb,
            free_kb = mem.free_kb,
            "RESULT: parsed memory info"
        );

        assert_eq!(mem.total_kb, 16384000);
        assert_eq!(mem.available_kb, 10240000);
        assert_eq!(mem.free_kb, 8192000);
        assert_eq!(mem.buffers_kb, 512000);
        assert_eq!(mem.cached_kb, 2048000);
        assert_eq!(mem.swap_total_kb, 4096000);
        assert_eq!(mem.swap_free_kb, 4096000);
        assert_eq!(mem.dirty_kb, 12345);

        info!("TEST PASS: test_parse_proc_meminfo");
    }

    #[test]
    fn test_parse_meminfo_old_kernel_format() {
        init_test_logging();
        info!("TEST START: test_parse_meminfo_old_kernel_format");

        // Old kernel without MemAvailable
        let sample = r#"MemTotal:       16384000 kB
MemFree:         2000000 kB
Buffers:          500000 kB
Cached:          1500000 kB"#;

        info!("INPUT: old kernel format without MemAvailable");

        let mem = MemoryInfo::parse(sample).expect("parsing should succeed");

        // Should estimate available = free + buffers + cached
        let expected_available = 2000000 + 500000 + 1500000;
        info!(
            expected = expected_available,
            actual = mem.available_kb,
            "RESULT: estimated available memory"
        );

        assert_eq!(mem.available_kb, expected_available);

        info!("TEST PASS: test_parse_meminfo_old_kernel_format");
    }

    #[test]
    fn test_parse_meminfo_missing_required_field() {
        init_test_logging();
        info!("TEST START: test_parse_meminfo_missing_required_field");

        let sample = r#"MemFree:         8192000 kB"#;

        info!("INPUT: meminfo missing MemTotal");

        let result = MemoryInfo::parse(sample);

        assert!(result.is_err());
        let err = result.unwrap_err();
        info!(error = %err, "RESULT: got expected error");

        match err {
            MemoryError::MissingField(field) => {
                assert_eq!(field, "MemTotal");
            }
            _ => panic!("expected MissingField error"),
        }

        info!("TEST PASS: test_parse_meminfo_missing_required_field");
    }

    #[test]
    fn test_used_percent_calculation() {
        init_test_logging();
        info!("TEST START: test_used_percent_calculation");

        let mem = MemoryInfo {
            total_kb: 16_000_000,
            free_kb: 4_000_000,
            available_kb: 4_000_000,
            buffers_kb: 500_000,
            cached_kb: 1_500_000,
            swap_total_kb: 0,
            swap_free_kb: 0,
            dirty_kb: 0,
            writeback_kb: 0,
        };

        let used_pct = mem.used_percent();
        info!(
            total = mem.total_kb,
            available = mem.available_kb,
            used_kb = mem.used_kb(),
            used_pct = used_pct,
            "RESULT: calculated usage percentage"
        );

        // Used = 16M - 4M = 12M => 75%
        assert!((used_pct - 75.0).abs() < 0.1);

        info!("TEST PASS: test_used_percent_calculation");
    }

    #[test]
    fn test_pressure_score_no_swap() {
        init_test_logging();
        info!("TEST START: test_pressure_score_no_swap");

        let mem = MemoryInfo {
            total_kb: 16_000_000,
            free_kb: 4_000_000,
            available_kb: 4_000_000, // 75% used
            buffers_kb: 0,
            cached_kb: 0,
            swap_total_kb: 0, // No swap configured
            swap_free_kb: 0,
            dirty_kb: 0,
            writeback_kb: 0,
        };

        let pressure = mem.pressure_score();
        info!(
            used_pct = mem.used_percent(),
            pressure = pressure,
            "RESULT: pressure score without swap"
        );

        // With no swap and no dirty pages, pressure = used_percent = 75
        assert!((pressure - 75.0).abs() < 0.1);

        info!("TEST PASS: test_pressure_score_no_swap");
    }

    #[test]
    fn test_pressure_score_with_swap() {
        init_test_logging();
        info!("TEST START: test_pressure_score_with_swap");

        let mem = MemoryInfo {
            total_kb: 16_000_000,
            free_kb: 4_000_000,
            available_kb: 4_000_000, // 75% used
            buffers_kb: 0,
            cached_kb: 0,
            swap_total_kb: 8_000_000,
            swap_free_kb: 4_000_000, // 50% swap used
            dirty_kb: 0,
            writeback_kb: 0,
        };

        let pressure = mem.pressure_score();
        info!(
            used_pct = mem.used_percent(),
            swap_used_pct = 50.0,
            pressure = pressure,
            "RESULT: pressure score with 50% swap used"
        );

        // Base 75% + 50% of 20 points for swap = 75 + 10 = 85
        assert!((pressure - 85.0).abs() < 0.1);

        info!("TEST PASS: test_pressure_score_with_swap");
    }

    #[test]
    fn test_pressure_score_with_dirty_pages() {
        init_test_logging();
        info!("TEST START: test_pressure_score_with_dirty_pages");

        let mem = MemoryInfo {
            total_kb: 16_000_000,
            free_kb: 4_000_000,
            available_kb: 4_000_000, // 75% used
            buffers_kb: 0,
            cached_kb: 0,
            swap_total_kb: 0,
            swap_free_kb: 0,
            dirty_kb: 2_097_152, // 2 GB of dirty pages
            writeback_kb: 0,
        };

        let pressure = mem.pressure_score();
        info!(
            used_pct = mem.used_percent(),
            dirty_gb = 2.0,
            pressure = pressure,
            "RESULT: pressure score with 2GB dirty pages"
        );

        // Base 75% + 2 GB * 5 points/GB = 75 + 10 = 85
        assert!((pressure - 85.0).abs() < 0.1);

        info!("TEST PASS: test_pressure_score_with_dirty_pages");
    }

    #[test]
    fn test_pressure_score_capped_at_100() {
        init_test_logging();
        info!("TEST START: test_pressure_score_capped_at_100");

        let mem = MemoryInfo {
            total_kb: 16_000_000,
            free_kb: 0,
            available_kb: 0, // 100% used
            buffers_kb: 0,
            cached_kb: 0,
            swap_total_kb: 8_000_000,
            swap_free_kb: 0, // 100% swap used
            dirty_kb: 10_000_000,
            writeback_kb: 0,
        };

        let pressure = mem.pressure_score();
        info!(
            used_pct = mem.used_percent(),
            pressure = pressure,
            "RESULT: pressure score should be capped at 100"
        );

        assert!((pressure - 100.0).abs() < 0.01);

        info!("TEST PASS: test_pressure_score_capped_at_100");
    }

    #[test]
    fn test_zero_total_memory() {
        init_test_logging();
        info!("TEST START: test_zero_total_memory");

        let mem = MemoryInfo {
            total_kb: 0,
            free_kb: 0,
            available_kb: 0,
            buffers_kb: 0,
            cached_kb: 0,
            swap_total_kb: 0,
            swap_free_kb: 0,
            dirty_kb: 0,
            writeback_kb: 0,
        };

        let used_pct = mem.used_percent();
        info!(used_pct = used_pct, "RESULT: used percent with zero total");

        // Should return 0.0 without panic (division by zero protection)
        assert_eq!(used_pct, 0.0);

        info!("TEST PASS: test_zero_total_memory");
    }

    #[test]
    fn test_parse_psi_data() {
        init_test_logging();
        info!("TEST START: test_parse_psi_data");

        let sample = r#"some avg10=0.50 avg60=0.30 avg300=0.10 total=12345
full avg10=0.20 avg60=0.15 avg300=0.05 total=5678"#;

        info!("INPUT: sample PSI data");

        let psi = MemoryPressureStall::parse(sample).expect("parsing should succeed");

        info!(
            some_avg10 = psi.some_avg10,
            full_avg10 = psi.full_avg10,
            "RESULT: parsed PSI data"
        );

        assert!((psi.some_avg10 - 0.50).abs() < 0.01);
        assert!((psi.some_avg60 - 0.30).abs() < 0.01);
        assert!((psi.some_avg300 - 0.10).abs() < 0.01);
        assert!((psi.full_avg10 - 0.20).abs() < 0.01);
        assert!((psi.full_avg60 - 0.15).abs() < 0.01);
        assert!((psi.full_avg300 - 0.05).abs() < 0.01);

        info!("TEST PASS: test_parse_psi_data");
    }

    #[test]
    fn test_telemetry_from_info() {
        init_test_logging();
        info!("TEST START: test_telemetry_from_info");

        let mem = MemoryInfo {
            total_kb: 16_777_216, // 16 GB
            free_kb: 4_194_304,
            available_kb: 8_388_608, // 8 GB
            buffers_kb: 524_288,
            cached_kb: 2_097_152,
            swap_total_kb: 4_194_304, // 4 GB swap
            swap_free_kb: 2_097_152,  // 2 GB swap free
            dirty_kb: 102_400,        // 100 MB dirty
            writeback_kb: 0,
        };

        let telemetry = MemoryTelemetry::from_info(&mem, None);

        info!(
            total_gb = telemetry.total_gb,
            available_gb = telemetry.available_gb,
            used_pct = telemetry.used_percent,
            pressure = telemetry.pressure_score,
            "RESULT: created telemetry from info"
        );

        assert!((telemetry.total_gb - 16.0).abs() < 0.1);
        assert!((telemetry.available_gb - 8.0).abs() < 0.1);
        assert!((telemetry.used_percent - 50.0).abs() < 0.1);

        info!("TEST PASS: test_telemetry_from_info");
    }

    #[test]
    fn test_gb_conversion() {
        init_test_logging();
        info!("TEST START: test_gb_conversion");

        let mem = MemoryInfo {
            total_kb: 33_554_432, // 32 GB
            free_kb: 0,
            available_kb: 16_777_216, // 16 GB
            buffers_kb: 0,
            cached_kb: 0,
            swap_total_kb: 8_388_608, // 8 GB
            swap_free_kb: 4_194_304,  // 4 GB free = 4 GB used
            dirty_kb: 0,
            writeback_kb: 0,
        };

        info!(
            total_gb = mem.total_gb(),
            available_gb = mem.available_gb(),
            swap_used_gb = mem.swap_used_gb(),
            "RESULT: GB conversions"
        );

        assert!((mem.total_gb() - 32.0).abs() < 0.1);
        assert!((mem.available_gb() - 16.0).abs() < 0.1);
        assert!((mem.swap_used_gb() - 4.0).abs() < 0.1);

        info!("TEST PASS: test_gb_conversion");
    }

    #[test]
    fn test_serialization_roundtrip() {
        init_test_logging();
        info!("TEST START: test_serialization_roundtrip");

        let mem = MemoryInfo {
            total_kb: 16_000_000,
            free_kb: 4_000_000,
            available_kb: 8_000_000,
            buffers_kb: 500_000,
            cached_kb: 1_500_000,
            swap_total_kb: 4_000_000,
            swap_free_kb: 2_000_000,
            dirty_kb: 50_000,
            writeback_kb: 10_000,
        };

        let json = serde_json::to_string(&mem).expect("serialization should succeed");
        info!(json_len = json.len(), "RESULT: serialized to JSON");

        let deser: MemoryInfo =
            serde_json::from_str(&json).expect("deserialization should succeed");

        assert_eq!(mem.total_kb, deser.total_kb);
        assert_eq!(mem.available_kb, deser.available_kb);
        assert_eq!(mem.dirty_kb, deser.dirty_kb);

        info!("TEST PASS: test_serialization_roundtrip");
    }

    #[test]
    fn test_parse_darwin_vm_stat_available_bytes() {
        let output = "Mach Virtual Memory Statistics: (page size of 16384 bytes)\n\
Pages free:                              100000.\n\
Pages active:                            500000.\n\
Pages inactive:                          200000.\n\
Pages speculative:                        50000.\n\
Pages throttled:                              0.\n\
Pages wired down:                        300000.\n\
Pages purgeable:                          25000.\n";
        let available = parse_darwin_vm_stat_available_bytes(output).expect("should parse vm_stat");
        // (100000 + 200000 + 50000 + 25000) * 16384
        assert_eq!(available, 375_000 * 16_384);

        // Missing page size or free count is a parse failure, not zero.
        assert!(parse_darwin_vm_stat_available_bytes("Pages free: 5.\n").is_none());
        assert!(
            parse_darwin_vm_stat_available_bytes(
                "Mach Virtual Memory Statistics: (page size of 16384 bytes)\n"
            )
            .is_none()
        );
    }

    #[test]
    fn test_parse_darwin_swapusage_kb() {
        let (total, used) = parse_darwin_swapusage_kb(
            "total = 2048.00M  used = 1120.75M  free = 927.25M  (encrypted)",
        )
        .expect("should parse swapusage");
        assert_eq!(total, 2048 * 1024);
        assert_eq!(used, (1120.75_f64 * 1024.0) as u64);

        let (total_g, used_g) =
            parse_darwin_swapusage_kb("total = 3.00G  used = 0.50G  free = 2.50G")
                .expect("should parse G units");
        assert_eq!(total_g, 3 * 1024 * 1024);
        assert_eq!(used_g, 512 * 1024);

        // No swap configured.
        let (total_zero, used_zero) =
            parse_darwin_swapusage_kb("total = 0.00M  used = 0.00M  free = 0.00M")
                .expect("should parse zero swap");
        assert_eq!(total_zero, 0);
        assert_eq!(used_zero, 0);

        assert!(parse_darwin_swapusage_kb("").is_none());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_collect_darwin_on_macos() {
        let mem = MemoryTelemetry::collect_darwin()
            .expect("darwin memory collection should succeed on macOS");
        assert!(mem.total_gb > 0.0);
        assert!(mem.available_gb > 0.0);
        assert!((0.0..=100.0).contains(&mem.used_percent));
        assert!((0.0..=100.0).contains(&mem.pressure_score));
    }
}
