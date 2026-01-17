//! CPU metrics collection from /proc/stat and /proc/loadavg.
//!
//! Reads Linux /proc/stat to track CPU utilization percentages
//! for worker health monitoring and load balancing decisions.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, warn};

/// Errors that can occur during CPU metrics collection.
#[derive(Error, Debug)]
pub enum CpuError {
    #[error("failed to read /proc/stat: {0}")]
    ReadStatError(#[from] std::io::Error),

    #[error("failed to parse /proc/stat: {0}")]
    ParseError(String),

    #[error("failed to read /proc/loadavg: {0}")]
    ReadLoadAvgError(String),
}

/// Raw CPU statistics parsed from /proc/stat.
///
/// All values are in jiffies (typically 1/100 second) since boot.
/// To calculate CPU percentage, compare two samples over a time interval.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct CpuStats {
    /// Time spent in user mode.
    pub user: u64,
    /// Time spent in user mode with low priority (nice).
    pub nice: u64,
    /// Time spent in system mode.
    pub system: u64,
    /// Time spent idle.
    pub idle: u64,
    /// Time waiting for I/O to complete.
    pub iowait: u64,
    /// Time spent servicing hardware interrupts.
    pub irq: u64,
    /// Time spent servicing software interrupts.
    pub softirq: u64,
    /// Time stolen by other operating systems (virtualization).
    pub steal: u64,
    /// Time spent running virtual CPUs (guest).
    pub guest: u64,
    /// Time spent running niced guest (guest_nice).
    pub guest_nice: u64,
}

impl CpuStats {
    /// Read CPU statistics from /proc/stat.
    pub fn read_from_proc() -> Result<Self, CpuError> {
        let content = std::fs::read_to_string("/proc/stat")?;
        Self::parse(&content)
    }

    /// Parse /proc/stat content for aggregate CPU stats.
    ///
    /// Format: `cpu user nice system idle iowait irq softirq steal guest guest_nice`
    pub fn parse(content: &str) -> Result<Self, CpuError> {
        for line in content.lines() {
            // Look for the aggregate "cpu " line (not "cpu0", "cpu1", etc.)
            if line.starts_with("cpu ") {
                return Self::parse_cpu_line(line);
            }
        }
        Err(CpuError::ParseError(
            "no aggregate cpu line found in /proc/stat".to_string(),
        ))
    }

    /// Parse a single CPU line from /proc/stat.
    fn parse_cpu_line(line: &str) -> Result<Self, CpuError> {
        let parts: Vec<&str> = line.split_whitespace().collect();

        // Minimum required fields: cpu user nice system idle
        if parts.len() < 5 {
            return Err(CpuError::ParseError(format!(
                "cpu line too short: expected at least 5 fields, got {}",
                parts.len()
            )));
        }

        let parse_field =
            |idx: usize| -> u64 { parts.get(idx).and_then(|s| s.parse().ok()).unwrap_or(0) };

        Ok(Self {
            user: parse_field(1),
            nice: parse_field(2),
            system: parse_field(3),
            idle: parse_field(4),
            iowait: parse_field(5),
            irq: parse_field(6),
            softirq: parse_field(7),
            steal: parse_field(8),
            guest: parse_field(9),
            guest_nice: parse_field(10),
        })
    }

    /// Total time (all fields combined).
    pub fn total(&self) -> u64 {
        self.user
            + self.nice
            + self.system
            + self.idle
            + self.iowait
            + self.irq
            + self.softirq
            + self.steal
    }

    /// Active (non-idle) time.
    pub fn active(&self) -> u64 {
        self.total()
            .saturating_sub(self.idle)
            .saturating_sub(self.iowait)
    }

    /// Calculate CPU utilization percentage between two samples.
    ///
    /// Returns a value between 0.0 and 100.0.
    pub fn calculate_percent(prev: &CpuStats, curr: &CpuStats) -> f64 {
        let total_delta = curr.total().saturating_sub(prev.total());
        let active_delta = curr.active().saturating_sub(prev.active());

        if total_delta == 0 {
            return 0.0; // No time passed
        }

        (active_delta as f64 / total_delta as f64) * 100.0
    }
}

/// Per-core CPU statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerCoreCpu {
    /// Core identifier (0, 1, 2, ...).
    pub core_id: u32,
    /// CPU statistics for this core.
    pub stats: CpuStats,
}

/// Read per-core CPU statistics from /proc/stat.
pub fn read_per_core_stats() -> Result<Vec<PerCoreCpu>, CpuError> {
    let content = std::fs::read_to_string("/proc/stat")?;
    parse_per_core_stats(&content)
}

/// Parse per-core CPU statistics from /proc/stat content.
pub fn parse_per_core_stats(content: &str) -> Result<Vec<PerCoreCpu>, CpuError> {
    let mut cores = Vec::new();

    for line in content.lines() {
        // Look for lines like "cpu0 ...", "cpu1 ...", etc.
        if line.starts_with("cpu") && !line.starts_with("cpu ") {
            // Extract core ID from "cpuN"
            let prefix = line.split_whitespace().next().unwrap_or("");
            if let Some(id_str) = prefix.strip_prefix("cpu") {
                if let Ok(core_id) = id_str.parse::<u32>() {
                    let stats = CpuStats::parse_cpu_line(line)?;
                    cores.push(PerCoreCpu { core_id, stats });
                }
            }
        }
    }

    // Sort by core ID
    cores.sort_by_key(|c| c.core_id);
    Ok(cores)
}

/// Load average information from /proc/loadavg.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LoadAverage {
    /// 1-minute load average.
    pub one_min: f64,
    /// 5-minute load average.
    pub five_min: f64,
    /// 15-minute load average.
    pub fifteen_min: f64,
    /// Number of currently runnable processes.
    pub running_processes: u32,
    /// Total number of processes.
    pub total_processes: u32,
}

impl LoadAverage {
    /// Read load average from /proc/loadavg.
    pub fn read_from_proc() -> Result<Self, CpuError> {
        let content = std::fs::read_to_string("/proc/loadavg")
            .map_err(|e| CpuError::ReadLoadAvgError(e.to_string()))?;
        Self::parse(&content)
    }

    /// Parse /proc/loadavg content.
    ///
    /// Format: `0.45 0.52 0.48 2/512 12345`
    pub fn parse(content: &str) -> Result<Self, CpuError> {
        let parts: Vec<&str> = content.split_whitespace().collect();

        if parts.len() < 4 {
            return Err(CpuError::ParseError(format!(
                "loadavg too short: expected at least 4 fields, got {}",
                parts.len()
            )));
        }

        let one_min = parts[0]
            .parse()
            .map_err(|_| CpuError::ParseError(format!("invalid 1min load: {}", parts[0])))?;
        let five_min = parts[1]
            .parse()
            .map_err(|_| CpuError::ParseError(format!("invalid 5min load: {}", parts[1])))?;
        let fifteen_min = parts[2]
            .parse()
            .map_err(|_| CpuError::ParseError(format!("invalid 15min load: {}", parts[2])))?;

        // Parse "running/total" field
        let (running_processes, total_processes) =
            if let Some((running, total)) = parts[3].split_once('/') {
                let r = running.parse().unwrap_or(0);
                let t = total.parse().unwrap_or(0);
                (r, t)
            } else {
                (0, 0)
            };

        Ok(Self {
            one_min,
            five_min,
            fifteen_min,
            running_processes,
            total_processes,
        })
    }
}

/// Pressure Stall Information from /proc/pressure/cpu (Linux 4.20+).
///
/// PSI tracks the percentage of time tasks were stalled waiting for CPU.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CpuPressureStall {
    /// Percentage of time at least one task was stalled (10s average).
    pub some_avg10: f64,
    /// Percentage of time at least one task was stalled (60s average).
    pub some_avg60: f64,
    /// Percentage of time at least one task was stalled (300s average).
    pub some_avg300: f64,
}

impl CpuPressureStall {
    /// Read PSI data from /proc/pressure/cpu.
    ///
    /// Returns `None` if PSI is not available (kernel < 4.20).
    pub fn read_from_proc() -> Option<Self> {
        let content = match std::fs::read_to_string("/proc/pressure/cpu") {
            Ok(c) => c,
            Err(e) => {
                debug!("CPU PSI not available: {}", e);
                return None;
            }
        };
        Self::parse(&content)
    }

    /// Parse /proc/pressure/cpu content.
    ///
    /// Format:
    /// ```text
    /// some avg10=0.00 avg60=0.00 avg300=0.00 total=0
    /// ```
    /// Note: CPU pressure only has "some" line, not "full" like memory.
    pub fn parse(content: &str) -> Option<Self> {
        let mut result = Self::default();

        for line in content.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.is_empty() || parts[0] != "some" {
                continue;
            }

            for part in &parts[1..] {
                if let Some((key, value)) = part.split_once('=') {
                    if let Ok(v) = value.parse::<f64>() {
                        match key {
                            "avg10" => result.some_avg10 = v,
                            "avg60" => result.some_avg60 = v,
                            "avg300" => result.some_avg300 = v,
                            _ => {}
                        }
                    }
                }
            }
        }

        Some(result)
    }
}

/// Aggregated CPU telemetry snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuTelemetry {
    /// Timestamp of the telemetry collection.
    pub timestamp: DateTime<Utc>,
    /// Overall CPU utilization percentage (0-100).
    pub overall_percent: f64,
    /// Per-core CPU utilization percentages.
    pub per_core_percent: Vec<f64>,
    /// Number of CPU cores.
    pub num_cores: u32,
    /// Load average data.
    pub load_average: LoadAverage,
    /// PSI data if available (Linux 4.20+).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub psi: Option<CpuPressureStall>,
}

impl CpuTelemetry {
    /// Collect CPU telemetry by comparing current stats to previous stats.
    ///
    /// For the first collection (no previous stats), pass `None` and
    /// this will return zeros for percentages.
    pub fn collect(
        prev_stats: Option<&CpuStats>,
        prev_per_core: Option<&[PerCoreCpu]>,
    ) -> Result<(Self, CpuStats, Vec<PerCoreCpu>), CpuError> {
        let curr_stats = CpuStats::read_from_proc()?;
        let curr_per_core = read_per_core_stats()?;
        let load_average = LoadAverage::read_from_proc()?;
        let psi = CpuPressureStall::read_from_proc();

        // Calculate overall percentage
        let overall_percent = match prev_stats {
            Some(prev) => CpuStats::calculate_percent(prev, &curr_stats),
            None => 0.0,
        };

        // Calculate per-core percentages
        let per_core_percent = match prev_per_core {
            Some(prev) => curr_per_core
                .iter()
                .filter_map(|curr_core| {
                    prev.iter()
                        .find(|p| p.core_id == curr_core.core_id)
                        .map(|prev_core| {
                            CpuStats::calculate_percent(&prev_core.stats, &curr_core.stats)
                        })
                })
                .collect(),
            None => vec![0.0; curr_per_core.len()],
        };

        let telemetry = Self {
            timestamp: Utc::now(),
            overall_percent,
            per_core_percent,
            num_cores: curr_per_core.len() as u32,
            load_average,
            psi,
        };

        debug!(
            overall_percent = %telemetry.overall_percent,
            num_cores = %telemetry.num_cores,
            load_1m = %telemetry.load_average.one_min,
            load_5m = %telemetry.load_average.five_min,
            "CPU telemetry collected"
        );

        // Warn on high CPU usage
        if telemetry.overall_percent > 90.0 {
            warn!(
                cpu_percent = %telemetry.overall_percent,
                load_1m = %telemetry.load_average.one_min,
                "Worker under high CPU load"
            );
        }

        Ok((telemetry, curr_stats, curr_per_core))
    }

    /// Create telemetry from raw data (useful for testing).
    pub fn from_stats(
        prev: &CpuStats,
        curr: &CpuStats,
        prev_per_core: &[PerCoreCpu],
        curr_per_core: &[PerCoreCpu],
        load_average: LoadAverage,
        psi: Option<CpuPressureStall>,
    ) -> Self {
        let overall_percent = CpuStats::calculate_percent(prev, curr);
        let per_core_percent: Vec<f64> = curr_per_core
            .iter()
            .filter_map(|curr_core| {
                prev_per_core
                    .iter()
                    .find(|p| p.core_id == curr_core.core_id)
                    .map(|prev_core| {
                        CpuStats::calculate_percent(&prev_core.stats, &curr_core.stats)
                    })
            })
            .collect();

        Self {
            timestamp: Utc::now(),
            overall_percent,
            per_core_percent,
            num_cores: curr_per_core.len() as u32,
            load_average,
            psi,
        }
    }
}

/// Get the number of CPU cores available.
pub fn num_cpus() -> u32 {
    match read_per_core_stats() {
        Ok(cores) => cores.len() as u32,
        Err(_) => {
            // Fallback to std::thread::available_parallelism
            std::thread::available_parallelism()
                .map(|n| n.get() as u32)
                .unwrap_or(1)
        }
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
    fn test_parse_proc_stat() {
        init_test_logging();
        info!("TEST START: test_parse_proc_stat");

        let sample = r#"cpu  10132153 290696 3084719 46828483 16683 0 25195 0 0 0
cpu0 2503691 72712 771085 11706116 4178 0 6285 0 0 0
cpu1 2536866 73245 770462 11710849 4144 0 6252 0 0 0
cpu2 2530153 72258 771687 11705695 4139 0 6314 0 0 0
cpu3 2561443 72481 771485 11705823 4222 0 6344 0 0 0
intr 4287231 0 0 0 0 0 0 0 0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
ctxt 1234567
btime 1234567890
processes 12345
procs_running 2
procs_blocked 0"#;

        info!("INPUT: sample /proc/stat with 4 cores");

        let stats = CpuStats::parse(sample).expect("parsing should succeed");

        info!(
            user = stats.user,
            nice = stats.nice,
            system = stats.system,
            idle = stats.idle,
            iowait = stats.iowait,
            "RESULT: parsed aggregate CPU stats"
        );

        assert_eq!(stats.user, 10132153);
        assert_eq!(stats.nice, 290696);
        assert_eq!(stats.system, 3084719);
        assert_eq!(stats.idle, 46828483);
        assert_eq!(stats.iowait, 16683);
        assert_eq!(stats.irq, 0);
        assert_eq!(stats.softirq, 25195);
        assert_eq!(stats.steal, 0);
        assert_eq!(stats.guest, 0);
        assert_eq!(stats.guest_nice, 0);

        info!("TEST PASS: test_parse_proc_stat");
    }

    #[test]
    fn test_parse_per_core_stats() {
        init_test_logging();
        info!("TEST START: test_parse_per_core_stats");

        let sample = r#"cpu  10132153 290696 3084719 46828483 16683 0 25195 0 0 0
cpu0 2503691 72712 771085 11706116 4178 0 6285 0 0 0
cpu1 2536866 73245 770462 11710849 4144 0 6252 0 0 0
cpu2 2530153 72258 771687 11705695 4139 0 6314 0 0 0
cpu3 2561443 72481 771485 11705823 4222 0 6344 0 0 0"#;

        info!("INPUT: sample with 4 CPU cores");

        let cores = parse_per_core_stats(sample).expect("parsing should succeed");

        info!(num_cores = cores.len(), "RESULT: parsed per-core stats");

        assert_eq!(cores.len(), 4);
        assert_eq!(cores[0].core_id, 0);
        assert_eq!(cores[1].core_id, 1);
        assert_eq!(cores[2].core_id, 2);
        assert_eq!(cores[3].core_id, 3);

        // Verify core 0 stats
        assert_eq!(cores[0].stats.user, 2503691);
        assert_eq!(cores[0].stats.idle, 11706116);

        info!("TEST PASS: test_parse_per_core_stats");
    }

    #[test]
    fn test_parse_proc_stat_minimal() {
        init_test_logging();
        info!("TEST START: test_parse_proc_stat_minimal");

        // Some old systems may have minimal /proc/stat
        let sample = "cpu  100 50 30 500 20";

        info!("INPUT: minimal /proc/stat with only 5 fields");

        let stats = CpuStats::parse(sample).expect("parsing should succeed");

        assert_eq!(stats.user, 100);
        assert_eq!(stats.nice, 50);
        assert_eq!(stats.system, 30);
        assert_eq!(stats.idle, 500);
        assert_eq!(stats.iowait, 20);
        // Optional fields should be 0
        assert_eq!(stats.irq, 0);
        assert_eq!(stats.softirq, 0);

        info!("TEST PASS: test_parse_proc_stat_minimal");
    }

    #[test]
    fn test_parse_proc_stat_missing_cpu_line() {
        init_test_logging();
        info!("TEST START: test_parse_proc_stat_missing_cpu_line");

        let sample = r#"intr 4287231 0 0 0
ctxt 1234567"#;

        info!("INPUT: /proc/stat without cpu line");

        let result = CpuStats::parse(sample);
        assert!(result.is_err());

        info!("TEST PASS: test_parse_proc_stat_missing_cpu_line");
    }

    #[test]
    fn test_cpu_total_and_active() {
        init_test_logging();
        info!("TEST START: test_cpu_total_and_active");

        let stats = CpuStats {
            user: 100,
            nice: 50,
            system: 30,
            idle: 500,
            iowait: 20,
            irq: 10,
            softirq: 5,
            steal: 0,
            guest: 0,
            guest_nice: 0,
        };

        let total = stats.total();
        let active = stats.active();

        info!(
            total = total,
            active = active,
            "RESULT: calculated total and active"
        );

        // Total = 100 + 50 + 30 + 500 + 20 + 10 + 5 + 0 = 715
        assert_eq!(total, 715);
        // Active = total - idle - iowait = 715 - 500 - 20 = 195
        assert_eq!(active, 195);

        info!("TEST PASS: test_cpu_total_and_active");
    }

    #[test]
    fn test_calculate_percent() {
        init_test_logging();
        info!("TEST START: test_calculate_percent");

        let prev = CpuStats {
            user: 100,
            nice: 0,
            system: 50,
            idle: 800,
            iowait: 50,
            ..Default::default()
        };

        let curr = CpuStats {
            user: 200, // +100
            nice: 0,
            system: 100, // +50
            idle: 850,   // +50
            iowait: 100, // +50
            ..Default::default()
        };

        let percent = CpuStats::calculate_percent(&prev, &curr);

        info!(percent = percent, "RESULT: calculated CPU percentage");

        // prev total = 1000, curr total = 1250, delta = 250
        // prev active = 1000 - 800 - 50 = 150
        // curr active = 1250 - 850 - 100 = 300
        // active delta = 150
        // percent = 150/250 * 100 = 60%
        assert!((percent - 60.0).abs() < 0.1);

        info!("TEST PASS: test_calculate_percent");
    }

    #[test]
    fn test_calculate_percent_zero_delta() {
        init_test_logging();
        info!("TEST START: test_calculate_percent_zero_delta");

        let stats = CpuStats::default();

        let percent = CpuStats::calculate_percent(&stats, &stats);

        info!(percent = percent, "RESULT: percentage with zero delta");

        assert_eq!(percent, 0.0);

        info!("TEST PASS: test_calculate_percent_zero_delta");
    }

    #[test]
    fn test_calculate_percent_overflow_protection() {
        init_test_logging();
        info!("TEST START: test_calculate_percent_overflow_protection");

        // Simulate counter wrap (curr < prev)
        let prev = CpuStats {
            user: 1000,
            idle: 5000,
            ..Default::default()
        };

        let curr = CpuStats {
            user: 100, // Wrapped around (smaller than prev)
            idle: 500,
            ..Default::default()
        };

        // Should not panic, uses saturating_sub
        let percent = CpuStats::calculate_percent(&prev, &curr);

        info!(percent = percent, "RESULT: percentage with counter wrap");

        // saturating_sub will return 0 for negative deltas
        assert!(percent >= 0.0);
        assert!(percent <= 100.0);

        info!("TEST PASS: test_calculate_percent_overflow_protection");
    }

    #[test]
    fn test_parse_loadavg() {
        init_test_logging();
        info!("TEST START: test_parse_loadavg");

        let sample = "0.45 0.52 0.48 2/512 12345";

        info!("INPUT: sample /proc/loadavg");

        let load = LoadAverage::parse(sample).expect("parsing should succeed");

        info!(
            one_min = load.one_min,
            five_min = load.five_min,
            fifteen_min = load.fifteen_min,
            running = load.running_processes,
            total = load.total_processes,
            "RESULT: parsed load average"
        );

        assert!((load.one_min - 0.45).abs() < 0.001);
        assert!((load.five_min - 0.52).abs() < 0.001);
        assert!((load.fifteen_min - 0.48).abs() < 0.001);
        assert_eq!(load.running_processes, 2);
        assert_eq!(load.total_processes, 512);

        info!("TEST PASS: test_parse_loadavg");
    }

    #[test]
    fn test_parse_loadavg_high_values() {
        init_test_logging();
        info!("TEST START: test_parse_loadavg_high_values");

        let sample = "12.50 8.25 4.00 15/1024 99999";

        let load = LoadAverage::parse(sample).expect("parsing should succeed");

        info!(
            one_min = load.one_min,
            five_min = load.five_min,
            "RESULT: high load values"
        );

        assert!((load.one_min - 12.50).abs() < 0.001);
        assert!((load.five_min - 8.25).abs() < 0.001);
        assert!((load.fifteen_min - 4.00).abs() < 0.001);
        assert_eq!(load.running_processes, 15);
        assert_eq!(load.total_processes, 1024);

        info!("TEST PASS: test_parse_loadavg_high_values");
    }

    #[test]
    fn test_parse_loadavg_too_short() {
        init_test_logging();
        info!("TEST START: test_parse_loadavg_too_short");

        let sample = "0.45 0.52";

        info!("INPUT: loadavg with only 2 fields");

        let result = LoadAverage::parse(sample);
        assert!(result.is_err());

        info!("TEST PASS: test_parse_loadavg_too_short");
    }

    #[test]
    fn test_parse_psi_data() {
        init_test_logging();
        info!("TEST START: test_parse_psi_data");

        let sample = "some avg10=0.50 avg60=0.30 avg300=0.10 total=12345";

        info!("INPUT: sample PSI CPU data");

        let psi = CpuPressureStall::parse(sample).expect("parsing should succeed");

        info!(
            avg10 = psi.some_avg10,
            avg60 = psi.some_avg60,
            avg300 = psi.some_avg300,
            "RESULT: parsed PSI data"
        );

        assert!((psi.some_avg10 - 0.50).abs() < 0.01);
        assert!((psi.some_avg60 - 0.30).abs() < 0.01);
        assert!((psi.some_avg300 - 0.10).abs() < 0.01);

        info!("TEST PASS: test_parse_psi_data");
    }

    #[test]
    fn test_telemetry_from_stats() {
        init_test_logging();
        info!("TEST START: test_telemetry_from_stats");

        let prev = CpuStats {
            user: 100,
            system: 50,
            idle: 800,
            iowait: 50,
            ..Default::default()
        };

        let curr = CpuStats {
            user: 200,
            system: 100,
            idle: 850,
            iowait: 100,
            ..Default::default()
        };

        let prev_core = vec![PerCoreCpu {
            core_id: 0,
            stats: prev.clone(),
        }];

        let curr_core = vec![PerCoreCpu {
            core_id: 0,
            stats: curr.clone(),
        }];

        let load = LoadAverage {
            one_min: 1.5,
            five_min: 1.2,
            fifteen_min: 0.8,
            running_processes: 3,
            total_processes: 200,
        };

        let telemetry = CpuTelemetry::from_stats(&prev, &curr, &prev_core, &curr_core, load, None);

        info!(
            overall_percent = telemetry.overall_percent,
            num_cores = telemetry.num_cores,
            load_1m = telemetry.load_average.one_min,
            "RESULT: created telemetry from stats"
        );

        assert!((telemetry.overall_percent - 60.0).abs() < 0.1);
        assert_eq!(telemetry.num_cores, 1);
        assert_eq!(telemetry.per_core_percent.len(), 1);
        assert!((telemetry.load_average.one_min - 1.5).abs() < 0.01);

        info!("TEST PASS: test_telemetry_from_stats");
    }

    #[test]
    fn test_serialization_roundtrip() {
        init_test_logging();
        info!("TEST START: test_serialization_roundtrip");

        let stats = CpuStats {
            user: 12345,
            nice: 678,
            system: 9012,
            idle: 345678,
            iowait: 1234,
            irq: 56,
            softirq: 78,
            steal: 9,
            guest: 0,
            guest_nice: 0,
        };

        let json = serde_json::to_string(&stats).expect("serialization should succeed");
        info!(json_len = json.len(), "RESULT: serialized to JSON");

        let deser: CpuStats = serde_json::from_str(&json).expect("deserialization should succeed");

        assert_eq!(stats, deser);

        info!("TEST PASS: test_serialization_roundtrip");
    }

    #[test]
    fn test_load_average_serialization() {
        init_test_logging();
        info!("TEST START: test_load_average_serialization");

        let load = LoadAverage {
            one_min: 1.23,
            five_min: 2.34,
            fifteen_min: 3.45,
            running_processes: 5,
            total_processes: 500,
        };

        let json = serde_json::to_string(&load).expect("serialization should succeed");
        let deser: LoadAverage =
            serde_json::from_str(&json).expect("deserialization should succeed");

        assert!((load.one_min - deser.one_min).abs() < 0.001);
        assert!((load.five_min - deser.five_min).abs() < 0.001);
        assert!((load.fifteen_min - deser.fifteen_min).abs() < 0.001);
        assert_eq!(load.running_processes, deser.running_processes);

        info!("TEST PASS: test_load_average_serialization");
    }

    #[test]
    fn test_num_cpus() {
        init_test_logging();
        info!("TEST START: test_num_cpus");

        let cpus = num_cpus();
        info!(num_cpus = cpus, "RESULT: detected CPU count");

        // Should be at least 1
        assert!(cpus >= 1);

        info!("TEST PASS: test_num_cpus");
    }

    #[test]
    fn test_full_percent_range() {
        init_test_logging();
        info!("TEST START: test_full_percent_range");

        // Test 0% CPU (all idle)
        let prev_idle = CpuStats {
            idle: 1000,
            ..Default::default()
        };
        let curr_idle = CpuStats {
            idle: 2000,
            ..Default::default()
        };
        let percent_idle = CpuStats::calculate_percent(&prev_idle, &curr_idle);
        info!(percent = percent_idle, "RESULT: 0% CPU (all idle)");
        assert!((percent_idle - 0.0).abs() < 0.1);

        // Test 100% CPU (no idle time)
        let prev_busy = CpuStats {
            user: 1000,
            idle: 0,
            ..Default::default()
        };
        let curr_busy = CpuStats {
            user: 2000,
            idle: 0,
            ..Default::default()
        };
        let percent_busy = CpuStats::calculate_percent(&prev_busy, &curr_busy);
        info!(percent = percent_busy, "RESULT: 100% CPU (no idle)");
        assert!((percent_busy - 100.0).abs() < 0.1);

        info!("TEST PASS: test_full_percent_range");
    }

    #[test]
    fn test_read_from_proc_on_linux() {
        init_test_logging();
        info!("TEST START: test_read_from_proc_on_linux");

        // This test only runs on Linux
        #[cfg(target_os = "linux")]
        {
            let stats = CpuStats::read_from_proc();
            assert!(stats.is_ok(), "Should read /proc/stat on Linux");

            let stats = stats.unwrap();
            info!(
                user = stats.user,
                idle = stats.idle,
                total = stats.total(),
                "RESULT: read real /proc/stat"
            );

            // Sanity checks
            assert!(stats.total() > 0, "Total should be positive");
            assert!(stats.idle > 0, "Idle should be positive");
        }

        #[cfg(not(target_os = "linux"))]
        {
            info!("SKIP: Not on Linux, skipping /proc/stat test");
        }

        info!("TEST PASS: test_read_from_proc_on_linux");
    }

    #[test]
    fn test_loadavg_from_proc_on_linux() {
        init_test_logging();
        info!("TEST START: test_loadavg_from_proc_on_linux");

        #[cfg(target_os = "linux")]
        {
            let load = LoadAverage::read_from_proc();
            assert!(load.is_ok(), "Should read /proc/loadavg on Linux");

            let load = load.unwrap();
            info!(
                one_min = load.one_min,
                five_min = load.five_min,
                fifteen_min = load.fifteen_min,
                "RESULT: read real /proc/loadavg"
            );

            // Sanity checks - load average should be non-negative
            assert!(load.one_min >= 0.0);
            assert!(load.five_min >= 0.0);
            assert!(load.fifteen_min >= 0.0);
        }

        #[cfg(not(target_os = "linux"))]
        {
            info!("SKIP: Not on Linux, skipping /proc/loadavg test");
        }

        info!("TEST PASS: test_loadavg_from_proc_on_linux");
    }
}
