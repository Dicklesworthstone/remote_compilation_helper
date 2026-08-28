//! System metrics collection modules.
//!
//! This module provides collectors for various system metrics from /proc
//! filesystem (Linux) for worker telemetry.

pub mod cpu;
pub mod disk;
pub mod memory;
pub mod network;

use crate::collect::cpu::CpuTelemetry;
use crate::collect::disk::DiskCollector;
use crate::collect::memory::MemoryTelemetry;
use crate::collect::network::NetworkCollector;
use crate::protocol::WorkerTelemetry;
use anyhow::Result;
use std::time::{Duration, Instant};

pub fn resolve_worker_id(override_id: Option<String>) -> String {
    if let Some(id) = override_id {
        return id;
    }

    if let Ok(id) = std::env::var("RCH_WORKER_ID")
        && !id.trim().is_empty()
    {
        return id;
    }

    if let Ok(id) = std::env::var("HOSTNAME")
        && !id.trim().is_empty()
    {
        return id;
    }

    "unknown-worker".to_string()
}

pub fn collect_telemetry(
    sample_ms: u64,
    include_disk: bool,
    include_network: bool,
    worker_id: String,
) -> Result<WorkerTelemetry> {
    // Darwin has no /proc filesystem, so the Linux collectors below would
    // abort on the very first read and the telemetry command would exit 1 on
    // every poll — leaving macOS workers permanently in `telemetry_gap` /
    // "degraded" on the daemon side. Use the platform-native collectors
    // instead: real load/memory figures, with the Linux-only subsystems
    // (per-core deltas, disk IO, network, PSI) honestly absent rather than
    // fabricated.
    if cfg!(target_os = "macos") {
        return collect_telemetry_darwin(worker_id);
    }
    // Same failure mode on Windows (bd-jdcxd): no /proc, so the first read
    // exited 1 and rchd's telemetry poller re-opened the worker circuit on
    // every cycle, leaving Windows workers permanently "unreachable".
    if cfg!(target_os = "windows") {
        return collect_telemetry_windows(worker_id);
    }

    let start = Instant::now();

    let (_baseline_cpu, prev_stats, prev_per_core) = CpuTelemetry::collect(None, None)?;

    let mut disk_collector = if include_disk {
        let mut collector = DiskCollector::new();
        let _ = collector.collect()?; // warm-up sample
        Some(collector)
    } else {
        None
    };

    let mut network_collector = if include_network {
        let mut collector = NetworkCollector::new();
        let _ = collector.collect()?; // warm-up sample
        Some(collector)
    } else {
        None
    };

    if sample_ms > 0 {
        std::thread::sleep(Duration::from_millis(sample_ms));
    }

    let (cpu, _curr_stats, _curr_per_core) =
        CpuTelemetry::collect(Some(&prev_stats), Some(&prev_per_core))?;
    let memory = MemoryTelemetry::collect()?;

    let disk = match disk_collector.as_mut() {
        Some(collector) => collector.collect()?,
        None => None,
    };

    let network = match network_collector.as_mut() {
        Some(collector) => Some(collector.collect()?),
        None => None,
    };

    let duration_ms = start.elapsed().as_millis() as u64;

    Ok(WorkerTelemetry::new(
        worker_id,
        cpu,
        memory,
        disk,
        network,
        duration_ms,
    ))
}

/// Darwin snapshot: portable CPU (loadavg-based) + memory collectors; the
/// disk and network subsystems are `None` (their fields are optional in the
/// wire protocol, and the daemon's pressure policy treats absent disk IO /
/// network figures as unknown rather than as a telemetry failure).
fn collect_telemetry_darwin(worker_id: String) -> Result<WorkerTelemetry> {
    let start = Instant::now();

    let cpu = cpu::collect_darwin()?;
    let memory = MemoryTelemetry::collect_darwin()?;

    let duration_ms = start.elapsed().as_millis() as u64;

    Ok(WorkerTelemetry::new(
        worker_id,
        cpu,
        memory,
        None,
        None,
        duration_ms,
    ))
}

/// One PowerShell/CIM round trip that yields every figure the Windows
/// collectors need, printed as a single whitespace-separated line:
///
/// ```text
/// <cpu load %> <total RAM kB> <free RAM kB> <pagefile MB> <pagefile used MB> <process count>
/// ```
///
/// Spawning PowerShell costs ~1-2s on a laptop, so everything is gathered in
/// a single invocation. Nulls (no pagefile, no load counter) are cast to zero
/// inside the script so the line always has six numeric fields.
const WINDOWS_CIM_SAMPLE_SCRIPT: &str = "\
$c=[double]((Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average); \
$o=Get-CimInstance Win32_OperatingSystem; \
$p=@(Get-CimInstance Win32_PageFileUsage); \
$a=[uint64](($p | Measure-Object -Property AllocatedBaseSize -Sum).Sum); \
$u=[uint64](($p | Measure-Object -Property CurrentUsage -Sum).Sum); \
\"$c $($o.TotalVisibleMemorySize) $($o.FreePhysicalMemory) $a $u $(@(Get-Process).Count)\"";

/// Parsed output of [`WINDOWS_CIM_SAMPLE_SCRIPT`].
#[derive(Debug, Clone, PartialEq)]
pub struct WindowsSystemSample {
    pub cpu_load_percent: f64,
    pub total_memory_kb: u64,
    pub free_memory_kb: u64,
    pub pagefile_total_mb: u64,
    pub pagefile_used_mb: u64,
    pub process_count: u32,
}

impl WindowsSystemSample {
    /// Parse the six-field sample line. Any missing or non-numeric field
    /// yields `None` so a malformed shell response is a visible failure, not a
    /// zeroed snapshot the pressure policy would mistake for an idle host.
    pub fn parse(line: &str) -> Option<Self> {
        let mut parts = line.split_whitespace();
        let cpu_load_percent = parts.next()?.parse::<f64>().ok()?;
        let total_memory_kb = parts.next()?.parse::<u64>().ok()?;
        let free_memory_kb = parts.next()?.parse::<u64>().ok()?;
        let pagefile_total_mb = parts.next()?.parse::<u64>().ok()?;
        let pagefile_used_mb = parts.next()?.parse::<u64>().ok()?;
        let process_count = parts.next()?.parse::<u32>().ok()?;
        if parts.next().is_some() || total_memory_kb == 0 {
            return None;
        }
        Some(Self {
            cpu_load_percent,
            total_memory_kb,
            free_memory_kb,
            pagefile_total_mb,
            pagefile_used_mb,
            process_count,
        })
    }
}

/// Run the CIM sample script through the first PowerShell that exists
/// (Windows PowerShell 5.1 ships with every supported Windows; `pwsh` is the
/// optional newer install).
fn windows_cim_sample_output() -> Result<String> {
    let mut last_spawn_error = None;
    for program in ["powershell", "pwsh"] {
        match std::process::Command::new(program)
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                WINDOWS_CIM_SAMPLE_SCRIPT,
            ])
            .output()
        {
            Ok(output) if output.status.success() => {
                return Ok(String::from_utf8_lossy(&output.stdout).into_owned());
            }
            Ok(output) => {
                anyhow::bail!(
                    "{program} CIM sample exited with {}: {}",
                    output.status,
                    String::from_utf8_lossy(&output.stderr).trim()
                );
            }
            Err(e) => last_spawn_error = Some(e),
        }
    }
    Err(anyhow::anyhow!(
        "no PowerShell binary available for the Windows telemetry sample: {last_spawn_error:?}"
    ))
}

/// Windows snapshot: CPU load and memory from a single CIM query; disk IO and
/// network stay `None` exactly as on Darwin.
fn collect_telemetry_windows(worker_id: String) -> Result<WorkerTelemetry> {
    let start = Instant::now();

    let raw = windows_cim_sample_output()?;
    let sample = WindowsSystemSample::parse(&raw)
        .ok_or_else(|| anyhow::anyhow!("unparseable Windows CIM sample line: {:?}", raw.trim()))?;

    let cpu = cpu::collect_windows(sample.cpu_load_percent, sample.process_count);
    let memory = MemoryTelemetry::from_windows_counters(
        sample.total_memory_kb,
        sample.free_memory_kb,
        sample.pagefile_total_mb,
        sample.pagefile_used_mb,
    );

    let duration_ms = start.elapsed().as_millis() as u64;

    Ok(WorkerTelemetry::new(
        worker_id,
        cpu,
        memory,
        None,
        None,
        duration_ms,
    ))
}

#[cfg(test)]
mod tests {
    use super::WindowsSystemSample;

    #[test]
    fn windows_sample_parses_real_cim_line() {
        let sample = WindowsSystemSample::parse("1 16353432 10111800 26330 646 287\r\n")
            .expect("real CIM output must parse");
        assert_eq!(
            sample,
            WindowsSystemSample {
                cpu_load_percent: 1.0,
                total_memory_kb: 16_353_432,
                free_memory_kb: 10_111_800,
                pagefile_total_mb: 26_330,
                pagefile_used_mb: 646,
                process_count: 287,
            }
        );
    }

    #[test]
    fn windows_sample_rejects_malformed_lines() {
        assert!(WindowsSystemSample::parse("").is_none());
        assert!(WindowsSystemSample::parse("1 16353432 10111800 26330 646").is_none());
        assert!(WindowsSystemSample::parse("1 16353432 10111800 26330 646 287 extra").is_none());
        assert!(WindowsSystemSample::parse("nan? 16353432 10111800 26330 646 287").is_none());
        // Zero total RAM can only be a broken query, never a real host.
        assert!(WindowsSystemSample::parse("1 0 0 0 0 287").is_none());
    }

    /// Regression for bd-jdcxd: on Windows the telemetry snapshot must
    /// succeed (previously the /proc/stat read exited 1 on every daemon poll
    /// and rchd re-opened the worker circuit, leaving Windows workers
    /// permanently "unreachable").
    #[cfg(target_os = "windows")]
    #[test]
    fn collect_telemetry_succeeds_on_windows() {
        let telemetry = super::collect_telemetry(0, true, true, "test-worker".to_string())
            .expect("telemetry collection must succeed on Windows");
        assert_eq!(telemetry.worker_id, "test-worker");
        assert!(telemetry.cpu.num_cores >= 1);
        assert!(telemetry.memory.total_gb > 0.0);
        assert!(telemetry.disk.is_none());
        assert!(telemetry.network.is_none());
        telemetry.to_json().expect("snapshot should serialize");
    }

    /// Regression for issue #39: on macOS the telemetry snapshot must succeed
    /// (previously the first /proc read aborted the whole collection and
    /// `rch-wkr telemetry` exited 1 on every daemon poll, leaving macOS
    /// workers permanently in `telemetry_gap` / degraded).
    #[cfg(target_os = "macos")]
    #[test]
    fn collect_telemetry_succeeds_on_macos() {
        let telemetry = super::collect_telemetry(0, true, true, "test-worker".to_string())
            .expect("telemetry collection must succeed on macOS");
        assert_eq!(telemetry.worker_id, "test-worker");
        assert!(telemetry.cpu.num_cores >= 1);
        assert!(telemetry.memory.total_gb > 0.0);
        // Linux-only subsystems are honestly absent, not fabricated.
        assert!(telemetry.disk.is_none());
        assert!(telemetry.network.is_none());
        // And the snapshot serializes for the wire.
        telemetry.to_json().expect("snapshot should serialize");
    }
}
