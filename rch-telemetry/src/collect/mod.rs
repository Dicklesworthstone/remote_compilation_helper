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

#[cfg(test)]
mod tests {
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
