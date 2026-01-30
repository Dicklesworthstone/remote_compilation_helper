//! System metrics collection modules.
//!
//! This module provides collectors for various system metrics from /proc
//! filesystem (Linux) for worker telemetry.

pub mod cpu;
pub mod disk;
pub mod memory;
pub mod network;

use anyhow::Result;
use std::time::{Duration, Instant};
use crate::protocol::WorkerTelemetry;
use crate::collect::cpu::CpuTelemetry;
use crate::collect::disk::DiskCollector;
use crate::collect::memory::MemoryTelemetry;
use crate::collect::network::NetworkCollector;

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
