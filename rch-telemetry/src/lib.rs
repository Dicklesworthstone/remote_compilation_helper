//! Telemetry collection for Remote Compilation Helper workers.
//!
//! This crate provides utilities for collecting system metrics from worker
//! machines, including CPU, memory, disk I/O, and network statistics.
//!
//! ## Modules
//!
//! - [`collect`]: Real-time metrics collection from /proc filesystem
//! - [`benchmarks`]: Synthetic benchmarks for measuring worker performance

#![forbid(unsafe_code)]

pub mod benchmarks;
pub mod collect;

pub use benchmarks::cpu::{CpuBenchmark, CpuBenchmarkResult};
pub use benchmarks::memory::{MemoryBenchmark, MemoryBenchmarkResult};
pub use collect::disk::{
    DiskCollector, DiskError, DiskMetrics, DiskStats, DiskTelemetry, FileDescriptorStats,
};
pub use collect::memory::{MemoryInfo, MemoryPressureStall, MemoryTelemetry};
pub use collect::network::{
    NetDevStats, NetworkCollector, NetworkError, NetworkMetrics, NetworkTelemetry,
};
