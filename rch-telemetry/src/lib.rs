//! Telemetry collection for Remote Compilation Helper workers.
//!
//! This crate provides utilities for collecting system metrics from worker
//! machines, including CPU, memory, disk I/O, and network statistics.
//!
//! ## Modules
//!
//! - [`collect`]: Real-time metrics collection from /proc filesystem
//! - [`benchmarks`]: Synthetic benchmarks for measuring worker performance
//! - [`speedscore`]: Unified performance scoring combining all benchmarks

#![forbid(unsafe_code)]

pub mod benchmarks;
pub mod collect;
pub mod protocol;
pub mod speedscore;
#[cfg(feature = "storage")]
pub mod storage;

pub use rch_common::{LogConfig, LogFormat, LoggingGuards, init_logging};

pub use benchmarks::compilation::{
    CompilationBenchmark, CompilationBenchmarkError, CompilationBenchmarkResult,
};
pub use benchmarks::cpu::{CpuBenchmark, CpuBenchmarkResult};
pub use benchmarks::disk::{DiskBenchmark, DiskBenchmarkResult};
pub use benchmarks::memory::{MemoryBenchmark, MemoryBenchmarkResult};
pub use benchmarks::network::{
    NetworkBenchmark, NetworkBenchmarkError, NetworkBenchmarkResult, WorkerConnection,
    calculate_latency_stats,
};
pub use collect::disk::{
    DiskCollector, DiskError, DiskMetrics, DiskStats, DiskTelemetry, FileDescriptorStats,
};
pub use collect::memory::{MemoryInfo, MemoryPressureStall, MemoryTelemetry};
pub use collect::network::{
    NetDevStats, NetworkCollector, NetworkError, NetworkMetrics, NetworkTelemetry,
};
pub use protocol::{TestRunRecord, TestRunStats};
pub use speedscore::{
    BenchmarkConditions, BenchmarkResults, SPEEDSCORE_VERSION, SpeedScore, SpeedScoreWeights,
    calculate_speedscore,
};
#[cfg(feature = "storage")]
pub use storage::{MaintenanceStats, SpeedScoreHistoryPage, StorageStats, TelemetryStorage};
