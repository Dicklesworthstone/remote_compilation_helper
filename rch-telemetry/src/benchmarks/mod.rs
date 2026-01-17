//! Synthetic benchmarks for measuring worker performance.
//!
//! This module provides pure-Rust benchmark implementations for measuring
//! worker computational capabilities across multiple dimensions: CPU,
//! memory bandwidth, disk I/O, and network throughput.
//!
//! Benchmarks are designed to be:
//! - **Reproducible**: Same result on same hardware regardless of system state
//! - **Fast**: Complete in <5 seconds to minimize scheduling disruption
//! - **Representative**: Exercise operations similar to actual compilation workloads

pub mod compilation;
pub mod cpu;
pub mod disk;
pub mod memory;
pub mod network;

pub use compilation::{
    CompilationBenchmark, CompilationBenchmarkError, CompilationBenchmarkResult,
};
pub use cpu::{CpuBenchmark, CpuBenchmarkResult};
pub use disk::{DiskBenchmark, DiskBenchmarkResult};
pub use memory::{MemoryBenchmark, MemoryBenchmarkResult};
pub use network::{
    NetworkBenchmark, NetworkBenchmarkError, NetworkBenchmarkResult, WorkerConnection,
    calculate_latency_stats,
};
