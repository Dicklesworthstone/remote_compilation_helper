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

pub mod cpu;
pub mod memory;

pub use cpu::{CpuBenchmark, CpuBenchmarkResult};
pub use memory::{MemoryBenchmark, MemoryBenchmarkResult};
