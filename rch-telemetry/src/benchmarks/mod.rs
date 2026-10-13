//! Benchmarks for measuring worker performance.
//!
//! Synthetic CPU, memory, disk and network workloads complement real compiler
//! workloads. Paired serial/parallel compilation is an explicit, longer-running
//! diagnostic; callers must arrange idle/admitted execution before running it.

pub mod compilation;
pub mod cpu;
pub mod disk;
pub mod error;
pub mod memory;
pub mod network;
pub mod parallel_compilation;
pub mod report;
pub mod retry;

pub use compilation::{
    CompilationBenchmark, CompilationBenchmarkError, CompilationBenchmarkResult,
};
pub use cpu::{CpuBenchmark, CpuBenchmarkResult};
pub use disk::{DiskBenchmark, DiskBenchmarkResult};
pub use error::BenchmarkError;
pub use memory::{MemoryBenchmark, MemoryBenchmarkResult};
pub use network::{
    NetworkBenchmark, NetworkBenchmarkError, NetworkBenchmarkResult, WorkerConnection,
    calculate_latency_stats,
};
pub use parallel_compilation::{ParallelCompilationBenchmark, ParallelCompilationResult};
pub use retry::{BenchmarkRetryPolicy, RetryableError, run_with_retry};
