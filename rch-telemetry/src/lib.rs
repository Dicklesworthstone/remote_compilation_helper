//! Telemetry collection for Remote Compilation Helper workers.
//!
//! This crate provides utilities for collecting system metrics from worker
//! machines, including CPU, memory, disk I/O, and network statistics.

#![forbid(unsafe_code)]

pub mod collect;

pub use collect::memory::{MemoryInfo, MemoryPressureStall, MemoryTelemetry};
