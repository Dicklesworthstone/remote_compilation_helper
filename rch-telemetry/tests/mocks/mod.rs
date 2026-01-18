//! Mock infrastructure for deterministic benchmark testing.
//!
//! This module provides mock implementations for testing benchmark code
//! without relying on real hardware characteristics. These mocks enable:
//! - Deterministic timing for reproducible tests
//! - Simulated I/O operations with configurable characteristics
//! - Network simulation for testing without real connections
//!
//! # Usage
//!
//! ```rust,ignore
//! use mocks::MockClock;
//!
//! let clock = MockClock::new();
//! clock.advance(Duration::from_secs(1));
//! assert_eq!(clock.elapsed().as_secs(), 1);
//! ```

use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// A mock clock for deterministic timing in tests.
///
/// Unlike `std::time::Instant`, this clock can be advanced manually,
/// allowing tests to verify timing-related behavior without waiting.
#[derive(Debug, Clone)]
pub struct MockClock {
    /// Current simulated time in nanoseconds since creation.
    elapsed_nanos: Arc<AtomicU64>,
}

impl MockClock {
    /// Create a new mock clock starting at time zero.
    pub fn new() -> Self {
        Self {
            elapsed_nanos: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Advance the clock by the given duration.
    pub fn advance(&self, duration: Duration) {
        let nanos = duration.as_nanos() as u64;
        self.elapsed_nanos.fetch_add(nanos, Ordering::SeqCst);
    }

    /// Get the total elapsed time since the clock was created.
    pub fn elapsed(&self) -> Duration {
        Duration::from_nanos(self.elapsed_nanos.load(Ordering::SeqCst))
    }

    /// Reset the clock to zero.
    pub fn reset(&self) {
        self.elapsed_nanos.store(0, Ordering::SeqCst);
    }

    /// Set the clock to a specific elapsed time.
    pub fn set_elapsed(&self, duration: Duration) {
        let nanos = duration.as_nanos() as u64;
        self.elapsed_nanos.store(nanos, Ordering::SeqCst);
    }
}

impl Default for MockClock {
    fn default() -> Self {
        Self::new()
    }
}

/// Simulated file characteristics for mock filesystem operations.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct MockFileStats {
    /// Simulated write throughput in bytes per second.
    pub write_throughput_bps: u64,
    /// Simulated read throughput in bytes per second.
    pub read_throughput_bps: u64,
    /// Simulated seek latency in microseconds.
    pub seek_latency_us: u64,
    /// Simulated fsync latency in microseconds.
    pub fsync_latency_us: u64,
}

impl Default for MockFileStats {
    fn default() -> Self {
        // Default to typical SSD characteristics
        Self {
            write_throughput_bps: 500_000_000,  // 500 MB/s
            read_throughput_bps: 550_000_000,   // 550 MB/s
            seek_latency_us: 100,               // 100µs seek
            fsync_latency_us: 500,              // 0.5ms fsync
        }
    }
}

/// A mock filesystem for testing disk I/O benchmarks.
///
/// This allows simulating various storage characteristics without
/// requiring actual disk operations.
#[derive(Debug)]
pub struct MockFileSystem {
    /// Configuration for simulated file operations.
    pub stats: MockFileStats,
    /// In-memory file storage.
    files: RefCell<HashMap<String, Vec<u8>>>,
    /// Clock for timing simulations.
    clock: MockClock,
}

#[allow(dead_code)]
impl MockFileSystem {
    /// Create a new mock filesystem with default characteristics.
    pub fn new() -> Self {
        Self {
            stats: MockFileStats::default(),
            files: RefCell::new(HashMap::new()),
            clock: MockClock::new(),
        }
    }

    /// Create a mock filesystem with custom characteristics.
    pub fn with_stats(stats: MockFileStats) -> Self {
        Self {
            stats,
            files: RefCell::new(HashMap::new()),
            clock: MockClock::new(),
        }
    }

    /// Simulate writing data to a file.
    ///
    /// Returns the simulated time taken for the write operation.
    pub fn write(&self, path: &str, data: &[u8]) -> Duration {
        let bytes = data.len() as u64;
        let duration_secs = bytes as f64 / self.stats.write_throughput_bps as f64;
        let duration = Duration::from_secs_f64(duration_secs);

        self.files.borrow_mut().insert(path.to_string(), data.to_vec());
        self.clock.advance(duration);

        duration
    }

    /// Simulate reading data from a file.
    ///
    /// Returns the data and simulated time taken for the read operation.
    pub fn read(&self, path: &str) -> Option<(Vec<u8>, Duration)> {
        let files = self.files.borrow();
        let data = files.get(path)?.clone();
        let bytes = data.len() as u64;
        let duration_secs = bytes as f64 / self.stats.read_throughput_bps as f64;
        let duration = Duration::from_secs_f64(duration_secs);

        self.clock.advance(duration);

        Some((data, duration))
    }

    /// Simulate an fsync operation.
    pub fn fsync(&self) -> Duration {
        let duration = Duration::from_micros(self.stats.fsync_latency_us);
        self.clock.advance(duration);
        duration
    }

    /// Simulate a seek operation.
    pub fn seek(&self) -> Duration {
        let duration = Duration::from_micros(self.stats.seek_latency_us);
        self.clock.advance(duration);
        duration
    }

    /// Get the total simulated elapsed time.
    pub fn elapsed(&self) -> Duration {
        self.clock.elapsed()
    }

    /// Reset the filesystem state.
    pub fn reset(&self) {
        self.files.borrow_mut().clear();
        self.clock.reset();
    }
}

impl Default for MockFileSystem {
    fn default() -> Self {
        Self::new()
    }
}

/// Simulated network characteristics for mock network operations.
#[derive(Debug, Clone)]
pub struct MockNetworkStats {
    /// Simulated upload bandwidth in bits per second.
    pub upload_bps: u64,
    /// Simulated download bandwidth in bits per second.
    pub download_bps: u64,
    /// Simulated round-trip latency in milliseconds.
    pub latency_ms: f64,
    /// Simulated jitter (latency variation) in milliseconds.
    pub jitter_ms: f64,
    /// Packet loss rate (0.0 to 1.0).
    pub packet_loss_rate: f64,
}

impl Default for MockNetworkStats {
    fn default() -> Self {
        // Default to good network characteristics
        Self {
            upload_bps: 100_000_000,     // 100 Mbps upload
            download_bps: 100_000_000,   // 100 Mbps download
            latency_ms: 10.0,            // 10ms latency
            jitter_ms: 2.0,              // 2ms jitter
            packet_loss_rate: 0.0,       // No packet loss
        }
    }
}

/// A mock network connection for testing network benchmarks.
///
/// This allows simulating various network conditions without
/// requiring actual network connections.
#[derive(Debug)]
pub struct MockNetwork {
    /// Configuration for simulated network operations.
    pub stats: MockNetworkStats,
    /// Clock for timing simulations.
    clock: MockClock,
    /// Random number generator state for jitter simulation.
    rng_state: RefCell<u64>,
}

#[allow(dead_code)]
impl MockNetwork {
    /// Create a new mock network with default characteristics.
    pub fn new() -> Self {
        Self {
            stats: MockNetworkStats::default(),
            clock: MockClock::new(),
            rng_state: RefCell::new(12345),
        }
    }

    /// Create a mock network with custom characteristics.
    pub fn with_stats(stats: MockNetworkStats) -> Self {
        Self {
            stats,
            clock: MockClock::new(),
            rng_state: RefCell::new(12345),
        }
    }

    /// Generate a deterministic "random" value for jitter.
    fn next_jitter(&self) -> f64 {
        let mut state = self.rng_state.borrow_mut();
        // LCG random number generator
        *state = state.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
        // Map to [-1.0, 1.0]
        (*state as f64 / u64::MAX as f64) * 2.0 - 1.0
    }

    /// Simulate uploading data.
    ///
    /// Returns the simulated throughput in Mbps and time taken.
    pub fn upload(&self, bytes: u64) -> (f64, Duration) {
        let bits = bytes * 8;
        let base_secs = bits as f64 / self.stats.upload_bps as f64;
        let latency_secs = (self.stats.latency_ms + self.next_jitter() * self.stats.jitter_ms) / 1000.0;
        let total_secs = base_secs + latency_secs.max(0.0);

        let duration = Duration::from_secs_f64(total_secs);
        self.clock.advance(duration);

        let throughput_mbps = (bits as f64 / total_secs) / 1_000_000.0;
        (throughput_mbps, duration)
    }

    /// Simulate downloading data.
    ///
    /// Returns the simulated throughput in Mbps and time taken.
    pub fn download(&self, bytes: u64) -> (f64, Duration) {
        let bits = bytes * 8;
        let base_secs = bits as f64 / self.stats.download_bps as f64;
        let latency_secs = (self.stats.latency_ms + self.next_jitter() * self.stats.jitter_ms) / 1000.0;
        let total_secs = base_secs + latency_secs.max(0.0);

        let duration = Duration::from_secs_f64(total_secs);
        self.clock.advance(duration);

        let throughput_mbps = (bits as f64 / total_secs) / 1_000_000.0;
        (throughput_mbps, duration)
    }

    /// Simulate a latency ping.
    ///
    /// Returns the simulated round-trip time.
    pub fn ping(&self) -> Duration {
        let jitter = self.next_jitter() * self.stats.jitter_ms;
        let latency_ms = (self.stats.latency_ms + jitter).max(0.1);
        let duration = Duration::from_secs_f64(latency_ms / 1000.0);
        self.clock.advance(duration);
        duration
    }

    /// Simulate whether a packet would be lost.
    pub fn would_lose_packet(&self) -> bool {
        if self.stats.packet_loss_rate <= 0.0 {
            return false;
        }
        let random = (self.next_jitter() + 1.0) / 2.0; // Map to [0, 1]
        random < self.stats.packet_loss_rate
    }

    /// Get the total simulated elapsed time.
    pub fn elapsed(&self) -> Duration {
        self.clock.elapsed()
    }

    /// Reset the network state.
    pub fn reset(&self) {
        self.clock.reset();
        *self.rng_state.borrow_mut() = 12345;
    }
}

impl Default for MockNetwork {
    fn default() -> Self {
        Self::new()
    }
}
