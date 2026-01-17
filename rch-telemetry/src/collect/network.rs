//! Network metrics collection from /proc/net/dev.
//!
//! Reads Linux /proc/net/dev to track network interface statistics including
//! bytes transferred, packet counts, errors, and drops for worker telemetry.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;
use tracing::{debug, info, warn};

/// Errors that can occur during network metrics collection.
#[derive(Error, Debug)]
pub enum NetworkError {
    #[error("failed to read /proc/net/dev: {0}")]
    ReadError(#[from] std::io::Error),

    #[error("failed to parse /proc/net/dev: invalid format at line '{0}'")]
    ParseError(String),

    #[error("no network interfaces found")]
    NoInterfaces,
}

/// Raw network interface statistics parsed from /proc/net/dev.
///
/// Each interface has receive (rx) and transmit (tx) counters.
/// All byte values are cumulative since boot.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetDevStats {
    /// Interface name (e.g., "eth0", "ens5").
    pub interface: String,
    /// Bytes received.
    pub rx_bytes: u64,
    /// Packets received.
    pub rx_packets: u64,
    /// Receive errors.
    pub rx_errors: u64,
    /// Receive packets dropped.
    pub rx_dropped: u64,
    /// Bytes transmitted.
    pub tx_bytes: u64,
    /// Packets transmitted.
    pub tx_packets: u64,
    /// Transmit errors.
    pub tx_errors: u64,
    /// Transmit packets dropped.
    pub tx_dropped: u64,
}

impl NetDevStats {
    /// Read all network interface statistics from /proc/net/dev.
    pub fn read_from_proc() -> Result<Vec<Self>, NetworkError> {
        let content = std::fs::read_to_string("/proc/net/dev")?;
        Self::parse_all(&content)
    }

    /// Parse /proc/net/dev content into a list of interface statistics.
    ///
    /// Format:
    /// ```text
    /// Inter-|   Receive                                                |  Transmit
    ///  face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    ///   eth0: 12345678   12345    0    0    0     0          0         0 87654321   54321    0    0    0     0       0          0
    /// ```
    pub fn parse_all(content: &str) -> Result<Vec<Self>, NetworkError> {
        let mut stats = Vec::new();

        for line in content.lines().skip(2) {
            // Skip header lines
            if let Some(stat) = Self::parse_line(line)? {
                stats.push(stat);
            }
        }

        if stats.is_empty() {
            return Err(NetworkError::NoInterfaces);
        }

        Ok(stats)
    }

    /// Parse a single line from /proc/net/dev.
    fn parse_line(line: &str) -> Result<Option<Self>, NetworkError> {
        let line = line.trim();
        if line.is_empty() {
            return Ok(None);
        }

        // Split interface name from stats
        let (interface, rest) = line
            .split_once(':')
            .ok_or_else(|| NetworkError::ParseError(line.to_string()))?;

        let interface = interface.trim().to_string();

        // Parse numeric fields
        let values: Vec<u64> = rest
            .split_whitespace()
            .filter_map(|s| s.parse::<u64>().ok())
            .collect();

        // /proc/net/dev has 16 fields: 8 for receive, 8 for transmit
        // We only need the first 4 of each (bytes, packets, errs, drop)
        if values.len() < 16 {
            debug!(
                interface = %interface,
                field_count = values.len(),
                "Skipping interface with incomplete stats"
            );
            return Ok(None);
        }

        Ok(Some(Self {
            interface,
            rx_bytes: values[0],
            rx_packets: values[1],
            rx_errors: values[2],
            rx_dropped: values[3],
            tx_bytes: values[8],
            tx_packets: values[9],
            tx_errors: values[10],
            tx_dropped: values[11],
        }))
    }

    /// Check if this interface is a physical interface (not virtual).
    ///
    /// Filters out:
    /// - Loopback (lo)
    /// - Docker/container bridges (docker*, br-*, veth*)
    /// - Virtual interfaces (virbr*, vnet*)
    /// - Tunnel interfaces (tun*, tap*)
    /// - Bonding slaves (bond*)
    pub fn is_physical(&self) -> bool {
        let name = &self.interface;

        // Explicit loopback filter
        if name == "lo" {
            return false;
        }

        // Common virtual interface prefixes
        const VIRTUAL_PREFIXES: &[&str] = &[
            "docker",
            "br-",
            "veth",
            "virbr",
            "vnet",
            "tun",
            "tap",
            "bond",
            "dummy",
            "gre",
            "sit",
            "ip6tnl",
            "ip6gre",
            "vxlan",
            "geneve",
            "wg", // WireGuard
            "tailscale",
            "utun",
        ];

        for prefix in VIRTUAL_PREFIXES {
            if name.starts_with(prefix) {
                return false;
            }
        }

        true
    }

    /// Total errors (rx + tx).
    pub fn total_errors(&self) -> u64 {
        self.rx_errors.saturating_add(self.tx_errors)
    }

    /// Total dropped packets (rx + tx).
    pub fn total_dropped(&self) -> u64 {
        self.rx_dropped.saturating_add(self.tx_dropped)
    }

    /// Total bytes transferred (rx + tx).
    pub fn total_bytes(&self) -> u64 {
        self.rx_bytes.saturating_add(self.tx_bytes)
    }
}

/// Calculated network metrics with throughput rates.
///
/// Throughput is calculated from the delta between two snapshots.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkMetrics {
    /// Interface name.
    pub interface: String,
    /// Receive throughput in Mbps.
    pub rx_mbps: f64,
    /// Transmit throughput in Mbps.
    pub tx_mbps: f64,
    /// Combined throughput in Mbps.
    pub total_mbps: f64,
    /// Receive packet rate (packets/second).
    pub rx_pps: f64,
    /// Transmit packet rate (packets/second).
    pub tx_pps: f64,
    /// Error rate (errors/second).
    pub error_rate: f64,
    /// Drop rate (drops/second).
    pub drop_rate: f64,
    /// Cumulative bytes received.
    pub rx_bytes_total: u64,
    /// Cumulative bytes transmitted.
    pub tx_bytes_total: u64,
}

impl NetworkMetrics {
    /// Calculate metrics from two snapshots taken at different times.
    ///
    /// `prev` is the earlier snapshot, `curr` is the later snapshot.
    /// `duration_secs` is the time between snapshots.
    pub fn from_delta(prev: &NetDevStats, curr: &NetDevStats, duration_secs: f64) -> Self {
        if duration_secs <= 0.0 {
            return Self::zero(&curr.interface, curr);
        }

        // Calculate byte deltas (handle counter wraps)
        let rx_bytes_delta = curr.rx_bytes.saturating_sub(prev.rx_bytes);
        let tx_bytes_delta = curr.tx_bytes.saturating_sub(prev.tx_bytes);
        let rx_packets_delta = curr.rx_packets.saturating_sub(prev.rx_packets);
        let tx_packets_delta = curr.tx_packets.saturating_sub(prev.tx_packets);
        let errors_delta = curr.total_errors().saturating_sub(prev.total_errors());
        let dropped_delta = curr.total_dropped().saturating_sub(prev.total_dropped());

        // Convert bytes/sec to Mbps (megabits per second)
        // 1 byte = 8 bits, 1 Mbps = 1,000,000 bits/sec
        let bytes_to_mbps =
            |bytes: u64| -> f64 { (bytes as f64 * 8.0) / (duration_secs * 1_000_000.0) };

        let rx_mbps = bytes_to_mbps(rx_bytes_delta);
        let tx_mbps = bytes_to_mbps(tx_bytes_delta);

        Self {
            interface: curr.interface.clone(),
            rx_mbps,
            tx_mbps,
            total_mbps: rx_mbps + tx_mbps,
            rx_pps: rx_packets_delta as f64 / duration_secs,
            tx_pps: tx_packets_delta as f64 / duration_secs,
            error_rate: errors_delta as f64 / duration_secs,
            drop_rate: dropped_delta as f64 / duration_secs,
            rx_bytes_total: curr.rx_bytes,
            tx_bytes_total: curr.tx_bytes,
        }
    }

    /// Create zero metrics for an interface.
    fn zero(interface: &str, stats: &NetDevStats) -> Self {
        Self {
            interface: interface.to_string(),
            rx_mbps: 0.0,
            tx_mbps: 0.0,
            total_mbps: 0.0,
            rx_pps: 0.0,
            tx_pps: 0.0,
            error_rate: 0.0,
            drop_rate: 0.0,
            rx_bytes_total: stats.rx_bytes,
            tx_bytes_total: stats.tx_bytes,
        }
    }

    /// Check if this interface has significant activity.
    pub fn has_activity(&self) -> bool {
        self.total_mbps > 0.001 || self.rx_pps > 0.1 || self.tx_pps > 0.1
    }
}

/// Aggregated network telemetry snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkTelemetry {
    /// Timestamp of the telemetry collection.
    pub timestamp: DateTime<Utc>,
    /// Per-interface metrics (physical interfaces only).
    pub interfaces: Vec<NetworkMetrics>,
    /// Total receive throughput across all physical interfaces (Mbps).
    pub total_rx_mbps: f64,
    /// Total transmit throughput across all physical interfaces (Mbps).
    pub total_tx_mbps: f64,
    /// Combined throughput across all physical interfaces (Mbps).
    pub total_throughput_mbps: f64,
    /// Total error rate across all physical interfaces (errors/sec).
    pub total_error_rate: f64,
    /// Total drop rate across all physical interfaces (drops/sec).
    pub total_drop_rate: f64,
    /// Number of physical interfaces detected.
    pub interface_count: usize,
}

impl NetworkTelemetry {
    /// Collect network telemetry from two snapshots.
    ///
    /// Only includes physical interfaces (filters out virtual/container interfaces).
    pub fn from_snapshots(prev: &[NetDevStats], curr: &[NetDevStats], duration_secs: f64) -> Self {
        let timestamp = Utc::now();

        // Build a map of previous stats by interface name
        let prev_map: HashMap<&str, &NetDevStats> =
            prev.iter().map(|s| (s.interface.as_str(), s)).collect();

        // Calculate metrics for each physical interface
        let interfaces: Vec<NetworkMetrics> = curr
            .iter()
            .filter(|s| s.is_physical())
            .filter_map(|curr_stat| {
                prev_map.get(curr_stat.interface.as_str()).map(|prev_stat| {
                    NetworkMetrics::from_delta(prev_stat, curr_stat, duration_secs)
                })
            })
            .collect();

        // Aggregate totals
        let total_rx_mbps: f64 = interfaces.iter().map(|m| m.rx_mbps).sum();
        let total_tx_mbps: f64 = interfaces.iter().map(|m| m.tx_mbps).sum();
        let total_error_rate: f64 = interfaces.iter().map(|m| m.error_rate).sum();
        let total_drop_rate: f64 = interfaces.iter().map(|m| m.drop_rate).sum();

        let telemetry = Self {
            timestamp,
            interface_count: interfaces.len(),
            interfaces,
            total_rx_mbps,
            total_tx_mbps,
            total_throughput_mbps: total_rx_mbps + total_tx_mbps,
            total_error_rate,
            total_drop_rate,
        };

        debug!(
            rx_mbps = %telemetry.total_rx_mbps,
            tx_mbps = %telemetry.total_tx_mbps,
            interfaces = %telemetry.interface_count,
            "Network telemetry collected"
        );

        // Warn on high error/drop rates
        if telemetry.total_error_rate > 1.0 {
            warn!(
                error_rate = %telemetry.total_error_rate,
                "High network error rate detected"
            );
        }

        if telemetry.total_drop_rate > 10.0 {
            warn!(
                drop_rate = %telemetry.total_drop_rate,
                "High network drop rate detected"
            );
        }

        telemetry
    }

    /// Create telemetry from current stats only (no rate calculation).
    ///
    /// Useful for initial snapshot or when previous data is unavailable.
    pub fn from_current(stats: &[NetDevStats]) -> Self {
        let timestamp = Utc::now();

        let interfaces: Vec<NetworkMetrics> = stats
            .iter()
            .filter(|s| s.is_physical())
            .map(|s| NetworkMetrics::zero(&s.interface, s))
            .collect();

        Self {
            timestamp,
            interface_count: interfaces.len(),
            interfaces,
            total_rx_mbps: 0.0,
            total_tx_mbps: 0.0,
            total_throughput_mbps: 0.0,
            total_error_rate: 0.0,
            total_drop_rate: 0.0,
        }
    }

    /// Collect a single snapshot of raw network statistics.
    ///
    /// Use this to gather data for later comparison.
    pub fn collect_snapshot() -> Result<Vec<NetDevStats>, NetworkError> {
        NetDevStats::read_from_proc()
    }
}

/// Network telemetry collector that maintains state for rate calculations.
#[derive(Debug)]
pub struct NetworkCollector {
    /// Previous snapshot for delta calculation.
    prev_snapshot: Option<(DateTime<Utc>, Vec<NetDevStats>)>,
}

impl NetworkCollector {
    /// Create a new network collector.
    pub fn new() -> Self {
        Self {
            prev_snapshot: None,
        }
    }

    /// Collect network telemetry, calculating rates from previous snapshot.
    pub fn collect(&mut self) -> Result<NetworkTelemetry, NetworkError> {
        let now = Utc::now();
        let curr_stats = NetDevStats::read_from_proc()?;

        let telemetry = match &self.prev_snapshot {
            Some((prev_time, prev_stats)) => {
                let duration_secs = (now - *prev_time).num_milliseconds() as f64 / 1000.0;
                info!(
                    duration_secs = %duration_secs,
                    prev_interfaces = prev_stats.len(),
                    curr_interfaces = curr_stats.len(),
                    "Calculating network metrics from delta"
                );
                NetworkTelemetry::from_snapshots(prev_stats, &curr_stats, duration_secs)
            }
            None => {
                info!("First collection - no rate data available");
                NetworkTelemetry::from_current(&curr_stats)
            }
        };

        // Update stored snapshot
        self.prev_snapshot = Some((now, curr_stats));

        Ok(telemetry)
    }

    /// Reset the collector, discarding previous snapshot.
    pub fn reset(&mut self) {
        self.prev_snapshot = None;
    }
}

impl Default for NetworkCollector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

    fn init_test_logging() {
        let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("debug"));
        let _ = tracing_subscriber::registry()
            .with(
                fmt::layer()
                    .with_test_writer()
                    .with_target(true)
                    .with_file(true)
                    .with_line_number(true)
                    .with_thread_ids(true)
                    .json(),
            )
            .with(filter)
            .try_init();
    }

    const SAMPLE_PROC_NET_DEV: &str = r#"Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 12345678   12345    0    0    0     0          0         0 12345678   12345    0    0    0     0       0          0
  eth0: 98765432   54321   10    5    0     0          0         0 87654321   43210    2    1    0     0       0          0
docker0:  1000000    1000    0    0    0     0          0         0   500000     500    0    0    0     0       0          0
  ens5: 50000000   25000    0    0    0     0          0         0 40000000   20000    0    0    0     0       0          0
"#;

    #[test]
    fn test_parse_proc_net_dev() {
        init_test_logging();
        info!("TEST START: test_parse_proc_net_dev");

        info!("INPUT: sample /proc/net/dev with 4 interfaces");

        let stats = NetDevStats::parse_all(SAMPLE_PROC_NET_DEV).expect("parsing should succeed");

        info!(count = stats.len(), "RESULT: parsed interface count");

        assert_eq!(stats.len(), 4);

        // Check eth0 stats
        let eth0 = stats.iter().find(|s| s.interface == "eth0").unwrap();
        info!(
            rx_bytes = eth0.rx_bytes,
            tx_bytes = eth0.tx_bytes,
            rx_errors = eth0.rx_errors,
            "RESULT: eth0 stats"
        );

        assert_eq!(eth0.rx_bytes, 98765432);
        assert_eq!(eth0.rx_packets, 54321);
        assert_eq!(eth0.rx_errors, 10);
        assert_eq!(eth0.rx_dropped, 5);
        assert_eq!(eth0.tx_bytes, 87654321);
        assert_eq!(eth0.tx_packets, 43210);
        assert_eq!(eth0.tx_errors, 2);
        assert_eq!(eth0.tx_dropped, 1);

        info!("TEST PASS: test_parse_proc_net_dev");
    }

    #[test]
    fn test_physical_interface_filter() {
        init_test_logging();
        info!("TEST START: test_physical_interface_filter");

        let stats = NetDevStats::parse_all(SAMPLE_PROC_NET_DEV).expect("parsing should succeed");

        for stat in &stats {
            let is_physical = stat.is_physical();
            info!(
                interface = %stat.interface,
                is_physical = is_physical,
                "RESULT: interface classification"
            );
        }

        // eth0 and ens5 should be physical
        assert!(
            stats
                .iter()
                .find(|s| s.interface == "eth0")
                .unwrap()
                .is_physical()
        );
        assert!(
            stats
                .iter()
                .find(|s| s.interface == "ens5")
                .unwrap()
                .is_physical()
        );

        // lo and docker0 should not be physical
        assert!(
            !stats
                .iter()
                .find(|s| s.interface == "lo")
                .unwrap()
                .is_physical()
        );
        assert!(
            !stats
                .iter()
                .find(|s| s.interface == "docker0")
                .unwrap()
                .is_physical()
        );

        info!("TEST PASS: test_physical_interface_filter");
    }

    #[test]
    fn test_virtual_interface_prefixes() {
        init_test_logging();
        info!("TEST START: test_virtual_interface_prefixes");

        let virtual_names = vec![
            "lo",
            "docker0",
            "br-abc123",
            "veth12345",
            "virbr0",
            "vnet0",
            "tun0",
            "tap0",
            "bond0",
            "dummy0",
            "wg0",
            "tailscale0",
        ];

        let physical_names = vec!["eth0", "ens5", "enp0s3", "em1", "wlan0"];

        for name in &virtual_names {
            let stat = NetDevStats {
                interface: name.to_string(),
                rx_bytes: 0,
                rx_packets: 0,
                rx_errors: 0,
                rx_dropped: 0,
                tx_bytes: 0,
                tx_packets: 0,
                tx_errors: 0,
                tx_dropped: 0,
            };
            info!(interface = %name, "Testing virtual interface");
            assert!(!stat.is_physical(), "{} should be virtual", name);
        }

        for name in &physical_names {
            let stat = NetDevStats {
                interface: name.to_string(),
                rx_bytes: 0,
                rx_packets: 0,
                rx_errors: 0,
                rx_dropped: 0,
                tx_bytes: 0,
                tx_packets: 0,
                tx_errors: 0,
                tx_dropped: 0,
            };
            info!(interface = %name, "Testing physical interface");
            assert!(stat.is_physical(), "{} should be physical", name);
        }

        info!("TEST PASS: test_virtual_interface_prefixes");
    }

    #[test]
    fn test_throughput_calculation() {
        init_test_logging();
        info!("TEST START: test_throughput_calculation");

        let prev = NetDevStats {
            interface: "eth0".to_string(),
            rx_bytes: 0,
            rx_packets: 0,
            rx_errors: 0,
            rx_dropped: 0,
            tx_bytes: 0,
            tx_packets: 0,
            tx_errors: 0,
            tx_dropped: 0,
        };

        // Simulate 125 MB received in 1 second = 1000 Mbps
        // 125,000,000 bytes * 8 bits/byte = 1,000,000,000 bits = 1000 Mbps
        let curr = NetDevStats {
            interface: "eth0".to_string(),
            rx_bytes: 125_000_000,
            rx_packets: 100_000,
            rx_errors: 0,
            rx_dropped: 0,
            tx_bytes: 62_500_000, // 500 Mbps
            tx_packets: 50_000,
            tx_errors: 0,
            tx_dropped: 0,
        };

        let metrics = NetworkMetrics::from_delta(&prev, &curr, 1.0);

        info!(
            rx_mbps = %metrics.rx_mbps,
            tx_mbps = %metrics.tx_mbps,
            total_mbps = %metrics.total_mbps,
            rx_pps = %metrics.rx_pps,
            "RESULT: calculated throughput"
        );

        assert!(
            (metrics.rx_mbps - 1000.0).abs() < 0.1,
            "rx_mbps should be ~1000"
        );
        assert!(
            (metrics.tx_mbps - 500.0).abs() < 0.1,
            "tx_mbps should be ~500"
        );
        assert!(
            (metrics.total_mbps - 1500.0).abs() < 0.1,
            "total_mbps should be ~1500"
        );
        assert!(
            (metrics.rx_pps - 100_000.0).abs() < 0.1,
            "rx_pps should be ~100000"
        );

        info!("TEST PASS: test_throughput_calculation");
    }

    #[test]
    fn test_throughput_with_duration() {
        init_test_logging();
        info!("TEST START: test_throughput_with_duration");

        let prev = NetDevStats {
            interface: "eth0".to_string(),
            rx_bytes: 0,
            rx_packets: 0,
            rx_errors: 0,
            rx_dropped: 0,
            tx_bytes: 0,
            tx_packets: 0,
            tx_errors: 0,
            tx_dropped: 0,
        };

        // 125 MB in 10 seconds = 100 Mbps
        let curr = NetDevStats {
            interface: "eth0".to_string(),
            rx_bytes: 125_000_000,
            rx_packets: 100_000,
            rx_errors: 5,
            rx_dropped: 2,
            tx_bytes: 0,
            tx_packets: 0,
            tx_errors: 0,
            tx_dropped: 0,
        };

        let metrics = NetworkMetrics::from_delta(&prev, &curr, 10.0);

        info!(
            rx_mbps = %metrics.rx_mbps,
            rx_pps = %metrics.rx_pps,
            error_rate = %metrics.error_rate,
            drop_rate = %metrics.drop_rate,
            "RESULT: calculated rates over 10 seconds"
        );

        assert!(
            (metrics.rx_mbps - 100.0).abs() < 0.1,
            "rx_mbps should be ~100"
        );
        assert!(
            (metrics.rx_pps - 10_000.0).abs() < 0.1,
            "rx_pps should be ~10000"
        );
        assert!(
            (metrics.error_rate - 0.5).abs() < 0.01,
            "error_rate should be ~0.5"
        );
        assert!(
            (metrics.drop_rate - 0.2).abs() < 0.01,
            "drop_rate should be ~0.2"
        );

        info!("TEST PASS: test_throughput_with_duration");
    }

    #[test]
    fn test_zero_duration() {
        init_test_logging();
        info!("TEST START: test_zero_duration");

        let prev = NetDevStats {
            interface: "eth0".to_string(),
            rx_bytes: 100,
            rx_packets: 10,
            rx_errors: 0,
            rx_dropped: 0,
            tx_bytes: 100,
            tx_packets: 10,
            tx_errors: 0,
            tx_dropped: 0,
        };

        let curr = NetDevStats {
            interface: "eth0".to_string(),
            rx_bytes: 200,
            rx_packets: 20,
            rx_errors: 0,
            rx_dropped: 0,
            tx_bytes: 200,
            tx_packets: 20,
            tx_errors: 0,
            tx_dropped: 0,
        };

        let metrics = NetworkMetrics::from_delta(&prev, &curr, 0.0);

        info!(
            rx_mbps = %metrics.rx_mbps,
            "RESULT: metrics with zero duration"
        );

        // Should return zeros without panic
        assert_eq!(metrics.rx_mbps, 0.0);
        assert_eq!(metrics.tx_mbps, 0.0);

        info!("TEST PASS: test_zero_duration");
    }

    #[test]
    fn test_counter_wrap() {
        init_test_logging();
        info!("TEST START: test_counter_wrap");

        let prev = NetDevStats {
            interface: "eth0".to_string(),
            rx_bytes: u64::MAX - 1000,
            rx_packets: 0,
            rx_errors: 0,
            rx_dropped: 0,
            tx_bytes: 0,
            tx_packets: 0,
            tx_errors: 0,
            tx_dropped: 0,
        };

        // Counter wrapped (current < previous)
        let curr = NetDevStats {
            interface: "eth0".to_string(),
            rx_bytes: 500,
            rx_packets: 0,
            rx_errors: 0,
            rx_dropped: 0,
            tx_bytes: 0,
            tx_packets: 0,
            tx_errors: 0,
            tx_dropped: 0,
        };

        let metrics = NetworkMetrics::from_delta(&prev, &curr, 1.0);

        info!(
            rx_mbps = %metrics.rx_mbps,
            "RESULT: metrics with counter wrap (saturating_sub should give 0)"
        );

        // saturating_sub handles wrap by returning 0
        assert_eq!(metrics.rx_mbps, 0.0);

        info!("TEST PASS: test_counter_wrap");
    }

    #[test]
    fn test_telemetry_from_snapshots() {
        init_test_logging();
        info!("TEST START: test_telemetry_from_snapshots");

        let prev = vec![
            NetDevStats {
                interface: "lo".to_string(),
                rx_bytes: 0,
                rx_packets: 0,
                rx_errors: 0,
                rx_dropped: 0,
                tx_bytes: 0,
                tx_packets: 0,
                tx_errors: 0,
                tx_dropped: 0,
            },
            NetDevStats {
                interface: "eth0".to_string(),
                rx_bytes: 0,
                rx_packets: 0,
                rx_errors: 0,
                rx_dropped: 0,
                tx_bytes: 0,
                tx_packets: 0,
                tx_errors: 0,
                tx_dropped: 0,
            },
        ];

        let curr = vec![
            NetDevStats {
                interface: "lo".to_string(),
                rx_bytes: 1000,
                rx_packets: 10,
                rx_errors: 0,
                rx_dropped: 0,
                tx_bytes: 1000,
                tx_packets: 10,
                tx_errors: 0,
                tx_dropped: 0,
            },
            NetDevStats {
                interface: "eth0".to_string(),
                rx_bytes: 125_000_000, // 1000 Mbps
                rx_packets: 100_000,
                rx_errors: 0,
                rx_dropped: 0,
                tx_bytes: 62_500_000, // 500 Mbps
                tx_packets: 50_000,
                tx_errors: 0,
                tx_dropped: 0,
            },
        ];

        let telemetry = NetworkTelemetry::from_snapshots(&prev, &curr, 1.0);

        info!(
            interface_count = telemetry.interface_count,
            total_rx_mbps = %telemetry.total_rx_mbps,
            total_tx_mbps = %telemetry.total_tx_mbps,
            "RESULT: telemetry from snapshots"
        );

        // Should only include eth0 (lo is filtered)
        assert_eq!(telemetry.interface_count, 1);
        assert!((telemetry.total_rx_mbps - 1000.0).abs() < 0.1);
        assert!((telemetry.total_tx_mbps - 500.0).abs() < 0.1);
        assert!((telemetry.total_throughput_mbps - 1500.0).abs() < 0.1);

        info!("TEST PASS: test_telemetry_from_snapshots");
    }

    #[test]
    fn test_telemetry_from_current() {
        init_test_logging();
        info!("TEST START: test_telemetry_from_current");

        let stats = NetDevStats::parse_all(SAMPLE_PROC_NET_DEV).expect("parsing should succeed");
        let telemetry = NetworkTelemetry::from_current(&stats);

        info!(
            interface_count = telemetry.interface_count,
            "RESULT: telemetry from current (no rates)"
        );

        // Should include eth0 and ens5 (physical), but not lo or docker0
        assert_eq!(telemetry.interface_count, 2);
        assert_eq!(telemetry.total_rx_mbps, 0.0);
        assert_eq!(telemetry.total_tx_mbps, 0.0);

        info!("TEST PASS: test_telemetry_from_current");
    }

    #[test]
    fn test_total_errors_and_dropped() {
        init_test_logging();
        info!("TEST START: test_total_errors_and_dropped");

        let stat = NetDevStats {
            interface: "eth0".to_string(),
            rx_bytes: 0,
            rx_packets: 0,
            rx_errors: 10,
            rx_dropped: 5,
            tx_bytes: 0,
            tx_packets: 0,
            tx_errors: 3,
            tx_dropped: 2,
        };

        info!(
            total_errors = stat.total_errors(),
            total_dropped = stat.total_dropped(),
            total_bytes = stat.total_bytes(),
            "RESULT: aggregated totals"
        );

        assert_eq!(stat.total_errors(), 13);
        assert_eq!(stat.total_dropped(), 7);
        assert_eq!(stat.total_bytes(), 0);

        info!("TEST PASS: test_total_errors_and_dropped");
    }

    #[test]
    fn test_empty_proc_net_dev() {
        init_test_logging();
        info!("TEST START: test_empty_proc_net_dev");

        let content = r#"Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
"#;

        info!("INPUT: /proc/net/dev with no interfaces");

        let result = NetDevStats::parse_all(content);
        assert!(result.is_err());

        match result {
            Err(NetworkError::NoInterfaces) => {
                info!("RESULT: got expected NoInterfaces error");
            }
            _ => panic!("expected NoInterfaces error"),
        }

        info!("TEST PASS: test_empty_proc_net_dev");
    }

    #[test]
    fn test_serialization_roundtrip() {
        init_test_logging();
        info!("TEST START: test_serialization_roundtrip");

        let stat = NetDevStats {
            interface: "eth0".to_string(),
            rx_bytes: 12345678,
            rx_packets: 12345,
            rx_errors: 10,
            rx_dropped: 5,
            tx_bytes: 87654321,
            tx_packets: 54321,
            tx_errors: 2,
            tx_dropped: 1,
        };

        let json = serde_json::to_string(&stat).expect("serialization should succeed");
        info!(json_len = json.len(), "RESULT: serialized to JSON");

        let deser: NetDevStats =
            serde_json::from_str(&json).expect("deserialization should succeed");

        assert_eq!(stat, deser);

        info!("TEST PASS: test_serialization_roundtrip");
    }

    #[test]
    fn test_metrics_has_activity() {
        init_test_logging();
        info!("TEST START: test_metrics_has_activity");

        let no_activity = NetworkMetrics {
            interface: "eth0".to_string(),
            rx_mbps: 0.0,
            tx_mbps: 0.0,
            total_mbps: 0.0,
            rx_pps: 0.0,
            tx_pps: 0.0,
            error_rate: 0.0,
            drop_rate: 0.0,
            rx_bytes_total: 0,
            tx_bytes_total: 0,
        };

        let with_activity = NetworkMetrics {
            interface: "eth0".to_string(),
            rx_mbps: 10.0,
            tx_mbps: 5.0,
            total_mbps: 15.0,
            rx_pps: 1000.0,
            tx_pps: 500.0,
            error_rate: 0.0,
            drop_rate: 0.0,
            rx_bytes_total: 1000000,
            tx_bytes_total: 500000,
        };

        info!(
            no_activity = no_activity.has_activity(),
            with_activity = with_activity.has_activity(),
            "RESULT: activity detection"
        );

        assert!(!no_activity.has_activity());
        assert!(with_activity.has_activity());

        info!("TEST PASS: test_metrics_has_activity");
    }

    #[test]
    fn test_collector_state() {
        init_test_logging();
        info!("TEST START: test_collector_state");

        let mut collector = NetworkCollector::new();

        assert!(collector.prev_snapshot.is_none());
        info!("RESULT: new collector has no previous snapshot");

        collector.reset();
        assert!(collector.prev_snapshot.is_none());
        info!("RESULT: reset clears previous snapshot");

        info!("TEST PASS: test_collector_state");
    }
}
