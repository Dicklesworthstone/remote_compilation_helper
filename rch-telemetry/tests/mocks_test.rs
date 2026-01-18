//! Tests for the mock infrastructure module.

mod mocks;

use std::time::Duration;

#[test]
fn test_mock_clock_advance() {
    let clock = mocks::MockClock::new();
    assert_eq!(clock.elapsed(), Duration::ZERO);

    clock.advance(Duration::from_secs(1));
    assert_eq!(clock.elapsed(), Duration::from_secs(1));

    clock.advance(Duration::from_millis(500));
    assert_eq!(clock.elapsed(), Duration::from_millis(1500));
}

#[test]
fn test_mock_clock_reset() {
    let clock = mocks::MockClock::new();
    clock.advance(Duration::from_secs(10));
    clock.reset();
    assert_eq!(clock.elapsed(), Duration::ZERO);
}

#[test]
fn test_mock_clock_set_elapsed() {
    let clock = mocks::MockClock::new();
    clock.set_elapsed(Duration::from_secs(5));
    assert_eq!(clock.elapsed(), Duration::from_secs(5));
}

#[test]
fn test_mock_filesystem_write_read() {
    let fs = mocks::MockFileSystem::new();
    let data = vec![1u8; 1024 * 1024]; // 1 MB

    let write_time = fs.write("/test/file.bin", &data);
    assert!(write_time > Duration::ZERO);

    let (read_data, read_time) = fs.read("/test/file.bin").unwrap();
    assert_eq!(read_data, data);
    assert!(read_time > Duration::ZERO);
}

#[test]
fn test_mock_filesystem_missing_file() {
    let fs = mocks::MockFileSystem::new();
    assert!(fs.read("/nonexistent").is_none());
}

#[test]
fn test_mock_filesystem_throughput() {
    let stats = mocks::MockFileStats {
        write_throughput_bps: 100_000_000, // 100 MB/s
        read_throughput_bps: 100_000_000,
        ..Default::default()
    };
    let fs = mocks::MockFileSystem::with_stats(stats);

    let data = vec![0u8; 100_000_000]; // 100 MB
    let write_time = fs.write("/test", &data);

    // Should take approximately 1 second at 100 MB/s
    assert!(write_time.as_secs_f64() > 0.9);
    assert!(write_time.as_secs_f64() < 1.1);
}

#[test]
fn test_mock_network_upload_download() {
    let network = mocks::MockNetwork::new();
    let bytes = 10 * 1024 * 1024; // 10 MB

    let (upload_mbps, upload_time) = network.upload(bytes);
    assert!(upload_mbps > 0.0);
    assert!(upload_time > Duration::ZERO);

    let (download_mbps, download_time) = network.download(bytes);
    assert!(download_mbps > 0.0);
    assert!(download_time > Duration::ZERO);
}

#[test]
fn test_mock_network_ping() {
    let stats = mocks::MockNetworkStats {
        latency_ms: 10.0,
        jitter_ms: 0.0, // No jitter for deterministic test
        ..Default::default()
    };
    let network = mocks::MockNetwork::with_stats(stats);

    let latency = network.ping();
    assert!((latency.as_secs_f64() * 1000.0 - 10.0).abs() < 0.1);
}

#[test]
fn test_mock_network_jitter() {
    let stats = mocks::MockNetworkStats {
        latency_ms: 10.0,
        jitter_ms: 5.0,
        ..Default::default()
    };
    let network = mocks::MockNetwork::with_stats(stats);

    let mut latencies = Vec::new();
    for _ in 0..10 {
        latencies.push(network.ping().as_secs_f64() * 1000.0);
    }

    // With jitter, we should see some variation
    let min = latencies.iter().cloned().fold(f64::INFINITY, f64::min);
    let max = latencies.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
    assert!(max - min > 0.0);
}

#[test]
fn test_mock_network_packet_loss() {
    let stats = mocks::MockNetworkStats {
        packet_loss_rate: 0.5, // 50% loss
        ..Default::default()
    };
    let network = mocks::MockNetwork::with_stats(stats);

    let mut lost = 0;
    for _ in 0..100 {
        if network.would_lose_packet() {
            lost += 1;
        }
    }

    // With 50% loss rate, we should see some losses (but not test exact count due to RNG)
    assert!(lost > 0);
    assert!(lost < 100);
}

#[test]
fn test_mock_network_no_packet_loss() {
    let stats = mocks::MockNetworkStats {
        packet_loss_rate: 0.0,
        ..Default::default()
    };
    let network = mocks::MockNetwork::with_stats(stats);

    for _ in 0..100 {
        assert!(!network.would_lose_packet());
    }
}
