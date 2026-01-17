mod common;

use common::{fixture, init_test_logging};
use rch_telemetry::collect::network::{NetDevStats, NetworkMetrics};
use tracing::{debug, info};

#[test]
fn test_parse_net_dev_fixture() {
    init_test_logging();
    info!(test = "test_parse_net_dev_fixture", phase = "setup");

    let content = fixture("proc_net_dev_sample.txt");
    let stats = NetDevStats::parse_all(content).expect("net/dev parse");

    info!(
        test = "test_parse_net_dev_fixture",
        phase = "assert",
        iface_count = stats.len()
    );
    assert_eq!(stats.len(), 4);

    let eth0 = stats.iter().find(|s| s.interface == "eth0").expect("eth0");
    assert_eq!(eth0.rx_bytes, 98765432);
    assert_eq!(eth0.tx_bytes, 87654321);

    info!(
        test = "test_parse_net_dev_fixture",
        phase = "complete",
        status = "passed"
    );
}

#[test]
fn test_physical_interface_filter_fixture() {
    init_test_logging();
    info!(
        test = "test_physical_interface_filter_fixture",
        phase = "setup"
    );

    let content = fixture("proc_net_dev_sample.txt");
    let stats = NetDevStats::parse_all(content).expect("net/dev parse");

    let physical: Vec<_> = stats.iter().filter(|s| s.is_physical()).collect();
    info!(
        test = "test_physical_interface_filter_fixture",
        phase = "assert",
        physical_count = physical.len()
    );

    assert!(physical.iter().any(|s| s.interface == "eth0"));
    assert!(physical.iter().any(|s| s.interface == "ens5"));
    assert!(!physical.iter().any(|s| s.interface == "lo"));
    assert!(!physical.iter().any(|s| s.interface == "docker0"));

    info!(
        test = "test_physical_interface_filter_fixture",
        phase = "complete",
        status = "passed"
    );
}

#[test]
fn test_network_metrics_from_delta() {
    init_test_logging();
    info!(test = "test_network_metrics_from_delta", phase = "setup");

    let prev = NetDevStats {
        interface: "eth0".to_string(),
        rx_bytes: 1_000_000,
        tx_bytes: 2_000_000,
        rx_packets: 1000,
        tx_packets: 2000,
        rx_errors: 0,
        tx_errors: 0,
        rx_dropped: 0,
        tx_dropped: 0,
    };

    let curr = NetDevStats {
        interface: "eth0".to_string(),
        rx_bytes: 2_000_000,
        tx_bytes: 3_000_000,
        rx_packets: 2000,
        tx_packets: 3000,
        rx_errors: 2,
        tx_errors: 1,
        rx_dropped: 1,
        tx_dropped: 1,
    };

    let metrics = NetworkMetrics::from_delta(&prev, &curr, 1.0);

    debug!(
        test = "test_network_metrics_from_delta",
        phase = "execute",
        rx_mbps = metrics.rx_mbps,
        tx_mbps = metrics.tx_mbps,
        error_rate = metrics.error_rate,
        drop_rate = metrics.drop_rate
    );

    info!(
        test = "test_network_metrics_from_delta",
        phase = "assert",
        total_mbps = metrics.total_mbps
    );
    assert!(metrics.total_mbps > 0.0);
    assert!((metrics.error_rate - 3.0).abs() < 0.01);
    assert!((metrics.drop_rate - 2.0).abs() < 0.01);

    info!(
        test = "test_network_metrics_from_delta",
        phase = "complete",
        status = "passed"
    );
}
