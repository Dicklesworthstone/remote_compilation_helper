mod common;

use common::{fixture, init_test_logging};
use rch_telemetry::collect::disk::{DiskMetrics, DiskStats};
use tracing::{debug, info};

#[test]
fn test_parse_diskstats_fixture() {
    init_test_logging();
    info!(test = "test_parse_diskstats_fixture", phase = "setup");

    let content = fixture("proc_diskstats_sample.txt");
    let stats = DiskStats::parse(content).expect("diskstats parse");

    info!(
        test = "test_parse_diskstats_fixture",
        phase = "assert",
        device_count = stats.len()
    );
    assert!(stats.contains_key("sda"));
    assert!(stats.contains_key("nvme0n1"));
    assert!(!stats.contains_key("sda1"));

    let sda = stats.get("sda").expect("sda stats");
    assert_eq!(sda.sectors_read, 1_000_000);
    assert_eq!(sda.sectors_written, 500_000);

    info!(
        test = "test_parse_diskstats_fixture",
        phase = "complete",
        status = "passed"
    );
}

#[test]
fn test_disk_metrics_from_delta() {
    init_test_logging();
    info!(test = "test_disk_metrics_from_delta", phase = "setup");

    let prev = DiskStats {
        device: "sda".to_string(),
        reads_completed: 1000,
        sectors_read: 100_000,
        writes_completed: 500,
        sectors_written: 50_000,
        time_io_ms: 10_000,
        ..DiskStats::default()
    };

    let curr = DiskStats {
        device: "sda".to_string(),
        reads_completed: 1100,
        sectors_read: 120_000,
        writes_completed: 550,
        sectors_written: 60_000,
        time_io_ms: 10_800,
        ..DiskStats::default()
    };

    let metrics = DiskMetrics::from_delta(&prev, &curr, 1000);

    debug!(
        test = "test_disk_metrics_from_delta",
        phase = "execute",
        iops = metrics.iops,
        util_pct = metrics.io_utilization_pct
    );

    info!(
        test = "test_disk_metrics_from_delta",
        phase = "assert",
        iops = metrics.iops
    );
    assert!((metrics.iops - 150.0).abs() < 0.01);

    info!(
        test = "test_disk_metrics_from_delta",
        phase = "complete",
        status = "passed"
    );
}
