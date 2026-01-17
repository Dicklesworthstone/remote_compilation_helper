mod common;

use common::{fixture, init_test_logging};
use rch_telemetry::collect::memory::{MemoryInfo, MemoryPressureStall};
use tracing::{debug, info};

#[test]
fn test_parse_meminfo_fixture() {
    init_test_logging();
    info!(test = "test_parse_meminfo_fixture", phase = "setup");

    let content = fixture("proc_meminfo_sample.txt");
    let mem = MemoryInfo::parse(content).expect("meminfo parse");

    info!(
        test = "test_parse_meminfo_fixture",
        phase = "assert",
        total_kb = mem.total_kb,
        free_kb = mem.free_kb,
        available_kb = mem.available_kb
    );
    assert_eq!(mem.total_kb, 16384000);
    assert_eq!(mem.free_kb, 8192000);
    assert_eq!(mem.available_kb, 10240000);

    info!(
        test = "test_parse_meminfo_fixture",
        phase = "complete",
        status = "passed"
    );
}

#[test]
fn test_low_mem_pressure_score() {
    init_test_logging();
    info!(test = "test_low_mem_pressure_score", phase = "setup");

    let content = fixture("proc_meminfo_low.txt");
    let mem = MemoryInfo::parse(content).expect("meminfo parse");

    let pressure = mem.pressure_score();
    debug!(
        test = "test_low_mem_pressure_score",
        phase = "execute",
        used_pct = mem.used_percent(),
        swap_used_gb = mem.swap_used_gb(),
        dirty_kb = mem.dirty_kb
    );

    info!(
        test = "test_low_mem_pressure_score",
        phase = "assert",
        pressure = pressure
    );
    assert!(pressure > 70.0, "expected high pressure, got {pressure}");

    info!(
        test = "test_low_mem_pressure_score",
        phase = "complete",
        status = "passed"
    );
}

#[test]
fn test_parse_memory_psi() {
    init_test_logging();
    info!(test = "test_parse_memory_psi", phase = "setup");

    let content = "some avg10=1.00 avg60=0.50 avg300=0.10 total=123\nfull avg10=0.20 avg60=0.10 avg300=0.05 total=45";
    let psi = MemoryPressureStall::parse(content).expect("psi parse");

    info!(
        test = "test_parse_memory_psi",
        phase = "assert",
        some10 = psi.some_avg10,
        full10 = psi.full_avg10
    );
    assert!((psi.some_avg10 - 1.00).abs() < 0.001);
    assert!((psi.full_avg10 - 0.20).abs() < 0.001);

    info!(
        test = "test_parse_memory_psi",
        phase = "complete",
        status = "passed"
    );
}
