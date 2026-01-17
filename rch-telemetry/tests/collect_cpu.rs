mod common;

use common::{fixture, init_test_logging};
use rch_telemetry::collect::cpu::{CpuPressureStall, CpuStats, LoadAverage, parse_per_core_stats};
use tracing::{debug, info};

#[test]
fn test_parse_proc_stat_fixture() {
    init_test_logging();
    info!(test = "test_parse_proc_stat_fixture", phase = "setup");

    let content = fixture("proc_stat_sample.txt");
    info!(test = "test_parse_proc_stat_fixture", phase = "execute");
    let stats = CpuStats::parse(content).expect("parsing should succeed");

    info!(
        test = "test_parse_proc_stat_fixture",
        phase = "assert",
        user = stats.user,
        nice = stats.nice,
        system = stats.system,
        idle = stats.idle
    );
    assert_eq!(stats.user, 10132153);
    assert_eq!(stats.nice, 290696);
    assert_eq!(stats.system, 3084719);
    assert_eq!(stats.idle, 46828483);

    info!(
        test = "test_parse_proc_stat_fixture",
        phase = "complete",
        status = "passed"
    );
}

#[test]
fn test_parse_per_core_stats_fixture() {
    init_test_logging();
    info!(test = "test_parse_per_core_stats_fixture", phase = "setup");

    let content = fixture("proc_stat_sample.txt");
    let cores = parse_per_core_stats(content).expect("parsing should succeed");

    info!(
        test = "test_parse_per_core_stats_fixture",
        phase = "assert",
        core_count = cores.len()
    );
    assert_eq!(cores.len(), 4);
    assert_eq!(cores[0].core_id, 0);
    assert_eq!(cores[3].core_id, 3);

    info!(
        test = "test_parse_per_core_stats_fixture",
        phase = "complete",
        status = "passed"
    );
}

#[test]
fn test_calculate_percent_idle_to_busy() {
    init_test_logging();
    info!(
        test = "test_calculate_percent_idle_to_busy",
        phase = "setup"
    );

    let idle = CpuStats::parse(fixture("proc_stat_idle.txt")).expect("idle parse");
    let busy = CpuStats::parse(fixture("proc_stat_busy.txt")).expect("busy parse");

    debug!(
        test = "test_calculate_percent_idle_to_busy",
        phase = "execute",
        idle_total = idle.total(),
        busy_total = busy.total(),
        idle_active = idle.active(),
        busy_active = busy.active()
    );

    let pct = CpuStats::calculate_percent(&idle, &busy);

    info!(
        test = "test_calculate_percent_idle_to_busy",
        phase = "assert",
        percent = pct
    );
    assert!((pct - 66.6667).abs() < 0.1, "expected ~66.7%, got {pct}");

    info!(
        test = "test_calculate_percent_idle_to_busy",
        phase = "complete",
        status = "passed"
    );
}

#[test]
fn test_parse_loadavg_basic() {
    init_test_logging();
    info!(test = "test_parse_loadavg_basic", phase = "setup");

    let content = "0.45 0.52 0.48 2/512 12345";
    let load = LoadAverage::parse(content).expect("loadavg parse");

    info!(
        test = "test_parse_loadavg_basic",
        phase = "assert",
        one_min = load.one_min,
        five_min = load.five_min,
        fifteen_min = load.fifteen_min,
        running = load.running_processes,
        total = load.total_processes
    );
    assert_eq!(load.one_min, 0.45);
    assert_eq!(load.five_min, 0.52);
    assert_eq!(load.fifteen_min, 0.48);
    assert_eq!(load.running_processes, 2);
    assert_eq!(load.total_processes, 512);

    info!(
        test = "test_parse_loadavg_basic",
        phase = "complete",
        status = "passed"
    );
}

#[test]
fn test_parse_cpu_psi() {
    init_test_logging();
    info!(test = "test_parse_cpu_psi", phase = "setup");

    let content = "some avg10=0.20 avg60=0.10 avg300=0.05 total=12345";
    let psi = CpuPressureStall::parse(content).expect("psi parse");

    info!(
        test = "test_parse_cpu_psi",
        phase = "assert",
        avg10 = psi.some_avg10,
        avg60 = psi.some_avg60,
        avg300 = psi.some_avg300
    );
    assert!((psi.some_avg10 - 0.20).abs() < 0.001);
    assert!((psi.some_avg60 - 0.10).abs() < 0.001);
    assert!((psi.some_avg300 - 0.05).abs() < 0.001);

    info!(
        test = "test_parse_cpu_psi",
        phase = "complete",
        status = "passed"
    );
}
