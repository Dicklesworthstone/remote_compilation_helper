use std::sync::Once;
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

static INIT: Once = Once::new();

pub fn init_test_logging() {
    INIT.call_once(|| {
        let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("debug"));

        tracing_subscriber::registry()
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
            .init();
    });
}

#[allow(dead_code)]
pub fn fixture(name: &str) -> &'static str {
    match name {
        "proc_stat_sample.txt" => include_str!("../fixtures/proc_stat_sample.txt"),
        "proc_stat_idle.txt" => include_str!("../fixtures/proc_stat_idle.txt"),
        "proc_stat_busy.txt" => include_str!("../fixtures/proc_stat_busy.txt"),
        "proc_meminfo_sample.txt" => include_str!("../fixtures/proc_meminfo_sample.txt"),
        "proc_meminfo_low.txt" => include_str!("../fixtures/proc_meminfo_low.txt"),
        "proc_diskstats_sample.txt" => include_str!("../fixtures/proc_diskstats_sample.txt"),
        "proc_net_dev_sample.txt" => include_str!("../fixtures/proc_net_dev_sample.txt"),
        other => panic!("unknown fixture: {other}"),
    }
}
