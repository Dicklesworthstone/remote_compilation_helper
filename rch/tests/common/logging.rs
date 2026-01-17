use tracing_subscriber::{fmt, EnvFilter};

pub fn init_test_logging() {
    let _ = fmt()
        .with_test_writer()
        .with_env_filter(
            EnvFilter::from_default_env()
                .add_directive("rch=debug".parse().unwrap()),
        )
        .try_init();
}

#[macro_export]
macro_rules! test_log {
    ($($arg:tt)*) => {
        tracing::info!(target: "test", $($arg)*);
    };
}
