//! Remote Compilation Helper - Local Daemon
//!
//! The daemon manages the worker fleet, tracks slot availability,
//! and provides the Unix socket API for the hook CLI.

#![forbid(unsafe_code)]

mod api;
mod benchmark_queue;
mod benchmark_scheduler;
mod config;
mod events;
mod health;
mod history;
mod http_api;
mod metrics;
mod selection;
mod self_test;
mod telemetry;
mod ui;
mod workers;

use anyhow::Result;
use chrono::{Duration as ChronoDuration, Local};
use clap::Parser;
use rch_common::{LogConfig, SelfTestConfig, init_logging};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UnixListener;
use tokio::sync::mpsc;
use tracing::{info, warn};

use benchmark_queue::BenchmarkQueue;
use events::EventBus;
use history::BuildHistory;
use rch_telemetry::storage::TelemetryStorage;
use selection::WorkerSelector;
use self_test::{DEFAULT_RESULT_CAPACITY, DEFAULT_RUN_CAPACITY, SelfTestHistory, SelfTestService};
use telemetry::{TelemetryPoller, TelemetryPollerConfig, TelemetryStore};
use ui::DaemonBanner;

#[derive(Parser)]
#[command(name = "rchd")]
#[command(author, version, about = "RCH daemon - worker fleet orchestration")]
struct Cli {
    /// Path to Unix socket
    #[arg(short, long, default_value_os_t = crate::config::default_socket_path())]
    socket: PathBuf,

    /// Path to workers configuration
    #[arg(short, long)]
    workers_config: Option<PathBuf>,

    /// Path to build history file (JSONL format)
    #[arg(long)]
    history_file: Option<PathBuf>,

    /// Maximum build history entries to retain
    #[arg(long, default_value = "100")]
    history_capacity: usize,

    /// Enable verbose output
    #[arg(short, long)]
    verbose: bool,

    /// Run in foreground (don't daemonize)
    #[arg(short, long)]
    foreground: bool,

    /// Port for HTTP metrics/health endpoints (0 to disable)
    #[arg(long, default_value = "9100")]
    metrics_port: u16,
}

/// Shared daemon context passed to all API handlers.
#[derive(Clone)]
pub struct DaemonContext {
    /// Worker pool.
    pub pool: workers::WorkerPool,
    /// Worker selector with cache tracking.
    pub worker_selector: Arc<WorkerSelector>,
    /// Build history.
    pub history: Arc<BuildHistory>,
    /// Telemetry store.
    pub telemetry: Arc<TelemetryStore>,
    /// Benchmark trigger queue.
    pub benchmark_queue: Arc<BenchmarkQueue>,
    /// Event broadcast bus.
    pub events: EventBus,
    /// Self-test service.
    pub self_test: Arc<SelfTestService>,
    /// Daemon start time.
    pub started_at: Instant,
    /// Socket path (for status reporting).
    pub socket_path: String,
    /// Daemon version.
    pub version: &'static str,
    /// Daemon process ID.
    pub pid: u32,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let startup_started = Instant::now();

    // Initialize logging
    let mut log_config = LogConfig::from_env("info");
    if cli.verbose {
        log_config = log_config.with_level("debug");
    }
    let _logging_guards = init_logging(&log_config)?;

    info!("Starting RCH daemon...");

    // Register Prometheus metrics
    if let Err(e) = metrics::register_metrics() {
        warn!("Failed to register some metrics: {}", e);
    }
    metrics::set_daemon_info(env!("CARGO_PKG_VERSION"));

    // Initialize OpenTelemetry tracing (optional, configured via env vars)
    let _otel_guard = match metrics::tracing::init_otel() {
        Ok(guard) => guard,
        Err(e) => {
            warn!("Failed to initialize OpenTelemetry: {}", e);
            None
        }
    };
    let otel_enabled = _otel_guard.is_some();

    // Load worker configuration
    let workers = config::load_workers(cli.workers_config.as_deref())?;
    let worker_count = workers.len();
    let total_slots: u32 = workers.iter().map(|worker| worker.total_slots).sum();
    info!("Loaded {} workers from configuration", workers.len());

    // Initialize worker pool
    let worker_pool = workers::WorkerPool::new();
    for worker_config in workers {
        info!(
            "Adding worker: {} ({}@{}, {} slots)",
            worker_config.id, worker_config.user, worker_config.host, worker_config.total_slots
        );
        worker_pool.add_worker(worker_config).await;
    }

    // Load RCH config for selection and circuit breaker settings
    let rch_config = match config::load_rch_config() {
        Ok(cfg) => cfg,
        Err(e) => {
            warn!("Failed to load RCH config: {}, using defaults", e);
            rch_common::RchConfig::default()
        }
    };

    // Initialize worker selector
    let worker_selector = Arc::new(WorkerSelector::with_config(
        rch_config.selection,
        rch_config.circuit,
    ));

    // Initialize build history
    let history = if let Some(ref path) = cli.history_file {
        if path.exists() {
            match BuildHistory::load_from_file(path, cli.history_capacity) {
                Ok(h) => {
                    info!("Loaded build history from {:?} ({} entries)", path, h.len());
                    Arc::new(h)
                }
                Err(e) => {
                    warn!("Failed to load history from {:?}: {}", path, e);
                    Arc::new(BuildHistory::new(cli.history_capacity).with_persistence(path.clone()))
                }
            }
        } else {
            info!("Creating new build history at {:?}", path);
            Arc::new(BuildHistory::new(cli.history_capacity).with_persistence(path.clone()))
        }
    } else {
        info!("Build history in-memory only (no persistence)");
        Arc::new(BuildHistory::new(cli.history_capacity))
    };

    // Initialize self-test config and history
    let self_test_config = match config::load_self_test_config() {
        Ok(cfg) => cfg,
        Err(e) => {
            warn!("Failed to load self-test config: {}", e);
            SelfTestConfig::default()
        }
    };

    let self_test_history = match self_test::default_history_path() {
        Ok(path) => match SelfTestHistory::load_from_file(
            &path,
            DEFAULT_RUN_CAPACITY,
            DEFAULT_RESULT_CAPACITY,
        ) {
            Ok(history) => Arc::new(history),
            Err(e) => {
                warn!("Failed to load self-test history from {:?}: {}", path, e);
                Arc::new(
                    SelfTestHistory::new(DEFAULT_RUN_CAPACITY, DEFAULT_RESULT_CAPACITY)
                        .with_persistence(path),
                )
            }
        },
        Err(e) => {
            warn!("Failed to determine self-test history path: {}", e);
            Arc::new(SelfTestHistory::new(
                DEFAULT_RUN_CAPACITY,
                DEFAULT_RESULT_CAPACITY,
            ))
        }
    };

    let self_test_service = Arc::new(SelfTestService::new(
        worker_pool.clone(),
        self_test_config,
        self_test_history,
    ));
    if let Err(e) = self_test_service.clone().start().await {
        warn!("Failed to start self-test scheduler: {}", e);
    }

    // Remove existing socket if present
    if cli.socket.exists() {
        std::fs::remove_file(&cli.socket)?;
    }

    // Create Unix socket listener
    let listener = UnixListener::bind(&cli.socket)?;
    info!("Listening on {:?}", cli.socket);

    // Create daemon context
    let telemetry_storage = match telemetry::default_telemetry_db_path() {
        Ok(path) => match TelemetryStorage::new(&path, 30, 24, 365, 100) {
            Ok(storage) => {
                info!("Telemetry storage initialized at {:?}", path);
                Some(Arc::new(storage))
            }
            Err(e) => {
                warn!(
                    "Failed to initialize telemetry storage at {:?}: {}",
                    path, e
                );
                None
            }
        },
        Err(e) => {
            warn!("Failed to resolve telemetry storage path: {}", e);
            None
        }
    };

    let event_bus = EventBus::new(256);

    let telemetry_store = Arc::new(TelemetryStore::with_event_bus(
        Duration::from_secs(300),
        telemetry_storage.clone(),
        event_bus.clone(),
    ));

    let benchmark_queue = Arc::new(BenchmarkQueue::new(ChronoDuration::minutes(5)));

    let context = DaemonContext {
        pool: worker_pool.clone(),
        worker_selector: worker_selector.clone(),
        history,
        telemetry: telemetry_store.clone(),
        benchmark_queue: benchmark_queue.clone(),
        events: event_bus.clone(),
        self_test: self_test_service.clone(),
        started_at: Instant::now(),
        socket_path: cli.socket.to_string_lossy().to_string(),
        version: env!("CARGO_PKG_VERSION"),
        pid: std::process::id(),
    };

    // Start health monitor
    let health_config = health::HealthConfig::default();
    let health_monitor = health::HealthMonitor::new(worker_pool.clone(), health_config);
    let health_handle = health_monitor.start();
    info!("Health monitor started");

    // Start telemetry poller
    let telemetry_poller = TelemetryPoller::new(
        worker_pool.clone(),
        telemetry_store.clone(),
        TelemetryPollerConfig::default(),
    );
    let _telemetry_handle = telemetry_poller.start();
    info!("Telemetry poller started");

    if let Some(storage) = telemetry_storage {
        let _maintenance = telemetry::start_storage_maintenance(storage);
        info!("Telemetry storage maintenance started");
    }

    // Start HTTP server for metrics/health endpoints (if enabled)
    let _http_handle = if cli.metrics_port > 0 {
        let http_state = http_api::HttpState {
            pool: worker_pool.clone(),
            version: env!("CARGO_PKG_VERSION"),
            started_at: context.started_at,
            pid: context.pid,
        };
        Some(http_api::start_server(cli.metrics_port, http_state).await)
    } else {
        info!("HTTP metrics endpoint disabled (port 0)");
        None
    };

    let commit_hash = option_env!("RCH_GIT_COMMIT")
        .or(option_env!("VERGEN_GIT_SHA"))
        .or(option_env!("GIT_COMMIT"))
        .or(option_env!("GITHUB_SHA"))
        .map(|value| value.to_string());

    let banner = DaemonBanner::new(
        env!("CARGO_PKG_VERSION"),
        option_env!("PROFILE").map(|value| value.to_string()),
        option_env!("TARGET").map(|value| value.to_string()),
        commit_hash,
        cli.socket.to_string_lossy().to_string(),
        worker_count,
        total_slots,
        cli.metrics_port,
        true,
        otel_enabled,
        context.pid,
        Local::now(),
        startup_started.elapsed(),
    );
    banner.show();

    // Shutdown channel
    let (shutdown_tx, mut shutdown_rx) = mpsc::channel(1);

    // Main accept loop
    loop {
        tokio::select! {
            accept_result = listener.accept() => {
                match accept_result {
                    Ok((stream, _addr)) => {
                        let ctx = context.clone();
                        let tx = shutdown_tx.clone();
                        tokio::spawn(async move {
                            if let Err(e) = api::handle_connection(stream, ctx, tx).await {
                                warn!("Connection error: {}", e);
                            }
                        });
                    }
                    Err(e) => {
                        warn!("Accept error: {}", e);
                    }
                }
            }
            _ = shutdown_rx.recv() => {
                info!("Shutdown signal received");
                break;
            }
        }
    }

    // Graceful shutdown
    info!("Stopping health monitor...");
    health_monitor.stop().await;
    let _ = health_handle.await;

    // Clean up socket
    if std::path::Path::new(&context.socket_path).exists() {
        let _ = std::fs::remove_file(&context.socket_path);
    }

    info!("Daemon stopped");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::self_test::{SelfTestHistory, SelfTestService};
    use crate::telemetry::TelemetryStore;
    use crate::{benchmark_queue::BenchmarkQueue, events::EventBus};
    use chrono::Duration as ChronoDuration;
    use rch_common::SelfTestConfig;
    use std::time::Duration;
    use std::time::Instant;

    fn make_test_telemetry() -> Arc<TelemetryStore> {
        Arc::new(TelemetryStore::new(Duration::from_secs(300), None))
    }

    fn init_test_logging() {
        let _ = tracing_subscriber::fmt()
            .with_test_writer()
            .with_max_level(tracing::Level::DEBUG)
            .try_init();
    }

    fn make_test_self_test(pool: workers::WorkerPool) -> Arc<SelfTestService> {
        let history = Arc::new(SelfTestHistory::new(
            crate::self_test::DEFAULT_RUN_CAPACITY,
            crate::self_test::DEFAULT_RESULT_CAPACITY,
        ));
        Arc::new(SelfTestService::new(
            pool,
            SelfTestConfig::default(),
            history,
        ))
    }

    // =========================================================================
    // test_daemon_context_creation - DaemonContext initialization tests
    // =========================================================================

    #[tokio::test]
    async fn test_daemon_context_creation_basic() {
        init_test_logging();

        let pool = workers::WorkerPool::new();
        let selector = Arc::new(WorkerSelector::new());
        let history = Arc::new(BuildHistory::new(100));
        let started_at = Instant::now();

        let context = DaemonContext {
            pool: pool.clone(),
            worker_selector: selector,
            history: history.clone(),
            telemetry: make_test_telemetry(),
            benchmark_queue: Arc::new(BenchmarkQueue::new(ChronoDuration::minutes(5))),
            events: EventBus::new(16),
            self_test: make_test_self_test(pool.clone()),
            started_at,
            socket_path: "/tmp/test.sock".to_string(),
            version: "0.1.0-test",
            pid: std::process::id(),
        };

        assert_eq!(context.socket_path, "/tmp/test.sock");
        assert_eq!(context.version, "0.1.0-test");
        assert!(context.pid > 0);
        assert!(context.pool.is_empty());
        assert!(context.history.is_empty());
    }

    #[tokio::test]
    async fn test_daemon_context_with_workers() {
        init_test_logging();

        let pool = workers::WorkerPool::new();

        // Add a worker
        let worker_config = rch_common::WorkerConfig {
            id: rch_common::WorkerId::new("test-worker"),
            host: "192.168.1.100".to_string(),
            user: "ubuntu".to_string(),
            identity_file: "~/.ssh/id_rsa".to_string(),
            total_slots: 8,
            priority: 100,
            tags: vec!["rust".to_string()],
        };
        pool.add_worker(worker_config).await;

        let selector = Arc::new(WorkerSelector::new());
        let history = Arc::new(BuildHistory::new(100));
        let started_at = Instant::now();

        let context = DaemonContext {
            pool: pool.clone(),
            worker_selector: selector,
            history,
            telemetry: make_test_telemetry(),
            benchmark_queue: Arc::new(BenchmarkQueue::new(ChronoDuration::minutes(5))),
            events: EventBus::new(16),
            self_test: make_test_self_test(pool.clone()),
            started_at,
            socket_path: rch_common::default_socket_path(),
            version: env!("CARGO_PKG_VERSION"),
            pid: std::process::id(),
        };

        assert_eq!(context.pool.len(), 1);
        let workers = context.pool.all_workers().await;
        assert_eq!(workers.len(), 1);
        assert_eq!(workers[0].config.read().await.id.as_str(), "test-worker");
    }

    #[tokio::test]
    async fn test_daemon_context_with_history() {
        init_test_logging();

        let pool = workers::WorkerPool::new();
        let selector = Arc::new(WorkerSelector::new());
        let history = Arc::new(BuildHistory::new(100));

        // Add a build record
        let record = rch_common::BuildRecord {
            id: 1,
            started_at: "2024-01-01T00:00:00Z".to_string(),
            completed_at: "2024-01-01T00:01:00Z".to_string(),
            project_id: "test-project".to_string(),
            worker_id: Some("worker-1".to_string()),
            command: "cargo build".to_string(),
            exit_code: 0,
            duration_ms: 60000,
            location: rch_common::BuildLocation::Remote,
            bytes_transferred: Some(1024),
        };
        history.record(record);

        let context = DaemonContext {
            pool: pool.clone(),
            worker_selector: selector,
            history,
            telemetry: make_test_telemetry(),
            benchmark_queue: Arc::new(BenchmarkQueue::new(ChronoDuration::minutes(5))),
            events: EventBus::new(16),
            self_test: make_test_self_test(pool.clone()),
            started_at: Instant::now(),
            socket_path: rch_common::default_socket_path(),
            version: "0.1.0",
            pid: 12345,
        };

        assert_eq!(context.history.len(), 1);
        let recent = context.history.recent(10);
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].project_id, "test-project");
    }

    #[tokio::test]
    async fn test_daemon_context_clone() {
        init_test_logging();

        let pool = workers::WorkerPool::new();
        let selector = Arc::new(WorkerSelector::new());
        let history = Arc::new(BuildHistory::new(100));

        let context = DaemonContext {
            pool: pool.clone(),
            worker_selector: selector,
            history: history.clone(),
            telemetry: make_test_telemetry(),
            benchmark_queue: Arc::new(BenchmarkQueue::new(ChronoDuration::minutes(5))),
            events: EventBus::new(16),
            self_test: make_test_self_test(pool.clone()),
            started_at: Instant::now(),
            socket_path: rch_common::default_socket_path(),
            version: "0.1.0",
            pid: 1234,
        };

        // Clone the context
        let context_clone = context.clone();

        // Both should share the same underlying data
        assert_eq!(context.socket_path, context_clone.socket_path);
        assert_eq!(context.version, context_clone.version);
        assert_eq!(context.pid, context_clone.pid);

        // Add a worker via original - should be visible in clone
        let worker_config = rch_common::WorkerConfig {
            id: rch_common::WorkerId::new("shared-worker"),
            host: "192.168.1.200".to_string(),
            user: "admin".to_string(),
            identity_file: "~/.ssh/key".to_string(),
            total_slots: 4,
            priority: 50,
            tags: vec![],
        };
        context.pool.add_worker(worker_config).await;

        // Clone should see the worker
        assert_eq!(context_clone.pool.len(), 1);
    }

    #[tokio::test]
    async fn test_daemon_context_uptime() {
        init_test_logging();

        let pool = workers::WorkerPool::new();
        let selector = Arc::new(WorkerSelector::new());
        let history = Arc::new(BuildHistory::new(100));
        let started_at = Instant::now();

        let context = DaemonContext {
            pool: pool.clone(),
            worker_selector: selector,
            history,
            telemetry: make_test_telemetry(),
            benchmark_queue: Arc::new(BenchmarkQueue::new(ChronoDuration::minutes(5))),
            events: EventBus::new(16),
            self_test: make_test_self_test(pool.clone()),
            started_at,
            socket_path: rch_common::default_socket_path(),
            version: "0.1.0",
            pid: 1234,
        };

        // Wait a small amount
        std::thread::sleep(std::time::Duration::from_millis(10));

        // Uptime should be measurable
        let uptime = context.started_at.elapsed();
        assert!(uptime.as_millis() >= 10);
    }

    #[tokio::test]
    async fn test_daemon_context_multiple_workers() {
        init_test_logging();

        let pool = workers::WorkerPool::new();

        // Add multiple workers
        for i in 1..=5 {
            let worker_config = rch_common::WorkerConfig {
                id: rch_common::WorkerId::new(format!("worker-{}", i)),
                host: format!("192.168.1.{}", 100 + i),
                user: "ubuntu".to_string(),
                identity_file: "~/.ssh/id_rsa".to_string(),
                total_slots: (i * 4) as u32,
                priority: 100 - i as u32,
                tags: vec![format!("tag-{}", i)],
            };
            pool.add_worker(worker_config).await;
        }

        let selector = Arc::new(WorkerSelector::new());
        let history = Arc::new(BuildHistory::new(100));

        let context = DaemonContext {
            pool: pool.clone(),
            worker_selector: selector,
            history,
            telemetry: make_test_telemetry(),
            benchmark_queue: Arc::new(BenchmarkQueue::new(ChronoDuration::minutes(5))),
            events: EventBus::new(16),
            self_test: make_test_self_test(pool.clone()),
            started_at: Instant::now(),
            socket_path: rch_common::default_socket_path(),
            version: "0.1.0",
            pid: 1234,
        };

        assert_eq!(context.pool.len(), 5);
    }

    // =========================================================================
    // test_daemon_build_history - BuildHistory integration tests
    // =========================================================================

    #[test]
    fn test_daemon_build_history_capacity() {
        init_test_logging();

        // Test that BuildHistory respects capacity limits
        let history = BuildHistory::new(3);

        for i in 1..=5 {
            let record = rch_common::BuildRecord {
                id: i,
                started_at: format!("2024-01-01T00:0{}:00Z", i),
                completed_at: format!("2024-01-01T00:0{}:30Z", i),
                project_id: "test-project".to_string(),
                worker_id: None,
                command: format!("cargo build {}", i),
                exit_code: 0,
                duration_ms: 1000,
                location: rch_common::BuildLocation::Local,
                bytes_transferred: None,
            };
            history.record(record);
        }

        // Should only retain last 3 entries
        assert_eq!(history.len(), 3);
        let recent = history.recent(10);
        assert_eq!(recent[0].id, 5); // Most recent
        assert_eq!(recent[2].id, 3); // Oldest retained
    }

    #[test]
    fn test_daemon_build_history_stats() {
        init_test_logging();

        let history = BuildHistory::new(100);

        // Add mixed success/failure, remote/local builds
        let records = vec![
            (1, 0, rch_common::BuildLocation::Remote, 1000),
            (2, 0, rch_common::BuildLocation::Remote, 2000),
            (3, 1, rch_common::BuildLocation::Local, 500),
            (4, 0, rch_common::BuildLocation::Local, 1500),
        ];

        for (id, exit_code, location, duration_ms) in records {
            let record = rch_common::BuildRecord {
                id,
                started_at: "2024-01-01T00:00:00Z".to_string(),
                completed_at: "2024-01-01T00:00:30Z".to_string(),
                project_id: "test".to_string(),
                worker_id: None,
                command: "cargo test".to_string(),
                exit_code,
                duration_ms,
                location,
                bytes_transferred: None,
            };
            history.record(record);
        }

        let stats = history.stats();
        assert_eq!(stats.total_builds, 4);
        assert_eq!(stats.success_count, 3);
        assert_eq!(stats.failure_count, 1);
        assert_eq!(stats.remote_count, 2);
        assert_eq!(stats.local_count, 2);
        assert_eq!(stats.avg_duration_ms, 1250); // (1000+2000+500+1500)/4
    }
}
