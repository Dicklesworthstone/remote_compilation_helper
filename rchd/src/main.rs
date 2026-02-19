//! Remote Compilation Helper - Local Daemon
//!
//! The daemon manages the worker fleet, tracks slot availability,
//! and provides the Unix socket API for the hook CLI.

#![forbid(unsafe_code)]

mod admission;
mod alerts;
mod api;
mod benchmark_queue;
mod benchmark_scheduler;
mod cache_cleanup;
mod cancellation;
mod cleanup;
mod config;
#[cfg(test)]
mod disk_full_prevention_tests;
mod disk_pressure;
mod events;
mod headroom;
mod health;
mod history;
mod http_api;
mod metrics;
mod process_triage;
mod reclaim;
mod reliability;
mod reload;
mod repo_convergence;
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
use tokio::sync::{Mutex, mpsc};
use tokio::time::interval;
use tracing::{error, info, warn};

#[cfg(unix)]
use tokio::signal::unix::{SignalKind, signal};

use benchmark_queue::BenchmarkQueue;
use benchmark_scheduler::{BenchmarkScheduler, BenchmarkTriggerHandle, SchedulerConfig};
use disk_pressure::{DiskPressureMonitor, DiskPressurePolicyConfig};
use events::EventBus;
use history::BuildHistory;
use rch_telemetry::storage::TelemetryStorage;
use selection::WorkerSelector;
use self_test::{DEFAULT_RESULT_CAPACITY, DEFAULT_RUN_CAPACITY, SelfTestHistory, SelfTestService};
use telemetry::{TelemetryPoller, TelemetryPollerConfig, TelemetryStore};
use ui::{DaemonBanner, MetricsDashboard, WorkerStatusPanel};

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

    /// Reset interval for metrics dashboard window, in seconds
    #[arg(long, default_value = "300")]
    metrics_reset_interval: u64,

    /// Emit worker selection routing decisions to stderr
    #[arg(long)]
    debug_routing: bool,

    /// Disable hot-reload of configuration files
    #[arg(long)]
    no_hot_reload: bool,
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
    /// Live benchmark scheduler trigger handle.
    pub benchmark_trigger: BenchmarkTriggerHandle,
    /// Event broadcast bus.
    pub events: EventBus,
    /// Self-test service.
    pub self_test: Arc<SelfTestService>,
    /// Alert manager for worker health alerting.
    pub alert_manager: Arc<alerts::AlertManager>,
    /// Repo convergence service for worker fleet sync tracking.
    pub repo_convergence: Arc<repo_convergence::RepoConvergenceService>,
    /// Cancellation orchestrator for deterministic build cancellation.
    pub cancellation: Arc<cancellation::CancellationOrchestrator>,
    /// Daemon start time.
    pub started_at: Instant,
    /// Socket path (for status reporting).
    pub socket_path: String,
    /// Daemon version.
    pub version: &'static str,
    /// Daemon process ID.
    pub pid: u32,
    /// Maximum time a build can wait in queue (seconds) before timing out.
    pub queue_timeout_secs: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let startup_started = Instant::now();

    if cli.debug_routing {
        // Avoid env var mutation (unsafe in Rust 2024); use an in-process override.
        crate::ui::workers::set_debug_routing_enabled(true);
    }

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
        Ok(mut cfg) => {
            // Apply environment variable overrides to self-healing config
            cfg.self_healing = cfg.self_healing.with_env_overrides();
            cfg
        }
        Err(e) => {
            warn!("Failed to load RCH config: {}, using defaults", e);
            let mut cfg = rch_common::RchConfig::default();
            cfg.self_healing = cfg.self_healing.with_env_overrides();
            cfg
        }
    };

    // Initialize worker selector
    let worker_selector = Arc::new(WorkerSelector::with_config(
        rch_config.selection.clone(),
        rch_config.circuit.clone(),
    ));

    // Verify and install Claude Code hook if needed (self-healing)
    if rch_config.self_healing.daemon_installs_hooks {
        match rch_common::verify_and_install_claude_code_hook() {
            Ok(rch_common::HookResult::AlreadyInstalled) => {
                tracing::debug!("Claude Code hook already installed");
            }
            Ok(rch_common::HookResult::Installed) => {
                info!("Claude Code hook installed automatically");
            }
            Ok(rch_common::HookResult::NotApplicable) => {
                tracing::debug!("Claude Code not detected, skipping hook installation");
            }
            Ok(rch_common::HookResult::Skipped(reason)) => {
                tracing::debug!("Hook installation skipped: {}", reason);
            }
            Err(e) => {
                warn!("Failed to verify/install Claude Code hook: {}", e);
            }
        }
    } else {
        tracing::debug!("Hook auto-installation disabled via config");
    }

    // Load daemon config for queue + cache cleanup settings
    let daemon_config = match config::load_daemon_config(None) {
        Ok(cfg) => cfg,
        Err(e) => {
            warn!("Failed to load daemon config: {}, using defaults", e);
            config::DaemonConfig::default()
        }
    };

    // Initialize build history
    let history = if let Some(ref path) = cli.history_file {
        if path.exists() {
            match BuildHistory::load_from_file(path, cli.history_capacity) {
                Ok(h) => {
                    info!("Loaded build history from {:?} ({} entries)", path, h.len());
                    Arc::new(h.with_max_queue_depth(daemon_config.queue.max_depth))
                }
                Err(e) => {
                    warn!("Failed to load history from {:?}: {}", path, e);
                    Arc::new(
                        BuildHistory::new(cli.history_capacity)
                            .with_persistence(path.clone())
                            .with_max_queue_depth(daemon_config.queue.max_depth),
                    )
                }
            }
        } else {
            info!("Creating new build history at {:?}", path);
            Arc::new(
                BuildHistory::new(cli.history_capacity)
                    .with_persistence(path.clone())
                    .with_max_queue_depth(daemon_config.queue.max_depth),
            )
        }
    } else {
        info!("Build history in-memory only (no persistence)");
        Arc::new(
            BuildHistory::new(cli.history_capacity)
                .with_max_queue_depth(daemon_config.queue.max_depth),
        )
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

    // Start cache cleanup scheduler
    let cache_cleanup_scheduler = Arc::new(cache_cleanup::CacheCleanupScheduler::new(
        worker_pool.clone(),
        daemon_config.cache_cleanup,
    ));
    let _cache_cleanup_handle = cache_cleanup_scheduler.start();

    // Remove existing socket if present
    if cli.socket.exists() {
        std::fs::remove_file(&cli.socket)?;
    }

    // Create Unix socket listener
    let listener = UnixListener::bind(&cli.socket)?;

    // Set socket permissions to 600 (owner read/write only) to prevent unauthorized access
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&cli.socket, std::fs::Permissions::from_mode(0o600))?;
    }

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
    let (benchmark_scheduler, benchmark_trigger) = BenchmarkScheduler::new(
        SchedulerConfig::default(),
        worker_pool.clone(),
        telemetry_store.clone(),
        event_bus.clone(),
    );
    let benchmark_scheduler = Arc::new(benchmark_scheduler);
    let _benchmark_scheduler_handle = tokio::spawn(benchmark_scheduler.run());
    info!("Benchmark scheduler started");

    // Initialize alert manager for worker health alerting
    let suppress_secs = rch_config
        .alerts
        .suppress_duplicates_secs
        .min(i64::MAX as u64) as i64;

    // Convert webhook config from rch_common to alerts module format
    let webhook_config = rch_config
        .alerts
        .webhook
        .as_ref()
        .map(|w| alerts::WebhookConfig {
            url: w.url.clone(),
            secret: w.secret.clone(),
            timeout_secs: w.timeout_secs,
            retry_count: w.retry_count,
            events: w.events.clone(),
        });

    let alert_config = alerts::AlertConfig {
        enabled: rch_config.alerts.enabled,
        suppress_duplicates: ChronoDuration::seconds(suppress_secs),
        webhook: webhook_config,
    };
    let alert_manager = Arc::new(alerts::AlertManager::new(alert_config));

    let repo_convergence = Arc::new(repo_convergence::RepoConvergenceService::new(
        event_bus.clone(),
    ));

    let cancellation_orchestrator = Arc::new(cancellation::CancellationOrchestrator::new(
        cancellation::CancellationConfig::default(),
        event_bus.clone(),
    ));

    let context = DaemonContext {
        pool: worker_pool.clone(),
        worker_selector: worker_selector.clone(),
        history,
        telemetry: telemetry_store.clone(),
        benchmark_queue: benchmark_queue.clone(),
        benchmark_trigger: benchmark_trigger.clone(),
        events: event_bus.clone(),
        self_test: self_test_service.clone(),
        alert_manager: alert_manager.clone(),
        repo_convergence,
        cancellation: cancellation_orchestrator,
        started_at: Instant::now(),
        socket_path: cli.socket.to_string_lossy().to_string(),
        version: env!("CARGO_PKG_VERSION"),
        pid: std::process::id(),
        queue_timeout_secs: daemon_config.queue.timeout_secs,
    };

    // Start active build cleanup background task
    let active_cleanup = cleanup::ActiveBuildCleanup::new(context.clone());
    let _active_cleanup_handle = active_cleanup.start();

    let worker_status_panel = Arc::new(Mutex::new(
        WorkerStatusPanel::new()
            .with_verbose(cli.verbose)
            .with_debug_routing(cli.debug_routing),
    ));
    let metrics_interval = Duration::from_secs(cli.metrics_reset_interval.max(1));
    let metrics_dashboard = Arc::new(Mutex::new(MetricsDashboard::new(metrics_interval)));

    // Start health monitor with alert manager integration
    let health_config = health::HealthConfig::default();
    let health_monitor = health::HealthMonitor::new(worker_pool.clone(), health_config)
        .with_status_panel(worker_status_panel.clone())
        .with_alert_manager(alert_manager.clone());
    let health_handle = health_monitor.start();
    info!("Health monitor started with alerting enabled");

    // Start telemetry poller
    let telemetry_poller = TelemetryPoller::new(
        worker_pool.clone(),
        telemetry_store.clone(),
        TelemetryPollerConfig::default(),
    );
    let _telemetry_handle = telemetry_poller.start();
    info!("Telemetry poller started");

    // Start daemon-side disk pressure monitor + policy evaluator (bd-vvmd.4.2)
    let disk_pressure_monitor = DiskPressureMonitor::new(
        worker_pool.clone(),
        telemetry_store.clone(),
        DiskPressurePolicyConfig::default(),
    );
    let _disk_pressure_handle = disk_pressure_monitor.start();
    info!("Disk pressure monitor started");

    // Start background convergence loop (bd-vvmd.3.4)
    let convergence_loop = repo_convergence::ConvergenceLoop::new(
        context.repo_convergence.clone(),
        worker_pool.clone(),
        event_bus.clone(),
        repo_convergence::ConvergenceLoopConfig::default(),
    );
    let _convergence_loop_handle = convergence_loop.start();
    info!("Convergence loop started");

    let metrics_pool = worker_pool.clone();
    let metrics_history = context.history.clone();
    let metrics_selector = worker_selector.clone();
    let metrics_dashboard_handle = metrics_dashboard.clone();
    let mut metrics_handle: Option<tokio::task::JoinHandle<()>> = Some(tokio::spawn(async move {
        let mut ticker = interval(metrics_interval);
        loop {
            ticker.tick().await;
            let mut dashboard = metrics_dashboard_handle.lock().await;
            dashboard
                .emit_update(&metrics_pool, &metrics_history, &metrics_selector)
                .await;
        }
    }));

    // Start background cleanup for drained workers
    let cleanup_pool = worker_pool.clone();
    let mut cleanup_handle: Option<tokio::task::JoinHandle<()>> = Some(tokio::spawn(async move {
        // Check every minute
        let mut ticker = interval(Duration::from_secs(60));
        loop {
            ticker.tick().await;
            let pruned = cleanup_pool.prune_drained().await;
            if pruned > 0 {
                info!("Background cleanup: pruned {} drained workers", pruned);
            }
        }
    }));

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

    // Start config hot-reload watcher (unless disabled)
    let reload_tx = if !cli.no_hot_reload {
        match reload::start_config_watcher(worker_pool.clone(), cli.workers_config.clone()).await {
            Ok((handle, tx)) => {
                info!("Configuration hot-reload enabled");
                // Store handle to keep watcher alive
                let _reload_handle = handle;
                Some(tx)
            }
            Err(e) => {
                warn!("Failed to start config watcher: {}", e);
                None
            }
        }
    } else {
        info!("Configuration hot-reload disabled");
        None
    };

    // Set up SIGHUP handler for manual reload (Unix only)
    #[cfg(unix)]
    let mut sighup = signal(SignalKind::hangup()).expect("Failed to register SIGHUP handler");

    // Shutdown channel
    let (shutdown_tx, mut shutdown_rx) = mpsc::channel(1);

    // Main accept loop - platform-specific due to SIGHUP handling
    #[cfg(unix)]
    {
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
                _ = sighup.recv() => {
                    info!("SIGHUP received, triggering configuration reload");
                    if let Some(ref tx) = reload_tx {
                        if let Err(e) = tx.send(reload::ReloadMessage::ManualReload).await {
                            warn!("Failed to trigger reload: {}", e);
                        }
                    } else {
                        // Hot-reload disabled, perform inline reload
                        match reload::reload_workers(
                            &worker_pool,
                            cli.workers_config.as_deref(),
                            true,
                        ).await {
                            Ok(result) => {
                                if result.has_changes() {
                                    info!("SIGHUP reload: {} added, {} updated, {} removed",
                                        result.added, result.updated, result.removed);
                                } else {
                                    info!("SIGHUP reload: no configuration changes");
                                }
                            }
                            Err(e) => {
                                warn!("SIGHUP reload failed: {}", e);
                            }
                        }
                    }
                }
                // Monitor background tasks for unexpected termination (panics)
                // Use Option to avoid polling completed handles repeatedly
                result = async { metrics_handle.as_mut().unwrap().await }, if metrics_handle.is_some() => {
                    metrics_handle = None; // Don't poll again
                    match result {
                        Ok(_) => error!("Metrics task unexpectedly terminated"),
                        Err(e) => error!("Metrics task panicked: {}", e),
                    }
                    // Task is non-critical, continue running daemon
                }
                result = async { cleanup_handle.as_mut().unwrap().await }, if cleanup_handle.is_some() => {
                    cleanup_handle = None; // Don't poll again
                    match result {
                        Ok(_) => error!("Cleanup task unexpectedly terminated"),
                        Err(e) => error!("Cleanup task panicked: {}", e),
                    }
                    // Task is non-critical, continue running daemon
                }
            }
        }
    }

    #[cfg(not(unix))]
    {
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
                // Monitor background tasks for unexpected termination (panics)
                result = async { metrics_handle.as_mut().unwrap().await }, if metrics_handle.is_some() => {
                    metrics_handle = None; // Don't poll again
                    match result {
                        Ok(_) => error!("Metrics task unexpectedly terminated"),
                        Err(e) => error!("Metrics task panicked: {}", e),
                    }
                    // Task is non-critical, continue running daemon
                }
                result = async { cleanup_handle.as_mut().unwrap().await }, if cleanup_handle.is_some() => {
                    cleanup_handle = None; // Don't poll again
                    match result {
                        Ok(_) => error!("Cleanup task unexpectedly terminated"),
                        Err(e) => error!("Cleanup task panicked: {}", e),
                    }
                    // Task is non-critical, continue running daemon
                }
            }
        }
    }

    // Graceful shutdown
    info!("Stopping health monitor...");
    health_monitor.stop().await;
    let _ = health_handle.await;

    // Abort background tasks that have no cancellation mechanism
    info!("Stopping background tasks...");
    if let Some(handle) = metrics_handle {
        handle.abort();
    }
    if let Some(handle) = cleanup_handle {
        handle.abort();
    }

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
    use rch_common::test_guard;

    fn make_test_telemetry() -> Arc<TelemetryStore> {
        Arc::new(TelemetryStore::new(Duration::from_secs(300), None))
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

    fn make_test_alert_manager() -> Arc<crate::alerts::AlertManager> {
        Arc::new(crate::alerts::AlertManager::new(
            crate::alerts::AlertConfig::default(),
        ))
    }

    fn make_test_cancellation() -> Arc<cancellation::CancellationOrchestrator> {
        Arc::new(cancellation::CancellationOrchestrator::new(
            cancellation::CancellationConfig::default(),
            EventBus::new(16),
        ))
    }

    fn make_test_benchmark_trigger(pool: workers::WorkerPool) -> BenchmarkTriggerHandle {
        let (scheduler, trigger) = BenchmarkScheduler::new(
            SchedulerConfig::default(),
            pool,
            make_test_telemetry(),
            EventBus::new(16),
        );
        let scheduler = Arc::new(scheduler);
        tokio::spawn(scheduler.run());
        trigger
    }

    // =========================================================================
    // test_cli_parsing - CLI argument parsing sanity checks
    // =========================================================================

    #[test]
    fn test_cli_parsing_defaults() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rchd"]).unwrap();

        assert_eq!(cli.socket, crate::config::default_socket_path());
        assert_eq!(cli.history_capacity, 100);
        assert_eq!(cli.metrics_port, 9100);
        assert_eq!(cli.metrics_reset_interval, 300);

        assert!(!cli.verbose);
        assert!(!cli.foreground);
        assert!(!cli.debug_routing);
        assert!(!cli.no_hot_reload);
    }

    #[test]
    fn test_cli_parsing_overrides() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from([
            "rchd",
            "--socket",
            "/tmp/rch-test.sock",
            "--workers-config",
            "/tmp/workers.toml",
            "--history-file",
            "/tmp/history.jsonl",
            "--history-capacity",
            "250",
            "--metrics-port",
            "0",
            "--metrics-reset-interval",
            "60",
            "--debug-routing",
            "--no-hot-reload",
            "--verbose",
            "--foreground",
        ])
        .unwrap();

        assert_eq!(cli.socket, std::path::PathBuf::from("/tmp/rch-test.sock"));
        assert_eq!(
            cli.workers_config,
            Some(std::path::PathBuf::from("/tmp/workers.toml"))
        );
        assert_eq!(
            cli.history_file,
            Some(std::path::PathBuf::from("/tmp/history.jsonl"))
        );
        assert_eq!(cli.history_capacity, 250);
        assert_eq!(cli.metrics_port, 0);
        assert_eq!(cli.metrics_reset_interval, 60);
        assert!(cli.debug_routing);
        assert!(cli.no_hot_reload);
        assert!(cli.verbose);
        assert!(cli.foreground);
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
            benchmark_trigger: make_test_benchmark_trigger(pool.clone()),
            events: EventBus::new(16),
            self_test: make_test_self_test(pool.clone()),
            alert_manager: make_test_alert_manager(),
            repo_convergence: Arc::new(repo_convergence::RepoConvergenceService::new(
                EventBus::new(16),
            )),
            cancellation: make_test_cancellation(),
            started_at,
            socket_path: "/tmp/test.sock".to_string(),
            version: "0.1.0-test",
            pid: std::process::id(),
            queue_timeout_secs: 300,
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
            benchmark_trigger: make_test_benchmark_trigger(pool.clone()),
            events: EventBus::new(16),
            self_test: make_test_self_test(pool.clone()),
            alert_manager: make_test_alert_manager(),
            repo_convergence: Arc::new(repo_convergence::RepoConvergenceService::new(
                EventBus::new(16),
            )),
            cancellation: make_test_cancellation(),
            started_at,
            socket_path: rch_common::default_socket_path(),
            version: env!("CARGO_PKG_VERSION"),
            pid: std::process::id(),
            queue_timeout_secs: 300,
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
            timing: None,
            cancellation: None,
        };
        history.record(record);

        let context = DaemonContext {
            pool: pool.clone(),
            worker_selector: selector,
            history,
            telemetry: make_test_telemetry(),
            benchmark_queue: Arc::new(BenchmarkQueue::new(ChronoDuration::minutes(5))),
            benchmark_trigger: make_test_benchmark_trigger(pool.clone()),
            events: EventBus::new(16),
            self_test: make_test_self_test(pool.clone()),
            alert_manager: make_test_alert_manager(),
            repo_convergence: Arc::new(repo_convergence::RepoConvergenceService::new(
                EventBus::new(16),
            )),
            cancellation: make_test_cancellation(),
            started_at: Instant::now(),
            socket_path: rch_common::default_socket_path(),
            version: "0.1.0",
            pid: 12345,
            queue_timeout_secs: 300,
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
            benchmark_trigger: make_test_benchmark_trigger(pool.clone()),
            events: EventBus::new(16),
            self_test: make_test_self_test(pool.clone()),
            alert_manager: make_test_alert_manager(),
            repo_convergence: Arc::new(repo_convergence::RepoConvergenceService::new(
                EventBus::new(16),
            )),
            cancellation: make_test_cancellation(),
            started_at: Instant::now(),
            socket_path: rch_common::default_socket_path(),
            version: "0.1.0",
            pid: 1234,
            queue_timeout_secs: 300,
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
            benchmark_trigger: make_test_benchmark_trigger(pool.clone()),
            events: EventBus::new(16),
            self_test: make_test_self_test(pool.clone()),
            alert_manager: make_test_alert_manager(),
            repo_convergence: Arc::new(repo_convergence::RepoConvergenceService::new(
                EventBus::new(16),
            )),
            cancellation: make_test_cancellation(),
            started_at,
            socket_path: rch_common::default_socket_path(),
            version: "0.1.0",
            pid: 1234,
            queue_timeout_secs: 300,
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
            benchmark_trigger: make_test_benchmark_trigger(pool.clone()),
            events: EventBus::new(16),
            self_test: make_test_self_test(pool.clone()),
            alert_manager: make_test_alert_manager(),
            repo_convergence: Arc::new(repo_convergence::RepoConvergenceService::new(
                EventBus::new(16),
            )),
            cancellation: make_test_cancellation(),
            started_at: Instant::now(),
            socket_path: rch_common::default_socket_path(),
            version: "0.1.0",
            pid: 1234,
            queue_timeout_secs: 300,
        };

        assert_eq!(context.pool.len(), 5);
    }

    // =========================================================================
    // test_daemon_build_history - BuildHistory integration tests
    // =========================================================================

    #[test]
    fn test_daemon_build_history_capacity() {
        let _guard = test_guard!();
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
                timing: None,
                cancellation: None,
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
        let _guard = test_guard!();
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
                timing: None,
                cancellation: None,
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

// Global test logging initialization - enables JSONL output for all unit tests
#[cfg(test)]
#[ctor::ctor]
fn init_test_logging() {
    rch_common::testing::init_global_test_logging();
}
