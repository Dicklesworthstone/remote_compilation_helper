//! Remote Compilation Helper - Local Daemon
//!
//! The daemon manages the worker fleet, tracks slot availability,
//! and provides the Unix socket API for the hook CLI.

#![forbid(unsafe_code)]

mod api;
mod config;
mod health;
mod history;
mod selection;
mod workers;

use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use tokio::net::UnixListener;
use tracing::{info, warn};
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

use history::BuildHistory;

#[derive(Parser)]
#[command(name = "rchd")]
#[command(author, version, about = "RCH daemon - worker fleet orchestration")]
struct Cli {
    /// Path to Unix socket
    #[arg(short, long, default_value = "/tmp/rch.sock")]
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
}

/// Shared daemon context passed to all API handlers.
#[derive(Clone)]
pub struct DaemonContext {
    /// Worker pool.
    pub pool: workers::WorkerPool,
    /// Build history.
    pub history: Arc<BuildHistory>,
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

    // Initialize logging
    let filter = if cli.verbose {
        EnvFilter::new("debug")
    } else {
        EnvFilter::new("info")
    };

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(filter)
        .init();

    info!("Starting RCH daemon...");

    // Load worker configuration
    let workers = config::load_workers(cli.workers_config.as_deref())?;
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

    // Remove existing socket if present
    if cli.socket.exists() {
        std::fs::remove_file(&cli.socket)?;
    }

    // Create Unix socket listener
    let listener = UnixListener::bind(&cli.socket)?;
    info!("Listening on {:?}", cli.socket);

    // Create daemon context
    let context = DaemonContext {
        pool: worker_pool.clone(),
        history,
        started_at: Instant::now(),
        socket_path: cli.socket.to_string_lossy().to_string(),
        version: env!("CARGO_PKG_VERSION"),
        pid: std::process::id(),
    };

    // Start health monitor
    let health_config = health::HealthConfig::default();
    let health_monitor = health::HealthMonitor::new(worker_pool.clone(), health_config);
    let _health_handle = health_monitor.start();
    info!("Health monitor started");

    // Main accept loop
    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                let ctx = context.clone();
                tokio::spawn(async move {
                    if let Err(e) = api::handle_connection(stream, ctx).await {
                        warn!("Connection error: {}", e);
                    }
                });
            }
            Err(e) => {
                warn!("Accept error: {}", e);
            }
        }
    }
}
