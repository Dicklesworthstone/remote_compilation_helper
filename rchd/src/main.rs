//! Remote Compilation Helper - Local Daemon
//!
//! The daemon manages the worker fleet, tracks slot availability,
//! and provides the Unix socket API for the hook CLI.

#![forbid(unsafe_code)]

mod api;
mod config;
mod health;
mod selection;
mod workers;

use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;
use tokio::net::UnixListener;
use tracing::{info, warn};
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

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

    /// Enable verbose output
    #[arg(short, long)]
    verbose: bool,

    /// Run in foreground (don't daemonize)
    #[arg(short, long)]
    foreground: bool,
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
        info!("Adding worker: {} ({}@{}, {} slots)",
              worker_config.id, worker_config.user, worker_config.host, worker_config.total_slots);
        worker_pool.add_worker(worker_config).await;
    }

    // Remove existing socket if present
    if cli.socket.exists() {
        std::fs::remove_file(&cli.socket)?;
    }

    // Create Unix socket listener
    let listener = UnixListener::bind(&cli.socket)?;
    info!("Listening on {:?}", cli.socket);

    // Start health monitor
    let health_config = health::HealthConfig::default();
    let health_monitor = health::HealthMonitor::new(worker_pool.clone(), health_config);
    let _health_handle = health_monitor.start();
    info!("Health monitor started");

    // Main accept loop
    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                let pool = worker_pool.clone();
                tokio::spawn(async move {
                    if let Err(e) = api::handle_connection(stream, pool).await {
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

