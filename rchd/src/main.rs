//! Remote Compilation Helper - Local Daemon
//!
//! The daemon manages the worker fleet, tracks slot availability,
//! and provides the Unix socket API for the hook CLI.

#![forbid(unsafe_code)]

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

    // Remove existing socket if present
    if cli.socket.exists() {
        std::fs::remove_file(&cli.socket)?;
    }

    // Create Unix socket listener
    let listener = UnixListener::bind(&cli.socket)?;
    info!("Listening on {:?}", cli.socket);

    // Load worker configuration
    let worker_pool = workers::WorkerPool::new();
    info!("Worker pool initialized with {} workers", worker_pool.len());

    // Main accept loop
    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                let pool = worker_pool.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(stream, pool).await {
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

async fn handle_connection(
    _stream: tokio::net::UnixStream,
    _pool: workers::WorkerPool,
) -> Result<()> {
    // TODO: Implement request handling
    // - Parse request (GET /select-worker?project=X&cores=N)
    // - Select worker using selection algorithm
    // - Return worker info as JSON
    info!("Connection received");
    Ok(())
}
