//! Remote Compilation Helper - PreToolUse Hook CLI
//!
//! This is the main entry point for the RCH hook that integrates with
//! Claude Code's PreToolUse hook system. It intercepts compilation commands
//! and routes them to remote workers for execution.

#![forbid(unsafe_code)]

mod config;
mod hook;

use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

#[derive(Parser)]
#[command(name = "rch")]
#[command(
    author,
    version,
    about = "Remote Compilation Helper - transparent compilation offloading"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Enable verbose output
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Suppress non-error output
    #[arg(short, long, global = true)]
    quiet: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the local daemon
    Daemon {
        #[command(subcommand)]
        action: DaemonAction,
    },

    /// Manage remote workers
    Workers {
        #[command(subcommand)]
        action: WorkersAction,
    },

    /// Show system status
    Status {
        /// Show worker details
        #[arg(long)]
        workers: bool,

        /// Show active jobs
        #[arg(long)]
        jobs: bool,
    },

    /// Manage configuration
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },

    /// Manage the Claude Code hook
    Hook {
        #[command(subcommand)]
        action: HookAction,
    },
}

#[derive(Subcommand)]
enum DaemonAction {
    /// Start the daemon
    Start,
    /// Stop the daemon
    Stop,
    /// Restart the daemon
    Restart,
    /// Show daemon status
    Status,
    /// Tail daemon logs
    Logs {
        /// Number of lines to show
        #[arg(short = 'n', long, default_value = "50")]
        lines: usize,
    },
}

#[derive(Subcommand)]
enum WorkersAction {
    /// List configured workers
    List,
    /// Probe worker connectivity
    Probe {
        /// Worker ID to probe, or --all for all workers
        worker: Option<String>,
        /// Probe all workers
        #[arg(long)]
        all: bool,
    },
    /// Run speed benchmarks
    Benchmark,
    /// Drain a worker (stop sending new jobs)
    Drain { worker: String },
    /// Enable a worker
    Enable { worker: String },
}

#[derive(Subcommand)]
enum ConfigAction {
    /// Show effective configuration
    Show,
    /// Initialize project config
    Init,
    /// Validate configuration
    Validate,
    /// Set a configuration value
    Set { key: String, value: String },
}

#[derive(Subcommand)]
enum HookAction {
    /// Install the Claude Code hook
    Install,
    /// Uninstall the hook
    Uninstall,
    /// Test the hook with a sample command
    Test,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    let filter = if cli.verbose {
        EnvFilter::new("debug")
    } else if cli.quiet {
        EnvFilter::new("error")
    } else {
        EnvFilter::new("info")
    };

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(filter)
        .init();

    // If no subcommand, we're being invoked as a hook
    match cli.command {
        None => {
            // Running as PreToolUse hook - read from stdin, process, write to stdout
            hook::run_hook().await
        }
        Some(cmd) => match cmd {
            Commands::Daemon { action } => handle_daemon(action).await,
            Commands::Workers { action } => handle_workers(action).await,
            Commands::Status { workers, jobs } => handle_status(workers, jobs).await,
            Commands::Config { action } => handle_config(action).await,
            Commands::Hook { action } => handle_hook(action).await,
        },
    }
}

async fn handle_daemon(action: DaemonAction) -> Result<()> {
    match action {
        DaemonAction::Start => {
            tracing::info!("Starting RCH daemon...");
            // TODO: Implement daemon start
            println!("Daemon start not yet implemented");
        }
        DaemonAction::Stop => {
            tracing::info!("Stopping RCH daemon...");
            // TODO: Implement daemon stop
            println!("Daemon stop not yet implemented");
        }
        DaemonAction::Restart => {
            tracing::info!("Restarting RCH daemon...");
            // TODO: Implement daemon restart
            println!("Daemon restart not yet implemented");
        }
        DaemonAction::Status => {
            // TODO: Check if daemon is running
            println!("Daemon status not yet implemented");
        }
        DaemonAction::Logs { lines } => {
            tracing::info!("Showing last {} log lines...", lines);
            // TODO: Show daemon logs
            println!("Daemon logs not yet implemented");
        }
    }
    Ok(())
}

async fn handle_workers(action: WorkersAction) -> Result<()> {
    match action {
        WorkersAction::List => {
            // TODO: List workers from config
            println!("Workers list not yet implemented");
        }
        WorkersAction::Probe { worker, all } => {
            if all {
                tracing::info!("Probing all workers...");
            } else if let Some(w) = worker {
                tracing::info!("Probing worker: {}", w);
            }
            // TODO: Probe worker connectivity
            println!("Worker probe not yet implemented");
        }
        WorkersAction::Benchmark => {
            tracing::info!("Running benchmarks...");
            // TODO: Run speed benchmarks
            println!("Benchmark not yet implemented");
        }
        WorkersAction::Drain { worker } => {
            tracing::info!("Draining worker: {}", worker);
            // TODO: Drain worker
            println!("Worker drain not yet implemented");
        }
        WorkersAction::Enable { worker } => {
            tracing::info!("Enabling worker: {}", worker);
            // TODO: Enable worker
            println!("Worker enable not yet implemented");
        }
    }
    Ok(())
}

async fn handle_status(workers: bool, jobs: bool) -> Result<()> {
    println!("RCH Status");
    println!("==========");
    // TODO: Show daemon status

    if workers {
        println!("\nWorkers:");
        // TODO: Show worker status
        println!("  (not yet implemented)");
    }

    if jobs {
        println!("\nActive Jobs:");
        // TODO: Show active jobs
        println!("  (not yet implemented)");
    }

    Ok(())
}

async fn handle_config(action: ConfigAction) -> Result<()> {
    match action {
        ConfigAction::Show => {
            // TODO: Show effective config
            println!("Config show not yet implemented");
        }
        ConfigAction::Init => {
            // TODO: Initialize project config
            println!("Config init not yet implemented");
        }
        ConfigAction::Validate => {
            // TODO: Validate config
            println!("Config validate not yet implemented");
        }
        ConfigAction::Set { key, value } => {
            tracing::info!("Setting {} = {}", key, value);
            // TODO: Set config value
            println!("Config set not yet implemented");
        }
    }
    Ok(())
}

async fn handle_hook(action: HookAction) -> Result<()> {
    match action {
        HookAction::Install => {
            tracing::info!("Installing Claude Code hook...");
            // TODO: Install hook
            println!("Hook install not yet implemented");
        }
        HookAction::Uninstall => {
            tracing::info!("Uninstalling Claude Code hook...");
            // TODO: Uninstall hook
            println!("Hook uninstall not yet implemented");
        }
        HookAction::Test => {
            tracing::info!("Testing hook...");
            // TODO: Test hook
            println!("Hook test not yet implemented");
        }
    }
    Ok(())
}
