//! Remote Compilation Helper - PreToolUse Hook CLI
//!
//! This is the main entry point for the RCH hook that integrates with
//! Claude Code's PreToolUse hook system. It intercepts compilation commands
//! and routes them to remote workers for execution.

#![forbid(unsafe_code)]

mod commands;
mod config;
mod hook;
mod transfer;
pub mod ui;

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
            commands::daemon_start().await?;
        }
        DaemonAction::Stop => {
            commands::daemon_stop().await?;
        }
        DaemonAction::Restart => {
            commands::daemon_restart().await?;
        }
        DaemonAction::Status => {
            commands::daemon_status()?;
        }
        DaemonAction::Logs { lines } => {
            commands::daemon_logs(lines)?;
        }
    }
    Ok(())
}

async fn handle_workers(action: WorkersAction) -> Result<()> {
    match action {
        WorkersAction::List => {
            commands::workers_list()?;
        }
        WorkersAction::Probe { worker, all } => {
            commands::workers_probe(worker, all).await?;
        }
        WorkersAction::Benchmark => {
            commands::workers_benchmark().await?;
        }
        WorkersAction::Drain { worker } => {
            commands::workers_drain(&worker).await?;
        }
        WorkersAction::Enable { worker } => {
            commands::workers_enable(&worker).await?;
        }
    }
    Ok(())
}

async fn handle_status(workers: bool, jobs: bool) -> Result<()> {
    commands::status_overview(workers, jobs).await?;
    Ok(())
}

async fn handle_config(action: ConfigAction) -> Result<()> {
    match action {
        ConfigAction::Show => {
            commands::config_show()?;
        }
        ConfigAction::Init => {
            commands::config_init()?;
        }
        ConfigAction::Validate => {
            commands::config_validate()?;
        }
        ConfigAction::Set { key, value } => {
            commands::config_set(&key, &value)?;
        }
    }
    Ok(())
}

async fn handle_hook(action: HookAction) -> Result<()> {
    match action {
        HookAction::Install => {
            commands::hook_install()?;
        }
        HookAction::Uninstall => {
            commands::hook_uninstall()?;
        }
        HookAction::Test => {
            commands::hook_test().await?;
        }
    }
    Ok(())
}
