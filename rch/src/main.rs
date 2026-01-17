//! Remote Compilation Helper - PreToolUse Hook CLI
//!
//! This is the main entry point for the RCH hook that integrates with
//! Claude Code's PreToolUse hook system. It intercepts compilation commands
//! and routes them to remote workers for execution.

#![forbid(unsafe_code)]

mod commands;
mod config;
mod hook;
mod status_display;
mod status_types;
mod toolchain;
mod transfer;
pub mod ui;

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::sync::Arc;
use tracing_subscriber::{EnvFilter, fmt, prelude::*};
use ui::{ColorChoice, OutputConfig, OutputContext};

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

    /// Output as JSON for machine parsing
    #[arg(long, global = true)]
    json: bool,

    /// Color output mode: auto, always, never
    #[arg(long, global = true, default_value = "auto")]
    color: String,
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

    // Create output context from CLI flags
    let output_config = OutputConfig {
        json: cli.json,
        verbose: cli.verbose,
        quiet: cli.quiet,
        color: ColorChoice::parse(&cli.color),
        ..Default::default()
    };
    let ctx = Arc::new(OutputContext::new(output_config));

    // If no subcommand, we're being invoked as a hook
    match cli.command {
        None => {
            // Running as PreToolUse hook - read from stdin, process, write to stdout
            hook::run_hook().await
        }
        Some(cmd) => match cmd {
            Commands::Daemon { action } => handle_daemon(action, &ctx).await,
            Commands::Workers { action } => handle_workers(action, &ctx).await,
            Commands::Status { workers, jobs } => handle_status(workers, jobs, &ctx).await,
            Commands::Config { action } => handle_config(action, &ctx).await,
            Commands::Hook { action } => handle_hook(action, &ctx).await,
        },
    }
}

async fn handle_daemon(action: DaemonAction, ctx: &OutputContext) -> Result<()> {
    match action {
        DaemonAction::Start => {
            commands::daemon_start(ctx).await?;
        }
        DaemonAction::Stop => {
            commands::daemon_stop(ctx).await?;
        }
        DaemonAction::Restart => {
            commands::daemon_restart(ctx).await?;
        }
        DaemonAction::Status => {
            commands::daemon_status(ctx)?;
        }
        DaemonAction::Logs { lines } => {
            commands::daemon_logs(lines, ctx)?;
        }
    }
    Ok(())
}

async fn handle_workers(action: WorkersAction, ctx: &OutputContext) -> Result<()> {
    match action {
        WorkersAction::List => {
            commands::workers_list(ctx)?;
        }
        WorkersAction::Probe { worker, all } => {
            commands::workers_probe(worker, all, ctx).await?;
        }
        WorkersAction::Benchmark => {
            commands::workers_benchmark(ctx).await?;
        }
        WorkersAction::Drain { worker } => {
            commands::workers_drain(&worker, ctx).await?;
        }
        WorkersAction::Enable { worker } => {
            commands::workers_enable(&worker, ctx).await?;
        }
    }
    Ok(())
}

async fn handle_status(workers: bool, jobs: bool, _ctx: &OutputContext) -> Result<()> {
    commands::status_overview(workers, jobs).await?;
    Ok(())
}

async fn handle_config(action: ConfigAction, ctx: &OutputContext) -> Result<()> {
    match action {
        ConfigAction::Show => {
            commands::config_show(ctx)?;
        }
        ConfigAction::Init => {
            commands::config_init(ctx)?;
        }
        ConfigAction::Validate => {
            commands::config_validate(ctx)?;
        }
        ConfigAction::Set { key, value } => {
            commands::config_set(&key, &value, ctx)?;
        }
    }
    Ok(())
}

async fn handle_hook(action: HookAction, ctx: &OutputContext) -> Result<()> {
    match action {
        HookAction::Install => {
            commands::hook_install(ctx)?;
        }
        HookAction::Uninstall => {
            commands::hook_uninstall(ctx)?;
        }
        HookAction::Test => {
            commands::hook_test(ctx).await?;
        }
    }
    Ok(())
}
