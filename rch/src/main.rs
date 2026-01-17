//! Remote Compilation Helper - PreToolUse Hook CLI
//!
//! This is the main entry point for the RCH hook that integrates with
//! Claude Code's PreToolUse hook system. It intercepts compilation commands
//! and routes them to remote workers for execution.

#![forbid(unsafe_code)]

pub mod agent;
mod commands;
mod completions;
mod config;
mod doctor;
pub mod error;
mod hook;
pub mod state;
mod status_display;
mod status_types;
mod toolchain;
mod transfer;
pub mod ui;
mod update;

use anyhow::Result;
use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::CompleteEnv;
use std::sync::Arc;
use tracing_subscriber::{EnvFilter, fmt, prelude::*};
use ui::{ColorChoice, OutputConfig, OutputContext};

#[derive(Parser)]
#[command(name = "rch")]
#[command(
    author,
    version,
    about = "Remote Compilation Helper - transparent compilation offloading",
    long_about = "Remote Compilation Helper (RCH) transparently offloads compilation commands \
                  to remote workers. When invoked without a subcommand, RCH runs as a Claude Code \
                  PreToolUse hook, intercepting build commands and routing them to faster remote machines.",
    after_help = r#"EXAMPLES:
    # Quick start - install hook and start daemon
    rch hook install && rch daemon start

    # Check system status
    rch status --workers --jobs

    # Probe worker connectivity
    rch workers probe --all

    # Show where config values come from
    rch config show --sources

    # Test hook with a sample cargo build
    rch hook test

    # Generate shell completions
    rch completions bash > ~/.local/share/bash-completion/completions/rch

HOOK MODE:
    When invoked without arguments, RCH acts as a PreToolUse hook for Claude Code.
    It reads JSON from stdin, decides whether to intercept the command, and writes
    JSON to stdout. This is automatic when installed via 'rch hook install'.

ENVIRONMENT VARIABLES:
    RCH_PROFILE           Profile to use: dev, prod, test (sets defaults below)
    RCH_LOG_LEVEL         Logging level: trace, debug, info, warn, error, off
    RCH_LOG_FORMAT        Log format: pretty, json, compact
    RCH_DAEMON_SOCKET     Path to daemon Unix socket
    RCH_DAEMON_TIMEOUT_MS Timeout for daemon communication (default: 5000)
    RCH_SSH_KEY           Path to SSH private key for worker connections
    RCH_TRANSFER_ZSTD_LEVEL  Compression level 1-22 (default: 3)
    RCH_MOCK_SSH          Enable mock SSH for testing (set to 1)
    RCH_TEST_MODE         Enable test mode (set to 1)
    RCH_ENABLE_METRICS    Enable metrics collection (set to true)

CONFIG PRECEDENCE (highest to lowest):
    1. Command-line arguments
    2. Environment variables
    3. Profile defaults (RCH_PROFILE)
    4. .env / .rch.env files
    5. Project config (.rch/config.toml)
    6. User config (~/.config/rch/config.toml)
    7. Built-in defaults

For more information, see: https://github.com/anthropics/rch"#
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
    /// Start, stop, and manage the local RCH daemon
    #[command(after_help = r#"EXAMPLES:
    rch daemon start      # Start the daemon in background
    rch daemon status     # Check if daemon is running
    rch daemon logs -n 100  # View last 100 log lines
    rch daemon restart    # Restart after config changes"#)]
    Daemon {
        #[command(subcommand)]
        action: DaemonAction,
    },

    /// Manage remote compilation workers
    #[command(after_help = r#"EXAMPLES:
    rch workers list          # Show all configured workers
    rch workers probe --all   # Test connectivity to all workers
    rch workers probe css     # Probe specific worker
    rch workers benchmark     # Run speed tests on all workers
    rch workers drain css     # Stop sending jobs to worker
    rch workers enable css    # Resume sending jobs to worker"#)]
    Workers {
        #[command(subcommand)]
        action: WorkersAction,
    },

    /// Show system status overview
    #[command(after_help = r#"EXAMPLES:
    rch status                  # Quick overview
    rch status --workers        # Include worker details
    rch status --jobs           # Show active compilations
    rch status --workers --jobs # Full status report"#)]
    Status {
        /// Show worker details
        #[arg(long)]
        workers: bool,

        /// Show active jobs
        #[arg(long)]
        jobs: bool,
    },

    /// View and manage RCH configuration
    #[command(after_help = r#"EXAMPLES:
    rch config show           # Display effective config
    rch config show --sources # Show where each value comes from
    rch config init           # Create project .rch/config.toml
    rch config validate       # Check for config errors
    rch config set log_level debug  # Update a setting
    rch config export --format=env  # Export as .env format"#)]
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },

    /// Install and manage the Claude Code PreToolUse hook
    #[command(after_help = r#"EXAMPLES:
    rch hook install    # Register RCH as PreToolUse hook
    rch hook uninstall  # Remove the hook
    rch hook test       # Test with a sample 'cargo build' command

The hook intercepts Bash tool calls and transparently offloads
compilation commands to remote workers."#)]
    Hook {
        #[command(subcommand)]
        action: HookAction,
    },

    /// Detect and manage AI coding agents (Claude Code, Gemini CLI, etc.)
    #[command(after_help = r#"EXAMPLES:
    rch agents list               # Show detected agents
    rch agents list --all         # Include non-installed agents
    rch agents status             # Check hook status for all agents
    rch agents status claude-code # Check specific agent
    rch agents install-hook gemini-cli --dry-run  # Preview hook install"#)]
    Agents {
        #[command(subcommand)]
        action: AgentsAction,
    },

    /// Generate and install shell completion scripts
    #[command(after_help = r#"EXAMPLES:
    # Generate completions to stdout
    rch completions generate bash > ~/.local/share/bash-completion/completions/rch

    # Install completions automatically (recommended)
    rch completions install bash
    rch completions install zsh
    rch completions install fish

    # Install for current shell (auto-detected)
    rch completions install

    # Check installation status
    rch completions status

    # Uninstall completions
    rch completions uninstall bash

INSTALL LOCATIONS:
    Bash:       ~/.local/share/bash-completion/completions/rch
    Zsh:        ~/.zfunc/_rch (adds fpath to .zshrc)
    Fish:       ~/.config/fish/completions/rch.fish
    PowerShell: ~/.config/powershell/rch.ps1"#)]
    Completions {
        #[command(subcommand)]
        action: CompletionsAction,
    },

    /// Run comprehensive diagnostics and optionally auto-fix issues
    #[command(after_help = r#"EXAMPLES:
    rch doctor              # Run all diagnostic checks
    rch doctor --fix        # Attempt to fix safe issues
    rch doctor -v           # Show detailed output
    rch doctor --json       # Output as JSON for scripting

CHECKS PERFORMED:
    Prerequisites   - rsync, zstd, ssh, rustup, cargo
    Configuration   - config.toml, workers.toml validity
    SSH Keys        - Identity files exist with correct permissions
    Daemon          - Socket exists and responds
    Hooks           - Claude Code hook installed
    Workers         - Connectivity (with --verbose)"#)]
    Doctor {
        /// Attempt to fix safe issues (e.g., key permissions)
        #[arg(long)]
        fix: bool,

        /// Allow installing missing prerequisites (requires confirmation)
        #[arg(long)]
        install_deps: bool,
    },

    /// Update RCH binaries on local machine and/or workers
    #[command(after_help = r#"EXAMPLES:
    rch update --check          # Check for available updates
    rch update                  # Update to latest stable
    rch update --channel=beta   # Update to beta channel
    rch update --version=v0.3.0 # Install specific version
    rch update --fleet          # Update all workers too
    rch update --dry-run        # Preview what would happen
    rch update --rollback       # Restore previous version
    rch update --verify         # Check installation integrity"#)]
    Update {
        /// Check for updates without installing
        #[arg(long)]
        check: bool,

        /// Install specific version (e.g., v0.2.0)
        #[arg(long)]
        version: Option<String>,

        /// Release channel: stable (default), beta, nightly
        #[arg(long, default_value = "stable")]
        channel: String,

        /// Update all configured workers
        #[arg(long)]
        fleet: bool,

        /// Restore previous version from backup
        #[arg(long)]
        rollback: bool,

        /// Verify current installation integrity
        #[arg(long)]
        verify: bool,

        /// Skip confirmation prompts
        #[arg(long, short = 'y')]
        yes: bool,

        /// Show planned actions without executing
        #[arg(long)]
        dry_run: bool,

        /// Update binaries but don't restart daemon
        #[arg(long)]
        no_restart: bool,

        /// Wait up to N seconds for builds to complete (default: 60)
        #[arg(long, default_value = "60")]
        drain_timeout: u64,

        /// Display changelog between current and target version
        #[arg(long)]
        show_changelog: bool,
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
    /// Deploy rch-wkr binary to remote workers
    DeployBinary {
        /// Worker ID to deploy to, or --all for all workers
        worker: Option<String>,
        /// Deploy to all workers
        #[arg(long)]
        all: bool,
        /// Force deployment even if version matches
        #[arg(long)]
        force: bool,
        /// Show planned actions without executing
        #[arg(long)]
        dry_run: bool,
    },
    /// Discover potential workers from SSH config and shell aliases
    #[command(after_help = r#"EXAMPLES:
    rch workers discover           # List discovered hosts
    rch workers discover --probe   # Probe discovered hosts for connectivity
    rch workers discover --add     # Add discovered hosts to workers.toml"#)]
    Discover {
        /// Probe discovered hosts for SSH connectivity
        #[arg(long)]
        probe: bool,
        /// Add discovered hosts to workers.toml
        #[arg(long)]
        add: bool,
        /// Skip interactive confirmation when adding
        #[arg(long)]
        yes: bool,
    },
    /// Synchronize Rust toolchain to workers
    #[command(after_help = r#"EXAMPLES:
    rch workers sync-toolchain css           # Sync toolchain to specific worker
    rch workers sync-toolchain --all         # Sync toolchain to all workers
    rch workers sync-toolchain --all --dry-run  # Preview what would happen"#)]
    SyncToolchain {
        /// Worker ID to sync, or --all for all workers
        worker: Option<String>,
        /// Sync to all workers
        #[arg(long)]
        all: bool,
        /// Show planned actions without executing
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(Subcommand)]
enum ConfigAction {
    /// Show effective configuration
    Show {
        /// Show where each value comes from (env, project, user, default)
        #[arg(long)]
        sources: bool,
    },
    /// Initialize project config
    Init,
    /// Validate configuration
    Validate,
    /// Set a configuration value
    Set { key: String, value: String },
    /// Export configuration as shell script (for sourcing)
    Export {
        /// Output format: shell (default) or env
        #[arg(long, default_value = "shell")]
        format: String,
    },
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

#[derive(Subcommand)]
enum AgentsAction {
    /// List detected AI coding agents
    List {
        /// Show all agents, including not installed
        #[arg(long)]
        all: bool,
    },
    /// Show hook status for an agent
    Status {
        /// Agent to check (e.g., claude-code, gemini-cli)
        agent: Option<String>,
    },
    /// Install RCH hook for an agent
    InstallHook {
        /// Agent to install hook for
        agent: String,
        /// Show what would be done without making changes
        #[arg(long)]
        dry_run: bool,
    },
    /// Uninstall RCH hook from an agent
    UninstallHook {
        /// Agent to uninstall hook from
        agent: String,
        /// Show what would be done without making changes
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(Subcommand)]
enum CompletionsAction {
    /// Generate completion script to stdout
    Generate {
        /// Shell to generate completions for
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },
    /// Install completions to standard shell locations
    Install {
        /// Shell to install completions for (auto-detected if omitted)
        #[arg(value_enum)]
        shell: Option<clap_complete::Shell>,
        /// Show what would be done without making changes
        #[arg(long)]
        dry_run: bool,
    },
    /// Uninstall completions
    Uninstall {
        /// Shell to uninstall completions for
        #[arg(value_enum)]
        shell: clap_complete::Shell,
        /// Show what would be done without making changes
        #[arg(long)]
        dry_run: bool,
    },
    /// Show completion installation status for all shells
    Status,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Handle dynamic shell completions (exits if handling a completion request)
    CompleteEnv::with_factory(Cli::command).complete();

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
            Commands::Agents { action } => handle_agents(action, &ctx).await,
            Commands::Completions { action } => handle_completions(action, &ctx),
            Commands::Doctor { fix, install_deps } => handle_doctor(fix, install_deps, &ctx).await,
            Commands::Update {
                check,
                version,
                channel,
                fleet,
                rollback,
                verify,
                yes,
                dry_run,
                no_restart,
                drain_timeout,
                show_changelog,
            } => {
                handle_update(
                    &ctx,
                    check,
                    version,
                    channel,
                    fleet,
                    rollback,
                    verify,
                    yes,
                    dry_run,
                    no_restart,
                    drain_timeout,
                    show_changelog,
                )
                .await
            }
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
        WorkersAction::DeployBinary {
            worker,
            all,
            force,
            dry_run,
        } => {
            commands::workers_deploy_binary(worker, all, force, dry_run, ctx).await?;
        }
        WorkersAction::Discover { probe, add, yes } => {
            commands::workers_discover(probe, add, yes, ctx).await?;
        }
        WorkersAction::SyncToolchain { worker, all, dry_run } => {
            commands::workers_sync_toolchain(worker, all, dry_run, ctx).await?;
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
        ConfigAction::Show { sources } => {
            commands::config_show(sources, ctx)?;
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
        ConfigAction::Export { format } => {
            commands::config_export(&format, ctx)?;
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

async fn handle_agents(action: AgentsAction, ctx: &OutputContext) -> Result<()> {
    match action {
        AgentsAction::List { all } => {
            commands::agents_list(all, ctx)?;
        }
        AgentsAction::Status { agent } => {
            commands::agents_status(agent, ctx)?;
        }
        AgentsAction::InstallHook { agent, dry_run } => {
            commands::agents_install_hook(&agent, dry_run, ctx)?;
        }
        AgentsAction::UninstallHook { agent, dry_run } => {
            commands::agents_uninstall_hook(&agent, dry_run, ctx)?;
        }
    }
    Ok(())
}

async fn handle_doctor(fix: bool, install_deps: bool, ctx: &OutputContext) -> Result<()> {
    use crate::doctor::DoctorOptions;
    let options = DoctorOptions {
        fix,
        install_deps,
        verbose: ctx.is_verbose(),
    };
    crate::doctor::run_doctor(ctx, options).await
}

#[allow(clippy::too_many_arguments)]
async fn handle_update(
    ctx: &OutputContext,
    check_only: bool,
    version: Option<String>,
    channel: String,
    fleet: bool,
    do_rollback: bool,
    verify_only: bool,
    yes: bool,
    dry_run: bool,
    no_restart: bool,
    drain_timeout: u64,
    show_changelog: bool,
) -> Result<()> {
    let channel = channel
        .parse::<update::Channel>()
        .map_err(|e| anyhow::anyhow!(e))?;

    update::run_update(
        ctx,
        check_only,
        version,
        channel,
        fleet,
        do_rollback,
        verify_only,
        dry_run,
        yes,
        no_restart,
        drain_timeout,
        show_changelog,
    )
    .await
    .map_err(|e| anyhow::anyhow!("{}", e))
}

/// Handle completions subcommands
fn handle_completions(action: CompletionsAction, ctx: &OutputContext) -> Result<()> {
    match action {
        CompletionsAction::Generate { shell } => {
            clap_complete::generate(shell, &mut Cli::command(), "rch", &mut std::io::stdout());
            Ok(())
        }
        CompletionsAction::Install { shell, dry_run } => {
            let shell = shell.or_else(completions::detect_current_shell).ok_or_else(|| {
                anyhow::anyhow!(
                    "Could not detect current shell. Please specify a shell explicitly:\n\
                     rch completions install bash\n\
                     rch completions install zsh\n\
                     rch completions install fish"
                )
            })?;
            completions::install_completions(shell, ctx, dry_run)?;
            Ok(())
        }
        CompletionsAction::Uninstall { shell, dry_run } => {
            completions::uninstall_completions(shell, ctx, dry_run)?;
            Ok(())
        }
        CompletionsAction::Status => {
            completions::show_status(ctx)?;
            Ok(())
        }
    }
}
