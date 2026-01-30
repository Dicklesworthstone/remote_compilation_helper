//! Remote Compilation Helper - PreToolUse Hook CLI
//!
//! This is the main entry point for the RCH hook that integrates with
//! Claude Code's PreToolUse hook system. It intercepts compilation commands
//! and routes them to remote workers for execution.

#![forbid(unsafe_code)]

pub mod agent;
mod cache;
mod commands;
mod completions;
mod config;
mod doctor;
pub mod error;
pub mod fleet;
#[cfg_attr(not(unix), path = "hook_windows.rs")]
mod hook;
pub mod state;
mod status_display;
mod status_types;
mod toolchain;
mod transfer;
pub mod tui;
pub mod ui;
mod update;

use anyhow::Result;
use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::CompleteEnv;
use rch_common::{ApiResponse, LogConfig, init_logging};
use schemars::schema_for;
use std::env;
use std::path::PathBuf;
use std::sync::Arc;
use ui::{ColorChoice, OutputConfig, OutputContext, OutputFormat};

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
    RCH_SSH_SERVER_ALIVE_INTERVAL_SECS  SSH keepalive interval (ServerAliveInterval)
    RCH_SSH_CONTROL_PERSIST_SECS        SSH ControlPersist idle seconds (0 disables persistence)
    RCH_TRANSFER_ZSTD_LEVEL  Compression level 1-22 (default: 3)
    RCH_ENV_ALLOWLIST     Comma-separated env vars to forward (e.g., RUSTFLAGS,CARGO_TARGET_DIR)
    RCH_VISIBILITY        Hook output visibility: none, summary, verbose
    RCH_VERBOSE           Convenience: sets visibility=verbose when true
    RCH_QUIET             Force visibility=none when true
    RCH_OUTPUT_FORMAT     Machine output format: json, toon (implies --json)
    TOON_DEFAULT_FORMAT   Default machine format when --json is set (json/toon)
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
    #[arg(short = 'j', long, global = true)]
    json: bool,

    /// Machine output format: json or toon
    #[arg(
        short = 'F',
        long,
        global = true,
        value_name = "format",
        env = "RCH_OUTPUT_FORMAT",
        value_parser = ["json", "toon"]
    )]
    format: Option<String>,

    /// Color output mode: auto, always, never
    #[arg(long, global = true, default_value = "auto")]
    color: String,

    /// Emit JSON Schema for command output format
    ///
    /// When specified with a command, outputs the JSON Schema for that command's
    /// JSON output format. Use to validate output or understand structure programmatically.
    ///
    /// Examples:
    ///   rch --schema config lint    # Schema for 'config lint' output
    ///   rch --schema workers list   # Schema for 'workers list' output
    ///   rch --schema daemon status  # Schema for 'daemon status' output
    #[arg(long, global = true)]
    schema: bool,

    /// Emit help text as JSON for machine parsing
    ///
    /// Outputs the CLI structure as JSON, including all subcommands, arguments,
    /// and descriptions. Useful for agents to discover available functionality.
    ///
    /// Examples:
    ///   rch --help-json             # Full CLI structure as JSON
    ///   rch --help-json workers     # Workers subcommand structure
    #[arg(long, global = true)]
    help_json: bool,

    /// List all RCH capabilities for machine discovery
    ///
    /// Outputs a JSON object describing all RCH features, supported runtimes,
    /// and available commands. Enables agents to discover functionality
    /// without parsing human-readable help text.
    ///
    /// Example output includes:
    ///   - version and build info
    ///   - supported runtimes (rust, bun, node)
    ///   - available subcommands with brief descriptions
    ///   - feature flags and their status
    #[arg(long)]
    capabilities: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Interactive first-time setup wizard
    #[command(
        alias = "setup",
        after_help = r#"EXAMPLES:
    rch init              # Start interactive setup wizard
    rch setup             # Same as 'rch init' (alias)
    rch init --yes        # Accept all defaults without prompting
    rch init --skip-test  # Skip the test compilation step

The wizard will guide you through:
  1. Detecting potential workers from SSH config
  2. Selecting which hosts to use as workers
  3. Probing hosts for connectivity
  4. Deploying rch-wkr binary to workers
  5. Synchronizing Rust toolchain
  6. Starting the daemon
  7. Installing the Claude Code hook
  8. Running a test compilation

For more control, use the individual commands:
  rch workers discover --add
  rch workers setup --all
  rch daemon start
  rch hook install"#
    )]
    Init {
        /// Accept all defaults without prompting
        #[arg(long, short = 'y')]
        yes: bool,
        /// Skip the test compilation step
        #[arg(long)]
        skip_test: bool,
    },

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
    rch workers enable css    # Resume sending jobs to worker
    rch workers disable css   # Take worker offline

WORKER STATES:
    HEALTHY    Normal operation - accepting and running jobs
    DRAINING   Not accepting new jobs, finishing current ones
    DRAINED    Idle after drain completes (no active jobs)
    DISABLED   Completely offline, skipped by job assignment

STATE TRANSITIONS:
    drain:   HEALTHY -> DRAINING -> DRAINED (automatic when jobs finish)
    disable: DRAINED -> DISABLED (or use --drain flag from any state)
    enable:  DRAINING/DRAINED/DISABLED -> HEALTHY

Use 'drain' to gracefully stop a worker before maintenance.
Use 'enable' to bring a drained/disabled worker back online.
Use 'disable' to mark a worker as unavailable (optionally with --reason)."#)]
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
        #[arg(short = 'w', long)]
        workers: bool,

        /// Show active jobs
        #[arg(short = 'J', long)]
        jobs: bool,
    },

    /// Quick health check - is RCH working?
    ///
    /// Single command to answer: "Is RCH working right now?"
    /// Exit codes: 0=ready, 1=degraded (partial), 2=not ready.
    #[command(after_help = r#"EXAMPLES:
    rch check               # Quick status check
    rch check --verbose     # Detailed health report
    rch check --json        # Machine-readable output

EXIT CODES:
    0   Ready - daemon running, all workers healthy
    1   Degraded - daemon running, some workers unreachable
    2   Not ready - daemon not running or fatal issues

USAGE:
    # CI/CD health gate
    rch check || exit 1

    # Monitoring integration
    rch check --json | jq '.data.status'

    # Quick troubleshooting
    rch check --verbose"#)]
    Check,

    /// Show build queue - active and waiting compilations
    #[command(after_help = r#"EXAMPLES:
    rch queue                 # Show active builds and queue
    rch queue --watch         # Watch queue in real-time (updates every second)
    rch queue --json          # Output as JSON for scripting

The queue shows:
  - Currently running builds with worker, elapsed time
  - Queued builds waiting for workers
  - Worker availability summary"#)]
    Queue {
        /// Watch mode - continuously update (1s interval)
        #[arg(long, short = 'w')]
        watch: bool,

        /// Follow mode - stream build events as they happen (like tail -f)
        #[arg(long, short = 'f')]
        follow: bool,
    },

    /// Cancel active builds
    #[command(after_help = r#"EXAMPLES:
    rch cancel 42             # Cancel build with ID 42
    rch cancel --all          # Cancel all active builds (with confirmation)
    rch cancel --all --yes    # Cancel all without confirmation
    rch cancel 42 --force     # Force kill (SIGKILL instead of SIGTERM)

Graceful cancellation sends SIGTERM to the build process, allowing it
to clean up. Use --force to immediately terminate with SIGKILL."#)]
    Cancel {
        /// Build ID to cancel (use 'rch queue' to see active builds)
        build_id: Option<u64>,

        /// Cancel all active builds
        #[arg(short = 'a', long)]
        all: bool,

        /// Force termination (SIGKILL instead of SIGTERM)
        #[arg(long, short = 'f')]
        force: bool,

        /// Skip confirmation prompt for --all
        #[arg(long, short = 'y')]
        yes: bool,

        /// Preview what would be cancelled without actually cancelling
        #[arg(long, short = 'n')]
        dry_run: bool,
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

    /// Explain why a command would or wouldn't be offloaded
    #[command(after_help = r#"EXAMPLES:
    rch diagnose "cargo build --release"
    rch diagnose cargo build --release
    rch diagnose "bun test"
    rch diagnose "ls -la"
    rch diagnose --dry-run "cargo build"  # Show full pipeline without side effects"#)]
    Diagnose {
        /// Command to analyze (quote or pass as multiple args)
        #[arg(required = true, num_args = 1.., trailing_var_arg = true)]
        command: Vec<String>,
        /// Show full offload pipeline steps without any network side effects
        #[arg(long, short = 'n')]
        dry_run: bool,
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
    rch doctor --fix --dry-run  # Show what would be fixed
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

        /// Show what would be fixed without making changes
        #[arg(long)]
        dry_run: bool,

        /// Allow installing missing prerequisites (requires confirmation)
        #[arg(long)]
        install_deps: bool,
    },

    /// Verify remote compilation by running a self-test
    #[command(after_help = r#"EXAMPLES:
    rch self-test                     # Test the first configured worker
    rch self-test --all               # Test all configured workers
    rch self-test --worker css        # Test a specific worker
    rch self-test --project ../app    # Test a different project directory
    rch self-test --timeout 600       # Increase timeout to 10 minutes
    rch self-test --debug             # Use debug build instead of release
    rch self-test status              # Show schedule and last run
    rch self-test history --limit 10  # Show recent runs"#)]
    SelfTest {
        /// Self-test subcommand
        #[command(subcommand)]
        action: Option<SelfTestAction>,
        /// Test a specific worker by id
        #[arg(long)]
        worker: Option<String>,
        /// Test all configured workers
        #[arg(long)]
        all: bool,
        /// Project path to test (defaults to current directory)
        #[arg(long)]
        project: Option<PathBuf>,
        /// Timeout in seconds for each worker test
        #[arg(long, default_value = "300")]
        timeout: u64,
        /// Use debug build instead of release
        #[arg(long)]
        debug: bool,
        /// Run using scheduled settings (ignores worker selection flags)
        #[arg(long)]
        scheduled: bool,
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

    /// Deploy, rollback, and manage the worker fleet
    #[command(after_help = r#"EXAMPLES:
    rch fleet deploy                    # Deploy to all workers
    rch fleet deploy --canary 25        # Canary deployment to 25%
    rch fleet rollback                  # Rollback to previous version
    rch fleet status                    # Show deployment status
    rch fleet verify                    # Verify installations
    rch fleet history                   # Show deployment history

Fleet management provides centralized deployment, rollback, and
monitoring capabilities for the rch-wkr worker agent across all
configured remote workers."#)]
    Fleet {
        #[command(subcommand)]
        action: FleetAction,
    },

    /// View and analyze worker SpeedScores
    #[command(
        name = "speedscore",
        after_help = r#"EXAMPLES:
    rch speedscore css              # Show SpeedScore for worker 'css'
    rch speedscore css --verbose    # Show detailed component breakdown
    rch speedscore css --history    # Show score history
    rch speedscore css --history --days 7  # Last 7 days of history
    rch speedscore --all            # Show SpeedScores for all workers

SpeedScore is a composite performance metric (0-100) combining:
  - CPU performance (30%)
  - Memory efficiency (15%)
  - Disk I/O (20%)
  - Network latency (15%)
  - Compilation speed (20%)

Ratings:
  90+ Excellent | 75+ Very Good | 60+ Good | 45+ Average | 30+ Below Average"#
    )]
    SpeedScore {
        /// Worker ID to show SpeedScore for
        worker: Option<String>,
        /// Show SpeedScores for all workers
        #[arg(long)]
        all: bool,
        /// Show SpeedScore history
        #[arg(long)]
        history: bool,
        /// Number of days for history (default: 30)
        #[arg(long, default_value = "30")]
        days: u32,
        /// Max history entries to show (default: 20)
        #[arg(long, default_value = "20")]
        limit: usize,
    },

    /// Interactive TUI dashboard for real-time monitoring
    #[command(
        alias = "tui",
        after_help = r#"EXAMPLES:
    rch dashboard                      # Launch TUI dashboard
    rch dashboard --refresh 500        # 500ms refresh rate
    rch dashboard --no-mouse           # Disable mouse support
    rch dashboard --high-contrast      # High contrast mode
    rch dashboard --color-blind tritanopia  # Color blind palette
    rch dashboard --test-mode          # Render once and exit (CI-friendly)
    rch dashboard --mock-data          # Use deterministic mock data (no daemon required)
    rch dashboard --dump-state         # Print JSON state and exit (automation)

The dashboard provides real-time monitoring of:
  - Worker status and slot utilization
  - Active build progress
  - Build history with filtering
  - Log tail view for active builds

Controls:
  q/Esc    - Quit
  ↑/↓      - Navigate
  Tab      - Switch panels
  r        - Refresh data
  ?        - Help"#
    )]
    Dashboard {
        /// Refresh interval in milliseconds (default: 1000)
        #[arg(long, default_value = "1000", alias = "refresh-ms")]
        refresh: u64,

        /// Disable mouse support
        #[arg(long)]
        no_mouse: bool,

        /// Render once and exit (no raw mode / alt-screen).
        ///
        /// Useful for CI/scripting where an interactive terminal isn't available.
        #[arg(long)]
        test_mode: bool,

        /// Populate the dashboard with deterministic mock data (no daemon required).
        #[arg(long)]
        mock_data: bool,

        /// Dump dashboard state as JSON to stdout and exit (no terminal control).
        ///
        /// Intended for automation and E2E scripts.
        #[arg(long)]
        dump_state: bool,

        /// High contrast mode for accessibility
        #[arg(long)]
        high_contrast: bool,

        /// Color blind palette (none, deuteranopia, protanopia, tritanopia)
        #[arg(long, value_enum, default_value = "none")]
        color_blind: tui::ColorBlindMode,
    },

    /// Launch the web-based dashboard in your browser
    #[command(after_help = r#"EXAMPLES:
    rch web                           # Start dev server and open browser
    rch web --port 3001               # Use custom port
    rch web --no-open                 # Don't open browser automatically
    rch web --prod                    # Serve production build

The web dashboard provides a modern browser-based interface for:
  - Viewing worker status and slot utilization
  - Monitoring active and recent builds
  - Viewing system issues and metrics
  - Real-time updates via polling"#)]
    Web {
        /// Port to run the web server on (default: 3000)
        #[arg(long, default_value = "3000")]
        port: u16,

        /// Don't automatically open the browser
        #[arg(long)]
        no_open: bool,

        /// Serve production build instead of dev server
        #[arg(long)]
        prod: bool,
    },

    /// Export API schemas and error code documentation
    #[command(after_help = r#"EXAMPLES:
    rch schema export                     # Export to docs/api/schemas/
    rch schema export --output ./schemas  # Custom output directory
    rch schema export --json              # Output summary as JSON
    rch schema list                       # List available schemas

The schema command generates machine-readable API documentation:
  - api-response.schema.json    JSON Schema for API response envelope
  - api-error.schema.json       JSON Schema for error structure
  - error-codes.json            Complete error code catalog

These files enable agents and tooling to validate RCH output
and understand error codes programmatically."#)]
    Schema {
        #[command(subcommand)]
        action: SchemaAction,
    },
}

#[derive(Subcommand)]
enum SchemaAction {
    /// Export all schemas to a directory
    Export {
        /// Output directory (default: docs/api/schemas/)
        #[arg(long, short = 'o')]
        output: Option<PathBuf>,
    },
    /// List available schemas
    List,
}

#[derive(Subcommand)]
enum SelfTestAction {
    /// Show schedule and last run information
    Status,
    /// Show recent self-test runs
    History {
        /// Number of runs to show (default: 10)
        #[arg(long, default_value = "10")]
        limit: usize,
    },
}

#[derive(Subcommand)]
enum DaemonAction {
    /// Start the daemon
    Start,
    /// Stop the daemon (prompts for confirmation if builds are active)
    Stop {
        /// Skip confirmation prompt
        #[arg(short = 'y', long)]
        yes: bool,
    },
    /// Restart the daemon (prompts for confirmation if builds are active)
    Restart {
        /// Skip confirmation prompt
        #[arg(short = 'y', long)]
        yes: bool,
    },
    /// Show daemon status
    Status,
    /// Tail daemon logs
    Logs {
        /// Number of lines to show
        #[arg(short = 'n', long, default_value = "50")]
        lines: usize,
    },
    /// Reload configuration without restart
    Reload,
}

impl DaemonAction {
    /// Return the subcommand name as a string for error messages.
    fn as_str(&self) -> &'static str {
        match self {
            DaemonAction::Start => "start",
            DaemonAction::Stop { .. } => "stop",
            DaemonAction::Restart { .. } => "restart",
            DaemonAction::Status => "status",
            DaemonAction::Logs { .. } => "logs",
            DaemonAction::Reload => "reload",
        }
    }
}

#[derive(Subcommand)]
enum WorkersAction {
    /// List configured workers
    List {
        /// Show SpeedScore for each worker
        #[arg(long)]
        speedscore: bool,
    },
    /// Show worker runtime capabilities
    Capabilities {
        /// Refresh cached capabilities by probing workers now
        #[arg(long)]
        refresh: bool,
        /// Optional command to evaluate required runtime
        #[arg(long)]
        command: Option<String>,
    },
    /// Probe worker connectivity
    Probe {
        /// Worker ID to probe, or --all for all workers
        worker: Option<String>,
        /// Probe all workers
        #[arg(short = 'a', long)]
        all: bool,
    },
    /// Run speed benchmarks
    Benchmark,

    /// Drain a worker (stop accepting new jobs, finish current ones)
    ///
    /// A drained worker will complete any active builds but won't accept new ones.
    /// Use this before maintenance or when you want to gracefully stop a worker.
    /// Use 'rch workers enable' to resume normal operation.
    #[command(after_help = r#"EXAMPLES:
    rch workers drain css     # Drain worker 'css' (completes active builds)

The worker will transition: HEALTHY → DRAINING → DRAINED (when jobs finish)
Use 'rch workers list' to monitor the drain progress."#)]
    Drain {
        /// Worker ID to drain
        worker: String,
    },

    /// Enable a worker (resume accepting jobs)
    ///
    /// Brings a drained or disabled worker back to normal operation.
    /// The worker will immediately start accepting new compilation jobs.
    #[command(after_help = r#"EXAMPLES:
    rch workers enable css    # Resume normal operation for worker 'css'

The worker will transition: DRAINING/DRAINED/DISABLED → HEALTHY"#)]
    Enable {
        /// Worker ID to enable
        worker: String,
    },

    /// Disable a worker (mark as offline)
    ///
    /// A disabled worker is excluded from job assignment entirely.
    /// Use this when a worker is unavailable (e.g., maintenance, network issues).
    /// Optionally specify --reason to document why the worker is disabled.
    /// Use --drain to complete active builds before disabling.
    #[command(after_help = r#"EXAMPLES:
    rch workers disable css                    # Disable immediately
    rch workers disable css --reason "hardware upgrade"
    rch workers disable css --drain            # Finish builds first

Use 'rch workers enable css' to bring the worker back online."#)]
    Disable {
        /// Worker ID to disable
        worker: String,
        /// Reason for disabling (e.g., "maintenance window")
        #[arg(long)]
        reason: Option<String>,
        /// Drain active builds before fully disabling
        #[arg(long)]
        drain: bool,
    },
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
    /// Complete worker setup (deploy binary + sync toolchain)
    #[command(after_help = r#"EXAMPLES:
    rch workers setup css           # Full setup for specific worker
    rch workers setup --all         # Setup all workers
    rch workers setup --all --dry-run  # Preview what would happen"#)]
    Setup {
        /// Worker ID to setup, or --all for all workers
        worker: Option<String>,
        /// Setup all workers
        #[arg(long)]
        all: bool,
        /// Show planned actions without executing
        #[arg(long)]
        dry_run: bool,
        /// Skip binary deployment
        #[arg(long)]
        skip_binary: bool,
        /// Skip toolchain synchronization
        #[arg(long)]
        skip_toolchain: bool,
    },
    /// Interactive wizard to add a new worker
    #[command(after_help = r#"EXAMPLES:
    rch workers init                # Interactive wizard to add a worker
    rch workers init --yes          # Accept all detected defaults

This wizard will guide you through adding a worker:
  1. Enter hostname/IP and SSH credentials
  2. Test SSH connection
  3. Auto-detect CPU cores
  4. Auto-detect Rust toolchain
  5. Save to workers.toml"#)]
    Init {
        /// Accept detected defaults without prompting
        #[arg(long, short = 'y')]
        yes: bool,
    },
}

impl WorkersAction {
    /// Return the subcommand name as a string for error messages.
    fn as_str(&self) -> &'static str {
        match self {
            WorkersAction::List { .. } => "list",
            WorkersAction::Capabilities { .. } => "capabilities",
            WorkersAction::Probe { .. } => "probe",
            WorkersAction::Benchmark => "benchmark",
            WorkersAction::Drain { .. } => "drain",
            WorkersAction::Enable { .. } => "enable",
            WorkersAction::Disable { .. } => "disable",
            WorkersAction::DeployBinary { .. } => "deploy-binary",
            WorkersAction::Discover { .. } => "discover",
            WorkersAction::SyncToolchain { .. } => "sync-toolchain",
            WorkersAction::Setup { .. } => "setup",
            WorkersAction::Init { .. } => "init",
        }
    }
}

#[derive(Subcommand)]
enum ConfigAction {
    /// Show effective configuration
    Show {
        /// Show where each value comes from (env, project, user, default)
        #[arg(long)]
        sources: bool,
    },
    /// Initialize configuration files with optional interactive wizard
    #[command(after_help = r#"EXAMPLES:
    rch config init                    # Create config files with defaults
    rch config init --wizard           # Interactive wizard with prompts
    rch config init --non-interactive  # Generate full config without prompts

The wizard helps you configure:
  • General settings (log level, socket path)
  • Compilation thresholds (confidence, min local time)
  • Transfer settings (compression, exclude patterns)
  • Worker definitions (host, user, identity file, slots)"#)]
    Init {
        /// Run interactive configuration wizard
        #[arg(long)]
        wizard: bool,
        /// Generate full wizard config with defaults (no interactive prompts)
        #[arg(long)]
        non_interactive: bool,
    },
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
    /// Check configuration for potential issues and misconfigurations
    #[command(after_help = r#"EXAMPLES:
    rch config lint               # Check for issues with warnings/errors
    rch config lint --json        # Machine-readable output for CI

Checks for:
  • Missing workers configuration
  • Conflicting settings (force_local + force_remote)
  • Invalid regex patterns in excludes
  • Risky exclude patterns (removing essential directories)
  • Performance warnings (compression=0 with large projects)"#)]
    Lint,
    /// Show configuration values that differ from defaults
    #[command(after_help = r#"EXAMPLES:
    rch config diff               # Show all non-default values
    rch config diff --json        # Machine-readable output

Shows:
  • Key name
  • Current value
  • Default value
  • Source (env, project, user)"#)]
    Diff,
}

impl ConfigAction {
    /// Return the subcommand name as a string for error messages.
    fn as_str(&self) -> &'static str {
        match self {
            ConfigAction::Show { .. } => "show",
            ConfigAction::Init { .. } => "init",
            ConfigAction::Validate => "validate",
            ConfigAction::Set { .. } => "set",
            ConfigAction::Export { .. } => "export",
            ConfigAction::Lint => "lint",
            ConfigAction::Diff => "diff",
        }
    }
}

#[derive(Subcommand)]
enum HookAction {
    /// Install the Claude Code hook
    Install,
    /// Uninstall the hook
    Uninstall,
    /// Test the hook with a sample command
    Test,
    /// Show hook status
    Status,
}

impl HookAction {
    /// Return the subcommand name as a string for error messages.
    fn as_str(&self) -> &'static str {
        match self {
            HookAction::Install => "install",
            HookAction::Uninstall => "uninstall",
            HookAction::Test => "test",
            HookAction::Status => "status",
        }
    }
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

#[derive(Subcommand)]
enum FleetAction {
    /// Deploy or update rch-wkr to workers
    #[command(after_help = r#"EXAMPLES:
    rch fleet deploy                    # Deploy to all workers
    rch fleet deploy --worker css       # Deploy to specific worker
    rch fleet deploy --canary 25        # Deploy to 25% first, then all
    rch fleet deploy --parallel 4       # Max 4 concurrent deployments
    rch fleet deploy --dry-run          # Preview deployment plan
    rch fleet deploy --verify           # Verify after deployment
    rch fleet deploy --drain-first      # Drain builds before deploy"#)]
    Deploy {
        /// Target specific worker(s), comma-separated
        #[arg(long)]
        worker: Option<String>,
        /// Max parallel deployments (default: 4)
        #[arg(long, default_value = "4")]
        parallel: usize,
        /// Deploy to N% of workers first, wait before full rollout
        #[arg(long)]
        canary: Option<u8>,
        /// Wait time in seconds after canary before full rollout (default: 60)
        #[arg(long, default_value = "60")]
        canary_wait: u64,
        /// Skip rustup/toolchain sync
        #[arg(long)]
        no_toolchain: bool,
        /// Reinstall even if version matches
        #[arg(long)]
        force: bool,
        /// Run post-install verification
        #[arg(long)]
        verify: bool,
        /// Drain active builds before deploy
        #[arg(long)]
        drain_first: bool,
        /// Max wait for drain in seconds (default: 120)
        #[arg(long, default_value = "120")]
        drain_timeout: u64,
        /// Show detailed plan without executing
        #[arg(long)]
        dry_run: bool,
        /// Resume from previous failed deployment
        #[arg(long)]
        resume: bool,
        /// Deploy specific version (default: current local)
        #[arg(long)]
        version: Option<String>,
        /// Write deployment audit log to file
        #[arg(long)]
        audit_log: Option<PathBuf>,
    },

    /// Rollback to previous version
    #[command(after_help = r#"EXAMPLES:
    rch fleet rollback                  # Rollback all to previous version
    rch fleet rollback --worker css     # Rollback specific worker
    rch fleet rollback --to-version v0.1.0  # Rollback to specific version
    rch fleet rollback --dry-run        # Preview rollback plan"#)]
    Rollback {
        /// Rollback specific worker(s)
        #[arg(long)]
        worker: Option<String>,
        /// Rollback to specific version
        #[arg(long)]
        to_version: Option<String>,
        /// Max parallel rollbacks (default: 4)
        #[arg(long, default_value = "4")]
        parallel: usize,
        /// Verify after rollback
        #[arg(long)]
        verify: bool,
        /// Show planned actions without executing
        #[arg(long)]
        dry_run: bool,
    },

    /// Show fleet deployment status
    #[command(after_help = r#"EXAMPLES:
    rch fleet status                    # Quick overview
    rch fleet status --worker css       # Show specific worker
    rch fleet status --watch            # Continuous update"#)]
    Status {
        /// Show specific worker
        #[arg(long)]
        worker: Option<String>,
        /// Continuous update (1s interval)
        #[arg(long)]
        watch: bool,
    },

    /// Verify worker installations
    #[command(after_help = r#"EXAMPLES:
    rch fleet verify                    # Verify all workers
    rch fleet verify --worker css       # Verify specific worker"#)]
    Verify {
        /// Verify specific worker(s)
        #[arg(long)]
        worker: Option<String>,
    },

    /// Drain workers before maintenance
    #[command(after_help = r#"EXAMPLES:
    rch fleet drain css                 # Drain specific worker
    rch fleet drain --all               # Drain all workers
    rch fleet drain css --timeout 300   # Custom drain timeout"#)]
    Drain {
        /// Worker to drain
        worker: Option<String>,
        /// Drain all workers
        #[arg(long)]
        all: bool,
        /// Timeout in seconds (default: 120)
        #[arg(long, default_value = "120")]
        timeout: u64,
    },

    /// Show deployment history
    #[command(after_help = r#"EXAMPLES:
    rch fleet history                   # Show last 10 deployments
    rch fleet history --limit 20        # Show more entries
    rch fleet history --worker css      # Filter by worker"#)]
    History {
        /// Number of deployments to show (default: 10)
        #[arg(long, default_value = "10")]
        limit: usize,
        /// Filter by worker
        #[arg(long)]
        worker: Option<String>,
    },
}

fn machine_output_requested(format: Option<&str>, json_flag: bool) -> bool {
    json_flag || format.is_some()
}

fn resolve_output_format(format: Option<&str>, json_flag: bool) -> OutputFormat {
    if let Some(raw) = format
        && let Some(parsed) = OutputFormat::parse(raw)
    {
        return parsed;
    }

    if json_flag
        && let Ok(value) = env::var("TOON_DEFAULT_FORMAT")
        && let Some(parsed) = OutputFormat::parse(&value)
    {
        return parsed;
    }

    OutputFormat::Json
}

/// Use current-thread runtime for CLI commands to minimize startup overhead.
/// Multi-threaded runtime spawns one thread per CPU core (64 cores = 128MB stack allocations).
/// Current-thread runtime uses a single thread, drastically reducing startup time.
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    // Handle dynamic shell completions (exits if handling a completion request)
    CompleteEnv::with_factory(Cli::command).complete();

    // Early check for --help-json to handle it before full clap parsing
    // (which would fail on subcommands that require further arguments)
    let args: Vec<String> = env::args().collect();
    if args.iter().any(|a| a == "--help-json") {
        let subcommand = args
            .iter()
            .skip(1)
            .find(|a| !a.starts_with('-'))
            .map(|s| s.as_str());
        return handle_help_json_early(subcommand);
    }

    // Early check for --capabilities (standalone flag, no subcommand context needed)
    if args.iter().any(|a| a == "--capabilities") {
        return handle_capabilities();
    }

    let cli = Cli::parse();

    // Initialize logging - ALWAYS use stderr to keep stdout clean for hook JSON
    let base_level = match config::load_config() {
        Ok(cfg) => cfg.general.log_level,
        Err(_) => "info".to_string(),
    };
    let mut log_config = LogConfig::from_env(&base_level).with_stderr();
    if cli.verbose {
        log_config = log_config.with_level("debug");
    } else if cli.quiet {
        log_config = log_config.with_level("error");
    }
    let _logging_guards = init_logging(&log_config)?;

    // Spawn background update check to warm cache (non-blocking)
    update::spawn_update_check_if_needed();

    // Create output context from CLI flags
    let format = resolve_output_format(cli.format.as_deref(), cli.json);
    let machine = machine_output_requested(cli.format.as_deref(), cli.json);
    let output_config = OutputConfig {
        json: machine,
        format,
        verbose: cli.verbose,
        quiet: cli.quiet,
        color: ColorChoice::parse(&cli.color),
        ..Default::default()
    };
    let ctx = Arc::new(OutputContext::new(output_config));

    // Handle --schema flag: output JSON Schema for command's JSON output format
    if cli.schema {
        return handle_schema_request(&cli.command);
    }

    // Note: --help-json and --capabilities are handled early (before Cli::parse)
    // to avoid clap errors when subcommands require additional arguments

    // If no subcommand, we're being invoked as a hook
    match cli.command {
        None => {
            // Running as PreToolUse hook - read from stdin, process, write to stdout
            hook::run_hook().await
        }
        Some(cmd) => match cmd {
            Commands::Init { yes, skip_test } => commands::init_wizard(yes, skip_test, &ctx).await,
            Commands::Daemon { action } => handle_daemon(action, &ctx).await,
            Commands::Workers { action } => handle_workers(action, &ctx).await,
            Commands::Status { workers, jobs } => handle_status(workers, jobs, &ctx).await,
            Commands::Check => commands::check(&ctx).await,
            Commands::Queue { watch, follow } => commands::queue_status(watch, follow, &ctx).await,
            Commands::Cancel {
                build_id,
                all,
                force,
                yes,
                dry_run,
            } => commands::cancel_build(build_id, all, force, yes, dry_run, &ctx).await,
            Commands::Config { action } => handle_config(action, &ctx).await,
            Commands::Diagnose { command, dry_run } => {
                handle_diagnose(command, dry_run, &ctx).await
            }
            Commands::Hook { action } => handle_hook(action, &ctx).await,
            Commands::Agents { action } => handle_agents(action, &ctx).await,
            Commands::Completions { action } => handle_completions(action, &ctx),
            Commands::Doctor {
                fix,
                dry_run,
                install_deps,
            } => handle_doctor(fix, dry_run, install_deps, &ctx).await,
            Commands::SelfTest {
                action,
                worker,
                all,
                project,
                timeout,
                debug,
                scheduled,
            } => {
                commands::self_test(
                    action, worker, all, project, timeout, debug, scheduled, &ctx,
                )
                .await
            }
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
            Commands::Fleet { action } => handle_fleet(action, &ctx).await,
            Commands::SpeedScore {
                worker,
                all,
                history,
                days,
                limit,
            } => commands::speedscore(worker, all, history, days, limit, &ctx).await,
            Commands::Dashboard {
                refresh,
                no_mouse,
                test_mode,
                mock_data,
                dump_state,
                high_contrast,
                color_blind,
            } => {
                let config = tui::TuiConfig {
                    refresh_interval_ms: refresh,
                    mouse_support: !no_mouse,
                    test_mode,
                    mock_data,
                    dump_state,
                    high_contrast,
                    color_blind,
                };
                tui::run_tui(config).await
            }
            Commands::Web {
                port,
                no_open,
                prod,
            } => handle_web(port, no_open, prod, &ctx).await,
            Commands::Schema { action } => handle_schema_command(action, &ctx),
        },
    }
}

/// Handle 'rch schema' subcommands.
fn handle_schema_command(action: SchemaAction, ctx: &OutputContext) -> Result<()> {
    use rch_common::api::{export_schemas, generate_error_catalog};

    match action {
        SchemaAction::Export { output } => {
            let output_dir = output.unwrap_or_else(|| {
                // Default to docs/api/schemas/ relative to project root
                // Try to find project root via Cargo.toml or use current dir
                let cwd = std::env::current_dir().unwrap_or_default();
                cwd.join("docs").join("api").join("schemas")
            });

            let result = export_schemas(&output_dir)?;

            if ctx.is_json() {
                let response = ApiResponse::ok("schema export", result);
                println!("{}", serde_json::to_string_pretty(&response)?);
            } else {
                println!(
                    "Exported {} schema files to {}",
                    result.files_generated, result.output_dir
                );
                for file in &result.files {
                    println!("  - {}", file);
                }
            }
            Ok(())
        }
        SchemaAction::List => {
            #[derive(serde::Serialize, schemars::JsonSchema)]
            struct SchemaListResponse {
                schemas: Vec<SchemaInfo>,
            }

            #[derive(serde::Serialize, schemars::JsonSchema)]
            struct SchemaInfo {
                name: String,
                description: String,
                filename: String,
            }

            let schemas = vec![
                SchemaInfo {
                    name: "API Response".to_string(),
                    description: "JSON Schema for the unified API response envelope".to_string(),
                    filename: "api-response.schema.json".to_string(),
                },
                SchemaInfo {
                    name: "API Error".to_string(),
                    description: "JSON Schema for error response structure".to_string(),
                    filename: "api-error.schema.json".to_string(),
                },
                SchemaInfo {
                    name: "Error Codes".to_string(),
                    description: "Machine-readable error code catalog with all RCH-Exxx codes"
                        .to_string(),
                    filename: "error-codes.json".to_string(),
                },
            ];

            if ctx.is_json() {
                let response = ApiResponse::ok("schema list", SchemaListResponse { schemas });
                println!("{}", serde_json::to_string_pretty(&response)?);
            } else {
                println!("Available RCH API Schemas:\n");
                for schema in &schemas {
                    println!("  {} ({})", schema.name, schema.filename);
                    println!("    {}\n", schema.description);
                }

                // Also show error catalog stats
                let catalog = generate_error_catalog();
                println!("Error Catalog Statistics:");
                println!("  Categories: {}", catalog.categories.len());
                println!("  Error codes: {}", catalog.errors.len());
            }
            Ok(())
        }
    }
}

/// Handle --schema flag: output JSON Schema for the specified command's JSON output format.
fn handle_schema_request(command: &Option<Commands>) -> Result<()> {
    use commands::{
        ConfigDiffResponse, ConfigLintResponse, ConfigShowResponse, ConfigValidationResponse,
        DaemonStatusResponse, DiagnoseResponse, HookActionResponse, WorkersListResponse,
    };

    let schema_json = match command {
        Some(Commands::Config { action }) => match action {
            ConfigAction::Lint => {
                let schema = schema_for!(ConfigLintResponse);
                serde_json::to_string_pretty(&schema)?
            }
            ConfigAction::Diff => {
                let schema = schema_for!(ConfigDiffResponse);
                serde_json::to_string_pretty(&schema)?
            }
            ConfigAction::Show { .. } => {
                let schema = schema_for!(ConfigShowResponse);
                serde_json::to_string_pretty(&schema)?
            }
            ConfigAction::Validate => {
                let schema = schema_for!(ConfigValidationResponse);
                serde_json::to_string_pretty(&schema)?
            }
            _ => {
                eprintln!(
                    "No JSON Schema available for 'config {}' output",
                    action.as_str()
                );
                std::process::exit(1);
            }
        },
        Some(Commands::Workers { action }) => match action {
            WorkersAction::List { .. } => {
                let schema = schema_for!(WorkersListResponse);
                serde_json::to_string_pretty(&schema)?
            }
            _ => {
                eprintln!(
                    "No JSON Schema available for 'workers {}' output",
                    action.as_str()
                );
                std::process::exit(1);
            }
        },
        Some(Commands::Daemon { action }) => match action {
            DaemonAction::Status => {
                let schema = schema_for!(DaemonStatusResponse);
                serde_json::to_string_pretty(&schema)?
            }
            _ => {
                eprintln!(
                    "No JSON Schema available for 'daemon {}' output",
                    action.as_str()
                );
                std::process::exit(1);
            }
        },
        Some(Commands::Diagnose { .. }) => {
            let schema = schema_for!(DiagnoseResponse);
            serde_json::to_string_pretty(&schema)?
        }
        Some(Commands::Hook { action }) => match action {
            HookAction::Install | HookAction::Uninstall | HookAction::Status => {
                let schema = schema_for!(HookActionResponse);
                serde_json::to_string_pretty(&schema)?
            }
            _ => {
                eprintln!(
                    "No JSON Schema available for 'hook {}' output",
                    action.as_str()
                );
                std::process::exit(1);
            }
        },
        None => {
            eprintln!("Usage: rch --schema <command> [subcommand]");
            eprintln!();
            eprintln!("Available schemas:");
            eprintln!("  rch --schema config lint       # ConfigLintResponse");
            eprintln!("  rch --schema config diff       # ConfigDiffResponse");
            eprintln!("  rch --schema config show       # ConfigShowResponse");
            eprintln!("  rch --schema config validate   # ConfigValidationResponse");
            eprintln!("  rch --schema workers list      # WorkersListResponse");
            eprintln!("  rch --schema daemon status     # DaemonStatusResponse");
            eprintln!("  rch --schema diagnose <cmd>    # DiagnoseResponse");
            eprintln!("  rch --schema hook install      # HookActionResponse");
            std::process::exit(0);
        }
        _ => {
            eprintln!("No JSON Schema available for this command");
            std::process::exit(1);
        }
    };

    println!("{schema_json}");
    Ok(())
}

/// JSON structure for --help-json output.
#[derive(Debug, Clone, serde::Serialize, schemars::JsonSchema)]
struct HelpJsonOutput {
    name: String,
    version: String,
    about: Option<String>,
    subcommands: Vec<SubcommandHelp>,
    global_flags: Vec<ArgHelp>,
}

#[derive(Debug, Clone, serde::Serialize, schemars::JsonSchema)]
struct SubcommandHelp {
    name: String,
    about: Option<String>,
    aliases: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    subcommands: Vec<SubcommandHelp>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    arguments: Vec<ArgHelp>,
}

#[derive(Debug, Clone, serde::Serialize, schemars::JsonSchema)]
struct ArgHelp {
    name: String,
    short: Option<char>,
    long: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    help: Option<String>,
    required: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    default_value: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    possible_values: Vec<String>,
}

/// Handle --help-json flag early (before full clap parsing).
/// Takes an optional subcommand name as a string.
fn handle_help_json_early(subcommand: Option<&str>) -> Result<()> {
    let cmd = Cli::command();

    let output = match subcommand {
        None => {
            // Full CLI structure
            build_help_json(&cmd)
        }
        Some(subcmd_name) => {
            // Find the specific subcommand (supporting nested lookups like "workers/list")
            let parts: Vec<&str> = subcmd_name.split('/').collect();
            let mut current_cmd = &cmd;

            for part in &parts {
                match current_cmd
                    .get_subcommands()
                    .find(|s| s.get_name() == *part)
                {
                    Some(sub) => current_cmd = sub,
                    None => {
                        eprintln!("Unknown subcommand: {subcmd_name}");
                        std::process::exit(1);
                    }
                }
            }
            build_help_json(current_cmd)
        }
    };

    let json = serde_json::to_string_pretty(&output)?;
    println!("{json}");
    Ok(())
}

fn build_help_json(cmd: &clap::Command) -> HelpJsonOutput {
    HelpJsonOutput {
        name: cmd.get_name().to_string(),
        version: cmd.get_version().map(|v| v.to_string()).unwrap_or_default(),
        about: cmd.get_about().map(|a| a.to_string()),
        subcommands: cmd
            .get_subcommands()
            .filter(|s| !s.is_hide_set())
            .map(build_subcommand_help)
            .collect(),
        global_flags: cmd
            .get_arguments()
            .filter(|a| a.is_global_set() && a.get_id() != "help" && a.get_id() != "version")
            .map(build_arg_help)
            .collect(),
    }
}

fn build_subcommand_help(cmd: &clap::Command) -> SubcommandHelp {
    SubcommandHelp {
        name: cmd.get_name().to_string(),
        about: cmd.get_about().map(|a| a.to_string()),
        aliases: cmd.get_all_aliases().map(|s| s.to_string()).collect(),
        subcommands: cmd
            .get_subcommands()
            .filter(|s| !s.is_hide_set())
            .map(build_subcommand_help)
            .collect(),
        arguments: cmd
            .get_arguments()
            .filter(|a| a.get_id() != "help" && a.get_id() != "version")
            .map(build_arg_help)
            .collect(),
    }
}

fn build_arg_help(arg: &clap::Arg) -> ArgHelp {
    ArgHelp {
        name: arg.get_id().to_string(),
        short: arg.get_short(),
        long: arg.get_long().map(|s| s.to_string()),
        help: arg.get_help().map(|h| h.to_string()),
        required: arg.is_required_set(),
        default_value: arg
            .get_default_values()
            .first()
            .map(|v| v.to_string_lossy().to_string()),
        possible_values: arg
            .get_possible_values()
            .iter()
            .map(|v| v.get_name().to_string())
            .collect(),
    }
}

/// JSON structure for --capabilities output.
#[derive(Debug, Clone, serde::Serialize, schemars::JsonSchema)]
struct CapabilitiesOutput {
    /// RCH version
    version: String,
    /// Build timestamp if available
    #[serde(skip_serializing_if = "Option::is_none")]
    build_timestamp: Option<String>,
    /// Supported compilation runtimes
    runtimes: Vec<RuntimeCapability>,
    /// Available CLI commands
    commands: Vec<CommandCapability>,
    /// Feature flags and their status
    features: Vec<FeatureCapability>,
    /// Supported hook formats
    hook_formats: Vec<String>,
    /// Machine-readable output formats
    output_formats: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize, schemars::JsonSchema)]
struct RuntimeCapability {
    name: String,
    description: String,
    /// File extensions associated with this runtime
    extensions: Vec<String>,
    /// Example commands that trigger this runtime
    example_commands: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize, schemars::JsonSchema)]
struct CommandCapability {
    name: String,
    description: String,
    /// Brief category: "setup", "monitoring", "management", "configuration"
    category: String,
}

#[derive(Debug, Clone, serde::Serialize, schemars::JsonSchema)]
struct FeatureCapability {
    name: String,
    description: String,
    enabled: bool,
}

/// Handle --capabilities flag: output RCH capabilities for machine discovery.
fn handle_capabilities() -> Result<()> {
    let output = CapabilitiesOutput {
        version: env!("CARGO_PKG_VERSION").to_string(),
        build_timestamp: option_env!("RCH_BUILD_TIMESTAMP").map(|s| s.to_string()),
        runtimes: vec![
            RuntimeCapability {
                name: "rust".to_string(),
                description: "Rust/Cargo compilation".to_string(),
                extensions: vec!["rs".to_string()],
                example_commands: vec![
                    "cargo build".to_string(),
                    "cargo test".to_string(),
                    "cargo check".to_string(),
                    "rustc".to_string(),
                ],
            },
            RuntimeCapability {
                name: "bun".to_string(),
                description: "Bun JavaScript/TypeScript runtime".to_string(),
                extensions: vec![
                    "js".to_string(),
                    "ts".to_string(),
                    "jsx".to_string(),
                    "tsx".to_string(),
                ],
                example_commands: vec![
                    "bun build".to_string(),
                    "bun test".to_string(),
                    "bun run".to_string(),
                ],
            },
            RuntimeCapability {
                name: "node".to_string(),
                description: "Node.js JavaScript runtime".to_string(),
                extensions: vec!["js".to_string(), "ts".to_string(), "mjs".to_string()],
                example_commands: vec![
                    "npm run build".to_string(),
                    "npm test".to_string(),
                    "npx".to_string(),
                ],
            },
        ],
        commands: vec![
            CommandCapability {
                name: "init".to_string(),
                description: "Interactive first-time setup wizard".to_string(),
                category: "setup".to_string(),
            },
            CommandCapability {
                name: "daemon".to_string(),
                description: "Control the RCH daemon (start/stop/status)".to_string(),
                category: "management".to_string(),
            },
            CommandCapability {
                name: "workers".to_string(),
                description: "Manage remote workers (list/probe/setup)".to_string(),
                category: "management".to_string(),
            },
            CommandCapability {
                name: "status".to_string(),
                description: "Show system status overview".to_string(),
                category: "monitoring".to_string(),
            },
            CommandCapability {
                name: "queue".to_string(),
                description: "View build queue status".to_string(),
                category: "monitoring".to_string(),
            },
            CommandCapability {
                name: "cancel".to_string(),
                description: "Cancel running builds".to_string(),
                category: "management".to_string(),
            },
            CommandCapability {
                name: "config".to_string(),
                description: "View and modify configuration".to_string(),
                category: "configuration".to_string(),
            },
            CommandCapability {
                name: "diagnose".to_string(),
                description: "Diagnose command routing decisions".to_string(),
                category: "debugging".to_string(),
            },
            CommandCapability {
                name: "hook".to_string(),
                description: "Manage Claude Code hook integration".to_string(),
                category: "setup".to_string(),
            },
            CommandCapability {
                name: "agents".to_string(),
                description: "Manage AI coding agent integrations".to_string(),
                category: "setup".to_string(),
            },
            CommandCapability {
                name: "completions".to_string(),
                description: "Generate shell completions".to_string(),
                category: "setup".to_string(),
            },
            CommandCapability {
                name: "doctor".to_string(),
                description: "Diagnose and fix system issues".to_string(),
                category: "debugging".to_string(),
            },
            CommandCapability {
                name: "self-test".to_string(),
                description: "Run end-to-end self-tests".to_string(),
                category: "debugging".to_string(),
            },
            CommandCapability {
                name: "update".to_string(),
                description: "Update RCH binaries".to_string(),
                category: "management".to_string(),
            },
            CommandCapability {
                name: "fleet".to_string(),
                description: "Deploy and manage worker fleet".to_string(),
                category: "management".to_string(),
            },
            CommandCapability {
                name: "speedscore".to_string(),
                description: "View worker performance scores".to_string(),
                category: "monitoring".to_string(),
            },
            CommandCapability {
                name: "dashboard".to_string(),
                description: "Interactive TUI dashboard".to_string(),
                category: "monitoring".to_string(),
            },
            CommandCapability {
                name: "web".to_string(),
                description: "Web-based dashboard".to_string(),
                category: "monitoring".to_string(),
            },
        ],
        features: vec![
            FeatureCapability {
                name: "rich-ui".to_string(),
                description: "Rich terminal UI with colors and formatting".to_string(),
                enabled: cfg!(feature = "rich-ui"),
            },
            FeatureCapability {
                name: "json-output".to_string(),
                description: "Machine-readable JSON output via --json flag".to_string(),
                enabled: true,
            },
            FeatureCapability {
                name: "toon-output".to_string(),
                description: "TOON protocol output via --format=toon".to_string(),
                enabled: true,
            },
            FeatureCapability {
                name: "schema-introspection".to_string(),
                description: "JSON Schema generation via --schema flag".to_string(),
                enabled: true,
            },
            FeatureCapability {
                name: "shell-completions".to_string(),
                description: "Tab completion for bash, zsh, fish, etc.".to_string(),
                enabled: true,
            },
            FeatureCapability {
                name: "tui-dashboard".to_string(),
                description: "Interactive terminal dashboard".to_string(),
                enabled: true,
            },
        ],
        hook_formats: vec![
            "claude-code-pre-tool-use".to_string(),
            "gemini-cli".to_string(),
        ],
        output_formats: vec!["json".to_string(), "toon".to_string(), "human".to_string()],
    };

    let json = serde_json::to_string_pretty(&output)?;
    println!("{json}");
    Ok(())
}

async fn handle_daemon(action: DaemonAction, ctx: &OutputContext) -> Result<()> {
    match action {
        DaemonAction::Start => {
            commands::daemon_start(ctx).await?;
        }
        DaemonAction::Stop { yes } => {
            commands::daemon_stop(yes, ctx).await?;
        }
        DaemonAction::Restart { yes } => {
            commands::daemon_restart(yes, ctx).await?;
        }
        DaemonAction::Status => {
            commands::daemon_status(ctx)?;
        }
        DaemonAction::Logs { lines } => {
            commands::daemon_logs(lines, ctx)?;
        }
        DaemonAction::Reload => {
            commands::daemon_reload(ctx).await?;
        }
    }
    Ok(())
}

async fn handle_workers(action: WorkersAction, ctx: &OutputContext) -> Result<()> {
    match action {
        WorkersAction::List { speedscore } => {
            commands::workers_list(speedscore, ctx).await?;
        }
        WorkersAction::Capabilities { refresh, command } => {
            commands::workers_capabilities(command, refresh, ctx).await?;
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
        WorkersAction::Disable {
            worker,
            reason,
            drain,
        } => {
            commands::workers_disable(&worker, reason, drain, ctx).await?;
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
        WorkersAction::SyncToolchain {
            worker,
            all,
            dry_run,
        } => {
            commands::workers_sync_toolchain(worker, all, dry_run, ctx).await?;
        }
        WorkersAction::Setup {
            worker,
            all,
            dry_run,
            skip_binary,
            skip_toolchain,
        } => {
            commands::workers_setup(worker, all, dry_run, skip_binary, skip_toolchain, ctx).await?;
        }
        WorkersAction::Init { yes } => {
            commands::workers_init(yes, ctx).await?;
        }
    }
    Ok(())
}

async fn handle_status(workers: bool, jobs: bool, ctx: &OutputContext) -> Result<()> {
    commands::status_overview(workers, jobs, ctx).await?;
    Ok(())
}

async fn handle_config(action: ConfigAction, ctx: &OutputContext) -> Result<()> {
    match action {
        ConfigAction::Show { sources } => {
            commands::config_show(sources, ctx)?;
        }
        ConfigAction::Init {
            wizard,
            non_interactive,
        } => {
            // --non-interactive implies wizard mode (generates full config)
            let run_wizard = wizard || non_interactive;
            commands::config_init(ctx, run_wizard, non_interactive)?;
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
        ConfigAction::Lint => {
            commands::config_lint(ctx)?;
        }
        ConfigAction::Diff => {
            commands::config_diff(ctx)?;
        }
    }
    Ok(())
}

async fn handle_diagnose(command: Vec<String>, dry_run: bool, ctx: &OutputContext) -> Result<()> {
    let joined = command.join(" ");
    commands::diagnose(&joined, dry_run, ctx).await?;
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
        HookAction::Status => {
            commands::hook_status(ctx)?;
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

async fn handle_doctor(
    fix: bool,
    dry_run: bool,
    install_deps: bool,
    ctx: &OutputContext,
) -> Result<()> {
    use crate::doctor::DoctorOptions;
    let options = DoctorOptions {
        fix,
        dry_run,
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
            let shell = shell
                .or_else(completions::detect_current_shell)
                .ok_or_else(|| {
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

/// Handle fleet subcommands
async fn handle_fleet(action: FleetAction, ctx: &OutputContext) -> Result<()> {
    match action {
        FleetAction::Deploy {
            worker,
            parallel,
            canary,
            canary_wait,
            no_toolchain,
            force,
            verify,
            drain_first,
            drain_timeout,
            dry_run,
            resume,
            version,
            audit_log,
        } => {
            fleet::deploy(
                ctx,
                worker,
                parallel,
                canary,
                canary_wait,
                no_toolchain,
                force,
                verify,
                drain_first,
                drain_timeout,
                dry_run,
                resume,
                version,
                audit_log,
            )
            .await
        }
        FleetAction::Rollback {
            worker,
            to_version,
            parallel,
            verify,
            dry_run,
        } => fleet::rollback(ctx, worker, to_version, parallel, verify, dry_run).await,
        FleetAction::Status { worker, watch } => fleet::status(ctx, worker, watch).await,
        FleetAction::Verify { worker } => fleet::verify(ctx, worker).await,
        FleetAction::Drain {
            worker,
            all,
            timeout,
        } => fleet::drain(ctx, worker, all, timeout).await,
        FleetAction::History { limit, worker } => fleet::history(ctx, limit, worker).await,
    }
}

/// Handle web dashboard command
async fn handle_web(port: u16, no_open: bool, prod: bool, ctx: &OutputContext) -> Result<()> {
    use std::process::{Command, Stdio};

    // Find the web directory relative to the rch binary or use compile-time path
    let web_dir = find_web_directory()?;

    ctx.info(&format!("Starting web dashboard on port {}...", port));

    // Check if bun is available
    let bun_check = Command::new("bun")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    let port_str = port.to_string();
    let (cmd_name, cmd_args): (&str, Vec<&str>) = if bun_check.is_ok() {
        if prod {
            ("bun", vec!["run", "start", "--", "-p", &port_str])
        } else {
            ("bun", vec!["run", "dev", "--", "-p", &port_str])
        }
    } else {
        // Fall back to npm
        if prod {
            ("npm", vec!["run", "start", "--", "-p", &port_str])
        } else {
            ("npm", vec!["run", "dev", "--", "-p", &port_str])
        }
    };

    let url = format!("http://localhost:{}", port);
    ctx.info(&format!("Dashboard available at: {}", url));

    // Open browser unless disabled
    if !no_open {
        ctx.info("Opening browser...");
        // Give the server a moment to start
        let url_clone = url.clone();
        tokio::spawn(async move {
            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
            let _ = open_browser(&url_clone);
        });
    }

    ctx.info("Press Ctrl+C to stop the server");

    // Run the web server
    let status = Command::new(cmd_name)
        .args(&cmd_args)
        .current_dir(&web_dir)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()?;

    if !status.success() {
        anyhow::bail!("Web server exited with error");
    }

    Ok(())
}

/// Find the web directory
fn find_web_directory() -> Result<PathBuf> {
    // Try relative to current directory first
    let cwd = std::env::current_dir()?;
    let web_in_cwd = cwd.join("web");
    if web_in_cwd.exists() && web_in_cwd.join("package.json").exists() {
        return Ok(web_in_cwd);
    }

    // Try relative to the executable
    if let Ok(exe_path) = std::env::current_exe()
        && let Some(exe_dir) = exe_path.parent()
    {
        // Check sibling web directory
        let web_sibling = exe_dir.join("web");
        if web_sibling.exists() && web_sibling.join("package.json").exists() {
            return Ok(web_sibling);
        }

        // Check parent's web directory (for dev builds)
        if let Some(parent) = exe_dir.parent() {
            let web_parent = parent.join("web");
            if web_parent.exists() && web_parent.join("package.json").exists() {
                return Ok(web_parent);
            }
        }
    }

    // Try common installation paths
    let home = dirs::home_dir().ok_or_else(|| anyhow::anyhow!("Could not find home directory"))?;
    let common_paths = [
        home.join(".local/share/rch/web"),
        home.join(".rch/web"),
        PathBuf::from("/usr/local/share/rch/web"),
        PathBuf::from("/usr/share/rch/web"),
    ];

    for path in common_paths {
        if path.exists() && path.join("package.json").exists() {
            return Ok(path);
        }
    }

    anyhow::bail!(
        "Could not find web dashboard directory. \n\
         Expected to find it at one of:\n  \
         - ./web\n  \
         - ~/.local/share/rch/web\n  \
         - /usr/local/share/rch/web\n\n\
         If you installed from source, run 'rch web' from the project root."
    )
}

/// Open a URL in the default browser
fn open_browser(url: &str) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open").arg(url).spawn()?;
    }

    #[cfg(target_os = "linux")]
    {
        // Try xdg-open first, then fall back to common browsers
        let result = std::process::Command::new("xdg-open").arg(url).spawn();

        if result.is_err() {
            // Try common browsers
            for browser in &["firefox", "chromium", "chromium-browser", "google-chrome"] {
                if std::process::Command::new(browser).arg(url).spawn().is_ok() {
                    break;
                }
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("cmd")
            .args(&["/C", "start", "", url])
            .spawn()?;
    }

    Ok(())
}

// =============================================================================
// Unit Tests
// =============================================================================

// Global test logging initialization - enables JSONL output for all unit tests
#[cfg(test)]
#[ctor::ctor]
fn init_test_logging() {
    rch_common::testing::init_global_test_logging();
}

#[cfg(test)]
mod tests {
    use super::*;
    use rch_common::test_guard;

    // -------------------------------------------------------------------------
    // CLI Parsing Tests
    // -------------------------------------------------------------------------

    #[test]
    fn cli_parses_no_args() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch"]).unwrap();
        assert!(cli.command.is_none());
        assert!(!cli.verbose);
        assert!(!cli.quiet);
        assert!(!cli.json);
        assert_eq!(cli.color, "auto");
    }

    #[test]
    fn cli_parses_verbose_flag() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "-v"]).unwrap();
        assert!(cli.verbose);
        assert!(!cli.quiet);
    }

    #[test]
    fn cli_parses_verbose_long_flag() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "--verbose"]).unwrap();
        assert!(cli.verbose);
    }

    #[test]
    fn cli_parses_quiet_flag() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "-q"]).unwrap();
        assert!(cli.quiet);
        assert!(!cli.verbose);
    }

    #[test]
    fn cli_parses_quiet_long_flag() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "--quiet"]).unwrap();
        assert!(cli.quiet);
    }

    #[test]
    fn cli_parses_json_flag() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "--json"]).unwrap();
        assert!(cli.json);
    }

    #[test]
    fn cli_parses_format_flag() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "--format", "toon"]).unwrap();
        assert_eq!(cli.format.as_deref(), Some("toon"));
    }

    #[test]
    fn cli_parses_color_always() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "--color", "always"]).unwrap();
        assert_eq!(cli.color, "always");
    }

    #[test]
    fn cli_parses_color_never() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "--color", "never"]).unwrap();
        assert_eq!(cli.color, "never");
    }

    #[test]
    fn cli_parses_color_auto() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "--color", "auto"]).unwrap();
        assert_eq!(cli.color, "auto");
    }

    // -------------------------------------------------------------------------
    // Daemon Subcommand Tests
    // -------------------------------------------------------------------------

    #[test]
    fn cli_parses_daemon_start() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "daemon", "start"]).unwrap();
        match cli.command {
            Some(Commands::Daemon {
                action: DaemonAction::Start,
            }) => {}
            _ => panic!("Expected daemon start command"),
        }
    }

    #[test]
    fn cli_parses_daemon_stop() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "daemon", "stop"]).unwrap();
        match cli.command {
            Some(Commands::Daemon {
                action: DaemonAction::Stop { yes },
            }) => {
                assert!(!yes, "yes should default to false");
            }
            _ => panic!("Expected daemon stop command"),
        }
    }

    #[test]
    fn cli_parses_daemon_stop_with_yes() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "daemon", "stop", "--yes"]).unwrap();
        match cli.command {
            Some(Commands::Daemon {
                action: DaemonAction::Stop { yes },
            }) => {
                assert!(yes, "yes should be true");
            }
            _ => panic!("Expected daemon stop --yes command"),
        }
    }

    #[test]
    fn cli_parses_daemon_restart() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "daemon", "restart"]).unwrap();
        match cli.command {
            Some(Commands::Daemon {
                action: DaemonAction::Restart { yes },
            }) => {
                assert!(!yes, "yes should default to false");
            }
            _ => panic!("Expected daemon restart command"),
        }
    }

    #[test]
    fn cli_parses_daemon_restart_with_yes() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "daemon", "restart", "-y"]).unwrap();
        match cli.command {
            Some(Commands::Daemon {
                action: DaemonAction::Restart { yes },
            }) => {
                assert!(yes, "yes should be true with -y flag");
            }
            _ => panic!("Expected daemon restart -y command"),
        }
    }

    #[test]
    fn cli_parses_daemon_status() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "daemon", "status"]).unwrap();
        match cli.command {
            Some(Commands::Daemon {
                action: DaemonAction::Status,
            }) => {}
            _ => panic!("Expected daemon status command"),
        }
    }

    #[test]
    fn cli_parses_daemon_logs_default() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "daemon", "logs"]).unwrap();
        match cli.command {
            Some(Commands::Daemon {
                action: DaemonAction::Logs { lines },
            }) => {
                assert_eq!(lines, 50);
            }
            _ => panic!("Expected daemon logs command"),
        }
    }

    #[test]
    fn cli_parses_daemon_logs_custom_lines() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "daemon", "logs", "-n", "100"]).unwrap();
        match cli.command {
            Some(Commands::Daemon {
                action: DaemonAction::Logs { lines },
            }) => {
                assert_eq!(lines, 100);
            }
            _ => panic!("Expected daemon logs command"),
        }
    }

    // -------------------------------------------------------------------------
    // Workers Subcommand Tests
    // -------------------------------------------------------------------------

    #[test]
    fn cli_parses_workers_list() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "workers", "list"]).unwrap();
        match cli.command {
            Some(Commands::Workers {
                action: WorkersAction::List { speedscore },
            }) => {
                assert!(!speedscore);
            }
            _ => panic!("Expected workers list command"),
        }
    }

    #[test]
    fn cli_parses_workers_capabilities() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "workers", "capabilities"]).unwrap();
        match cli.command {
            Some(Commands::Workers {
                action: WorkersAction::Capabilities { refresh, command },
            }) => {
                assert!(!refresh);
                assert!(command.is_none());
            }
            _ => panic!("Expected workers capabilities command"),
        }
    }

    #[test]
    fn cli_parses_workers_capabilities_with_flags() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from([
            "rch",
            "workers",
            "capabilities",
            "--refresh",
            "--command",
            "bun test",
        ])
        .unwrap();
        match cli.command {
            Some(Commands::Workers {
                action: WorkersAction::Capabilities { refresh, command },
            }) => {
                assert!(refresh);
                assert_eq!(command.as_deref(), Some("bun test"));
            }
            _ => panic!("Expected workers capabilities command"),
        }
    }

    #[test]
    fn cli_parses_workers_probe_specific() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "workers", "probe", "css"]).unwrap();
        match cli.command {
            Some(Commands::Workers {
                action: WorkersAction::Probe { worker, all },
            }) => {
                assert_eq!(worker, Some("css".to_string()));
                assert!(!all);
            }
            _ => panic!("Expected workers probe command"),
        }
    }

    #[test]
    fn cli_parses_workers_probe_all() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "workers", "probe", "--all"]).unwrap();
        match cli.command {
            Some(Commands::Workers {
                action: WorkersAction::Probe { worker, all },
            }) => {
                assert!(worker.is_none());
                assert!(all);
            }
            _ => panic!("Expected workers probe command"),
        }
    }

    #[test]
    fn cli_parses_workers_benchmark() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "workers", "benchmark"]).unwrap();
        match cli.command {
            Some(Commands::Workers {
                action: WorkersAction::Benchmark,
            }) => {}
            _ => panic!("Expected workers benchmark command"),
        }
    }

    #[test]
    fn cli_parses_workers_drain() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "workers", "drain", "css"]).unwrap();
        match cli.command {
            Some(Commands::Workers {
                action: WorkersAction::Drain { worker },
            }) => {
                assert_eq!(worker, "css");
            }
            _ => panic!("Expected workers drain command"),
        }
    }

    #[test]
    fn cli_parses_workers_enable() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "workers", "enable", "css"]).unwrap();
        match cli.command {
            Some(Commands::Workers {
                action: WorkersAction::Enable { worker },
            }) => {
                assert_eq!(worker, "css");
            }
            _ => panic!("Expected workers enable command"),
        }
    }

    #[test]
    fn cli_parses_workers_discover() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "workers", "discover", "--probe", "--add"]).unwrap();
        match cli.command {
            Some(Commands::Workers {
                action: WorkersAction::Discover { probe, add, yes },
            }) => {
                assert!(probe);
                assert!(add);
                assert!(!yes);
            }
            _ => panic!("Expected workers discover command"),
        }
    }

    #[test]
    fn cli_parses_workers_init() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "workers", "init"]).unwrap();
        match cli.command {
            Some(Commands::Workers {
                action: WorkersAction::Init { yes },
            }) => {
                assert!(!yes);
            }
            _ => panic!("Expected workers init command"),
        }
    }

    #[test]
    fn cli_parses_workers_init_with_yes() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "workers", "init", "--yes"]).unwrap();
        match cli.command {
            Some(Commands::Workers {
                action: WorkersAction::Init { yes },
            }) => {
                assert!(yes);
            }
            _ => panic!("Expected workers init command with --yes"),
        }
    }

    #[test]
    fn cli_parses_workers_init_short_yes_flag() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "workers", "init", "-y"]).unwrap();
        match cli.command {
            Some(Commands::Workers {
                action: WorkersAction::Init { yes },
            }) => {
                assert!(yes);
            }
            _ => panic!("Expected workers init command with -y"),
        }
    }

    // -------------------------------------------------------------------------
    // Status Subcommand Tests
    // -------------------------------------------------------------------------

    #[test]
    fn cli_parses_status_default() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "status"]).unwrap();
        match cli.command {
            Some(Commands::Status { workers, jobs }) => {
                assert!(!workers);
                assert!(!jobs);
            }
            _ => panic!("Expected status command"),
        }
    }

    #[test]
    fn cli_parses_status_with_workers() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "status", "--workers"]).unwrap();
        match cli.command {
            Some(Commands::Status { workers, jobs }) => {
                assert!(workers);
                assert!(!jobs);
            }
            _ => panic!("Expected status command"),
        }
    }

    #[test]
    fn cli_parses_status_with_jobs() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "status", "--jobs"]).unwrap();
        match cli.command {
            Some(Commands::Status { workers, jobs }) => {
                assert!(!workers);
                assert!(jobs);
            }
            _ => panic!("Expected status command"),
        }
    }

    #[test]
    fn cli_parses_status_with_both() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "status", "--workers", "--jobs"]).unwrap();
        match cli.command {
            Some(Commands::Status { workers, jobs }) => {
                assert!(workers);
                assert!(jobs);
            }
            _ => panic!("Expected status command"),
        }
    }

    // -------------------------------------------------------------------------
    // Config Subcommand Tests
    // -------------------------------------------------------------------------

    #[test]
    fn cli_parses_config_show() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "config", "show"]).unwrap();
        match cli.command {
            Some(Commands::Config {
                action: ConfigAction::Show { sources },
            }) => {
                assert!(!sources);
            }
            _ => panic!("Expected config show command"),
        }
    }

    #[test]
    fn cli_parses_config_show_sources() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "config", "show", "--sources"]).unwrap();
        match cli.command {
            Some(Commands::Config {
                action: ConfigAction::Show { sources },
            }) => {
                assert!(sources);
            }
            _ => panic!("Expected config show command"),
        }
    }

    // -------------------------------------------------------------------------
    // Diagnose Subcommand Tests
    // -------------------------------------------------------------------------

    #[test]
    fn cli_parses_diagnose_single_arg() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "diagnose", "cargo build --release"]).unwrap();
        match cli.command {
            Some(Commands::Diagnose { command, dry_run }) => {
                assert_eq!(command, vec!["cargo build --release"]);
                assert!(!dry_run);
            }
            _ => panic!("Expected diagnose command"),
        }
    }

    #[test]
    fn cli_parses_diagnose_multi_arg() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "diagnose", "cargo", "build", "--release"]).unwrap();
        match cli.command {
            Some(Commands::Diagnose { command, dry_run }) => {
                assert_eq!(command, vec!["cargo", "build", "--release"]);
                assert!(!dry_run);
            }
            _ => panic!("Expected diagnose command"),
        }
    }

    #[test]
    fn cli_parses_diagnose_dry_run() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "diagnose", "--dry-run", "cargo", "build"]).unwrap();
        match cli.command {
            Some(Commands::Diagnose { command, dry_run }) => {
                assert_eq!(command, vec!["cargo", "build"]);
                assert!(dry_run);
            }
            _ => panic!("Expected diagnose command"),
        }
    }

    #[test]
    fn cli_parses_diagnose_dry_run_short() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "diagnose", "-n", "cargo", "build"]).unwrap();
        match cli.command {
            Some(Commands::Diagnose { command, dry_run }) => {
                assert_eq!(command, vec!["cargo", "build"]);
                assert!(dry_run);
            }
            _ => panic!("Expected diagnose command"),
        }
    }

    #[test]
    fn cli_parses_config_init() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "config", "init"]).unwrap();
        match cli.command {
            Some(Commands::Config {
                action:
                    ConfigAction::Init {
                        wizard,
                        non_interactive,
                    },
            }) => {
                assert!(!wizard);
                assert!(!non_interactive);
            }
            _ => panic!("Expected config init command"),
        }
    }

    #[test]
    fn cli_parses_config_init_wizard() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "config", "init", "--wizard"]).unwrap();
        match cli.command {
            Some(Commands::Config {
                action: ConfigAction::Init { wizard, .. },
            }) => {
                assert!(wizard);
            }
            _ => panic!("Expected config init command"),
        }
    }

    #[test]
    fn cli_parses_config_validate() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "config", "validate"]).unwrap();
        match cli.command {
            Some(Commands::Config {
                action: ConfigAction::Validate,
            }) => {}
            _ => panic!("Expected config validate command"),
        }
    }

    #[test]
    fn cli_parses_config_set() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "config", "set", "log_level", "debug"]).unwrap();
        match cli.command {
            Some(Commands::Config {
                action: ConfigAction::Set { key, value },
            }) => {
                assert_eq!(key, "log_level");
                assert_eq!(value, "debug");
            }
            _ => panic!("Expected config set command"),
        }
    }

    #[test]
    fn cli_parses_config_export() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "config", "export"]).unwrap();
        match cli.command {
            Some(Commands::Config {
                action: ConfigAction::Export { format },
            }) => {
                assert_eq!(format, "shell");
            }
            _ => panic!("Expected config export command"),
        }
    }

    #[test]
    fn cli_parses_config_lint() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "config", "lint"]).unwrap();
        match cli.command {
            Some(Commands::Config {
                action: ConfigAction::Lint,
            }) => {}
            _ => panic!("Expected config lint command"),
        }
    }

    #[test]
    fn cli_parses_config_diff() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "config", "diff"]).unwrap();
        match cli.command {
            Some(Commands::Config {
                action: ConfigAction::Diff,
            }) => {}
            _ => panic!("Expected config diff command"),
        }
    }

    // -------------------------------------------------------------------------
    // Hook Subcommand Tests
    // -------------------------------------------------------------------------

    #[test]
    fn cli_parses_hook_install() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "hook", "install"]).unwrap();
        match cli.command {
            Some(Commands::Hook {
                action: HookAction::Install,
            }) => {}
            _ => panic!("Expected hook install command"),
        }
    }

    #[test]
    fn cli_parses_hook_uninstall() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "hook", "uninstall"]).unwrap();
        match cli.command {
            Some(Commands::Hook {
                action: HookAction::Uninstall,
            }) => {}
            _ => panic!("Expected hook uninstall command"),
        }
    }

    #[test]
    fn cli_parses_hook_test() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "hook", "test"]).unwrap();
        match cli.command {
            Some(Commands::Hook {
                action: HookAction::Test,
            }) => {}
            _ => panic!("Expected hook test command"),
        }
    }

    // -------------------------------------------------------------------------
    // Doctor Subcommand Tests
    // -------------------------------------------------------------------------

    #[test]
    fn cli_parses_doctor_default() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "doctor"]).unwrap();
        match cli.command {
            Some(Commands::Doctor {
                fix,
                dry_run,
                install_deps,
            }) => {
                assert!(!fix);
                assert!(!dry_run);
                assert!(!install_deps);
            }
            _ => panic!("Expected doctor command"),
        }
    }

    #[test]
    fn cli_parses_doctor_with_fix() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "doctor", "--fix"]).unwrap();
        match cli.command {
            Some(Commands::Doctor {
                fix,
                dry_run,
                install_deps,
            }) => {
                assert!(fix);
                assert!(!dry_run);
                assert!(!install_deps);
            }
            _ => panic!("Expected doctor command"),
        }
    }

    #[test]
    fn cli_parses_doctor_with_dry_run() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "doctor", "--dry-run"]).unwrap();
        match cli.command {
            Some(Commands::Doctor {
                fix,
                dry_run,
                install_deps,
            }) => {
                assert!(!fix);
                assert!(dry_run);
                assert!(!install_deps);
            }
            _ => panic!("Expected doctor command"),
        }
    }

    #[test]
    fn cli_parses_doctor_install_deps() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "doctor", "--install-deps"]).unwrap();
        match cli.command {
            Some(Commands::Doctor {
                fix,
                dry_run,
                install_deps,
            }) => {
                assert!(!fix);
                assert!(!dry_run);
                assert!(install_deps);
            }
            _ => panic!("Expected doctor command"),
        }
    }

    // -------------------------------------------------------------------------
    // Init Subcommand Tests
    // -------------------------------------------------------------------------

    #[test]
    fn cli_parses_init_default() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "init"]).unwrap();
        match cli.command {
            Some(Commands::Init { yes, skip_test }) => {
                assert!(!yes);
                assert!(!skip_test);
            }
            _ => panic!("Expected init command"),
        }
    }

    #[test]
    fn cli_parses_init_yes() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "init", "--yes"]).unwrap();
        match cli.command {
            Some(Commands::Init { yes, skip_test }) => {
                assert!(yes);
                assert!(!skip_test);
            }
            _ => panic!("Expected init command"),
        }
    }

    #[test]
    fn cli_parses_init_skip_test() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "init", "--skip-test"]).unwrap();
        match cli.command {
            Some(Commands::Init { yes, skip_test }) => {
                assert!(!yes);
                assert!(skip_test);
            }
            _ => panic!("Expected init command"),
        }
    }

    #[test]
    fn cli_parses_setup_as_alias_for_init() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "setup"]).unwrap();
        match cli.command {
            Some(Commands::Init { yes, skip_test }) => {
                assert!(!yes);
                assert!(!skip_test);
            }
            _ => panic!("Expected init command from setup alias"),
        }
    }

    #[test]
    fn cli_parses_setup_with_flags() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "setup", "--yes", "--skip-test"]).unwrap();
        match cli.command {
            Some(Commands::Init { yes, skip_test }) => {
                assert!(yes);
                assert!(skip_test);
            }
            _ => panic!("Expected init command from setup alias with flags"),
        }
    }

    // -------------------------------------------------------------------------
    // Update Subcommand Tests
    // -------------------------------------------------------------------------

    #[test]
    fn cli_parses_update_default() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "update"]).unwrap();
        match cli.command {
            Some(Commands::Update {
                check,
                version,
                channel,
                fleet,
                ..
            }) => {
                assert!(!check);
                assert!(version.is_none());
                assert_eq!(channel, "stable");
                assert!(!fleet);
            }
            _ => panic!("Expected update command"),
        }
    }

    #[test]
    fn cli_parses_update_check() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "update", "--check"]).unwrap();
        match cli.command {
            Some(Commands::Update { check, .. }) => {
                assert!(check);
            }
            _ => panic!("Expected update command"),
        }
    }

    #[test]
    fn cli_parses_update_version() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "update", "--version", "v0.2.0"]).unwrap();
        match cli.command {
            Some(Commands::Update { version, .. }) => {
                assert_eq!(version, Some("v0.2.0".to_string()));
            }
            _ => panic!("Expected update command"),
        }
    }

    #[test]
    fn cli_parses_update_channel() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "update", "--channel", "beta"]).unwrap();
        match cli.command {
            Some(Commands::Update { channel, .. }) => {
                assert_eq!(channel, "beta");
            }
            _ => panic!("Expected update command"),
        }
    }

    #[test]
    fn cli_parses_update_fleet() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "update", "--fleet"]).unwrap();
        match cli.command {
            Some(Commands::Update { fleet, .. }) => {
                assert!(fleet);
            }
            _ => panic!("Expected update command"),
        }
    }

    // -------------------------------------------------------------------------
    // Fleet Subcommand Tests
    // -------------------------------------------------------------------------

    #[test]
    fn cli_parses_fleet_deploy_default() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "fleet", "deploy"]).unwrap();
        match cli.command {
            Some(Commands::Fleet {
                action:
                    FleetAction::Deploy {
                        worker,
                        parallel,
                        canary,
                        dry_run,
                        ..
                    },
            }) => {
                assert!(worker.is_none());
                assert_eq!(parallel, 4);
                assert!(canary.is_none());
                assert!(!dry_run);
            }
            _ => panic!("Expected fleet deploy command"),
        }
    }

    #[test]
    fn cli_parses_fleet_deploy_worker() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "fleet", "deploy", "--worker", "css"]).unwrap();
        match cli.command {
            Some(Commands::Fleet {
                action: FleetAction::Deploy { worker, .. },
            }) => {
                assert_eq!(worker, Some("css".to_string()));
            }
            _ => panic!("Expected fleet deploy command"),
        }
    }

    #[test]
    fn cli_parses_fleet_deploy_canary() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "fleet", "deploy", "--canary", "25"]).unwrap();
        match cli.command {
            Some(Commands::Fleet {
                action: FleetAction::Deploy { canary, .. },
            }) => {
                assert_eq!(canary, Some(25));
            }
            _ => panic!("Expected fleet deploy command"),
        }
    }

    #[test]
    fn cli_parses_fleet_rollback() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "fleet", "rollback"]).unwrap();
        match cli.command {
            Some(Commands::Fleet {
                action:
                    FleetAction::Rollback {
                        worker, to_version, ..
                    },
            }) => {
                assert!(worker.is_none());
                assert!(to_version.is_none());
            }
            _ => panic!("Expected fleet rollback command"),
        }
    }

    #[test]
    fn cli_parses_fleet_status() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "fleet", "status"]).unwrap();
        match cli.command {
            Some(Commands::Fleet {
                action: FleetAction::Status { worker, watch },
            }) => {
                assert!(worker.is_none());
                assert!(!watch);
            }
            _ => panic!("Expected fleet status command"),
        }
    }

    #[test]
    fn cli_parses_fleet_verify() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "fleet", "verify"]).unwrap();
        match cli.command {
            Some(Commands::Fleet {
                action: FleetAction::Verify { worker },
            }) => {
                assert!(worker.is_none());
            }
            _ => panic!("Expected fleet verify command"),
        }
    }

    #[test]
    fn cli_parses_fleet_history() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "fleet", "history", "--limit", "20"]).unwrap();
        match cli.command {
            Some(Commands::Fleet {
                action: FleetAction::History { limit, worker },
            }) => {
                assert_eq!(limit, 20);
                assert!(worker.is_none());
            }
            _ => panic!("Expected fleet history command"),
        }
    }

    // -------------------------------------------------------------------------
    // Dashboard and Web Subcommand Tests
    // -------------------------------------------------------------------------

    #[test]
    fn cli_parses_dashboard_default() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "dashboard"]).unwrap();
        match cli.command {
            Some(Commands::Dashboard {
                refresh,
                no_mouse,
                test_mode,
                mock_data,
                dump_state,
                high_contrast,
                color_blind,
            }) => {
                assert_eq!(refresh, 1000);
                assert!(!no_mouse);
                assert!(!test_mode);
                assert!(!mock_data);
                assert!(!dump_state);
                assert!(!high_contrast);
                assert_eq!(color_blind, tui::ColorBlindMode::None);
            }
            _ => panic!("Expected dashboard command"),
        }
    }

    #[test]
    fn cli_parses_dashboard_custom_refresh() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "dashboard", "--refresh", "500"]).unwrap();
        match cli.command {
            Some(Commands::Dashboard { refresh, .. }) => {
                assert_eq!(refresh, 500);
            }
            _ => panic!("Expected dashboard command"),
        }
    }

    #[test]
    fn cli_parses_web_default() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "web"]).unwrap();
        match cli.command {
            Some(Commands::Web {
                port,
                no_open,
                prod,
            }) => {
                assert_eq!(port, 3000);
                assert!(!no_open);
                assert!(!prod);
            }
            _ => panic!("Expected web command"),
        }
    }

    #[test]
    fn cli_parses_web_custom_port() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "web", "--port", "3001"]).unwrap();
        match cli.command {
            Some(Commands::Web { port, .. }) => {
                assert_eq!(port, 3001);
            }
            _ => panic!("Expected web command"),
        }
    }

    // -------------------------------------------------------------------------
    // SpeedScore Subcommand Tests
    // -------------------------------------------------------------------------

    #[test]
    fn cli_parses_speedscore_single_worker() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "speedscore", "css"]).unwrap();
        // verbose is now a global flag on Cli, not on SpeedScore
        assert!(!cli.verbose);
        match cli.command {
            Some(Commands::SpeedScore {
                worker,
                all,
                history,
                days,
                limit,
            }) => {
                assert_eq!(worker, Some("css".to_string()));
                assert!(!all);
                assert!(!history);
                assert_eq!(days, 30);
                assert_eq!(limit, 20);
            }
            _ => panic!("Expected speedscore command"),
        }
    }

    #[test]
    fn cli_parses_speedscore_all() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "speedscore", "--all"]).unwrap();
        match cli.command {
            Some(Commands::SpeedScore { all, worker, .. }) => {
                assert!(all);
                assert!(worker.is_none());
            }
            _ => panic!("Expected speedscore --all command"),
        }
    }

    #[test]
    fn cli_parses_speedscore_verbose() {
        let _guard = test_guard!();
        // --verbose is a global flag, so we check cli.verbose
        let cli = Cli::try_parse_from(["rch", "speedscore", "css", "--verbose"]).unwrap();
        assert!(cli.verbose, "Global verbose flag should be set");
        match cli.command {
            Some(Commands::SpeedScore { worker, .. }) => {
                assert_eq!(worker, Some("css".to_string()));
            }
            _ => panic!("Expected speedscore --verbose command"),
        }
    }

    #[test]
    fn cli_parses_speedscore_history() {
        let _guard = test_guard!();
        let cli =
            Cli::try_parse_from(["rch", "speedscore", "css", "--history", "--days", "7"]).unwrap();
        match cli.command {
            Some(Commands::SpeedScore {
                worker,
                history,
                days,
                ..
            }) => {
                assert_eq!(worker, Some("css".to_string()));
                assert!(history);
                assert_eq!(days, 7);
            }
            _ => panic!("Expected speedscore --history command"),
        }
    }

    #[test]
    fn cli_parses_speedscore_short_verbose() {
        let _guard = test_guard!();
        // -v is the global short verbose flag
        let cli = Cli::try_parse_from(["rch", "speedscore", "css", "-v"]).unwrap();
        assert!(cli.verbose, "Global verbose flag should be set with -v");
        match cli.command {
            Some(Commands::SpeedScore { .. }) => {}
            _ => panic!("Expected speedscore -v command"),
        }
    }

    // -------------------------------------------------------------------------
    // Completions Subcommand Tests
    // -------------------------------------------------------------------------

    #[test]
    fn cli_parses_completions_generate_bash() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "completions", "generate", "bash"]).unwrap();
        match cli.command {
            Some(Commands::Completions {
                action: CompletionsAction::Generate { shell },
            }) => {
                assert_eq!(shell, clap_complete::Shell::Bash);
            }
            _ => panic!("Expected completions generate command"),
        }
    }

    #[test]
    fn cli_parses_completions_install() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "completions", "install", "zsh"]).unwrap();
        match cli.command {
            Some(Commands::Completions {
                action: CompletionsAction::Install { shell, dry_run },
            }) => {
                assert_eq!(shell, Some(clap_complete::Shell::Zsh));
                assert!(!dry_run);
            }
            _ => panic!("Expected completions install command"),
        }
    }

    #[test]
    fn cli_parses_completions_status() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "completions", "status"]).unwrap();
        match cli.command {
            Some(Commands::Completions {
                action: CompletionsAction::Status,
            }) => {}
            _ => panic!("Expected completions status command"),
        }
    }

    // -------------------------------------------------------------------------
    // Agents Subcommand Tests
    // -------------------------------------------------------------------------

    #[test]
    fn cli_parses_agents_list() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "agents", "list"]).unwrap();
        match cli.command {
            Some(Commands::Agents {
                action: AgentsAction::List { all },
            }) => {
                assert!(!all);
            }
            _ => panic!("Expected agents list command"),
        }
    }

    #[test]
    fn cli_parses_agents_list_all() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "agents", "list", "--all"]).unwrap();
        match cli.command {
            Some(Commands::Agents {
                action: AgentsAction::List { all },
            }) => {
                assert!(all);
            }
            _ => panic!("Expected agents list command"),
        }
    }

    #[test]
    fn cli_parses_agents_status() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "agents", "status"]).unwrap();
        match cli.command {
            Some(Commands::Agents {
                action: AgentsAction::Status { agent },
            }) => {
                assert!(agent.is_none());
            }
            _ => panic!("Expected agents status command"),
        }
    }

    #[test]
    fn cli_parses_agents_install_hook() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "agents", "install-hook", "claude-code"]).unwrap();
        match cli.command {
            Some(Commands::Agents {
                action: AgentsAction::InstallHook { agent, dry_run },
            }) => {
                assert_eq!(agent, "claude-code");
                assert!(!dry_run);
            }
            _ => panic!("Expected agents install-hook command"),
        }
    }

    // -------------------------------------------------------------------------
    // Global Flag Inheritance Tests
    // -------------------------------------------------------------------------

    #[test]
    fn cli_global_flags_with_subcommand() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "-v", "--json", "daemon", "status"]).unwrap();
        assert!(cli.verbose);
        assert!(cli.json);
        match cli.command {
            Some(Commands::Daemon {
                action: DaemonAction::Status,
            }) => {}
            _ => panic!("Expected daemon status command"),
        }
    }

    #[test]
    fn cli_global_flags_after_subcommand() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "daemon", "status", "-v", "--json"]).unwrap();
        assert!(cli.verbose);
        assert!(cli.json);
    }

    // -------------------------------------------------------------------------
    // Error Case Tests
    // -------------------------------------------------------------------------

    #[test]
    fn cli_rejects_unknown_subcommand() {
        let _guard = test_guard!();
        let result = Cli::try_parse_from(["rch", "unknown"]);
        assert!(result.is_err());
    }

    #[test]
    fn cli_rejects_invalid_color_option() {
        let _guard = test_guard!();
        // Note: clap accepts any string for color, the validation happens at runtime
        // with ColorChoice::parse, so this test verifies clap accepts it
        let cli = Cli::try_parse_from(["rch", "--color", "invalid"]).unwrap();
        assert_eq!(cli.color, "invalid");
    }

    #[test]
    fn cli_daemon_requires_action() {
        let _guard = test_guard!();
        let result = Cli::try_parse_from(["rch", "daemon"]);
        assert!(result.is_err());
    }

    #[test]
    fn cli_workers_requires_action() {
        let _guard = test_guard!();
        let result = Cli::try_parse_from(["rch", "workers"]);
        assert!(result.is_err());
    }

    #[test]
    fn cli_config_requires_action() {
        let _guard = test_guard!();
        let result = Cli::try_parse_from(["rch", "config"]);
        assert!(result.is_err());
    }

    #[test]
    fn cli_hook_requires_action() {
        let _guard = test_guard!();
        let result = Cli::try_parse_from(["rch", "hook"]);
        assert!(result.is_err());
    }

    // -------------------------------------------------------------------------
    // ColorChoice Tests
    // -------------------------------------------------------------------------

    #[test]
    fn color_choice_parse_auto() {
        let _guard = test_guard!();
        let choice = ColorChoice::parse("auto");
        assert_eq!(choice, ColorChoice::Auto);
    }

    #[test]
    fn color_choice_parse_always() {
        let _guard = test_guard!();
        let choice = ColorChoice::parse("always");
        assert_eq!(choice, ColorChoice::Always);
    }

    #[test]
    fn color_choice_parse_never() {
        let _guard = test_guard!();
        let choice = ColorChoice::parse("never");
        assert_eq!(choice, ColorChoice::Never);
    }

    #[test]
    fn color_choice_parse_unknown_defaults_to_auto() {
        let _guard = test_guard!();
        let choice = ColorChoice::parse("invalid");
        assert_eq!(choice, ColorChoice::Auto);
    }

    // -------------------------------------------------------------------------
    // OutputConfig Tests
    // -------------------------------------------------------------------------

    #[test]
    fn output_config_default_values() {
        let _guard = test_guard!();
        let config = OutputConfig::default();
        assert!(!config.json);
        assert!(!config.verbose);
        assert!(!config.quiet);
        assert_eq!(config.format, OutputFormat::Json);
    }

    #[test]
    fn output_config_from_cli_args_verbose() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "-v"]).unwrap();
        let format = resolve_output_format(cli.format.as_deref(), cli.json);
        let machine = machine_output_requested(cli.format.as_deref(), cli.json);
        let config = OutputConfig {
            json: machine,
            format,
            verbose: cli.verbose,
            quiet: cli.quiet,
            color: ColorChoice::parse(&cli.color),
            ..Default::default()
        };
        assert!(config.verbose);
        assert!(!config.quiet);
        assert!(!config.json);
    }

    #[test]
    fn output_config_from_cli_args_json() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "--json"]).unwrap();
        let format = resolve_output_format(cli.format.as_deref(), cli.json);
        let machine = machine_output_requested(cli.format.as_deref(), cli.json);
        let config = OutputConfig {
            json: machine,
            format,
            verbose: cli.verbose,
            quiet: cli.quiet,
            color: ColorChoice::parse(&cli.color),
            ..Default::default()
        };
        assert!(config.json);
        assert!(!config.verbose);
    }

    #[test]
    fn output_config_from_cli_args_quiet() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "-q"]).unwrap();
        let format = resolve_output_format(cli.format.as_deref(), cli.json);
        let machine = machine_output_requested(cli.format.as_deref(), cli.json);
        let config = OutputConfig {
            json: machine,
            format,
            verbose: cli.verbose,
            quiet: cli.quiet,
            color: ColorChoice::parse(&cli.color),
            ..Default::default()
        };
        assert!(config.quiet);
        assert!(!config.verbose);
    }

    #[test]
    fn output_format_resolves_to_toon() {
        let _guard = test_guard!();
        let format = resolve_output_format(Some("toon"), false);
        let machine = machine_output_requested(Some("toon"), false);
        assert_eq!(format, OutputFormat::Toon);
        assert!(machine);
    }

    // -------------------------------------------------------------------------
    // OutputContext Tests
    // -------------------------------------------------------------------------

    #[test]
    fn output_context_creation_from_config() {
        let _guard = test_guard!();
        let config = OutputConfig {
            json: true,
            verbose: true,
            quiet: false,
            color: ColorChoice::Never,
            ..Default::default()
        };
        let ctx = OutputContext::new(config);
        assert!(ctx.is_json());
        assert!(ctx.is_verbose());
        assert!(!ctx.is_quiet());
    }

    #[test]
    fn output_context_is_verbose_false_by_default() {
        let _guard = test_guard!();
        let ctx = OutputContext::new(OutputConfig::default());
        assert!(!ctx.is_verbose());
    }

    #[test]
    fn output_context_is_quiet_false_by_default() {
        let _guard = test_guard!();
        let ctx = OutputContext::new(OutputConfig::default());
        assert!(!ctx.is_quiet());
    }

    // -------------------------------------------------------------------------
    // find_web_directory Tests
    // -------------------------------------------------------------------------

    #[test]
    fn find_web_directory_error_message_is_helpful() {
        let _guard = test_guard!();
        let temp_dir = std::env::temp_dir().join("rch_test_no_web");
        let _ = std::fs::create_dir_all(&temp_dir);
        let original_dir = std::env::current_dir().unwrap();

        let _ = std::env::set_current_dir(&temp_dir);
        let result = find_web_directory();
        let _ = std::env::set_current_dir(&original_dir);

        if let Err(e) = result {
            let msg = e.to_string();
            assert!(msg.contains("Could not find web dashboard"));
        }
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    // -------------------------------------------------------------------------
    // Command Definition Validity Tests
    // -------------------------------------------------------------------------

    #[test]
    fn cli_command_debug_assert_passes() {
        let _guard = test_guard!();
        use clap::CommandFactory;
        Cli::command().debug_assert();
    }

    #[test]
    fn cli_has_version() {
        let _guard = test_guard!();
        use clap::CommandFactory;
        let cmd = Cli::command();
        assert!(cmd.get_version().is_some());
    }

    #[test]
    fn cli_has_about() {
        let _guard = test_guard!();
        use clap::CommandFactory;
        let cmd = Cli::command();
        assert!(cmd.get_about().is_some());
    }

    #[test]
    fn cli_has_after_help_with_examples() {
        let _guard = test_guard!();
        use clap::CommandFactory;
        let cmd = Cli::command();
        let after_help = cmd
            .get_after_help()
            .map(|s| s.to_string())
            .unwrap_or_default();
        assert!(after_help.contains("EXAMPLES:"));
        assert!(after_help.contains("ENVIRONMENT VARIABLES:"));
        assert!(after_help.contains("CONFIG PRECEDENCE"));
    }

    #[test]
    fn cli_subcommands_have_help() {
        let _guard = test_guard!();
        use clap::CommandFactory;
        let cmd = Cli::command();
        let subcommands: Vec<_> = cmd.get_subcommands().collect();
        assert!(!subcommands.is_empty());

        // Verify key subcommands exist
        let names: Vec<_> = subcommands
            .iter()
            .filter_map(|c| c.get_name().into())
            .collect();
        assert!(names.contains(&"daemon"));
        assert!(names.contains(&"workers"));
        assert!(names.contains(&"status"));
        assert!(names.contains(&"config"));
        assert!(names.contains(&"hook"));
    }

    // -------------------------------------------------------------------------
    // Queue Subcommand Tests
    // -------------------------------------------------------------------------

    #[test]
    fn cli_parses_queue_default() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "queue"]).unwrap();
        match cli.command {
            Some(Commands::Queue { watch, follow }) => {
                assert!(!watch);
                assert!(!follow);
            }
            _ => panic!("Expected queue command"),
        }
    }

    #[test]
    fn cli_parses_queue_watch() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "queue", "--watch"]).unwrap();
        match cli.command {
            Some(Commands::Queue { watch, .. }) => {
                assert!(watch);
            }
            _ => panic!("Expected queue command with watch"),
        }
    }

    #[test]
    fn cli_parses_queue_watch_short() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "queue", "-w"]).unwrap();
        match cli.command {
            Some(Commands::Queue { watch, .. }) => {
                assert!(watch);
            }
            _ => panic!("Expected queue command with -w"),
        }
    }

    #[test]
    fn cli_parses_queue_follow() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "queue", "--follow"]).unwrap();
        match cli.command {
            Some(Commands::Queue { follow, .. }) => {
                assert!(follow);
            }
            _ => panic!("Expected queue command with follow"),
        }
    }

    #[test]
    fn cli_parses_queue_follow_short() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "queue", "-f"]).unwrap();
        match cli.command {
            Some(Commands::Queue { follow, .. }) => {
                assert!(follow);
            }
            _ => panic!("Expected queue command with -f"),
        }
    }

    #[test]
    fn cli_parses_queue_watch_and_follow() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "queue", "-wf"]).unwrap();
        match cli.command {
            Some(Commands::Queue { watch, follow }) => {
                assert!(watch);
                assert!(follow);
            }
            _ => panic!("Expected queue command with watch and follow"),
        }
    }

    // -------------------------------------------------------------------------
    // Cancel Subcommand Tests
    // -------------------------------------------------------------------------

    #[test]
    fn cli_parses_cancel_by_id() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "cancel", "42"]).unwrap();
        match cli.command {
            Some(Commands::Cancel {
                build_id,
                all,
                force,
                yes,
                dry_run,
            }) => {
                assert_eq!(build_id, Some(42));
                assert!(!all);
                assert!(!force);
                assert!(!yes);
                assert!(!dry_run);
            }
            _ => panic!("Expected cancel command"),
        }
    }

    #[test]
    fn cli_parses_cancel_all() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "cancel", "--all"]).unwrap();
        match cli.command {
            Some(Commands::Cancel { all, .. }) => {
                assert!(all);
            }
            _ => panic!("Expected cancel --all command"),
        }
    }

    #[test]
    fn cli_parses_cancel_all_yes() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "cancel", "--all", "--yes"]).unwrap();
        match cli.command {
            Some(Commands::Cancel { all, yes, .. }) => {
                assert!(all);
                assert!(yes);
            }
            _ => panic!("Expected cancel --all --yes command"),
        }
    }

    #[test]
    fn cli_parses_cancel_force() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "cancel", "42", "--force"]).unwrap();
        match cli.command {
            Some(Commands::Cancel {
                build_id, force, ..
            }) => {
                assert_eq!(build_id, Some(42));
                assert!(force);
            }
            _ => panic!("Expected cancel with --force"),
        }
    }

    #[test]
    fn cli_parses_cancel_force_short() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "cancel", "42", "-f"]).unwrap();
        match cli.command {
            Some(Commands::Cancel {
                build_id, force, ..
            }) => {
                assert_eq!(build_id, Some(42));
                assert!(force);
            }
            _ => panic!("Expected cancel with -f"),
        }
    }

    #[test]
    fn cli_parses_cancel_yes_short() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "cancel", "--all", "-y"]).unwrap();
        match cli.command {
            Some(Commands::Cancel { yes, .. }) => {
                assert!(yes);
            }
            _ => panic!("Expected cancel with -y"),
        }
    }

    #[test]
    fn cli_parses_cancel_dry_run() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "cancel", "--dry-run"]).unwrap();
        match cli.command {
            Some(Commands::Cancel { dry_run, .. }) => {
                assert!(dry_run);
            }
            _ => panic!("Expected cancel with --dry-run"),
        }
    }

    #[test]
    fn cli_parses_cancel_dry_run_short() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "cancel", "-n"]).unwrap();
        match cli.command {
            Some(Commands::Cancel { dry_run, .. }) => {
                assert!(dry_run);
            }
            _ => panic!("Expected cancel with -n"),
        }
    }

    #[test]
    fn cli_parses_cancel_dry_run_with_id() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "cancel", "42", "--dry-run"]).unwrap();
        match cli.command {
            Some(Commands::Cancel {
                build_id, dry_run, ..
            }) => {
                assert_eq!(build_id, Some(42));
                assert!(dry_run);
            }
            _ => panic!("Expected cancel 42 --dry-run"),
        }
    }

    #[test]
    fn cli_parses_cancel_all_dry_run_combined() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "cancel", "-an"]).unwrap();
        match cli.command {
            Some(Commands::Cancel { all, dry_run, .. }) => {
                assert!(all);
                assert!(dry_run);
            }
            _ => panic!("Expected cancel -an"),
        }
    }

    // -------------------------------------------------------------------------
    // SelfTest Subcommand Tests
    // -------------------------------------------------------------------------

    #[test]
    fn cli_parses_self_test_default() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "self-test"]).unwrap();
        match cli.command {
            Some(Commands::SelfTest {
                action,
                worker,
                all,
                project,
                timeout,
                debug,
                scheduled,
            }) => {
                assert!(action.is_none());
                assert!(worker.is_none());
                assert!(!all);
                assert!(project.is_none());
                assert_eq!(timeout, 300);
                assert!(!debug);
                assert!(!scheduled);
            }
            _ => panic!("Expected self-test command"),
        }
    }

    #[test]
    fn cli_parses_self_test_worker() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "self-test", "--worker", "css"]).unwrap();
        match cli.command {
            Some(Commands::SelfTest { worker, all, .. }) => {
                assert_eq!(worker.as_deref(), Some("css"));
                assert!(!all);
            }
            _ => panic!("Expected self-test --worker command"),
        }
    }

    #[test]
    fn cli_parses_self_test_all() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "self-test", "--all"]).unwrap();
        match cli.command {
            Some(Commands::SelfTest { all, .. }) => {
                assert!(all);
            }
            _ => panic!("Expected self-test --all command"),
        }
    }

    #[test]
    fn cli_parses_self_test_timeout() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "self-test", "--timeout", "600"]).unwrap();
        match cli.command {
            Some(Commands::SelfTest { timeout, .. }) => {
                assert_eq!(timeout, 600);
            }
            _ => panic!("Expected self-test --timeout command"),
        }
    }

    #[test]
    fn cli_parses_self_test_debug() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "self-test", "--debug"]).unwrap();
        match cli.command {
            Some(Commands::SelfTest { debug, .. }) => {
                assert!(debug);
            }
            _ => panic!("Expected self-test --debug command"),
        }
    }

    #[test]
    fn cli_parses_self_test_scheduled() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "self-test", "--scheduled"]).unwrap();
        match cli.command {
            Some(Commands::SelfTest { scheduled, .. }) => {
                assert!(scheduled);
            }
            _ => panic!("Expected self-test --scheduled command"),
        }
    }

    #[test]
    fn cli_parses_self_test_status() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "self-test", "status"]).unwrap();
        match cli.command {
            Some(Commands::SelfTest { action, .. }) => {
                assert!(matches!(action, Some(SelfTestAction::Status)));
            }
            _ => panic!("Expected self-test status command"),
        }
    }

    #[test]
    fn cli_parses_self_test_history() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "self-test", "history"]).unwrap();
        match cli.command {
            Some(Commands::SelfTest { action, .. }) => {
                assert!(matches!(
                    action,
                    Some(SelfTestAction::History { limit: 10 })
                ));
            }
            _ => panic!("Expected self-test history command"),
        }
    }

    #[test]
    fn cli_parses_self_test_history_limit() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "self-test", "history", "--limit", "20"]).unwrap();
        match cli.command {
            Some(Commands::SelfTest { action, .. }) => {
                assert!(matches!(
                    action,
                    Some(SelfTestAction::History { limit: 20 })
                ));
            }
            _ => panic!("Expected self-test history --limit command"),
        }
    }

    #[test]
    fn cli_parses_self_test_project() {
        let _guard = test_guard!();
        let cli = Cli::try_parse_from(["rch", "self-test", "--project", "/tmp/test"]).unwrap();
        match cli.command {
            Some(Commands::SelfTest { project, .. }) => {
                assert_eq!(
                    project.as_ref().map(|p| p.display().to_string()),
                    Some("/tmp/test".to_string())
                );
            }
            _ => panic!("Expected self-test --project command"),
        }
    }

    // -------------------------------------------------------------------------
    // Output Format Utility Tests
    // -------------------------------------------------------------------------

    #[test]
    fn machine_output_requested_json_flag_true() {
        let _guard = test_guard!();
        assert!(machine_output_requested(None, true));
    }

    #[test]
    fn machine_output_requested_format_some() {
        let _guard = test_guard!();
        assert!(machine_output_requested(Some("toon"), false));
    }

    #[test]
    fn machine_output_requested_both_set() {
        let _guard = test_guard!();
        assert!(machine_output_requested(Some("json"), true));
    }

    #[test]
    fn machine_output_requested_neither_set() {
        let _guard = test_guard!();
        assert!(!machine_output_requested(None, false));
    }

    #[test]
    fn resolve_output_format_explicit_json() {
        let _guard = test_guard!();
        assert_eq!(
            resolve_output_format(Some("json"), false),
            OutputFormat::Json
        );
    }

    #[test]
    fn resolve_output_format_explicit_toon() {
        let _guard = test_guard!();
        assert_eq!(
            resolve_output_format(Some("toon"), false),
            OutputFormat::Toon
        );
    }

    #[test]
    fn resolve_output_format_explicit_with_json_flag() {
        let _guard = test_guard!();
        // Explicit format takes precedence over json flag
        assert_eq!(
            resolve_output_format(Some("toon"), true),
            OutputFormat::Toon
        );
    }

    #[test]
    fn resolve_output_format_invalid_format_falls_back() {
        let _guard = test_guard!();
        // Invalid format string should fall back to Json default
        assert_eq!(
            resolve_output_format(Some("invalid"), false),
            OutputFormat::Json
        );
    }
}
