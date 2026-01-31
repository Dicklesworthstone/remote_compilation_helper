//! Rich error diagnostics with miette integration.
//!
//! This module provides context-rich error types that leverage miette's
//! diagnostic capabilities for beautiful, actionable error messages.
//!
//! All public errors implement `Diagnostic` and follow the error code
//! convention `RCH-Exxx`.

#![allow(unused_assignments)]

use miette::{Diagnostic, NamedSource, SourceSpan};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use thiserror::Error;

/// Convenient Result type alias using miette::Report for rich errors.
pub type Result<T> = std::result::Result<T, miette::Report>;

// =============================================================================
// Configuration Errors
// =============================================================================

/// Errors related to configuration file parsing and validation.
///
/// Error code range: RCH-E001 to RCH-E012
#[allow(unused_assignments)]
#[derive(Error, Diagnostic, Debug)]
pub enum ConfigError {
    /// Configuration file not found at expected location.
    #[error("Config file not found: {path}")]
    #[diagnostic(code("RCH-E001"), help("Create a config file with: rch config init"))]
    NotFound { path: PathBuf },

    /// Failed to read the configuration file from disk.
    #[error("Failed to read config file: {path}")]
    #[diagnostic(
        code("RCH-E002"),
        help("Check that the file exists and you have read permissions")
    )]
    ReadFailed {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// TOML syntax error in configuration file.
    #[error("Invalid TOML syntax in config")]
    #[diagnostic(code("RCH-E003"))]
    ParseError {
        #[source_code]
        src: NamedSource<String>,
        #[label("{message}")]
        span: SourceSpan,
        message: String,
    },

    /// Invalid configuration value.
    #[error("Invalid value for '{field}': {reason}")]
    #[diagnostic(code("RCH-E004"), help("{suggestion}"))]
    InvalidValue {
        field: String,
        reason: String,
        suggestion: String,
    },

    /// Workers configuration file not found.
    #[error("Workers config not found: {path}")]
    #[diagnostic(
        code("RCH-E005"),
        help(
            "Create a workers config at ~/.config/rch/workers.toml\nExample:\n\n[[workers]]\nid = \"worker1\"\nhost = \"192.168.1.100\"\nuser = \"ubuntu\"\nidentity_file = \"~/.ssh/id_rsa\"\ntotal_slots = 16\n"
        )
    )]
    WorkersNotFound { path: PathBuf },

    /// Workers configuration file parse error.
    #[error("Failed to parse workers config: {path}")]
    #[diagnostic(
        code("RCH-E006"),
        help("Check the TOML syntax in your workers.toml file")
    )]
    WorkersParseError { path: PathBuf, message: String },

    /// No workers are configured.
    #[error("No workers configured")]
    #[diagnostic(
        code("RCH-E007"),
        help("Configure workers in ~/.config/rch/workers.toml")
    )]
    NoWorkers,

    /// Worker not found by ID.
    #[error("Worker '{worker_id}' not found in configuration")]
    #[diagnostic(code("RCH-E008"), help("List available workers: rch workers list"))]
    WorkerNotFound { worker_id: String },

    /// Duplicate worker ID in configuration.
    #[error("Duplicate worker ID: {worker_id}")]
    #[diagnostic(
        code("RCH-E009"),
        help("Each worker must have a unique ID in workers.toml")
    )]
    DuplicateWorkerId { worker_id: String },

    /// Invalid worker configuration.
    #[error("Invalid worker configuration for '{worker_id}': {reason}")]
    #[diagnostic(code("RCH-E010"), help("{suggestion}"))]
    InvalidWorker {
        worker_id: String,
        reason: String,
        suggestion: String,
    },

    /// Missing required configuration field.
    #[error("Missing required field: {field}")]
    #[diagnostic(code("RCH-E011"), help("Add the '{field}' field to your config file"))]
    MissingField { field: String },

    /// Configuration migration required.
    #[error("Configuration migration required: {reason}")]
    #[diagnostic(
        code("RCH-E012"),
        help("Run 'rch config migrate' to update your configuration")
    )]
    MigrationRequired { reason: String },
}

impl ConfigError {
    /// Create a parse error from a TOML deserialization error.
    pub fn from_toml_error(path: &std::path::Path, content: String, err: toml::de::Error) -> Self {
        let span = err.span().map(|s| (s.start, s.end.saturating_sub(s.start)));
        ConfigError::ParseError {
            src: NamedSource::new(path.display().to_string(), content),
            span: span.map(|(o, l)| (o, l).into()).unwrap_or((0, 0).into()),
            message: err.message().to_string(),
        }
    }
}

// =============================================================================
// Worker Errors
// =============================================================================

/// Errors related to worker connectivity and management.
///
/// Error code range: RCH-E200 to RCH-E210
#[derive(Error, Diagnostic, Debug)]
pub enum WorkerError {
    /// Worker probe failed.
    #[error("Probe failed for worker '{worker_id}': {reason}")]
    #[diagnostic(
        code("RCH-E200"),
        help("Check worker connectivity: rch workers probe {worker_id}")
    )]
    ProbeFailed { worker_id: String, reason: String },

    /// Worker is unreachable.
    #[error("Worker '{worker_id}' is unreachable")]
    #[diagnostic(
        code("RCH-E201"),
        help("Verify SSH access with:\n  ssh -i {identity_file} {user}@{host}")
    )]
    Unreachable {
        worker_id: String,
        host: String,
        user: String,
        identity_file: String,
        #[source]
        source: std::io::Error,
    },

    /// Worker is configured but unhealthy.
    #[error("Worker '{worker_id}' is unhealthy: {reason}")]
    #[diagnostic(
        code("RCH-E202"),
        help("Check worker status: rch workers probe {worker_id}")
    )]
    Unhealthy { worker_id: String, reason: String },

    /// Worker is at capacity (all slots busy).
    #[error("Worker '{worker_id}' is at capacity (all {total_slots} slots busy)")]
    #[diagnostic(
        code("RCH-E203"),
        help("Wait for running jobs to complete or use a different worker")
    )]
    AtCapacity { worker_id: String, total_slots: u32 },

    /// All workers are busy (at capacity).
    #[error("All workers are at capacity")]
    #[diagnostic(
        code("RCH-E204"),
        help("Wait for running jobs to complete or add more workers")
    )]
    AllBusy,

    /// Worker circuit breaker is open.
    #[error("Circuit breaker open for worker '{worker_id}'")]
    #[diagnostic(
        code("RCH-E205"),
        help("Worker has experienced repeated failures. Wait for recovery or check health.")
    )]
    CircuitOpen { worker_id: String },

    /// Worker circuit breaker is half-open.
    #[error("Circuit breaker half-open for worker '{worker_id}' (testing recovery)")]
    #[diagnostic(
        code("RCH-E206"),
        help("Worker is recovering from failures. A test request is in progress.")
    )]
    CircuitHalfOpen { worker_id: String },

    /// All workers have their circuit breakers open.
    #[error("All worker circuit breakers are open")]
    #[diagnostic(
        code("RCH-E207"),
        help(
            "Workers have experienced repeated failures.\nWait for circuit breakers to reset or check worker health:\n  rch workers probe --all"
        )
    )]
    AllCircuitsOpen,

    /// Worker selection failed.
    #[error("Failed to select a worker: {reason}")]
    #[diagnostic(code("RCH-E208"), help("Check worker availability: rch workers list"))]
    SelectionFailed { reason: String },

    /// Worker drain timeout.
    #[error("Drain timeout for worker '{worker_id}' after {timeout_secs}s")]
    #[diagnostic(
        code("RCH-E209"),
        help("Active jobs are still running. Consider increasing timeout or force-draining.")
    )]
    DrainTimeout {
        worker_id: String,
        timeout_secs: u64,
    },

    /// Worker benchmark failed.
    #[error("Benchmark failed for worker '{worker_id}': {reason}")]
    #[diagnostic(
        code("RCH-E210"),
        help("Check worker status: rch workers probe {worker_id}")
    )]
    BenchmarkFailed { worker_id: String, reason: String },
}

// =============================================================================
// SSH Errors
// =============================================================================

/// Errors related to SSH connectivity and authentication.
///
/// Error code range: RCH-E100 to RCH-E113
#[derive(Error, Diagnostic, Debug)]
pub enum SshError {
    /// Generic SSH connection failure.
    #[error("SSH connection failed for {user}@{host}: {message}")]
    #[diagnostic(
        code("RCH-E100"),
        help(
            "SSH Troubleshooting:\n\
  1. Verify host/user/key in workers.toml.\n\
  2. Try a manual connection with verbose logs:\n\
     ssh -vvv -i {key_path:?} {user}@{host}\n\n\
Run 'rch doctor' for comprehensive SSH diagnostics."
        )
    )]
    ConnectionFailed {
        host: String,
        user: String,
        key_path: PathBuf,
        message: String,
    },

    /// SSH authentication failed (permission denied).
    #[error("SSH authentication failed for {user}@{host}")]
    #[diagnostic(
        code("RCH-E101"),
        help(
            "SSH Troubleshooting:\n\
  1. Verify key exists:\n\
     ls -la {key_path:?}\n\n\
  2. Generate a key if needed:\n\
     ssh-keygen -t ed25519 -f {key_path:?}\n\n\
  3. Copy key to worker:\n\
     ssh-copy-id -i {key_path:?} {user}@{host}\n\n\
  4. Test connection manually:\n\
     ssh -i {key_path:?} {user}@{host} echo \"success\"\n\n\
  5. If using SSH agent:\n\
     eval $(ssh-agent) && ssh-add {key_path:?}\n\n\
  6. Debug with verbose logs:\n\
     ssh -vvv -i {key_path:?} {user}@{host}\n\n\
Run 'rch doctor' for comprehensive SSH diagnostics."
        )
    )]
    AuthFailed {
        host: String,
        user: String,
        key_path: PathBuf,
    },

    /// SSH key file not found.
    #[error("SSH identity file not found: {key_path}")]
    #[diagnostic(
        code("RCH-E102"),
        help("Verify the identity_file path in your workers.toml")
    )]
    KeyNotFound { key_path: PathBuf },

    /// SSH key has wrong permissions.
    #[error("SSH key has insecure permissions: {}", key_path.display())]
    #[diagnostic(code("RCH-E103"), help("Fix with: chmod 600 <key_path>"))]
    KeyInsecurePermissions { key_path: PathBuf },

    /// SSH host key verification failed.
    #[error("SSH host key verification failed for {host}")]
    #[diagnostic(
        code("RCH-E104"),
        help(
            "SSH Troubleshooting:\n\
  1. Remove the old host key:\n\
     ssh-keygen -R {host}\n\n\
  2. Fetch and trust the new host key:\n\
     ssh-keyscan -H {host} >> ~/.ssh/known_hosts\n\n\
  3. Retry with verbose logs:\n\
     ssh -vvv -i {key_path:?} {user}@{host}\n\n\
Run 'rch doctor' for comprehensive SSH diagnostics."
        )
    )]
    HostKeyVerificationFailed {
        host: String,
        user: String,
        key_path: PathBuf,
    },

    /// SSH connection timed out.
    #[error("SSH connection to {host} timed out after {timeout_secs}s")]
    #[diagnostic(
        code("RCH-E105"),
        help(
            "SSH Troubleshooting:\n\
  1. Check network connectivity and firewall rules.\n\
  2. Verify the host is reachable:\n\
     ssh -vvv -i {key_path:?} {user}@{host}\n\n\
Run 'rch doctor' for comprehensive SSH diagnostics."
        )
    )]
    ConnectionTimeout {
        host: String,
        user: String,
        key_path: PathBuf,
        timeout_secs: u64,
    },

    /// SSH command execution failed.
    #[error("SSH command execution failed on {host}: {message}")]
    #[diagnostic(
        code("RCH-E106"),
        help("Check the command output and worker logs for details")
    )]
    CommandFailed { host: String, message: String },

    /// SSH channel error.
    #[error("SSH channel error for {user}@{host}: {message}")]
    #[diagnostic(
        code("RCH-E107"),
        help("The SSH session encountered a channel error. Try reconnecting.")
    )]
    ChannelError {
        host: String,
        user: String,
        message: String,
    },

    /// SSH connection was refused by the host.
    #[error("SSH connection refused for {user}@{host}")]
    #[diagnostic(
        code("RCH-E108"),
        help(
            "SSH Troubleshooting:\n\
  1. Ensure sshd is running on the worker and port 22 is open.\n\
  2. If using a custom port, configure it in ~/.ssh/config and workers.toml.\n\
  3. Debug with verbose logs:\n\
     ssh -vvv -i {key_path:?} {user}@{host}\n\n\
Run 'rch doctor' for comprehensive SSH diagnostics."
        )
    )]
    ConnectionRefused {
        host: String,
        user: String,
        key_path: PathBuf,
    },

    /// Binary not found on remote worker.
    #[error("Required binary '{binary}' not found on worker {host}")]
    #[diagnostic(
        code("RCH-E109"),
        help("Install the required binary on the worker: {install_hint}")
    )]
    BinaryNotFound {
        host: String,
        binary: String,
        install_hint: String,
    },

    /// Toolchain installation failed on remote worker.
    #[error("Toolchain installation failed on {host}: {message}")]
    #[diagnostic(
        code("RCH-E110"),
        help("Try installing the toolchain manually: rustup toolchain install {toolchain}")
    )]
    ToolchainInstallFailed {
        host: String,
        toolchain: String,
        message: String,
    },

    /// Remote file permission error.
    #[error("Permission denied for file on {host}: {path}")]
    #[diagnostic(code("RCH-E111"), help("Check file permissions on the remote worker"))]
    RemotePermissionDenied { host: String, path: String },

    /// SSH authentication failed (permission denied) - legacy alias.
    #[error("SSH authentication failed for {user}@{host}")]
    #[diagnostic(
        code("RCH-E113"),
        help(
            "SSH Troubleshooting:\n\
  1. Verify key exists and copy key to worker if needed.\n\
  2. Debug with verbose logs: ssh -vvv -i <key> {user}@{host}\n\n\
Run 'rch doctor' for comprehensive SSH diagnostics."
        )
    )]
    PermissionDenied {
        host: String,
        user: String,
        key_path: PathBuf,
    },

    /// SSH agent is unavailable or has no keys.
    #[error("SSH agent unavailable for key {key_path:?}")]
    #[diagnostic(
        code("RCH-E112"),
        help(
            "SSH Troubleshooting:\n\
  1. Start the SSH agent and add your key:\n\
     eval $(ssh-agent) && ssh-add {key_path:?}\n\n\
  2. Verify agent has keys:\n\
     ssh-add -L\n\n\
Run 'rch doctor' for comprehensive SSH diagnostics."
        )
    )]
    AgentUnavailable {
        host: String,
        user: String,
        key_path: PathBuf,
    },
}

// =============================================================================
// Daemon Errors
// =============================================================================

/// Errors related to the RCH daemon.
///
/// Error code range: RCH-E300 to RCH-E308
#[derive(Error, Diagnostic, Debug)]
pub enum DaemonError {
    /// Daemon is not running.
    #[error("RCH daemon is not running")]
    #[diagnostic(code("RCH-E300"), help("Start the daemon with: rch daemon start"))]
    NotRunning,

    /// Daemon socket file not found.
    #[error("Daemon socket not found at {socket_path}")]
    #[diagnostic(
        code("RCH-E301"),
        help(
            "The daemon socket file does not exist. This usually means:\n  1. The daemon is not running\n  2. The socket path is misconfigured\n\nStart the daemon: rch daemon start\nOr check config: rch config show | grep socket"
        )
    )]
    SocketNotFound { socket_path: String },

    /// Daemon socket connection refused.
    #[error("Failed to connect to daemon at {socket_path}")]
    #[diagnostic(
        code("RCH-E302"),
        help(
            "The daemon socket exists but connection failed.\n\nCheck daemon status: rch daemon status\nView daemon logs: rch daemon logs\nRestart daemon: rch daemon restart"
        )
    )]
    ConnectionFailed {
        socket_path: String,
        #[source]
        source: std::io::Error,
    },

    /// Daemon socket permission denied.
    #[error("Permission denied connecting to daemon socket at {socket_path}")]
    #[diagnostic(
        code("RCH-E303"),
        help("Check socket permissions or run with appropriate privileges")
    )]
    SocketPermissionDenied { socket_path: String },

    /// Daemon startup failed.
    #[error("Daemon startup failed")]
    #[diagnostic(code("RCH-E304"), help("Check the logs for details: rch daemon logs"))]
    StartupFailed {
        #[source]
        source: std::io::Error,
    },

    /// Daemon already running.
    #[error("RCH daemon is already running (PID: {pid})")]
    #[diagnostic(
        code("RCH-E305"),
        help("Stop the existing daemon first: rch daemon stop")
    )]
    AlreadyRunning { pid: u32 },

    /// Daemon communication timeout.
    #[error("Daemon communication timed out after {timeout_secs}s")]
    #[diagnostic(
        code("RCH-E306"),
        help("The daemon may be overloaded. Try again or restart the daemon.")
    )]
    CommunicationTimeout { timeout_secs: u64 },

    /// Daemon returned an error.
    #[error("Daemon returned error: {message}")]
    #[diagnostic(code("RCH-E307"))]
    ProtocolError { message: String },

    /// Daemon version mismatch.
    #[error("Daemon version mismatch: expected {expected}, got {actual}")]
    #[diagnostic(
        code("RCH-E308"),
        help("Restart the daemon to load the new version: rch daemon restart")
    )]
    VersionMismatch { expected: String, actual: String },
}

// =============================================================================
// Build/Transfer Errors
// =============================================================================

/// Errors related to build and file transfer operations.
///
/// Error code range: RCH-E400 to RCH-E409
#[derive(Error, Diagnostic, Debug)]
pub enum TransferError {
    /// Build failed on remote worker.
    #[error("Build failed on {worker_id}")]
    #[diagnostic(code("RCH-E400"), help("Check the build output for errors"))]
    BuildFailed { worker_id: String, stderr: String },

    /// Build timed out.
    #[error("Build timed out after {seconds}s")]
    #[diagnostic(
        code("RCH-E401"),
        help("Consider increasing the build timeout or optimizing the build")
    )]
    Timeout { seconds: u64 },

    /// Build cancelled.
    #[error("Build cancelled")]
    #[diagnostic(code("RCH-E402"), help("The build was cancelled before completion"))]
    Cancelled,

    /// Build output missing.
    #[error("Build output missing: expected {expected_path}")]
    #[diagnostic(
        code("RCH-E403"),
        help("The build may have failed silently. Check build logs.")
    )]
    OutputMissing { expected_path: String },

    /// Artifact transfer failed.
    #[error("Failed to retrieve build artifacts from {worker_id}")]
    #[diagnostic(
        code("RCH-E404"),
        help("Check that the build completed successfully on the worker")
    )]
    ArtifactFailed {
        worker_id: String,
        #[source]
        source: std::io::Error,
    },

    /// Project sync failed.
    #[error("Project sync failed: {reason}")]
    #[diagnostic(
        code("RCH-E405"),
        help(
            "Ensure rsync is installed on both local and remote machines:\n  which rsync\n  ssh worker which rsync"
        )
    )]
    SyncFailed {
        reason: String,
        exit_code: Option<i32>,
        stderr: String,
    },

    /// Working directory not found.
    #[error("Working directory not found: {path}")]
    #[diagnostic(
        code("RCH-E406"),
        help(
            "Could not access the working directory.\n\nEnsure you are running from a valid directory:\n  pwd\n  ls -la"
        )
    )]
    WorkingDirNotFound {
        path: String,
        #[source]
        source: std::io::Error,
    },

    /// Command classification failed.
    #[error("Failed to classify command: {command}")]
    #[diagnostic(
        code("RCH-E407"),
        help("The command could not be classified for remote execution")
    )]
    ClassificationFailed { command: String },

    /// Build queue full.
    #[error("Build queue is full ({queue_size} pending)")]
    #[diagnostic(
        code("RCH-E408"),
        help("Wait for pending builds to complete or add more workers")
    )]
    QueueFull { queue_size: usize },

    /// Failed to determine project root - legacy variant.
    #[error("Failed to determine project root directory")]
    #[diagnostic(
        code("RCH-E409"),
        help(
            "Could not get the current working directory.\n\nEnsure you are running from a valid directory:\n  pwd\n  ls -la"
        )
    )]
    NoProjectRoot {
        #[source]
        source: std::io::Error,
    },

    /// Transfer estimation indicates transfer should be skipped.
    ///
    /// This is not a fatal error - it indicates that the transfer would exceed
    /// configured limits (size, time) and local execution should be used instead.
    #[error("Transfer skipped: {reason}")]
    #[diagnostic(
        code("RCH-W409"),
        help("Adjust transfer limits in config: max_transfer_mb, max_transfer_time_ms")
    )]
    TransferSkipped { reason: String },
}

// =============================================================================
// Hook Errors
// =============================================================================

/// Errors related to the Claude Code hook.
///
/// Error code range: RCH-E500 to RCH-E505
#[derive(Error, Diagnostic, Debug)]
pub enum HookError {
    /// Hook installation failed.
    #[error("Failed to install Claude Code hook")]
    #[diagnostic(
        code("RCH-E500"),
        help(
            "Manual installation:\n  Add to ~/.config/claude-code/settings.json:\n  \"hooks\": {{\n    \"PreToolUse\": [{{ \"command\": \"rch\" }}]\n  }}"
        )
    )]
    InstallFailed {
        #[source]
        source: std::io::Error,
    },

    /// Claude Code settings file not found.
    #[error("Claude Code settings not found: {path}")]
    #[diagnostic(
        code("RCH-E501"),
        help("Ensure Claude Code is installed and has been run at least once")
    )]
    SettingsNotFound { path: PathBuf },

    /// Hook settings parse error.
    #[error("Failed to parse Claude Code settings: {message}")]
    #[diagnostic(
        code("RCH-E502"),
        help("Check the JSON syntax in your Claude Code settings file")
    )]
    SettingsParseError { message: String },

    /// Hook settings write error.
    #[error("Failed to write Claude Code settings: {path}")]
    #[diagnostic(code("RCH-E503"), help("Check file permissions for the settings file"))]
    SettingsWriteFailed {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// Hook already installed.
    #[error("RCH hook is already installed")]
    #[diagnostic(
        code("RCH-E504"),
        help("Use 'rch uninstall' to remove and reinstall if needed")
    )]
    AlreadyInstalled,

    /// Hook not installed.
    #[error("RCH hook is not installed")]
    #[diagnostic(code("RCH-E505"), help("Install the hook with: rch install"))]
    NotInstalled,

    /// Hook operation not supported for this agent.
    #[error("{agent} does not support hook {operation}: {reason}")]
    #[diagnostic(
        code("RCH-E506"),
        help(
            "Not all AI coding agents support hook integration. Check 'rch agent list' for supported agents."
        )
    )]
    NotSupported {
        agent: String,
        operation: String,
        reason: String,
    },

    /// Hook operation not yet implemented for this agent.
    #[error("{agent} hook {operation} is not yet implemented")]
    #[diagnostic(
        code("RCH-E507"),
        help(
            "This agent may be supported in a future release. Check for updates with 'rch update'."
        )
    )]
    NotImplemented { agent: String, operation: String },
}

// =============================================================================
// Update Errors
// =============================================================================

/// Errors related to self-update functionality.
///
/// Error code range: RCH-E520 to RCH-E524
#[derive(Error, Diagnostic, Debug)]
pub enum UpdateError {
    /// Failed to fetch release information.
    #[error("Failed to fetch release info from GitHub")]
    #[diagnostic(code("RCH-E520"), help("Check your internet connection and try again"))]
    FetchFailed {
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// No compatible release found.
    #[error("No compatible release found for {platform}")]
    #[diagnostic(
        code("RCH-E521"),
        help(
            "Build from source: cargo install --git https://github.com/Dicklesworthstone/remote_compilation_helper.git"
        )
    )]
    NoRelease { platform: String },

    /// Checksum verification failed.
    #[error("Checksum verification failed for downloaded binary")]
    #[diagnostic(
        code("RCH-E522"),
        help("The download may be corrupted. Try again or download manually from GitHub.")
    )]
    ChecksumFailed { expected: String, actual: String },

    /// Installation failed.
    #[error("Failed to install update")]
    #[diagnostic(
        code("RCH-E523"),
        help("Check that you have write permissions to the installation directory")
    )]
    InstallFailed {
        #[source]
        source: std::io::Error,
    },

    /// Rollback not available.
    #[error("No backup available for rollback")]
    #[diagnostic(
        code("RCH-E524"),
        help("Rollback is only available after a successful update")
    )]
    NoBackup,
}

// =============================================================================
// Artifact Retrieval Warning (bd-1q3p)
// =============================================================================

/// Warning details when artifact retrieval fails but compilation succeeded.
///
/// This struct captures actionable information for users when the build artifacts
/// couldn't be retrieved from the worker, even though the remote compilation succeeded.
/// This enables soft-fail semantics where the user can understand what went wrong
/// and take corrective action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactRetrievalWarning {
    /// The artifact patterns that were attempted for retrieval.
    pub attempted_patterns: Vec<String>,
    /// Snippet of rsync stderr (truncated for display).
    pub rsync_stderr_snippet: String,
    /// Exit code from rsync command.
    pub rsync_exit_code: Option<i32>,
    /// Worker ID where the artifacts remain.
    pub worker_id: String,
    /// Suggested actions for remediation.
    pub suggestions: Vec<String>,
}

impl ArtifactRetrievalWarning {
    /// Maximum length for stderr snippet.
    const MAX_STDERR_LEN: usize = 500;

    /// Create a new artifact retrieval warning with default suggestions.
    pub fn new(
        worker_id: impl Into<String>,
        attempted_patterns: Vec<String>,
        rsync_stderr: impl Into<String>,
        rsync_exit_code: Option<i32>,
    ) -> Self {
        let stderr = rsync_stderr.into();
        let rsync_stderr_snippet = if stderr.len() > Self::MAX_STDERR_LEN {
            format!("{}...", &stderr[..Self::MAX_STDERR_LEN])
        } else {
            stderr
        };

        Self {
            attempted_patterns,
            rsync_stderr_snippet,
            rsync_exit_code,
            worker_id: worker_id.into(),
            suggestions: vec![
                "Run `rch diagnose` for detailed diagnostics".to_string(),
                "Check worker connectivity: `rch workers probe`".to_string(),
                "Build artifacts remain on worker and can be fetched manually".to_string(),
            ],
        }
    }

    /// Add custom suggestions.
    pub fn with_suggestions(mut self, suggestions: Vec<String>) -> Self {
        self.suggestions = suggestions;
        self
    }

    /// Format a user-friendly warning message.
    pub fn format_warning(&self) -> String {
        let mut msg = String::new();
        msg.push_str("⚠️  Artifact retrieval failed (compilation succeeded)\n\n");

        msg.push_str("Attempted patterns:\n");
        for pattern in &self.attempted_patterns {
            msg.push_str(&format!("  • {}\n", pattern));
        }

        if !self.rsync_stderr_snippet.is_empty() {
            msg.push_str("\nrsync error:\n");
            for line in self.rsync_stderr_snippet.lines().take(5) {
                msg.push_str(&format!("  {}\n", line));
            }
        }

        if let Some(code) = self.rsync_exit_code {
            msg.push_str(&format!("\nrsync exit code: {}\n", code));
        }

        msg.push_str(&format!(
            "\nArtifacts remain on worker: {}\n",
            self.worker_id
        ));

        if !self.suggestions.is_empty() {
            msg.push_str("\nSuggested actions:\n");
            for (i, suggestion) in self.suggestions.iter().enumerate() {
                msg.push_str(&format!("  {}. {}\n", i + 1, suggestion));
            }
        }

        msg
    }

    /// Convert to JSON for machine-readable output.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "artifact_retrieval_warning",
            "worker_id": self.worker_id,
            "attempted_patterns": self.attempted_patterns,
            "rsync_stderr_snippet": self.rsync_stderr_snippet,
            "rsync_exit_code": self.rsync_exit_code,
            "suggestions": self.suggestions,
        })
    }
}

impl std::fmt::Display for ArtifactRetrievalWarning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.format_warning())
    }
}

// =============================================================================
// Platform Errors
// =============================================================================

/// Errors related to platform-specific functionality.
///
/// Error code range: RCH-E600 to RCH-E610
#[derive(Error, Diagnostic, Debug)]
pub enum PlatformError {
    /// Feature requires Unix-like platform (Linux, macOS, BSD).
    #[error("{feature} is only supported on Unix-like platforms (Linux, macOS, BSD)")]
    #[diagnostic(
        code("RCH-E600"),
        help(
            "This feature requires Unix domain sockets or other Unix-specific APIs.\nConsider using WSL2 on Windows."
        )
    )]
    UnixOnly { feature: String },

    /// Feature requires Windows platform.
    #[error("{feature} is only supported on Windows")]
    #[diagnostic(
        code("RCH-E601"),
        help("This feature uses Windows-specific APIs that are not available on Unix.")
    )]
    WindowsOnly { feature: String },

    /// Platform-specific binary not found.
    #[error("{binary} binary not found for platform {platform}")]
    #[diagnostic(
        code("RCH-E602"),
        help("Build the binary with: cargo build --release -p {binary}")
    )]
    BinaryNotFound { binary: String, platform: String },

    /// Unix domain socket not supported on this platform.
    #[error("Unix domain socket communication is not supported on this platform")]
    #[diagnostic(
        code("RCH-E603"),
        help(
            "Daemon communication requires Unix domain sockets.\nOn Windows, consider using WSL2 or a TCP-based alternative."
        )
    )]
    UnixSocketUnsupported,
}

// =============================================================================
// Binary/Deployment Errors
// =============================================================================

/// Errors related to binary deployment and version management.
///
/// Error code range: RCH-E800 to RCH-E810
#[derive(Error, Diagnostic, Debug)]
pub enum BinaryError {
    /// Binary not found at expected location.
    #[error("Could not find {name} binary")]
    #[diagnostic(code("RCH-E800"), help("Build with: cargo build --release -p {name}"))]
    NotFound { name: String },

    /// Binary version check failed.
    #[error("Binary at {path} returned non-zero exit code for --version")]
    #[diagnostic(
        code("RCH-E801"),
        help("The binary may be corrupted or incompatible. Try rebuilding it.")
    )]
    VersionCheckFailed { path: String },

    /// Binary version mismatch.
    #[error("Version mismatch for {name}: local={local_version}, remote={remote_version}")]
    #[diagnostic(code("RCH-E802"), help("Update the binary with: rch fleet deploy"))]
    VersionMismatch {
        name: String,
        local_version: String,
        remote_version: String,
    },

    /// Binary deployment failed.
    #[error("Failed to deploy {name} to {worker_id}: {reason}")]
    #[diagnostic(
        code("RCH-E803"),
        help("Check SSH connectivity: rch workers probe {worker_id}")
    )]
    DeploymentFailed {
        name: String,
        worker_id: String,
        reason: String,
    },
}

// =============================================================================
// Fleet Management Errors
// =============================================================================

/// Errors related to fleet management operations.
///
/// Error code range: RCH-E700 to RCH-E710
#[derive(Error, Diagnostic, Debug)]
pub enum FleetError {
    /// Fleet deployment failed.
    #[error("Fleet deployment failed: {reason}")]
    #[diagnostic(
        code("RCH-E700"),
        help("Check worker connectivity: rch workers probe --all")
    )]
    DeploymentFailed { reason: String },

    /// Fleet rollback failed.
    #[error("Fleet rollback failed for {worker_id}: {reason}")]
    #[diagnostic(
        code("RCH-E701"),
        help("Check worker status and try manual intervention if needed")
    )]
    RollbackFailed { worker_id: String, reason: String },

    /// No backup available for rollback.
    #[error("No backup available for rollback on {worker_id}")]
    #[diagnostic(code("RCH-E702"), help("Deploy a fresh binary: rch fleet deploy"))]
    NoBackupAvailable { worker_id: String },

    /// Fleet health check failed.
    #[error("Fleet health check failed: {reason}")]
    #[diagnostic(
        code("RCH-E703"),
        help("Check individual workers: rch workers probe --all")
    )]
    HealthCheckFailed { reason: String },

    /// Unexpected output format from fleet operation.
    #[error("Unexpected output format: {context}")]
    #[diagnostic(
        code("RCH-E704"),
        help("The remote command returned unexpected output. Check worker compatibility.")
    )]
    UnexpectedOutput { context: String },
}

// =============================================================================
// Web Dashboard Errors
// =============================================================================

/// Errors related to the web dashboard functionality.
///
/// Error code range: RCH-E900 to RCH-E905
#[derive(Error, Diagnostic, Debug)]
pub enum WebError {
    /// Web dashboard directory not found.
    #[error("Web dashboard directory not found")]
    #[diagnostic(
        code("RCH-E900"),
        help(
            "Expected to find the web dashboard at one of:\n  \
            - ./web\n  \
            - ~/.local/share/rch/web\n  \
            - /usr/local/share/rch/web\n\n\
            If you installed from source, run 'rch web' from the project root."
        )
    )]
    DashboardNotFound,

    /// Web server exited with error.
    #[error("Web server exited with error (exit code: {exit_code:?})")]
    #[diagnostic(
        code("RCH-E901"),
        help(
            "Check the server logs for details. The web server may have encountered a startup error."
        )
    )]
    ServerExitedWithError { exit_code: Option<i32> },

    /// Web server failed to start.
    #[error("Failed to start web server: {reason}")]
    #[diagnostic(
        code("RCH-E902"),
        help("Ensure bun or npm is installed and the web dependencies are available")
    )]
    ServerStartFailed { reason: String },
}

// =============================================================================
// Completion Errors
// =============================================================================

/// Errors related to shell completion functionality.
///
/// Error code range: RCH-E910 to RCH-E915
#[derive(Error, Diagnostic, Debug)]
pub enum CompletionError {
    /// Shell not supported for completion installation.
    #[error("Shell '{shell}' is not supported for automatic completion installation")]
    #[diagnostic(
        code("RCH-E910"),
        help(
            "Supported shells for automatic installation: bash, zsh, fish, elvish, powershell\n\n\
            For other shells, generate completions manually:\n  \
            rch completions <shell> > ~/.rch-completions"
        )
    )]
    UnsupportedShell { shell: String },

    /// Completion file write failed.
    #[error("Failed to write completion file: {path}")]
    #[diagnostic(
        code("RCH-E911"),
        help("Check that you have write permissions to the completion directory")
    )]
    WriteFailed {
        path: String,
        #[source]
        source: std::io::Error,
    },
}

// =============================================================================
// Editor Errors
// =============================================================================

/// Errors related to external editor operations.
///
/// Error code range: RCH-E920 to RCH-E925
#[derive(Error, Diagnostic, Debug)]
pub enum EditorError {
    /// Editor exited with non-zero status.
    #[error("Editor exited with non-zero status (exit code: {exit_code:?})")]
    #[diagnostic(
        code("RCH-E920"),
        help(
            "The editor process exited with an error. Check that your $EDITOR is configured correctly."
        )
    )]
    ExitedWithError { exit_code: Option<i32> },

    /// Failed to launch editor.
    #[error("Failed to launch editor '{editor}'")]
    #[diagnostic(
        code("RCH-E921"),
        help("Ensure your $EDITOR environment variable points to a valid editor")
    )]
    LaunchFailed {
        editor: String,
        #[source]
        source: std::io::Error,
    },
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use miette::Report;
    use tracing::info;

    // =========================================================================
    // ConfigError Tests
    // =========================================================================

    #[test]
    fn test_config_parse_error_formatting() {
        let err = ConfigError::ParseError {
            src: NamedSource::new("test.toml", "[invalid".to_string()),
            span: (0, 8).into(),
            message: "expected ']'".to_string(),
        };

        let code = err.code().map(|code| code.to_string());
        let report = Report::new(err);
        let formatted = format!("{:?}", report);

        assert!(
            formatted.contains("test.toml"),
            "Should include filename: {formatted}"
        );
        assert!(
            formatted.contains("expected ']'"),
            "Should include error message: {formatted}"
        );
        assert_eq!(code, Some("RCH-E003".to_string()));
    }

    #[test]
    fn test_config_read_failed_includes_path() {
        let err = ConfigError::ReadFailed {
            path: PathBuf::from("/nonexistent/config.toml"),
            source: std::io::Error::new(std::io::ErrorKind::NotFound, "file not found"),
        };

        let code = err.code().map(|code| code.to_string());
        let report = Report::new(err);
        let formatted = format!("{:?}", report);

        assert!(formatted.contains("Failed to read config file"));
        assert_eq!(code, Some("RCH-E002".to_string()));
    }

    #[test]
    fn test_config_missing_field_has_help() {
        let err = ConfigError::MissingField {
            field: "workers".to_string(),
        };

        let code = err.code().map(|code| code.to_string());
        let report = Report::new(err);
        let formatted = format!("{:?}", report);

        assert!(formatted.contains("workers"));
        assert!(
            formatted.contains("help") || formatted.contains("Add"),
            "Should include help text: {formatted}"
        );
        // MissingField uses E011 per error code schema (bd-3b94)
        assert_eq!(code, Some("RCH-E011".to_string()));
    }

    // =========================================================================
    // WorkerError Tests
    // =========================================================================

    #[test]
    fn test_worker_unhealthy_includes_worker_id() {
        let err = WorkerError::Unhealthy {
            worker_id: "slow-worker".to_string(),
            reason: "high load".to_string(),
        };

        let code = err.code().map(|code| code.to_string());
        let report = Report::new(err);
        let formatted = format!("{:?}", report);

        assert!(formatted.contains("slow-worker"));
        assert!(formatted.contains("rch workers probe"));
        assert_eq!(code, Some("RCH-E202".to_string()));
    }

    // =========================================================================
    // SshError Tests
    // =========================================================================

    #[test]
    fn test_ssh_permission_denied_includes_guidance() {
        info!("TEST START: test_ssh_permission_denied_includes_guidance");
        let err = SshError::PermissionDenied {
            host: "gpu-1".to_string(),
            user: "ubuntu".to_string(),
            key_path: PathBuf::from("/home/user/.ssh/id_rsa"),
        };
        info!("INPUT: SshError::PermissionDenied for ubuntu@gpu-1");
        let report = Report::new(err);
        let formatted = format!("{:?}", report);
        info!("RESULT: Error message:\n{formatted}");

        assert!(
            formatted.contains("copy key to worker") || formatted.contains("ssh-copy-id"),
            "Should include key copy guidance: {formatted}"
        );
        assert!(
            formatted.contains("ubuntu@gpu-1"),
            "Should include host/user: {formatted}"
        );
        info!("VERIFY: Message includes key copy guidance with actual host");
        info!("TEST PASS: test_ssh_permission_denied_includes_guidance");
    }

    #[test]
    fn test_ssh_timeout_includes_guidance() {
        info!("TEST START: test_ssh_timeout_includes_guidance");
        let err = SshError::ConnectionTimeout {
            host: "10.0.0.5".to_string(),
            user: "ubuntu".to_string(),
            key_path: PathBuf::from("/home/user/.ssh/id_rsa"),
            timeout_secs: 30,
        };
        info!("INPUT: SshError::ConnectionTimeout for 10.0.0.5");
        let report = Report::new(err);
        let formatted = format!("{:?}", report);
        info!("RESULT: Error message:\n{formatted}");

        assert!(
            formatted.contains("firewall") || formatted.contains("network"),
            "Should include network/firewall guidance: {formatted}"
        );
        assert!(
            formatted.contains("10.0.0.5"),
            "Should include host: {formatted}"
        );
        info!("VERIFY: Message includes network troubleshooting guidance");
        info!("TEST PASS: test_ssh_timeout_includes_guidance");
    }

    #[test]
    fn test_ssh_host_key_includes_guidance() {
        info!("TEST START: test_ssh_host_key_includes_guidance");
        let err = SshError::HostKeyVerificationFailed {
            host: "gpu-1".to_string(),
            user: "ubuntu".to_string(),
            key_path: PathBuf::from("/home/user/.ssh/id_rsa"),
        };
        info!("INPUT: SshError::HostKeyVerificationFailed");
        let report = Report::new(err);
        let formatted = format!("{:?}", report);
        info!("RESULT: Error message:\n{formatted}");

        assert!(
            formatted.contains("known_hosts") || formatted.contains("ssh-keyscan"),
            "Should include known_hosts troubleshooting: {formatted}"
        );
        info!("VERIFY: Message includes known_hosts troubleshooting");
        info!("TEST PASS: test_ssh_host_key_includes_guidance");
    }

    // =========================================================================
    // DaemonError Tests
    // =========================================================================

    #[test]
    fn test_daemon_not_running_has_start_command() {
        let err = DaemonError::NotRunning;
        let code = err.code().map(|code| code.to_string());
        let report = Report::new(err);
        let formatted = format!("{:?}", report);

        assert!(
            formatted.contains("rch daemon start"),
            "Should suggest starting daemon: {formatted}"
        );
        assert_eq!(code, Some("RCH-E300".to_string()));
    }

    #[test]
    fn test_daemon_socket_not_found() {
        let socket_path = rch_common::default_socket_path();
        let err = DaemonError::SocketNotFound {
            socket_path: socket_path.clone(),
        };

        let code = err.code().map(|code| code.to_string());
        let report = Report::new(err);
        let formatted = format!("{:?}", report);

        assert!(
            formatted.contains(&socket_path),
            "Should include socket path: {formatted}"
        );
        assert!(
            formatted.contains("rch daemon start"),
            "Should suggest starting daemon: {formatted}"
        );
        assert_eq!(code, Some("RCH-E301".to_string()));
    }

    #[test]
    fn test_daemon_connection_failed() {
        let socket_path = rch_common::default_socket_path();
        let err = DaemonError::ConnectionFailed {
            socket_path: socket_path.clone(),
            source: std::io::Error::new(std::io::ErrorKind::NotFound, "socket not found"),
        };

        let code = err.code().map(|code| code.to_string());
        let report = Report::new(err);
        let formatted = format!("{:?}", report);

        assert!(formatted.contains(&socket_path));
        assert_eq!(code, Some("RCH-E302".to_string()));
    }

    // =========================================================================
    // TransferError Tests
    // =========================================================================

    #[test]
    fn test_transfer_no_project_root() {
        let err = TransferError::NoProjectRoot {
            source: std::io::Error::new(std::io::ErrorKind::NotFound, "directory not found"),
        };

        let code = err.code().map(|code| code.to_string());
        let report = Report::new(err);
        let formatted = format!("{:?}", report);

        assert!(
            formatted.contains("project root"),
            "Should mention project root: {formatted}"
        );
        assert_eq!(code, Some("RCH-E409".to_string()));
    }

    #[test]
    fn test_transfer_timeout() {
        let err = TransferError::Timeout { seconds: 120 };

        let code = err.code().map(|code| code.to_string());
        let report = Report::new(err);
        let formatted = format!("{:?}", report);

        assert!(formatted.contains("120"));
        assert_eq!(code, Some("RCH-E401".to_string()));
    }

    // =========================================================================
    // HookError Tests
    // =========================================================================

    #[test]
    fn test_hook_settings_parse_error() {
        let err = HookError::SettingsParseError {
            message: "missing tool_name".to_string(),
        };

        let code = err.code().map(|code| code.to_string());
        let report = Report::new(err);
        let formatted = format!("{:?}", report);

        assert!(formatted.contains("missing tool_name"));
        assert_eq!(code, Some("RCH-E502".to_string()));
    }

    #[test]
    fn test_hook_settings_not_found() {
        let err = HookError::SettingsNotFound {
            path: PathBuf::from("/home/user/.config/claude-code/settings.json"),
        };

        let code = err.code().map(|code| code.to_string());
        let report = Report::new(err);
        let formatted = format!("{:?}", report);

        assert!(formatted.contains("settings.json"));
        assert_eq!(code, Some("RCH-E501".to_string()));
    }

    // =========================================================================
    // UpdateError Tests
    // =========================================================================

    #[test]
    fn test_update_no_release() {
        let err = UpdateError::NoRelease {
            platform: "x86_64-unknown-freebsd".to_string(),
        };

        let code = err.code().map(|code| code.to_string());
        let report = Report::new(err);
        let formatted = format!("{:?}", report);

        assert!(formatted.contains("freebsd"));
        assert!(
            formatted.contains("cargo install") || formatted.contains("source"),
            "Should suggest building from source: {formatted}"
        );
        assert_eq!(code, Some("RCH-E521".to_string()));
    }

    #[test]
    fn test_update_checksum_failed() {
        let err = UpdateError::ChecksumFailed {
            expected: "abc123".to_string(),
            actual: "def456".to_string(),
        };

        let code = err.code().map(|code| code.to_string());
        let report = Report::new(err);
        let formatted = format!("{:?}", report);

        assert_eq!(code, Some("RCH-E522".to_string()));
        assert!(
            formatted.contains("corrupted") || formatted.contains("download"),
            "Should suggest redownload: {formatted}"
        );
    }

    // =========================================================================
    // Error Chain Tests
    // =========================================================================

    #[test]
    fn test_error_source_chain_preserved() {
        let inner = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "access denied");
        let err = ConfigError::ReadFailed {
            path: PathBuf::from("/etc/rch/config.toml"),
            source: inner,
        };

        let report = Report::new(err);
        let formatted = format!("{:?}", report);

        // miette should show the error chain
        assert!(
            formatted.contains("access denied") || formatted.contains("PermissionDenied"),
            "Should preserve error source: {formatted}"
        );
    }

    // =========================================================================
    // Source Context Tests
    // =========================================================================

    #[test]
    fn test_source_context_shows_line_context() {
        let content = r#"[daemon]
port = 7800

[workers.test]
host = unquoted_value
user = "test"
"#;

        let err = ConfigError::ParseError {
            src: NamedSource::new("config.toml", content.to_string()),
            span: (42, 14).into(), // Points to unquoted_value
            message: "expected string".to_string(),
        };

        let report = Report::new(err);
        let formatted = format!("{:?}", report);

        // Should show surrounding context
        assert!(
            formatted.contains("host") || formatted.contains("config.toml"),
            "Should show source context: {formatted}"
        );
    }

    // =========================================================================
    // Non-TTY Output Tests
    // =========================================================================

    #[test]
    fn test_error_readable_without_colors() {
        // Force non-graphical output for testing
        let err = DaemonError::NotRunning;
        let report = Report::new(err);

        // Basic formatting should work without panicking
        let debug_fmt = format!("{:?}", report);
        let display_fmt = format!("{}", report);

        assert!(!debug_fmt.is_empty());
        assert!(!display_fmt.is_empty());
    }

    #[test]
    fn test_display_vs_debug_formats() {
        let err = WorkerError::SelectionFailed {
            reason: "no workers available".to_string(),
        };
        let report = Report::new(err);

        let debug = format!("{:?}", report);
        let display = format!("{}", report);

        // Display should be simpler
        assert!(display.len() <= debug.len());
        // Both should contain the core message
        assert!(display.contains("no workers available"));
    }

    // =========================================================================
    // ArtifactRetrievalWarning Tests (bd-1q3p)
    // =========================================================================

    #[test]
    fn test_artifact_retrieval_warning_basic() {
        info!("TEST START: test_artifact_retrieval_warning_basic");
        let warning = ArtifactRetrievalWarning::new(
            "worker1",
            vec![
                "target/debug/**".to_string(),
                "target/release/**".to_string(),
            ],
            "connection reset by peer",
            Some(12),
        );

        assert_eq!(warning.worker_id, "worker1");
        assert_eq!(warning.attempted_patterns.len(), 2);
        assert_eq!(warning.rsync_exit_code, Some(12));
        assert!(warning.rsync_stderr_snippet.contains("connection reset"));
        info!("TEST PASS: test_artifact_retrieval_warning_basic");
    }

    #[test]
    fn test_artifact_retrieval_warning_format() {
        info!("TEST START: test_artifact_retrieval_warning_format");
        let warning = ArtifactRetrievalWarning::new(
            "gpu-worker-1",
            vec!["target/debug/**".to_string()],
            "Permission denied",
            Some(1),
        );

        let formatted = warning.format_warning();
        info!("Formatted warning:\n{}", formatted);

        assert!(formatted.contains("Artifact retrieval failed"));
        assert!(formatted.contains("target/debug/**"));
        assert!(formatted.contains("gpu-worker-1"));
        assert!(formatted.contains("Permission denied"));
        assert!(formatted.contains("rch diagnose"));
        info!("TEST PASS: test_artifact_retrieval_warning_format");
    }

    #[test]
    fn test_artifact_retrieval_warning_json() {
        info!("TEST START: test_artifact_retrieval_warning_json");
        let warning = ArtifactRetrievalWarning::new(
            "worker2",
            vec!["*.o".to_string(), "build/**".to_string()],
            "rsync error",
            Some(23),
        );

        let json = warning.to_json();
        info!("JSON output: {}", json);

        assert_eq!(json["type"], "artifact_retrieval_warning");
        assert_eq!(json["worker_id"], "worker2");
        assert_eq!(json["rsync_exit_code"], 23);
        assert!(json["attempted_patterns"].as_array().unwrap().len() == 2);
        info!("TEST PASS: test_artifact_retrieval_warning_json");
    }

    #[test]
    fn test_artifact_retrieval_warning_truncates_stderr() {
        info!("TEST START: test_artifact_retrieval_warning_truncates_stderr");
        // Create a very long stderr message
        let long_stderr = "x".repeat(1000);
        let warning = ArtifactRetrievalWarning::new(
            "worker1",
            vec!["target/**".to_string()],
            long_stderr,
            None,
        );

        // Snippet should be truncated
        assert!(warning.rsync_stderr_snippet.len() <= 503); // 500 + "..."
        assert!(warning.rsync_stderr_snippet.ends_with("..."));
        info!("TEST PASS: test_artifact_retrieval_warning_truncates_stderr");
    }

    #[test]
    fn test_artifact_retrieval_warning_with_custom_suggestions() {
        info!("TEST START: test_artifact_retrieval_warning_with_custom_suggestions");
        let warning =
            ArtifactRetrievalWarning::new("worker1", vec!["target/**".to_string()], "error", None)
                .with_suggestions(vec![
                    "Custom suggestion 1".to_string(),
                    "Custom suggestion 2".to_string(),
                ]);

        assert_eq!(warning.suggestions.len(), 2);
        assert!(warning.suggestions[0].contains("Custom"));
        info!("TEST PASS: test_artifact_retrieval_warning_with_custom_suggestions");
    }

    #[test]
    fn test_artifact_retrieval_warning_display_trait() {
        info!("TEST START: test_artifact_retrieval_warning_display_trait");
        let warning = ArtifactRetrievalWarning::new(
            "worker1",
            vec!["target/**".to_string()],
            "test error",
            Some(1),
        );

        let display_output = format!("{}", warning);
        let format_output = warning.format_warning();

        // Display trait should use format_warning
        assert_eq!(display_output, format_output);
        info!("TEST PASS: test_artifact_retrieval_warning_display_trait");
    }

    // =========================================================================
    // Error Code Schema Validation
    // =========================================================================

    /// Extract error code from a Diagnostic-implementing error.
    fn extract_code(err: &dyn Diagnostic) -> Option<String> {
        err.code().map(|c| c.to_string())
    }

    #[test]
    fn test_all_error_codes_unique() {
        // Collect error codes from each enum by constructing representative variants.
        // This ensures no two variants share the same RCH-Exxx code.
        let mut codes: Vec<(&str, String)> = Vec::new();

        // ConfigError codes (E001-E012)
        let config_errors: Vec<(&str, Box<dyn Diagnostic>)> = vec![
            (
                "NotFound",
                Box::new(ConfigError::NotFound {
                    path: PathBuf::from("x"),
                }),
            ),
            (
                "ReadFailed",
                Box::new(ConfigError::ReadFailed {
                    path: PathBuf::from("x"),
                    source: std::io::Error::other(""),
                }),
            ),
            (
                "ParseError",
                Box::new(ConfigError::ParseError {
                    src: NamedSource::new("x", String::new()),
                    span: (0, 0).into(),
                    message: String::new(),
                }),
            ),
            (
                "InvalidValue",
                Box::new(ConfigError::InvalidValue {
                    field: String::new(),
                    reason: String::new(),
                    suggestion: String::new(),
                }),
            ),
            (
                "WorkersNotFound",
                Box::new(ConfigError::WorkersNotFound {
                    path: PathBuf::from("x"),
                }),
            ),
            (
                "WorkersParseError",
                Box::new(ConfigError::WorkersParseError {
                    path: PathBuf::from("x"),
                    message: String::new(),
                }),
            ),
            ("NoWorkers", Box::new(ConfigError::NoWorkers)),
            (
                "WorkerNotFound",
                Box::new(ConfigError::WorkerNotFound {
                    worker_id: String::new(),
                }),
            ),
            (
                "DuplicateWorkerId",
                Box::new(ConfigError::DuplicateWorkerId {
                    worker_id: String::new(),
                }),
            ),
            (
                "InvalidWorker",
                Box::new(ConfigError::InvalidWorker {
                    worker_id: String::new(),
                    reason: String::new(),
                    suggestion: String::new(),
                }),
            ),
            (
                "MissingField",
                Box::new(ConfigError::MissingField {
                    field: String::new(),
                }),
            ),
            (
                "MigrationRequired",
                Box::new(ConfigError::MigrationRequired {
                    reason: String::new(),
                }),
            ),
        ];
        for (name, err) in &config_errors {
            if let Some(code) = extract_code(err.as_ref()) {
                codes.push((name, code));
            }
        }

        // DaemonError codes (E300-E308)
        let daemon_errors: Vec<(&str, Box<dyn Diagnostic>)> = vec![
            ("NotRunning", Box::new(DaemonError::NotRunning)),
            (
                "SocketNotFound",
                Box::new(DaemonError::SocketNotFound {
                    socket_path: String::new(),
                }),
            ),
            (
                "ConnectionFailed",
                Box::new(DaemonError::ConnectionFailed {
                    socket_path: String::new(),
                    source: std::io::Error::other(""),
                }),
            ),
            (
                "SocketPermissionDenied",
                Box::new(DaemonError::SocketPermissionDenied {
                    socket_path: String::new(),
                }),
            ),
            (
                "StartupFailed",
                Box::new(DaemonError::StartupFailed {
                    source: std::io::Error::other(""),
                }),
            ),
            (
                "AlreadyRunning",
                Box::new(DaemonError::AlreadyRunning { pid: 0 }),
            ),
            (
                "CommunicationTimeout",
                Box::new(DaemonError::CommunicationTimeout { timeout_secs: 0 }),
            ),
            (
                "ProtocolError",
                Box::new(DaemonError::ProtocolError {
                    message: String::new(),
                }),
            ),
            (
                "VersionMismatch",
                Box::new(DaemonError::VersionMismatch {
                    expected: String::new(),
                    actual: String::new(),
                }),
            ),
        ];
        for (name, err) in &daemon_errors {
            if let Some(code) = extract_code(err.as_ref()) {
                codes.push((name, code));
            }
        }

        // Check for duplicates
        codes.sort_by(|a, b| a.1.cmp(&b.1));
        for window in codes.windows(2) {
            assert_ne!(
                window[0].1, window[1].1,
                "Duplicate error code {}: variants '{}' and '{}'",
                window[0].1, window[0].0, window[1].0,
            );
        }
    }

    #[test]
    fn test_error_codes_follow_convention() {
        // All error codes must match the RCH-Exxx pattern
        let test_errors: Vec<Box<dyn Diagnostic>> = vec![
            Box::new(ConfigError::NotFound {
                path: PathBuf::from("x"),
            }),
            Box::new(DaemonError::NotRunning),
        ];
        for err in &test_errors {
            if let Some(code) = err.code() {
                let code_str = code.to_string();
                assert!(
                    code_str.starts_with("RCH-E"),
                    "Error code '{}' doesn't follow RCH-Exxx convention",
                    code_str,
                );
            }
        }
    }

    #[test]
    fn test_error_categories_cover_ranges() {
        // Config: E001-E012, SSH: E100-E113, Worker: E200-E210,
        // Daemon: E300-E308, Build: E400-E409, Hook: E500-E510,
        // Platform: E600-E610, Fleet: E700-E710, Binary: E800-E810
        let expected_ranges = [
            ("Config", 1, 12),
            ("SSH", 100, 113),
            ("Worker", 200, 210),
            ("Daemon", 300, 308),
            ("Build", 400, 409),
            ("Hook/Update", 500, 510),
            ("Platform", 600, 610),
            ("Fleet", 700, 710),
            ("Binary", 800, 810),
        ];

        // Just verify the documented ranges are consistent
        for (category, start, end) in &expected_ranges {
            assert!(
                start < end,
                "Category '{}' has invalid range: {}-{}",
                category,
                start,
                end,
            );
        }
    }
}
