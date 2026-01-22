//! Error Catalog for Remote Compilation Helper
//!
//! This module defines a comprehensive error catalog with unique error codes,
//! categorized by subsystem. Each error includes:
//! - A unique code (RCH-E001 through RCH-E999)
//! - A human-readable message template
//! - Remediation steps
//! - Documentation links where applicable
//!
//! # Error Code Ranges
//!
//! | Range      | Category    | Description                          |
//! |------------|-------------|--------------------------------------|
//! | E001-E099  | Config      | Configuration and setup errors       |
//! | E100-E199  | Network     | Network and SSH connectivity         |
//! | E200-E299  | Worker      | Worker selection and management      |
//! | E300-E399  | Build       | Compilation and build errors         |
//! | E400-E499  | Transfer    | File transfer and sync errors        |
//! | E500-E599  | Internal    | Internal/unexpected errors           |
//!
//! # Example
//!
//! ```rust
//! use rch_common::errors::catalog::{ErrorCode, ErrorEntry};
//!
//! let error = ErrorCode::ConfigNotFound;
//! let entry = error.entry();
//!
//! println!("Error {}: {}", entry.code, entry.message);
//! for step in entry.remediation {
//!     println!("  - {}", step);
//! }
//! ```

use serde::{Deserialize, Serialize};
use std::fmt;

/// Error code enumeration covering all RCH error scenarios.
///
/// Each variant maps to a unique error code in the RCH-Exxx format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[non_exhaustive]
pub enum ErrorCode {
    // =========================================================================
    // Config Errors (E001-E099)
    // =========================================================================
    /// Configuration file not found
    ConfigNotFound,
    /// Configuration file could not be read
    ConfigReadError,
    /// Configuration file contains invalid TOML syntax
    ConfigParseError,
    /// Configuration contains invalid values
    ConfigValidationError,
    /// Environment variable has invalid value
    ConfigEnvError,
    /// Profile not found in configuration
    ConfigProfileNotFound,
    /// No workers configured
    ConfigNoWorkers,
    /// Worker configuration is invalid
    ConfigInvalidWorker,
    /// SSH key path is invalid or inaccessible
    ConfigSshKeyError,
    /// Socket path is invalid
    ConfigSocketPathError,

    // =========================================================================
    // Network Errors (E100-E199)
    // =========================================================================
    /// SSH connection failed
    SshConnectionFailed,
    /// SSH authentication failed
    SshAuthFailed,
    /// SSH key not found or invalid format
    SshKeyError,
    /// SSH known hosts verification failed
    SshHostKeyError,
    /// SSH command execution timed out
    SshTimeout,
    /// SSH session terminated unexpectedly
    SshSessionDropped,
    /// DNS resolution failed for worker host
    NetworkDnsError,
    /// Network unreachable
    NetworkUnreachable,
    /// Connection refused by remote host
    NetworkConnectionRefused,
    /// TCP connection timed out
    NetworkTimeout,

    // =========================================================================
    // Worker Errors (E200-E299)
    // =========================================================================
    /// No workers available for selection
    WorkerNoneAvailable,
    /// All workers are unhealthy
    WorkerAllUnhealthy,
    /// Worker failed health check
    WorkerHealthCheckFailed,
    /// Worker self-test failed
    WorkerSelfTestFailed,
    /// Worker is at capacity
    WorkerAtCapacity,
    /// Worker missing required toolchain
    WorkerMissingToolchain,
    /// Worker state is inconsistent
    WorkerStateError,
    /// Worker circuit breaker is open
    WorkerCircuitOpen,
    /// Worker selection strategy failed
    WorkerSelectionFailed,
    /// Worker load query failed
    WorkerLoadQueryFailed,

    // =========================================================================
    // Build Errors (E300-E399)
    // =========================================================================
    /// Remote compilation failed
    BuildCompilationFailed,
    /// Build command not recognized
    BuildUnknownCommand,
    /// Build process was killed by signal
    BuildKilledBySignal,
    /// Build timed out
    BuildTimeout,
    /// Build output capture failed
    BuildOutputError,
    /// Remote working directory error
    BuildWorkdirError,
    /// Toolchain wrapper failed
    BuildToolchainError,
    /// Build environment setup failed
    BuildEnvError,
    /// Incremental build state corrupted
    BuildIncrementalError,
    /// Build artifact not found
    BuildArtifactMissing,

    // =========================================================================
    // Transfer Errors (E400-E499)
    // =========================================================================
    /// Rsync transfer failed
    TransferRsyncFailed,
    /// File sync timed out
    TransferTimeout,
    /// Source files not found
    TransferSourceMissing,
    /// Destination path error
    TransferDestError,
    /// Insufficient disk space on worker
    TransferDiskFull,
    /// Permission denied during transfer
    TransferPermissionDenied,
    /// Transfer checksum mismatch
    TransferChecksumError,
    /// Binary download failed
    TransferBinaryFailed,
    /// Partial transfer detected
    TransferIncomplete,
    /// Transfer protocol error
    TransferProtocolError,

    // =========================================================================
    // Internal Errors (E500-E599)
    // =========================================================================
    /// Daemon socket connection failed
    InternalDaemonSocket,
    /// Daemon protocol error
    InternalDaemonProtocol,
    /// Daemon not running
    InternalDaemonNotRunning,
    /// Inter-process communication error
    InternalIpcError,
    /// Unexpected internal state
    InternalStateError,
    /// Serialization/deserialization error
    InternalSerdeError,
    /// Hook execution failed
    InternalHookError,
    /// Metrics collection error
    InternalMetricsError,
    /// Logging system error
    InternalLoggingError,
    /// Update check failed
    InternalUpdateError,
}

impl ErrorCode {
    /// Returns the numeric error code (without prefix).
    #[must_use]
    pub const fn code_number(&self) -> u16 {
        match self {
            // Config (001-099)
            Self::ConfigNotFound => 1,
            Self::ConfigReadError => 2,
            Self::ConfigParseError => 3,
            Self::ConfigValidationError => 4,
            Self::ConfigEnvError => 5,
            Self::ConfigProfileNotFound => 6,
            Self::ConfigNoWorkers => 7,
            Self::ConfigInvalidWorker => 8,
            Self::ConfigSshKeyError => 9,
            Self::ConfigSocketPathError => 10,

            // Network (100-199)
            Self::SshConnectionFailed => 100,
            Self::SshAuthFailed => 101,
            Self::SshKeyError => 102,
            Self::SshHostKeyError => 103,
            Self::SshTimeout => 104,
            Self::SshSessionDropped => 105,
            Self::NetworkDnsError => 106,
            Self::NetworkUnreachable => 107,
            Self::NetworkConnectionRefused => 108,
            Self::NetworkTimeout => 109,

            // Worker (200-299)
            Self::WorkerNoneAvailable => 200,
            Self::WorkerAllUnhealthy => 201,
            Self::WorkerHealthCheckFailed => 202,
            Self::WorkerSelfTestFailed => 203,
            Self::WorkerAtCapacity => 204,
            Self::WorkerMissingToolchain => 205,
            Self::WorkerStateError => 206,
            Self::WorkerCircuitOpen => 207,
            Self::WorkerSelectionFailed => 208,
            Self::WorkerLoadQueryFailed => 209,

            // Build (300-399)
            Self::BuildCompilationFailed => 300,
            Self::BuildUnknownCommand => 301,
            Self::BuildKilledBySignal => 302,
            Self::BuildTimeout => 303,
            Self::BuildOutputError => 304,
            Self::BuildWorkdirError => 305,
            Self::BuildToolchainError => 306,
            Self::BuildEnvError => 307,
            Self::BuildIncrementalError => 308,
            Self::BuildArtifactMissing => 309,

            // Transfer (400-499)
            Self::TransferRsyncFailed => 400,
            Self::TransferTimeout => 401,
            Self::TransferSourceMissing => 402,
            Self::TransferDestError => 403,
            Self::TransferDiskFull => 404,
            Self::TransferPermissionDenied => 405,
            Self::TransferChecksumError => 406,
            Self::TransferBinaryFailed => 407,
            Self::TransferIncomplete => 408,
            Self::TransferProtocolError => 409,

            // Internal (500-599)
            Self::InternalDaemonSocket => 500,
            Self::InternalDaemonProtocol => 501,
            Self::InternalDaemonNotRunning => 502,
            Self::InternalIpcError => 503,
            Self::InternalStateError => 504,
            Self::InternalSerdeError => 505,
            Self::InternalHookError => 506,
            Self::InternalMetricsError => 507,
            Self::InternalLoggingError => 508,
            Self::InternalUpdateError => 509,
        }
    }

    /// Returns the formatted error code string (e.g., "RCH-E001").
    #[must_use]
    pub fn code_string(&self) -> String {
        format!("RCH-E{:03}", self.code_number())
    }

    /// Returns the error category.
    #[must_use]
    pub const fn category(&self) -> ErrorCategory {
        match self.code_number() {
            1..=99 => ErrorCategory::Config,
            100..=199 => ErrorCategory::Network,
            200..=299 => ErrorCategory::Worker,
            300..=399 => ErrorCategory::Build,
            400..=499 => ErrorCategory::Transfer,
            500..=599 => ErrorCategory::Internal,
            _ => ErrorCategory::Internal,
        }
    }

    /// Returns the full error entry with all metadata.
    #[must_use]
    pub fn entry(&self) -> ErrorEntry {
        ErrorEntry {
            code: self.code_string(),
            category: self.category(),
            message: self.message().to_string(),
            remediation: self
                .remediation()
                .iter()
                .map(|s| (*s).to_string())
                .collect(),
            doc_url: self.doc_url().map(String::from),
        }
    }

    /// Returns the error message template.
    #[must_use]
    pub const fn message(&self) -> &'static str {
        match self {
            // Config
            Self::ConfigNotFound => "Configuration file not found",
            Self::ConfigReadError => "Failed to read configuration file",
            Self::ConfigParseError => "Configuration file contains invalid TOML syntax",
            Self::ConfigValidationError => "Configuration contains invalid values",
            Self::ConfigEnvError => "Environment variable has invalid value",
            Self::ConfigProfileNotFound => "Profile not found in configuration",
            Self::ConfigNoWorkers => "No workers are configured",
            Self::ConfigInvalidWorker => "Worker configuration is invalid",
            Self::ConfigSshKeyError => "SSH key path is invalid or inaccessible",
            Self::ConfigSocketPathError => "Socket path is invalid or inaccessible",

            // Network
            Self::SshConnectionFailed => "SSH connection to worker failed",
            Self::SshAuthFailed => "SSH authentication failed",
            Self::SshKeyError => "SSH key not found or has invalid format",
            Self::SshHostKeyError => "SSH host key verification failed",
            Self::SshTimeout => "SSH command execution timed out",
            Self::SshSessionDropped => "SSH session terminated unexpectedly",
            Self::NetworkDnsError => "DNS resolution failed for worker host",
            Self::NetworkUnreachable => "Network is unreachable",
            Self::NetworkConnectionRefused => "Connection refused by remote host",
            Self::NetworkTimeout => "TCP connection timed out",

            // Worker
            Self::WorkerNoneAvailable => "No workers available for selection",
            Self::WorkerAllUnhealthy => "All configured workers are unhealthy",
            Self::WorkerHealthCheckFailed => "Worker failed health check",
            Self::WorkerSelfTestFailed => "Worker self-test failed",
            Self::WorkerAtCapacity => "Worker is at maximum capacity",
            Self::WorkerMissingToolchain => "Worker is missing required toolchain",
            Self::WorkerStateError => "Worker state is inconsistent",
            Self::WorkerCircuitOpen => "Worker circuit breaker is open",
            Self::WorkerSelectionFailed => "Worker selection strategy failed",
            Self::WorkerLoadQueryFailed => "Failed to query worker load",

            // Build
            Self::BuildCompilationFailed => "Remote compilation failed",
            Self::BuildUnknownCommand => "Build command not recognized",
            Self::BuildKilledBySignal => "Build process was killed by signal",
            Self::BuildTimeout => "Build operation timed out",
            Self::BuildOutputError => "Failed to capture build output",
            Self::BuildWorkdirError => "Remote working directory error",
            Self::BuildToolchainError => "Toolchain wrapper failed",
            Self::BuildEnvError => "Build environment setup failed",
            Self::BuildIncrementalError => "Incremental build state is corrupted",
            Self::BuildArtifactMissing => "Build artifact not found",

            // Transfer
            Self::TransferRsyncFailed => "Rsync transfer failed",
            Self::TransferTimeout => "File sync operation timed out",
            Self::TransferSourceMissing => "Source files not found",
            Self::TransferDestError => "Destination path error",
            Self::TransferDiskFull => "Insufficient disk space on worker",
            Self::TransferPermissionDenied => "Permission denied during file transfer",
            Self::TransferChecksumError => "Transfer checksum mismatch",
            Self::TransferBinaryFailed => "Binary download failed",
            Self::TransferIncomplete => "Transfer completed partially",
            Self::TransferProtocolError => "Transfer protocol error",

            // Internal
            Self::InternalDaemonSocket => "Failed to connect to daemon socket",
            Self::InternalDaemonProtocol => "Daemon protocol error",
            Self::InternalDaemonNotRunning => "RCH daemon is not running",
            Self::InternalIpcError => "Inter-process communication error",
            Self::InternalStateError => "Unexpected internal state",
            Self::InternalSerdeError => "Serialization/deserialization error",
            Self::InternalHookError => "Hook execution failed",
            Self::InternalMetricsError => "Metrics collection error",
            Self::InternalLoggingError => "Logging system error",
            Self::InternalUpdateError => "Update check failed",
        }
    }

    /// Returns remediation steps for this error.
    #[must_use]
    pub const fn remediation(&self) -> &'static [&'static str] {
        match self {
            // Config
            Self::ConfigNotFound => &[
                "Run 'rch init' to create a default configuration",
                "Check if ~/.config/rch/config.toml exists",
                "Set RCH_CONFIG environment variable to specify custom path",
            ],
            Self::ConfigReadError => &[
                "Check file permissions on the configuration file",
                "Verify the file is not corrupted",
                "Ensure no other process has locked the file",
            ],
            Self::ConfigParseError => &[
                "Run 'rch config validate' to identify syntax errors",
                "Check TOML syntax at the indicated line",
                "Ensure all strings are properly quoted",
            ],
            Self::ConfigValidationError => &[
                "Run 'rch config validate' for detailed diagnostics",
                "Check that all required fields are present",
                "Verify values are within allowed ranges",
            ],
            Self::ConfigEnvError => &[
                "Check the environment variable value format",
                "Unset the variable to use config file defaults",
                "See 'rch help env' for valid environment variables",
            ],
            Self::ConfigProfileNotFound => &[
                "List available profiles with 'rch config profiles'",
                "Create the profile in your configuration file",
                "Check for typos in the profile name",
            ],
            Self::ConfigNoWorkers => &[
                "Add at least one worker to your configuration",
                "Run 'rch discover' to find available workers",
                "Check the [workers] section in your config",
            ],
            Self::ConfigInvalidWorker => &[
                "Verify worker hostname is correct",
                "Check SSH username and key configuration",
                "Ensure remote_base_dir is a valid path",
            ],
            Self::ConfigSshKeyError => &[
                "Check that the SSH key file exists",
                "Verify file permissions (should be 600)",
                "Ensure the key format is valid (ssh-keygen -y -f KEY)",
            ],
            Self::ConfigSocketPathError => &[
                "Check directory permissions for socket path",
                "Ensure parent directory exists",
                "Try using the default socket path",
            ],

            // Network
            Self::SshConnectionFailed => &[
                "Verify the worker host is reachable: ping <host>",
                "Check that SSH service is running on the worker",
                "Verify firewall allows SSH (port 22)",
                "Try connecting manually: ssh <user>@<host>",
            ],
            Self::SshAuthFailed => &[
                "Verify SSH key is in authorized_keys on the worker",
                "Check SSH key passphrase if applicable",
                "Ensure ssh-agent is running with key loaded",
                "Try: ssh-add -l to list loaded keys",
            ],
            Self::SshKeyError => &[
                "Check that the SSH key file exists at the configured path",
                "Verify key file permissions are 600",
                "Regenerate key if format is corrupted",
            ],
            Self::SshHostKeyError => &[
                "Accept the host key: ssh <user>@<host> (confirm fingerprint)",
                "Check known_hosts for conflicting entries",
                "Update known_hosts_policy in config if appropriate",
            ],
            Self::SshTimeout => &[
                "Check network connectivity to the worker",
                "Increase timeout in configuration",
                "Verify worker is not overloaded",
            ],
            Self::SshSessionDropped => &[
                "Check network stability",
                "Verify worker has not rebooted",
                "Look for keepalive settings in SSH config",
            ],
            Self::NetworkDnsError => &[
                "Verify worker hostname is correct",
                "Check DNS server configuration",
                "Try using IP address instead of hostname",
            ],
            Self::NetworkUnreachable => &[
                "Check network connection on local machine",
                "Verify VPN connection if required",
                "Check routing to worker network",
            ],
            Self::NetworkConnectionRefused => &[
                "Verify SSH service is running on worker",
                "Check if worker firewall allows connections",
                "Ensure correct port is being used",
            ],
            Self::NetworkTimeout => &[
                "Check network latency to worker",
                "Verify worker is responsive",
                "Increase connection timeout in config",
            ],

            // Worker
            Self::WorkerNoneAvailable => &[
                "Configure at least one worker in config.toml",
                "Run 'rch discover' to find available workers",
                "Check that configured workers are enabled",
            ],
            Self::WorkerAllUnhealthy => &[
                "Run 'rch doctor' to diagnose worker issues",
                "Check individual worker connectivity",
                "Review worker health check logs",
            ],
            Self::WorkerHealthCheckFailed => &[
                "Verify SSH connectivity to worker",
                "Check worker disk space and load",
                "Review health check timeout settings",
            ],
            Self::WorkerSelfTestFailed => &[
                "Run 'rch self-test --worker <name>' for details",
                "Verify Rust toolchain on worker",
                "Check worker has required dependencies",
            ],
            Self::WorkerAtCapacity => &[
                "Wait for current builds to complete",
                "Add more workers to distribute load",
                "Increase max_concurrent_builds on worker",
            ],
            Self::WorkerMissingToolchain => &[
                "Install required toolchain on worker",
                "Run 'rustup show' on worker to verify",
                "Update worker toolchain configuration",
            ],
            Self::WorkerStateError => &[
                "Restart the RCH daemon: rchd restart",
                "Check for stale lock files",
                "Review daemon logs for details",
            ],
            Self::WorkerCircuitOpen => &[
                "Wait for circuit breaker reset period",
                "Check worker health manually",
                "Review recent build failures on worker",
            ],
            Self::WorkerSelectionFailed => &[
                "Verify at least one worker is healthy",
                "Check selection strategy configuration",
                "Review worker weights and priorities",
            ],
            Self::WorkerLoadQueryFailed => &[
                "Verify SSH connectivity to worker",
                "Check that load query command works on worker",
                "Review timeout settings for load queries",
            ],

            // Build
            Self::BuildCompilationFailed => &[
                "Review compilation errors in output",
                "Verify code compiles locally first",
                "Check for missing dependencies on worker",
            ],
            Self::BuildUnknownCommand => &[
                "Check that the command is supported",
                "Verify cargo/rustc version compatibility",
                "Review RCH command pattern configuration",
            ],
            Self::BuildKilledBySignal => &[
                "Check worker system logs for OOM killer",
                "Review build memory requirements",
                "Check if build was manually interrupted",
            ],
            Self::BuildTimeout => &[
                "Increase build timeout in configuration",
                "Check for infinite loops or hangs",
                "Verify worker is not overloaded",
            ],
            Self::BuildOutputError => &[
                "Check worker disk space",
                "Verify PTY allocation settings",
                "Review output buffer configuration",
            ],
            Self::BuildWorkdirError => &[
                "Verify remote_base_dir is writable",
                "Check directory permissions on worker",
                "Ensure path does not contain special characters",
            ],
            Self::BuildToolchainError => &[
                "Verify toolchain is installed on worker",
                "Check rustup default toolchain",
                "Review toolchain override settings",
            ],
            Self::BuildEnvError => &[
                "Check environment variable configuration",
                "Verify required environment is set on worker",
                "Review shell initialization on worker",
            ],
            Self::BuildIncrementalError => &[
                "Run 'cargo clean' on remote workspace",
                "Delete incremental compilation cache",
                "Try full rebuild with --release",
            ],
            Self::BuildArtifactMissing => &[
                "Verify build completed successfully",
                "Check artifact path configuration",
                "Review build output for artifact location",
            ],

            // Transfer
            Self::TransferRsyncFailed => &[
                "Verify rsync is installed on both ends",
                "Check SSH connectivity to worker",
                "Review rsync exclude patterns",
            ],
            Self::TransferTimeout => &[
                "Increase transfer timeout in configuration",
                "Check network bandwidth to worker",
                "Consider using incremental sync",
            ],
            Self::TransferSourceMissing => &[
                "Verify source files exist locally",
                "Check file patterns in configuration",
                "Review .rchignore exclusions",
            ],
            Self::TransferDestError => &[
                "Check remote directory permissions",
                "Verify remote_base_dir is valid",
                "Ensure sufficient disk space on worker",
            ],
            Self::TransferDiskFull => &[
                "Clean up old builds on worker",
                "Check disk usage: df -h on worker",
                "Increase disk allocation for worker",
            ],
            Self::TransferPermissionDenied => &[
                "Check file ownership on worker",
                "Verify SSH user has write permissions",
                "Review umask settings",
            ],
            Self::TransferChecksumError => &[
                "Retry the transfer",
                "Check for network issues",
                "Verify file integrity on source",
            ],
            Self::TransferBinaryFailed => &[
                "Check network connectivity",
                "Verify binary URL is accessible",
                "Try manual download to diagnose",
            ],
            Self::TransferIncomplete => &[
                "Retry the transfer operation",
                "Check for network interruptions",
                "Review transfer logs for details",
            ],
            Self::TransferProtocolError => &[
                "Verify rsync version compatibility",
                "Check SSH protocol settings",
                "Review transfer configuration",
            ],

            // Internal
            Self::InternalDaemonSocket => &[
                "Start the daemon: rchd start",
                "Check socket path permissions",
                "Verify no stale socket file exists",
            ],
            Self::InternalDaemonProtocol => &[
                "Restart the daemon: rchd restart",
                "Check for version mismatch between rch and rchd",
                "Review daemon logs for details",
            ],
            Self::InternalDaemonNotRunning => &[
                "Start the daemon: rchd start",
                "Check if daemon crashed: journalctl -u rchd",
                "Verify daemon configuration",
            ],
            Self::InternalIpcError => &[
                "Restart the daemon",
                "Check system message queue limits",
                "Review logs for detailed error",
            ],
            Self::InternalStateError => &[
                "Restart the daemon",
                "Clear any lock files",
                "Report bug if persists",
            ],
            Self::InternalSerdeError => &[
                "Check for corrupted state files",
                "Clear cache and restart",
                "Report bug with reproduction steps",
            ],
            Self::InternalHookError => &[
                "Verify hook script exists and is executable",
                "Check hook script for errors",
                "Review hook timeout settings",
            ],
            Self::InternalMetricsError => &[
                "Check metrics file permissions",
                "Verify disk space for metrics",
                "Review metrics configuration",
            ],
            Self::InternalLoggingError => &[
                "Check log directory permissions",
                "Verify disk space for logs",
                "Review logging configuration",
            ],
            Self::InternalUpdateError => &[
                "Check network connectivity",
                "Verify update server is reachable",
                "Try manual update check",
            ],
        }
    }

    /// Returns documentation URL for this error, if available.
    #[must_use]
    pub const fn doc_url(&self) -> Option<&'static str> {
        match self.category() {
            ErrorCategory::Config => Some("https://rch.dev/docs/config"),
            ErrorCategory::Network => Some("https://rch.dev/docs/ssh"),
            ErrorCategory::Worker => Some("https://rch.dev/docs/workers"),
            ErrorCategory::Build => Some("https://rch.dev/docs/builds"),
            ErrorCategory::Transfer => Some("https://rch.dev/docs/sync"),
            ErrorCategory::Internal => Some("https://rch.dev/docs/troubleshooting"),
        }
    }

    /// Returns all error codes.
    #[must_use]
    pub const fn all() -> &'static [ErrorCode] {
        &[
            // Config
            Self::ConfigNotFound,
            Self::ConfigReadError,
            Self::ConfigParseError,
            Self::ConfigValidationError,
            Self::ConfigEnvError,
            Self::ConfigProfileNotFound,
            Self::ConfigNoWorkers,
            Self::ConfigInvalidWorker,
            Self::ConfigSshKeyError,
            Self::ConfigSocketPathError,
            // Network
            Self::SshConnectionFailed,
            Self::SshAuthFailed,
            Self::SshKeyError,
            Self::SshHostKeyError,
            Self::SshTimeout,
            Self::SshSessionDropped,
            Self::NetworkDnsError,
            Self::NetworkUnreachable,
            Self::NetworkConnectionRefused,
            Self::NetworkTimeout,
            // Worker
            Self::WorkerNoneAvailable,
            Self::WorkerAllUnhealthy,
            Self::WorkerHealthCheckFailed,
            Self::WorkerSelfTestFailed,
            Self::WorkerAtCapacity,
            Self::WorkerMissingToolchain,
            Self::WorkerStateError,
            Self::WorkerCircuitOpen,
            Self::WorkerSelectionFailed,
            Self::WorkerLoadQueryFailed,
            // Build
            Self::BuildCompilationFailed,
            Self::BuildUnknownCommand,
            Self::BuildKilledBySignal,
            Self::BuildTimeout,
            Self::BuildOutputError,
            Self::BuildWorkdirError,
            Self::BuildToolchainError,
            Self::BuildEnvError,
            Self::BuildIncrementalError,
            Self::BuildArtifactMissing,
            // Transfer
            Self::TransferRsyncFailed,
            Self::TransferTimeout,
            Self::TransferSourceMissing,
            Self::TransferDestError,
            Self::TransferDiskFull,
            Self::TransferPermissionDenied,
            Self::TransferChecksumError,
            Self::TransferBinaryFailed,
            Self::TransferIncomplete,
            Self::TransferProtocolError,
            // Internal
            Self::InternalDaemonSocket,
            Self::InternalDaemonProtocol,
            Self::InternalDaemonNotRunning,
            Self::InternalIpcError,
            Self::InternalStateError,
            Self::InternalSerdeError,
            Self::InternalHookError,
            Self::InternalMetricsError,
            Self::InternalLoggingError,
            Self::InternalUpdateError,
        ]
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code_string(), self.message())
    }
}

/// Error category for grouping related errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ErrorCategory {
    /// Configuration and setup errors (E001-E099)
    Config,
    /// Network and SSH connectivity errors (E100-E199)
    Network,
    /// Worker selection and management errors (E200-E299)
    Worker,
    /// Compilation and build errors (E300-E399)
    Build,
    /// File transfer and sync errors (E400-E499)
    Transfer,
    /// Internal/unexpected errors (E500-E599)
    Internal,
}

impl ErrorCategory {
    /// Returns a human-readable name for the category.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Config => "Configuration",
            Self::Network => "Network",
            Self::Worker => "Worker",
            Self::Build => "Build",
            Self::Transfer => "Transfer",
            Self::Internal => "Internal",
        }
    }

    /// Returns a short description of the category.
    #[must_use]
    pub const fn description(&self) -> &'static str {
        match self {
            Self::Config => "Configuration file and environment setup issues",
            Self::Network => "SSH connectivity and network communication issues",
            Self::Worker => "Remote worker selection, health, and management issues",
            Self::Build => "Remote compilation and build process issues",
            Self::Transfer => "File synchronization and transfer issues",
            Self::Internal => "Internal errors that may indicate bugs",
        }
    }
}

impl fmt::Display for ErrorCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Complete error entry with all metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorEntry {
    /// Error code string (e.g., "RCH-E001")
    pub code: String,
    /// Error category
    pub category: ErrorCategory,
    /// Human-readable error message
    pub message: String,
    /// Steps to remediate the error
    pub remediation: Vec<String>,
    /// Documentation URL, if available
    pub doc_url: Option<String>,
}

impl ErrorEntry {
    /// Formats the error for display with full remediation steps.
    #[must_use]
    pub fn format_full(&self) -> String {
        let mut output = format!("[{}] {}\n\n", self.code, self.message);

        if !self.remediation.is_empty() {
            output.push_str("Remediation steps:\n");
            for (i, step) in self.remediation.iter().enumerate() {
                output.push_str(&format!("  {}. {}\n", i + 1, step));
            }
        }

        if let Some(url) = &self.doc_url {
            output.push_str(&format!("\nFor more information: {}\n", url));
        }

        output
    }

    /// Formats the error as a single line.
    #[must_use]
    pub fn format_brief(&self) -> String {
        format!("[{}] {}", self.code, self.message)
    }
}

impl fmt::Display for ErrorEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.format_brief())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_code_numbers_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for code in ErrorCode::all() {
            let num = code.code_number();
            assert!(
                seen.insert(num),
                "Duplicate error code number: {} for {:?}",
                num,
                code
            );
        }
    }

    #[test]
    fn test_error_code_format() {
        assert_eq!(ErrorCode::ConfigNotFound.code_string(), "RCH-E001");
        assert_eq!(ErrorCode::SshConnectionFailed.code_string(), "RCH-E100");
        assert_eq!(ErrorCode::WorkerNoneAvailable.code_string(), "RCH-E200");
        assert_eq!(ErrorCode::BuildCompilationFailed.code_string(), "RCH-E300");
        assert_eq!(ErrorCode::TransferRsyncFailed.code_string(), "RCH-E400");
        assert_eq!(ErrorCode::InternalDaemonSocket.code_string(), "RCH-E500");
    }

    #[test]
    fn test_error_categories() {
        assert_eq!(ErrorCode::ConfigNotFound.category(), ErrorCategory::Config);
        assert_eq!(
            ErrorCode::SshConnectionFailed.category(),
            ErrorCategory::Network
        );
        assert_eq!(
            ErrorCode::WorkerNoneAvailable.category(),
            ErrorCategory::Worker
        );
        assert_eq!(
            ErrorCode::BuildCompilationFailed.category(),
            ErrorCategory::Build
        );
        assert_eq!(
            ErrorCode::TransferRsyncFailed.category(),
            ErrorCategory::Transfer
        );
        assert_eq!(
            ErrorCode::InternalDaemonSocket.category(),
            ErrorCategory::Internal
        );
    }

    #[test]
    fn test_all_errors_have_message() {
        for code in ErrorCode::all() {
            let msg = code.message();
            assert!(!msg.is_empty(), "Error {:?} has empty message", code);
        }
    }

    #[test]
    fn test_all_errors_have_remediation() {
        for code in ErrorCode::all() {
            let steps = code.remediation();
            assert!(
                !steps.is_empty(),
                "Error {:?} has no remediation steps",
                code
            );
        }
    }

    #[test]
    fn test_error_entry_serialization() {
        let entry = ErrorCode::ConfigNotFound.entry();
        let json = serde_json::to_string(&entry).expect("serialization failed");
        assert!(json.contains("RCH-E001"));
        assert!(json.contains("config"));

        let parsed: ErrorEntry = serde_json::from_str(&json).expect("deserialization failed");
        assert_eq!(parsed.code, "RCH-E001");
        assert_eq!(parsed.category, ErrorCategory::Config);
    }

    #[test]
    fn test_error_code_serialization() {
        let code = ErrorCode::SshAuthFailed;
        let json = serde_json::to_string(&code).expect("serialization failed");
        assert_eq!(json, "\"SSH_AUTH_FAILED\"");

        let parsed: ErrorCode = serde_json::from_str(&json).expect("deserialization failed");
        assert_eq!(parsed, ErrorCode::SshAuthFailed);
    }

    #[test]
    fn test_format_full() {
        let entry = ErrorCode::ConfigNotFound.entry();
        let formatted = entry.format_full();

        assert!(formatted.contains("[RCH-E001]"));
        assert!(formatted.contains("Configuration file not found"));
        assert!(formatted.contains("Remediation steps:"));
        assert!(formatted.contains("rch init"));
    }

    #[test]
    fn test_format_brief() {
        let entry = ErrorCode::ConfigNotFound.entry();
        let formatted = entry.format_brief();

        assert_eq!(formatted, "[RCH-E001] Configuration file not found");
    }

    #[test]
    fn test_display_implementations() {
        let code = ErrorCode::ConfigNotFound;
        let display = format!("{}", code);
        assert!(display.contains("RCH-E001"));
        assert!(display.contains("Configuration file not found"));

        let category = ErrorCategory::Config;
        assert_eq!(format!("{}", category), "Configuration");
    }

    #[test]
    fn test_category_ranges() {
        // Verify each category has errors in the correct range
        for code in ErrorCode::all() {
            let num = code.code_number();
            let cat = code.category();
            match cat {
                ErrorCategory::Config => assert!(num < 100, "{:?} should be < 100", code),
                ErrorCategory::Network => {
                    assert!((100..200).contains(&num), "{:?} should be 100-199", code)
                }
                ErrorCategory::Worker => {
                    assert!((200..300).contains(&num), "{:?} should be 200-299", code)
                }
                ErrorCategory::Build => {
                    assert!((300..400).contains(&num), "{:?} should be 300-399", code)
                }
                ErrorCategory::Transfer => {
                    assert!((400..500).contains(&num), "{:?} should be 400-499", code)
                }
                ErrorCategory::Internal => {
                    assert!((500..600).contains(&num), "{:?} should be 500-599", code)
                }
            }
        }
    }
}
