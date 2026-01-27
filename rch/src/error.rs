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
#[allow(unused_assignments)]
#[derive(Error, Diagnostic, Debug)]
pub enum ConfigError {
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

    /// Missing required configuration field.
    #[error("Missing required field: {field}")]
    #[diagnostic(code("RCH-E004"), help("Add the '{field}' field to your config file"))]
    MissingField { field: String },

    /// Invalid configuration value.
    #[error("Invalid value for '{field}': {reason}")]
    #[diagnostic(code("RCH-E004"), help("{suggestion}"))]
    InvalidValue {
        field: String,
        reason: String,
        suggestion: String,
    },

    /// Configuration file not found at expected location.
    #[error("Config file not found: {path}")]
    #[diagnostic(code("RCH-E001"), help("Create a config file with: rch config init"))]
    NotFound { path: PathBuf },

    /// Workers configuration file not found.
    #[error("Workers config not found: {path}")]
    #[diagnostic(
        code("RCH-E001"),
        help(
            "Create a workers config at ~/.config/rch/workers.toml\nExample:\n\n[[workers]]\nid = \"worker1\"\nhost = \"192.168.1.100\"\nuser = \"ubuntu\"\nidentity_file = \"~/.ssh/id_rsa\"\ntotal_slots = 16\n"
        )
    )]
    WorkersNotFound { path: PathBuf },
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
#[derive(Error, Diagnostic, Debug)]
pub enum WorkerError {
    /// SSH connection to worker failed.
    #[error("Connection to worker '{worker_id}' failed")]
    #[diagnostic(
        code("RCH-E100"),
        help("Verify SSH access with:\n  ssh -i {identity_file} {user}@{host}")
    )]
    ConnectionFailed {
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

    /// Worker not found in configuration.
    #[error("Worker '{worker_id}' not found in configuration")]
    #[diagnostic(code("RCH-E008"), help("List available workers: rch workers list"))]
    NotFound { worker_id: String },

    /// No workers are configured.
    #[error("No workers configured")]
    #[diagnostic(
        code("RCH-E007"),
        help("Configure workers in ~/.config/rch/workers.toml")
    )]
    NoneConfigured,

    /// All workers are busy (at capacity).
    #[error("All workers are at capacity")]
    #[diagnostic(
        code("RCH-E204"),
        help("Wait for running jobs to complete or add more workers")
    )]
    AllBusy,

    /// All workers have their circuit breakers open.
    #[error("All worker circuit breakers are open")]
    #[diagnostic(
        code("RCH-E207"),
        help(
            "Workers have experienced repeated failures.\nWait for circuit breakers to reset or check worker health:\n  rch workers probe --all"
        )
    )]
    AllCircuitsOpen,

    /// SSH key file not found.
    #[error("SSH identity file not found: {path}")]
    #[diagnostic(
        code("RCH-E009"),
        help("Verify the identity_file path in your workers.toml")
    )]
    IdentityNotFound { path: PathBuf },

    /// SSH key has wrong permissions.
    #[error("SSH key has insecure permissions: {}", path.display())]
    #[diagnostic(code("RCH-E009"), help("Fix with: chmod 600 <key_path>"))]
    InsecurePermissions { path: PathBuf },
}

// =============================================================================
// SSH Errors
// =============================================================================

/// Errors related to SSH connectivity and authentication.
#[derive(Error, Diagnostic, Debug)]
pub enum SshError {
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
    PermissionDenied {
        host: String,
        user: String,
        key_path: PathBuf,
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

    /// SSH connection timed out.
    #[error("SSH connection to {host} timed out after {timeout_secs}s")]
    #[diagnostic(
        code("RCH-E104"),
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

    /// SSH host key verification failed.
    #[error("SSH host key verification failed for {host}")]
    #[diagnostic(
        code("RCH-E103"),
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

    /// SSH agent is unavailable or has no keys.
    #[error("SSH agent unavailable for key {key_path:?}")]
    #[diagnostic(
        code("RCH-E101"),
        help(
            "SSH Troubleshooting:\n\
  1. Start the SSH agent and add your key:\n\
     eval $(ssh-agent) && ssh-add {key_path:?}\n\n\
  2. Verify agent has keys:\n\
     ssh-add -L\n\n\
  3. Retry with verbose logs:\n\
     ssh -vvv -i {key_path:?} {user}@{host}\n\n\
Run 'rch doctor' for comprehensive SSH diagnostics."
        )
    )]
    AgentUnavailable {
        host: String,
        user: String,
        key_path: PathBuf,
    },

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
}

// =============================================================================
// Daemon Errors
// =============================================================================

/// Errors related to the RCH daemon.
#[derive(Error, Diagnostic, Debug)]
pub enum DaemonError {
    /// Daemon is not running.
    #[error("RCH daemon is not running")]
    #[diagnostic(code("RCH-E502"), help("Start the daemon with: rch daemon start"))]
    NotRunning,

    /// Daemon socket file not found.
    #[error("Daemon socket not found at {socket_path}")]
    #[diagnostic(
        code("RCH-E502"),
        help(
            "The daemon socket file does not exist. This usually means:\n  1. The daemon is not running\n  2. The socket path is misconfigured\n\nStart the daemon: rch daemon start\nOr check config: rch config show | grep socket"
        )
    )]
    SocketNotFound { socket_path: String },

    /// Failed to connect to daemon.
    #[error("Failed to connect to daemon at {socket_path}")]
    #[diagnostic(
        code("RCH-E500"),
        help(
            "The daemon socket exists but connection failed.\n\nCheck daemon status: rch daemon status\nView daemon logs: rch daemon logs\nRestart daemon: rch daemon restart"
        )
    )]
    ConnectionFailed {
        socket_path: String,
        #[source]
        source: std::io::Error,
    },

    /// Daemon port is already in use.
    #[error("Port {port} is already in use")]
    #[diagnostic(
        code("RCH-E504"),
        help("Stop the existing process or use RCH_SOCKET_PATH to specify a different socket")
    )]
    PortInUse { port: u16 },

    /// Daemon startup failed.
    #[error("Daemon startup failed")]
    #[diagnostic(code("RCH-E504"), help("Check the logs for details: rch daemon logs"))]
    StartupFailed {
        #[source]
        source: std::io::Error,
    },

    /// Daemon protocol error.
    #[error("Daemon protocol error: {message}")]
    #[diagnostic(code("RCH-E501"))]
    ProtocolError { message: String },

    /// Daemon returned an unexpected response.
    #[error("Unexpected daemon response: {response}")]
    #[diagnostic(
        code("RCH-E501"),
        help("This may indicate a version mismatch between rch and rchd")
    )]
    UnexpectedResponse { response: String },
}

// =============================================================================
// Transfer Errors
// =============================================================================

/// Errors related to file transfer operations.
#[derive(Error, Diagnostic, Debug)]
pub enum TransferError {
    /// Failed to determine project root.
    #[error("Failed to determine project root directory")]
    #[diagnostic(
        code("RCH-E402"),
        help(
            "Could not get the current working directory.\n\nEnsure you are running from a valid directory:\n  pwd\n  ls -la"
        )
    )]
    NoProjectRoot {
        #[source]
        source: std::io::Error,
    },

    /// rsync command failed.
    #[error("rsync failed with exit code {exit_code:?}")]
    #[diagnostic(
        code("RCH-E400"),
        help(
            "Ensure rsync is installed on both local and remote machines:\n  which rsync\n  ssh worker which rsync"
        )
    )]
    RsyncFailed {
        exit_code: Option<i32>,
        stderr: String,
    },

    /// SSH authentication failed during transfer.
    #[error("SSH authentication failed for {user}@{host}")]
    #[diagnostic(
        code("RCH-E101"),
        help(
            "Verify SSH key permissions (chmod 600) and that the key is added to remote authorized_keys:\n  ssh-copy-id -i {identity_file} {user}@{host}"
        )
    )]
    SshAuthFailed {
        host: String,
        user: String,
        identity_file: String,
    },

    /// Transfer timed out.
    #[error("Transfer timed out after {seconds}s")]
    #[diagnostic(
        code("RCH-E401"),
        help("Consider increasing the transfer timeout or checking network connectivity")
    )]
    Timeout { seconds: u64 },

    /// Failed to create remote directory.
    #[error("Failed to create remote directory: {path}")]
    #[diagnostic(
        code("RCH-E403"),
        help("Check disk space and permissions on the remote worker")
    )]
    MkdirFailed {
        path: String,
        #[source]
        source: std::io::Error,
    },

    /// Artifact retrieval failed.
    #[error("Failed to retrieve build artifacts from {worker_id}")]
    #[diagnostic(
        code("RCH-E309"),
        help("Check that the build completed successfully on the worker")
    )]
    ArtifactFailed {
        worker_id: String,
        #[source]
        source: std::io::Error,
    },

    /// Transfer estimation indicates transfer should be skipped.
    ///
    /// This is not a fatal error - it indicates that the transfer would exceed
    /// configured limits (size, time) and local execution should be used instead.
    #[error("Transfer skipped: {reason}")]
    #[diagnostic(
        code("RCH-W410"),
        help("Adjust transfer limits in config: max_transfer_mb, max_transfer_time_ms")
    )]
    TransferSkipped { reason: String },
}

// =============================================================================
// Hook Errors
// =============================================================================

/// Errors related to the Claude Code hook.
#[derive(Error, Diagnostic, Debug)]
pub enum HookError {
    /// Invalid hook input JSON.
    #[error("Invalid hook input: {message}")]
    #[diagnostic(
        code("RCH-E506"),
        help(
            "This error indicates a problem with the hook protocol.\nExpected JSON with tool_name and tool_input fields."
        )
    )]
    InvalidInput { message: String },

    /// Hook installation failed.
    #[error("Failed to install Claude Code hook")]
    #[diagnostic(
        code("RCH-E506"),
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
        code("RCH-E506"),
        help("Ensure Claude Code is installed and has been run at least once")
    )]
    SettingsNotFound { path: PathBuf },
}

// =============================================================================
// Update Errors
// =============================================================================

/// Errors related to self-update functionality.
#[derive(Error, Diagnostic, Debug)]
pub enum UpdateError {
    /// Failed to fetch release information.
    #[error("Failed to fetch release info from GitHub")]
    #[diagnostic(code("RCH-E509"), help("Check your internet connection and try again"))]
    FetchFailed {
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// No compatible release found.
    #[error("No compatible release found for {platform}")]
    #[diagnostic(
        code("RCH-E509"),
        help(
            "Build from source: cargo install --git https://github.com/Dicklesworthstone/remote_compilation_helper.git"
        )
    )]
    NoRelease { platform: String },

    /// Checksum verification failed.
    #[error("Checksum verification failed for downloaded binary")]
    #[diagnostic(
        code("RCH-E406"),
        help("The download may be corrupted. Try again or download manually from GitHub.")
    )]
    ChecksumFailed { expected: String, actual: String },

    /// Installation failed.
    #[error("Failed to install update")]
    #[diagnostic(
        code("RCH-E509"),
        help("Check that you have write permissions to the installation directory")
    )]
    InstallFailed {
        #[source]
        source: std::io::Error,
    },

    /// Rollback not available.
    #[error("No backup available for rollback")]
    #[diagnostic(
        code("RCH-E509"),
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
        assert_eq!(code, Some("RCH-E004".to_string()));
    }

    // =========================================================================
    // WorkerError Tests
    // =========================================================================

    #[test]
    fn test_worker_connection_failed_includes_remediation() {
        let err = WorkerError::ConnectionFailed {
            worker_id: "gpu-worker".to_string(),
            host: "192.168.1.100".to_string(),
            user: "build".to_string(),
            identity_file: "~/.ssh/id_rsa".to_string(),
            source: std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "refused"),
        };

        let code = err.code().map(|code| code.to_string());
        let report = Report::new(err);
        let formatted = format!("{:?}", report);

        assert!(
            formatted.contains("gpu-worker"),
            "Should include worker id: {formatted}"
        );
        assert!(
            formatted.contains("ssh -i") || formatted.contains("Verify SSH"),
            "Should include SSH verification command: {formatted}"
        );
        assert_eq!(code, Some("RCH-E100".to_string()));
    }

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

    #[test]
    fn test_worker_not_found() {
        let err = WorkerError::NotFound {
            worker_id: "missing".to_string(),
        };

        let report = Report::new(err);
        let formatted = format!("{:?}", report);

        assert!(formatted.contains("missing"));
        assert!(formatted.contains("rch workers list"));
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
            formatted.contains("ssh-copy-id"),
            "Should include ssh-copy-id guidance: {formatted}"
        );
        assert!(
            formatted.contains("ubuntu@gpu-1"),
            "Should include host/user: {formatted}"
        );
        assert!(
            formatted.contains("/home/user/.ssh/id_rsa"),
            "Should include key path: {formatted}"
        );
        info!("VERIFY: Message includes ssh-copy-id command with actual host/path");
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
        assert_eq!(code, Some("RCH-E502".to_string()));
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
        assert_eq!(code, Some("RCH-E502".to_string()));
    }

    #[test]
    fn test_daemon_port_in_use_suggests_alternative() {
        let err = DaemonError::PortInUse { port: 7800 };
        let code = err.code().map(|code| code.to_string());
        let report = Report::new(err);
        let formatted = format!("{:?}", report);

        assert!(formatted.contains("7800"));
        assert!(
            formatted.contains("RCH_SOCKET_PATH") || formatted.contains("socket"),
            "Should suggest alternative: {formatted}"
        );
        assert_eq!(code, Some("RCH-E504".to_string()));
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
        assert_eq!(code, Some("RCH-E500".to_string()));
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
        assert_eq!(code, Some("RCH-E402".to_string()));
    }

    #[test]
    fn test_rsync_failed_includes_exit_code() {
        let err = TransferError::RsyncFailed {
            exit_code: Some(12),
            stderr: "connection unexpectedly closed".to_string(),
        };

        let code = err.code().map(|code| code.to_string());
        let report = Report::new(err);
        let formatted = format!("{:?}", report);

        assert!(formatted.contains("rsync"));
        assert_eq!(code, Some("RCH-E400".to_string()));
    }

    #[test]
    fn test_ssh_auth_failed_includes_key_hint() {
        let err = TransferError::SshAuthFailed {
            host: "example.com".to_string(),
            user: "deploy".to_string(),
            identity_file: "~/.ssh/deploy_key".to_string(),
        };

        let code = err.code().map(|code| code.to_string());
        let report = Report::new(err);
        let formatted = format!("{:?}", report);

        assert!(
            formatted.contains("chmod 600") || formatted.contains("permissions"),
            "Should mention permissions: {formatted}"
        );
        assert!(
            formatted.contains("authorized_keys") || formatted.contains("ssh-copy-id"),
            "Should mention authorized_keys: {formatted}"
        );
        assert_eq!(code, Some("RCH-E101".to_string()));
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
    fn test_hook_invalid_input() {
        let err = HookError::InvalidInput {
            message: "missing tool_name".to_string(),
        };

        let code = err.code().map(|code| code.to_string());
        let report = Report::new(err);
        let formatted = format!("{:?}", report);

        assert!(formatted.contains("missing tool_name"));
        assert_eq!(code, Some("RCH-E506".to_string()));
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
        assert_eq!(code, Some("RCH-E506".to_string()));
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
        assert_eq!(code, Some("RCH-E509".to_string()));
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

        assert_eq!(code, Some("RCH-E406".to_string()));
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
        let err = WorkerError::NoneConfigured;
        let report = Report::new(err);

        let debug = format!("{:?}", report);
        let display = format!("{}", report);

        // Display should be simpler
        assert!(display.len() <= debug.len());
        // Both should contain the core message
        assert!(display.contains("No workers configured"));
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
}
