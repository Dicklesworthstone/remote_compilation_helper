//! Rich error diagnostics with miette integration.
//!
//! This module provides context-rich error types that leverage miette's
//! diagnostic capabilities for beautiful, actionable error messages.
//!
//! All public errors implement `Diagnostic` and follow the error code
//! convention `rch::category::specific`.

#![allow(unused_assignments)]

use miette::{Diagnostic, NamedSource, SourceSpan};
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
        code(rch::config::read_failed),
        help("Check that the file exists and you have read permissions")
    )]
    ReadFailed {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// TOML syntax error in configuration file.
    #[error("Invalid TOML syntax in config")]
    #[diagnostic(code(rch::config::parse_error))]
    ParseError {
        #[source_code]
        src: NamedSource<String>,
        #[label("{message}")]
        span: SourceSpan,
        message: String,
    },

    /// Missing required configuration field.
    #[error("Missing required field: {field}")]
    #[diagnostic(
        code(rch::config::missing_field),
        help("Add the '{field}' field to your config file")
    )]
    MissingField { field: String },

    /// Invalid configuration value.
    #[error("Invalid value for '{field}': {reason}")]
    #[diagnostic(code(rch::config::invalid_value), help("{suggestion}"))]
    InvalidValue {
        field: String,
        reason: String,
        suggestion: String,
    },

    /// Configuration file not found at expected location.
    #[error("Config file not found: {path}")]
    #[diagnostic(
        code(rch::config::not_found),
        help("Create a config file with: rch config init")
    )]
    NotFound { path: PathBuf },

    /// Workers configuration file not found.
    #[error("Workers config not found: {path}")]
    #[diagnostic(
        code(rch::config::workers_not_found),
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
        code(rch::worker::connection_failed),
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
        code(rch::worker::unhealthy),
        help("Check worker status: rch workers probe {worker_id}")
    )]
    Unhealthy { worker_id: String, reason: String },

    /// Worker not found in configuration.
    #[error("Worker '{worker_id}' not found in configuration")]
    #[diagnostic(
        code(rch::worker::not_found),
        help("List available workers: rch workers list")
    )]
    NotFound { worker_id: String },

    /// No workers are configured.
    #[error("No workers configured")]
    #[diagnostic(
        code(rch::worker::none_configured),
        help("Configure workers in ~/.config/rch/workers.toml")
    )]
    NoneConfigured,

    /// All workers are busy (at capacity).
    #[error("All workers are at capacity")]
    #[diagnostic(
        code(rch::worker::all_busy),
        help("Wait for running jobs to complete or add more workers")
    )]
    AllBusy,

    /// All workers have their circuit breakers open.
    #[error("All worker circuit breakers are open")]
    #[diagnostic(
        code(rch::worker::all_circuits_open),
        help(
            "Workers have experienced repeated failures.\nWait for circuit breakers to reset or check worker health:\n  rch workers probe --all"
        )
    )]
    AllCircuitsOpen,

    /// SSH key file not found.
    #[error("SSH identity file not found: {path}")]
    #[diagnostic(
        code(rch::worker::identity_not_found),
        help("Verify the identity_file path in your workers.toml")
    )]
    IdentityNotFound { path: PathBuf },

    /// SSH key has wrong permissions.
    #[error("SSH key has insecure permissions: {}", path.display())]
    #[diagnostic(
        code(rch::worker::insecure_permissions),
        help("Fix with: chmod 600 <key_path>")
    )]
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
        code(rch::ssh::permission_denied),
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
        code(rch::ssh::connection_refused),
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
        code(rch::ssh::timeout),
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
        code(rch::ssh::host_key_verification_failed),
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
        code(rch::ssh::agent_unavailable),
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
        code(rch::ssh::connection_failed),
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
    #[diagnostic(
        code(rch::daemon::not_running),
        help("Start the daemon with: rch daemon start")
    )]
    NotRunning,

    /// Daemon socket file not found.
    #[error("Daemon socket not found at {socket_path}")]
    #[diagnostic(
        code(rch::daemon::socket_not_found),
        help(
            "The daemon socket file does not exist. This usually means:\n  1. The daemon is not running\n  2. The socket path is misconfigured\n\nStart the daemon: rch daemon start\nOr check config: rch config show | grep socket"
        )
    )]
    SocketNotFound { socket_path: String },

    /// Failed to connect to daemon.
    #[error("Failed to connect to daemon at {socket_path}")]
    #[diagnostic(
        code(rch::daemon::connection_failed),
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
        code(rch::daemon::port_in_use),
        help("Stop the existing process or use RCH_SOCKET_PATH to specify a different socket")
    )]
    PortInUse { port: u16 },

    /// Daemon startup failed.
    #[error("Daemon startup failed")]
    #[diagnostic(
        code(rch::daemon::startup_failed),
        help("Check the logs for details: rch daemon logs")
    )]
    StartupFailed {
        #[source]
        source: std::io::Error,
    },

    /// Daemon protocol error.
    #[error("Daemon protocol error: {message}")]
    #[diagnostic(code(rch::daemon::protocol_error))]
    ProtocolError { message: String },

    /// Daemon returned an unexpected response.
    #[error("Unexpected daemon response: {response}")]
    #[diagnostic(
        code(rch::daemon::unexpected_response),
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
        code(rch::transfer::no_project_root),
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
        code(rch::transfer::rsync_failed),
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
        code(rch::transfer::ssh_auth_failed),
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
        code(rch::transfer::timeout),
        help("Consider increasing the transfer timeout or checking network connectivity")
    )]
    Timeout { seconds: u64 },

    /// Failed to create remote directory.
    #[error("Failed to create remote directory: {path}")]
    #[diagnostic(
        code(rch::transfer::mkdir_failed),
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
        code(rch::transfer::artifact_failed),
        help("Check that the build completed successfully on the worker")
    )]
    ArtifactFailed {
        worker_id: String,
        #[source]
        source: std::io::Error,
    },
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
        code(rch::hook::invalid_input),
        help(
            "This error indicates a problem with the hook protocol.\nExpected JSON with tool_name and tool_input fields."
        )
    )]
    InvalidInput { message: String },

    /// Hook installation failed.
    #[error("Failed to install Claude Code hook")]
    #[diagnostic(
        code(rch::hook::install_failed),
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
        code(rch::hook::settings_not_found),
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
    #[diagnostic(
        code(rch::update::fetch_failed),
        help("Check your internet connection and try again")
    )]
    FetchFailed {
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// No compatible release found.
    #[error("No compatible release found for {platform}")]
    #[diagnostic(
        code(rch::update::no_release),
        help(
            "Build from source: cargo install --git https://github.com/Dicklesworthstone/remote_compilation_helper.git"
        )
    )]
    NoRelease { platform: String },

    /// Checksum verification failed.
    #[error("Checksum verification failed for downloaded binary")]
    #[diagnostic(
        code(rch::update::checksum_failed),
        help("The download may be corrupted. Try again or download manually from GitHub.")
    )]
    ChecksumFailed { expected: String, actual: String },

    /// Installation failed.
    #[error("Failed to install update")]
    #[diagnostic(
        code(rch::update::install_failed),
        help("Check that you have write permissions to the installation directory")
    )]
    InstallFailed {
        #[source]
        source: std::io::Error,
    },

    /// Rollback not available.
    #[error("No backup available for rollback")]
    #[diagnostic(
        code(rch::update::no_backup),
        help("Rollback is only available after a successful update")
    )]
    NoBackup,
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
        assert!(
            formatted.contains("rch::config::parse_error"),
            "Should include error code: {formatted}"
        );
    }

    #[test]
    fn test_config_read_failed_includes_path() {
        let err = ConfigError::ReadFailed {
            path: PathBuf::from("/nonexistent/config.toml"),
            source: std::io::Error::new(std::io::ErrorKind::NotFound, "file not found"),
        };

        let report = Report::new(err);
        let formatted = format!("{:?}", report);

        assert!(formatted.contains("Failed to read config file"));
        assert!(formatted.contains("rch::config::read_failed"));
    }

    #[test]
    fn test_config_missing_field_has_help() {
        let err = ConfigError::MissingField {
            field: "workers".to_string(),
        };

        let report = Report::new(err);
        let formatted = format!("{:?}", report);

        assert!(formatted.contains("workers"));
        assert!(
            formatted.contains("help") || formatted.contains("Add"),
            "Should include help text: {formatted}"
        );
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
        assert!(
            formatted.contains("rch::worker::connection_failed"),
            "Should include error code: {formatted}"
        );
    }

    #[test]
    fn test_worker_unhealthy_includes_worker_id() {
        let err = WorkerError::Unhealthy {
            worker_id: "slow-worker".to_string(),
            reason: "high load".to_string(),
        };

        let report = Report::new(err);
        let formatted = format!("{:?}", report);

        assert!(formatted.contains("slow-worker"));
        assert!(formatted.contains("rch workers probe"));
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
        let report = Report::new(err);
        let formatted = format!("{:?}", report);

        assert!(
            formatted.contains("rch daemon start"),
            "Should suggest starting daemon: {formatted}"
        );
        assert!(formatted.contains("rch::daemon::not_running"));
    }

    #[test]
    fn test_daemon_socket_not_found() {
        let socket_path = rch_common::default_socket_path();
        let err = DaemonError::SocketNotFound {
            socket_path: socket_path.clone(),
        };

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
        assert!(formatted.contains("rch::daemon::socket_not_found"));
    }

    #[test]
    fn test_daemon_port_in_use_suggests_alternative() {
        let err = DaemonError::PortInUse { port: 7800 };
        let report = Report::new(err);
        let formatted = format!("{:?}", report);

        assert!(formatted.contains("7800"));
        assert!(
            formatted.contains("RCH_SOCKET_PATH") || formatted.contains("socket"),
            "Should suggest alternative: {formatted}"
        );
    }

    #[test]
    fn test_daemon_connection_failed() {
        let socket_path = rch_common::default_socket_path();
        let err = DaemonError::ConnectionFailed {
            socket_path: socket_path.clone(),
            source: std::io::Error::new(std::io::ErrorKind::NotFound, "socket not found"),
        };

        let report = Report::new(err);
        let formatted = format!("{:?}", report);

        assert!(formatted.contains(&socket_path));
        assert!(formatted.contains("rch::daemon::connection_failed"));
    }

    // =========================================================================
    // TransferError Tests
    // =========================================================================

    #[test]
    fn test_transfer_no_project_root() {
        let err = TransferError::NoProjectRoot {
            source: std::io::Error::new(std::io::ErrorKind::NotFound, "directory not found"),
        };

        let report = Report::new(err);
        let formatted = format!("{:?}", report);

        assert!(
            formatted.contains("project root"),
            "Should mention project root: {formatted}"
        );
        assert!(formatted.contains("rch::transfer::no_project_root"));
    }

    #[test]
    fn test_rsync_failed_includes_exit_code() {
        let err = TransferError::RsyncFailed {
            exit_code: Some(12),
            stderr: "connection unexpectedly closed".to_string(),
        };

        let report = Report::new(err);
        let formatted = format!("{:?}", report);

        assert!(formatted.contains("rsync"));
        assert!(formatted.contains("rch::transfer::rsync_failed"));
    }

    #[test]
    fn test_ssh_auth_failed_includes_key_hint() {
        let err = TransferError::SshAuthFailed {
            host: "example.com".to_string(),
            user: "deploy".to_string(),
            identity_file: "~/.ssh/deploy_key".to_string(),
        };

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
    }

    #[test]
    fn test_transfer_timeout() {
        let err = TransferError::Timeout { seconds: 120 };

        let report = Report::new(err);
        let formatted = format!("{:?}", report);

        assert!(formatted.contains("120"));
        assert!(formatted.contains("rch::transfer::timeout"));
    }

    // =========================================================================
    // HookError Tests
    // =========================================================================

    #[test]
    fn test_hook_invalid_input() {
        let err = HookError::InvalidInput {
            message: "missing tool_name".to_string(),
        };

        let report = Report::new(err);
        let formatted = format!("{:?}", report);

        assert!(formatted.contains("missing tool_name"));
        assert!(formatted.contains("rch::hook::invalid_input"));
    }

    #[test]
    fn test_hook_settings_not_found() {
        let err = HookError::SettingsNotFound {
            path: PathBuf::from("/home/user/.config/claude-code/settings.json"),
        };

        let report = Report::new(err);
        let formatted = format!("{:?}", report);

        assert!(formatted.contains("settings.json"));
        assert!(formatted.contains("rch::hook::settings_not_found"));
    }

    // =========================================================================
    // UpdateError Tests
    // =========================================================================

    #[test]
    fn test_update_no_release() {
        let err = UpdateError::NoRelease {
            platform: "x86_64-unknown-freebsd".to_string(),
        };

        let report = Report::new(err);
        let formatted = format!("{:?}", report);

        assert!(formatted.contains("freebsd"));
        assert!(
            formatted.contains("cargo install") || formatted.contains("source"),
            "Should suggest building from source: {formatted}"
        );
    }

    #[test]
    fn test_update_checksum_failed() {
        let err = UpdateError::ChecksumFailed {
            expected: "abc123".to_string(),
            actual: "def456".to_string(),
        };

        let report = Report::new(err);
        let formatted = format!("{:?}", report);

        assert!(formatted.contains("rch::update::checksum_failed"));
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
}
