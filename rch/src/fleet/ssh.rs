//! Fleet SSH command execution infrastructure.
//!
//! Provides reusable SSH command execution utilities for fleet operations
//! like deploy, rollback, preflight checks, and status queries.
//!
//! This module uses the raw `ssh` command via `tokio::process::Command` for
//! maximum compatibility with existing SSH configurations, agent forwarding,
//! and system-wide SSH settings. It complements the `rch-common/src/ssh.rs`
//! module which uses the `openssh` crate for the compilation pipeline.

use anyhow::{Context, Result, bail};
use rch_common::WorkerConfig;
use rch_common::mock;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::{Duration, Instant};
use tokio::process::Command;
use tracing::{debug, error, info, warn};

// =============================================================================
// Configuration Constants
// =============================================================================

/// Default SSH connection timeout in seconds.
pub const DEFAULT_CONNECT_TIMEOUT_SECS: u64 = 10;

/// Default command execution timeout in seconds.
pub const DEFAULT_COMMAND_TIMEOUT_SECS: u64 = 300;

/// Default SCP transfer timeout in seconds.
pub const DEFAULT_SCP_TIMEOUT_SECS: u64 = 600;

// =============================================================================
// CommandOutput - Structured command result
// =============================================================================

/// Result of a remote SSH command execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandOutput {
    /// Standard output from the command.
    pub stdout: String,
    /// Standard error from the command.
    pub stderr: String,
    /// Exit code of the command.
    pub exit_code: i32,
    /// Execution duration.
    #[serde(with = "duration_millis")]
    pub duration: Duration,
}

impl CommandOutput {
    /// Check if the command succeeded (exit code 0).
    pub fn success(&self) -> bool {
        self.exit_code == 0
    }
}

/// Serde helper for Duration as milliseconds.
mod duration_millis {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::time::Duration;

    pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        duration.as_millis().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let millis = u64::deserialize(deserializer)?;
        Ok(Duration::from_millis(millis))
    }
}

// =============================================================================
// FleetSshError - Specific error types for fleet SSH operations
// =============================================================================

/// Errors specific to fleet SSH operations.
#[derive(Debug, thiserror::Error)]
pub enum FleetSshError {
    /// SSH connection could not be established.
    #[error("SSH connection timeout after {timeout_secs}s to {host}")]
    ConnectionTimeout { host: String, timeout_secs: u64 },

    /// Command execution timed out.
    #[error("Command timed out after {timeout_secs}s on {host}")]
    CommandTimeout { host: String, timeout_secs: u64 },

    /// SSH authentication failed.
    #[error("SSH authentication failed for {user}@{host}")]
    AuthenticationFailed { host: String, user: String },

    /// Host is unreachable (network failure).
    #[error("Host {host} is unreachable: {reason}")]
    HostUnreachable { host: String, reason: String },

    /// Command executed but returned non-zero exit code.
    #[error("Command failed on {host} with exit code {exit_code}: {stderr}")]
    CommandFailed {
        host: String,
        exit_code: i32,
        stderr: String,
    },

    /// SSH key or identity file issue.
    #[error("SSH key error for {host}: {reason}")]
    KeyError { host: String, reason: String },

    /// SCP transfer failed.
    #[error("SCP transfer failed to {host}: {reason}")]
    ScpFailed { host: String, reason: String },

    /// Host key verification failed.
    #[error("Host key verification failed for {host}")]
    HostKeyVerificationFailed { host: String },
}

impl FleetSshError {
    /// Create an error from SSH stderr output.
    pub fn from_ssh_stderr(host: &str, user: &str, stderr: &str, exit_code: i32) -> Self {
        let stderr_lower = stderr.to_lowercase();

        if stderr_lower.contains("permission denied") {
            return FleetSshError::AuthenticationFailed {
                host: host.to_string(),
                user: user.to_string(),
            };
        }

        if stderr_lower.contains("host key verification failed") {
            return FleetSshError::HostKeyVerificationFailed {
                host: host.to_string(),
            };
        }

        if stderr_lower.contains("connection timed out")
            || stderr_lower.contains("connection refused")
            || stderr_lower.contains("no route to host")
            || stderr_lower.contains("network is unreachable")
        {
            return FleetSshError::HostUnreachable {
                host: host.to_string(),
                reason: stderr.trim().to_string(),
            };
        }

        if stderr_lower.contains("identity file") || stderr_lower.contains("no such file") {
            return FleetSshError::KeyError {
                host: host.to_string(),
                reason: stderr.trim().to_string(),
            };
        }

        FleetSshError::CommandFailed {
            host: host.to_string(),
            exit_code,
            stderr: stderr.trim().to_string(),
        }
    }
}

// =============================================================================
// SshExecutor - Main SSH execution wrapper
// =============================================================================

/// SSH executor for fleet operations.
///
/// Provides a unified interface for executing SSH commands across workers
/// with consistent timeout handling, error classification, and logging.
///
/// # Example
///
/// ```ignore
/// let worker = /* WorkerConfig */;
/// let ssh = SshExecutor::new(&worker);
///
/// // Test connectivity
/// if ssh.check_connectivity().await? {
///     // Run a command
///     let output = ssh.run_command("uname -a").await?;
///     println!("OS: {}", output.stdout);
/// }
/// ```
pub struct SshExecutor<'a> {
    /// Reference to the worker configuration.
    worker: &'a WorkerConfig,
    /// Connection timeout.
    connect_timeout: Duration,
    /// Command execution timeout.
    command_timeout: Duration,
    /// SCP transfer timeout.
    scp_timeout: Duration,
}

impl<'a> SshExecutor<'a> {
    /// Create a new SSH executor with default timeouts.
    pub fn new(worker: &'a WorkerConfig) -> Self {
        Self {
            worker,
            connect_timeout: Duration::from_secs(DEFAULT_CONNECT_TIMEOUT_SECS),
            command_timeout: Duration::from_secs(DEFAULT_COMMAND_TIMEOUT_SECS),
            scp_timeout: Duration::from_secs(DEFAULT_SCP_TIMEOUT_SECS),
        }
    }

    /// Create a new SSH executor with custom command timeout.
    pub fn with_timeout(worker: &'a WorkerConfig, timeout: Duration) -> Self {
        Self {
            worker,
            connect_timeout: Duration::from_secs(DEFAULT_CONNECT_TIMEOUT_SECS),
            command_timeout: timeout,
            scp_timeout: Duration::from_secs(DEFAULT_SCP_TIMEOUT_SECS),
        }
    }

    /// Set the connection timeout.
    pub fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Set the command execution timeout.
    pub fn command_timeout(mut self, timeout: Duration) -> Self {
        self.command_timeout = timeout;
        self
    }

    /// Set the SCP transfer timeout.
    pub fn scp_timeout(mut self, timeout: Duration) -> Self {
        self.scp_timeout = timeout;
        self
    }

    /// Get the worker ID.
    pub fn worker_id(&self) -> &str {
        &self.worker.id.0
    }

    /// Get the target destination (user@host).
    fn destination(&self) -> String {
        format!("{}@{}", self.worker.user, self.worker.host)
    }

    // =========================================================================
    // SSH Options Builder
    // =========================================================================

    /// Build common SSH command arguments.
    fn build_ssh_args(&self, cmd: &mut Command) {
        cmd.arg("-o").arg("BatchMode=yes");
        cmd.arg("-o")
            .arg(format!("ConnectTimeout={}", self.connect_timeout.as_secs()));
        cmd.arg("-o").arg("StrictHostKeyChecking=accept-new");
        cmd.arg("-i").arg(&self.worker.identity_file);
    }

    /// Build common SCP command arguments.
    fn build_scp_args(&self, cmd: &mut Command) {
        cmd.arg("-o").arg("BatchMode=yes");
        cmd.arg("-o")
            .arg(format!("ConnectTimeout={}", self.scp_timeout.as_secs()));
        cmd.arg("-o").arg("StrictHostKeyChecking=accept-new");
        cmd.arg("-i").arg(&self.worker.identity_file);
    }

    // =========================================================================
    // Core SSH Operations
    // =========================================================================

    /// Check SSH connectivity to the worker.
    ///
    /// Returns `true` if the connection succeeds, `false` otherwise.
    pub async fn check_connectivity(&self) -> Result<bool> {
        // Mock mode: skip actual SSH
        if mock::is_mock_enabled() || mock::is_mock_worker(self.worker) {
            debug!(
                worker = %self.worker.id,
                host = %self.worker.host,
                "Mock mode: skipping SSH connectivity check"
            );
            return Ok(true);
        }

        debug!(
            worker = %self.worker.id,
            host = %self.worker.host,
            timeout_ms = %self.connect_timeout.as_millis(),
            "Testing SSH connectivity"
        );

        let start = Instant::now();
        let mut cmd = Command::new("ssh");
        self.build_ssh_args(&mut cmd);
        cmd.arg(self.destination());
        cmd.arg("true");

        let output =
            match tokio::time::timeout(self.connect_timeout + Duration::from_secs(5), cmd.output())
                .await
            {
                Ok(Ok(output)) => output,
                Ok(Err(e)) => {
                    warn!(
                        worker = %self.worker.id,
                        host = %self.worker.host,
                        error = %e,
                        "SSH connectivity check failed to execute"
                    );
                    return Ok(false);
                }
                Err(_) => {
                    warn!(
                        worker = %self.worker.id,
                        host = %self.worker.host,
                        timeout_ms = %self.connect_timeout.as_millis(),
                        "SSH connectivity check timed out"
                    );
                    return Ok(false);
                }
            };

        let duration = start.elapsed();

        if output.status.success() {
            info!(
                worker = %self.worker.id,
                host = %self.worker.host,
                duration_ms = %duration.as_millis(),
                "SSH connectivity check passed"
            );
            Ok(true)
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            warn!(
                worker = %self.worker.id,
                host = %self.worker.host,
                exit_code = output.status.code().unwrap_or(-1),
                stderr = %stderr.trim(),
                duration_ms = %duration.as_millis(),
                "SSH connectivity check failed"
            );
            Ok(false)
        }
    }

    /// Execute a command on the remote worker.
    ///
    /// Returns the structured command output including stdout, stderr,
    /// exit code, and execution duration.
    pub async fn run_command(&self, remote_cmd: &str) -> Result<CommandOutput, FleetSshError> {
        // Mock mode: return success
        if mock::is_mock_enabled() || mock::is_mock_worker(self.worker) {
            debug!(
                worker = %self.worker.id,
                host = %self.worker.host,
                command = %remote_cmd,
                "Mock mode: simulating successful SSH command"
            );
            return Ok(CommandOutput {
                stdout: String::new(),
                stderr: String::new(),
                exit_code: 0,
                duration: Duration::from_millis(1),
            });
        }

        debug!(
            worker = %self.worker.id,
            host = %self.worker.host,
            command = %remote_cmd,
            timeout_ms = %self.command_timeout.as_millis(),
            "Executing SSH command"
        );

        let start = Instant::now();
        let mut cmd = Command::new("ssh");
        self.build_ssh_args(&mut cmd);
        cmd.arg(self.destination());
        cmd.arg(remote_cmd);

        let output = match tokio::time::timeout(self.command_timeout, cmd.output()).await {
            Ok(Ok(output)) => output,
            Ok(Err(e)) => {
                error!(
                    worker = %self.worker.id,
                    host = %self.worker.host,
                    command = %remote_cmd,
                    error = %e,
                    "SSH command failed to execute"
                );
                return Err(FleetSshError::HostUnreachable {
                    host: self.worker.host.clone(),
                    reason: e.to_string(),
                });
            }
            Err(_) => {
                warn!(
                    worker = %self.worker.id,
                    host = %self.worker.host,
                    command = %remote_cmd,
                    timeout_ms = %self.command_timeout.as_millis(),
                    "SSH command timed out"
                );
                return Err(FleetSshError::CommandTimeout {
                    host: self.worker.host.clone(),
                    timeout_secs: self.command_timeout.as_secs(),
                });
            }
        };

        let duration = start.elapsed();
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        let exit_code = output.status.code().unwrap_or(-1);

        if output.status.success() {
            info!(
                worker = %self.worker.id,
                command = %remote_cmd,
                exit_code = %exit_code,
                duration_ms = %duration.as_millis(),
                stdout_len = %stdout.len(),
                stderr_len = %stderr.len(),
                "SSH command completed successfully"
            );
        } else {
            warn!(
                worker = %self.worker.id,
                host = %self.worker.host,
                command = %remote_cmd,
                exit_code = %exit_code,
                stderr = %stderr.trim(),
                duration_ms = %duration.as_millis(),
                "SSH command failed"
            );
        }

        Ok(CommandOutput {
            stdout,
            stderr,
            exit_code,
            duration,
        })
    }

    /// Execute a command and return only stdout (trimmed).
    ///
    /// Returns an error if the command fails (non-zero exit code).
    pub async fn run_command_raw(&self, remote_cmd: &str) -> Result<String, FleetSshError> {
        let output = self.run_command(remote_cmd).await?;

        if !output.success() {
            return Err(FleetSshError::from_ssh_stderr(
                &self.worker.host,
                &self.worker.user,
                &output.stderr,
                output.exit_code,
            ));
        }

        Ok(output.stdout.trim().to_string())
    }

    /// Create a directory on the remote worker.
    pub async fn create_directory(&self, path: &str) -> Result<(), FleetSshError> {
        let cmd = format!("mkdir -p {}", path);
        let output = self.run_command(&cmd).await?;

        if !output.success() {
            return Err(FleetSshError::CommandFailed {
                host: self.worker.host.clone(),
                exit_code: output.exit_code,
                stderr: output.stderr,
            });
        }

        debug!(
            worker = %self.worker.id,
            path = %path,
            "Created remote directory"
        );

        Ok(())
    }

    /// Set executable permissions on a remote file.
    pub async fn set_executable(&self, path: &str) -> Result<(), FleetSshError> {
        let cmd = format!("chmod +x {}", path);
        let output = self.run_command(&cmd).await?;

        if !output.success() {
            return Err(FleetSshError::CommandFailed {
                host: self.worker.host.clone(),
                exit_code: output.exit_code,
                stderr: output.stderr,
            });
        }

        debug!(
            worker = %self.worker.id,
            path = %path,
            "Set executable permissions"
        );

        Ok(())
    }

    /// Copy a file to the remote worker via SCP.
    pub async fn copy_file(
        &self,
        local_path: &Path,
        remote_path: &str,
    ) -> Result<(), FleetSshError> {
        // Mock mode: skip actual SCP
        if mock::is_mock_enabled() || mock::is_mock_worker(self.worker) {
            debug!(
                worker = %self.worker.id,
                local_path = %local_path.display(),
                remote_path = %remote_path,
                "Mock mode: skipping SCP copy"
            );
            return Ok(());
        }

        debug!(
            worker = %self.worker.id,
            local_path = %local_path.display(),
            remote_path = %remote_path,
            timeout_ms = %self.scp_timeout.as_millis(),
            "Copying file via SCP"
        );

        let start = Instant::now();
        let mut cmd = Command::new("scp");
        self.build_scp_args(&mut cmd);
        cmd.arg(local_path);
        cmd.arg(format!("{}:{}", self.destination(), remote_path));

        let output = match tokio::time::timeout(self.scp_timeout, cmd.output()).await {
            Ok(Ok(output)) => output,
            Ok(Err(e)) => {
                error!(
                    worker = %self.worker.id,
                    local_path = %local_path.display(),
                    error = %e,
                    "SCP failed to execute"
                );
                return Err(FleetSshError::ScpFailed {
                    host: self.worker.host.clone(),
                    reason: e.to_string(),
                });
            }
            Err(_) => {
                warn!(
                    worker = %self.worker.id,
                    local_path = %local_path.display(),
                    timeout_ms = %self.scp_timeout.as_millis(),
                    "SCP transfer timed out"
                );
                return Err(FleetSshError::ScpFailed {
                    host: self.worker.host.clone(),
                    reason: format!("Timeout after {}s", self.scp_timeout.as_secs()),
                });
            }
        };

        let duration = start.elapsed();

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            error!(
                worker = %self.worker.id,
                local_path = %local_path.display(),
                stderr = %stderr.trim(),
                "SCP transfer failed"
            );
            return Err(FleetSshError::ScpFailed {
                host: self.worker.host.clone(),
                reason: stderr.trim().to_string(),
            });
        }

        info!(
            worker = %self.worker.id,
            local_path = %local_path.display(),
            remote_path = %remote_path,
            duration_ms = %duration.as_millis(),
            "SCP transfer completed"
        );

        Ok(())
    }
}

// =============================================================================
// MockSshExecutor - Fleet-specific testing presets
// =============================================================================

/// Mock SSH executor for fleet operation testing.
///
/// Provides convenient presets for testing preflight checks, status queries,
/// and rollback operations without real SSH connections.
///
/// # Example
///
/// ```ignore
/// use rch::fleet::ssh::MockSshExecutor;
///
/// // Test with a healthy worker
/// let mock = MockSshExecutor::all_healthy();
/// let result = run_preflight_with_mock(&worker, &mock).await;
/// assert!(result.is_ok());
///
/// // Test with unreachable worker
/// let mock = MockSshExecutor::unreachable();
/// let result = run_preflight_with_mock(&worker, &mock).await;
/// assert!(result.is_err());
/// ```
#[derive(Debug, Clone)]
pub struct MockSshExecutor {
    /// Whether connectivity checks should pass.
    connectivity: MockConnectivity,
    /// Command results keyed by command substring.
    command_results: std::collections::HashMap<String, MockCommandResult>,
    /// Default result for commands not in the map.
    default_result: MockCommandResult,
    /// Simulated delay before returning results.
    delay: Option<Duration>,
}

/// Mock connectivity behavior.
#[derive(Debug, Clone, Copy, Default)]
pub enum MockConnectivity {
    /// Connection succeeds.
    #[default]
    Connected,
    /// Connection fails with timeout.
    Timeout,
    /// Connection fails with auth error.
    AuthFailed,
    /// Connection fails with unreachable host.
    Unreachable,
}

/// Mock command result.
#[derive(Debug, Clone, Default)]
pub struct MockCommandResult {
    /// Exit code (0 = success).
    pub exit_code: i32,
    /// Standard output.
    pub stdout: String,
    /// Standard error.
    pub stderr: String,
}

impl MockCommandResult {
    /// Create a successful result with stdout.
    pub fn ok(stdout: impl Into<String>) -> Self {
        Self {
            exit_code: 0,
            stdout: stdout.into(),
            stderr: String::new(),
        }
    }

    /// Create a failed result with exit code and stderr.
    pub fn err(exit_code: i32, stderr: impl Into<String>) -> Self {
        Self {
            exit_code,
            stdout: String::new(),
            stderr: stderr.into(),
        }
    }
}

impl Default for MockSshExecutor {
    fn default() -> Self {
        Self {
            connectivity: MockConnectivity::Connected,
            command_results: std::collections::HashMap::new(),
            default_result: MockCommandResult::default(),
            delay: None,
        }
    }
}

impl MockSshExecutor {
    /// Create a new mock executor with default (success) behavior.
    pub fn new() -> Self {
        Self::default()
    }

    // =========================================================================
    // Preset Configurations
    // =========================================================================

    /// All preflight checks pass - worker is fully healthy.
    ///
    /// Simulates:
    /// - Connectivity: success
    /// - Disk space: 100GB available
    /// - rsync: installed at /usr/bin/rsync
    /// - zstd: installed at /usr/bin/zstd
    /// - rustup: installed at ~/.cargo/bin/rustup
    /// - rch-wkr: version 1.0.0
    pub fn all_healthy() -> Self {
        Self::new()
            .with_connectivity(MockConnectivity::Connected)
            .with_command("df", MockCommandResult::ok(
                "Filesystem     1B-blocks         Used    Available Use% Mounted on\n\
                 /dev/sda1  500000000000 400000000000 100000000000  80% /"
            ))
            .with_command("which rsync", MockCommandResult::ok("/usr/bin/rsync"))
            .with_command("which zstd", MockCommandResult::ok("/usr/bin/zstd"))
            .with_command("which rustup", MockCommandResult::ok("/home/user/.cargo/bin/rustup"))
            .with_command("rustc --version", MockCommandResult::ok("rustc 1.75.0 (82e1608df 2024-01-01)"))
            .with_command("rch-wkr --version", MockCommandResult::ok("rch-wkr 1.0.0"))
            .with_command("rch-wkr health", MockCommandResult::ok("ok"))
    }

    /// Worker is unreachable (SSH connection fails).
    pub fn unreachable() -> Self {
        Self::new().with_connectivity(MockConnectivity::Unreachable)
    }

    /// Worker has SSH authentication failure.
    pub fn auth_failed() -> Self {
        Self::new().with_connectivity(MockConnectivity::AuthFailed)
    }

    /// Worker connection times out.
    pub fn timeout() -> Self {
        Self::new().with_connectivity(MockConnectivity::Timeout)
    }

    /// Simulate slow connection (for timeout tests).
    pub fn slow(delay: Duration) -> Self {
        Self::new().with_delay(delay)
    }

    /// Worker is healthy but has low disk space.
    pub fn low_disk_space(available_bytes: u64) -> Self {
        Self::all_healthy().with_command(
            "df",
            MockCommandResult::ok(format!(
                "Filesystem     1B-blocks         Used    Available Use% Mounted on\n\
                 /dev/sda1  500000000000 {} {} 99% /",
                500000000000u64 - available_bytes,
                available_bytes
            )),
        )
    }

    /// Worker is missing rsync.
    pub fn missing_rsync() -> Self {
        Self::all_healthy()
            .with_command("which rsync", MockCommandResult::err(1, ""))
    }

    /// Worker is missing zstd.
    pub fn missing_zstd() -> Self {
        Self::all_healthy()
            .with_command("which zstd", MockCommandResult::err(1, ""))
    }

    /// Worker is missing rustup.
    pub fn missing_rustup() -> Self {
        Self::all_healthy()
            .with_command("which rustup", MockCommandResult::err(1, ""))
    }

    /// Worker has rch-wkr not installed.
    pub fn missing_rch_wkr() -> Self {
        Self::all_healthy()
            .with_command("rch-wkr --version", MockCommandResult::err(127, "command not found: rch-wkr"))
            .with_command("rch-wkr health", MockCommandResult::err(127, "command not found: rch-wkr"))
    }

    // =========================================================================
    // Builder Methods
    // =========================================================================

    /// Set connectivity behavior.
    pub fn with_connectivity(mut self, connectivity: MockConnectivity) -> Self {
        self.connectivity = connectivity;
        self
    }

    /// Add a command result for a specific command pattern.
    ///
    /// The pattern is matched as a substring of the full command.
    pub fn with_command(mut self, pattern: impl Into<String>, result: MockCommandResult) -> Self {
        self.command_results.insert(pattern.into(), result);
        self
    }

    /// Set the default result for commands not matched by patterns.
    pub fn with_default_result(mut self, result: MockCommandResult) -> Self {
        self.default_result = result;
        self
    }

    /// Set a delay before returning results (for timeout testing).
    pub fn with_delay(mut self, delay: Duration) -> Self {
        self.delay = Some(delay);
        self
    }

    // =========================================================================
    // Execution Methods (for use in tests)
    // =========================================================================

    /// Simulate checking connectivity.
    pub async fn check_connectivity(&self) -> Result<bool, FleetSshError> {
        if let Some(delay) = self.delay {
            tokio::time::sleep(delay).await;
        }

        match self.connectivity {
            MockConnectivity::Connected => Ok(true),
            MockConnectivity::Timeout => Err(FleetSshError::ConnectionTimeout {
                host: "mock".to_string(),
                timeout_secs: 10,
            }),
            MockConnectivity::AuthFailed => Err(FleetSshError::AuthenticationFailed {
                host: "mock".to_string(),
                user: "mock".to_string(),
            }),
            MockConnectivity::Unreachable => Err(FleetSshError::HostUnreachable {
                host: "mock".to_string(),
                reason: "mock: no route to host".to_string(),
            }),
        }
    }

    /// Simulate running a command.
    pub async fn run_command(&self, cmd: &str) -> Result<CommandOutput, FleetSshError> {
        // Check connectivity first
        match self.connectivity {
            MockConnectivity::Connected => {}
            MockConnectivity::Timeout => {
                return Err(FleetSshError::ConnectionTimeout {
                    host: "mock".to_string(),
                    timeout_secs: 10,
                });
            }
            MockConnectivity::AuthFailed => {
                return Err(FleetSshError::AuthenticationFailed {
                    host: "mock".to_string(),
                    user: "mock".to_string(),
                });
            }
            MockConnectivity::Unreachable => {
                return Err(FleetSshError::HostUnreachable {
                    host: "mock".to_string(),
                    reason: "mock: no route to host".to_string(),
                });
            }
        }

        if let Some(delay) = self.delay {
            tokio::time::sleep(delay).await;
        }

        // Find matching command result
        let result = self
            .command_results
            .iter()
            .find(|(pattern, _)| cmd.contains(pattern.as_str()))
            .map(|(_, result)| result)
            .unwrap_or(&self.default_result);

        Ok(CommandOutput {
            stdout: result.stdout.clone(),
            stderr: result.stderr.clone(),
            exit_code: result.exit_code,
            duration: Duration::from_millis(10),
        })
    }

    /// Simulate running a command and return stdout on success.
    pub async fn run_command_raw(&self, cmd: &str) -> Result<String, FleetSshError> {
        let output = self.run_command(cmd).await?;

        if !output.success() {
            return Err(FleetSshError::CommandFailed {
                host: "mock".to_string(),
                exit_code: output.exit_code,
                stderr: output.stderr,
            });
        }

        Ok(output.stdout.trim().to_string())
    }
}

// =============================================================================
// Output Parsing Utilities
// =============================================================================

/// Parse disk space from `df` output.
///
/// Expects output from `df -B1 <path>` and extracts the available bytes.
pub fn parse_disk_space(df_output: &str) -> Result<u64> {
    // df output format:
    // Filesystem     1B-blocks      Used Available Use% Mounted on
    // /dev/sda1  1234567890123 123456789 1111111101234  11% /
    let lines: Vec<&str> = df_output.lines().collect();
    if lines.len() < 2 {
        bail!("Unexpected df output format: too few lines");
    }

    let data_line = lines[1];
    let fields: Vec<&str> = data_line.split_whitespace().collect();
    if fields.len() < 4 {
        bail!("Unexpected df output format: too few fields");
    }

    // Available is the 4th field (index 3)
    fields[3]
        .parse::<u64>()
        .context("Failed to parse available disk space")
}

/// Parse a version string from command output.
///
/// Attempts to extract a semantic version (X.Y.Z) from the output.
pub fn parse_version_string(version_output: &str) -> Result<String> {
    // Try to find a semver-like pattern
    let re = regex::Regex::new(r"(\d+\.\d+\.\d+(?:-[a-zA-Z0-9.]+)?)")?;

    if let Some(captures) = re.captures(version_output)
        && let Some(version) = captures.get(1)
    {
        return Ok(version.as_str().to_string());
    }

    // Fall back to returning first non-empty line
    version_output
        .lines()
        .find(|line| !line.trim().is_empty())
        .map(|s| s.trim().to_string())
        .context("No version string found in output")
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use rch_common::WorkerId;

    fn test_worker() -> WorkerConfig {
        WorkerConfig {
            id: WorkerId("test-worker".to_string()),
            host: "localhost".to_string(),
            user: "test".to_string(),
            identity_file: "/tmp/test_key".to_string(),
            total_slots: 4,
            priority: 1,
            tags: vec![],
        }
    }

    // =========================================================================
    // CommandOutput tests
    // =========================================================================

    #[test]
    fn command_output_success_check() {
        let output = CommandOutput {
            stdout: "hello".to_string(),
            stderr: String::new(),
            exit_code: 0,
            duration: Duration::from_millis(100),
        };
        assert!(output.success());

        let failed = CommandOutput {
            stdout: String::new(),
            stderr: "error".to_string(),
            exit_code: 1,
            duration: Duration::from_millis(50),
        };
        assert!(!failed.success());
    }

    #[test]
    fn command_output_serialization() {
        let output = CommandOutput {
            stdout: "test output".to_string(),
            stderr: "test error".to_string(),
            exit_code: 42,
            duration: Duration::from_millis(1234),
        };

        let json = serde_json::to_string(&output).unwrap();
        assert!(json.contains("\"exit_code\":42"));
        assert!(json.contains("\"duration\":1234"));

        let restored: CommandOutput = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.exit_code, 42);
        assert_eq!(restored.duration, Duration::from_millis(1234));
    }

    // =========================================================================
    // FleetSshError tests
    // =========================================================================

    #[test]
    fn fleet_ssh_error_from_permission_denied() {
        let err = FleetSshError::from_ssh_stderr(
            "worker1",
            "ubuntu",
            "Permission denied (publickey).",
            255,
        );
        assert!(matches!(err, FleetSshError::AuthenticationFailed { .. }));
    }

    #[test]
    fn fleet_ssh_error_from_host_key() {
        let err = FleetSshError::from_ssh_stderr(
            "worker1",
            "ubuntu",
            "Host key verification failed.",
            255,
        );
        assert!(matches!(
            err,
            FleetSshError::HostKeyVerificationFailed { .. }
        ));
    }

    #[test]
    fn fleet_ssh_error_from_network() {
        let err = FleetSshError::from_ssh_stderr(
            "worker1",
            "ubuntu",
            "ssh: connect to host worker1 port 22: Connection refused",
            255,
        );
        assert!(matches!(err, FleetSshError::HostUnreachable { .. }));
    }

    #[test]
    fn fleet_ssh_error_from_generic() {
        let err = FleetSshError::from_ssh_stderr("worker1", "ubuntu", "some other error", 1);
        assert!(matches!(err, FleetSshError::CommandFailed { .. }));
    }

    // =========================================================================
    // SshExecutor tests
    // =========================================================================

    #[test]
    fn ssh_executor_creation() {
        let worker = test_worker();
        let ssh = SshExecutor::new(&worker);

        assert_eq!(ssh.worker_id(), "test-worker");
        assert_eq!(ssh.destination(), "test@localhost");
    }

    #[test]
    fn ssh_executor_builder_pattern() {
        let worker = test_worker();
        let ssh = SshExecutor::new(&worker)
            .connect_timeout(Duration::from_secs(20))
            .command_timeout(Duration::from_secs(600))
            .scp_timeout(Duration::from_secs(1200));

        assert_eq!(ssh.connect_timeout, Duration::from_secs(20));
        assert_eq!(ssh.command_timeout, Duration::from_secs(600));
        assert_eq!(ssh.scp_timeout, Duration::from_secs(1200));
    }

    #[test]
    fn ssh_executor_with_timeout() {
        let worker = test_worker();
        let ssh = SshExecutor::with_timeout(&worker, Duration::from_secs(120));

        assert_eq!(ssh.command_timeout, Duration::from_secs(120));
    }

    // =========================================================================
    // Output parsing tests
    // =========================================================================

    #[test]
    fn parse_disk_space_valid() {
        let df_output = "Filesystem     1B-blocks         Used    Available Use% Mounted on\n/dev/sda1  500107862016 234567890123 265539971893  47% /";
        let available = parse_disk_space(df_output).unwrap();
        assert_eq!(available, 265539971893);
    }

    #[test]
    fn parse_disk_space_invalid() {
        let df_output = "invalid output";
        assert!(parse_disk_space(df_output).is_err());
    }

    #[test]
    fn parse_version_semver() {
        let output = "rustc 1.75.0-nightly (abcdef123 2024-01-15)";
        let version = parse_version_string(output).unwrap();
        assert_eq!(version, "1.75.0-nightly");
    }

    #[test]
    fn parse_version_simple() {
        let output = "rch-wkr 0.2.0";
        let version = parse_version_string(output).unwrap();
        assert_eq!(version, "0.2.0");
    }

    #[test]
    fn parse_version_fallback() {
        let output = "some tool version info";
        let version = parse_version_string(output).unwrap();
        assert_eq!(version, "some tool version info");
    }
}
