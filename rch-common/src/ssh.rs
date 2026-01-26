//! SSH client utilities for remote command execution.
//!
//! Provides connection management, command execution, and pooling support
//! for the remote compilation pipeline.

use crate::types::{WorkerConfig, WorkerId};
use anyhow::{Context, Result};
use openssh::{KnownHosts, Session, SessionBuilder, Stdio};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
use tokio::sync::{RwLock, mpsc};
use tracing::{debug, error, info, warn};

/// Default SSH connection timeout.
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Default command execution timeout.
const DEFAULT_COMMAND_TIMEOUT: Duration = Duration::from_secs(300);

/// Result of a remote command execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandResult {
    /// Exit code of the command.
    pub exit_code: i32,
    /// Standard output.
    pub stdout: String,
    /// Standard error.
    pub stderr: String,
    /// Execution duration in milliseconds.
    pub duration_ms: u64,
}

impl CommandResult {
    /// Check if the command succeeded (exit code 0).
    pub fn success(&self) -> bool {
        self.exit_code == 0
    }
}

/// Environment variable prefix for remote command execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvPrefix {
    /// Shell-safe prefix (includes trailing space when non-empty).
    pub prefix: String,
    /// Keys applied to the command.
    pub applied: Vec<String>,
    /// Keys rejected due to invalid name or unsafe value.
    pub rejected: Vec<String>,
}

/// Build a shell-safe environment variable prefix from an allowlist.
///
/// - Missing variables are ignored silently.
/// - Unsafe values (newline, carriage return, NUL) are rejected.
/// - Invalid keys are rejected.
pub fn build_env_prefix<F>(allowlist: &[String], mut get_env: F) -> EnvPrefix
where
    F: FnMut(&str) -> Option<String>,
{
    let mut parts = Vec::new();
    let mut applied = Vec::new();
    let mut rejected = Vec::new();

    for raw_key in allowlist {
        let key = raw_key.trim();
        if key.is_empty() {
            continue;
        }
        if !is_valid_env_key(key) {
            rejected.push(key.to_string());
            continue;
        }
        let Some(value) = get_env(key) else {
            continue;
        };
        let Some(escaped) = shell_escape_value(&value) else {
            rejected.push(key.to_string());
            continue;
        };
        parts.push(format!("{}={}", key, escaped));
        applied.push(key.to_string());
    }

    let prefix = if parts.is_empty() {
        String::new()
    } else {
        format!("{} ", parts.join(" "))
    };

    EnvPrefix {
        prefix,
        applied,
        rejected,
    }
}

fn is_valid_env_key(key: &str) -> bool {
    let mut chars = key.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first == '_' || first.is_ascii_alphabetic()) {
        return false;
    }
    chars.all(|c| c == '_' || c.is_ascii_alphanumeric())
}

fn shell_escape_value(value: &str) -> Option<String> {
    if value.contains('\n') || value.contains('\r') || value.contains('\0') {
        return None;
    }
    let mut out = String::with_capacity(value.len() + 2);
    out.push('\'');
    for ch in value.chars() {
        if ch == '\'' {
            out.push_str("'\"'\"'");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    Some(out)
}

/// SSH connection options.
#[derive(Debug, Clone)]
pub struct SshOptions {
    /// Connection timeout.
    pub connect_timeout: Duration,
    /// Command execution timeout.
    pub command_timeout: Duration,
    /// SSH control master mode for connection reuse.
    pub control_master: bool,
    /// Known hosts policy.
    pub known_hosts: KnownHostsPolicy,
}

impl Default for SshOptions {
    fn default() -> Self {
        Self {
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            command_timeout: DEFAULT_COMMAND_TIMEOUT,
            control_master: true,
            known_hosts: KnownHostsPolicy::Add,
        }
    }
}

/// Known hosts policy for SSH connections.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KnownHostsPolicy {
    /// Strictly verify known hosts (recommended for production).
    Strict,
    /// Add unknown hosts automatically (for development).
    Add,
    /// Accept all hosts without verification (INSECURE - testing only).
    AcceptAll,
}

/// SSH client for a single worker connection.
pub struct SshClient {
    /// Worker configuration.
    config: WorkerConfig,
    /// SSH options.
    options: SshOptions,
    /// Active SSH session (if connected).
    session: Option<Session>,
}

impl SshClient {
    /// Create a new SSH client for a worker.
    pub fn new(config: WorkerConfig, options: SshOptions) -> Self {
        Self {
            config,
            options,
            session: None,
        }
    }

    /// Get the worker ID.
    pub fn worker_id(&self) -> &WorkerId {
        &self.config.id
    }

    /// Check if connected to the worker.
    pub fn is_connected(&self) -> bool {
        self.session.is_some()
    }

    /// Connect to the remote worker.
    pub async fn connect(&mut self) -> Result<()> {
        if self.session.is_some() {
            debug!("Already connected to {}", self.config.id);
            return Ok(());
        }

        let destination = format!("{}@{}", self.config.user, self.config.host);
        debug!("Connecting to {} via SSH...", destination);

        let known_hosts = match self.options.known_hosts {
            KnownHostsPolicy::Strict => KnownHosts::Strict,
            KnownHostsPolicy::Add => KnownHosts::Add,
            KnownHostsPolicy::AcceptAll => KnownHosts::Accept,
        };

        let mut builder = SessionBuilder::default();
        builder
            .known_hosts_check(known_hosts)
            .connect_timeout(self.options.connect_timeout);

        // Add identity file if specified
        let identity_path = shellexpand::tilde(&self.config.identity_file);
        if Path::new(identity_path.as_ref()).exists() {
            builder.keyfile(identity_path.as_ref());
        }

        // Enable control master for connection reuse
        if self.options.control_master {
            let control_dir = if let Some(runtime_dir) = dirs::runtime_dir() {
                runtime_dir.join("rch-ssh")
            } else {
                let username = whoami::username().unwrap_or_else(|_| "unknown".to_string());
                std::env::temp_dir().join(format!("rch-ssh-{}", username))
            };

            if let Err(e) = std::fs::create_dir_all(&control_dir) {
                warn!(
                    "Failed to create SSH control directory {:?}: {}",
                    control_dir, e
                );
            }
            builder.control_directory(&control_dir);
        }

        let session = builder
            .connect(&destination)
            .await
            .with_context(|| format!("Failed to connect to {}", destination))?;

        info!("Connected to {} ({})", self.config.id, self.config.host);
        self.session = Some(session);
        Ok(())
    }

    /// Disconnect from the worker.
    pub async fn disconnect(&mut self) -> Result<()> {
        if let Some(session) = self.session.take() {
            debug!("Disconnecting from {}", self.config.id);
            session.close().await?;
            info!("Disconnected from {}", self.config.id);
        }
        Ok(())
    }

    /// Execute a command on the remote worker.
    pub async fn execute(&self, command: &str) -> Result<CommandResult> {
        let session = self.session.as_ref().context("Not connected to worker")?;

        let start = std::time::Instant::now();
        debug!("Executing on {}: {}", self.config.id, command);

        let mut child = session
            .command("sh")
            .arg("-c")
            .arg(command)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .await
            .with_context(|| format!("Failed to spawn command on {}", self.config.id))?;

        let execution_future = async {
            // Read stdout and stderr concurrently to avoid deadlock if one pipe fills.
            let stdout_handle = child.stdout().take();
            let stderr_handle = child.stderr().take();

            let stdout_fut = async {
                if let Some(out) = stdout_handle {
                    let mut reader = BufReader::new(out);
                    let mut buf = String::new();
                    reader.read_to_string(&mut buf).await?;
                    Ok::<String, anyhow::Error>(buf)
                } else {
                    Ok(String::new())
                }
            };

            let stderr_fut = async {
                if let Some(err) = stderr_handle {
                    let mut reader = BufReader::new(err);
                    let mut buf = String::new();
                    reader.read_to_string(&mut buf).await?;
                    Ok::<String, anyhow::Error>(buf)
                } else {
                    Ok(String::new())
                }
            };

            let (stdout, stderr) = tokio::try_join!(stdout_fut, stderr_fut)?;

            let status = child
                .wait()
                .await
                .with_context(|| "Failed to wait for command completion")?;

            Ok::<_, anyhow::Error>((status, stdout, stderr))
        };

        match tokio::time::timeout(self.options.command_timeout, execution_future).await {
            Ok(result) => {
                let (status, stdout, stderr) = result?;
                let duration = start.elapsed();
                let exit_code = status.code().unwrap_or(-1);

                debug!(
                    "Command completed on {} (exit={}, duration={}ms)",
                    self.config.id,
                    exit_code,
                    duration.as_millis()
                );

                Ok(CommandResult {
                    exit_code,
                    stdout,
                    stderr,
                    duration_ms: duration.as_millis() as u64,
                })
            }
            Err(_) => {
                // Timeout occurred - the async block owns child and dropping it will terminate the process
                warn!(
                    "Command timed out on {} after {:?}",
                    self.config.id, self.options.command_timeout
                );
                anyhow::bail!("Command timed out after {:?}", self.options.command_timeout);
            }
        }
    }

    /// Execute a command and stream output in real-time.
    pub async fn execute_streaming<F, G>(
        &self,
        command: &str,
        mut on_stdout: F,
        mut on_stderr: G,
    ) -> Result<CommandResult>
    where
        F: FnMut(&str),
        G: FnMut(&str),
    {
        let session = self.session.as_ref().context("Not connected to worker")?;

        let start = std::time::Instant::now();
        debug!("Executing (streaming) on {}: {}", self.config.id, command);

        let mut child = session
            .command("sh")
            .arg("-c")
            .arg(command)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .await
            .with_context(|| format!("Failed to spawn command on {}", self.config.id))?;

        let stdout = child.stdout().take();
        let stderr = child.stderr().take();

        // Use a channel to aggregate stream events from reader tasks.
        // This avoids cancellation safety issues with select! over AsyncBufReadExt::read_line.
        let (tx, mut rx) = mpsc::channel(100);

        // Spawn stdout reader
        if let Some(out) = stdout {
            let tx = tx.clone();
            tokio::spawn(async move {
                let mut reader = BufReader::new(out);
                let mut line = String::new();
                loop {
                    line.clear();
                    match reader.read_line(&mut line).await {
                        Ok(0) => break, // EOF
                        Ok(_) => {
                            if tx.send(StreamEvent::Stdout(line.clone())).await.is_err() {
                                break; // Receiver dropped
                            }
                        }
                        Err(_) => break, // Read error
                    }
                }
            });
        }

        // Spawn stderr reader
        if let Some(err) = stderr {
            let tx = tx.clone();
            tokio::spawn(async move {
                let mut reader = BufReader::new(err);
                let mut line = String::new();
                loop {
                    line.clear();
                    match reader.read_line(&mut line).await {
                        Ok(0) => break, // EOF
                        Ok(_) => {
                            if tx.send(StreamEvent::Stderr(line.clone())).await.is_err() {
                                break; // Receiver dropped
                            }
                        }
                        Err(_) => break, // Read error
                    }
                }
            });
        }

        // Drop original tx so rx closes when tasks finish
        drop(tx);

        let mut stdout_acc = String::new();
        let mut stderr_acc = String::new();

        enum StreamEvent {
            Stdout(String),
            Stderr(String),
        }

        let streaming_future = async {
            // Process events until channel closes (EOF from both streams)
            while let Some(event) = rx.recv().await {
                match event {
                    StreamEvent::Stdout(line) => {
                        on_stdout(&line);
                        stdout_acc.push_str(&line);
                    }
                    StreamEvent::Stderr(line) => {
                        on_stderr(&line);
                        stderr_acc.push_str(&line);
                    }
                }
            }

            let status = child.wait().await?;
            Ok::<_, anyhow::Error>(status)
        };

        match tokio::time::timeout(self.options.command_timeout, streaming_future).await {
            Ok(result) => {
                let status = result?;
                let duration = start.elapsed();
                let exit_code = status.code().unwrap_or(-1);

                Ok(CommandResult {
                    exit_code,
                    stdout: stdout_acc,
                    stderr: stderr_acc,
                    duration_ms: duration.as_millis() as u64,
                })
            }
            Err(_) => {
                // Timeout occurred - child is dropped and killed
                warn!(
                    "Command (streaming) timed out on {} after {:?}",
                    self.config.id, self.options.command_timeout
                );
                anyhow::bail!("Command timed out after {:?}", self.options.command_timeout);
            }
        }
    }

    /// Check if the worker is reachable via SSH.
    pub async fn health_check(&self) -> Result<bool> {
        match self.execute("echo ok").await {
            Ok(result) => Ok(result.success() && result.stdout.trim() == "ok"),
            Err(e) => {
                warn!("Health check failed for {}: {}", self.config.id, e);
                Ok(false)
            }
        }
    }
}

/// Connection pool for managing multiple SSH connections.
pub struct SshPool {
    /// Pool of active connections.
    connections: Arc<RwLock<HashMap<WorkerId, Arc<RwLock<SshClient>>>>>,
    /// Default SSH options.
    options: SshOptions,
}

impl SshPool {
    /// Create a new connection pool.
    pub fn new(options: SshOptions) -> Self {
        Self {
            connections: Arc::new(RwLock::new(HashMap::new())),
            options,
        }
    }

    /// Get or create a connection to a worker.
    pub async fn get_or_connect(&self, config: &WorkerConfig) -> Result<Arc<RwLock<SshClient>>> {
        let worker_id = config.id.clone();

        // Check if we already have a connection
        {
            let connections = self.connections.read().await;
            if let Some(client) = connections.get(&worker_id) {
                let client_guard = client.read().await;
                if client_guard.is_connected() {
                    debug!("Reusing existing connection to {}", worker_id);
                    return Ok(client.clone());
                }
            }
        }

        // Create new connection
        let mut client = SshClient::new(config.clone(), self.options.clone());
        client.connect().await?;

        let client = Arc::new(RwLock::new(client));

        // Store in pool
        {
            let mut connections = self.connections.write().await;
            connections.insert(worker_id.clone(), client.clone());
        }

        Ok(client)
    }

    /// Close a specific connection.
    pub async fn close(&self, worker_id: &WorkerId) -> Result<()> {
        let client = {
            let mut connections = self.connections.write().await;
            connections.remove(worker_id)
        };

        if let Some(client) = client {
            let mut client = client.write().await;
            client.disconnect().await?;
        }

        Ok(())
    }

    /// Close all connections.
    pub async fn close_all(&self) -> Result<()> {
        let clients: Vec<_> = {
            let mut connections = self.connections.write().await;
            connections.drain().map(|(_, v)| v).collect()
        };

        for client in clients {
            let mut client = client.write().await;
            if let Err(e) = client.disconnect().await {
                error!("Error closing connection: {}", e);
            }
        }

        Ok(())
    }

    /// Get the number of active connections.
    pub async fn active_connections(&self) -> usize {
        self.connections.read().await.len()
    }
}

impl Default for SshPool {
    fn default() -> Self {
        Self::new(SshOptions::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_command_result_success() {
        let result = CommandResult {
            exit_code: 0,
            stdout: "output".to_string(),
            stderr: String::new(),
            duration_ms: 100,
        };
        assert!(result.success());

        let failed = CommandResult {
            exit_code: 1,
            stdout: String::new(),
            stderr: "error".to_string(),
            duration_ms: 50,
        };
        assert!(!failed.success());
    }

    #[test]
    fn test_ssh_options_default() {
        let options = SshOptions::default();
        assert_eq!(options.connect_timeout, Duration::from_secs(10));
        assert_eq!(options.command_timeout, Duration::from_secs(300));
        assert!(options.control_master);
    }

    #[test]
    fn test_ssh_client_creation() {
        let config = WorkerConfig {
            id: WorkerId::new("test-worker"),
            host: "192.168.1.100".to_string(),
            user: "ubuntu".to_string(),
            identity_file: "~/.ssh/id_rsa".to_string(),
            total_slots: 8,
            priority: 100,
            tags: vec!["rust".to_string()],
        };

        let client = SshClient::new(config.clone(), SshOptions::default());
        assert_eq!(client.worker_id().as_str(), "test-worker");
        assert!(!client.is_connected());
    }

    #[test]
    fn test_build_env_prefix_quotes_and_rejects() {
        let mut env = HashMap::new();
        env.insert("RUSTFLAGS".to_string(), "-C target-cpu=native".to_string());
        env.insert("QUOTED".to_string(), "a'b".to_string());
        env.insert("BADVAL".to_string(), "line1\nline2".to_string());

        let allowlist = vec![
            "RUSTFLAGS".to_string(),
            "QUOTED".to_string(),
            "MISSING".to_string(),
            "BADVAL".to_string(),
            "BAD=KEY".to_string(),
        ];

        let prefix = build_env_prefix(&allowlist, |key| env.get(key).cloned());

        assert!(prefix.prefix.contains("RUSTFLAGS='-C target-cpu=native'"));
        assert!(prefix.prefix.contains("QUOTED='a'\"'\"'b'"));
        assert!(!prefix.prefix.contains("MISSING="));
        assert!(!prefix.prefix.contains("BADVAL="));
        assert!(prefix.rejected.contains(&"BADVAL".to_string()));
        assert!(prefix.rejected.contains(&"BAD=KEY".to_string()));
        assert_eq!(
            prefix.applied,
            vec!["RUSTFLAGS".to_string(), "QUOTED".to_string()]
        );
    }
}
