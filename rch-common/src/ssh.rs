//! SSH client utilities for remote command execution.
//!
//! Provides connection management, command execution, and pooling support
//! for the remote compilation pipeline.
//!
//! This module is only available on Unix platforms (requires openssh crate).

use crate::types::{WorkerConfig, WorkerId};
use anyhow::{Context, Result};
use openssh::{ControlPersist, KnownHosts, Session, SessionBuilder, Stdio};
use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
use tokio::sync::{RwLock, mpsc};
use tracing::{debug, error, info, warn};

// Re-export platform-independent utilities for backwards compatibility
pub use crate::ssh_utils::{
    CommandResult, EnvPrefix, build_env_prefix, is_retryable_transport_error,
    is_retryable_transport_error_text, is_valid_env_key, shell_escape_value,
};

/// Default SSH connection timeout.
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Default command execution timeout.
const DEFAULT_COMMAND_TIMEOUT: Duration = Duration::from_secs(300);

/// Maximum size for command output (stdout/stderr) to prevent OOM (10MB).
const MAX_OUTPUT_SIZE: u64 = 10 * 1024 * 1024;

/// SSH connection options.
#[derive(Debug, Clone)]
pub struct SshOptions {
    /// Connection timeout.
    pub connect_timeout: Duration,
    /// Command execution timeout.
    pub command_timeout: Duration,
    /// Server keepalive interval (`ssh -o ServerAliveInterval`).
    ///
    /// Defaults to `None` (OpenSSH default; keepalive disabled).
    pub server_alive_interval: Option<Duration>,
    /// How long the SSH ControlMaster should remain alive while idle.
    ///
    /// `None` preserves the OpenSSH crate default (`ControlPersist=yes`).
    /// `Some(0s)` sets `ControlPersist=no` (close after initial connection).
    pub control_persist_idle: Option<Duration>,
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
            server_alive_interval: None,
            control_persist_idle: None,
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

#[cfg(test)]
mod retry_tests {
    use super::*;
    use crate::test_guard;

    #[test]
    fn test_retryable_transport_error_text() {
        let _guard = test_guard!();
        assert!(is_retryable_transport_error_text(
            "ssh: connect to host 1.2.3.4 port 22: Connection timed out"
        ));
        assert!(is_retryable_transport_error_text(
            "kex_exchange_identification: Connection reset by peer"
        ));
        assert!(is_retryable_transport_error_text("Broken pipe"));
        assert!(is_retryable_transport_error_text("Network is unreachable"));
    }

    #[test]
    fn test_non_retryable_transport_error_text() {
        let _guard = test_guard!();
        assert!(!is_retryable_transport_error_text(
            "Permission denied (publickey)."
        ));
        assert!(!is_retryable_transport_error_text(
            "Host key verification failed."
        ));
        assert!(!is_retryable_transport_error_text(
            "Could not resolve hostname worker.example.com: Name or service not known"
        ));
        assert!(!is_retryable_transport_error_text(
            "Identity file /nope/id_rsa not accessible: No such file or directory"
        ));
    }
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

        if let Some(interval) = self.options.server_alive_interval {
            builder.server_alive_interval(interval);
        }

        if let Some(idle) = self.options.control_persist_idle {
            if idle.is_zero() {
                builder.control_persist(ControlPersist::ClosedAfterInitialConnection);
            } else {
                match usize::try_from(idle.as_secs()) {
                    Ok(secs) => {
                        if let Some(nonzero) = NonZeroUsize::new(secs) {
                            builder.control_persist(ControlPersist::IdleFor(nonzero));
                        } else {
                            builder.control_persist(ControlPersist::ClosedAfterInitialConnection);
                        }
                    }
                    Err(_) => {
                        warn!(
                            "control_persist_idle too large ({}s); ignoring override",
                            idle.as_secs()
                        );
                    }
                }
            }
        }

        // Add identity file if specified
        let identity_path = shellexpand::tilde(&self.config.identity_file);
        if Path::new(identity_path.as_ref()).exists() {
            builder.keyfile(identity_path.as_ref());
        }

        // Enable control master for connection reuse
        if self.options.control_master {
            // Use a short control directory path to stay within the Unix domain
            // socket path limit (104 bytes on macOS, 108 on Linux).  The openssh
            // crate appends a `%C` hash (~32 chars) to form the socket filename,
            // so the directory path itself must be short.
            //
            // On macOS `std::env::temp_dir()` returns a long path under
            // /var/folders/…/T/ which, combined with the hash, exceeds 104 bytes.
            // We therefore prefer `~/.ssh/rch` (short, stable, correct perms).
            let control_dir = {
                let home_ssh = dirs::home_dir().map(|h| h.join(".ssh").join("rch"));

                if let Some(ref dir) = home_ssh {
                    dir.clone()
                } else if let Some(runtime_dir) = dirs::runtime_dir() {
                    runtime_dir.join("rch-ssh")
                } else {
                    let username = whoami::username().unwrap_or_else(|_| "unknown".to_string());
                    std::env::temp_dir().join(format!("rch-ssh-{}", username))
                }
            };

            if let Err(e) = std::fs::create_dir_all(&control_dir) {
                warn!(
                    "Failed to create SSH control directory {:?}: {}",
                    control_dir, e
                );
            } else {
                // Set restrictive permissions (0700) to prevent symlink attacks
                // and unauthorized access to SSH control sockets
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    if let Err(e) = std::fs::set_permissions(
                        &control_dir,
                        std::fs::Permissions::from_mode(0o700),
                    ) {
                        warn!(
                            "Failed to set permissions on SSH control directory {:?}: {}",
                            control_dir, e
                        );
                    }
                }
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
        debug!(
            "Executing on {}: {}",
            self.config.id,
            crate::util::mask_sensitive_command(command)
        );

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
                    let reader = BufReader::new(out);
                    let mut buf = String::new();
                    reader
                        .take(MAX_OUTPUT_SIZE)
                        .read_to_string(&mut buf)
                        .await?;
                    Ok::<String, anyhow::Error>(buf)
                } else {
                    Ok(String::new())
                }
            };

            let stderr_fut = async {
                if let Some(err) = stderr_handle {
                    let reader = BufReader::new(err);
                    let mut buf = String::new();
                    reader
                        .take(MAX_OUTPUT_SIZE)
                        .read_to_string(&mut buf)
                        .await?;
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
                // Timeout occurred. The inner future (which owns `child`) is dropped,
                // but dropping an openssh RemoteChild does NOT kill the remote process
                // if a ControlMaster is active. The remote process will only terminate
                // when the caller disconnects the SshClient (closing the Session/
                // ControlMaster). Callers should ensure disconnect() is called after
                // a timeout to avoid leaked remote processes.
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
        debug!(
            "Executing (streaming) on {}: {}",
            self.config.id,
            crate::util::mask_sensitive_command(command)
        );

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
                // Timeout occurred - the spawned reader tasks will terminate when they
                // try to send on rx (which is dropped when this scope exits).
                // The child process is also dropped here, but openssh may not kill
                // the remote process immediately. Log the situation for visibility.
                //
                // Note: The reader tasks are detached (tokio::spawn) so they continue
                // briefly until they hit EOF or the send fails. This is acceptable
                // because they're lightweight and will terminate quickly once the
                // channel closes.
                warn!(
                    "Command (streaming) timed out on {} after {:?}, cleaning up",
                    self.config.id, self.options.command_timeout
                );
                // rx is dropped here, which will cause senders to fail on next send
                // child is dropped here, which signals termination to openssh
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

        // Fast path: check if we already have a valid connection (read lock)
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

        // Slow path: acquire write lock and double-check before creating connection
        // This prevents TOCTOU race where multiple tasks create duplicate connections
        let mut connections = self.connections.write().await;

        // Double-check under write lock: another task may have added a connection
        if let Some(client) = connections.get(&worker_id) {
            let client_guard = client.read().await;
            if client_guard.is_connected() {
                debug!(
                    "Reusing connection added by concurrent task to {}",
                    worker_id
                );
                return Ok(client.clone());
            }
            // Connection exists but is disconnected - we'll replace it below
        }

        // Create new connection while holding write lock to prevent races
        // Note: holding lock during connect() is acceptable here because:
        // 1. Connections are per-worker, so only requests to same worker contend
        // 2. Alternative (release lock during connect) has worse race conditions
        let mut client = SshClient::new(config.clone(), self.options.clone());
        client.connect().await?;

        let client = Arc::new(RwLock::new(client));
        connections.insert(worker_id.clone(), client.clone());

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
    use crate::test_guard;

    #[test]
    fn test_command_result_success() {
        let _guard = test_guard!();
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
        let _guard = test_guard!();
        let options = SshOptions::default();
        assert_eq!(options.connect_timeout, Duration::from_secs(10));
        assert_eq!(options.command_timeout, Duration::from_secs(300));
        assert!(options.server_alive_interval.is_none());
        assert!(options.control_persist_idle.is_none());
        assert!(options.control_master);
    }

    #[test]
    fn test_ssh_client_creation() {
        let _guard = test_guard!();
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
        let _guard = test_guard!();
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
        // shell_escape uses '\'' style (end string, escaped quote, start string)
        assert!(prefix.prefix.contains("QUOTED='a'\\''b'"));
        assert!(!prefix.prefix.contains("MISSING="));
        assert!(!prefix.prefix.contains("BADVAL="));
        assert!(prefix.rejected.contains(&"BADVAL".to_string()));
        assert!(prefix.rejected.contains(&"BAD=KEY".to_string()));
        assert_eq!(
            prefix.applied,
            vec!["RUSTFLAGS".to_string(), "QUOTED".to_string()]
        );
    }

    // ==========================================================================
    // Proptest: SSH command escaping with special chars (bd-2elj)
    // ==========================================================================

    mod proptest_ssh_escaping {
        use super::*;
        use proptest::prelude::*;
        use std::collections::HashMap;

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(1000))]

            // Test 1: is_valid_env_key never panics on arbitrary strings
            #[test]
            fn test_is_valid_env_key_no_panic(s in ".*") {
        let _guard = test_guard!();
                let _ = is_valid_env_key(&s);
            }

            // Test 2: Valid env keys start with letter/_ and contain only alphanum/_
            #[test]
            fn test_is_valid_env_key_accepts_valid(
                first in "[a-zA-Z_]",
                rest in "[a-zA-Z0-9_]{0,50}"
            ) {
        let _guard = test_guard!();
                let key = format!("{}{}", first, rest);
                prop_assert!(is_valid_env_key(&key), "Should accept valid key: {}", key);
            }

            // Test 3: Env keys starting with digit are invalid
            #[test]
            fn test_is_valid_env_key_rejects_digit_start(
                digit in "[0-9]",
                rest in "[a-zA-Z0-9_]{0,20}"
            ) {
        let _guard = test_guard!();
                let key = format!("{}{}", digit, rest);
                prop_assert!(!is_valid_env_key(&key), "Should reject digit-start key: {}", key);
            }

            // Test 4: shell_escape_value never panics on arbitrary strings
            #[test]
            fn test_shell_escape_value_no_panic(s in ".*") {
        let _guard = test_guard!();
                let _ = shell_escape_value(&s);
            }

            // Test 5: shell_escape_value rejects newlines/carriage returns/NUL
            #[test]
            fn test_shell_escape_value_rejects_unsafe(
                prefix in "[a-zA-Z0-9 ]{0,10}",
                bad_char in "[\n\r\0]",
                suffix in "[a-zA-Z0-9 ]{0,10}"
            ) {
        let _guard = test_guard!();
                let value = format!("{}{}{}", prefix, bad_char, suffix);
                prop_assert!(shell_escape_value(&value).is_none(),
                    "Should reject value with unsafe char: {:?}", value);
            }

            // Test 6: shell_escape_value handles safe values
            #[test]
            fn test_shell_escape_value_accepts_safe(s in "[a-zA-Z0-9 !@#$%^&*()_+=\\-\\[\\]{}|;:,./<>?]{0,100}") {
                // These don't contain \n, \r, or \0
                let result = shell_escape_value(&s);
                prop_assert!(result.is_some(), "Should accept safe value: {:?}", s);

                // shell_escape only quotes values that need it (contain special chars)
                // Simple alphanumeric strings may be returned unquoted
                let escaped = result.unwrap();
                if s.chars().any(|c| !c.is_ascii_alphanumeric() && c != '_') {
                    // Values with special chars should be quoted
                    prop_assert!(escaped.starts_with('\'') || escaped.contains('\''),
                        "Value with special chars should be quoted: {:?} -> {:?}", s, escaped);
                }
            }

            // Test 7: shell_escape_value properly escapes single quotes
            #[test]
            fn test_shell_escape_value_escapes_quotes(
                prefix in "[a-zA-Z0-9]{0,10}",
                suffix in "[a-zA-Z0-9]{0,10}"
            ) {
        let _guard = test_guard!();
                let value = format!("{}'{}", prefix, suffix);
                let result = shell_escape_value(&value);
                prop_assert!(result.is_some());

                let escaped = result.unwrap();
                // shell_escape uses '\'' style (end string, escaped quote, start string)
                prop_assert!(escaped.contains("'\\''"),
                    "Should escape single quote: {} -> {}", value, escaped);
            }

            // Test 8: build_env_prefix never panics
            #[test]
            fn test_build_env_prefix_no_panic(
                keys in prop::collection::vec("[a-zA-Z_][a-zA-Z0-9_]{0,10}", 0..10),
                values in prop::collection::vec(".*", 0..10)
            ) {
                let mut env = HashMap::new();
                for (i, key) in keys.iter().enumerate() {
                    if let Some(val) = values.get(i) {
                        env.insert(key.clone(), val.clone());
                    }
                }

                let allowlist: Vec<String> = keys;
                let _ = build_env_prefix(&allowlist, |k| env.get(k).cloned());
            }

            // Test 9: build_env_prefix rejects invalid keys (non-empty after trim)
            #[test]
            fn test_build_env_prefix_rejects_invalid_keys(
                // Generate keys that are invalid even after trimming
                invalid_key in "[0-9][a-zA-Z0-9_]{0,10}"  // Starts with digit
            ) {
        let _guard = test_guard!();
                let mut env = HashMap::new();
                env.insert(invalid_key.clone(), "value".to_string());

                let allowlist = vec![invalid_key.clone()];
                let prefix = build_env_prefix(&allowlist, |k| env.get(k).cloned());

                // Key should be rejected since it starts with a digit
                prop_assert!(!is_valid_env_key(&invalid_key),
                    "Key should be invalid: {}", invalid_key);
                prop_assert!(prefix.rejected.contains(&invalid_key),
                    "Should reject invalid key: {}", invalid_key);
                prop_assert!(prefix.prefix.is_empty());
            }

            // Test 10: build_env_prefix handles missing values gracefully
            #[test]
            fn test_build_env_prefix_missing_values(
                keys in prop::collection::vec("[A-Z_][A-Z0-9_]{0,10}", 1..5)
            ) {
                // Empty env - all keys missing
                let env: HashMap<String, String> = HashMap::new();
                let prefix = build_env_prefix(&keys, |k| env.get(k).cloned());

                // Should be empty prefix since no values found
                prop_assert!(prefix.prefix.is_empty(), "Should be empty when no values");
                prop_assert!(prefix.applied.is_empty());
                // Missing values don't count as rejected
                prop_assert!(prefix.rejected.is_empty());
            }
        }

        // Targeted edge case tests
        #[test]
        fn test_shell_escape_edge_cases() {
            let _guard = test_guard!();
            // Empty string
            let result = shell_escape_value("");
            assert_eq!(result, Some("''".to_string()));

            // Just single quote - shell_escape uses '\'' style (end string, escaped quote, start string)
            let result = shell_escape_value("'");
            assert_eq!(result, Some("''\\'''".to_string()));

            // Multiple single quotes
            let result = shell_escape_value("'''");
            assert!(result.is_some());
            let escaped = result.unwrap();
            // shell_escape uses '\'' style for each single quote
            assert_eq!(escaped.matches("'\\''").count(), 3);

            // Unicode
            let result = shell_escape_value("日本語");
            assert!(result.is_some());

            // Emoji
            let result = shell_escape_value("🔥🚀");
            assert!(result.is_some());

            // Mixed quotes and special chars
            let result = shell_escape_value("it's a \"test\" with $vars");
            assert!(result.is_some());
        }

        #[test]
        fn test_is_valid_env_key_edge_cases() {
            let _guard = test_guard!();
            // Empty
            assert!(!is_valid_env_key(""));

            // Single underscore
            assert!(is_valid_env_key("_"));

            // Single letter
            assert!(is_valid_env_key("A"));

            // Typical env vars
            assert!(is_valid_env_key("PATH"));
            assert!(is_valid_env_key("HOME"));
            assert!(is_valid_env_key("RUSTFLAGS"));
            assert!(is_valid_env_key("CC"));
            assert!(is_valid_env_key("_PRIVATE"));
            assert!(is_valid_env_key("MY_VAR_123"));

            // Invalid: starts with number
            assert!(!is_valid_env_key("1VAR"));
            assert!(!is_valid_env_key("123"));

            // Invalid: contains special chars
            assert!(!is_valid_env_key("MY-VAR"));
            assert!(!is_valid_env_key("MY.VAR"));
            assert!(!is_valid_env_key("MY VAR"));
            assert!(!is_valid_env_key("MY=VAR"));

            // Invalid: Unicode
            assert!(!is_valid_env_key("日本語"));
            assert!(!is_valid_env_key("VAR🔥"));
        }

        #[test]
        fn test_build_env_prefix_integration() {
            let _guard = test_guard!();
            // Complex scenario with mixed valid/invalid
            let mut env = HashMap::new();
            env.insert("VALID".to_string(), "simple".to_string());
            env.insert("WITH_QUOTE".to_string(), "it's here".to_string());
            env.insert("NEWLINE".to_string(), "line1\nline2".to_string());
            env.insert("UNICODE".to_string(), "日本語".to_string());
            env.insert("EMPTY".to_string(), String::new());
            env.insert("123INVALID".to_string(), "value".to_string());

            let allowlist = vec![
                "VALID".to_string(),
                "WITH_QUOTE".to_string(),
                "NEWLINE".to_string(),
                "UNICODE".to_string(),
                "EMPTY".to_string(),
                "123INVALID".to_string(),
                "MISSING".to_string(),
            ];

            let prefix = build_env_prefix(&allowlist, |k| env.get(k).cloned());

            // VALID should be applied
            assert!(prefix.applied.contains(&"VALID".to_string()));
            // shell_escape doesn't quote simple alphanumeric strings
            assert!(prefix.prefix.contains("VALID=simple"));

            // WITH_QUOTE should be applied with escaped quote
            assert!(prefix.applied.contains(&"WITH_QUOTE".to_string()));

            // NEWLINE should be rejected (unsafe value)
            assert!(prefix.rejected.contains(&"NEWLINE".to_string()));

            // UNICODE should be applied (safe unicode)
            assert!(prefix.applied.contains(&"UNICODE".to_string()));

            // EMPTY should be applied
            assert!(prefix.applied.contains(&"EMPTY".to_string()));

            // 123INVALID should be rejected (invalid key)
            assert!(prefix.rejected.contains(&"123INVALID".to_string()));

            // MISSING should not appear in either list (not found = silently ignored)
            assert!(!prefix.applied.contains(&"MISSING".to_string()));
            assert!(!prefix.rejected.contains(&"MISSING".to_string()));
        }

        #[test]
        fn test_shell_escape_roundtrip_safety() {
            let _guard = test_guard!();
            // Values that when escaped and passed through shell should reconstruct original
            let test_values = [
                "simple",
                "with spaces",
                "with\ttab",
                "special!@#$%^&*()",
                "quoted\"value",
                "path/to/file",
                "-flag",
                "--long-flag=value",
                "",
            ];

            for value in &test_values {
                let escaped = shell_escape_value(value);
                assert!(escaped.is_some(), "Should escape: {:?}", value);
            }
        }
    }
}
