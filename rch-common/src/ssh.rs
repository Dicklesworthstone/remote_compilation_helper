//! SSH client utilities for remote command execution.
//!
//! Provides connection management, command execution, and pooling support
//! for the remote compilation pipeline.
//!
//! This module is only available on Unix platforms (requires openssh crate).

use crate::types::{WorkerConfig, WorkerId, declared_os};
use anyhow::{Context, Result};
use openssh::{ControlPersist, KnownHosts, Session, SessionBuilder, Stdio};
use std::collections::HashMap;
use std::ffi::OsString;
use std::num::NonZeroUsize;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
use tokio::sync::{RwLock, mpsc};
use tracing::{debug, error, warn};

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

const HEALTH_CHECK_COMMAND: &str = "echo ok";

fn is_expected_health_check_output(stdout: &str) -> bool {
    stdout
        .trim()
        .lines()
        .last()
        .is_some_and(is_health_check_sentinel)
}

fn is_health_check_sentinel(line: &str) -> bool {
    matches!(line.trim(), "ok")
}

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
    /// Only applies when `control_master` is true (connection reuse). `Some(n)`
    /// with n > 0 keeps the master warm for n idle seconds (`ControlPersist=Ns`).
    /// `Some(0s)`/`None`, or ANY non-mux per-call session, closes the master
    /// after the initial connection (`ControlPersist=no`). The OpenSSH crate
    /// `ControlPersist=yes` (forever) default is never used — it leaked a
    /// master process per per-call SSH. See `control_persist_mode`.
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
            // Default to a plain SSH session. ControlMaster is an optimization
            // and stale local control sockets can poison otherwise healthy
            // connections. Callers that explicitly want mux reuse can opt in.
            control_master: false,
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

    fn is_configured_for(&self, config: &WorkerConfig) -> bool {
        self.config.id == config.id
            && self.config.host == config.host
            && self.config.user == config.user
            && self.config.identity_file == config.identity_file
    }

    /// Connect to the remote worker.
    pub async fn connect(&mut self) -> Result<()> {
        if self.session.is_some() {
            debug!("Already connected to {}", self.config.id);
            return Ok(());
        }

        let destination = format!("{}@{}", self.config.user, self.config.host);
        debug!("Connecting to {} via SSH...", destination);

        let session = match self
            .connect_with_mode(&destination, self.options.control_master)
            .await
        {
            Ok(session) => session,
            Err(primary_error) if self.options.control_master => {
                warn!(
                    "SSH ControlMaster connection to {} failed ({}). Retrying without ControlMaster.",
                    destination, primary_error
                );
                self.connect_with_mode(&destination, false)
                    .await
                    .with_context(|| {
                        format!(
                            "Failed to connect to {} after retrying without ControlMaster",
                            destination
                        )
                    })?
            }
            Err(primary_error) => {
                return Err(primary_error)
                    .with_context(|| format!("Failed to connect to {}", destination));
            }
        };

        // debug, not info: the telemetry pool connects to every worker each poll
        // cycle, so at info this floods the daemon log (8M+ lines / multi-GB).
        debug!("Connected to {} ({})", self.config.id, self.config.host);
        self.session = Some(session);
        Ok(())
    }

    async fn connect_with_mode(&self, destination: &str, control_master: bool) -> Result<Session> {
        let mut builder = SessionBuilder::default();
        self.configure_builder(&mut builder, control_master);

        builder.connect(destination).await.with_context(|| {
            if control_master {
                format!(
                    "Failed to connect to {} with ControlMaster enabled",
                    destination
                )
            } else {
                format!(
                    "Failed to connect to {} with ControlMaster disabled",
                    destination
                )
            }
        })
    }

    fn configure_builder(&self, builder: &mut SessionBuilder, control_master: bool) {
        let known_hosts = match self.options.known_hosts {
            KnownHostsPolicy::Strict => KnownHosts::Strict,
            KnownHostsPolicy::Add => KnownHosts::Add,
            KnownHostsPolicy::AcceptAll => KnownHosts::Accept,
        };

        builder
            .known_hosts_check(known_hosts)
            .connect_timeout(self.options.connect_timeout);

        if let Some(interval) = self.options.server_alive_interval {
            builder.server_alive_interval(interval);
        }

        // Add identity file if specified
        let identity_path = shellexpand::tilde(&self.config.identity_file);
        if Path::new(identity_path.as_ref()).exists() {
            builder.keyfile(identity_path.as_ref());
        }

        // Always pin ControlPersist explicitly. The openssh crate ALWAYS
        // spawns a control-master; leaving it unset defaults to
        // `ControlPersist=yes` (Forever), which leaks a master process for
        // every short-lived per-call SSH (telemetry/health/capabilities run
        // with control_master=false). ClosedAfterInitialConnection lets
        // non-mux masters self-terminate; only the explicit mux-reuse path
        // with a configured idle keeps a warm master.
        match control_persist_mode(control_master, self.options.control_persist_idle) {
            ControlPersistMode::IdleFor(nonzero) => {
                builder.control_persist(ControlPersist::IdleFor(nonzero));
            }
            ControlPersistMode::TooLarge(secs) => {
                warn!("control_persist_idle too large ({secs}s); closing after initial connection");
                builder.control_persist(ControlPersist::ClosedAfterInitialConnection);
            }
            ControlPersistMode::Closed => {
                builder.control_persist(ControlPersist::ClosedAfterInitialConnection);
            }
        }

        // Control-master socket directory only matters when reusing connections.
        if control_master {
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
    }

    /// Disconnect from the worker.
    pub async fn disconnect(&mut self) -> Result<()> {
        if let Some(session) = self.session.take() {
            debug!("Disconnecting from {}", self.config.id);
            session.close().await?;
            // debug, not info: paired with the connect log above; floods at info.
            debug!("Disconnected from {}", self.config.id);
        }
        Ok(())
    }

    /// Force a fresh connection, dropping any existing (possibly dead) session.
    ///
    /// [`connect`](Self::connect) is a no-op when a `Session` object already
    /// exists, so a pooled client whose underlying SSH ControlMaster has died
    /// cannot recover through it. `reconnect` tears the stale session down first
    /// (closing it best-effort — a dead master may itself error on close, but
    /// [`disconnect`](Self::disconnect) `take()`s the session before closing so
    /// it is gone regardless) and then establishes a new one.
    pub async fn reconnect(&mut self) -> Result<()> {
        if let Err(e) = self.disconnect().await {
            debug!(
                "Ignoring error closing stale session to {} before reconnect: {}",
                self.config.id, e
            );
        }
        self.connect().await
    }

    /// Execute a command on the remote worker using this client's configured
    /// command timeout.
    pub async fn execute(&self, command: &str) -> Result<CommandResult> {
        self.execute_with_timeout(command, self.options.command_timeout)
            .await
    }

    /// Execute a command on the remote worker with an explicit per-call timeout.
    ///
    /// Used by the connection pool ([`SshPool::run_with_timeout`]) so a single
    /// pooled client can serve calls with different timeouts (a fast health
    /// probe vs. a slower cleanup) without mutating the shared client options.
    pub async fn execute_with_timeout(
        &self,
        command: &str,
        command_timeout: Duration,
    ) -> Result<CommandResult> {
        // Windows fallback (bd-kzy2x): the openssh crate cannot execute
        // commands on Windows OpenSSH (the slave never completes the
        // command channel), so we dispatch through the system `ssh` binary
        // for declared-OS Windows workers. The connect path above is
        // untouched and still uses the openssh crate (it succeeds); only
        // the execute step swaps. Linux / unlabelled workers keep the
        // openssh-crate path verbatim.
        if prefers_system_ssh(&self.config) {
            return system_ssh_execute(
                &self.config,
                command,
                command_timeout,
                self.options
                    .server_alive_interval
                    .unwrap_or(Duration::from_secs(2)),
            )
            .await;
        }

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
                    let mut take = reader.take(MAX_OUTPUT_SIZE);
                    let mut buf = String::new();
                    take.read_to_string(&mut buf).await?;
                    // Drain the rest to prevent SIGPIPE or blocking
                    let mut reader = take.into_inner();
                    let mut sink = tokio::io::sink();
                    tokio::io::copy(&mut reader, &mut sink).await?;
                    if buf.len() >= MAX_OUTPUT_SIZE as usize {
                        buf.push_str("\n...[output truncated]...\n");
                    }
                    Ok::<String, anyhow::Error>(buf)
                } else {
                    Ok(String::new())
                }
            };

            let stderr_fut = async {
                if let Some(err) = stderr_handle {
                    let reader = BufReader::new(err);
                    let mut take = reader.take(MAX_OUTPUT_SIZE);
                    let mut buf = String::new();
                    take.read_to_string(&mut buf).await?;
                    // Drain the rest to prevent SIGPIPE or blocking
                    let mut reader = take.into_inner();
                    let mut sink = tokio::io::sink();
                    tokio::io::copy(&mut reader, &mut sink).await?;
                    if buf.len() >= MAX_OUTPUT_SIZE as usize {
                        buf.push_str("\n...[output truncated]...\n");
                    }
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

        match tokio::time::timeout(command_timeout, execution_future).await {
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
                    self.config.id, command_timeout
                );
                anyhow::bail!("Command timed out after {:?}", command_timeout);
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
                        if stdout_acc.len() < MAX_OUTPUT_SIZE as usize {
                            stdout_acc.push_str(&line);
                            if stdout_acc.len() >= MAX_OUTPUT_SIZE as usize {
                                stdout_acc.push_str("\n...[output truncated]...\n");
                            }
                        }
                    }
                    StreamEvent::Stderr(line) => {
                        on_stderr(&line);
                        if stderr_acc.len() < MAX_OUTPUT_SIZE as usize {
                            stderr_acc.push_str(&line);
                            if stderr_acc.len() >= MAX_OUTPUT_SIZE as usize {
                                stderr_acc.push_str("\n...[output truncated]...\n");
                            }
                        }
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
        match self.execute(HEALTH_CHECK_COMMAND).await {
            Ok(result) => Ok(result.success() && is_expected_health_check_output(&result.stdout)),
            Err(e) => {
                warn!("Health check failed for {}: {}", self.config.id, e);
                Ok(false)
            }
        }
    }
}

/// Derive the per-worker [`SshOptions`] a pool hands to each pooled
/// [`SshClient`].
///
/// POLICY — Windows workers never get ControlMaster multiplexing. Windows
/// OpenSSH has no ControlMaster support: a pooled (multiplexed) session
/// appears to connect, then every command over it hangs and dies at the
/// command stage ("Failed to wait for command completion"), so each pooled
/// probe fails deterministically and the daemon marks the worker permanently
/// unreachable even though fresh one-shot SSH to the same host succeeds
/// (2026-08-30 incident: worker `wsurf`, `os = "windows"` — healthy via
/// `rch workers probe` fresh connections, "unreachable" via every pooled
/// health check). Applying the override HERE — the single place pooled
/// clients are constructed from the pool's global options — fixes every pool
/// consumer (daemon shared build/telemetry pool, dedicated health pool) at
/// once. [`SshClient::connect`]'s ControlMaster-failure retry cannot catch
/// this class: the mux connect does not fail, the commands do.
///
/// `control_persist_idle` needs no separate neutralization: it is consulted
/// only when `control_master` is true (see [`control_persist_mode`]), so it
/// is inert once mux is disabled and is left verbatim. Non-Windows workers
/// get the pool options verbatim in full.
fn pooled_client_options(pool_options: &SshOptions, config: &WorkerConfig) -> SshOptions {
    let mut options = pool_options.clone();
    if declared_os(&config.tags).as_deref() == Some("windows") {
        options.control_master = false;
    }
    options
}

/// System-ssh command-execution fallback (bd-kzy2x).
///
/// The `openssh` crate 0.11.6 cannot execute commands on Windows OpenSSH
/// regardless of `control_master` / `control_persist` / keepalive settings:
/// the slave never completes the command channel and every command hangs at
/// the execute stage even though the connect succeeds. The CLI `ssh` binary
/// speaks the OpenSSH wire protocol directly and works fine. For workers that
/// declare `os = "windows"` we therefore spawn the system `ssh` binary at
/// command-execution time, mirroring the proven system-ssh pattern already
/// used by the fleet preflight path (`rch/src/fleet/ssh.rs::SshExecutor`) and
/// the CLI worker init / probe paths. The connect path stays the openssh
/// crate (it succeeds) — the fallback is purely an execute-time dispatch
/// inside `SshClient::execute_with_timeout`.
///
/// Policy key (kept in lockstep with the existing pool-layer override
/// `pooled_client_options`): `declared_os(&config.tags) == Some("windows")`.
/// `os = "Windows"` is case-normalized by `declared_os` so both spellings
/// route through the same fallback.

/// Should `SshClient::execute_with_timeout` dispatch through the system `ssh`
/// binary for this worker instead of the `openssh` crate?
pub(crate) fn prefers_system_ssh(config: &WorkerConfig) -> bool {
    declared_os(&config.tags).as_deref() == Some("windows")
}

/// Build the argv for the system-ssh fallback, mirroring the proven CLI
/// system-ssh pattern (see `rch/src/fleet/ssh.rs::SshExecutor::build_ssh_args`
/// and `rch/src/commands/workers_init.rs`). Pure / testable: no process is
/// spawned. The first element is the program name `"ssh"` so the vector can
/// be passed straight to `Command::new` callers that prefer the explicit
/// first arg, but the standard `Command::new("ssh").args(...)` callers can
/// skip it — see `system_ssh_execute` which drops it.
///
/// Argv layout:
/// `ssh -i <identity_file> -o BatchMode=yes -o ConnectTimeout=8 -o
///   StrictHostKeyChecking=accept-new -o ServerAliveInterval=<secs>
///   <user>@<host> <command>`
///
/// `WorkerConfig` has no port field today; the SSH port is carried as part
/// of the host (`host:port`) and SSH's own config handles non-default
/// ports, so the argv has no `-p` flag. The 8s `ConnectTimeout` matches the
/// fleet SshExecutor default (`DEFAULT_CONNECT_TIMEOUT_SECS = 10` would be
/// the natural match too — kept at 8 to match the FINDINGS spec exactly).
/// `server_alive_interval` is rounded up to 1s minimum when non-zero to
/// avoid `ServerAliveInterval=0` (which OpenSSH treats as "disable
/// keepalives" — fine — but matches the spec "0 -> omit" intent).
pub(crate) fn system_ssh_argv(
    config: &WorkerConfig,
    command: &str,
    server_alive_interval: Duration,
) -> Vec<OsString> {
    let identity_path = shellexpand::tilde(&config.identity_file);
    let destination = format!("{}@{}", config.user, config.host);

    let mut argv: Vec<OsString> = Vec::with_capacity(10);
    argv.push(OsString::from("ssh"));
    argv.push(OsString::from("-i"));
    argv.push(OsString::from(identity_path.as_ref()));
    argv.push(OsString::from("-o"));
    argv.push(OsString::from("BatchMode=yes"));
    argv.push(OsString::from("-o"));
    argv.push(OsString::from("ConnectTimeout=8"));
    argv.push(OsString::from("-o"));
    argv.push(OsString::from("StrictHostKeyChecking=accept-new"));
    if !server_alive_interval.is_zero() {
        // `0` means "no keepalive" in OpenSSH; otherwise emit the requested
        // interval in whole seconds (sub-second values are rounded up to 1s
        // because OpenSSH only accepts integer seconds for this option).
        let secs = server_alive_interval.as_secs().max(1);
        argv.push(OsString::from("-o"));
        argv.push(OsString::from(format!("ServerAliveInterval={secs}")));
    }
    argv.push(OsString::from(destination));
    argv.push(OsString::from(command));
    argv
}

/// Execute a command on a Windows worker via the system `ssh` binary.
///
/// Mirrors the openssh-crate path's size cap (`MAX_OUTPUT_SIZE`), timeout
/// semantics (tokio timeout that bails on expiry), and `CommandResult`
/// shape. The local ssh process is set `kill_on_drop(true)` so a timeout
/// cannot leak an `ssh` child — the openssh-crate timeout path likewise
/// relies on the caller to drop the child (and warns about the leak risk);
/// here we get a hard SIGKILL on drop instead. Output reads are
/// concurrent over `tokio::io::BufReader` to avoid a single-stream back-
/// pressure deadlock (same pattern as the openssh path). `env_clear()` is
/// used so a hostile / noisy environment from the calling daemon cannot
/// perturb the local `ssh` invocation; SSH agent forwarding and standard
/// paths still resolve via `~/.ssh/config` because ssh reads them from the
/// filesystem, not the env.
pub(crate) async fn system_ssh_execute(
    config: &WorkerConfig,
    command: &str,
    command_timeout: Duration,
    server_alive_interval: Duration,
) -> Result<CommandResult> {
    use std::process::Stdio;
    use tokio::io::AsyncReadExt;
    use tokio::process::Command;

    let argv = system_ssh_argv(config, command, server_alive_interval);
    // Drop the program name — `Command::new("ssh")` is the standard form.
    let args = argv.into_iter().skip(1);

    let start = std::time::Instant::now();
    debug!(
        "system-ssh executing on {}: {}",
        config.id,
        crate::util::mask_sensitive_command(command)
    );

    let mut child = Command::new("ssh")
        .args(args)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .with_context(|| {
            format!(
                "failed to spawn system ssh for {} (Windows fallback)",
                config.id
            )
        })?;

    let execution = async {
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();

        let stdout_fut = async {
            let mut buf = String::new();
            if let Some(out) = stdout {
                let mut handle = out.take(MAX_OUTPUT_SIZE);
                handle.read_to_string(&mut buf).await?;
            }
            Ok::<String, anyhow::Error>(buf)
        };
        let stderr_fut = async {
            let mut buf = String::new();
            if let Some(err) = stderr {
                let mut handle = err.take(MAX_OUTPUT_SIZE);
                handle.read_to_string(&mut buf).await?;
            }
            Ok::<String, anyhow::Error>(buf)
        };

        let (stdout, stderr) = tokio::try_join!(stdout_fut, stderr_fut)?;
        let status = child
            .wait()
            .await
            .with_context(|| "system ssh command failed to wait for completion")?;
        Ok::<_, anyhow::Error>((status, stdout, stderr))
    };

    match tokio::time::timeout(command_timeout, execution).await {
        Ok(result) => {
            let (status, stdout, stderr) = result?;
            let duration = start.elapsed();
            let exit_code = status.code().unwrap_or(-1);
            debug!(
                "system-ssh command completed on {} (exit={}, duration={}ms)",
                config.id,
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
            // `kill_on_drop(true)` ensures the local ssh process is
            // SIGKILLed when `child` drops here, so no ssh child can leak
            // even if the remote end is wedged. The remote shell is killed
            // too because the local ssh process holds the connection.
            warn!(
                "system-ssh command timed out on {} after {:?}",
                config.id, command_timeout
            );
            anyhow::bail!("Command timed out after {:?}", command_timeout);
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
    ///
    /// Validates liveness on borrow: a pooled `SshClient` reports
    /// [`is_connected`](SshClient::is_connected) purely from the presence of a
    /// `Session` object, which cannot detect that the underlying SSH
    /// ControlMaster has died (idle `ControlPersist` expiry, a network blip, or
    /// the remote `sshd` being restarted). Returning such a client hands the
    /// caller a dead master, and its next `execute()` fails with
    /// broken-pipe/connection-closed and no chance to recover. So before reusing
    /// a connected client this probes it with a lightweight health check, and on
    /// failure reconnects once under the per-worker write lock.
    pub async fn get_or_connect(&self, config: &WorkerConfig) -> Result<Arc<RwLock<SshClient>>> {
        let shared_client = self.get_or_create_client_entry(config).await;

        // Fast path: reuse only a session that is both present AND verified live.
        // The probe needs `&self` only (health_check → execute), so it runs under
        // a shared read lock and never blocks other borrowers of this worker.
        let reusable = {
            let guard = shared_client.read().await;
            guard.is_connected() && guard.health_check().await.unwrap_or(false)
        };
        if reusable {
            debug!("Reusing live connection to {}", config.id);
            return Ok(shared_client);
        }

        // Slow path: (re)connect under the per-worker write lock. Re-evaluate the
        // state here because another task may have connected/reconnected while we
        // waited for the lock, and to distinguish "never connected" (connect)
        // from "session exists but the master is dead" (reconnect).
        let mut client_guard = shared_client.write().await;
        if !client_guard.is_connected() {
            client_guard.connect().await?;
        } else if !client_guard.health_check().await.unwrap_or(false) {
            warn!(
                "Pooled SSH connection to {} failed liveness probe; reconnecting",
                config.id
            );
            client_guard.reconnect().await?;
        }
        // Drop write lock before returning
        drop(client_guard);

        Ok(shared_client)
    }

    async fn get_or_create_client_entry(&self, config: &WorkerConfig) -> Arc<RwLock<SshClient>> {
        let worker_id = config.id.clone();

        loop {
            let existing_client = {
                let connections = self.connections.read().await;
                connections.get(&worker_id).cloned()
            };

            if let Some(client) = existing_client {
                let is_configured_for_worker = {
                    let guard = client.read().await;
                    guard.is_configured_for(config)
                };
                if is_configured_for_worker {
                    return client;
                }

                let replacement = Arc::new(RwLock::new(SshClient::new(
                    config.clone(),
                    pooled_client_options(&self.options, config),
                )));
                let replaced = {
                    let mut connections = self.connections.write().await;
                    if connections
                        .get(&worker_id)
                        .is_some_and(|current| Arc::ptr_eq(current, &client))
                    {
                        connections.insert(worker_id.clone(), replacement.clone());
                        true
                    } else {
                        false
                    }
                };

                if replaced {
                    debug!(
                        "Replaced SSH connection entry for {} after endpoint config changed",
                        worker_id
                    );
                    return replacement;
                }

                continue;
            }

            let new_client = Arc::new(RwLock::new(SshClient::new(
                config.clone(),
                pooled_client_options(&self.options, config),
            )));
            let inserted = {
                let mut connections = self.connections.write().await;
                if connections.contains_key(&worker_id) {
                    false
                } else {
                    connections.insert(worker_id.clone(), new_client.clone());
                    true
                }
            };

            if inserted {
                return new_client;
            }
        }
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

    /// Run a single command on a worker over a POOLED (warm, reused) connection,
    /// bounded by `command_timeout`.
    ///
    /// This is the entry point daemon subsystems use instead of the throwaway
    /// `SshClient::new().connect()...execute()...disconnect()` dance. It
    /// [`get_or_connect`](Self::get_or_connect)s a live master (validating
    /// liveness on borrow and reconnecting a dead one), runs exactly one command,
    /// and — crucially — does NOT disconnect afterwards, keeping the
    /// ControlMaster warm for the next call. That is the whole point: reuse one
    /// master per worker instead of spawning (and, under the old code, leaking) a
    /// fresh master for every telemetry/health/cleanup poll.
    ///
    /// The per-command timeout is applied via a temporary [`SshOptions`] override
    /// on the pooled client so it does not disturb the pool's shared default
    /// (e.g. a long build vs. a short health probe). The connect timeout and
    /// control-master/persist settings come from the pool's options — except
    /// that Windows workers are ALWAYS non-mux (see [`pooled_client_options`]):
    /// Windows OpenSSH cannot multiplex, so a pooled mux session hangs at the
    /// command stage.
    pub async fn run_with_timeout(
        &self,
        config: &WorkerConfig,
        command: &str,
        command_timeout: Duration,
    ) -> Result<CommandResult> {
        let client = self.get_or_connect(config).await?;
        // Execute under a shared read lock: execute() needs only `&self`, so
        // concurrent callers for the same worker can multiplex over the one
        // master without serializing on a write lock.
        let guard = client.read().await;
        guard.execute_with_timeout(command, command_timeout).await
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
        assert!(!options.control_master);
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
    fn test_expected_health_check_output_accepts_sentinel_as_last_line() {
        let _guard = test_guard!();

        assert!(is_expected_health_check_output("ok\n"));
        assert!(is_expected_health_check_output("login banner\nok\n"));
        assert!(!is_expected_health_check_output(""));
        assert!(!is_expected_health_check_output("not ok\n"));
        assert!(!is_expected_health_check_output("ok\npost-command noise\n"));
    }

    fn worker_config(id: &str, host: &str, user: &str, identity_file: &str) -> WorkerConfig {
        WorkerConfig {
            id: WorkerId::new(id),
            host: host.to_string(),
            user: user.to_string(),
            identity_file: identity_file.to_string(),
            total_slots: 8,
            priority: 100,
            tags: vec!["rust".to_string()],
        }
    }

    #[test]
    fn test_ssh_client_configured_for_ignores_scheduling_fields() {
        let _guard = test_guard!();
        let config = worker_config("worker-a", "192.168.1.100", "ubuntu", "~/.ssh/id_rsa");
        let client = SshClient::new(config.clone(), SshOptions::default());

        let mut scheduling_only_change = config;
        scheduling_only_change.total_slots = 16;
        scheduling_only_change.priority = 250;
        scheduling_only_change.tags = vec!["rust".to_string(), "gpu".to_string()];

        assert!(client.is_configured_for(&scheduling_only_change));
    }

    #[test]
    fn test_ssh_client_configured_for_detects_endpoint_changes() {
        let _guard = test_guard!();
        let config = worker_config("worker-a", "192.168.1.100", "ubuntu", "~/.ssh/id_rsa");
        let client = SshClient::new(config, SshOptions::default());

        assert!(!client.is_configured_for(&worker_config(
            "worker-a",
            "192.168.1.101",
            "ubuntu",
            "~/.ssh/id_rsa",
        )));
        assert!(!client.is_configured_for(&worker_config(
            "worker-a",
            "192.168.1.100",
            "admin",
            "~/.ssh/id_rsa",
        )));
        assert!(!client.is_configured_for(&worker_config(
            "worker-a",
            "192.168.1.100",
            "ubuntu",
            "~/.ssh/other_key",
        )));
    }

    #[tokio::test]
    async fn test_ssh_pool_reuses_matching_disconnected_entry() {
        let _guard = test_guard!();
        let pool = SshPool::default();
        let config = worker_config("worker-a", "192.168.1.100", "ubuntu", "~/.ssh/id_rsa");

        let first = pool.get_or_create_client_entry(&config).await;
        let second = pool.get_or_create_client_entry(&config).await;

        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(pool.active_connections().await, 1);
    }

    #[tokio::test]
    async fn test_ssh_pool_reuses_single_entry_and_close_all_drops_to_zero() {
        // Leak guard: repeated borrows of the SAME worker must reuse ONE pool
        // entry (one warm master, not one-per-call), and close_all() must empty
        // the pool. Uses the entry-creation path (get_or_create_client_entry) so
        // the test needs no live SSH host; get_or_connect layers only a liveness
        // probe + reconnect on top of this same entry map.
        let _guard = test_guard!();
        let options = SshOptions {
            control_master: true,
            control_persist_idle: Some(Duration::from_secs(60)),
            ..Default::default()
        };
        let pool = SshPool::new(options);
        let config = worker_config("worker-a", "192.168.1.100", "ubuntu", "~/.ssh/id_rsa");

        for _ in 0..5 {
            let _entry = pool.get_or_create_client_entry(&config).await;
        }
        assert_eq!(
            pool.active_connections().await,
            1,
            "repeated borrows of one worker must reuse a single pool entry"
        );

        pool.close_all().await.expect("close_all should succeed");
        assert_eq!(
            pool.active_connections().await,
            0,
            "close_all must drop all pooled connections"
        );
    }

    #[test]
    fn test_pool_options_map_to_bounded_idle_persist() {
        // Leak guard: the pool's mux options must map to a BOUNDED
        // ControlPersist=IdleFor(60), never Closed/Forever. control_persist_mode
        // is the single decision point configure_builder uses.
        let _guard = test_guard!();
        assert_eq!(
            control_persist_mode(true, Some(Duration::from_secs(60))),
            ControlPersistMode::IdleFor(NonZeroUsize::new(60).unwrap()),
            "pool mux options must keep a warm master for a bounded idle window"
        );
    }

    // ======================================================================
    // Windows workers never get pooled ControlMaster (bd-wgbx9)
    // ======================================================================

    fn windows_worker_config(id: &str) -> WorkerConfig {
        let mut config = worker_config(id, "100.68.2.11", "jeffr", "~/.ssh/surfacebookje_key");
        config.tags = vec!["rust".to_string(), crate::types::os_tag("windows")];
        config
    }

    #[test]
    fn test_pooled_options_disable_control_master_for_windows_workers() {
        // Regression (bd-wgbx9): Windows OpenSSH has no ControlMaster — a
        // pooled mux session hangs at the command stage ("Failed to wait for
        // command completion") and the worker is falsely marked unreachable
        // while fresh one-shot SSH succeeds. Whatever the pool's global
        // options say, a Windows worker's pooled client must be non-mux.
        let _guard = test_guard!();
        let pool_mux = SshOptions {
            control_master: true,
            control_persist_idle: Some(Duration::from_secs(60)),
            ..Default::default()
        };
        let config = windows_worker_config("wsurf");

        let effective = pooled_client_options(&pool_mux, &config);
        assert!(
            !effective.control_master,
            "a Windows worker must never get a pooled ControlMaster"
        );
        // The override must be surgical: everything else stays verbatim.
        // control_persist_idle is left as-is because it is inert once mux is
        // off (control_persist_mode only reads it when control_master is true).
        assert_eq!(effective.connect_timeout, pool_mux.connect_timeout);
        assert_eq!(effective.command_timeout, pool_mux.command_timeout);
        assert_eq!(
            effective.server_alive_interval,
            pool_mux.server_alive_interval
        );
        assert_eq!(
            effective.control_persist_idle,
            pool_mux.control_persist_idle
        );
        assert_eq!(effective.known_hosts, pool_mux.known_hosts);

        // A pool that already disabled mux stays disabled.
        let pool_plain = SshOptions {
            control_master: false,
            ..pool_mux
        };
        assert!(!pooled_client_options(&pool_plain, &config).control_master);

        // declared_os normalizes case: `os = "Windows"` in workers.toml is the
        // same reserved tag and must disable mux too.
        let mut mixed_case = windows_worker_config("wsurf-2");
        mixed_case.tags = vec![crate::types::os_tag("Windows")];
        assert!(!pooled_client_options(&pool_mux, &mixed_case).control_master);
    }

    #[test]
    fn test_pooled_options_keep_pool_options_verbatim_for_non_windows_workers() {
        // Linux/unlabelled workers keep the pool's options VERBATIM — the
        // override must not degrade warm-master reuse for the rest of the
        // fleet, under either a mux or a hypothetical non-mux pool.
        let _guard = test_guard!();
        let pool_mux = SshOptions {
            control_master: true,
            control_persist_idle: Some(Duration::from_secs(60)),
            ..Default::default()
        };
        let linux = worker_config("contabo-a", "1.2.3.4", "root", "~/.ssh/id_rsa");
        let unlabelled = worker_config("contabo-b", "1.2.3.5", "root", "~/.ssh/id_rsa");

        for config in [&linux, &unlabelled] {
            let effective = pooled_client_options(&pool_mux, config);
            assert!(
                effective.control_master,
                "non-Windows workers keep the pool's mux setting"
            );
            assert_eq!(
                effective.control_persist_idle,
                pool_mux.control_persist_idle
            );
        }

        let pool_plain = SshOptions {
            control_master: false,
            ..pool_mux
        };
        for config in [&linux, &unlabelled] {
            assert!(!pooled_client_options(&pool_plain, config).control_master);
        }
    }

    #[tokio::test]
    async fn test_pool_entry_for_windows_worker_is_never_mux() {
        // End-to-end at the pool layer: the daemon's health pool and shared
        // build/telemetry pool both construct per-worker clients via
        // get_or_create_client_entry with pool-global mux options — the
        // Windows entry must come out non-mux. Uses the entry-creation path
        // (like the other pool tests) so no live SSH host is needed.
        let _guard = test_guard!();
        let pool = SshPool::new(SshOptions {
            control_master: true,
            control_persist_idle: Some(Duration::from_secs(60)),
            ..Default::default()
        });
        let config = windows_worker_config("wsurf");

        let entry = pool.get_or_create_client_entry(&config).await;
        let guard = entry.read().await;
        assert!(
            !guard.options.control_master,
            "pooled entry for a Windows worker must be non-mux"
        );
        // The inert companion setting is untouched, proving the override was
        // surgical rather than a blanket options reset.
        assert_eq!(
            guard.options.control_persist_idle,
            Some(Duration::from_secs(60))
        );
    }

    #[tokio::test]
    async fn test_pool_entry_for_linux_worker_keeps_mux() {
        let _guard = test_guard!();
        let pool = SshPool::new(SshOptions {
            control_master: true,
            control_persist_idle: Some(Duration::from_secs(60)),
            ..Default::default()
        });
        let config = worker_config("contabo-a", "1.2.3.4", "root", "~/.ssh/id_rsa");

        let entry = pool.get_or_create_client_entry(&config).await;
        let guard = entry.read().await;
        assert!(
            guard.options.control_master,
            "pooled entry for a Linux worker must keep the pool's mux setting"
        );
    }

    #[tokio::test]
    async fn test_ssh_pool_replaces_stale_entry_when_endpoint_changes() {
        let _guard = test_guard!();
        let pool = SshPool::default();
        let old_config = worker_config("worker-a", "192.168.1.100", "ubuntu", "~/.ssh/id_rsa");
        let new_config = worker_config("worker-a", "192.168.1.101", "admin", "~/.ssh/new_key");

        let stale = pool.get_or_create_client_entry(&old_config).await;
        let replacement = pool.get_or_create_client_entry(&new_config).await;

        assert!(!Arc::ptr_eq(&stale, &replacement));
        assert_eq!(pool.active_connections().await, 1);

        let replacement_guard = replacement.read().await;
        assert!(replacement_guard.is_configured_for(&new_config));
    }

    #[tokio::test]
    async fn test_health_check_reports_not_alive_without_session() {
        // get_or_connect's liveness probe relies on health_check() returning a
        // non-true value (without erroring) for a client that has no live
        // session, so a dead/empty pooled entry is reconnected rather than
        // falsely handed back as "reused". execute() errors "Not connected",
        // which health_check() maps to Ok(false).
        let _guard = test_guard!();
        let config = worker_config("worker-a", "192.168.1.100", "ubuntu", "~/.ssh/id_rsa");
        let client = SshClient::new(config, SshOptions::default());
        assert!(!client.is_connected());
        let alive = client
            .health_check()
            .await
            .expect("health_check maps execution errors to Ok(false), never Err");
        assert!(!alive, "a client with no session must not report as alive");
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
                let escaped = match result {
                    Some(escaped) => escaped,
                    None => {
                        prop_assert!(false, "Should accept safe value: {:?}", s);
                        String::new()
                    }
                };
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

                let escaped = match result {
                    Some(escaped) => escaped,
                    None => {
                        prop_assert!(false, "Should escape single quote: {}", value);
                        String::new()
                    }
                };
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
            // shell_escape uses '\'' style for each single quote
            assert_eq!(
                result
                    .as_deref()
                    .map(|escaped| escaped.matches("'\\''").count()),
                Some(3)
            );

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

    // ======================================================================
    // System-ssh fallback for Windows workers (bd-kzy2x)
    // ======================================================================

    fn windows_worker(id: &str) -> WorkerConfig {
        let mut config = worker_config(id, "100.68.2.11", "jeffr", "~/.ssh/surfacebookje_key");
        config.tags = vec!["rust".to_string(), crate::types::os_tag("windows")];
        config
    }

    #[test]
    fn test_prefers_system_ssh_for_windows_tag() {
        // The dispatch key in lockstep with `pooled_client_options`:
        // declared_os == "windows" -> system-ssh fallback.
        let _guard = test_guard!();
        let cfg = windows_worker("wsurf");
        assert!(prefers_system_ssh(&cfg));
    }

    #[test]
    fn test_prefers_system_ssh_case_normalized() {
        // declared_os lower-cases the tag's OS, so `os = "Windows"` (mixed
        // case) and `os = "WINDOWS"` (all caps) both route to the fallback.
        let _guard = test_guard!();
        let mut cfg = windows_worker("wsurf-mixed");
        cfg.tags = vec![crate::types::os_tag("Windows")];
        assert!(prefers_system_ssh(&cfg));

        let mut upper = windows_worker("wsurf-upper");
        upper.tags = vec![crate::types::os_tag("WINDOWS")];
        assert!(prefers_system_ssh(&upper));
    }

    #[test]
    fn test_prefers_system_ssh_false_for_linux() {
        // `os:linux` and unlabelled workers do NOT trigger the fallback —
        // they keep the openssh-crate path verbatim.
        let _guard = test_guard!();
        let mut linux = worker_config("contabo-a", "1.2.3.4", "root", "~/.ssh/id_rsa");
        linux.tags = vec!["rust".to_string(), crate::types::os_tag("linux")];
        assert!(!prefers_system_ssh(&linux));

        let unlabelled = worker_config("contabo-b", "1.2.3.5", "root", "~/.ssh/id_rsa");
        assert!(!prefers_system_ssh(&unlabelled));
    }

    #[test]
    fn test_system_ssh_argv_basic_windows() {
        // Baseline Windows worker (no port today — WorkerConfig has no
        // `port` field; non-default ports travel as `host:port`). The argv
        // ends with the destination then the command, never has a `-p`
        // flag, and carries the keepalive when non-zero.
        let _guard = test_guard!();
        let cfg = windows_worker("wsurf");
        let argv = system_ssh_argv(&cfg, "uname -a", Duration::from_secs(2));
        let s: Vec<String> = argv
            .iter()
            .map(|o| o.to_string_lossy().into_owned())
            .collect();

        assert_eq!(s[0], "ssh", "argv[0] is the program name");
        assert_eq!(s[1], "-i");
        // shellexpand::tilde expands `~`; on this machine it goes to a
        // $HOME-anchored path, so the suffix is the right invariant.
        assert!(
            s[2].ends_with(".ssh/surfacebookje_key"),
            "identity file is the tilde-expanded path: {}",
            s[2]
        );
        // Pair -o/value: BatchMode=yes, ConnectTimeout=8,
        // StrictHostKeyChecking=accept-new, ServerAliveInterval=2.
        assert!(s.contains(&"-o".to_string()));
        assert!(s.contains(&"BatchMode=yes".to_string()));
        assert!(s.contains(&"ConnectTimeout=8".to_string()));
        assert!(s.contains(&"StrictHostKeyChecking=accept-new".to_string()));
        assert!(s.contains(&"ServerAliveInterval=2".to_string()));
        // No -p flag — WorkerConfig has no port.
        assert!(!s.iter().any(|arg| arg == "-p"));
        // destination is `user@host` then the command.
        assert!(s.contains(&"jeffr@100.68.2.11".to_string()));
        assert_eq!(s[s.len() - 1], "uname -a", "command is the last argv");
    }

    #[test]
    fn test_system_ssh_argv_zero_server_alive_omits_keepalive() {
        // `server_alive_interval = 0` must NOT emit `-o ServerAliveInterval=0`
        // (which OpenSSH treats as "disable keepalives" — fine, but the spec
        // calls for omitting the flag entirely at 0).
        let _guard = test_guard!();
        let cfg = windows_worker("wsurf");
        let argv = system_ssh_argv(&cfg, "echo hi", Duration::from_secs(0));
        let s: Vec<String> = argv
            .iter()
            .map(|o| o.to_string_lossy().into_owned())
            .collect();
        assert!(
            !s.iter().any(|a| a.starts_with("ServerAliveInterval=")),
            "no ServerAliveInterval flag when interval is 0; got {:?}",
            s
        );
    }

    #[test]
    fn test_system_ssh_argv_long_keepalive_preserved() {
        // Non-default keepalive values must be preserved verbatim (no
        // truncation, no off-by-one). Use 60s — the same value the openssh
        // pool applies for warm masters.
        let _guard = test_guard!();
        let cfg = windows_worker("wsurf");
        let argv = system_ssh_argv(&cfg, "true", Duration::from_secs(60));
        let s: Vec<String> = argv
            .iter()
            .map(|o| o.to_string_lossy().into_owned())
            .collect();
        assert!(s.contains(&"ServerAliveInterval=60".to_string()));
    }

    #[test]
    fn test_system_ssh_argv_uses_tilde_expanded_identity() {
        // `shellexpand::tilde` is invoked on the identity_file path so an
        // operator can write `~/.ssh/foo` in workers.toml and have ssh
        // see the expanded path. Compare the raw `~`-prefixed form is
        // NOT in the argv.
        let _guard = test_guard!();
        let mut cfg = windows_worker("wsurf");
        cfg.identity_file = "~/.ssh/operator_key".to_string();
        let argv = system_ssh_argv(&cfg, "true", Duration::from_secs(2));
        let s: Vec<String> = argv
            .iter()
            .map(|o| o.to_string_lossy().into_owned())
            .collect();
        assert!(
            !s.contains(&"~/.ssh/operator_key".to_string()),
            "identity file must be tilde-expanded, got {:?}",
            s
        );
        assert!(
            s.contains(&"~/.ssh/operator_key".to_string())
                || s.iter().any(|a| a.ends_with(".ssh/operator_key")),
            "tilde-expanded path appears in argv: {:?}",
            s
        );
    }

    #[test]
    fn test_dispatch_helper_matches_declared_os_key() {
        // The dispatch key MUST be the same one `pooled_client_options` uses
        // so the two Windows fallbacks (no ControlMaster on the pool side,
        // system-ssh on the execute side) cannot diverge on which workers
        // they apply to.
        let _guard = test_guard!();
        let cfg = windows_worker("wsurf");
        assert_eq!(declared_os(&cfg.tags).as_deref(), Some("windows"));
        assert!(prefers_system_ssh(&cfg));
    }
}

/// How an SSH session's `ControlPersist` should be configured.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ControlPersistMode {
    /// Close the control-master once the initial connection ends (ControlPersist=no).
    Closed,
    /// Keep a warm control-master for the given idle seconds (ControlPersist=Ns).
    IdleFor(NonZeroUsize),
    /// Requested idle exceeded usize; caller falls back to Closed.
    TooLarge(u64),
}

/// Decide `ControlPersist` for an SSH session. A warm master is kept ONLY for the
/// explicit connection-reuse path (`control_master` + a configured non-zero idle);
/// every other case closes after the initial connection so per-call SSH sessions
/// (telemetry/health/capabilities) cannot leak `ControlPersist=yes` masters.
fn control_persist_mode(control_master: bool, idle: Option<Duration>) -> ControlPersistMode {
    match idle {
        Some(idle) if control_master && !idle.is_zero() => match usize::try_from(idle.as_secs()) {
            Ok(secs) => match NonZeroUsize::new(secs) {
                Some(nonzero) => ControlPersistMode::IdleFor(nonzero),
                None => ControlPersistMode::Closed,
            },
            Err(_) => ControlPersistMode::TooLarge(idle.as_secs()),
        },
        _ => ControlPersistMode::Closed,
    }
}

#[cfg(test)]
mod control_persist_tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn non_mux_sessions_never_persist_forever() {
        // The per-call paths (control_master=false) must close after use.
        assert_eq!(
            control_persist_mode(false, None),
            ControlPersistMode::Closed
        );
        assert_eq!(
            control_persist_mode(false, Some(Duration::from_secs(60))),
            ControlPersistMode::Closed
        );
    }

    #[test]
    fn mux_without_idle_closes() {
        assert_eq!(control_persist_mode(true, None), ControlPersistMode::Closed);
        assert_eq!(
            control_persist_mode(true, Some(Duration::from_secs(0))),
            ControlPersistMode::Closed
        );
    }

    #[test]
    fn mux_with_idle_keeps_warm() {
        assert_eq!(
            control_persist_mode(true, Some(Duration::from_secs(60))),
            ControlPersistMode::IdleFor(NonZeroUsize::new(60).unwrap())
        );
    }
}
