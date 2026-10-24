//! SSH client utilities for remote command execution.
//!
//! Provides connection management, command execution, and pooling support
//! for the remote compilation pipeline.
//!
//! This module is only available on Unix platforms (requires openssh crate).

use crate::types::{WorkerConfig, WorkerId, declared_os};
use anyhow::{Context, Result};
use openssh::{Session, Stdio};
use std::collections::HashMap;
use std::ffi::OsString;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::process::ExitStatus;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
use tokio::sync::{RwLock, mpsc, watch};
use tokio::time::Instant;
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

/// Bound on the pool's reuse liveness probe (`echo ok` over an existing
/// master). A live master answers in milliseconds; a hung one must not hold a
/// caller for the client's multi-minute command timeout.
const POOL_LIVENESS_PROBE_TIMEOUT: Duration = Duration::from_secs(10);

/// Reaping a killed local SSH process must not wedge disconnect/reload either.
const SSH_CLEANUP_TIMEOUT: Duration = Duration::from_secs(1);
const SSH_READY_POLL_INTERVAL: Duration = Duration::from_millis(20);

#[derive(Clone)]
struct SshProcessState {
    active_commands: usize,
    idle_since: Instant,
    draining: bool,
    stopping: bool,
    outcome: Option<std::result::Result<ExitStatus, String>>,
}

/// Owns a foreground SSH process from spawn through wait/reap. Dropping a
/// connect future or a client requests termination; the supervisor retains the
/// child and socket directory until it has reaped the child.
struct OwnedSshProcess {
    state: watch::Sender<SshProcessState>,
    supervisor: tokio::task::JoinHandle<()>,
}

impl OwnedSshProcess {
    fn spawn(
        command: &mut tokio::process::Command,
        control_dir: Option<Arc<tempfile::TempDir>>,
        idle_timeout: Option<Duration>,
    ) -> Result<Self> {
        let mut child = command.kill_on_drop(true).spawn()?;
        let (state, mut changes) = watch::channel(SshProcessState {
            active_commands: 0,
            idle_since: Instant::now(),
            draining: false,
            stopping: false,
            outcome: None,
        });
        let updates = state.clone();
        let supervisor = tokio::spawn(async move {
            // In particular, do not unlink a control socket while its master
            // is still alive following cancellation of the caller.
            let _control_dir = control_dir;
            let outcome = loop {
                let current = changes.borrow_and_update().clone();
                if current.stopping {
                    if let Err(error) = child.start_kill() {
                        debug!("Failed to signal owned SSH child: {error}");
                    }
                    break child.wait().await;
                }
                let idle_deadline = idle_timeout
                    .filter(|_| current.active_commands == 0)
                    .and_then(|idle| current.idle_since.checked_add(idle));
                tokio::select! {
                    outcome = child.wait() => break outcome,
                    _ = changes.changed() => {},
                    _ = async {
                        if let Some(deadline) = idle_deadline {
                            tokio::time::sleep_until(deadline).await;
                        } else {
                            std::future::pending::<()>().await;
                        }
                    } => {
                        // Serialize expiry with command admission: a command
                        // starting as the timer fires either owns a use guard
                        // or observes a closing session before it is spawned.
                        updates.send_if_modified(|state| {
                            if !state.stopping && state.active_commands == 0
                                && idle_timeout.is_some_and(|idle| {
                                    state.idle_since.elapsed() >= idle
                                })
                            {
                                state.stopping = true;
                                true
                            } else {
                                false
                            }
                        });
                    }
                }
            };
            updates.send_modify(|state| {
                state.stopping = true;
                state.outcome = Some(outcome.map_err(|error| error.to_string()));
            });
        });
        Ok(Self { state, supervisor })
    }

    fn is_running(&self) -> bool {
        let state = self.state.borrow();
        !state.draining
            && !state.stopping
            && state.outcome.is_none()
            && !self.supervisor.is_finished()
    }

    fn begin_use(&self) -> Result<SshProcessUse> {
        let mut admitted = false;
        self.state.send_if_modified(|state| {
            if !state.draining
                && !state.stopping
                && state.outcome.is_none()
                && let Some(active) = state.active_commands.checked_add(1)
            {
                state.active_commands = active;
                admitted = true;
            }
            admitted
        });
        anyhow::ensure!(admitted, "SSH connection is closing or disconnected");
        Ok(SshProcessUse {
            state: self.state.clone(),
            completed: false,
        })
    }

    fn request_stop(&self) {
        self.state.send_modify(|state| state.stopping = true);
    }

    async fn wait_until(&self, deadline: Instant) -> Result<ExitStatus> {
        let mut changes = self.state.subscribe();
        loop {
            if let Some(outcome) = changes.borrow_and_update().outcome.clone() {
                return outcome.map_err(anyhow::Error::msg);
            }
            tokio::time::timeout_at(deadline, changes.changed())
                .await
                .context(
                    "SSH connection timed out during authentication or control socket readiness",
                )?
                .context("SSH child supervisor stopped unexpectedly")?;
        }
    }

    async fn stop_before(&mut self, deadline: Instant) -> Result<()> {
        self.request_stop();
        tokio::time::timeout_at(deadline, &mut self.supervisor)
            .await
            .context("Timed out reaping owned SSH child")?
            .context("SSH child supervisor failed")
    }
}

impl Drop for OwnedSshProcess {
    fn drop(&mut self) {
        // Do not abort the supervisor: it must wait/reap after signalling the
        // child, even when our caller was itself cancelled at its deadline.
        self.request_stop();
    }
}

struct SshProcessUse {
    state: watch::Sender<SshProcessState>,
    completed: bool,
}

impl SshProcessUse {
    fn complete(mut self) {
        self.completed = true;
    }
}

impl Drop for SshProcessUse {
    fn drop(&mut self) {
        self.state.send_modify(|state| {
            // A cancelled/failed command may leave remote work attached to
            // the mux. Retire the transport after its already-running users
            // finish, without disconnecting those unrelated commands.
            state.draining |= !self.completed;
            state.active_commands = state.active_commands.saturating_sub(1);
            if state.active_commands == 0 {
                state.idle_since = Instant::now();
                state.stopping |= state.draining;
            }
        });
    }
}

struct OwnedSshSession {
    // Session::resume does not run openssh's unbounded synchronous `ssh -O
    // exit` in Drop. Our foreground process supervisor performs that cleanup.
    session: Session,
    process: OwnedSshProcess,
    _control_dir: Arc<tempfile::TempDir>,
}

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
    /// Wall-clock deadline for connection setup, including authentication and
    /// ControlMaster readiness. A mux fallback shares the same deadline.
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
    /// with n > 0 keeps the master warm for n idle seconds. Active commands
    /// prevent expiry. `Some(0s)`/`None`, or a non-mux per-call session, keeps
    /// the master only for this client's lifetime. RCH owns this idle timer:
    /// OpenSSH's `ControlPersist` forks an unowned process even without `-f`,
    /// so the SSH child always uses `ControlPersist=no`.
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
    session: Option<OwnedSshSession>,
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
        self.session
            .as_ref()
            .is_some_and(|session| session.process.is_running())
    }

    #[cfg(test)]
    fn is_configured_for(&self, config: &WorkerConfig) -> bool {
        same_ssh_endpoint(&self.config, config)
    }

    /// Connect to the remote worker.
    pub async fn connect(&mut self) -> Result<()> {
        self.connect_using(Path::new("ssh"), None).await
    }

    async fn connect_using(
        &mut self,
        ssh_program: &Path,
        control_directory: Option<&Path>,
    ) -> Result<()> {
        if self.is_connected() {
            debug!("Already connected to {}", self.config.id);
            return Ok(());
        }
        // A master that exited or expired is no longer a usable session.
        self.session.take();
        let deadline = Instant::now()
            .checked_add(self.options.connect_timeout)
            .context("SSH connect_timeout exceeds the supported clock range")?;

        let destination = format!("{}@{}", self.config.user, self.config.host);
        debug!("Connecting to {} via SSH...", destination);

        let session = match self
            .connect_with_mode(
                &destination,
                self.options.control_master,
                ssh_program,
                control_directory,
                deadline,
            )
            .await
        {
            Ok(session) => session,
            Err(primary_error) if self.options.control_master && Instant::now() < deadline => {
                warn!(
                    "SSH ControlMaster connection to {} failed ({}). Retrying without ControlMaster.",
                    destination, primary_error
                );
                self.connect_with_mode(
                    &destination,
                    false,
                    ssh_program,
                    control_directory,
                    deadline,
                )
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

    async fn connect_with_mode(
        &self,
        destination: &str,
        control_master: bool,
        ssh_program: &Path,
        control_directory: Option<&Path>,
        deadline: Instant,
    ) -> Result<OwnedSshSession> {
        anyhow::ensure!(
            Instant::now() < deadline,
            "SSH connection timed out before spawn"
        );
        let directory = control_directory
            .map(Path::to_path_buf)
            .unwrap_or_else(ssh_control_directory);
        std::fs::create_dir_all(&directory)
            .with_context(|| format!("Failed to create SSH control directory {directory:?}"))?;
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
                .context("Failed to protect SSH control directory")?;
        }
        let control_dir = Arc::new(
            tempfile::Builder::new()
                .prefix("rch-")
                .tempdir_in(directory)
                .context("Failed to create private SSH control directory")?,
        );
        let socket = control_dir.path().join("master");
        let log = control_dir.path().join("log");
        let idle_timeout =
            match control_persist_mode(control_master, self.options.control_persist_idle) {
                ControlPersistMode::IdleFor(seconds) => {
                    Some(Duration::from_secs(seconds.get() as u64))
                }
                ControlPersistMode::TooLarge(seconds) => {
                    warn!("control_persist_idle too large ({seconds}s); closing with client");
                    None
                }
                ControlPersistMode::Closed => None,
            };
        if let Some(idle) = idle_timeout {
            anyhow::ensure!(
                Instant::now().checked_add(idle).is_some(),
                "SSH idle timeout exceeds the supported clock range"
            );
        }
        // -F /dev/null probes the client itself without running user Match
        // directives. Older clients do not understand ForkAfterAuthentication;
        // a global IgnoreUnknown override would break the user's own list.
        let can_disable_background =
            ssh_can_disable_background(ssh_program, control_dir.clone(), deadline).await?;
        let mut command = self.master_command(
            ssh_program,
            destination,
            &socket,
            &log,
            can_disable_background,
        );
        let mut process =
            OwnedSshProcess::spawn(&mut command, Some(control_dir.clone()), idle_timeout)
                .with_context(|| format!("Failed to spawn SSH connection to {destination}"))?;
        // Authentication is activity too; a short idle policy must not cut it
        // off before the connection deadline.
        let connecting = process.begin_use()?;
        let ready = wait_for_ssh_master(&process, ssh_program, &socket, &log, deadline).await;
        if let Err(error) = ready {
            // Cleanup consumes only the remaining connection budget. If the
            // caller's deadline already fired, the supervisor still owns and
            // reaps the child after this future returns or is cancelled.
            let _ = process.stop_before(deadline).await;
            return Err(error).with_context(|| format!("Failed to connect to {destination}"));
        }
        connecting.complete();
        Ok(OwnedSshSession {
            session: Session::resume(socket.into_boxed_path(), Some(log.into_boxed_path())),
            process,
            _control_dir: control_dir,
        })
    }

    fn master_command(
        &self,
        ssh_program: &Path,
        destination: &str,
        socket: &Path,
        log: &Path,
        can_disable_background: bool,
    ) -> tokio::process::Command {
        let mut command = tokio::process::Command::new(ssh_program);
        command
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .arg("-E")
            .arg(log)
            .arg("-S")
            .arg(socket)
            .args(["-M", "-N", "-T", "-o", "BatchMode=yes"])
            // ControlPersist forks after authentication even without `-f`.
            // Keep the master in this owned foreground child instead.
            .args(["-o", "ControlPersist=no"])
            .arg("-o")
            .arg(match self.options.known_hosts {
                KnownHostsPolicy::Strict => "StrictHostKeyChecking=yes",
                KnownHostsPolicy::Add => "StrictHostKeyChecking=accept-new",
                KnownHostsPolicy::AcceptAll => "StrictHostKeyChecking=no",
            })
            .arg("-o")
            .arg(format!(
                "ConnectTimeout={}",
                self.options.connect_timeout.as_secs()
            ));
        if can_disable_background {
            command.args(["-o", "ForkAfterAuthentication=no"]);
        }
        if let Some(interval) = self.options.server_alive_interval {
            command
                .arg("-o")
                .arg(format!("ServerAliveInterval={}", interval.as_secs()));
        }
        let identity = shellexpand::tilde(&self.config.identity_file);
        if Path::new(identity.as_ref()).exists() {
            command
                .arg("-i")
                .arg(identity.as_ref())
                .args(["-o", "IdentitiesOnly=yes"]);
        }
        command.arg(destination);
        command
    }

    /// Disconnect from the worker.
    pub async fn disconnect(&mut self) -> Result<()> {
        if let Some(mut session) = self.session.take() {
            debug!("Disconnecting from {}", self.config.id);
            session
                .process
                .stop_before(Instant::now() + SSH_CLEANUP_TIMEOUT)
                .await?;
            // debug, not info: paired with the connect log above; floods at info.
            debug!("Disconnected from {}", self.config.id);
        }
        Ok(())
    }

    /// Force a fresh connection, dropping any existing (possibly dead) session.
    ///
    /// `reconnect` tears the old master down even if its local process is
    /// running but its transport no longer answers, then establishes a new one.
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
        // for declared-OS Windows workers. Connection setup still uses our
        // supervised SSH master; Linux / unlabelled workers execute through
        // the openssh session attached to that master.
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
        let activity = session.process.begin_use()?;

        let start = std::time::Instant::now();
        debug!(
            "Executing on {}: {}",
            self.config.id,
            crate::util::mask_sensitive_command(command)
        );

        let mut child = session
            .session
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

                activity.complete();
                Ok(CommandResult {
                    exit_code,
                    stdout,
                    stderr,
                    duration_ms: duration.as_millis() as u64,
                })
            }
            Err(_) => {
                // openssh kills the local slave when its RemoteChild drops.
                // The incomplete activity guard also retires the master once
                // other active commands finish, so cancelled remote work is
                // not left attached to an indefinitely warm connection.
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
        let activity = session.process.begin_use()?;

        let start = std::time::Instant::now();
        debug!(
            "Executing (streaming) on {}: {}",
            self.config.id,
            crate::util::mask_sensitive_command(command)
        );

        let mut child = session
            .session
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

                activity.complete();
                Ok(CommandResult {
                    exit_code,
                    stdout: stdout_acc,
                    stderr: stderr_acc,
                    duration_ms: duration.as_millis() as u64,
                })
            }
            Err(_) => {
                // Dropping RemoteChild kills the local slave and closes its
                // pipes, ending the reader tasks. The incomplete activity
                // guard retires the master after other active commands finish.
                warn!(
                    "Command (streaming) timed out on {} after {:?}, cleaning up",
                    self.config.id, self.options.command_timeout
                );
                anyhow::bail!("Command timed out after {:?}", self.options.command_timeout);
            }
        }
    }

    /// Check if the worker is reachable via SSH.
    pub async fn health_check(&self) -> Result<bool> {
        self.health_check_with_timeout(self.options.command_timeout)
            .await
    }

    /// [`health_check`](Self::health_check) bounded by `timeout` instead of
    /// the client's command timeout (300s for pooled clients).
    pub async fn health_check_with_timeout(&self, timeout: Duration) -> Result<bool> {
        match self
            .execute_with_timeout(HEALTH_CHECK_COMMAND, timeout)
            .await
        {
            Ok(result) => Ok(result.success() && is_expected_health_check_output(&result.stdout)),
            Err(e) => {
                warn!("Health check failed for {}: {}", self.config.id, e);
                Ok(false)
            }
        }
    }
}

fn ssh_control_directory() -> PathBuf {
    // Keep socket names short on macOS, where temp_dir commonly lives under
    // a long /var/folders path. Each connection gets a fresh private subdir.
    if let Some(home) = dirs::home_dir() {
        home.join(".ssh").join("rch")
    } else if let Some(runtime) = dirs::runtime_dir() {
        runtime.join("rch-ssh")
    } else {
        let username = whoami::username().unwrap_or_else(|_| "unknown".to_owned());
        std::env::temp_dir().join(format!("rch-ssh-{username}"))
    }
}

async fn ssh_can_disable_background(
    ssh_program: &Path,
    control_dir: Arc<tempfile::TempDir>,
    deadline: Instant,
) -> Result<bool> {
    use std::io::Read;

    anyhow::ensure!(
        Instant::now() < deadline,
        "SSH connection timed out before capability probe"
    );
    let configuration = control_dir.path().join("client-config");
    let mut command = tokio::process::Command::new(ssh_program);
    command
        .args(["-G", "-F", "/dev/null", "-T", "none"])
        .stdin(std::process::Stdio::null())
        .stdout(std::fs::File::create(&configuration)?)
        .stderr(std::process::Stdio::null());
    let mut probe = OwnedSshProcess::spawn(&mut command, Some(control_dir.clone()), None)?;
    let checked = probe.wait_until(deadline).await;
    let _ = probe.stop_before(deadline).await;
    anyhow::ensure!(checked?.success(), "SSH client capability probe failed");
    let mut output = String::new();
    std::fs::File::open(configuration)?
        .take(65_537)
        .read_to_string(&mut output)?;
    anyhow::ensure!(
        output.len() <= 65_536,
        "SSH client capability response is too large"
    );
    anyhow::ensure!(
        output.lines().any(|line| {
            let mut words = line.split_whitespace();
            words.next() == Some("hostname") && words.next() == Some("none")
        }),
        "SSH client returned an invalid capability response"
    );
    Ok(output.lines().any(|line| {
        line.split_whitespace()
            .next()
            .is_some_and(|key| key.eq_ignore_ascii_case("forkafterauthentication"))
    }))
}

async fn wait_for_ssh_master(
    process: &OwnedSshProcess,
    ssh_program: &Path,
    socket: &Path,
    log: &Path,
    deadline: Instant,
) -> Result<()> {
    loop {
        let outcome = process.state.borrow().outcome.clone();
        if let Some(outcome) = outcome {
            let status = outcome.map_err(anyhow::Error::msg)?;
            let diagnostic = ssh_connect_diagnostic(log);
            anyhow::bail!("SSH master exited before becoming ready ({status}): {diagnostic}");
        }
        anyhow::ensure!(
            Instant::now() < deadline,
            "SSH connection timed out during authentication or control socket readiness"
        );
        if socket.exists() {
            // Socket existence alone does not prove the mux accepts commands.
            // This probe is also owned and shares the authentication deadline;
            // openssh::Session::check itself does not kill its child on drop.
            let mut command = tokio::process::Command::new(ssh_program);
            command
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .arg("-S")
                .arg(socket)
                .args(["-o", "BatchMode=yes", "-O", "check", "none"]);
            let mut probe = OwnedSshProcess::spawn(&mut command, None, None)?;
            let checked = probe.wait_until(deadline).await;
            let _ = probe.stop_before(deadline).await;
            if checked?.success() && process.is_running() {
                return Ok(());
            }
        }
        tokio::time::sleep_until(deadline.min(Instant::now() + SSH_READY_POLL_INTERVAL)).await;
    }
}

fn ssh_connect_diagnostic(log: &Path) -> String {
    use std::io::Read;

    let mut diagnostic = Vec::new();
    if let Ok(file) = std::fs::File::open(log) {
        let _ = file.take(16 * 1024).read_to_end(&mut diagnostic);
    }
    String::from_utf8_lossy(&diagnostic).trim().to_owned()
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

// System-ssh command-execution fallback (bd-kzy2x).
//
// The `openssh` crate 0.11.6 cannot execute commands on Windows OpenSSH
// regardless of `control_master` / `control_persist` / keepalive settings:
// the slave never completes the command channel and every command hangs at
// the execute stage even though the connect succeeds. The CLI `ssh` binary
// speaks the OpenSSH wire protocol directly and works fine. For workers that
// declare `os = "windows"` we therefore spawn the system `ssh` binary at
// command-execution time, mirroring the proven system-ssh pattern already
// used by the fleet preflight path (`rch/src/fleet/ssh.rs::SshExecutor`) and
// the CLI worker init / probe paths. Connection setup uses the supervised
// master above; the fallback is an execute-time dispatch inside
// `SshClient::execute_with_timeout`.
//
// Policy key (kept in lockstep with the existing pool-layer override
// `pooled_client_options`): `declared_os(&config.tags) == Some("windows")`.
// `os = "Windows"` is case-normalized by `declared_os` so both spellings
// route through the same fallback.

/// Should `SshClient::execute_with_timeout` dispatch through the system `ssh`
/// binary for this worker instead of the `openssh` crate?
pub(crate) fn prefers_system_ssh(config: &WorkerConfig) -> bool {
    declared_os(&config.tags).as_deref() == Some("windows")
}

/// Remote command and optional stdin payload for a system SSH invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteShellCommand {
    /// Command argument passed to SSH after the destination.
    pub command: String,
    /// Script to write and close concurrently with draining stdout/stderr.
    /// When absent, the caller should provide null stdin.
    pub stdin_script: Option<String>,
}

/// Prepare a POSIX script without exposing its contents to Windows cmd.exe.
/// Windows uses a fixed `sh -s` reader, which replaces itself with a command
/// shell whose stdin is empty. An exact `sh -s` keeps its existing EOF behavior.
/// POSIX workers receive the original command argument and null stdin.
#[must_use]
pub fn remote_shell_command(config: &WorkerConfig, command: &str) -> RemoteShellCommand {
    if prefers_system_ssh(config) {
        RemoteShellCommand {
            command: "sh -s".into(),
            stdin_script: (command != "sh -s").then(|| {
                format!(
                    "exec sh -c {} </dev/null\n",
                    shell_escape::escape(command.into())
                )
            }),
        }
    } else {
        RemoteShellCommand {
            command: command.into(),
            stdin_script: None,
        }
    }
}

pub use crate::ssh_utils::identities_only_args;

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
/// Windows receives only the fixed POSIX reader `sh -s`; the original script
/// travels through stdin so cmd.exe never interprets its contents.
pub(crate) fn system_ssh_argv(
    config: &WorkerConfig,
    command: &RemoteShellCommand,
    server_alive_interval: Duration,
) -> Vec<OsString> {
    let identity_path = shellexpand::tilde(&config.identity_file);
    let destination = format!("{}@{}", config.user, config.host);

    let mut argv: Vec<OsString> = Vec::with_capacity(12);
    argv.push(OsString::from("ssh"));
    argv.push(OsString::from("-i"));
    argv.push(OsString::from(identity_path.as_ref()));
    if let Some(opts) = identities_only_args(&config.identity_file) {
        argv.extend(opts.map(OsString::from));
    }
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
    argv.push(OsString::from(&command.command));
    argv
}

/// Write and close an SSH script pipe within the caller's execution deadline.
/// Run concurrently with output draining. A closed pipe is allowed so the
/// caller can collect an early SSH failure's actual exit status and stderr.
///
/// # Errors
/// Returns write or shutdown errors other than an expected broken pipe.
pub async fn write_ssh_command_stdin(
    mut stdin: tokio::process::ChildStdin,
    input: &str,
) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;

    let result = async {
        stdin.write_all(input.as_bytes()).await?;
        stdin.shutdown().await
    }
    .await;
    match result {
        // An authentication failure or early remote exit can close stdin
        // before the payload is written. Preserve its actual status/stderr.
        Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
        result => result,
    }
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

    let prepared = remote_shell_command(config, command);
    let argv = system_ssh_argv(config, &prepared, server_alive_interval);
    let input = prepared.stdin_script;
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
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
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
        let stdin = child.stdin.take();

        let stdin_fut = async {
            if let (Some(stdin), Some(input)) = (stdin, input) {
                write_ssh_command_stdin(stdin, &input).await?;
            }
            Ok::<(), anyhow::Error>(())
        };

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

        let ((), stdout, stderr) = tokio::try_join!(stdin_fut, stdout_fut, stderr_fut)?;
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
            // even if the remote end is wedged. This only owns the local
            // SSH child; remote process termination is not guaranteed.
            warn!(
                "system-ssh command timed out on {} after {:?}",
                config.id, command_timeout
            );
            anyhow::bail!("Command timed out after {:?}", command_timeout);
        }
    }
}

fn same_ssh_endpoint(left: &WorkerConfig, right: &WorkerConfig) -> bool {
    left.id == right.id
        && left.host == right.host
        && left.user == right.user
        && left.identity_file == right.identity_file
        && declared_os(&left.tags) == declared_os(&right.tags)
}

#[derive(Clone)]
struct PooledSshClient {
    // Endpoint identity is immutable and does not require the client's lock.
    // An old caller can hold that lock across authentication while a new
    // endpoint is admitted independently into the pool.
    config: WorkerConfig,
    client: Arc<RwLock<SshClient>>,
}

/// Connection pool for managing multiple SSH connections.
pub struct SshPool {
    /// Pool of active connections.
    connections: Arc<RwLock<HashMap<WorkerId, PooledSshClient>>>,
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
    /// Validates transport liveness on borrow. The client detects exited or
    /// expired local masters, but a running master can still have a broken or
    /// stalled remote transport. Probe before reuse and reconnect once under
    /// the per-worker write lock if the transport no longer answers.
    pub async fn get_or_connect(&self, config: &WorkerConfig) -> Result<Arc<RwLock<SshClient>>> {
        self.get_or_connect_probing_within(config, POOL_LIVENESS_PROBE_TIMEOUT)
            .await
    }

    /// [`get_or_connect`](Self::get_or_connect) with the liveness probe bounded
    /// by `probe_timeout`.
    ///
    /// The probe used to run under the client's command timeout (300s for the
    /// daemon's pools), and a failed probe is followed by a reconnect and a
    /// second probe. A worker whose master was up but whose commands hung (fork
    /// exhaustion, D-state) therefore held a caller with a 10-15s budget (health
    /// probe, toolchain preflight during selection) for ~10 minutes, and the
    /// sequential health loop stalled the whole fleet's state behind it.
    async fn get_or_connect_probing_within(
        &self,
        config: &WorkerConfig,
        probe_timeout: Duration,
    ) -> Result<Arc<RwLock<SshClient>>> {
        let shared_client = self.get_or_create_client_entry(config).await;

        // Fast path: reuse only a session that is both present AND verified live.
        // The probe needs `&self` only (health_check → execute), so it runs under
        // a shared read lock and never blocks other borrowers of this worker.
        let reusable = {
            let guard = shared_client.read().await;
            guard.is_connected()
                && guard
                    .health_check_with_timeout(probe_timeout)
                    .await
                    .unwrap_or(false)
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
        } else if !client_guard
            .health_check_with_timeout(probe_timeout)
            .await
            .unwrap_or(false)
        {
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
            let existing_entry = {
                let connections = self.connections.read().await;
                connections.get(&worker_id).cloned()
            };

            if let Some(entry) = existing_entry {
                if same_ssh_endpoint(&entry.config, config) {
                    return entry.client;
                }

                let replacement = Arc::new(RwLock::new(SshClient::new(
                    config.clone(),
                    pooled_client_options(&self.options, config),
                )));
                let replaced = {
                    let mut connections = self.connections.write().await;
                    if connections
                        .get(&worker_id)
                        .is_some_and(|current| Arc::ptr_eq(&current.client, &entry.client))
                    {
                        connections.insert(
                            worker_id.clone(),
                            PooledSshClient {
                                config: config.clone(),
                                client: replacement.clone(),
                            },
                        );
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
                    connections.insert(
                        worker_id.clone(),
                        PooledSshClient {
                            config: config.clone(),
                            client: new_client.clone(),
                        },
                    );
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
            connections.remove(worker_id).map(|entry| entry.client)
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
            connections.drain().map(|(_, entry)| entry.client).collect()
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
        let client = self
            .get_or_connect_probing_within(config, command_timeout.min(POOL_LIVENESS_PROBE_TIMEOUT))
            .await?;
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
            tools: Vec::new(),
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
            tools: Vec::new(),
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
    async fn test_ssh_pool_retarget_does_not_wait_for_old_authentication_lock() {
        let _guard = test_guard!();
        let pool = SshPool::default();
        let old_config = worker_config("worker-a", "old-endpoint", "builder", "~/.ssh/id_rsa");
        let new_config = worker_config("worker-a", "new-endpoint", "builder", "~/.ssh/id_rsa");
        let old = pool.get_or_create_client_entry(&old_config).await;
        let authenticating = old.write().await;
        let unchanged = tokio::time::timeout(
            Duration::from_millis(100),
            pool.get_or_create_client_entry(&old_config),
        )
        .await
        .expect("immutable identity lookup must not wait on authentication");
        assert!(Arc::ptr_eq(&old, &unchanged));
        let replacement = tokio::time::timeout(
            Duration::from_millis(100),
            pool.get_or_create_client_entry(&new_config),
        )
        .await
        .expect("new endpoint must not wait on the old endpoint's authentication");
        assert!(!Arc::ptr_eq(&old, &replacement));
        assert_eq!(pool.active_connections().await, 1);
        assert!(replacement.read().await.is_configured_for(&new_config));
        drop(authenticating);
    }

    #[tokio::test]
    async fn test_ssh_pool_os_transition_replaces_transport_but_case_and_scheduling_reuse() {
        let _guard = test_guard!();
        let pool = SshPool::new(SshOptions {
            control_master: true,
            ..Default::default()
        });
        let mut config = worker_config("worker-a", "1.2.3.4", "root", "~/.ssh/id_rsa");
        let unlabelled = pool.get_or_create_client_entry(&config).await;
        config.tags.push(crate::types::os_tag("windows"));
        let windows = pool.get_or_create_client_entry(&config).await;
        assert!(!Arc::ptr_eq(&unlabelled, &windows));
        {
            let client = windows.read().await;
            assert!(prefers_system_ssh(&client.config));
            assert!(!client.options.control_master);
        }

        config.tags = vec!["gpu".into(), "os: WiNdOwS ".into()];
        config.total_slots += 1;
        config.priority += 1;
        let reused = pool.get_or_create_client_entry(&config).await;
        assert!(Arc::ptr_eq(&windows, &reused));

        config.tags = vec![crate::types::os_tag("linux")];
        let linux = pool.get_or_create_client_entry(&config).await;
        assert!(!Arc::ptr_eq(&windows, &linux));
        {
            let client = linux.read().await;
            assert!(!prefers_system_ssh(&client.config));
            assert!(client.options.control_master);
        }
        // Existing borrowers retain their original transport while the pool
        // exposes only the replacement to subsequent requests.
        assert!(prefers_system_ssh(&windows.read().await.config));
        assert!(unlabelled.read().await.options.control_master);
        assert_eq!(pool.active_connections().await, 1);

        config.tags.clear();
        let removed = pool.get_or_create_client_entry(&config).await;
        assert!(!Arc::ptr_eq(&linux, &removed));
        assert!(removed.read().await.options.control_master);
        assert_eq!(pool.active_connections().await, 1);
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
        // ends with the destination then a fixed reader, never has a `-p`
        // flag, and carries the keepalive when non-zero.
        let _guard = test_guard!();
        let cfg = windows_worker("wsurf");
        let command = remote_shell_command(&cfg, "uname -a");
        let argv = system_ssh_argv(&cfg, &command, Duration::from_secs(2));
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
        // The script never reaches the account's cmd.exe command line.
        assert!(s.contains(&"jeffr@100.68.2.11".to_string()));
        assert_eq!(s[s.len() - 1], "sh -s", "Windows gets only a fixed reader");
    }

    #[test]
    fn test_system_ssh_script_transport_keeps_posix_argv_and_exact_stdin_reader() {
        let _guard = test_guard!();
        let linux = worker_config("linux", "1.2.3.4", "root", "~/.ssh/id_rsa");
        let windows = windows_worker("windows");
        let script = "printf '%s\\n' '%PATH% !VAR! & | < > ^ $()'\nprintf done";
        let prepared = remote_shell_command(&linux, script);
        let argv = system_ssh_argv(&linux, &prepared, Duration::ZERO);
        assert_eq!(argv.last().unwrap(), script);
        assert!(prepared.stdin_script.is_none());
        for command in [script, "sh -s", "", "sh -s\n"] {
            let prepared = remote_shell_command(&windows, command);
            let argv = system_ssh_argv(&windows, &prepared, Duration::ZERO);
            assert_eq!(argv.last().unwrap(), "sh -s");
            assert_eq!(prepared.stdin_script.is_none(), command == "sh -s");
        }
    }

    #[tokio::test]
    async fn test_system_ssh_stdin_roundtrip_matches_null_stdin_shell() {
        use std::process::Stdio;

        let _guard = test_guard!();
        let config = windows_worker("windows");
        // These are real POSIX shell oracles for the stdin payload; native
        // Windows SSH dispatch is qualified separately on a Windows worker.
        for script in [
            "",
            "printf '%s\\n' \"apostrophe's\" 'double\"quote' '%PATH% !VAR! ^ & | < >' '$() `x` \\'",
            "cat\nprintf 'AFTER\\n'\nread value || printf 'EMPTY\\n'",
            "cat <<'END'\nheredoc ' \" % ! $() \\\nEND\nprintf 'done\\n'",
            "printf '%s\\n' 'first\nsecond' # trailing comment",
            "printf 'before\\n'; printf 'diagnostic\\n' >&2; exit 37",
            "# comment ending with a backslash \\",
        ] {
            let expected = tokio::process::Command::new("sh")
                .args(["-c", script])
                .stdin(Stdio::null())
                .output()
                .await
                .unwrap();
            let mut child = tokio::process::Command::new("sh")
                .arg("-s")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .kill_on_drop(true)
                .spawn()
                .unwrap();
            let stdin = child.stdin.take().unwrap();
            let payload = remote_shell_command(&config, script).stdin_script.unwrap();
            let (written, observed) = tokio::time::timeout(Duration::from_secs(5), async {
                tokio::join!(
                    write_ssh_command_stdin(stdin, &payload),
                    child.wait_with_output()
                )
            })
            .await
            .unwrap();
            written.unwrap();
            let observed = observed.unwrap();
            assert_eq!(observed.status.code(), expected.status.code(), "{script:?}");
            assert_eq!(observed.stdout, expected.stdout, "{script:?}");
            assert_eq!(observed.stderr, expected.stderr, "{script:?}");
        }
    }

    #[tokio::test]
    async fn test_system_ssh_split_stdin_never_becomes_command_input() {
        use std::process::Stdio;
        use tokio::io::AsyncWriteExt;

        let _guard = test_guard!();
        let script = "cat\nprintf 'AFTER\\n'\nread value || printf 'EMPTY\\n'";
        let payload = remote_shell_command(&windows_worker("windows"), script)
            .stdin_script
            .unwrap();
        let split = payload.find("cat\n").unwrap() + "cat\n".len();
        let mut child = tokio::process::Command::new("sh")
            .arg("-s")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let mut stdin = child.stdin.take().unwrap();
        let writer = async {
            stdin.write_all(&payload.as_bytes()[..split]).await.unwrap();
            tokio::time::sleep(Duration::from_millis(100)).await;
            stdin.write_all(&payload.as_bytes()[split..]).await.unwrap();
            stdin.shutdown().await.unwrap();
        };
        let ((), output) = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(writer, child.wait_with_output())
        })
        .await
        .unwrap();
        let output = output.unwrap();
        assert!(output.status.success(), "{:?}", output.stderr);
        assert_eq!(output.stdout, b"AFTER\nEMPTY\n");
        assert!(output.stderr.is_empty());
    }

    #[tokio::test]
    async fn test_system_ssh_closed_stdin_preserves_early_exit_diagnostic() {
        use std::process::Stdio;

        let _guard = test_guard!();
        let mut child = tokio::process::Command::new("sh")
            .args(["-c", "printf 'remote failure\\n' >&2; exit 37"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let stdin = child.stdin.take().unwrap();
        // Force the pipe closed before writing; a tiny concurrent payload
        // could fit in the buffer and accidentally miss BrokenPipe coverage.
        child.wait().await.unwrap();
        write_ssh_command_stdin(stdin, &"x".repeat(128 * 1024))
            .await
            .unwrap();
        let output = child.wait_with_output().await.unwrap();
        assert_eq!(output.status.code(), Some(37));
        assert_eq!(output.stderr, b"remote failure\n");
        assert!(output.stdout.is_empty());
    }

    #[test]
    fn test_system_ssh_argv_zero_server_alive_omits_keepalive() {
        // `server_alive_interval = 0` must NOT emit `-o ServerAliveInterval=0`
        // (which OpenSSH treats as "disable keepalives" — fine, but the spec
        // calls for omitting the flag entirely at 0).
        let _guard = test_guard!();
        let cfg = windows_worker("wsurf");
        let command = remote_shell_command(&cfg, "echo hi");
        let argv = system_ssh_argv(&cfg, &command, Duration::from_secs(0));
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
        let command = remote_shell_command(&cfg, "true");
        let argv = system_ssh_argv(&cfg, &command, Duration::from_secs(60));
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
        let command = remote_shell_command(&cfg, "true");
        let argv = system_ssh_argv(&cfg, &command, Duration::from_secs(2));
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
    fn test_identities_only_only_when_identity_file_exists() {
        // bd-ebszo: an existing `-i` key must be the ONLY key offered (no agent
        // keys first); a missing key file keeps agent fallback working.
        let _guard = test_guard!();
        let dir = tempfile::tempdir().expect("tempdir");
        let key = dir.path().join("worker_key");
        std::fs::write(&key, b"not a real key").expect("write key");
        let key = key.to_string_lossy().into_owned();
        assert_eq!(
            identities_only_args(&key),
            Some(["-o", "IdentitiesOnly=yes"])
        );
        assert_eq!(identities_only_args("/nonexistent/rch/worker_key"), None);

        let mut cfg = windows_worker("wsurf");
        cfg.identity_file = key;
        let command = remote_shell_command(&cfg, "true");
        let argv = system_ssh_argv(&cfg, &command, Duration::ZERO);
        assert!(argv.contains(&OsString::from("IdentitiesOnly=yes")));

        cfg.identity_file = "/nonexistent/rch/worker_key".to_string();
        let argv = system_ssh_argv(&cfg, &command, Duration::ZERO);
        assert!(!argv.contains(&OsString::from("IdentitiesOnly=yes")));
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

#[cfg(test)]
mod ssh_connection_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    struct FakeSsh {
        directory: tempfile::TempDir,
        program: PathBuf,
    }

    impl FakeSsh {
        fn new(mode: &str) -> Self {
            let directory = tempfile::tempdir().unwrap();
            let program = directory.path().join("fake-ssh");
            let script = format!(
                r#"#!/bin/sh
root={root}
mode={mode}
operation=
socket=
log=
while [ "$#" -gt 0 ]; do
    case "$1" in
        -G) operation=config; shift ;;
        -F) shift 2 ;;
        -S) socket=$2; shift 2 ;;
        -E) log=$2; shift 2 ;;
        -O) operation=$2; shift 2 ;;
        *) shift ;;
    esac
done
if [ "$operation" = config ]; then
    printf '%s\n' "$$" >> "$root/capability-pids"
    case "$mode" in
        capability-stall) exec sleep 30 ;;
        old-client) printf 'hostname none\n' ;;
        *) printf 'hostname none\nforkafterauthentication no\n' ;;
    esac
    exit 0
fi
if [ "$operation" = check ]; then
    printf '%s\n' "$$" >> "$root/check-pids"
    case "$mode" in
        probe-stall) exec sleep 30 ;;
        probe-reject) exit 37 ;;
        *) exit 0 ;;
    esac
fi
printf '%s\n' "$$" >> "$root/master-pids"
case "$mode" in
    ready|old-client|probe-stall|probe-reject) : > "$socket" ;;
    fail) printf 'Permission denied (publickey).\n' > "$log"; exit 255 ;;
esac
exec sleep 30
"#,
                root = shell_escape_value(&directory.path().to_string_lossy())
                    .expect("fixture path must be shell-escapable"),
                mode = shell_escape_value(mode).expect("fixture mode must be shell-escapable"),
            );
            std::fs::write(&program, script).unwrap();
            std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o700)).unwrap();
            Self { directory, program }
        }

        fn client(&self, timeout: Duration, reuse: bool) -> SshClient {
            SshClient::new(
                WorkerConfig {
                    host: "auth-stalled.invalid".to_owned(),
                    identity_file: "/nonexistent/rch/test-key".to_owned(),
                    ..WorkerConfig::default()
                },
                SshOptions {
                    connect_timeout: timeout,
                    control_master: reuse,
                    ..SshOptions::default()
                },
            )
        }

        async fn connect(&self, client: &mut SshClient) -> Result<()> {
            client
                .connect_using(&self.program, Some(self.directory.path()))
                .await
        }

        fn pids(&self, filename: &str) -> Vec<u32> {
            std::fs::read_to_string(self.directory.path().join(filename))
                .unwrap_or_default()
                .lines()
                .map(|line| line.parse().unwrap())
                .collect()
        }

        async fn wait_for_pid(&self, filename: &str) {
            tokio::time::timeout(Duration::from_secs(3), async {
                while self.pids(filename).is_empty() {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("fake SSH process must start");
        }

        async fn assert_reaped(&self) {
            let pids: Vec<_> = self
                .pids("master-pids")
                .into_iter()
                .chain(self.pids("check-pids"))
                .chain(self.pids("capability-pids"))
                .collect();
            assert!(!pids.is_empty(), "test must launch a real SSH stand-in");
            tokio::time::timeout(Duration::from_secs(3), async {
                loop {
                    let any_alive = pids.iter().any(|pid| {
                        // kill -0 also sees zombies, so this checks reaping,
                        // not just sending a termination signal. sh supplies
                        // the same builtin on Linux and macOS.
                        std::process::Command::new("sh")
                            .args(["-c", &format!("kill -0 {pid} 2>/dev/null")])
                            .stdin(std::process::Stdio::null())
                            .stdout(std::process::Stdio::null())
                            .stderr(std::process::Stdio::null())
                            .status()
                            .unwrap()
                            .success()
                    });
                    let control_dir_exists =
                        std::fs::read_dir(self.directory.path())
                            .unwrap()
                            .any(|entry| {
                                entry
                                    .unwrap()
                                    .file_name()
                                    .to_string_lossy()
                                    .starts_with("rch-")
                            });
                    if !any_alive && !control_dir_exists {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("owned SSH children must be killed, reaped, and release their sockets");
        }
    }

    #[test]
    fn foreground_master_keeps_host_identity_and_keepalive_policy() {
        let fake = FakeSsh::new("ready");
        let key = fake.directory.path().join("identity");
        std::fs::write(&key, "test identity").unwrap();
        for (policy, expected) in [
            (KnownHostsPolicy::Strict, "StrictHostKeyChecking=yes"),
            (KnownHostsPolicy::Add, "StrictHostKeyChecking=accept-new"),
            (KnownHostsPolicy::AcceptAll, "StrictHostKeyChecking=no"),
        ] {
            let mut client = fake.client(Duration::from_secs(7), true);
            client.config.identity_file = key.to_string_lossy().into_owned();
            client.options.known_hosts = policy;
            client.options.server_alive_interval = Some(Duration::from_secs(13));
            client.options.control_persist_idle = Some(Duration::from_secs(60));
            let command = client.master_command(
                &fake.program,
                "builder@worker",
                Path::new("/private/control/master"),
                Path::new("/private/control/log"),
                true,
            );
            let args: Vec<_> = command
                .as_std()
                .get_args()
                .map(|argument| argument.to_string_lossy().into_owned())
                .collect();
            for expected in [
                expected,
                "BatchMode=yes",
                "ConnectTimeout=7",
                "ServerAliveInterval=13",
                "IdentitiesOnly=yes",
                "ControlPersist=no",
                "ForkAfterAuthentication=no",
                "-M",
                "-N",
                "builder@worker",
            ] {
                assert!(args.iter().any(|argument| argument == expected), "{args:?}");
            }
            assert!(
                args.iter()
                    .any(|argument| argument == key.to_str().unwrap())
            );
            assert!(!args.iter().any(|argument| argument == "-f"));
            assert!(
                !args
                    .iter()
                    .any(|argument| argument.starts_with("IgnoreUnknown="))
            );
        }

        let client = fake.client(Duration::from_secs(1), false);
        let command = client.master_command(
            &fake.program,
            "builder@worker",
            Path::new("/private/master"),
            Path::new("/private/log"),
            false,
        );
        assert!(
            command
                .as_std()
                .get_args()
                .all(|arg| arg != "IdentitiesOnly=yes")
        );
        assert!(
            command
                .as_std()
                .get_args()
                .all(|arg| arg != "ForkAfterAuthentication=no")
        );
    }

    #[tokio::test]
    async fn capability_probe_deadline_and_cancellation_reap_before_authentication() {
        for cancelled in [false, true] {
            let fake = FakeSsh::new("capability-stall");
            let timeout = if cancelled {
                Duration::from_secs(30)
            } else {
                Duration::from_millis(200)
            };
            let mut client = fake.client(timeout, true);
            let program = fake.program.clone();
            let directory = fake.directory.path().to_owned();
            let connecting =
                tokio::spawn(async move { client.connect_using(&program, Some(&directory)).await });
            if cancelled {
                fake.wait_for_pid("capability-pids").await;
                connecting.abort();
                assert!(connecting.await.unwrap_err().is_cancelled());
            } else {
                let error = connecting.await.unwrap().unwrap_err();
                assert!(format!("{error:#}").contains("timed out"), "{error:#}");
            }
            assert!(fake.pids("master-pids").is_empty());
            assert_eq!(fake.pids("capability-pids").len(), 1);
            fake.assert_reaped().await;
        }
    }

    #[tokio::test]
    async fn client_without_fork_option_remains_supported() {
        let fake = FakeSsh::new("old-client");
        let mut client = fake.client(Duration::from_secs(3), true);
        fake.connect(&mut client).await.unwrap();
        assert!(client.is_connected());
        client.disconnect().await.unwrap();
        fake.assert_reaped().await;
    }

    #[tokio::test]
    async fn foreground_options_preserve_user_ignore_unknown_configuration() {
        let directory = Arc::new(tempfile::tempdir().unwrap());
        let config = directory.path().join("user-config");
        std::fs::write(
            &config,
            "IgnoreUnknown RchFixtureExtension\nRchFixtureExtension yes\n",
        )
        .unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        let capability = ssh_can_disable_background(Path::new("ssh"), directory.clone(), deadline)
            .await
            .unwrap();
        let client = SshClient::new(WorkerConfig::default(), SshOptions::default());
        let master = client.master_command(
            Path::new("ssh"),
            "none",
            &directory.path().join("master"),
            &directory.path().join("log"),
            capability,
        );
        // -G inspects the real client's configuration without connecting. Use
        // precisely the master's options, including its backgrounding policy.
        let mut command = tokio::process::Command::new("ssh");
        command
            .args(["-G", "-F"])
            .arg(config)
            .args(master.as_std().get_args())
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        let process = OwnedSshProcess::spawn(&mut command, Some(directory), None).unwrap();
        assert!(process.wait_until(deadline).await.unwrap().success());
    }

    #[tokio::test]
    async fn authentication_deadline_kills_and_reaps_without_starting_fallback() {
        let fake = FakeSsh::new("auth-stall");
        let mut client = fake.client(Duration::from_millis(200), true);
        let start = Instant::now();
        let error = fake.connect(&mut client).await.unwrap_err();
        assert!(format!("{error:#}").contains("timed out"), "{error:#}");
        assert!(start.elapsed() < Duration::from_secs(2));
        assert!(!client.is_connected());
        assert_eq!(fake.pids("master-pids").len(), 1);
        fake.assert_reaped().await;
    }

    #[tokio::test]
    async fn cancelling_authentication_kills_and_reaps_child() {
        let fake = FakeSsh::new("auth-stall");
        let mut client = fake.client(Duration::from_secs(30), true);
        let program = fake.program.clone();
        let directory = fake.directory.path().to_owned();
        let connecting =
            tokio::spawn(async move { client.connect_using(&program, Some(&directory)).await });
        fake.wait_for_pid("master-pids").await;
        connecting.abort();
        assert!(connecting.await.unwrap_err().is_cancelled());
        fake.assert_reaped().await;
    }

    #[tokio::test]
    async fn stalled_readiness_probe_shares_deadline_and_is_reaped() {
        let fake = FakeSsh::new("probe-stall");
        let mut client = fake.client(Duration::from_millis(200), true);
        let error = fake.connect(&mut client).await.unwrap_err();
        assert!(format!("{error:#}").contains("timed out"), "{error:#}");
        assert_eq!(fake.pids("master-pids").len(), 1);
        assert_eq!(fake.pids("check-pids").len(), 1);
        fake.assert_reaped().await;
    }

    #[tokio::test]
    async fn unsuccessful_readiness_probe_never_marks_client_connected() {
        let fake = FakeSsh::new("probe-reject");
        let mut client = fake.client(Duration::from_millis(200), false);
        assert!(fake.connect(&mut client).await.is_err());
        assert!(!client.is_connected());
        assert!(!fake.pids("check-pids").is_empty());
        fake.assert_reaped().await;
    }

    #[tokio::test]
    async fn dropping_and_disconnecting_ready_client_reap_master() {
        let fake = FakeSsh::new("ready");
        let mut client = fake.client(Duration::from_secs(3), true);
        fake.connect(&mut client).await.unwrap();
        assert!(client.is_connected());
        client.disconnect().await.unwrap();
        assert!(!client.is_connected());
        fake.assert_reaped().await;

        fake.connect(&mut client).await.unwrap();
        assert!(client.is_connected());
        drop(client);
        fake.assert_reaped().await;
        assert_eq!(fake.pids("master-pids").len(), 2);
    }

    #[tokio::test]
    async fn failed_primary_retries_and_preserves_authentication_diagnostic() {
        let fake = FakeSsh::new("fail");
        let mut client = fake.client(Duration::from_secs(3), true);
        let error = fake.connect(&mut client).await.unwrap_err();
        assert!(
            format!("{error:#}").contains("Permission denied (publickey)."),
            "{error:#}"
        );
        assert_eq!(fake.pids("master-pids").len(), 2);
        fake.assert_reaped().await;
    }

    #[tokio::test]
    async fn active_commands_prevent_idle_expiry_and_release_restarts_timer() {
        let mut command = tokio::process::Command::new("sleep");
        command.arg("30");
        let process =
            OwnedSshProcess::spawn(&mut command, None, Some(Duration::from_millis(100))).unwrap();
        let first = process.begin_use().unwrap();
        let second = process.begin_use().unwrap();
        tokio::time::sleep(Duration::from_millis(150)).await;
        first.complete();
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(
            process.is_running(),
            "the remaining command still owns the master"
        );
        second.complete();
        assert!(
            process.is_running(),
            "expiry starts after the last command completes"
        );
        let status = process
            .wait_until(Instant::now() + Duration::from_secs(3))
            .await
            .unwrap();
        assert!(!status.success());
        assert!(!process.is_running());
        assert!(process.begin_use().is_err());
    }

    #[tokio::test]
    async fn cancelled_command_retires_master_after_other_commands_finish() {
        let mut command = tokio::process::Command::new("sleep");
        command.arg("30");
        let process = OwnedSshProcess::spawn(&mut command, None, None).unwrap();
        let cancelled = process.begin_use().unwrap();
        let running = process.begin_use().unwrap();
        drop(cancelled);
        assert!(
            process.begin_use().is_err(),
            "a draining master rejects new work"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            process.state.borrow().outcome.is_none(),
            "cancellation must not kill another active command's master"
        );
        running.complete();
        let status = process
            .wait_until(Instant::now() + Duration::from_secs(3))
            .await
            .unwrap();
        assert!(!status.success());
    }

    #[tokio::test]
    async fn expired_pooled_connection_can_connect_again() {
        let fake = FakeSsh::new("ready");
        let mut client = fake.client(Duration::from_secs(3), true);
        client.options.control_persist_idle = Some(Duration::from_secs(1));
        fake.connect(&mut client).await.unwrap();
        client
            .session
            .as_ref()
            .unwrap()
            .process
            .wait_until(Instant::now() + Duration::from_secs(3))
            .await
            .unwrap();
        assert!(!client.is_connected());
        fake.connect(&mut client).await.unwrap();
        assert!(client.is_connected());
        client.disconnect().await.unwrap();
        fake.assert_reaped().await;
        assert_eq!(fake.pids("master-pids").len(), 2);
    }
}

/// The client-owned lifetime policy for an SSH control master.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ControlPersistMode {
    /// Close the control master when its client is dropped or disconnected.
    Closed,
    /// Keep a warm control master for the given idle seconds between commands.
    IdleFor(NonZeroUsize),
    /// Requested idle exceeded usize; caller falls back to Closed.
    TooLarge(u64),
}

/// Decide idle expiry for an SSH session. A warm master is kept ONLY for the
/// explicit connection-reuse path (`control_master` + a configured non-zero idle);
/// every other case closes with its owning client. OpenSSH persistence is always
/// disabled so cancellation can kill and reap the actual master process.
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
