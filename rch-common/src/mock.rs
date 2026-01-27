//! Mock transport layer for testing.
//!
//! Provides mock implementations of SSH and rsync operations
//! for deterministic testing without real network dependencies.
//!
//! Enable mock mode by setting `RCH_MOCK_SSH=1` environment variable.

use crate::ssh::CommandResult;
use crate::types::{WorkerConfig, WorkerId};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Instant;
use tracing::{debug, info};

fn env_flag(key: &str) -> bool {
    std::env::var(key)
        .map(|v| v == "1" || v.to_lowercase() == "true")
        .unwrap_or(false)
}

#[derive(Debug, Default, Clone)]
struct MockOverrides {
    enabled: Option<bool>,
    ssh_config: Option<MockConfig>,
    rsync_config: Option<MockRsyncConfig>,
    /// Active "override scopes" to reduce cross-test flakiness.
    ///
    /// Some workspace tests run in parallel and share these global overrides.
    /// We treat `set_mock_enabled_override(Some(_))` + `clear_mock_overrides()`
    /// as a push/pop pair so one test can't accidentally disable mock mode
    /// while another is still running.
    active_scopes: usize,
}

fn overrides() -> &'static Mutex<MockOverrides> {
    static OVERRIDES: OnceLock<Mutex<MockOverrides>> = OnceLock::new();
    OVERRIDES.get_or_init(|| Mutex::new(MockOverrides::default()))
}

/// Set or clear the mock enabled override (test helper).
pub fn set_mock_enabled_override(enabled: Option<bool>) {
    let mut guard = overrides().lock().unwrap();
    if enabled.is_some() {
        guard.active_scopes = guard.active_scopes.saturating_add(1);
    }
    guard.enabled = enabled;
}

/// Set or clear the mock SSH config override (test helper).
pub fn set_mock_ssh_config_override(config: Option<MockConfig>) {
    overrides().lock().unwrap().ssh_config = config;
}

/// Set or clear the mock rsync config override (test helper).
pub fn set_mock_rsync_config_override(config: Option<MockRsyncConfig>) {
    overrides().lock().unwrap().rsync_config = config;
}

/// Clear all mock overrides.
pub fn clear_mock_overrides() {
    let mut guard = overrides().lock().unwrap();
    if guard.active_scopes > 0 {
        guard.active_scopes -= 1;
    }
    if guard.active_scopes == 0 {
        guard.enabled = None;
        guard.ssh_config = None;
        guard.rsync_config = None;
    }
}

/// Check if mock mode is enabled via override or environment variable.
pub fn is_mock_enabled() -> bool {
    if let Some(enabled) = overrides().lock().unwrap().enabled {
        return enabled;
    }
    std::env::var("RCH_MOCK_SSH")
        .map(|v| v == "1" || v.to_lowercase() == "true")
        .unwrap_or(false)
}

/// Check if a host string indicates mock mode (mock://).
pub fn is_mock_host(host: &str) -> bool {
    host.starts_with("mock://")
}

/// Check if a worker should use mock transport.
pub fn is_mock_worker(worker: &WorkerConfig) -> bool {
    is_mock_host(&worker.host)
}

fn global_ssh_invocations() -> &'static Mutex<Vec<MockInvocation>> {
    static GLOBAL: OnceLock<Mutex<Vec<MockInvocation>>> = OnceLock::new();
    GLOBAL.get_or_init(|| Mutex::new(Vec::new()))
}

fn global_rsync_invocations() -> &'static Mutex<Vec<MockSyncInvocation>> {
    static GLOBAL: OnceLock<Mutex<Vec<MockSyncInvocation>>> = OnceLock::new();
    GLOBAL.get_or_init(|| Mutex::new(Vec::new()))
}

/// Clear global mock invocation logs.
pub fn clear_global_invocations() {
    global_ssh_invocations().lock().unwrap().clear();
    global_rsync_invocations().lock().unwrap().clear();
}

/// Snapshot global SSH invocations.
pub fn global_ssh_invocations_snapshot() -> Vec<MockInvocation> {
    global_ssh_invocations().lock().unwrap().clone()
}

/// Snapshot global rsync invocations.
pub fn global_rsync_invocations_snapshot() -> Vec<MockSyncInvocation> {
    global_rsync_invocations().lock().unwrap().clone()
}

/// Phase markers for logging.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// Project sync phase.
    Sync,
    /// Command execution phase.
    Execute,
    /// Artifact retrieval phase.
    Artifacts,
    /// Connection phase.
    Connect,
    /// Disconnect phase.
    Disconnect,
}

impl std::fmt::Display for Phase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Phase::Sync => write!(f, "SYNC"),
            Phase::Execute => write!(f, "EXEC"),
            Phase::Artifacts => write!(f, "ARTIFACTS"),
            Phase::Connect => write!(f, "CONNECT"),
            Phase::Disconnect => write!(f, "DISCONNECT"),
        }
    }
}

/// Log a phase event with timestamp.
pub fn log_phase(phase: Phase, message: &str) {
    let timestamp = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ");
    info!("[{}] [{}] {}", timestamp, phase, message);
}

/// Log a phase event with timestamp (debug level).
pub fn debug_phase(phase: Phase, message: &str) {
    let timestamp = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ");
    debug!("[{}] [{}] {}", timestamp, phase, message);
}

/// Recorded invocation for mock verification.
#[derive(Debug, Clone)]
pub struct MockInvocation {
    /// Worker ID the invocation was made against.
    pub worker_id: WorkerId,
    /// Command that was executed (if applicable).
    pub command: Option<String>,
    /// Phase of the invocation.
    pub phase: Phase,
    /// Timestamp of invocation.
    pub timestamp: std::time::SystemTime,
}

/// Configuration for mock behavior.
#[derive(Debug, Clone)]
pub struct MockConfig {
    /// Default exit code for commands.
    pub default_exit_code: i32,
    /// Default stdout for commands.
    pub default_stdout: String,
    /// Default stderr for commands.
    pub default_stderr: String,
    /// Simulate connection failure.
    pub fail_connect: bool,
    /// Simulate transient connection failures for N attempts (then succeed).
    pub fail_connect_attempts: u32,
    /// Simulate command failure.
    pub fail_execute: bool,
    /// Simulate transient execution failures for N attempts (then succeed).
    pub fail_execute_attempts: u32,
    /// Simulated execution time in milliseconds.
    pub execution_delay_ms: u64,
    /// Command-specific results (command -> result).
    pub command_results: HashMap<String, CommandResult>,
    /// Simulate toolchain install failure.
    pub fail_toolchain_install: bool,
    /// Simulate no rustup available.
    pub no_rustup: bool,
}

impl Default for MockConfig {
    fn default() -> Self {
        Self {
            default_exit_code: 0,
            default_stdout: String::new(),
            default_stderr: String::new(),
            fail_connect: false,
            fail_connect_attempts: 0,
            fail_execute: false,
            fail_execute_attempts: 0,
            execution_delay_ms: 10,
            command_results: HashMap::new(),
            fail_toolchain_install: false,
            no_rustup: false,
        }
    }
}

impl MockConfig {
    /// Create a config that simulates successful operations.
    pub fn success() -> Self {
        Self::default()
    }

    /// Create a config that simulates connection failure.
    pub fn connection_failure() -> Self {
        Self {
            fail_connect: true,
            ..Self::default()
        }
    }

    /// Create a config that simulates command failure.
    pub fn command_failure(exit_code: i32, stderr: &str) -> Self {
        Self {
            default_exit_code: exit_code,
            default_stderr: stderr.to_string(),
            fail_execute: true,
            ..Self::default()
        }
    }

    /// Add a specific result for a command pattern.
    pub fn with_command_result(mut self, command: &str, result: CommandResult) -> Self {
        self.command_results.insert(command.to_string(), result);
        self
    }

    /// Set default stdout.
    pub fn with_stdout(mut self, stdout: &str) -> Self {
        self.default_stdout = stdout.to_string();
        self
    }

    /// Build mock config from environment variables.
    pub fn from_env() -> Self {
        if let Some(config) = overrides().lock().unwrap().ssh_config.clone() {
            return config;
        }

        let mut config = MockConfig::default();

        if let Ok(val) = std::env::var("RCH_MOCK_SSH_EXIT_CODE")
            && let Ok(code) = val.parse()
        {
            config.default_exit_code = code;
        }
        if let Ok(val) = std::env::var("RCH_MOCK_SSH_STDOUT") {
            config.default_stdout = val;
        }
        if let Ok(val) = std::env::var("RCH_MOCK_SSH_STDERR") {
            config.default_stderr = val;
        }
        if let Ok(val) = std::env::var("RCH_MOCK_SSH_DELAY_MS")
            && let Ok(delay) = val.parse()
        {
            config.execution_delay_ms = delay;
        }

        config.fail_connect = env_flag("RCH_MOCK_SSH_FAIL_CONNECT");
        config.fail_execute = env_flag("RCH_MOCK_SSH_FAIL_EXECUTE");

        if let Ok(val) = std::env::var("RCH_MOCK_SSH_FAIL_CONNECT_ATTEMPTS")
            && let Ok(count) = val.parse()
        {
            config.fail_connect_attempts = count;
        }
        if let Ok(val) = std::env::var("RCH_MOCK_SSH_FAIL_EXECUTE_ATTEMPTS")
            && let Ok(count) = val.parse()
        {
            config.fail_execute_attempts = count;
        }

        config.fail_toolchain_install = env_flag("RCH_MOCK_TOOLCHAIN_INSTALL_FAIL");
        config.no_rustup = env_flag("RCH_MOCK_NO_RUSTUP");

        config
    }

    /// Create a config that simulates toolchain install failure.
    pub fn toolchain_install_failure() -> Self {
        Self {
            fail_toolchain_install: true,
            ..Self::default()
        }
    }

    /// Create a config that simulates no rustup available.
    pub fn no_rustup() -> Self {
        Self {
            no_rustup: true,
            ..Self::default()
        }
    }
}

/// Mock SSH client for testing.
pub struct MockSshClient {
    /// Worker configuration.
    config: WorkerConfig,
    /// Mock behavior configuration.
    mock_config: MockConfig,
    /// Whether currently "connected".
    connected: bool,
    /// Recorded invocations.
    invocations: Arc<Mutex<Vec<MockInvocation>>>,
    /// Remaining transient connect failures to simulate.
    connect_failures_remaining: AtomicU32,
    /// Remaining transient execute failures to simulate.
    execute_failures_remaining: AtomicU32,
}

impl MockSshClient {
    /// Create a new mock SSH client.
    pub fn new(config: WorkerConfig, mock_config: MockConfig) -> Self {
        Self {
            config,
            connect_failures_remaining: AtomicU32::new(mock_config.fail_connect_attempts),
            execute_failures_remaining: AtomicU32::new(mock_config.fail_execute_attempts),
            mock_config,
            connected: false,
            invocations: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Create with default mock config.
    pub fn new_default(config: WorkerConfig) -> Self {
        Self::new(config, MockConfig::default())
    }

    /// Get the worker ID.
    pub fn worker_id(&self) -> &WorkerId {
        &self.config.id
    }

    /// Check if "connected".
    pub fn is_connected(&self) -> bool {
        self.connected
    }

    /// Get recorded invocations.
    pub fn invocations(&self) -> Vec<MockInvocation> {
        self.invocations.lock().unwrap().clone()
    }

    /// Clear recorded invocations.
    pub fn clear_invocations(&self) {
        self.invocations.lock().unwrap().clear();
    }

    fn record(&self, phase: Phase, command: Option<String>) {
        let invocation = MockInvocation {
            worker_id: self.config.id.clone(),
            command,
            phase,
            timestamp: std::time::SystemTime::now(),
        };

        let mut invocations = self.invocations.lock().unwrap();
        invocations.push(invocation.clone());

        let mut global = global_ssh_invocations().lock().unwrap();
        global.push(invocation);
    }

    /// Simulate connecting to the worker.
    pub async fn connect(&mut self) -> anyhow::Result<()> {
        log_phase(
            Phase::Connect,
            &format!("Connecting to mock worker {}", self.config.id),
        );
        self.record(Phase::Connect, None);

        if self.mock_config.fail_connect {
            log_phase(
                Phase::Connect,
                &format!("Mock connection failed for {}", self.config.id),
            );
            return Err(anyhow::anyhow!(
                "Mock: Connection failed to {}",
                self.config.id
            ));
        }

        // Transient connect failures (retryable)
        if self
            .connect_failures_remaining
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |current| {
                current.checked_sub(1)
            })
            .is_ok()
        {
            log_phase(
                Phase::Connect,
                &format!("Mock transient connect failure for {}", self.config.id),
            );
            return Err(anyhow::anyhow!(
                "Mock: Connection timed out to {}",
                self.config.id
            ));
        }

        // Simulate connection delay
        tokio::time::sleep(tokio::time::Duration::from_millis(5)).await;

        self.connected = true;
        log_phase(
            Phase::Connect,
            &format!("Mock connected to {}", self.config.id),
        );
        Ok(())
    }

    /// Simulate disconnecting from the worker.
    pub async fn disconnect(&mut self) -> anyhow::Result<()> {
        log_phase(
            Phase::Disconnect,
            &format!("Disconnecting from mock worker {}", self.config.id),
        );
        self.record(Phase::Disconnect, None);
        self.connected = false;
        Ok(())
    }

    /// Simulate executing a command.
    pub async fn execute(&self, command: &str) -> anyhow::Result<CommandResult> {
        if !self.connected {
            return Err(anyhow::anyhow!("Mock: Not connected to worker"));
        }

        log_phase(
            Phase::Execute,
            &format!("Executing on {}: {}", self.config.id, command),
        );
        self.record(Phase::Execute, Some(command.to_string()));

        if self.mock_config.fail_execute {
            log_phase(
                Phase::Execute,
                &format!("Mock execution failed for {}", self.config.id),
            );
            return Err(anyhow::anyhow!("Mock: Command execution failed"));
        }

        // Transient execute failures (retryable)
        if self
            .execute_failures_remaining
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |current| {
                current.checked_sub(1)
            })
            .is_ok()
        {
            log_phase(
                Phase::Execute,
                &format!("Mock transient execute failure for {}", self.config.id),
            );
            return Err(anyhow::anyhow!("Mock: Broken pipe"));
        }

        // Simulate execution delay
        let start = Instant::now();
        tokio::time::sleep(tokio::time::Duration::from_millis(
            self.mock_config.execution_delay_ms,
        ))
        .await;

        // Check for toolchain-related failures
        if self.mock_config.no_rustup && command.contains("rustup") {
            log_phase(
                Phase::Execute,
                "Mock: rustup not available (no_rustup mode)",
            );
            return Ok(CommandResult {
                exit_code: 127,
                stdout: String::new(),
                stderr: "rustup: command not found".to_string(),
                duration_ms: start.elapsed().as_millis() as u64,
            });
        }

        if self.mock_config.fail_toolchain_install
            && command.contains("rustup")
            && (command.contains("toolchain install") || command.contains("run"))
        {
            log_phase(
                Phase::Execute,
                "Mock: toolchain install failed (fail_toolchain_install mode)",
            );
            return Ok(CommandResult {
                exit_code: 1,
                stdout: String::new(),
                stderr: "error: toolchain 'nightly-2024-01-15' is not installed".to_string(),
                duration_ms: start.elapsed().as_millis() as u64,
            });
        }

        // Check for command-specific result
        if let Some(result) = self.mock_config.command_results.get(command) {
            log_phase(
                Phase::Execute,
                &format!(
                    "Mock command completed (specific): exit={}",
                    result.exit_code
                ),
            );
            return Ok(result.clone());
        }

        let result = CommandResult {
            exit_code: self.mock_config.default_exit_code,
            stdout: self.mock_config.default_stdout.clone(),
            stderr: self.mock_config.default_stderr.clone(),
            duration_ms: start.elapsed().as_millis() as u64,
        };

        log_phase(
            Phase::Execute,
            &format!("Mock command completed: exit={}", result.exit_code),
        );
        Ok(result)
    }

    /// Simulate streaming execution.
    pub async fn execute_streaming<F, G>(
        &self,
        command: &str,
        mut on_stdout: F,
        mut on_stderr: G,
    ) -> anyhow::Result<CommandResult>
    where
        F: FnMut(&str),
        G: FnMut(&str),
    {
        let result = self.execute(command).await?;

        // Stream the output line by line
        for line in result.stdout.lines() {
            on_stdout(&format!("{}\n", line));
        }
        for line in result.stderr.lines() {
            on_stderr(&format!("{}\n", line));
        }

        Ok(result)
    }

    /// Simulate health check.
    pub async fn health_check(&self) -> anyhow::Result<bool> {
        match self.execute("echo ok").await {
            Ok(result) => Ok(result.exit_code == 0),
            Err(_) => Ok(false),
        }
    }
}

/// Mock rsync for testing file transfers.
#[derive(Debug, Clone)]
pub struct MockRsyncResult {
    /// Number of files "transferred".
    pub files_transferred: u32,
    /// Bytes "transferred".
    pub bytes_transferred: u64,
    /// Duration in milliseconds.
    pub duration_ms: u64,
}

/// Mock rsync operations.
pub struct MockRsync {
    /// Recorded sync operations.
    sync_invocations: Arc<Mutex<Vec<MockSyncInvocation>>>,
    /// Mock configuration.
    config: MockRsyncConfig,
    /// Remaining transient sync failures to simulate.
    sync_failures_remaining: AtomicU32,
    /// Remaining transient artifact failures to simulate.
    artifacts_failures_remaining: AtomicU32,
}

/// Configuration for mock rsync behavior.
#[derive(Debug, Clone, Default)]
pub struct MockRsyncConfig {
    /// Simulate sync failure.
    pub fail_sync: bool,
    /// Simulate transient sync failures for N attempts (then succeed).
    pub fail_sync_attempts: u32,
    /// Simulate artifact retrieval failure.
    pub fail_artifacts: bool,
    /// Simulate transient artifact failures for N attempts (then succeed).
    pub fail_artifacts_attempts: u32,
    /// Simulated files per sync.
    pub files_per_sync: u32,
    /// Simulated bytes per sync.
    pub bytes_per_sync: u64,
}

impl MockRsyncConfig {
    /// Create default success config.
    pub fn success() -> Self {
        Self {
            fail_sync: false,
            fail_sync_attempts: 0,
            fail_artifacts: false,
            fail_artifacts_attempts: 0,
            files_per_sync: 10,
            bytes_per_sync: 1024 * 100,
        }
    }

    /// Create config that fails sync.
    pub fn sync_failure() -> Self {
        Self {
            fail_sync: true,
            ..Self::default()
        }
    }

    /// Create config that fails artifact retrieval.
    pub fn artifact_failure() -> Self {
        Self {
            fail_artifacts: true,
            ..Self::default()
        }
    }

    /// Build mock rsync config from environment variables.
    pub fn from_env() -> Self {
        if let Some(config) = overrides().lock().unwrap().rsync_config.clone() {
            return config;
        }

        let mut config = MockRsyncConfig::success();

        config.fail_sync = env_flag("RCH_MOCK_RSYNC_FAIL_SYNC");
        config.fail_artifacts = env_flag("RCH_MOCK_RSYNC_FAIL_ARTIFACTS");

        if let Ok(val) = std::env::var("RCH_MOCK_RSYNC_FAIL_SYNC_ATTEMPTS")
            && let Ok(count) = val.parse()
        {
            config.fail_sync_attempts = count;
        }
        if let Ok(val) = std::env::var("RCH_MOCK_RSYNC_FAIL_ARTIFACTS_ATTEMPTS")
            && let Ok(count) = val.parse()
        {
            config.fail_artifacts_attempts = count;
        }

        if let Ok(val) = std::env::var("RCH_MOCK_RSYNC_FILES")
            && let Ok(files) = val.parse()
        {
            config.files_per_sync = files;
        }
        if let Ok(val) = std::env::var("RCH_MOCK_RSYNC_BYTES")
            && let Ok(bytes) = val.parse()
        {
            config.bytes_per_sync = bytes;
        }

        config
    }
}

/// Recorded sync invocation.
#[derive(Debug, Clone)]
pub struct MockSyncInvocation {
    /// Source path.
    pub source: String,
    /// Destination path.
    pub destination: String,
    /// Phase (sync or artifacts).
    pub phase: Phase,
    /// Timestamp.
    pub timestamp: std::time::SystemTime,
}

impl MockRsync {
    /// Create new mock rsync.
    pub fn new(config: MockRsyncConfig) -> Self {
        let sync_failures_remaining = AtomicU32::new(config.fail_sync_attempts);
        let artifacts_failures_remaining = AtomicU32::new(config.fail_artifacts_attempts);
        Self {
            sync_invocations: Arc::new(Mutex::new(Vec::new())),
            sync_failures_remaining,
            artifacts_failures_remaining,
            config,
        }
    }

    /// Create with default config.
    pub fn new_default() -> Self {
        Self::new(MockRsyncConfig::success())
    }

    /// Get recorded invocations.
    pub fn invocations(&self) -> Vec<MockSyncInvocation> {
        self.sync_invocations.lock().unwrap().clone()
    }

    /// Simulate syncing to remote.
    pub async fn sync_to_remote(
        &self,
        source: &str,
        destination: &str,
        _exclude_patterns: &[String],
    ) -> anyhow::Result<MockRsyncResult> {
        log_phase(
            Phase::Sync,
            &format!("Mock sync: {} -> {}", source, destination),
        );

        {
            let invocation = MockSyncInvocation {
                source: source.to_string(),
                destination: destination.to_string(),
                phase: Phase::Sync,
                timestamp: std::time::SystemTime::now(),
            };
            let mut invocations = self.sync_invocations.lock().unwrap();
            invocations.push(invocation.clone());
            global_rsync_invocations().lock().unwrap().push(invocation);
        }

        if self.config.fail_sync {
            log_phase(Phase::Sync, "Mock sync failed");
            return Err(anyhow::anyhow!("Mock: Sync failed"));
        }

        // Transient failures (retryable)
        if self
            .sync_failures_remaining
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |current| {
                current.checked_sub(1)
            })
            .is_ok()
        {
            log_phase(Phase::Sync, "Mock transient sync failure");
            return Err(anyhow::anyhow!(
                "Mock: Sync failed (transient) - Connection timed out"
            ));
        }

        // Simulate transfer delay
        let start = Instant::now();
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

        let result = MockRsyncResult {
            files_transferred: self.config.files_per_sync,
            bytes_transferred: self.config.bytes_per_sync,
            duration_ms: start.elapsed().as_millis() as u64,
        };

        log_phase(
            Phase::Sync,
            &format!(
                "Mock sync complete: {} files, {} bytes",
                result.files_transferred, result.bytes_transferred
            ),
        );

        Ok(result)
    }

    /// Simulate retrieving artifacts.
    pub async fn retrieve_artifacts(
        &self,
        source: &str,
        destination: &str,
        _artifact_patterns: &[String],
    ) -> anyhow::Result<MockRsyncResult> {
        log_phase(
            Phase::Artifacts,
            &format!("Mock artifact retrieval: {} -> {}", source, destination),
        );

        {
            let invocation = MockSyncInvocation {
                source: source.to_string(),
                destination: destination.to_string(),
                phase: Phase::Artifacts,
                timestamp: std::time::SystemTime::now(),
            };
            let mut invocations = self.sync_invocations.lock().unwrap();
            invocations.push(invocation.clone());
            global_rsync_invocations().lock().unwrap().push(invocation);
        }

        if self.config.fail_artifacts {
            log_phase(Phase::Artifacts, "Mock artifact retrieval failed");
            return Err(anyhow::anyhow!("Mock: Artifact retrieval failed"));
        }

        // Transient failures (retryable)
        if self
            .artifacts_failures_remaining
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |current| {
                current.checked_sub(1)
            })
            .is_ok()
        {
            log_phase(
                Phase::Artifacts,
                "Mock transient artifact retrieval failure",
            );
            return Err(anyhow::anyhow!(
                "Mock: Artifact retrieval failed (transient) - Connection reset by peer"
            ));
        }

        // Simulate transfer delay
        let start = Instant::now();
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

        let result = MockRsyncResult {
            files_transferred: self.config.files_per_sync / 2,
            bytes_transferred: self.config.bytes_per_sync * 2,
            duration_ms: start.elapsed().as_millis() as u64,
        };

        log_phase(
            Phase::Artifacts,
            &format!(
                "Mock artifact retrieval complete: {} files, {} bytes",
                result.files_transferred, result.bytes_transferred
            ),
        );

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_mock_enabled_default() {
        // With override disabled, should be false
        set_mock_enabled_override(Some(false));
        assert!(!is_mock_enabled());
        clear_mock_overrides();
    }

    #[test]
    fn test_mock_config_defaults() {
        let config = MockConfig::default();
        assert_eq!(config.default_exit_code, 0);
        assert!(!config.fail_connect);
        assert!(!config.fail_execute);
    }

    #[test]
    fn test_mock_config_connection_failure() {
        let config = MockConfig::connection_failure();
        assert!(config.fail_connect);
    }

    #[test]
    fn test_mock_config_command_failure() {
        let config = MockConfig::command_failure(1, "error message");
        assert_eq!(config.default_exit_code, 1);
        assert_eq!(config.default_stderr, "error message");
    }

    #[tokio::test]
    async fn test_mock_ssh_client_connect() {
        let worker_config = WorkerConfig {
            id: WorkerId::new("mock-worker"),
            host: "mock.host".to_string(),
            user: "mockuser".to_string(),
            identity_file: "~/.ssh/mock".to_string(),
            total_slots: 8,
            priority: 100,
            tags: vec![],
        };

        let mut client = MockSshClient::new_default(worker_config);
        assert!(!client.is_connected());

        client.connect().await.unwrap();
        assert!(client.is_connected());

        client.disconnect().await.unwrap();
        assert!(!client.is_connected());
    }

    #[tokio::test]
    async fn test_mock_ssh_client_execute() {
        let worker_config = WorkerConfig {
            id: WorkerId::new("mock-worker"),
            host: "mock.host".to_string(),
            user: "mockuser".to_string(),
            identity_file: "~/.ssh/mock".to_string(),
            total_slots: 8,
            priority: 100,
            tags: vec![],
        };

        let mut client = MockSshClient::new(
            worker_config,
            MockConfig::default().with_stdout("test output"),
        );

        client.connect().await.unwrap();

        let result = client.execute("echo test").await.unwrap();
        assert_eq!(result.exit_code, 0);
        assert_eq!(result.stdout, "test output");

        let invocations = client.invocations();
        assert_eq!(invocations.len(), 2); // connect + execute
        assert_eq!(invocations[1].command, Some("echo test".to_string()));
    }

    #[tokio::test]
    async fn test_mock_ssh_client_connection_failure() {
        let worker_config = WorkerConfig {
            id: WorkerId::new("mock-worker"),
            host: "mock.host".to_string(),
            user: "mockuser".to_string(),
            identity_file: "~/.ssh/mock".to_string(),
            total_slots: 8,
            priority: 100,
            tags: vec![],
        };

        let mut client = MockSshClient::new(worker_config, MockConfig::connection_failure());

        let result = client.connect().await;
        assert!(result.is_err());
        assert!(!client.is_connected());
    }

    #[tokio::test]
    async fn test_mock_rsync_sync() {
        let rsync = MockRsync::new_default();

        let result = rsync
            .sync_to_remote("/local/path", "user@host:/remote/path", &[])
            .await
            .unwrap();

        assert!(result.files_transferred > 0);
        assert!(result.bytes_transferred > 0);

        let invocations = rsync.invocations();
        assert_eq!(invocations.len(), 1);
        assert_eq!(invocations[0].phase, Phase::Sync);
    }

    #[tokio::test]
    async fn test_mock_rsync_failure() {
        let rsync = MockRsync::new(MockRsyncConfig::sync_failure());

        let result = rsync
            .sync_to_remote("/local/path", "user@host:/remote/path", &[])
            .await;

        assert!(result.is_err());
    }

    #[test]
    fn test_phase_display() {
        assert_eq!(format!("{}", Phase::Sync), "SYNC");
        assert_eq!(format!("{}", Phase::Execute), "EXEC");
        assert_eq!(format!("{}", Phase::Artifacts), "ARTIFACTS");
    }

    #[test]
    fn test_mock_config_toolchain_install_failure() {
        let config = MockConfig::toolchain_install_failure();
        assert!(config.fail_toolchain_install);
        assert!(!config.no_rustup);
    }

    #[test]
    fn test_mock_config_no_rustup() {
        let config = MockConfig::no_rustup();
        assert!(config.no_rustup);
        assert!(!config.fail_toolchain_install);
    }

    #[tokio::test]
    async fn test_mock_ssh_client_no_rustup() {
        let worker_config = WorkerConfig {
            id: WorkerId::new("mock-worker"),
            host: "mock.host".to_string(),
            user: "mockuser".to_string(),
            identity_file: "~/.ssh/mock".to_string(),
            total_slots: 8,
            priority: 100,
            tags: vec![],
        };

        let mut client = MockSshClient::new(worker_config, MockConfig::no_rustup());
        client.connect().await.unwrap();

        // Any rustup command should fail with command not found
        let result = client.execute("rustup --version").await.unwrap();
        assert_eq!(result.exit_code, 127);
        assert!(result.stderr.contains("command not found"));
    }

    #[tokio::test]
    async fn test_mock_ssh_client_toolchain_install_failure() {
        let worker_config = WorkerConfig {
            id: WorkerId::new("mock-worker"),
            host: "mock.host".to_string(),
            user: "mockuser".to_string(),
            identity_file: "~/.ssh/mock".to_string(),
            total_slots: 8,
            priority: 100,
            tags: vec![],
        };

        let mut client = MockSshClient::new(worker_config, MockConfig::toolchain_install_failure());
        client.connect().await.unwrap();

        // Toolchain install commands should fail
        let result = client
            .execute("rustup toolchain install nightly-2024-01-15")
            .await
            .unwrap();
        assert_eq!(result.exit_code, 1);
        assert!(result.stderr.contains("is not installed"));

        // Rustup run commands should also fail
        let result = client
            .execute("rustup run nightly-2024-01-15 cargo build")
            .await
            .unwrap();
        assert_eq!(result.exit_code, 1);
        assert!(result.stderr.contains("is not installed"));
    }

    #[tokio::test]
    async fn test_mock_ssh_client_normal_command_with_toolchain_failure() {
        let worker_config = WorkerConfig {
            id: WorkerId::new("mock-worker"),
            host: "mock.host".to_string(),
            user: "mockuser".to_string(),
            identity_file: "~/.ssh/mock".to_string(),
            total_slots: 8,
            priority: 100,
            tags: vec![],
        };

        let mut client = MockSshClient::new(worker_config, MockConfig::toolchain_install_failure());
        client.connect().await.unwrap();

        // Non-rustup commands should still succeed
        let result = client.execute("cargo build").await.unwrap();
        assert_eq!(result.exit_code, 0);
    }
}
