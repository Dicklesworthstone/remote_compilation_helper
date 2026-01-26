//! Test worker configuration loading for true E2E tests.
//!
//! This module handles loading and validating worker configurations
//! specifically for end-to-end testing scenarios that require real
//! SSH-accessible worker machines.
//!
//! # Configuration File
//!
//! Tests use the configuration in `tests/true_e2e/workers_test.toml`.
//! Override with the `RCH_E2E_WORKERS_CONFIG` environment variable.
//!
//! # Example Configuration
//!
//! ```toml
//! [settings]
//! default_timeout_secs = 300
//! ssh_connection_timeout_secs = 10
//! remote_work_dir = "/tmp/rch_test"
//!
//! [[workers]]
//! id = "test-worker"
//! host = "192.168.1.100"
//! user = "ubuntu"
//! identity_file = "~/.ssh/id_rsa"
//! total_slots = 16
//! enabled = true
//! ```

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use super::logging::{LogLevel, LogSource, TestLogger};

/// Environment variable to override config file location.
pub const ENV_WORKERS_CONFIG: &str = "RCH_E2E_WORKERS_CONFIG";

/// Environment variable to skip worker availability checks.
pub const ENV_SKIP_WORKER_CHECK: &str = "RCH_E2E_SKIP_WORKER_CHECK";

/// Environment variable to skip all true E2E tests.
pub const ENV_SKIP_ALL_TESTS: &str = "RCH_E2E_SKIP";

/// Environment variable to override command timeout.
pub const ENV_TIMEOUT_SECS: &str = "RCH_E2E_TIMEOUT_SECS";

/// Default config file path relative to workspace root.
pub const DEFAULT_CONFIG_PATH: &str = "tests/true_e2e/workers_test.toml";

/// Error type for configuration operations.
#[derive(Debug, thiserror::Error)]
pub enum TestConfigError {
    #[error("Configuration file not found: {0}")]
    NotFound(PathBuf),

    #[error("Failed to read configuration file: {0}")]
    ReadError(#[from] std::io::Error),

    #[error("Failed to parse configuration: {0}")]
    ParseError(#[from] toml::de::Error),

    #[error("Invalid configuration: {0}")]
    ValidationError(String),

    #[error("No workers configured")]
    NoWorkersConfigured,

    #[error("Path expansion failed for: {0}")]
    PathExpansionFailed(String),
}

/// Result type for configuration operations.
pub type TestConfigResult<T> = Result<T, TestConfigError>;

/// Test-specific settings for E2E tests.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestSettings {
    /// Default timeout for test commands in seconds.
    #[serde(default = "default_timeout_secs")]
    pub default_timeout_secs: u64,

    /// SSH connection timeout in seconds.
    #[serde(default = "default_ssh_timeout")]
    pub ssh_connection_timeout_secs: u64,

    /// Remote working directory for test artifacts.
    #[serde(default = "default_remote_work_dir")]
    pub remote_work_dir: String,

    /// Rsync compression method.
    #[serde(default = "default_rsync_compression")]
    pub rsync_compression: String,

    /// Whether to clean up remote artifacts after tests.
    #[serde(default = "default_cleanup_after_test")]
    pub cleanup_after_test: bool,

    /// Minimum required Rust version on workers.
    #[serde(default)]
    pub min_rust_version: Option<String>,
}

impl Default for TestSettings {
    fn default() -> Self {
        Self {
            default_timeout_secs: default_timeout_secs(),
            ssh_connection_timeout_secs: default_ssh_timeout(),
            remote_work_dir: default_remote_work_dir(),
            rsync_compression: default_rsync_compression(),
            cleanup_after_test: default_cleanup_after_test(),
            min_rust_version: None,
        }
    }
}

fn default_timeout_secs() -> u64 {
    300
}

fn default_ssh_timeout() -> u64 {
    10
}

fn default_remote_work_dir() -> String {
    "/tmp/rch_test".to_string()
}

fn default_rsync_compression() -> String {
    "zstd".to_string()
}

fn default_cleanup_after_test() -> bool {
    true
}

/// Single worker entry in test configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestWorkerEntry {
    /// Unique identifier for this worker.
    pub id: String,

    /// SSH hostname or IP address.
    pub host: String,

    /// SSH username.
    #[serde(default = "default_user")]
    pub user: String,

    /// SSH port.
    #[serde(default = "default_port")]
    pub port: u16,

    /// Path to SSH private key.
    #[serde(default = "default_identity_file")]
    pub identity_file: String,

    /// Total CPU slots available on this worker.
    #[serde(default = "default_slots")]
    pub total_slots: u32,

    /// Priority for worker selection (higher = preferred).
    #[serde(default = "default_priority")]
    pub priority: u32,

    /// Optional tags for filtering.
    #[serde(default)]
    pub tags: Vec<String>,

    /// Whether this worker is enabled.
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

fn default_user() -> String {
    "ubuntu".to_string()
}

fn default_port() -> u16 {
    22
}

fn default_identity_file() -> String {
    "~/.ssh/id_rsa".to_string()
}

fn default_slots() -> u32 {
    8
}

fn default_priority() -> u32 {
    100
}

fn default_enabled() -> bool {
    true
}

impl TestWorkerEntry {
    /// Expand tilde in the identity file path.
    pub fn expanded_identity_file(&self) -> TestConfigResult<PathBuf> {
        expand_tilde_path(&self.identity_file)
    }

    /// Convert to the standard WorkerConfig type for daemon integration.
    pub fn to_worker_config(&self) -> crate::WorkerConfig {
        crate::WorkerConfig {
            id: crate::WorkerId::new(&self.id),
            host: self.host.clone(),
            user: self.user.clone(),
            identity_file: self.identity_file.clone(),
            total_slots: self.total_slots,
            priority: self.priority,
            tags: self.tags.clone(),
        }
    }
}

/// Complete test worker configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TestWorkersConfig {
    /// Test-specific settings.
    #[serde(default)]
    pub settings: TestSettings,

    /// List of worker definitions.
    #[serde(default)]
    pub workers: Vec<TestWorkerEntry>,
}

impl TestWorkersConfig {
    /// Load configuration from the default path or environment override.
    pub fn load() -> TestConfigResult<Self> {
        let path = get_config_path();
        Self::load_from(&path)
    }

    /// Load configuration from a specific path.
    pub fn load_from(path: &Path) -> TestConfigResult<Self> {
        if !path.exists() {
            return Err(TestConfigError::NotFound(path.to_path_buf()));
        }

        let contents = std::fs::read_to_string(path)?;
        let config: TestWorkersConfig = toml::from_str(&contents)?;

        config.validate()?;
        Ok(config)
    }

    /// Try to load configuration, returning None if not found.
    pub fn try_load() -> Option<Self> {
        Self::load().ok()
    }

    /// Validate the configuration.
    pub fn validate(&self) -> TestConfigResult<()> {
        // Check for duplicate worker IDs
        let mut seen_ids: HashMap<&str, usize> = HashMap::new();
        for (i, worker) in self.workers.iter().enumerate() {
            if let Some(prev_idx) = seen_ids.insert(&worker.id, i) {
                return Err(TestConfigError::ValidationError(format!(
                    "Duplicate worker ID '{}' at indices {} and {}",
                    worker.id, prev_idx, i
                )));
            }

            // Validate individual worker entries
            if worker.host.is_empty() {
                return Err(TestConfigError::ValidationError(format!(
                    "Worker '{}' has empty hostname",
                    worker.id
                )));
            }

            if worker.user.is_empty() {
                return Err(TestConfigError::ValidationError(format!(
                    "Worker '{}' has empty username",
                    worker.id
                )));
            }
        }

        Ok(())
    }

    /// Get only enabled workers.
    pub fn enabled_workers(&self) -> Vec<&TestWorkerEntry> {
        self.workers.iter().filter(|w| w.enabled).collect()
    }

    /// Check if any workers are configured.
    pub fn has_workers(&self) -> bool {
        !self.workers.is_empty()
    }

    /// Check if any workers are enabled.
    pub fn has_enabled_workers(&self) -> bool {
        self.workers.iter().any(|w| w.enabled)
    }

    /// Get the effective timeout, considering environment override.
    pub fn effective_timeout_secs(&self) -> u64 {
        std::env::var(ENV_TIMEOUT_SECS)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(self.settings.default_timeout_secs)
    }

    /// Convert all enabled workers to standard WorkerConfig for daemon integration.
    pub fn to_worker_configs(&self) -> Vec<crate::WorkerConfig> {
        self.enabled_workers()
            .iter()
            .map(|w| w.to_worker_config())
            .collect()
    }
}

/// Get the configuration file path, considering environment override.
pub fn get_config_path() -> PathBuf {
    if let Ok(override_path) = std::env::var(ENV_WORKERS_CONFIG) {
        return PathBuf::from(override_path);
    }

    // Try to find the config relative to CARGO_MANIFEST_DIR
    if let Ok(manifest_dir) = std::env::var("CARGO_MANIFEST_DIR") {
        // Go up one level from the crate directory to workspace root
        let path = PathBuf::from(manifest_dir)
            .parent()
            .map(|p| p.join(DEFAULT_CONFIG_PATH))
            .unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG_PATH));
        if path.exists() {
            return path;
        }
    }

    // Fall back to relative path from current directory
    PathBuf::from(DEFAULT_CONFIG_PATH)
}

/// Expand tilde (~) in a path to the user's home directory.
pub fn expand_tilde_path(path: &str) -> TestConfigResult<PathBuf> {
    if let Some(rest) = path.strip_prefix("~/") {
        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .map_err(|_| TestConfigError::PathExpansionFailed(path.to_string()))?;
        Ok(PathBuf::from(home).join(rest))
    } else if path == "~" {
        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .map_err(|_| TestConfigError::PathExpansionFailed(path.to_string()))?;
        Ok(PathBuf::from(home))
    } else {
        Ok(PathBuf::from(path))
    }
}

/// Check if worker availability checks should be skipped.
pub fn should_skip_worker_check() -> bool {
    std::env::var(ENV_SKIP_WORKER_CHECK)
        .map(|v| v == "1" || v.to_lowercase() == "true")
        .unwrap_or(false)
}

/// Check if all true E2E tests should be skipped.
pub fn should_skip_all_tests() -> bool {
    std::env::var(ENV_SKIP_ALL_TESTS)
        .map(|v| v == "1" || v.to_lowercase() == "true")
        .unwrap_or(false)
}

/// Check if mock SSH mode is enabled (for CI testing without real workers).
pub fn is_mock_ssh_mode() -> bool {
    std::env::var("RCH_MOCK_SSH")
        .map(|v| v == "1" || v.to_lowercase() == "true")
        .unwrap_or(false)
}

fn is_ci() -> bool {
    std::env::var("CI")
        .map(|v| v == "1" || v.to_lowercase() == "true")
        .unwrap_or(false)
}

fn log_skip_event(
    logger: &TestLogger,
    level: LogLevel,
    message: &str,
    context: Vec<(String, String)>,
) {
    let mut ctx = Vec::with_capacity(context.len() + 1);
    ctx.push(("phase".to_string(), "skip_check".to_string()));
    ctx.extend(context);
    logger.log_with_context(
        level,
        LogSource::Custom("skip_check".to_string()),
        message,
        ctx,
    );
}

fn ping_worker(host: &str, port: u16, timeout: Duration) -> Result<bool, std::io::Error> {
    let addrs = (host, port).to_socket_addrs()?;
    for addr in addrs {
        if TcpStream::connect_timeout(&addr, timeout).is_ok() {
            return Ok(true);
        }
    }
    Ok(false)
}

fn effective_ping_timeout(settings: &TestSettings) -> Duration {
    let requested = settings.ssh_connection_timeout_secs.max(1);
    let cap = if is_ci() { 3 } else { 8 };
    Duration::from_secs(requested.min(cap))
}

/// Load worker config and verify at least one reachable worker.
/// Returns None when tests should be skipped, with structured logs explaining why.
pub fn require_workers(logger: &TestLogger) -> Option<TestWorkersConfig> {
    let config_path = get_config_path();
    log_skip_event(
        logger,
        LogLevel::Info,
        "Checking worker availability",
        vec![
            ("config_path".to_string(), config_path.display().to_string()),
            ("ci".to_string(), is_ci().to_string()),
        ],
    );

    if should_skip_all_tests() {
        log_skip_event(
            logger,
            LogLevel::Info,
            "E2E tests disabled via env",
            vec![
                ("reason".to_string(), "env_skip_all".to_string()),
                ("env".to_string(), ENV_SKIP_ALL_TESTS.to_string()),
                ("skip".to_string(), "true".to_string()),
            ],
        );
        return None;
    }

    let config = match TestWorkersConfig::load_from(&config_path) {
        Ok(config) => config,
        Err(TestConfigError::NotFound(path)) => {
            log_skip_event(
                logger,
                LogLevel::Info,
                "Workers unavailable, skipping test",
                vec![
                    ("reason".to_string(), "config_not_found".to_string()),
                    ("path".to_string(), path.display().to_string()),
                    ("skip".to_string(), "true".to_string()),
                ],
            );
            return None;
        }
        Err(e) => {
            log_skip_event(
                logger,
                LogLevel::Warn,
                "Workers unavailable, skipping test",
                vec![
                    ("reason".to_string(), "config_load_failed".to_string()),
                    ("error".to_string(), e.to_string()),
                    ("skip".to_string(), "true".to_string()),
                ],
            );
            return None;
        }
    };

    if !config.has_enabled_workers() {
        log_skip_event(
            logger,
            LogLevel::Info,
            "Workers unavailable, skipping test",
            vec![
                ("reason".to_string(), "no_enabled_workers".to_string()),
                ("configured".to_string(), config.workers.len().to_string()),
                ("skip".to_string(), "true".to_string()),
            ],
        );
        return None;
    }

    if should_skip_worker_check() {
        log_skip_event(
            logger,
            LogLevel::Info,
            "Skipping worker reachability check via env",
            vec![
                ("reason".to_string(), "env_skip_check".to_string()),
                ("env".to_string(), ENV_SKIP_WORKER_CHECK.to_string()),
                ("skip".to_string(), "false".to_string()),
            ],
        );
        return Some(config);
    }

    let timeout = effective_ping_timeout(&config.settings);
    let mut reachable = 0usize;

    for worker in config.enabled_workers() {
        let start = Instant::now();
        let outcome = ping_worker(&worker.host, worker.port, timeout);
        let elapsed_ms = start.elapsed().as_millis().to_string();

        match outcome {
            Ok(true) => {
                reachable += 1;
                logger.log_with_context(
                    LogLevel::Info,
                    LogSource::Custom("skip_check".to_string()),
                    "Worker reachable",
                    vec![
                        ("phase".to_string(), "skip_check".to_string()),
                        ("worker_id".to_string(), worker.id.clone()),
                        ("host".to_string(), worker.host.clone()),
                        ("port".to_string(), worker.port.to_string()),
                        ("reachable".to_string(), "true".to_string()),
                        ("duration_ms".to_string(), elapsed_ms),
                    ],
                );
            }
            Ok(false) => {
                logger.log_with_context(
                    LogLevel::Warn,
                    LogSource::Custom("skip_check".to_string()),
                    "Worker unreachable",
                    vec![
                        ("phase".to_string(), "skip_check".to_string()),
                        ("worker_id".to_string(), worker.id.clone()),
                        ("host".to_string(), worker.host.clone()),
                        ("port".to_string(), worker.port.to_string()),
                        ("reachable".to_string(), "false".to_string()),
                        ("duration_ms".to_string(), elapsed_ms),
                    ],
                );
            }
            Err(e) => {
                logger.log_with_context(
                    LogLevel::Warn,
                    LogSource::Custom("skip_check".to_string()),
                    "Worker reachability check failed",
                    vec![
                        ("phase".to_string(), "skip_check".to_string()),
                        ("worker_id".to_string(), worker.id.clone()),
                        ("host".to_string(), worker.host.clone()),
                        ("port".to_string(), worker.port.to_string()),
                        ("error".to_string(), e.to_string()),
                        ("duration_ms".to_string(), elapsed_ms),
                    ],
                );
            }
        }
    }

    if reachable == 0 {
        log_skip_event(
            logger,
            LogLevel::Info,
            "Workers unavailable, skipping test",
            vec![
                ("reason".to_string(), "no_reachable_workers".to_string()),
                (
                    "configured".to_string(),
                    config.enabled_workers().len().to_string(),
                ),
                ("reachable".to_string(), reachable.to_string()),
                ("skip".to_string(), "true".to_string()),
            ],
        );
        return None;
    }

    log_skip_event(
        logger,
        LogLevel::Info,
        "Worker availability check complete",
        vec![
            (
                "configured".to_string(),
                config.enabled_workers().len().to_string(),
            ),
            ("reachable".to_string(), reachable.to_string()),
            ("skip".to_string(), "false".to_string()),
        ],
    );

    Some(config)
}

#[cfg(test)]
#[allow(unsafe_code)] // Tests need to set/remove env vars, which is unsafe in Rust 2024
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    #[test]
    fn test_config_parses_valid_toml() {
        let config_str = r#"
[settings]
default_timeout_secs = 300

[[workers]]
id = "test"
host = "test.example.com"
user = "builder"
"#;
        let config: TestWorkersConfig = toml::from_str(config_str).unwrap();
        assert_eq!(config.workers.len(), 1);
        assert_eq!(config.workers[0].id, "test");
        assert_eq!(config.workers[0].host, "test.example.com");
    }

    #[test]
    fn test_config_rejects_missing_hostname() {
        let config_str = r#"
[[workers]]
id = "test"
user = "builder"
"#;
        let result: Result<TestWorkersConfig, _> = toml::from_str(config_str);
        assert!(result.is_err());
    }

    #[test]
    fn test_config_rejects_missing_id() {
        let config_str = r#"
[[workers]]
host = "test.example.com"
user = "builder"
"#;
        let result: Result<TestWorkersConfig, _> = toml::from_str(config_str);
        assert!(result.is_err());
    }

    #[test]
    fn test_config_default_port() {
        let config_str = r#"
[[workers]]
id = "test"
host = "test.example.com"
user = "builder"
"#;
        let config: TestWorkersConfig = toml::from_str(config_str).unwrap();
        assert_eq!(config.workers[0].port, 22);
    }

    #[test]
    fn test_config_custom_port() {
        let config_str = r#"
[[workers]]
id = "test"
host = "test.example.com"
user = "builder"
port = 2222
"#;
        let config: TestWorkersConfig = toml::from_str(config_str).unwrap();
        assert_eq!(config.workers[0].port, 2222);
    }

    #[test]
    fn test_config_expands_home_in_identity_file() {
        let config_str = r#"
[[workers]]
id = "test"
host = "test.example.com"
user = "builder"
identity_file = "~/.ssh/id_ed25519"
"#;
        let config: TestWorkersConfig = toml::from_str(config_str).unwrap();
        let expanded = config.workers[0].expanded_identity_file().unwrap();
        assert!(!expanded.to_string_lossy().contains("~"));
    }

    #[test]
    fn test_config_from_env_override() {
        let temp_dir = TempDir::new().unwrap();
        let custom_path = temp_dir.path().join("custom_workers.toml");

        // SAFETY: Test isolation - env var is set and removed in same test
        unsafe {
            std::env::set_var(ENV_WORKERS_CONFIG, custom_path.to_string_lossy().as_ref());
        }
        let path = get_config_path();
        assert_eq!(path, custom_path);
        unsafe {
            std::env::remove_var(ENV_WORKERS_CONFIG);
        }
    }

    #[test]
    fn test_config_missing_file_returns_error() {
        let result = TestWorkersConfig::load_from(Path::new("/nonexistent/workers_test.toml"));
        assert!(result.is_err());
        match result {
            Err(TestConfigError::NotFound(_)) => {}
            _ => panic!("Expected NotFound error"),
        }
    }

    #[test]
    fn test_config_empty_workers_is_valid() {
        let config_str = r#"
[settings]
default_timeout_secs = 300
"#;
        let config: TestWorkersConfig = toml::from_str(config_str).unwrap();
        assert!(config.workers.is_empty());
        assert!(!config.has_workers());
    }

    #[test]
    fn test_config_duplicate_worker_ids_rejected() {
        let config_str = r#"
[[workers]]
id = "duplicate"
host = "host1.example.com"

[[workers]]
id = "duplicate"
host = "host2.example.com"
"#;
        let config: TestWorkersConfig = toml::from_str(config_str).unwrap();
        let result = config.validate();
        assert!(result.is_err());
        match result {
            Err(TestConfigError::ValidationError(msg)) => {
                assert!(msg.contains("Duplicate worker ID"));
            }
            _ => panic!("Expected ValidationError"),
        }
    }

    #[test]
    fn test_config_enabled_workers_filter() {
        let config_str = r#"
[[workers]]
id = "enabled1"
host = "host1.example.com"
enabled = true

[[workers]]
id = "disabled"
host = "host2.example.com"
enabled = false

[[workers]]
id = "enabled2"
host = "host3.example.com"
enabled = true
"#;
        let config: TestWorkersConfig = toml::from_str(config_str).unwrap();
        let enabled = config.enabled_workers();
        assert_eq!(enabled.len(), 2);
        assert_eq!(enabled[0].id, "enabled1");
        assert_eq!(enabled[1].id, "enabled2");
    }

    #[test]
    fn test_config_default_settings() {
        let config_str = r#"
[[workers]]
id = "test"
host = "test.example.com"
"#;
        let config: TestWorkersConfig = toml::from_str(config_str).unwrap();
        assert_eq!(config.settings.default_timeout_secs, 300);
        assert_eq!(config.settings.ssh_connection_timeout_secs, 10);
        assert_eq!(config.settings.remote_work_dir, "/tmp/rch_test");
        assert_eq!(config.settings.rsync_compression, "zstd");
        assert!(config.settings.cleanup_after_test);
    }

    #[test]
    fn test_config_custom_settings() {
        let config_str = r#"
[settings]
default_timeout_secs = 600
ssh_connection_timeout_secs = 30
remote_work_dir = "/data/rch_test"
rsync_compression = "lz4"
cleanup_after_test = false
min_rust_version = "1.85.0"

[[workers]]
id = "test"
host = "test.example.com"
"#;
        let config: TestWorkersConfig = toml::from_str(config_str).unwrap();
        assert_eq!(config.settings.default_timeout_secs, 600);
        assert_eq!(config.settings.ssh_connection_timeout_secs, 30);
        assert_eq!(config.settings.remote_work_dir, "/data/rch_test");
        assert_eq!(config.settings.rsync_compression, "lz4");
        assert!(!config.settings.cleanup_after_test);
        assert_eq!(config.settings.min_rust_version, Some("1.85.0".to_string()));
    }

    #[test]
    fn test_effective_timeout_from_env() {
        let config_str = r#"
[settings]
default_timeout_secs = 300

[[workers]]
id = "test"
host = "test.example.com"
"#;
        let config: TestWorkersConfig = toml::from_str(config_str).unwrap();

        // Without env var, use config value
        assert_eq!(config.effective_timeout_secs(), 300);

        // With env var, use override
        // SAFETY: Test isolation
        unsafe {
            std::env::set_var(ENV_TIMEOUT_SECS, "600");
        }
        assert_eq!(config.effective_timeout_secs(), 600);
        unsafe {
            std::env::remove_var(ENV_TIMEOUT_SECS);
        }
    }

    #[test]
    fn test_config_loads_from_file() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("workers_test.toml");

        let config_content = r#"
[settings]
default_timeout_secs = 120

[[workers]]
id = "file-test"
host = "192.168.1.100"
user = "testuser"
total_slots = 16
"#;
        let mut file = std::fs::File::create(&config_path).unwrap();
        file.write_all(config_content.as_bytes()).unwrap();

        let config = TestWorkersConfig::load_from(&config_path).unwrap();
        assert_eq!(config.settings.default_timeout_secs, 120);
        assert_eq!(config.workers.len(), 1);
        assert_eq!(config.workers[0].id, "file-test");
        assert_eq!(config.workers[0].total_slots, 16);
    }

    #[test]
    fn test_should_skip_worker_check() {
        // Default is false
        unsafe {
            std::env::remove_var(ENV_SKIP_WORKER_CHECK);
        }
        assert!(!should_skip_worker_check());

        // Set to "1"
        unsafe {
            std::env::set_var(ENV_SKIP_WORKER_CHECK, "1");
        }
        assert!(should_skip_worker_check());

        // Set to "true"
        unsafe {
            std::env::set_var(ENV_SKIP_WORKER_CHECK, "true");
        }
        assert!(should_skip_worker_check());

        // Set to "0" (false)
        unsafe {
            std::env::set_var(ENV_SKIP_WORKER_CHECK, "0");
        }
        assert!(!should_skip_worker_check());

        // Clean up
        unsafe {
            std::env::remove_var(ENV_SKIP_WORKER_CHECK);
        }
    }

    #[test]
    fn test_expand_path_tilde() {
        let expanded = expand_tilde_path("~/.ssh/id_rsa").unwrap();
        assert!(!expanded.to_string_lossy().starts_with("~"));
        assert!(expanded.to_string_lossy().ends_with(".ssh/id_rsa"));
    }

    #[test]
    fn test_expand_path_absolute() {
        let expanded = expand_tilde_path("/etc/ssh/ssh_host_key").unwrap();
        assert_eq!(expanded, PathBuf::from("/etc/ssh/ssh_host_key"));
    }

    #[test]
    fn test_expand_path_relative() {
        let expanded = expand_tilde_path("./keys/id_rsa").unwrap();
        assert_eq!(expanded, PathBuf::from("./keys/id_rsa"));
    }

    #[test]
    fn test_worker_tags() {
        let config_str = r#"
[[workers]]
id = "tagged"
host = "test.example.com"
tags = ["rust", "fast", "production"]
"#;
        let config: TestWorkersConfig = toml::from_str(config_str).unwrap();
        assert_eq!(config.workers[0].tags.len(), 3);
        assert!(config.workers[0].tags.contains(&"rust".to_string()));
        assert!(config.workers[0].tags.contains(&"fast".to_string()));
        assert!(config.workers[0].tags.contains(&"production".to_string()));
    }

    #[test]
    fn test_config_all_default_values() {
        let config_str = r#"
[[workers]]
id = "minimal"
host = "minimal.example.com"
"#;
        let config: TestWorkersConfig = toml::from_str(config_str).unwrap();
        let worker = &config.workers[0];

        assert_eq!(worker.user, "ubuntu");
        assert_eq!(worker.port, 22);
        assert_eq!(worker.identity_file, "~/.ssh/id_rsa");
        assert_eq!(worker.total_slots, 8);
        assert_eq!(worker.priority, 100);
        assert!(worker.tags.is_empty());
        assert!(worker.enabled);
    }

    #[test]
    fn test_validation_empty_hostname_rejected() {
        let config = TestWorkersConfig {
            settings: TestSettings::default(),
            workers: vec![TestWorkerEntry {
                id: "test".to_string(),
                host: String::new(), // Empty!
                user: "ubuntu".to_string(),
                port: 22,
                identity_file: "~/.ssh/id_rsa".to_string(),
                total_slots: 8,
                priority: 100,
                tags: vec![],
                enabled: true,
            }],
        };
        let result = config.validate();
        assert!(result.is_err());
        match result {
            Err(TestConfigError::ValidationError(msg)) => {
                assert!(msg.contains("empty hostname"));
            }
            _ => panic!("Expected ValidationError"),
        }
    }

    #[test]
    fn test_validation_empty_username_rejected() {
        let config = TestWorkersConfig {
            settings: TestSettings::default(),
            workers: vec![TestWorkerEntry {
                id: "test".to_string(),
                host: "test.example.com".to_string(),
                user: String::new(), // Empty!
                port: 22,
                identity_file: "~/.ssh/id_rsa".to_string(),
                total_slots: 8,
                priority: 100,
                tags: vec![],
                enabled: true,
            }],
        };
        let result = config.validate();
        assert!(result.is_err());
        match result {
            Err(TestConfigError::ValidationError(msg)) => {
                assert!(msg.contains("empty username"));
            }
            _ => panic!("Expected ValidationError"),
        }
    }

    #[test]
    fn test_to_worker_config_conversion() {
        let config_str = r#"
[[workers]]
id = "convert-test"
host = "192.168.1.50"
user = "admin"
identity_file = "~/.ssh/admin_key"
total_slots = 32
priority = 150
tags = ["fast", "ssd"]
"#;
        let config: TestWorkersConfig = toml::from_str(config_str).unwrap();
        let worker_config = config.workers[0].to_worker_config();

        assert_eq!(worker_config.id.as_str(), "convert-test");
        assert_eq!(worker_config.host, "192.168.1.50");
        assert_eq!(worker_config.user, "admin");
        assert_eq!(worker_config.identity_file, "~/.ssh/admin_key");
        assert_eq!(worker_config.total_slots, 32);
        assert_eq!(worker_config.priority, 150);
        assert_eq!(worker_config.tags, vec!["fast", "ssd"]);
    }

    #[test]
    fn test_to_worker_configs_batch() {
        let config_str = r#"
[[workers]]
id = "worker1"
host = "host1.example.com"
enabled = true

[[workers]]
id = "worker2"
host = "host2.example.com"
enabled = false

[[workers]]
id = "worker3"
host = "host3.example.com"
enabled = true
"#;
        let config: TestWorkersConfig = toml::from_str(config_str).unwrap();
        let worker_configs = config.to_worker_configs();

        // Only enabled workers should be converted
        assert_eq!(worker_configs.len(), 2);
        assert_eq!(worker_configs[0].id.as_str(), "worker1");
        assert_eq!(worker_configs[1].id.as_str(), "worker3");
    }
}
