//! Configuration loading for the RCH daemon.
//!
//! Loads worker definitions from workers.toml and daemon settings from config.toml.

use anyhow::{Context, Result};
use rch_common::WorkerConfig;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};

/// Default config directory name.
const CONFIG_DIR_NAME: &str = "rch";

/// Default workers config file name.
const WORKERS_FILE_NAME: &str = "workers.toml";

/// Default daemon config file name.
#[allow(dead_code)] // Used when daemon config loading is integrated
const DAEMON_FILE_NAME: &str = "daemon.toml";

/// Daemon configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonConfig {
    /// Unix socket path for hook communication.
    #[serde(default = "default_socket_path")]
    pub socket_path: PathBuf,

    /// Health check interval in seconds.
    #[serde(default = "default_health_interval")]
    pub health_check_interval_secs: u64,

    /// Worker timeout before marking as unreachable.
    #[serde(default = "default_worker_timeout")]
    pub worker_timeout_secs: u64,

    /// Maximum concurrent jobs per worker slot.
    #[serde(default = "default_max_jobs_per_slot")]
    pub max_jobs_per_slot: u32,

    /// Enable SSH connection pooling.
    #[serde(default = "default_true")]
    pub connection_pooling: bool,

    /// Log level (trace, debug, info, warn, error).
    #[serde(default = "default_log_level")]
    pub log_level: String,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            socket_path: PathBuf::from("/tmp/rch.sock"),
            health_check_interval_secs: 30,
            worker_timeout_secs: 10,
            max_jobs_per_slot: 1,
            connection_pooling: true,
            log_level: "info".to_string(),
        }
    }
}

/// Workers configuration file structure.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WorkersConfig {
    /// List of worker definitions.
    #[serde(default)]
    pub workers: Vec<WorkerEntry>,
}

/// Single worker entry in configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerEntry {
    /// Unique identifier for this worker.
    pub id: String,

    /// SSH hostname or IP address.
    pub host: String,

    /// SSH username.
    #[serde(default = "default_user")]
    pub user: String,

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
    #[serde(default = "default_true")]
    pub enabled: bool,
}

impl From<WorkerEntry> for WorkerConfig {
    fn from(entry: WorkerEntry) -> Self {
        WorkerConfig {
            id: rch_common::WorkerId::new(entry.id),
            host: entry.host,
            user: entry.user,
            identity_file: entry.identity_file,
            total_slots: entry.total_slots,
            priority: entry.priority,
            tags: entry.tags,
        }
    }
}

// Default value functions
fn default_socket_path() -> PathBuf {
    PathBuf::from("/tmp/rch.sock")
}

fn default_health_interval() -> u64 {
    30
}

fn default_worker_timeout() -> u64 {
    10
}

fn default_max_jobs_per_slot() -> u32 {
    1
}

fn default_true() -> bool {
    true
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_user() -> String {
    "ubuntu".to_string()
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

/// Get the configuration directory path.
pub fn config_dir() -> Option<PathBuf> {
    directories::ProjectDirs::from("com", "rch", CONFIG_DIR_NAME)
        .map(|dirs| dirs.config_dir().to_path_buf())
}

/// Load daemon configuration from file.
#[allow(dead_code)] // Will be used when daemon config CLI is added
pub fn load_daemon_config(path: Option<&Path>) -> Result<DaemonConfig> {
    let config_path = match path {
        Some(p) => p.to_path_buf(),
        None => {
            let dir = config_dir().context("Could not determine config directory")?;
            dir.join(DAEMON_FILE_NAME)
        }
    };

    if !config_path.exists() {
        debug!(
            "Daemon config not found at {:?}, using defaults",
            config_path
        );
        return Ok(DaemonConfig::default());
    }

    info!("Loading daemon config from {:?}", config_path);
    let contents = std::fs::read_to_string(&config_path)
        .with_context(|| format!("Failed to read daemon config from {:?}", config_path))?;

    let config: DaemonConfig = toml::from_str(&contents)
        .with_context(|| format!("Failed to parse daemon config from {:?}", config_path))?;

    Ok(config)
}

/// Load workers configuration from file.
pub fn load_workers_config(path: Option<&Path>) -> Result<WorkersConfig> {
    let config_path = match path {
        Some(p) => p.to_path_buf(),
        None => {
            let dir = config_dir().context("Could not determine config directory")?;
            dir.join(WORKERS_FILE_NAME)
        }
    };

    if !config_path.exists() {
        warn!("Workers config not found at {:?}", config_path);
        return Ok(WorkersConfig::default());
    }

    info!("Loading workers config from {:?}", config_path);
    let contents = std::fs::read_to_string(&config_path)
        .with_context(|| format!("Failed to read workers config from {:?}", config_path))?;

    let config: WorkersConfig = toml::from_str(&contents)
        .with_context(|| format!("Failed to parse workers config from {:?}", config_path))?;

    info!("Loaded {} worker definitions", config.workers.len());
    Ok(config)
}

/// Load enabled workers as WorkerConfig instances.
pub fn load_workers(path: Option<&Path>) -> Result<Vec<WorkerConfig>> {
    let config = load_workers_config(path)?;

    let workers: Vec<WorkerConfig> = config
        .workers
        .into_iter()
        .filter(|w| w.enabled)
        .map(WorkerConfig::from)
        .collect();

    debug!("Loaded {} enabled workers", workers.len());
    Ok(workers)
}

/// Generate an example workers.toml configuration.
#[allow(dead_code)] // Will be used by config init command
pub fn example_workers_config() -> String {
    r#"# RCH Workers Configuration
# Place this file at ~/.config/rch/workers.toml

# Example worker definitions
[[workers]]
id = "server1"
host = "192.168.1.100"
user = "ubuntu"
identity_file = "~/.ssh/id_rsa"
total_slots = 16
priority = 100
tags = ["rust", "fast"]
enabled = true

[[workers]]
id = "server2"
host = "192.168.1.101"
user = "ubuntu"
identity_file = "~/.ssh/id_rsa"
total_slots = 8
priority = 80
tags = ["rust"]
enabled = true

# Disabled worker example
[[workers]]
id = "maintenance"
host = "192.168.1.102"
user = "admin"
identity_file = "~/.ssh/maintenance_key"
total_slots = 4
priority = 50
tags = ["backup"]
enabled = false
"#
    .to_string()
}

/// Generate an example daemon.toml configuration.
#[allow(dead_code)] // Will be used by config init command
pub fn example_daemon_config() -> String {
    r#"# RCH Daemon Configuration
# Place this file at ~/.config/rch/daemon.toml

# Unix socket path for hook communication
socket_path = "/tmp/rch.sock"

# Health check interval in seconds
health_check_interval_secs = 30

# Worker timeout before marking as unreachable (seconds)
worker_timeout_secs = 10

# Maximum concurrent jobs per worker slot
max_jobs_per_slot = 1

# Enable SSH connection pooling
connection_pooling = true

# Log level: trace, debug, info, warn, error
log_level = "info"
"#
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn init_test_logging() {
        let _ = tracing_subscriber::fmt()
            .with_test_writer()
            .with_max_level(tracing::Level::DEBUG)
            .try_init();
    }

    #[test]
    fn test_default_daemon_config() {
        let config = DaemonConfig::default();
        assert_eq!(config.socket_path, PathBuf::from("/tmp/rch.sock"));
        assert_eq!(config.health_check_interval_secs, 30);
        assert!(config.connection_pooling);
    }

    #[test]
    fn test_parse_workers_config() {
        let toml = r#"
[[workers]]
id = "test"
host = "localhost"
user = "testuser"
identity_file = "~/.ssh/id_rsa"
total_slots = 4
priority = 100
tags = ["test"]
enabled = true
"#;
        let config: WorkersConfig = toml::from_str(toml).unwrap();
        assert_eq!(config.workers.len(), 1);
        assert_eq!(config.workers[0].id, "test");
        assert_eq!(config.workers[0].total_slots, 4);
    }

    #[test]
    fn test_worker_entry_to_config() {
        let entry = WorkerEntry {
            id: "worker1".to_string(),
            host: "192.168.1.100".to_string(),
            user: "ubuntu".to_string(),
            identity_file: "~/.ssh/id_rsa".to_string(),
            total_slots: 8,
            priority: 100,
            tags: vec!["rust".to_string()],
            enabled: true,
        };

        let config: WorkerConfig = entry.into();
        assert_eq!(config.id.as_str(), "worker1");
        assert_eq!(config.host, "192.168.1.100");
        assert_eq!(config.total_slots, 8);
    }

    #[test]
    fn test_example_configs_valid() {
        let workers_toml = example_workers_config();
        let _: WorkersConfig =
            toml::from_str(&workers_toml).expect("Example workers config should parse");

        let daemon_toml = example_daemon_config();
        let _: DaemonConfig =
            toml::from_str(&daemon_toml).expect("Example daemon config should parse");
    }

    // =========================================================================
    // test_daemon_config_loading - Config file parsing, defaults, validation
    // =========================================================================

    #[test]
    fn test_daemon_config_loading_from_file() {
        init_test_logging();

        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("daemon.toml");

        let config_content = r#"
socket_path = "/custom/path/rch.sock"
health_check_interval_secs = 60
worker_timeout_secs = 30
max_jobs_per_slot = 2
connection_pooling = false
log_level = "debug"
"#;
        std::fs::write(&config_path, config_content).unwrap();

        let config = load_daemon_config(Some(&config_path)).unwrap();

        assert_eq!(config.socket_path, PathBuf::from("/custom/path/rch.sock"));
        assert_eq!(config.health_check_interval_secs, 60);
        assert_eq!(config.worker_timeout_secs, 30);
        assert_eq!(config.max_jobs_per_slot, 2);
        assert!(!config.connection_pooling);
        assert_eq!(config.log_level, "debug");
    }

    #[test]
    fn test_daemon_config_loading_missing_file_uses_defaults() {
        init_test_logging();

        let temp_dir = TempDir::new().unwrap();
        let nonexistent_path = temp_dir.path().join("nonexistent.toml");

        let config = load_daemon_config(Some(&nonexistent_path)).unwrap();

        // Should use default values
        assert_eq!(config.socket_path, PathBuf::from("/tmp/rch.sock"));
        assert_eq!(config.health_check_interval_secs, 30);
        assert_eq!(config.worker_timeout_secs, 10);
        assert_eq!(config.max_jobs_per_slot, 1);
        assert!(config.connection_pooling);
        assert_eq!(config.log_level, "info");
    }

    #[test]
    fn test_daemon_config_loading_partial_file() {
        init_test_logging();

        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("daemon.toml");

        // Only specify some fields - others should use defaults
        let config_content = r#"
socket_path = "/custom/rch.sock"
log_level = "warn"
"#;
        std::fs::write(&config_path, config_content).unwrap();

        let config = load_daemon_config(Some(&config_path)).unwrap();

        // Specified values
        assert_eq!(config.socket_path, PathBuf::from("/custom/rch.sock"));
        assert_eq!(config.log_level, "warn");

        // Default values for unspecified fields
        assert_eq!(config.health_check_interval_secs, 30);
        assert_eq!(config.worker_timeout_secs, 10);
        assert_eq!(config.max_jobs_per_slot, 1);
        assert!(config.connection_pooling);
    }

    #[test]
    fn test_daemon_config_loading_invalid_toml() {
        init_test_logging();

        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("daemon.toml");

        let config_content = "this is not valid toml {{{";
        std::fs::write(&config_path, config_content).unwrap();

        let result = load_daemon_config(Some(&config_path));
        assert!(result.is_err());
    }

    // =========================================================================
    // test_daemon_worker_loading - Workers.toml parsing, validation
    // =========================================================================

    #[test]
    fn test_worker_loading_from_file() {
        init_test_logging();

        let temp_dir = TempDir::new().unwrap();
        let workers_path = temp_dir.path().join("workers.toml");

        let config_content = r#"
[[workers]]
id = "server1"
host = "192.168.1.100"
user = "ubuntu"
identity_file = "~/.ssh/id_rsa"
total_slots = 16
priority = 100
tags = ["rust", "fast"]
enabled = true

[[workers]]
id = "server2"
host = "192.168.1.101"
user = "admin"
identity_file = "~/.ssh/admin_key"
total_slots = 8
priority = 80
tags = ["backup"]
enabled = true
"#;
        std::fs::write(&workers_path, config_content).unwrap();

        let workers = load_workers(Some(&workers_path)).unwrap();

        assert_eq!(workers.len(), 2);
        assert_eq!(workers[0].id.as_str(), "server1");
        assert_eq!(workers[0].host, "192.168.1.100");
        assert_eq!(workers[0].total_slots, 16);
        assert_eq!(workers[1].id.as_str(), "server2");
        assert_eq!(workers[1].host, "192.168.1.101");
    }

    #[test]
    fn test_worker_loading_disabled_workers_filtered() {
        init_test_logging();

        let temp_dir = TempDir::new().unwrap();
        let workers_path = temp_dir.path().join("workers.toml");

        let config_content = r#"
[[workers]]
id = "enabled-worker"
host = "192.168.1.100"
enabled = true

[[workers]]
id = "disabled-worker"
host = "192.168.1.101"
enabled = false
"#;
        std::fs::write(&workers_path, config_content).unwrap();

        let workers = load_workers(Some(&workers_path)).unwrap();

        assert_eq!(workers.len(), 1);
        assert_eq!(workers[0].id.as_str(), "enabled-worker");
    }

    #[test]
    fn test_worker_loading_missing_file_returns_empty() {
        init_test_logging();

        let temp_dir = TempDir::new().unwrap();
        let nonexistent_path = temp_dir.path().join("nonexistent.toml");

        let workers = load_workers(Some(&nonexistent_path)).unwrap();

        assert!(workers.is_empty());
    }

    #[test]
    fn test_worker_loading_default_values() {
        init_test_logging();

        let temp_dir = TempDir::new().unwrap();
        let workers_path = temp_dir.path().join("workers.toml");

        // Only specify required fields - others should use defaults
        let config_content = r#"
[[workers]]
id = "minimal"
host = "192.168.1.100"
"#;
        std::fs::write(&workers_path, config_content).unwrap();

        let config = load_workers_config(Some(&workers_path)).unwrap();

        assert_eq!(config.workers.len(), 1);
        let worker = &config.workers[0];

        assert_eq!(worker.id, "minimal");
        assert_eq!(worker.host, "192.168.1.100");
        // Default values
        assert_eq!(worker.user, "ubuntu"); // default_user()
        assert_eq!(worker.identity_file, "~/.ssh/id_rsa"); // default_identity_file()
        assert_eq!(worker.total_slots, 8); // default_slots()
        assert_eq!(worker.priority, 100); // default_priority()
        assert!(worker.tags.is_empty());
        assert!(worker.enabled); // default_true()
    }

    #[test]
    fn test_worker_loading_missing_required_id_fails() {
        init_test_logging();

        let temp_dir = TempDir::new().unwrap();
        let workers_path = temp_dir.path().join("workers.toml");

        // Missing required 'id' field
        let config_content = r#"
[[workers]]
host = "192.168.1.100"
user = "ubuntu"
"#;
        std::fs::write(&workers_path, config_content).unwrap();

        let result = load_workers_config(Some(&workers_path));
        assert!(result.is_err());
    }

    #[test]
    fn test_worker_loading_missing_required_host_fails() {
        init_test_logging();

        let temp_dir = TempDir::new().unwrap();
        let workers_path = temp_dir.path().join("workers.toml");

        // Missing required 'host' field
        let config_content = r#"
[[workers]]
id = "worker1"
user = "ubuntu"
"#;
        std::fs::write(&workers_path, config_content).unwrap();

        let result = load_workers_config(Some(&workers_path));
        assert!(result.is_err());
    }

    #[test]
    fn test_worker_loading_invalid_toml_fails() {
        init_test_logging();

        let temp_dir = TempDir::new().unwrap();
        let workers_path = temp_dir.path().join("workers.toml");

        let config_content = "this is not valid toml {{{";
        std::fs::write(&workers_path, config_content).unwrap();

        let result = load_workers_config(Some(&workers_path));
        assert!(result.is_err());
    }

    #[test]
    fn test_worker_loading_empty_workers_array() {
        init_test_logging();

        let temp_dir = TempDir::new().unwrap();
        let workers_path = temp_dir.path().join("workers.toml");

        let config_content = "# Empty workers config\n";
        std::fs::write(&workers_path, config_content).unwrap();

        let workers = load_workers(Some(&workers_path)).unwrap();
        assert!(workers.is_empty());
    }

    #[test]
    fn test_worker_loading_multiple_tags() {
        init_test_logging();

        let temp_dir = TempDir::new().unwrap();
        let workers_path = temp_dir.path().join("workers.toml");

        let config_content = r#"
[[workers]]
id = "multi-tag"
host = "192.168.1.100"
tags = ["rust", "go", "python", "fast", "production"]
"#;
        std::fs::write(&workers_path, config_content).unwrap();

        let config = load_workers_config(Some(&workers_path)).unwrap();

        assert_eq!(config.workers[0].tags.len(), 5);
        assert!(config.workers[0].tags.contains(&"rust".to_string()));
        assert!(config.workers[0].tags.contains(&"production".to_string()));
    }

    #[test]
    fn test_worker_entry_conversion_preserves_all_fields() {
        init_test_logging();

        let entry = WorkerEntry {
            id: "test-worker".to_string(),
            host: "10.0.0.1".to_string(),
            user: "admin".to_string(),
            identity_file: "/path/to/key".to_string(),
            total_slots: 32,
            priority: 200,
            tags: vec!["tag1".to_string(), "tag2".to_string()],
            enabled: true,
        };

        let config: WorkerConfig = entry.into();

        assert_eq!(config.id.as_str(), "test-worker");
        assert_eq!(config.host, "10.0.0.1");
        assert_eq!(config.user, "admin");
        assert_eq!(config.identity_file, "/path/to/key");
        assert_eq!(config.total_slots, 32);
        assert_eq!(config.priority, 200);
        assert_eq!(config.tags.len(), 2);
        assert_eq!(config.tags[0], "tag1");
        assert_eq!(config.tags[1], "tag2");
    }

    #[test]
    fn test_worker_loading_zero_slots() {
        init_test_logging();

        let temp_dir = TempDir::new().unwrap();
        let workers_path = temp_dir.path().join("workers.toml");

        let config_content = r#"
[[workers]]
id = "zero-slots"
host = "192.168.1.100"
total_slots = 0
"#;
        std::fs::write(&workers_path, config_content).unwrap();

        let config = load_workers_config(Some(&workers_path)).unwrap();
        assert_eq!(config.workers[0].total_slots, 0);
    }

    #[test]
    fn test_worker_loading_high_priority() {
        init_test_logging();

        let temp_dir = TempDir::new().unwrap();
        let workers_path = temp_dir.path().join("workers.toml");

        let config_content = r#"
[[workers]]
id = "high-priority"
host = "192.168.1.100"
priority = 999999
"#;
        std::fs::write(&workers_path, config_content).unwrap();

        let config = load_workers_config(Some(&workers_path)).unwrap();
        assert_eq!(config.workers[0].priority, 999999);
    }
}
