//! Configuration loading for RCH.

use anyhow::{Context, Result};
use directories::ProjectDirs;
use rch_common::RchConfig;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tracing::debug;

#[cfg(test)]
use std::sync::{Mutex, OnceLock};

#[cfg(test)]
fn test_config_override() -> &'static Mutex<Option<RchConfig>> {
    static OVERRIDE: OnceLock<Mutex<Option<RchConfig>>> = OnceLock::new();
    OVERRIDE.get_or_init(|| Mutex::new(None))
}

#[cfg(test)]
pub fn set_test_config_override(config: Option<RchConfig>) {
    *test_config_override().lock().unwrap() = config;
}

/// Get the user config directory.
pub fn config_dir() -> Option<PathBuf> {
    ProjectDirs::from("com", "rch", "rch").map(|dirs| dirs.config_dir().to_path_buf())
}

/// Load configuration from all sources.
pub fn load_config() -> Result<RchConfig> {
    #[cfg(test)]
    if let Some(config) = test_config_override().lock().unwrap().clone() {
        return Ok(config);
    }

    // Start with defaults
    let mut config = RchConfig::default();

    // Try to load user config
    if let Some(config_dir) = config_dir() {
        let config_path = config_dir.join("config.toml");
        if config_path.exists() {
            debug!("Loading user config from {:?}", config_path);
            let content = std::fs::read_to_string(&config_path)?;
            let user_config: RchConfig = toml::from_str(&content)?;
            config = user_config;
        }
    }

    // Try to load project config
    let project_config_path = PathBuf::from(".rch/config.toml");
    if project_config_path.exists() {
        debug!("Loading project config from {:?}", project_config_path);
        let content = std::fs::read_to_string(&project_config_path)?;
        let project_config: RchConfig = toml::from_str(&content)?;
        // Merge project config (project overrides user)
        config = merge_config(config, project_config);
    }

    // Apply environment variable overrides
    config = apply_env_overrides(config);

    Ok(config)
}

/// Merge two configs, with the second overriding the first.
fn merge_config(_base: RchConfig, overlay: RchConfig) -> RchConfig {
    // For now, just return the overlay as it has all fields
    // TODO: Implement proper field-by-field merging
    RchConfig {
        general: overlay.general,
        compilation: overlay.compilation,
        transfer: overlay.transfer,
    }
}

/// Apply environment variable overrides.
fn apply_env_overrides(mut config: RchConfig) -> RchConfig {
    if let Ok(val) = std::env::var("RCH_ENABLED") {
        config.general.enabled = val.parse().unwrap_or(true);
    }

    if let Ok(val) = std::env::var("RCH_LOG_LEVEL") {
        config.general.log_level = val;
    }

    if let Ok(val) = std::env::var("RCH_SOCKET_PATH") {
        config.general.socket_path = val;
    }

    if let Ok(val) = std::env::var("RCH_CONFIDENCE_THRESHOLD") {
        if let Ok(threshold) = val.parse() {
            config.compilation.confidence_threshold = threshold;
        }
    }

    if let Ok(val) = std::env::var("RCH_COMPRESSION") {
        if let Ok(level) = val.parse() {
            config.transfer.compression_level = level;
        }
    }

    config
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

fn default_true() -> bool {
    true
}

/// Load workers configuration from file.
#[allow(dead_code)] // Scaffolded for future CLI usage
pub fn load_workers_config(path: Option<&Path>) -> Result<WorkersConfig> {
    let config_path = match path {
        Some(p) => p.to_path_buf(),
        None => {
            let dir = config_dir().context("Could not determine config directory")?;
            dir.join("workers.toml")
        }
    };

    if !config_path.exists() {
        debug!("Workers config not found at {:?}", config_path);
        return Ok(WorkersConfig::default());
    }

    debug!("Loading workers config from {:?}", config_path);
    let contents = std::fs::read_to_string(&config_path)
        .with_context(|| format!("Failed to read workers config from {:?}", config_path))?;

    let config: WorkersConfig = toml::from_str(&contents)
        .with_context(|| format!("Failed to parse workers config from {:?}", config_path))?;

    debug!("Loaded {} worker definitions", config.workers.len());
    Ok(config)
}

/// Generate an example project config.
#[allow(dead_code)] // Used by future CLI scaffolding
pub fn example_project_config() -> String {
    r#"# RCH Project Configuration
# Place this file at .rch/config.toml in your project root

[general]
enabled = true
# Uncomment to use a custom socket path
# socket_path = "/tmp/rch.sock"

[compilation]
# Minimum confidence score to intercept (0.0-1.0)
confidence_threshold = 0.85
# Skip interception if estimated local time < this (ms)
min_local_time_ms = 2000

[transfer]
# zstd compression level (1-19)
compression_level = 3
# Additional patterns to exclude from transfer
exclude_patterns = [
    "target/",
    ".git/objects/",
    "node_modules/",
    "*.rlib",
    "*.rmeta",
]
"#
    .to_string()
}

/// Generate an example workers config.
#[allow(dead_code)] // Used by future CLI scaffolding
pub fn example_workers_config() -> String {
    r#"# RCH Workers Configuration
# Place this file at ~/.config/rch/workers.toml

[[workers]]
id = "worker1"
host = "192.168.1.100"
user = "ubuntu"
identity_file = "~/.ssh/id_rsa"
total_slots = 16
priority = 100
tags = ["rust", "fast"]
enabled = true

[[workers]]
id = "worker2"
host = "192.168.1.101"
user = "ubuntu"
identity_file = "~/.ssh/id_rsa"
total_slots = 8
priority = 80
tags = ["rust"]
enabled = true
"#
    .to_string()
}

/// Validate a config file.
#[allow(dead_code)] // Used by future CLI scaffolding
pub fn validate_config(path: &Path) -> Result<()> {
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read config from {:?}", path))?;

    // Try parsing as RchConfig first
    if toml::from_str::<RchConfig>(&contents).is_ok() {
        return Ok(());
    }

    // Try parsing as WorkersConfig
    if toml::from_str::<WorkersConfig>(&contents).is_ok() {
        return Ok(());
    }

    anyhow::bail!("Config file is not valid RCH or workers configuration")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = RchConfig::default();
        assert!(config.general.enabled);
        assert_eq!(config.general.log_level, "info");
        assert_eq!(config.compilation.confidence_threshold, 0.85);
    }

    #[test]
    fn test_example_project_config_valid() {
        let toml_str = example_project_config();
        let _: RchConfig = toml::from_str(&toml_str).expect("Example project config should parse");
    }

    #[test]
    fn test_example_workers_config_valid() {
        let toml_str = example_workers_config();
        let _: WorkersConfig =
            toml::from_str(&toml_str).expect("Example workers config should parse");
    }
}
