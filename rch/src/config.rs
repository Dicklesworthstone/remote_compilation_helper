//! Configuration loading for RCH.

use anyhow::Result;
use directories::ProjectDirs;
use rch_common::RchConfig;
use std::path::PathBuf;
use tracing::debug;

/// Get the user config directory.
pub fn config_dir() -> Option<PathBuf> {
    ProjectDirs::from("com", "rch", "rch").map(|dirs| dirs.config_dir().to_path_buf())
}

/// Load configuration from all sources.
pub fn load_config() -> Result<RchConfig> {
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
fn merge_config(base: RchConfig, overlay: RchConfig) -> RchConfig {
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
}
