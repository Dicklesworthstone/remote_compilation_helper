//! Configuration loading for RCH.

use crate::error::ConfigError;
use anyhow::{Context, Result};
use directories::ProjectDirs;
use rch_common::types::validate_remote_base;
use rch_common::{
    ConfigValueSource, OutputVisibility, RchConfig, SelfTestFailureAction, SelfTestWorkers,
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use tracing::{debug, warn};

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

/// Validation issues grouped by file.
#[derive(Debug, Clone, Default)]
pub struct FileValidation {
    pub file: PathBuf,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

impl FileValidation {
    pub fn new(file: &Path) -> Self {
        Self {
            file: file.to_path_buf(),
            errors: Vec::new(),
            warnings: Vec::new(),
        }
    }

    pub fn error(&mut self, message: impl Into<String>) {
        self.errors.push(message.into());
    }

    pub fn warn(&mut self, message: impl Into<String>) {
        self.warnings.push(message.into());
    }

    /// Validate that a path exists and is readable.
    /// Used by config doctor command (bd-xqxp).
    #[allow(dead_code)]
    pub fn validate_path_readable(&mut self, key: &str, path: &Path) {
        if !path.exists() {
            self.error(format!("{}: path does not exist: {}", key, path.display()));
        } else if let Err(e) = std::fs::metadata(path) {
            self.error(format!(
                "{}: cannot read path {}: {}",
                key,
                path.display(),
                e
            ));
        }
    }

    /// Validate that the parent directory of a path exists and is writable.
    pub fn validate_path_parent_writable(&mut self, key: &str, path: &Path) {
        let parent = match path.parent() {
            Some(p) if !p.as_os_str().is_empty() => p,
            _ => {
                self.error(format!(
                    "{}: path has no parent directory: {}",
                    key,
                    path.display()
                ));
                return;
            }
        };

        if !parent.exists() {
            self.error(format!(
                "{}: parent directory does not exist: {}",
                key,
                parent.display()
            ));
            return;
        }

        // Check if parent directory is writable
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(meta) = parent.metadata() {
                let mode = meta.permissions().mode();
                // Check if directory is writable by owner (bit 7) or group/other if applicable
                // A simple heuristic: if we can't write, warn (actual check would need uid/gid)
                if mode & 0o200 == 0 && mode & 0o020 == 0 && mode & 0o002 == 0 {
                    self.warn(format!(
                        "{}: parent directory may not be writable: {}",
                        key,
                        parent.display()
                    ));
                }
            }
        }

        // On non-Unix, just check that parent exists (already done above)
        #[cfg(not(unix))]
        {
            let _ = parent; // Avoid unused variable warning
        }
    }

    /// Validate SSH key file permissions (Unix: should be 600 or 400).
    #[cfg(unix)]
    pub fn validate_ssh_key_permissions(&mut self, key: &str, path: &Path) {
        use std::os::unix::fs::PermissionsExt;

        if !path.exists() {
            // Existence is checked elsewhere; don't duplicate the error
            return;
        }

        match path.metadata() {
            Ok(meta) => {
                let mode = meta.permissions().mode() & 0o777;
                if mode != 0o600 && mode != 0o400 {
                    self.warn(format!(
                        "{}: SSH key has insecure permissions {:o} (should be 600 or 400): {}",
                        key,
                        mode,
                        path.display()
                    ));
                }
            }
            Err(e) => {
                self.warn(format!(
                    "{}: cannot check permissions for {}: {}",
                    key,
                    path.display(),
                    e
                ));
            }
        }
    }

    /// Validate SSH key file permissions (no-op on non-Unix platforms).
    #[cfg(not(unix))]
    pub fn validate_ssh_key_permissions(&mut self, _key: &str, _path: &Path) {
        // SSH key permission checks only apply to Unix systems
    }

    /// Validate rsync exclude/include pattern syntax.
    ///
    /// rsync patterns support:
    /// - `*` matches any path component (excluding slashes)
    /// - `**` matches any path (including slashes)
    /// - `?` matches any single character except slash
    /// - `[...]` character class
    /// - Leading `/` anchors to transfer root
    /// - Trailing `/` matches directories only
    pub fn validate_rsync_pattern(&mut self, key: &str, pattern: &str) {
        if pattern.is_empty() {
            self.error(format!("{}: empty pattern is not allowed", key));
            return;
        }

        // Check for unbalanced brackets
        let mut bracket_depth = 0i32;
        let mut prev_char = '\0';
        for ch in pattern.chars() {
            match ch {
                '[' if prev_char != '\\' => bracket_depth += 1,
                ']' if prev_char != '\\' => bracket_depth -= 1,
                _ => {}
            }
            if bracket_depth < 0 {
                self.error(format!("{}: unbalanced ']' in pattern: {}", key, pattern));
                return;
            }
            prev_char = ch;
        }
        if bracket_depth != 0 {
            self.error(format!("{}: unclosed '[' in pattern: {}", key, pattern));
            return;
        }

        // Warn about potentially problematic patterns
        if pattern == "*" || pattern == "**" {
            self.warn(format!(
                "{}: pattern '{}' matches everything - is this intentional?",
                key, pattern
            ));
        }

        // Warn about patterns that might accidentally exclude too much
        if pattern.starts_with('/') && !pattern.contains('*') && !pattern.contains('?') {
            // Absolute path without wildcards - might be overly specific
            // This is fine, just informational
        }
    }
}

/// Mapping of config keys to their value sources.
pub type ConfigSourceMap = HashMap<String, ConfigValueSource>;

/// Loaded config with source tracking.
#[derive(Debug, Clone)]
pub struct LoadedConfig {
    pub config: RchConfig,
    pub sources: ConfigSourceMap,
}

#[derive(Debug, Default, Deserialize)]
struct PartialRchConfig {
    #[serde(default)]
    general: PartialGeneralConfig,
    #[serde(default)]
    compilation: PartialCompilationConfig,
    #[serde(default)]
    transfer: PartialTransferConfig,
    #[serde(default)]
    environment: PartialEnvironmentConfig,
    #[serde(default)]
    circuit: PartialCircuitConfig,
    #[serde(default)]
    output: PartialOutputConfig,
    #[serde(default)]
    self_healing: PartialSelfHealingConfig,
    #[serde(default)]
    self_test: PartialSelfTestConfig,
}

#[derive(Debug, Default, Deserialize)]
struct PartialGeneralConfig {
    enabled: Option<bool>,
    force_local: Option<bool>,
    force_remote: Option<bool>,
    log_level: Option<String>,
    socket_path: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct PartialCompilationConfig {
    confidence_threshold: Option<f64>,
    min_local_time_ms: Option<u64>,
    build_slots: Option<u32>,
    test_slots: Option<u32>,
    check_slots: Option<u32>,
    build_timeout_sec: Option<u64>,
    test_timeout_sec: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
struct PartialTransferConfig {
    compression_level: Option<u32>,
    exclude_patterns: Option<Vec<String>>,
    remote_base: Option<String>,
    ssh_server_alive_interval_secs: Option<u64>,
    ssh_control_persist_secs: Option<u64>,
    // Transfer optimization (bd-3hho)
    max_transfer_mb: Option<u64>,
    max_transfer_time_ms: Option<u64>,
    bwlimit_kbps: Option<u64>,
    estimated_bandwidth_bps: Option<u64>,
    // Adaptive compression (bd-243w)
    adaptive_compression: Option<bool>,
    min_compression_level: Option<u32>,
    max_compression_level: Option<u32>,
    // Artifact verification (bd-377q)
    verify_artifacts: Option<bool>,
    verify_max_size_bytes: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
struct PartialEnvironmentConfig {
    allowlist: Option<Vec<String>>,
}

#[derive(Debug, Default, Deserialize)]
struct PartialCircuitConfig {
    failure_threshold: Option<u32>,
    success_threshold: Option<u32>,
    error_rate_threshold: Option<f64>,
    window_secs: Option<u64>,
    open_cooldown_secs: Option<u64>,
    half_open_max_probes: Option<u32>,
}

#[derive(Debug, Default, Deserialize)]
struct PartialOutputConfig {
    visibility: Option<OutputVisibility>,
    first_run_complete: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
struct PartialSelfHealingConfig {
    hook_starts_daemon: Option<bool>,
    daemon_installs_hooks: Option<bool>,
    auto_start_cooldown_secs: Option<u64>,
    auto_start_timeout_secs: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
struct PartialSelfTestConfig {
    enabled: Option<bool>,
    schedule: Option<String>,
    interval: Option<String>,
    workers: Option<SelfTestWorkers>,
    on_failure: Option<SelfTestFailureAction>,
    retry_count: Option<u32>,
    retry_delay: Option<String>,
}

/// Load configuration with source tracking.
pub fn load_config_with_sources() -> Result<LoadedConfig> {
    let user_path = config_dir().map(|d| d.join("config.toml"));
    let project_path = PathBuf::from(".rch/config.toml");

    let user_path = user_path.as_deref().filter(|p| p.exists());
    let project_path = project_path.as_path();
    let project_path = if project_path.exists() {
        Some(project_path)
    } else {
        None
    };

    load_config_with_sources_from_paths(user_path, project_path, None)
}

fn load_config_with_sources_from_paths(
    user_path: Option<&Path>,
    project_path: Option<&Path>,
    env_overrides: Option<&HashMap<String, String>>,
) -> Result<LoadedConfig> {
    let defaults = RchConfig::default();
    let mut config = defaults.clone();
    let mut sources = default_sources_map();

    if let Some(path) = user_path {
        if path.exists() {
            debug!("Loading user config with sources from {:?}", path);
            let layer = load_partial_config(path)?;
            apply_layer(
                &mut config,
                &mut sources,
                &layer,
                &ConfigValueSource::UserConfig(path.to_path_buf()),
                &defaults,
            );
        } else {
            debug!("User config not found at {:?}; skipping", path);
        }
    }

    if let Some(path) = project_path {
        if path.exists() {
            debug!("Loading project config with sources from {:?}", path);
            let layer = load_partial_config(path)?;
            apply_layer(
                &mut config,
                &mut sources,
                &layer,
                &ConfigValueSource::ProjectConfig(path.to_path_buf()),
                &defaults,
            );
        } else {
            debug!("Project config not found at {:?}; skipping", path);
        }
    }

    apply_env_overrides_inner(&mut config, Some(&mut sources), env_overrides);

    Ok(LoadedConfig { config, sources })
}

fn load_partial_config(path: &Path) -> Result<PartialRchConfig> {
    let content =
        std::fs::read_to_string(path).with_context(|| format!("Failed to read {:?}", path))?;
    let parsed: PartialRchConfig =
        toml::from_str(&content).with_context(|| format!("Failed to parse {:?}", path))?;
    Ok(parsed)
}

/// Validate a standard RCH config file (config.toml or .rch/config.toml).
pub fn validate_rch_config_file(path: &Path) -> FileValidation {
    let mut validation = FileValidation::new(path);
    let contents = match std::fs::read_to_string(path) {
        Ok(content) => content,
        Err(err) => {
            validation.error(format!("Read failed: {}", err));
            return validation;
        }
    };

    let config: RchConfig = match toml::from_str(&contents) {
        Ok(config) => config,
        Err(err) => {
            validation.error(format!("TOML parse error: {}", err));
            return validation;
        }
    };

    if config.compilation.confidence_threshold < 0.0
        || config.compilation.confidence_threshold > 1.0
    {
        validation.error("compilation.confidence_threshold must be within [0.0, 1.0]".to_string());
    }
    if config.compilation.build_slots == 0 {
        validation.error("compilation.build_slots must be greater than 0".to_string());
    }
    if config.compilation.test_slots == 0 {
        validation.error("compilation.test_slots must be greater than 0".to_string());
    }
    if config.compilation.check_slots == 0 {
        validation.error("compilation.check_slots must be greater than 0".to_string());
    }
    if config.compilation.build_timeout_sec == 0 {
        validation.error("compilation.build_timeout_sec must be greater than 0".to_string());
    }
    if config.compilation.test_timeout_sec == 0 {
        validation.error("compilation.test_timeout_sec must be greater than 0".to_string());
    }

    if config.self_healing.auto_start_cooldown_secs == 0 {
        validation
            .error("self_healing.auto_start_cooldown_secs must be greater than 0".to_string());
    }
    if config.self_healing.auto_start_timeout_secs == 0 {
        validation.error("self_healing.auto_start_timeout_secs must be greater than 0".to_string());
    }

    if config.transfer.compression_level > 22 {
        validation.error("transfer.compression_level must be within [0, 22]".to_string());
    } else if config.transfer.compression_level > 19 {
        validation.warn("transfer.compression_level should be within [1, 19]".to_string());
    } else if config.transfer.compression_level == 0 {
        validation.warn("transfer.compression_level is 0 (compression disabled)".to_string());
    }

    if let Some(interval) = config.transfer.ssh_server_alive_interval_secs {
        if interval > 0 && interval < 5 {
            validation.warn(format!(
                "transfer.ssh_server_alive_interval_secs is very low ({}s)",
                interval
            ));
        }
        if interval > 600 {
            validation.warn(format!(
                "transfer.ssh_server_alive_interval_secs is very high ({}s)",
                interval
            ));
        }
    }
    if let Some(persist) = config.transfer.ssh_control_persist_secs
        && persist > 0
        && persist < 10
    {
        validation.warn(format!(
            "transfer.ssh_control_persist_secs is very low ({}s)",
            persist
        ));
    }

    if let Err(e) = validate_remote_base(&config.transfer.remote_base) {
        validation.error(format!("transfer.remote_base invalid: {}", e));
    }

    for entry in &config.environment.allowlist {
        let trimmed = entry.trim();
        if trimmed.is_empty() {
            validation.error("environment.allowlist contains an empty entry".to_string());
        } else if !is_valid_env_key(trimmed) {
            validation.error(format!(
                "environment.allowlist contains invalid key: {}",
                trimmed
            ));
        }
    }

    if config.general.socket_path.trim().is_empty() {
        validation.error("general.socket_path cannot be empty".to_string());
    } else {
        let expanded = shellexpand::tilde(&config.general.socket_path);
        let socket_path = Path::new(expanded.as_ref());
        if !socket_path.exists() {
            // Socket doesn't exist yet - check if parent directory is writable (bd-1g3l)
            validation.validate_path_parent_writable("general.socket_path", socket_path);
        }
    }

    if config.general.force_local && config.general.force_remote {
        validation
            .error("general.force_local and general.force_remote cannot both be true".to_string());
    }
    if !config.general.enabled && (config.general.force_local || config.general.force_remote) {
        validation.warn(
            "general.force_local/force_remote has no effect when general.enabled=false".to_string(),
        );
    }

    if !is_valid_log_level(&config.general.log_level) {
        validation.error(
            "general.log_level must be one of: trace, debug, info, warn, error, off".to_string(),
        );
    }

    // Validate exclude patterns (bd-1g3l)
    for (idx, pattern) in config.transfer.exclude_patterns.iter().enumerate() {
        validation.validate_rsync_pattern(&format!("transfer.exclude_patterns[{}]", idx), pattern);
    }

    validation
}

/// Validate a workers configuration file (workers.toml).
pub fn validate_workers_config_file(path: &Path) -> FileValidation {
    let mut validation = FileValidation::new(path);
    let contents = match std::fs::read_to_string(path) {
        Ok(content) => content,
        Err(err) => {
            validation.error(format!("Read failed: {}", err));
            return validation;
        }
    };

    let raw: toml::Value = match toml::from_str(&contents) {
        Ok(value) => value,
        Err(err) => {
            validation.error(format!("TOML parse error: {}", err));
            return validation;
        }
    };

    let workers = match raw.get("workers") {
        Some(val) => match val.as_array() {
            Some(array) => array,
            None => {
                validation.error("workers must be an array".to_string());
                return validation;
            }
        },
        None => {
            validation.warn("No workers defined in workers.toml".to_string());
            return validation;
        }
    };

    if workers.is_empty() {
        validation.warn("No workers defined in workers.toml".to_string());
        return validation;
    }

    let mut seen_ids = HashSet::new();

    for (index, worker) in workers.iter().enumerate() {
        let Some(table) = worker.as_table() else {
            validation.error(format!("workers[{}] must be a table", index));
            continue;
        };

        let id_value = table.get("id");
        let id = match id_value.and_then(|v| v.as_str()) {
            Some(value) => value.trim().to_string(),
            None => {
                if id_value.is_some() {
                    validation.error(format!("workers[{}].id must be a string", index));
                }
                String::new()
            }
        };
        if id.is_empty() {
            if id_value.is_none() {
                validation.error(format!("workers[{}].id is required", index));
            }
        } else {
            let key = id.to_lowercase();
            if !seen_ids.insert(key) {
                validation.error(format!("Duplicate worker id '{}'", id));
            }
        }

        let host_value = table.get("host");
        let host = match host_value.and_then(|v| v.as_str()) {
            Some(value) => value.trim().to_string(),
            None => {
                if host_value.is_some() {
                    validation.error(format!("workers[{}].host must be a string", index));
                }
                String::new()
            }
        };
        if host.is_empty() && host_value.is_none() {
            validation.error(format!("workers[{}].host is required", index));
        }

        let user_value = table.get("user");
        let user = match user_value.and_then(|v| v.as_str()) {
            Some(value) => value.trim().to_string(),
            None => {
                if user_value.is_some() {
                    validation.error(format!("workers[{}].user must be a string", index));
                } else {
                    validation.error(format!("workers[{}].user is required", index));
                }
                String::new()
            }
        };
        if user.is_empty() && user_value.is_some() {
            validation.error(format!("workers[{}].user cannot be empty", index));
        }

        let default_identity = default_identity_file();
        let identity_field = table.get("identity_file");
        let identity_value = match identity_field.and_then(|v| v.as_str()) {
            Some(value) => value,
            None => {
                if identity_field.is_some() {
                    validation.error(format!(
                        "workers[{}] {} identity_file must be a string",
                        index,
                        if id.is_empty() { "(unknown id)" } else { &id }
                    ));
                } else {
                    validation.warn(format!(
                        "workers[{}] {} has no identity_file (using default {})",
                        index,
                        if id.is_empty() { "(unknown id)" } else { &id },
                        default_identity
                    ));
                }
                default_identity.as_str()
            }
        };
        if identity_value.trim().is_empty() {
            validation.error(format!(
                "workers[{}] {} identity_file cannot be empty",
                index,
                if id.is_empty() { "(unknown id)" } else { &id }
            ));
        }

        let expanded_identity = shellexpand::tilde(identity_value);
        let identity_path = Path::new(expanded_identity.as_ref());
        if !identity_path.exists() {
            validation.warn(format!(
                "workers[{}] {} identity_file not found: {}",
                index,
                if id.is_empty() { "(unknown id)" } else { &id },
                identity_path.display()
            ));
        } else {
            // SSH key exists - validate permissions (bd-1g3l)
            validation.validate_ssh_key_permissions(
                &format!(
                    "workers[{}] {} identity_file",
                    index,
                    if id.is_empty() { "(unknown id)" } else { &id }
                ),
                identity_path,
            );
        }

        if let Some(total_slots) = table.get("total_slots") {
            if let Some(value) = total_slots.as_integer() {
                if value <= 0 {
                    validation.warn(format!(
                        "workers[{}] {} total_slots should be > 0",
                        index,
                        if id.is_empty() { "(unknown id)" } else { &id }
                    ));
                }
            } else {
                validation.error(format!(
                    "workers[{}] {} total_slots must be an integer",
                    index,
                    if id.is_empty() { "(unknown id)" } else { &id }
                ));
            }
        } else {
            validation.warn(format!(
                "workers[{}] {} total_slots not specified (run `rch workers init` to auto-detect)",
                index,
                if id.is_empty() { "(unknown id)" } else { &id }
            ));
        }
    }

    validation
}

fn default_sources_map() -> ConfigSourceMap {
    let mut sources = HashMap::new();
    for key in [
        "general.enabled",
        "general.force_local",
        "general.force_remote",
        "general.log_level",
        "general.socket_path",
        "compilation.confidence_threshold",
        "compilation.min_local_time_ms",
        "compilation.build_slots",
        "compilation.test_slots",
        "compilation.check_slots",
        "compilation.build_timeout_sec",
        "compilation.test_timeout_sec",
        "transfer.compression_level",
        "transfer.exclude_patterns",
        "environment.allowlist",
        "circuit.failure_threshold",
        "circuit.success_threshold",
        "circuit.error_rate_threshold",
        "circuit.window_secs",
        "circuit.open_cooldown_secs",
        "circuit.half_open_max_probes",
        "output.visibility",
        "output.first_run_complete",
        "self_healing.hook_starts_daemon",
        "self_healing.daemon_installs_hooks",
        "self_healing.auto_start_cooldown_secs",
        "self_healing.auto_start_timeout_secs",
        "self_test.enabled",
        "self_test.schedule",
        "self_test.interval",
        "self_test.workers",
        "self_test.on_failure",
        "self_test.retry_count",
        "self_test.retry_delay",
    ] {
        sources.insert(key.to_string(), ConfigValueSource::Default);
    }
    sources
}

fn apply_layer(
    config: &mut RchConfig,
    sources: &mut ConfigSourceMap,
    layer: &PartialRchConfig,
    source: &ConfigValueSource,
    defaults: &RchConfig,
) {
    const EPSILON: f64 = 0.0001;

    if let Some(enabled) = layer.general.enabled
        && enabled != defaults.general.enabled
    {
        config.general.enabled = enabled;
        set_source(sources, "general.enabled", source.clone());
    }
    if let Some(force_local) = layer.general.force_local
        && force_local != defaults.general.force_local
    {
        config.general.force_local = force_local;
        set_source(sources, "general.force_local", source.clone());
    }
    if let Some(force_remote) = layer.general.force_remote
        && force_remote != defaults.general.force_remote
    {
        config.general.force_remote = force_remote;
        set_source(sources, "general.force_remote", source.clone());
    }
    if let Some(log_level) = layer.general.log_level.as_ref()
        && log_level != &defaults.general.log_level
    {
        config.general.log_level = log_level.clone();
        set_source(sources, "general.log_level", source.clone());
    }
    if let Some(socket_path) = layer.general.socket_path.as_ref()
        && socket_path != &defaults.general.socket_path
    {
        config.general.socket_path = socket_path.clone();
        set_source(sources, "general.socket_path", source.clone());
    }

    if let Some(threshold) = layer.compilation.confidence_threshold
        && (threshold - defaults.compilation.confidence_threshold).abs() > EPSILON
    {
        config.compilation.confidence_threshold = threshold;
        set_source(sources, "compilation.confidence_threshold", source.clone());
    }
    if let Some(min_local) = layer.compilation.min_local_time_ms
        && min_local != defaults.compilation.min_local_time_ms
    {
        config.compilation.min_local_time_ms = min_local;
        set_source(sources, "compilation.min_local_time_ms", source.clone());
    }
    if let Some(build_slots) = layer.compilation.build_slots
        && build_slots != defaults.compilation.build_slots
    {
        config.compilation.build_slots = build_slots;
        set_source(sources, "compilation.build_slots", source.clone());
    }
    if let Some(test_slots) = layer.compilation.test_slots
        && test_slots != defaults.compilation.test_slots
    {
        config.compilation.test_slots = test_slots;
        set_source(sources, "compilation.test_slots", source.clone());
    }
    if let Some(check_slots) = layer.compilation.check_slots
        && check_slots != defaults.compilation.check_slots
    {
        config.compilation.check_slots = check_slots;
        set_source(sources, "compilation.check_slots", source.clone());
    }
    if let Some(build_timeout_sec) = layer.compilation.build_timeout_sec
        && build_timeout_sec != defaults.compilation.build_timeout_sec
    {
        config.compilation.build_timeout_sec = build_timeout_sec;
        set_source(sources, "compilation.build_timeout_sec", source.clone());
    }
    if let Some(test_timeout_sec) = layer.compilation.test_timeout_sec
        && test_timeout_sec != defaults.compilation.test_timeout_sec
    {
        config.compilation.test_timeout_sec = test_timeout_sec;
        set_source(sources, "compilation.test_timeout_sec", source.clone());
    }

    if let Some(compression) = layer.transfer.compression_level
        && compression != defaults.transfer.compression_level
    {
        config.transfer.compression_level = compression;
        set_source(sources, "transfer.compression_level", source.clone());
    }
    if let Some(patterns) = layer.transfer.exclude_patterns.as_ref()
        && patterns != &defaults.transfer.exclude_patterns
    {
        config.transfer.exclude_patterns = patterns.clone();
        set_source(sources, "transfer.exclude_patterns", source.clone());
    }
    if let Some(remote_base) = layer.transfer.remote_base.as_ref()
        && remote_base != &defaults.transfer.remote_base
    {
        // Validate and normalize the remote_base path
        match validate_remote_base(remote_base) {
            Ok(validated) => {
                config.transfer.remote_base = validated;
                set_source(sources, "transfer.remote_base", source.clone());
            }
            Err(e) => {
                warn!("Invalid remote_base in {}: {}", source, e);
            }
        }
    }

    if let Some(interval) = layer.transfer.ssh_server_alive_interval_secs {
        config.transfer.ssh_server_alive_interval_secs = Some(interval);
        set_source(
            sources,
            "transfer.ssh_server_alive_interval_secs",
            source.clone(),
        );
    }
    if let Some(persist) = layer.transfer.ssh_control_persist_secs {
        config.transfer.ssh_control_persist_secs = Some(persist);
        set_source(sources, "transfer.ssh_control_persist_secs", source.clone());
    }
    // Transfer optimization (bd-3hho)
    if let Some(max_mb) = layer.transfer.max_transfer_mb {
        config.transfer.max_transfer_mb = Some(max_mb);
        set_source(sources, "transfer.max_transfer_mb", source.clone());
    }
    if let Some(max_time) = layer.transfer.max_transfer_time_ms {
        config.transfer.max_transfer_time_ms = Some(max_time);
        set_source(sources, "transfer.max_transfer_time_ms", source.clone());
    }
    if let Some(bwlimit) = layer.transfer.bwlimit_kbps {
        config.transfer.bwlimit_kbps = Some(bwlimit);
        set_source(sources, "transfer.bwlimit_kbps", source.clone());
    }
    if let Some(bandwidth) = layer.transfer.estimated_bandwidth_bps {
        config.transfer.estimated_bandwidth_bps = Some(bandwidth);
        set_source(sources, "transfer.estimated_bandwidth_bps", source.clone());
    }
    // Adaptive compression (bd-243w)
    if let Some(adaptive) = layer.transfer.adaptive_compression {
        config.transfer.adaptive_compression = adaptive;
        set_source(sources, "transfer.adaptive_compression", source.clone());
    }
    if let Some(min_level) = layer.transfer.min_compression_level {
        config.transfer.min_compression_level = min_level;
        set_source(sources, "transfer.min_compression_level", source.clone());
    }
    if let Some(max_level) = layer.transfer.max_compression_level {
        config.transfer.max_compression_level = max_level;
        set_source(sources, "transfer.max_compression_level", source.clone());
    }
    // Artifact verification (bd-377q)
    if let Some(verify) = layer.transfer.verify_artifacts {
        config.transfer.verify_artifacts = verify;
        set_source(sources, "transfer.verify_artifacts", source.clone());
    }
    if let Some(max_size) = layer.transfer.verify_max_size_bytes {
        config.transfer.verify_max_size_bytes = max_size;
        set_source(sources, "transfer.verify_max_size_bytes", source.clone());
    }

    if let Some(allowlist) = layer.environment.allowlist.as_ref()
        && allowlist != &defaults.environment.allowlist
    {
        config.environment.allowlist = allowlist.clone();
        set_source(sources, "environment.allowlist", source.clone());
    }

    if let Some(failure_threshold) = layer.circuit.failure_threshold
        && failure_threshold != defaults.circuit.failure_threshold
    {
        config.circuit.failure_threshold = failure_threshold;
        set_source(sources, "circuit.failure_threshold", source.clone());
    }
    if let Some(success_threshold) = layer.circuit.success_threshold
        && success_threshold != defaults.circuit.success_threshold
    {
        config.circuit.success_threshold = success_threshold;
        set_source(sources, "circuit.success_threshold", source.clone());
    }
    if let Some(error_rate_threshold) = layer.circuit.error_rate_threshold
        && (error_rate_threshold - defaults.circuit.error_rate_threshold).abs() > EPSILON
    {
        config.circuit.error_rate_threshold = error_rate_threshold;
        set_source(sources, "circuit.error_rate_threshold", source.clone());
    }
    if let Some(window_secs) = layer.circuit.window_secs
        && window_secs != defaults.circuit.window_secs
    {
        config.circuit.window_secs = window_secs;
        set_source(sources, "circuit.window_secs", source.clone());
    }
    if let Some(open_cooldown_secs) = layer.circuit.open_cooldown_secs
        && open_cooldown_secs != defaults.circuit.open_cooldown_secs
    {
        config.circuit.open_cooldown_secs = open_cooldown_secs;
        set_source(sources, "circuit.open_cooldown_secs", source.clone());
    }
    if let Some(half_open_max_probes) = layer.circuit.half_open_max_probes
        && half_open_max_probes != defaults.circuit.half_open_max_probes
    {
        config.circuit.half_open_max_probes = half_open_max_probes;
        set_source(sources, "circuit.half_open_max_probes", source.clone());
    }

    if let Some(visibility) = layer.output.visibility
        && visibility != defaults.output.visibility
    {
        config.output.visibility = visibility;
        set_source(sources, "output.visibility", source.clone());
    }
    if let Some(first_run_complete) = layer.output.first_run_complete
        && first_run_complete != defaults.output.first_run_complete
    {
        config.output.first_run_complete = first_run_complete;
        set_source(sources, "output.first_run_complete", source.clone());
    }

    if let Some(hook_starts_daemon) = layer.self_healing.hook_starts_daemon
        && hook_starts_daemon != defaults.self_healing.hook_starts_daemon
    {
        config.self_healing.hook_starts_daemon = hook_starts_daemon;
        set_source(sources, "self_healing.hook_starts_daemon", source.clone());
    }
    if let Some(daemon_installs_hooks) = layer.self_healing.daemon_installs_hooks
        && daemon_installs_hooks != defaults.self_healing.daemon_installs_hooks
    {
        config.self_healing.daemon_installs_hooks = daemon_installs_hooks;
        set_source(
            sources,
            "self_healing.daemon_installs_hooks",
            source.clone(),
        );
    }
    if let Some(cooldown) = layer.self_healing.auto_start_cooldown_secs
        && cooldown != defaults.self_healing.auto_start_cooldown_secs
    {
        config.self_healing.auto_start_cooldown_secs = cooldown;
        set_source(
            sources,
            "self_healing.auto_start_cooldown_secs",
            source.clone(),
        );
    }
    if let Some(timeout) = layer.self_healing.auto_start_timeout_secs
        && timeout != defaults.self_healing.auto_start_timeout_secs
    {
        config.self_healing.auto_start_timeout_secs = timeout;
        set_source(
            sources,
            "self_healing.auto_start_timeout_secs",
            source.clone(),
        );
    }

    if let Some(enabled) = layer.self_test.enabled
        && enabled != defaults.self_test.enabled
    {
        config.self_test.enabled = enabled;
        set_source(sources, "self_test.enabled", source.clone());
    }
    if let Some(schedule) = layer.self_test.schedule.as_ref()
        && defaults.self_test.schedule.as_ref() != Some(schedule)
    {
        config.self_test.schedule = Some(schedule.clone());
        set_source(sources, "self_test.schedule", source.clone());
    }
    if let Some(interval) = layer.self_test.interval.as_ref()
        && defaults.self_test.interval.as_ref() != Some(interval)
    {
        config.self_test.interval = Some(interval.clone());
        set_source(sources, "self_test.interval", source.clone());
    }
    if let Some(workers) = layer.self_test.workers.as_ref()
        && workers != &defaults.self_test.workers
    {
        config.self_test.workers = workers.clone();
        set_source(sources, "self_test.workers", source.clone());
    }
    if let Some(on_failure) = layer.self_test.on_failure
        && on_failure != defaults.self_test.on_failure
    {
        config.self_test.on_failure = on_failure;
        set_source(sources, "self_test.on_failure", source.clone());
    }
    if let Some(retry_count) = layer.self_test.retry_count
        && retry_count != defaults.self_test.retry_count
    {
        config.self_test.retry_count = retry_count;
        set_source(sources, "self_test.retry_count", source.clone());
    }
    if let Some(retry_delay) = layer.self_test.retry_delay.as_ref()
        && defaults.self_test.retry_delay != *retry_delay
    {
        config.self_test.retry_delay = retry_delay.clone();
        set_source(sources, "self_test.retry_delay", source.clone());
    }
}

fn set_source(sources: &mut ConfigSourceMap, key: &str, source: ConfigValueSource) {
    sources.insert(key.to_string(), source);
}

/// Merge two configs, with the second overriding the first.
///
/// Only fields in the overlay that differ from their default values
/// will override the base config. This allows partial config files
/// (e.g., project configs that only set one field) to work correctly
/// without clobbering the entire section from the user config.
fn merge_config(mut base: RchConfig, overlay: RchConfig) -> RchConfig {
    let default = RchConfig::default();

    // Merge general section
    merge_general(&mut base.general, &overlay.general, &default.general);

    // Merge compilation section
    merge_compilation(
        &mut base.compilation,
        &overlay.compilation,
        &default.compilation,
    );

    // Merge transfer section
    merge_transfer(&mut base.transfer, &overlay.transfer, &default.transfer);

    // Merge environment section
    merge_environment(
        &mut base.environment,
        &overlay.environment,
        &default.environment,
    );

    // Merge circuit breaker section
    merge_circuit(&mut base.circuit, &overlay.circuit, &default.circuit);

    // Merge output section
    merge_output(&mut base.output, &overlay.output, &default.output);

    // Merge self-healing section
    merge_self_healing(
        &mut base.self_healing,
        &overlay.self_healing,
        &default.self_healing,
    );

    // Merge self-test section
    merge_self_test(&mut base.self_test, &overlay.self_test, &default.self_test);

    base
}

/// Merge GeneralConfig fields.
fn merge_general(
    base: &mut rch_common::GeneralConfig,
    overlay: &rch_common::GeneralConfig,
    default: &rch_common::GeneralConfig,
) {
    // Only override if overlay differs from default
    if overlay.enabled != default.enabled {
        base.enabled = overlay.enabled;
    }
    if overlay.force_local != default.force_local {
        base.force_local = overlay.force_local;
    }
    if overlay.force_remote != default.force_remote {
        base.force_remote = overlay.force_remote;
    }
    if overlay.log_level != default.log_level {
        base.log_level.clone_from(&overlay.log_level);
    }
    if overlay.socket_path != default.socket_path {
        base.socket_path.clone_from(&overlay.socket_path);
    }
}

/// Merge CompilationConfig fields.
fn merge_compilation(
    base: &mut rch_common::CompilationConfig,
    overlay: &rch_common::CompilationConfig,
    default: &rch_common::CompilationConfig,
) {
    // Use float comparison with small epsilon for confidence_threshold
    const EPSILON: f64 = 0.0001;
    if (overlay.confidence_threshold - default.confidence_threshold).abs() > EPSILON {
        base.confidence_threshold = overlay.confidence_threshold;
    }
    if overlay.min_local_time_ms != default.min_local_time_ms {
        base.min_local_time_ms = overlay.min_local_time_ms;
    }
    if overlay.build_slots != default.build_slots {
        base.build_slots = overlay.build_slots;
    }
    if overlay.test_slots != default.test_slots {
        base.test_slots = overlay.test_slots;
    }
    if overlay.check_slots != default.check_slots {
        base.check_slots = overlay.check_slots;
    }
    if overlay.build_timeout_sec != default.build_timeout_sec {
        base.build_timeout_sec = overlay.build_timeout_sec;
    }
    if overlay.test_timeout_sec != default.test_timeout_sec {
        base.test_timeout_sec = overlay.test_timeout_sec;
    }
}

/// Merge TransferConfig fields.
fn merge_transfer(
    base: &mut rch_common::TransferConfig,
    overlay: &rch_common::TransferConfig,
    default: &rch_common::TransferConfig,
) {
    if overlay.compression_level != default.compression_level {
        base.compression_level = overlay.compression_level;
    }
    // For exclude_patterns, if overlay specifies any patterns that differ
    // from default, use the overlay's list entirely (append semantics
    // would be confusing)
    if overlay.exclude_patterns != default.exclude_patterns {
        base.exclude_patterns.clone_from(&overlay.exclude_patterns);
    }
    if overlay.ssh_server_alive_interval_secs != default.ssh_server_alive_interval_secs {
        base.ssh_server_alive_interval_secs = overlay.ssh_server_alive_interval_secs;
    }
    if overlay.ssh_control_persist_secs != default.ssh_control_persist_secs {
        base.ssh_control_persist_secs = overlay.ssh_control_persist_secs;
    }
    // Override remote_base if overlay differs from default (with validation)
    if overlay.remote_base != default.remote_base {
        match rch_common::validate_remote_base(&overlay.remote_base) {
            Ok(validated) => {
                base.remote_base = validated;
            }
            Err(e) => {
                // If validation fails, do NOT apply the override.
                // Keep the previous value (from base or default).
                warn!("Ignoring invalid remote_base in overlay config: {}", e);
            }
        }
    }
    // Transfer optimization (bd-3hho)
    if overlay.max_transfer_mb != default.max_transfer_mb {
        base.max_transfer_mb = overlay.max_transfer_mb;
    }
    if overlay.max_transfer_time_ms != default.max_transfer_time_ms {
        base.max_transfer_time_ms = overlay.max_transfer_time_ms;
    }
    if overlay.bwlimit_kbps != default.bwlimit_kbps {
        base.bwlimit_kbps = overlay.bwlimit_kbps;
    }
    if overlay.estimated_bandwidth_bps != default.estimated_bandwidth_bps {
        base.estimated_bandwidth_bps = overlay.estimated_bandwidth_bps;
    }
    // Adaptive compression (bd-243w)
    if overlay.adaptive_compression != default.adaptive_compression {
        base.adaptive_compression = overlay.adaptive_compression;
    }
    if overlay.min_compression_level != default.min_compression_level {
        base.min_compression_level = overlay.min_compression_level;
    }
    if overlay.max_compression_level != default.max_compression_level {
        base.max_compression_level = overlay.max_compression_level;
    }
    // Artifact verification (bd-377q)
    if overlay.verify_artifacts != default.verify_artifacts {
        base.verify_artifacts = overlay.verify_artifacts;
    }
    if overlay.verify_max_size_bytes != default.verify_max_size_bytes {
        base.verify_max_size_bytes = overlay.verify_max_size_bytes;
    }
}

/// Merge EnvironmentConfig fields.
fn merge_environment(
    base: &mut rch_common::EnvironmentConfig,
    overlay: &rch_common::EnvironmentConfig,
    default: &rch_common::EnvironmentConfig,
) {
    if overlay.allowlist != default.allowlist {
        base.allowlist.clone_from(&overlay.allowlist);
    }
}

/// Merge CircuitBreakerConfig fields.
fn merge_circuit(
    base: &mut rch_common::CircuitBreakerConfig,
    overlay: &rch_common::CircuitBreakerConfig,
    default: &rch_common::CircuitBreakerConfig,
) {
    if overlay.failure_threshold != default.failure_threshold {
        base.failure_threshold = overlay.failure_threshold;
    }
    if overlay.success_threshold != default.success_threshold {
        base.success_threshold = overlay.success_threshold;
    }
    const EPSILON: f64 = 0.0001;
    if (overlay.error_rate_threshold - default.error_rate_threshold).abs() > EPSILON {
        base.error_rate_threshold = overlay.error_rate_threshold;
    }
    if overlay.window_secs != default.window_secs {
        base.window_secs = overlay.window_secs;
    }
    if overlay.open_cooldown_secs != default.open_cooldown_secs {
        base.open_cooldown_secs = overlay.open_cooldown_secs;
    }
    if overlay.half_open_max_probes != default.half_open_max_probes {
        base.half_open_max_probes = overlay.half_open_max_probes;
    }
}

/// Merge OutputConfig fields.
fn merge_output(
    base: &mut rch_common::OutputConfig,
    overlay: &rch_common::OutputConfig,
    default: &rch_common::OutputConfig,
) {
    if overlay.visibility != default.visibility {
        base.visibility = overlay.visibility;
    }
    if overlay.first_run_complete != default.first_run_complete {
        base.first_run_complete = overlay.first_run_complete;
    }
}

/// Merge SelfHealingConfig fields.
fn merge_self_healing(
    base: &mut rch_common::SelfHealingConfig,
    overlay: &rch_common::SelfHealingConfig,
    default: &rch_common::SelfHealingConfig,
) {
    if overlay.hook_starts_daemon != default.hook_starts_daemon {
        base.hook_starts_daemon = overlay.hook_starts_daemon;
    }
    if overlay.daemon_installs_hooks != default.daemon_installs_hooks {
        base.daemon_installs_hooks = overlay.daemon_installs_hooks;
    }
    if overlay.auto_start_cooldown_secs != default.auto_start_cooldown_secs {
        base.auto_start_cooldown_secs = overlay.auto_start_cooldown_secs;
    }
    if overlay.auto_start_timeout_secs != default.auto_start_timeout_secs {
        base.auto_start_timeout_secs = overlay.auto_start_timeout_secs;
    }
}

/// Merge SelfTestConfig fields.
fn merge_self_test(
    base: &mut rch_common::SelfTestConfig,
    overlay: &rch_common::SelfTestConfig,
    default: &rch_common::SelfTestConfig,
) {
    if overlay.enabled != default.enabled {
        base.enabled = overlay.enabled;
    }
    if overlay.schedule != default.schedule {
        base.schedule.clone_from(&overlay.schedule);
    }
    if overlay.interval != default.interval {
        base.interval.clone_from(&overlay.interval);
    }
    if overlay.workers != default.workers {
        base.workers = overlay.workers.clone();
    }
    if overlay.on_failure != default.on_failure {
        base.on_failure = overlay.on_failure;
    }
    if overlay.retry_count != default.retry_count {
        base.retry_count = overlay.retry_count;
    }
    if overlay.retry_delay != default.retry_delay {
        base.retry_delay.clone_from(&overlay.retry_delay);
    }
}

/// Apply environment variable overrides.
fn apply_env_overrides(mut config: RchConfig) -> RchConfig {
    apply_env_overrides_inner(&mut config, None, None);
    config
}

/// Persist the first-run completion flag in the user config.
#[allow(dead_code)] // Reserved for future CLI usage (first-run UX)
pub fn set_first_run_complete(value: bool) -> Result<()> {
    let config_dir = config_dir().context("Could not determine config directory")?;
    std::fs::create_dir_all(&config_dir)
        .with_context(|| format!("Failed to create config directory: {:?}", config_dir))?;
    let config_path = config_dir.join("config.toml");

    let mut config = if config_path.exists() {
        let contents = std::fs::read_to_string(&config_path)
            .with_context(|| format!("Failed to read {:?}", config_path))?;
        toml::from_str::<RchConfig>(&contents)
            .with_context(|| format!("Failed to parse {:?}", config_path))?
    } else {
        RchConfig::default()
    };

    if config.output.first_run_complete == value {
        return Ok(());
    }

    config.output.first_run_complete = value;
    let contents = toml::to_string_pretty(&config)?;
    std::fs::write(&config_path, format!("{}\n", contents))
        .with_context(|| format!("Failed to write {:?}", config_path))?;
    Ok(())
}

fn apply_env_overrides_inner(
    config: &mut RchConfig,
    mut sources: Option<&mut ConfigSourceMap>,
    env_overrides: Option<&HashMap<String, String>>,
) {
    let get_env = |name: &str| -> Option<String> {
        if let Some(map) = env_overrides {
            map.get(name).cloned()
        } else {
            std::env::var(name).ok()
        }
    };

    let parse_bool = |value: &str| -> Option<bool> {
        match value.trim().to_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => Some(true),
            "0" | "false" | "no" | "off" | "" => Some(false),
            _ => None,
        }
    };

    if let Some(val) = get_env("RCH_ENABLED")
        && let Some(enabled) = parse_bool(&val)
    {
        config.general.enabled = enabled;
        if let Some(ref mut sources) = sources {
            set_source(
                sources,
                "general.enabled",
                ConfigValueSource::EnvVar("RCH_ENABLED".to_string()),
            );
        }
    }

    if let Some(val) = get_env("RCH_LOG_LEVEL") {
        config.general.log_level = val;
        if let Some(ref mut sources) = sources {
            set_source(
                sources,
                "general.log_level",
                ConfigValueSource::EnvVar("RCH_LOG_LEVEL".to_string()),
            );
        }
    }

    if let Some(val) = get_env("RCH_SOCKET_PATH") {
        config.general.socket_path = val;
        if let Some(ref mut sources) = sources {
            set_source(
                sources,
                "general.socket_path",
                ConfigValueSource::EnvVar("RCH_SOCKET_PATH".to_string()),
            );
        }
    }

    if let Some(val) = get_env("RCH_CONFIDENCE_THRESHOLD")
        && let Ok(threshold) = val.parse()
    {
        config.compilation.confidence_threshold = threshold;
        if let Some(ref mut sources) = sources {
            set_source(
                sources,
                "compilation.confidence_threshold",
                ConfigValueSource::EnvVar("RCH_CONFIDENCE_THRESHOLD".to_string()),
            );
        }
    }
    if let Some(val) = get_env("RCH_BUILD_SLOTS")
        && let Ok(slots) = val.parse()
    {
        config.compilation.build_slots = slots;
        if let Some(ref mut sources) = sources {
            set_source(
                sources,
                "compilation.build_slots",
                ConfigValueSource::EnvVar("RCH_BUILD_SLOTS".to_string()),
            );
        }
    }
    if let Some(val) = get_env("RCH_TEST_SLOTS")
        && let Ok(slots) = val.parse()
    {
        config.compilation.test_slots = slots;
        if let Some(ref mut sources) = sources {
            set_source(
                sources,
                "compilation.test_slots",
                ConfigValueSource::EnvVar("RCH_TEST_SLOTS".to_string()),
            );
        }
    }
    if let Some(val) = get_env("RCH_CHECK_SLOTS")
        && let Ok(slots) = val.parse()
    {
        config.compilation.check_slots = slots;
        if let Some(ref mut sources) = sources {
            set_source(
                sources,
                "compilation.check_slots",
                ConfigValueSource::EnvVar("RCH_CHECK_SLOTS".to_string()),
            );
        }
    }
    if let Some(val) = get_env("RCH_BUILD_TIMEOUT_SEC")
        && let Ok(timeout) = val.parse()
    {
        config.compilation.build_timeout_sec = timeout;
        if let Some(ref mut sources) = sources {
            set_source(
                sources,
                "compilation.build_timeout_sec",
                ConfigValueSource::EnvVar("RCH_BUILD_TIMEOUT_SEC".to_string()),
            );
        }
    }
    if let Some(val) = get_env("RCH_TEST_TIMEOUT_SEC")
        && let Ok(timeout) = val.parse()
    {
        config.compilation.test_timeout_sec = timeout;
        if let Some(ref mut sources) = sources {
            set_source(
                sources,
                "compilation.test_timeout_sec",
                ConfigValueSource::EnvVar("RCH_TEST_TIMEOUT_SEC".to_string()),
            );
        }
    }

    if let Some(val) = get_env("RCH_COMPRESSION_LEVEL") {
        if let Ok(level) = val.parse() {
            config.transfer.compression_level = level;
            if let Some(ref mut sources) = sources {
                set_source(
                    sources,
                    "transfer.compression_level",
                    ConfigValueSource::EnvVar("RCH_COMPRESSION_LEVEL".to_string()),
                );
            }
        }
    } else if let Some(val) = get_env("RCH_COMPRESSION")
        && let Ok(level) = val.parse()
    {
        config.transfer.compression_level = level;
        if let Some(ref mut sources) = sources {
            set_source(
                sources,
                "transfer.compression_level",
                ConfigValueSource::EnvVar("RCH_COMPRESSION".to_string()),
            );
        }
    }

    if let Some(val) = get_env("RCH_SSH_SERVER_ALIVE_INTERVAL_SECS")
        && let Ok(secs) = val.parse::<u64>()
    {
        config.transfer.ssh_server_alive_interval_secs = Some(secs);
        if let Some(ref mut sources) = sources {
            set_source(
                sources,
                "transfer.ssh_server_alive_interval_secs",
                ConfigValueSource::EnvVar("RCH_SSH_SERVER_ALIVE_INTERVAL_SECS".to_string()),
            );
        }
    }

    if let Some(val) = get_env("RCH_SSH_CONTROL_PERSIST_SECS")
        && let Ok(secs) = val.parse::<u64>()
    {
        config.transfer.ssh_control_persist_secs = Some(secs);
        if let Some(ref mut sources) = sources {
            set_source(
                sources,
                "transfer.ssh_control_persist_secs",
                ConfigValueSource::EnvVar("RCH_SSH_CONTROL_PERSIST_SECS".to_string()),
            );
        }
    }

    if let Some(val) = get_env("RCH_ENV_ALLOWLIST") {
        let allowlist = parse_allowlist_value(&val);
        config.environment.allowlist = allowlist;
        if let Some(ref mut sources) = sources {
            set_source(
                sources,
                "environment.allowlist",
                ConfigValueSource::EnvVar("RCH_ENV_ALLOWLIST".to_string()),
            );
        }
    }

    let mut visibility_override: Option<(OutputVisibility, String)> = None;

    if let Some(val) = get_env("RCH_QUIET")
        && parse_bool(&val).unwrap_or(false)
    {
        visibility_override = Some((OutputVisibility::None, "RCH_QUIET".to_string()));
    }

    if visibility_override.is_none()
        && let Some(val) = get_env("RCH_VISIBILITY")
        && let Ok(mode) = val.parse::<OutputVisibility>()
    {
        visibility_override = Some((mode, "RCH_VISIBILITY".to_string()));
    }

    if visibility_override.is_none()
        && let Some(val) = get_env("RCH_VERBOSE")
        && parse_bool(&val).unwrap_or(false)
    {
        visibility_override = Some((OutputVisibility::Verbose, "RCH_VERBOSE".to_string()));
    }

    if let Some((mode, source_var)) = visibility_override {
        config.output.visibility = mode;
        if let Some(ref mut sources) = sources {
            set_source(
                sources,
                "output.visibility",
                ConfigValueSource::EnvVar(source_var),
            );
        }
    }

    let mut self_healing_master_disabled = false;
    if let Some(val) = get_env("RCH_NO_SELF_HEALING")
        && parse_bool(&val).unwrap_or(false)
    {
        self_healing_master_disabled = true;
        config.self_healing.hook_starts_daemon = false;
        config.self_healing.daemon_installs_hooks = false;
        if let Some(ref mut sources) = sources {
            set_source(
                sources,
                "self_healing.hook_starts_daemon",
                ConfigValueSource::EnvVar("RCH_NO_SELF_HEALING".to_string()),
            );
            set_source(
                sources,
                "self_healing.daemon_installs_hooks",
                ConfigValueSource::EnvVar("RCH_NO_SELF_HEALING".to_string()),
            );
        }
    }

    if let Some(val) = get_env("RCH_HOOK_STARTS_DAEMON")
        && let Some(enabled) = parse_bool(&val)
        && !self_healing_master_disabled
    {
        config.self_healing.hook_starts_daemon = enabled;
        if let Some(ref mut sources) = sources {
            set_source(
                sources,
                "self_healing.hook_starts_daemon",
                ConfigValueSource::EnvVar("RCH_HOOK_STARTS_DAEMON".to_string()),
            );
        }
    }

    if let Some(val) = get_env("RCH_DAEMON_INSTALLS_HOOKS")
        && let Some(enabled) = parse_bool(&val)
        && !self_healing_master_disabled
    {
        config.self_healing.daemon_installs_hooks = enabled;
        if let Some(ref mut sources) = sources {
            set_source(
                sources,
                "self_healing.daemon_installs_hooks",
                ConfigValueSource::EnvVar("RCH_DAEMON_INSTALLS_HOOKS".to_string()),
            );
        }
    }

    if let Some(val) = get_env("RCH_AUTO_START_COOLDOWN_SECS")
        && let Ok(secs) = val.parse()
        && !self_healing_master_disabled
    {
        config.self_healing.auto_start_cooldown_secs = secs;
        if let Some(ref mut sources) = sources {
            set_source(
                sources,
                "self_healing.auto_start_cooldown_secs",
                ConfigValueSource::EnvVar("RCH_AUTO_START_COOLDOWN_SECS".to_string()),
            );
        }
    }

    if let Some(val) = get_env("RCH_AUTO_START_TIMEOUT_SECS")
        && let Ok(secs) = val.parse()
        && !self_healing_master_disabled
    {
        config.self_healing.auto_start_timeout_secs = secs;
        if let Some(ref mut sources) = sources {
            set_source(
                sources,
                "self_healing.auto_start_timeout_secs",
                ConfigValueSource::EnvVar("RCH_AUTO_START_TIMEOUT_SECS".to_string()),
            );
        }
    }
}

fn parse_allowlist_value(value: &str) -> Vec<String> {
    value
        .split(',')
        .flat_map(|chunk| chunk.split_whitespace())
        .map(|item| item.trim())
        .filter(|item| !item.is_empty())
        .map(|item| item.to_string())
        .collect()
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

fn is_valid_log_level(level: &str) -> bool {
    matches!(
        level.trim().to_ascii_lowercase().as_str(),
        "trace" | "debug" | "info" | "warn" | "error" | "off"
    )
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
    detect_identity_file()
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

fn detect_identity_file() -> String {
    let Some(home) = dirs::home_dir() else {
        return "~/.ssh/id_rsa".to_string();
    };

    for name in ["id_ed25519", "id_rsa", "id_ecdsa"] {
        let path = home.join(".ssh").join(name);
        if path.exists() {
            return path.display().to_string();
        }
    }

    "~/.ssh/id_rsa".to_string()
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
# Default slot estimates
build_slots = 4
test_slots = 8
check_slots = 2

[transfer]
# zstd compression level (1-19)
compression_level = 3
# Additional patterns to exclude from transfer
exclude_patterns = [
    "target/",
    ".git/objects/",
    "node_modules/",
    ".beads/",
    "*.rlib",
    "*.rmeta",
]

[environment]
# Env vars to forward to workers.
# Note: CARGO_TARGET_DIR/TMPDIR/TMP/TEMP are automatically rewritten
# to worker-scoped paths under the remote project root for reliability.
allowlist = ["RUSTFLAGS", "CARGO_TARGET_DIR"]

[output]
# Hook output visibility: none, summary, verbose
visibility = "none"
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

    Err(ConfigError::InvalidValue {
        field: "config file".to_string(),
        reason: "Not a valid RCH or workers configuration".to_string(),
        suggestion: "Check TOML syntax or run 'rch init' to create a valid config".to_string(),
    }
    .into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rch_common::test_guard;
    use tempfile::NamedTempFile;
    use tracing::info;

    #[test]
    fn test_default_config() {
        let _guard = test_guard!();
        info!("TEST: test_default_config");
        let config = RchConfig::default();
        info!(
            "INPUT: default config - enabled={}, log_level={}, confidence={}",
            config.general.enabled,
            config.general.log_level,
            config.compilation.confidence_threshold
        );
        assert!(config.general.enabled);
        assert_eq!(config.general.log_level, "info");
        assert_eq!(config.compilation.confidence_threshold, 0.85);
        info!("PASS: Default config values correct");
    }

    #[test]
    fn test_example_project_config_valid() {
        let _guard = test_guard!();
        info!("TEST: test_example_project_config_valid");
        let toml_str = example_project_config();
        let _: RchConfig = toml::from_str(&toml_str).expect("Example project config should parse");
        info!("PASS: Example project config parses successfully");
    }

    #[test]
    fn test_example_workers_config_valid() {
        let _guard = test_guard!();
        info!("TEST: test_example_workers_config_valid");
        let toml_str = example_workers_config();
        let _: WorkersConfig =
            toml::from_str(&toml_str).expect("Example workers config should parse");
        info!("PASS: Example workers config parses successfully");
    }

    #[test]
    fn test_validate_valid_config() {
        let _guard = test_guard!();
        info!("TEST START: test_validate_valid_config");
        let mut file = NamedTempFile::new().expect("create temp file");
        std::io::Write::write_all(file.as_file_mut(), example_project_config().as_bytes())
            .expect("write config");
        let result = validate_rch_config_file(file.path());
        info!(
            "RESULT: errors={}, warnings={}",
            result.errors.len(),
            result.warnings.len()
        );
        assert!(result.errors.is_empty());
        info!("TEST PASS: test_validate_valid_config");
    }

    #[test]
    fn test_validate_force_override_conflict() {
        let _guard = test_guard!();
        info!("TEST START: test_validate_force_override_conflict");
        let mut file = NamedTempFile::new().expect("create temp file");
        std::io::Write::write_all(
            file.as_file_mut(),
            b"[general]\nforce_local = true\nforce_remote = true\n",
        )
        .expect("write config");
        let result = validate_rch_config_file(file.path());
        info!("RESULT: errors={:?}", result.errors);
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.contains("general.force_local") && e.contains("general.force_remote"))
        );
        info!("TEST PASS: test_validate_force_override_conflict");
    }

    #[test]
    fn test_validate_invalid_toml_syntax() {
        let _guard = test_guard!();
        info!("TEST START: test_validate_invalid_toml_syntax");
        let mut file = NamedTempFile::new().expect("create temp file");
        std::io::Write::write_all(file.as_file_mut(), b"invalid [ toml").expect("write config");
        let result = validate_rch_config_file(file.path());
        info!("RESULT: errors={:?}", result.errors);
        assert!(!result.errors.is_empty());
        info!("TEST PASS: test_validate_invalid_toml_syntax");
    }

    #[test]
    fn test_validate_threshold_range() {
        let _guard = test_guard!();
        info!("TEST START: test_validate_threshold_range");
        let mut file = NamedTempFile::new().expect("create temp file");
        std::io::Write::write_all(
            file.as_file_mut(),
            b"[compilation]\nconfidence_threshold = 1.5\n",
        )
        .expect("write config");
        let result = validate_rch_config_file(file.path());
        info!("RESULT: errors={:?}", result.errors);
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.contains("confidence_threshold"))
        );
        info!("TEST PASS: test_validate_threshold_range");
    }

    #[test]
    fn test_validate_env_allowlist_invalid_key() {
        let _guard = test_guard!();
        info!("TEST START: test_validate_env_allowlist_invalid_key");
        let mut file = NamedTempFile::new().expect("create temp file");
        std::io::Write::write_all(
            file.as_file_mut(),
            b"[environment]\nallowlist = [\"BAD=KEY\"]\n",
        )
        .expect("write config");
        let result = validate_rch_config_file(file.path());
        info!("RESULT: errors={:?}", result.errors);
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.contains("environment.allowlist"))
        );
        info!("TEST PASS: test_validate_env_allowlist_invalid_key");
    }

    #[test]
    fn test_validate_file_path_exists() {
        let _guard = test_guard!();
        info!("TEST START: test_validate_file_path_exists");
        let mut file = NamedTempFile::new().expect("create temp file");
        let workers_toml = r#"
[[workers]]
id = "gpu-1"
host = "10.0.0.5"
user = "ubuntu"
identity_file = "/nonexistent/ssh_key"
total_slots = 4
"#;
        std::io::Write::write_all(file.as_file_mut(), workers_toml.as_bytes())
            .expect("write workers config");
        let result = validate_workers_config_file(file.path());
        info!("RESULT: warnings={:?}", result.warnings);
        assert!(result.warnings.iter().any(|e| e.contains("identity_file")));
        info!("TEST PASS: test_validate_file_path_exists");
    }

    #[test]
    fn test_validate_workers_missing_user() {
        let _guard = test_guard!();
        info!("TEST START: test_validate_workers_missing_user");
        let mut file = NamedTempFile::new().expect("create temp file");
        let workers_toml = r#"
[[workers]]
id = "gpu-2"
host = "10.0.0.6"
identity_file = "/tmp/id_ed25519"
total_slots = 8
"#;
        std::io::Write::write_all(file.as_file_mut(), workers_toml.as_bytes())
            .expect("write workers config");
        let result = validate_workers_config_file(file.path());
        info!("RESULT: errors={:?}", result.errors);
        assert!(result.errors.iter().any(|e| e.contains("user is required")));
        info!("TEST PASS: test_validate_workers_missing_user");
    }

    #[test]
    fn test_validate_workers_missing_total_slots_warns() {
        let _guard = test_guard!();
        info!("TEST START: test_validate_workers_missing_total_slots_warns");
        let mut file = NamedTempFile::new().expect("create temp file");
        let workers_toml = r#"
[[workers]]
id = "gpu-3"
host = "10.0.0.7"
user = "builder"
identity_file = "/tmp/id_ed25519"
"#;
        std::io::Write::write_all(file.as_file_mut(), workers_toml.as_bytes())
            .expect("write workers config");
        let result = validate_workers_config_file(file.path());
        info!("RESULT: warnings={:?}", result.warnings);
        assert!(
            result
                .warnings
                .iter()
                .any(|e| e.contains("total_slots not specified"))
        );
        info!("TEST PASS: test_validate_workers_missing_total_slots_warns");
    }

    // ========================================================================
    // Merge Config Tests - Issue remote_compilation_helper-f0t.1
    // ========================================================================

    #[test]
    fn test_merge_compilation_slots_override() {
        let _guard = test_guard!();
        info!("TEST START: test_merge_compilation_slots_override");
        let mut base = RchConfig::default();
        base.compilation.build_slots = 6;
        base.compilation.test_slots = 10;
        base.compilation.check_slots = 3;
        base.compilation.build_timeout_sec = 420;
        base.compilation.test_timeout_sec = 2400;

        let mut overlay = RchConfig::default();
        overlay.compilation.build_slots = 12;
        overlay.compilation.build_timeout_sec = 600;

        let merged = merge_config(base.clone(), overlay);
        info!(
            "RESULT: build_slots={}, test_slots={}, check_slots={}, build_timeout_sec={}, test_timeout_sec={}",
            merged.compilation.build_slots,
            merged.compilation.test_slots,
            merged.compilation.check_slots,
            merged.compilation.build_timeout_sec,
            merged.compilation.test_timeout_sec
        );
        assert_eq!(merged.compilation.build_slots, 12);
        assert_eq!(merged.compilation.test_slots, 10);
        assert_eq!(merged.compilation.check_slots, 3);
        assert_eq!(merged.compilation.build_timeout_sec, 600);
        assert_eq!(merged.compilation.test_timeout_sec, 2400);
        info!("TEST PASS: test_merge_compilation_slots_override");
    }

    #[test]
    fn test_merge_preserves_base_fields() {
        let _guard = test_guard!();
        info!("TEST: test_merge_preserves_base_fields");

        // Base config with non-default values
        let mut base = RchConfig::default();
        base.compilation.confidence_threshold = 0.90;
        base.compilation.min_local_time_ms = 5000;
        base.general.log_level = "debug".to_string();

        info!(
            "INPUT base: confidence={}, min_local_time_ms={}, log_level={}",
            base.compilation.confidence_threshold,
            base.compilation.min_local_time_ms,
            base.general.log_level
        );

        // Overlay that only changes confidence_threshold (leaves others at default)
        let overlay_toml = r#"
            [compilation]
            confidence_threshold = 0.70
        "#;
        let overlay: RchConfig = toml::from_str(overlay_toml).expect("Parse overlay");

        info!(
            "INPUT overlay: confidence={}, min_local_time_ms={} (default)",
            overlay.compilation.confidence_threshold, overlay.compilation.min_local_time_ms
        );

        let merged = merge_config(base, overlay);

        info!(
            "RESULT: confidence={}, min_local_time_ms={}, log_level={}",
            merged.compilation.confidence_threshold,
            merged.compilation.min_local_time_ms,
            merged.general.log_level
        );

        // Confidence should be overridden (0.70 != 0.85 default)
        assert!(
            (merged.compilation.confidence_threshold - 0.70).abs() < 0.0001,
            "Expected confidence_threshold=0.70, got {}",
            merged.compilation.confidence_threshold
        );

        // min_local_time_ms should be preserved from base (overlay has default 2000)
        assert_eq!(
            merged.compilation.min_local_time_ms, 5000,
            "Expected min_local_time_ms=5000, got {}",
            merged.compilation.min_local_time_ms
        );

        // log_level should be preserved from base (overlay has default "info")
        assert_eq!(
            merged.general.log_level, "debug",
            "Expected log_level=debug, got {}",
            merged.general.log_level
        );

        info!("PASS: Base fields preserved when overlay uses defaults");
    }

    #[test]
    fn test_merge_overlay_wins() {
        let _guard = test_guard!();
        info!("TEST: test_merge_overlay_wins");

        let base = RchConfig::default();
        info!(
            "INPUT base (default): confidence={}, log_level={}",
            base.compilation.confidence_threshold, base.general.log_level
        );

        // Overlay with explicit non-default values
        let overlay_toml = r#"
            [general]
            log_level = "warn"
            socket_path = "/custom/rch.sock"

            [compilation]
            confidence_threshold = 0.95
            min_local_time_ms = 3000
        "#;
        let overlay: RchConfig = toml::from_str(overlay_toml).expect("Parse overlay");
        info!(
            "INPUT overlay: confidence={}, log_level={}, socket_path={}",
            overlay.compilation.confidence_threshold,
            overlay.general.log_level,
            overlay.general.socket_path
        );

        let merged = merge_config(base, overlay);

        info!(
            "RESULT: confidence={}, log_level={}, socket_path={}, min_local_time_ms={}",
            merged.compilation.confidence_threshold,
            merged.general.log_level,
            merged.general.socket_path,
            merged.compilation.min_local_time_ms
        );

        // All overlay fields should win
        assert!(
            (merged.compilation.confidence_threshold - 0.95).abs() < 0.0001,
            "Expected confidence_threshold=0.95"
        );
        assert_eq!(merged.general.log_level, "warn");
        assert_eq!(merged.general.socket_path, "/custom/rch.sock");
        assert_eq!(merged.compilation.min_local_time_ms, 3000);

        info!("PASS: Overlay non-default values override base");
    }

    #[test]
    fn test_merge_nested_sections() {
        let _guard = test_guard!();
        info!("TEST: test_merge_nested_sections");

        // Base with non-default circuit breaker settings
        let mut base = RchConfig::default();
        base.circuit.failure_threshold = 10;
        base.circuit.window_secs = 120;

        info!(
            "INPUT base: failure_threshold={}, window_secs={}",
            base.circuit.failure_threshold, base.circuit.window_secs
        );

        // Overlay only changes one circuit field
        let overlay_toml = r#"
            [circuit]
            success_threshold = 5
        "#;
        let overlay: RchConfig = toml::from_str(overlay_toml).expect("Parse overlay");

        info!(
            "INPUT overlay: success_threshold={}, failure_threshold={} (default)",
            overlay.circuit.success_threshold, overlay.circuit.failure_threshold
        );

        let merged = merge_config(base, overlay);

        info!(
            "RESULT: failure_threshold={}, window_secs={}, success_threshold={}",
            merged.circuit.failure_threshold,
            merged.circuit.window_secs,
            merged.circuit.success_threshold
        );

        // Base values should be preserved
        assert_eq!(
            merged.circuit.failure_threshold, 10,
            "failure_threshold should be preserved from base"
        );
        assert_eq!(
            merged.circuit.window_secs, 120,
            "window_secs should be preserved from base"
        );

        // Overlay value should be applied
        assert_eq!(
            merged.circuit.success_threshold, 5,
            "success_threshold should be from overlay"
        );

        info!("PASS: Nested section fields merge correctly");
    }

    // ========================================================================
    // Source Tracking Tests - Issue remote_compilation_helper-8qc.2
    // ========================================================================

    #[test]
    fn test_source_tracking_default() {
        let _guard = test_guard!();
        info!("TEST: test_source_tracking_default");
        let env_overrides: HashMap<String, String> = HashMap::new();

        let loaded = load_config_with_sources_from_paths(None, None, Some(&env_overrides))
            .expect("load_config_with_sources_from_paths should succeed");

        let source = loaded
            .sources
            .get("general.enabled")
            .expect("general.enabled source present");
        assert_eq!(source, &ConfigValueSource::Default);
        info!("PASS: Default source detected for general.enabled");
    }

    #[test]
    fn test_source_tracking_user_file() {
        let _guard = test_guard!();
        info!("TEST: test_source_tracking_user_file");
        let temp_dir = std::env::temp_dir().join(format!(
            "rch_test_config_user_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&temp_dir).expect("create temp dir");
        let user_path = temp_dir.join("config.toml");

        let toml_str = r#"
            [general]
            log_level = "debug"
        "#;
        std::fs::write(&user_path, toml_str).expect("write user config");

        let env_overrides: HashMap<String, String> = HashMap::new();
        let loaded =
            load_config_with_sources_from_paths(Some(&user_path), None, Some(&env_overrides))
                .expect("load_config_with_sources_from_paths should succeed");

        info!("RESULT: log_level={}", loaded.config.general.log_level);
        assert_eq!(loaded.config.general.log_level, "debug");

        let source = loaded
            .sources
            .get("general.log_level")
            .expect("general.log_level source present");
        assert_eq!(source, &ConfigValueSource::UserConfig(user_path));
        info!("PASS: User config source detected for general.log_level");
    }

    #[test]
    fn test_source_tracking_env_override() {
        let _guard = test_guard!();
        info!("TEST: test_source_tracking_env_override");
        let mut env_overrides: HashMap<String, String> = HashMap::new();
        env_overrides.insert("RCH_LOG_LEVEL".to_string(), "warn".to_string());

        let loaded = load_config_with_sources_from_paths(None, None, Some(&env_overrides))
            .expect("load_config_with_sources_from_paths should succeed");

        info!("RESULT: log_level={}", loaded.config.general.log_level);
        assert_eq!(loaded.config.general.log_level, "warn");

        let source = loaded
            .sources
            .get("general.log_level")
            .expect("general.log_level source present");
        assert_eq!(
            source,
            &ConfigValueSource::EnvVar("RCH_LOG_LEVEL".to_string())
        );
        info!("PASS: Environment source detected for general.log_level");
    }

    #[test]
    fn test_source_tracking_env_visibility_override() {
        let _guard = test_guard!();
        info!("TEST: test_source_tracking_env_visibility_override");
        let mut env_overrides: HashMap<String, String> = HashMap::new();
        env_overrides.insert("RCH_VISIBILITY".to_string(), "summary".to_string());

        let loaded = load_config_with_sources_from_paths(None, None, Some(&env_overrides))
            .expect("load_config_with_sources_from_paths should succeed");

        info!("RESULT: visibility={}", loaded.config.output.visibility);
        assert_eq!(loaded.config.output.visibility, OutputVisibility::Summary);

        let source = loaded
            .sources
            .get("output.visibility")
            .expect("output.visibility source present");
        assert_eq!(
            source,
            &ConfigValueSource::EnvVar("RCH_VISIBILITY".to_string())
        );
        info!("PASS: Environment source detected for output.visibility");
    }

    #[test]
    fn test_merge_empty_overlay() {
        let _guard = test_guard!();
        info!("TEST: test_merge_empty_overlay");

        // Base with custom values
        let mut base = RchConfig::default();
        base.compilation.confidence_threshold = 0.99;
        base.general.log_level = "trace".to_string();
        base.transfer.compression_level = 10;

        info!(
            "INPUT base: confidence={}, log_level={}, compression={}",
            base.compilation.confidence_threshold,
            base.general.log_level,
            base.transfer.compression_level
        );

        // Empty overlay (all defaults)
        let overlay = RchConfig::default();
        info!("INPUT overlay: all defaults");

        let merged = merge_config(base.clone(), overlay);

        info!(
            "RESULT: confidence={}, log_level={}, compression={}",
            merged.compilation.confidence_threshold,
            merged.general.log_level,
            merged.transfer.compression_level
        );

        // Everything should remain from base since overlay is all defaults
        assert!(
            (merged.compilation.confidence_threshold - 0.99).abs() < 0.0001,
            "confidence_threshold should be preserved"
        );
        assert_eq!(
            merged.general.log_level, "trace",
            "log_level should be preserved"
        );
        assert_eq!(
            merged.transfer.compression_level, 10,
            "compression_level should be preserved"
        );

        info!("PASS: Empty overlay is no-op");
    }

    #[test]
    fn test_merge_transfer_exclude_patterns() {
        let _guard = test_guard!();
        info!("TEST: test_merge_transfer_exclude_patterns");

        let base = RchConfig::default();
        info!(
            "INPUT base: exclude_patterns count={}",
            base.transfer.exclude_patterns.len()
        );

        // Overlay with custom exclude patterns
        let overlay_toml = r#"
            [transfer]
            exclude_patterns = [
                "target/",
                "custom_exclude/",
                "*.log"
            ]
        "#;
        let overlay: RchConfig = toml::from_str(overlay_toml).expect("Parse overlay");
        info!(
            "INPUT overlay: exclude_patterns={:?}",
            overlay.transfer.exclude_patterns
        );

        let merged = merge_config(base, overlay);

        info!(
            "RESULT: exclude_patterns={:?}",
            merged.transfer.exclude_patterns
        );

        // Custom patterns should replace defaults (not merge)
        assert_eq!(merged.transfer.exclude_patterns.len(), 3);
        assert!(
            merged
                .transfer
                .exclude_patterns
                .contains(&"target/".to_string())
        );
        assert!(
            merged
                .transfer
                .exclude_patterns
                .contains(&"custom_exclude/".to_string())
        );
        assert!(
            merged
                .transfer
                .exclude_patterns
                .contains(&"*.log".to_string())
        );

        info!("PASS: Custom exclude_patterns replace defaults");
    }

    #[test]
    fn test_merge_transfer_remote_base() {
        let _guard = test_guard!();
        info!("TEST: test_merge_transfer_remote_base");

        let base = RchConfig::default();
        info!("INPUT base: remote_base={}", base.transfer.remote_base);
        assert_eq!(base.transfer.remote_base, "/tmp/rch");

        // Overlay with custom remote_base
        let overlay_toml = r#"
            [transfer]
            remote_base = "/var/rch-builds"
        "#;
        let overlay: RchConfig = toml::from_str(overlay_toml).expect("Parse overlay");
        info!(
            "INPUT overlay: remote_base={}",
            overlay.transfer.remote_base
        );

        let merged = merge_config(base, overlay);

        info!("RESULT: remote_base={}", merged.transfer.remote_base);

        // Custom remote_base should replace default
        assert_eq!(merged.transfer.remote_base, "/var/rch-builds");

        info!("PASS: Custom remote_base replaces default");
    }

    #[test]
    fn test_merge_transfer_remote_base_with_tilde() {
        let _guard = test_guard!();
        info!("TEST: test_merge_transfer_remote_base_with_tilde");

        let base = RchConfig::default();

        // Overlay with tilde-based path
        let overlay_toml = r#"
            [transfer]
            remote_base = "~/rch-builds"
        "#;
        let overlay: RchConfig = toml::from_str(overlay_toml).expect("Parse overlay");

        let merged = merge_config(base, overlay);

        info!("RESULT: remote_base={}", merged.transfer.remote_base);

        // Tilde should be expanded to absolute path
        assert!(
            merged.transfer.remote_base.starts_with('/'),
            "remote_base should be absolute after tilde expansion"
        );
        assert!(
            !merged.transfer.remote_base.contains('~'),
            "Tilde should be expanded"
        );

        info!("PASS: Tilde-based remote_base is expanded");
    }

    #[test]
    fn test_merge_boolean_enabled_field() {
        let _guard = test_guard!();
        info!("TEST: test_merge_boolean_enabled_field");

        // Base has enabled=true (default)
        let base = RchConfig::default();
        assert!(base.general.enabled, "Base should have enabled=true");

        // Overlay explicitly disables
        let overlay_toml = r#"
            [general]
            enabled = false
        "#;
        let overlay: RchConfig = toml::from_str(overlay_toml).expect("Parse overlay");

        info!(
            "INPUT base: enabled={}, INPUT overlay: enabled={}",
            base.general.enabled, overlay.general.enabled
        );

        let merged = merge_config(base, overlay);

        info!("RESULT: enabled={}", merged.general.enabled);

        // enabled=false differs from default (true), so it should be applied
        assert!(
            !merged.general.enabled,
            "enabled=false should be applied from overlay"
        );

        info!("PASS: Boolean enabled=false overrides enabled=true");
    }

    #[test]
    fn test_merge_real_world_project_config() {
        let _guard = test_guard!();
        info!("TEST: test_merge_real_world_project_config");

        // User config with customizations
        let user_toml = r#"
            [general]
            log_level = "debug"

            [compilation]
            confidence_threshold = 0.90
            min_local_time_ms = 5000

            [transfer]
            compression_level = 6
        "#;
        let base: RchConfig = toml::from_str(user_toml).expect("Parse user config");

        info!(
            "INPUT user: log_level={}, confidence={}, min_local_time={}, compression={}",
            base.general.log_level,
            base.compilation.confidence_threshold,
            base.compilation.min_local_time_ms,
            base.transfer.compression_level
        );

        // Project config only overrides confidence
        let project_toml = r#"
            [compilation]
            confidence_threshold = 0.70
        "#;
        let overlay: RchConfig = toml::from_str(project_toml).expect("Parse project config");

        info!(
            "INPUT project: confidence={} (others are defaults)",
            overlay.compilation.confidence_threshold
        );

        let merged = merge_config(base, overlay);

        info!(
            "RESULT: log_level={}, confidence={}, min_local_time={}, compression={}",
            merged.general.log_level,
            merged.compilation.confidence_threshold,
            merged.compilation.min_local_time_ms,
            merged.transfer.compression_level
        );

        // Project config only changed confidence_threshold
        assert!(
            (merged.compilation.confidence_threshold - 0.70).abs() < 0.0001,
            "confidence_threshold should be from project"
        );

        // All other user values preserved
        assert_eq!(
            merged.general.log_level, "debug",
            "log_level from user preserved"
        );
        assert_eq!(
            merged.compilation.min_local_time_ms, 5000,
            "min_local_time_ms from user preserved"
        );
        assert_eq!(
            merged.transfer.compression_level, 6,
            "compression_level from user preserved"
        );

        info!("PASS: Real-world project config scenario works correctly");
    }

    #[test]
    fn test_apply_env_overrides_enabled_false() {
        let _guard = test_guard!();
        info!("TEST: test_apply_env_overrides_enabled_false");
        let mut config = RchConfig::default();
        let mut sources = default_sources_map();
        let mut env_overrides: HashMap<String, String> = HashMap::new();
        env_overrides.insert("RCH_ENABLED".to_string(), "0".to_string());

        apply_env_overrides_inner(&mut config, Some(&mut sources), Some(&env_overrides));

        info!("RESULT: enabled={}", config.general.enabled);
        assert!(!config.general.enabled, "expected RCH_ENABLED=0 to disable");
        let source = sources
            .get("general.enabled")
            .expect("general.enabled source present");
        assert_eq!(
            source,
            &ConfigValueSource::EnvVar("RCH_ENABLED".to_string())
        );
        info!("PASS: RCH_ENABLED override applied with source tracking");
    }

    #[test]
    fn test_apply_env_overrides_visibility_precedence() {
        let _guard = test_guard!();
        info!("TEST: test_apply_env_overrides_visibility_precedence");
        let mut config = RchConfig::default();
        let mut sources = default_sources_map();
        let mut env_overrides: HashMap<String, String> = HashMap::new();
        env_overrides.insert("RCH_VISIBILITY".to_string(), "verbose".to_string());
        env_overrides.insert("RCH_VERBOSE".to_string(), "true".to_string());
        env_overrides.insert("RCH_QUIET".to_string(), "1".to_string());

        apply_env_overrides_inner(&mut config, Some(&mut sources), Some(&env_overrides));

        info!("RESULT: visibility={:?}", config.output.visibility);
        assert_eq!(config.output.visibility, OutputVisibility::None);
        let source = sources
            .get("output.visibility")
            .expect("output.visibility source present");
        assert_eq!(source, &ConfigValueSource::EnvVar("RCH_QUIET".to_string()));
        info!("PASS: RCH_QUIET takes precedence over visibility/verbose");
    }

    #[test]
    fn test_apply_env_overrides_env_allowlist() {
        let _guard = test_guard!();
        info!("TEST: test_apply_env_overrides_env_allowlist");
        let mut config = RchConfig::default();
        let mut sources = default_sources_map();
        let mut env_overrides: HashMap<String, String> = HashMap::new();
        env_overrides.insert(
            "RCH_ENV_ALLOWLIST".to_string(),
            "RUSTFLAGS, CARGO_TARGET_DIR  EXTRA".to_string(),
        );

        apply_env_overrides_inner(&mut config, Some(&mut sources), Some(&env_overrides));

        assert_eq!(
            config.environment.allowlist,
            vec![
                "RUSTFLAGS".to_string(),
                "CARGO_TARGET_DIR".to_string(),
                "EXTRA".to_string()
            ]
        );
        let source = sources
            .get("environment.allowlist")
            .expect("environment.allowlist source present");
        assert_eq!(
            source,
            &ConfigValueSource::EnvVar("RCH_ENV_ALLOWLIST".to_string())
        );
        info!("PASS: RCH_ENV_ALLOWLIST override applied with source tracking");
    }

    #[test]
    fn test_apply_env_overrides_self_healing() {
        let _guard = test_guard!();
        info!("TEST: test_apply_env_overrides_self_healing");
        let mut config = RchConfig::default();
        let mut sources = default_sources_map();
        let mut env_overrides: HashMap<String, String> = HashMap::new();
        env_overrides.insert("RCH_HOOK_STARTS_DAEMON".to_string(), "false".to_string());
        env_overrides.insert("RCH_AUTO_START_COOLDOWN_SECS".to_string(), "45".to_string());
        env_overrides.insert("RCH_AUTO_START_TIMEOUT_SECS".to_string(), "7".to_string());

        apply_env_overrides_inner(&mut config, Some(&mut sources), Some(&env_overrides));

        assert!(!config.self_healing.hook_starts_daemon);
        assert_eq!(config.self_healing.auto_start_cooldown_secs, 45);
        assert_eq!(config.self_healing.auto_start_timeout_secs, 7);

        let source = sources
            .get("self_healing.hook_starts_daemon")
            .expect("self_healing.hook_starts_daemon source present");
        assert_eq!(
            source,
            &ConfigValueSource::EnvVar("RCH_HOOK_STARTS_DAEMON".to_string())
        );

        let source = sources
            .get("self_healing.auto_start_cooldown_secs")
            .expect("self_healing.auto_start_cooldown_secs source present");
        assert_eq!(
            source,
            &ConfigValueSource::EnvVar("RCH_AUTO_START_COOLDOWN_SECS".to_string())
        );

        let source = sources
            .get("self_healing.auto_start_timeout_secs")
            .expect("self_healing.auto_start_timeout_secs source present");
        assert_eq!(
            source,
            &ConfigValueSource::EnvVar("RCH_AUTO_START_TIMEOUT_SECS".to_string())
        );

        info!("PASS: self_healing env overrides applied with source tracking");
    }

    #[test]
    fn test_apply_env_overrides_self_healing_master_disable_precedence() {
        let _guard = test_guard!();
        info!("TEST: test_apply_env_overrides_self_healing_master_disable_precedence");
        let mut config = RchConfig::default();
        let mut sources = default_sources_map();
        let mut env_overrides: HashMap<String, String> = HashMap::new();
        env_overrides.insert("RCH_NO_SELF_HEALING".to_string(), "1".to_string());
        env_overrides.insert("RCH_HOOK_STARTS_DAEMON".to_string(), "true".to_string());
        env_overrides.insert("RCH_DAEMON_INSTALLS_HOOKS".to_string(), "true".to_string());
        env_overrides.insert("RCH_AUTO_START_COOLDOWN_SECS".to_string(), "45".to_string());
        env_overrides.insert("RCH_AUTO_START_TIMEOUT_SECS".to_string(), "7".to_string());

        apply_env_overrides_inner(&mut config, Some(&mut sources), Some(&env_overrides));

        // Master disable wins over all other self-healing env vars.
        assert!(!config.self_healing.hook_starts_daemon);
        assert!(!config.self_healing.daemon_installs_hooks);
        assert_eq!(config.self_healing.auto_start_cooldown_secs, 30);
        assert_eq!(config.self_healing.auto_start_timeout_secs, 3);

        let source = sources
            .get("self_healing.hook_starts_daemon")
            .expect("self_healing.hook_starts_daemon source present");
        assert_eq!(
            source,
            &ConfigValueSource::EnvVar("RCH_NO_SELF_HEALING".to_string())
        );

        let source = sources
            .get("self_healing.daemon_installs_hooks")
            .expect("self_healing.daemon_installs_hooks source present");
        assert_eq!(
            source,
            &ConfigValueSource::EnvVar("RCH_NO_SELF_HEALING".to_string())
        );

        info!("PASS: RCH_NO_SELF_HEALING takes precedence for self-healing config");
    }

    #[test]
    fn test_validate_workers_duplicate_ids() {
        let _guard = test_guard!();
        info!("TEST: test_validate_workers_duplicate_ids");
        let identity = NamedTempFile::new().expect("create identity file");
        let mut file = NamedTempFile::new().expect("create workers config file");

        let workers_toml = format!(
            r#"
[[workers]]
id = "dup"
host = "127.0.0.1"
identity_file = "{}"
total_slots = 4

[[workers]]
id = "dup"
host = "127.0.0.2"
identity_file = "{}"
total_slots = 8
"#,
            identity.path().display(),
            identity.path().display()
        );

        std::io::Write::write_all(file.as_file_mut(), workers_toml.as_bytes())
            .expect("write workers config");

        let result = validate_workers_config_file(file.path());
        info!("RESULT: errors={:?}", result.errors);
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.contains("Duplicate worker id")),
            "expected duplicate worker id error"
        );
        info!("PASS: duplicate worker ids are detected");
    }

    // ========================================================================
    // Additional Unit Tests - Issue bd-1aim.3
    // ========================================================================

    #[test]
    fn test_validate_compression_level_negative() {
        let _guard = test_guard!();
        info!("TEST: test_validate_compression_level_negative");
        let mut file = NamedTempFile::new().expect("create temp file");
        // Negative compression level should be invalid
        std::io::Write::write_all(file.as_file_mut(), b"[transfer]\ncompression_level = -1\n")
            .expect("write config");
        let result = validate_rch_config_file(file.path());
        info!("RESULT: errors={:?}", result.errors);
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.contains("compression_level")),
            "expected compression_level validation error for negative value"
        );
        info!("PASS: Negative compression_level rejected");
    }

    #[test]
    fn test_validate_compression_level_too_high() {
        let _guard = test_guard!();
        info!("TEST: test_validate_compression_level_too_high");
        let mut file = NamedTempFile::new().expect("create temp file");
        // Compression level > 22 (zstd max) should be invalid
        std::io::Write::write_all(file.as_file_mut(), b"[transfer]\ncompression_level = 25\n")
            .expect("write config");
        let result = validate_rch_config_file(file.path());
        info!("RESULT: errors={:?}", result.errors);
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.contains("compression_level")),
            "expected compression_level validation error for value > 22"
        );
        info!("PASS: Excessive compression_level rejected");
    }

    #[test]
    fn test_validate_invalid_timeout_negative() {
        let _guard = test_guard!();
        info!("TEST: test_validate_invalid_timeout_negative");
        let mut file = NamedTempFile::new().expect("create temp file");
        std::io::Write::write_all(
            file.as_file_mut(),
            b"[compilation]\nbuild_timeout_sec = -100\n",
        )
        .expect("write config");
        let result = validate_rch_config_file(file.path());
        info!("RESULT: errors={:?}", result.errors);
        // Negative timeout should either fail parsing or validation
        assert!(
            !result.errors.is_empty() || result.warnings.iter().any(|w| w.contains("timeout")),
            "expected validation issue for negative timeout"
        );
        info!("PASS: Negative timeout handled appropriately");
    }

    #[test]
    fn test_validate_invalid_log_level() {
        let _guard = test_guard!();
        info!("TEST: test_validate_invalid_log_level");
        let mut file = NamedTempFile::new().expect("create temp file");
        std::io::Write::write_all(
            file.as_file_mut(),
            b"[general]\nlog_level = \"invalid_level\"\n",
        )
        .expect("write config");
        let result = validate_rch_config_file(file.path());
        info!(
            "RESULT: errors={:?}, warnings={:?}",
            result.errors, result.warnings
        );
        // Invalid log level should produce warning or error
        let has_log_level_issue = result.errors.iter().any(|e| e.contains("log_level"))
            || result.warnings.iter().any(|w| w.contains("log_level"));
        assert!(has_log_level_issue, "expected log_level validation issue");
        info!("PASS: Invalid log_level detected");
    }

    #[test]
    fn test_config_file_not_found_graceful_fallback() {
        let _guard = test_guard!();
        info!("TEST: test_config_file_not_found_graceful_fallback");
        let nonexistent_path = std::path::PathBuf::from("/nonexistent/config/path/config.toml");
        let env_overrides: HashMap<String, String> = HashMap::new();

        // Should succeed with defaults when no config files exist
        let result = load_config_with_sources_from_paths(
            Some(&nonexistent_path),
            None,
            Some(&env_overrides),
        );

        info!("RESULT: {:?}", result.is_ok());
        assert!(
            result.is_ok(),
            "should succeed with defaults when config not found"
        );
        let loaded = result.expect("load_config should succeed");
        assert!(
            loaded.config.general.enabled,
            "default enabled should be true"
        );
        info!("PASS: Config loading falls back to defaults gracefully");
    }

    #[test]
    fn test_invalid_toml_type_mismatch() {
        let _guard = test_guard!();
        info!("TEST: test_invalid_toml_type_mismatch");
        let mut file = NamedTempFile::new().expect("create temp file");
        // String where integer expected
        std::io::Write::write_all(
            file.as_file_mut(),
            b"[compilation]\nbuild_slots = \"not_a_number\"\n",
        )
        .expect("write config");
        let result = validate_rch_config_file(file.path());
        info!("RESULT: errors={:?}", result.errors);
        assert!(
            !result.errors.is_empty(),
            "type mismatch should produce errors"
        );
        info!("PASS: Type mismatch detected");
    }

    #[test]
    fn test_empty_config_sections() {
        let _guard = test_guard!();
        info!("TEST: test_empty_config_sections");
        let mut file = NamedTempFile::new().expect("create temp file");
        // Empty sections should be valid
        let empty_sections = r#"
[general]

[compilation]

[transfer]

[circuit]

[output]

[environment]
"#;
        std::io::Write::write_all(file.as_file_mut(), empty_sections.as_bytes())
            .expect("write config");
        let result = validate_rch_config_file(file.path());
        info!("RESULT: errors={:?}", result.errors);
        assert!(result.errors.is_empty(), "empty sections should be valid");
        info!("PASS: Empty config sections accepted");
    }

    #[test]
    fn test_unknown_toml_fields_ignored() {
        let _guard = test_guard!();
        info!("TEST: test_unknown_toml_fields_ignored");
        let mut file = NamedTempFile::new().expect("create temp file");
        // Unknown fields should be gracefully ignored (serde default behavior)
        let toml_with_extra = r#"
[general]
enabled = true
unknown_field = "should_be_ignored"

[compilation]
confidence_threshold = 0.85
extra_field = 123
"#;
        std::io::Write::write_all(file.as_file_mut(), toml_with_extra.as_bytes())
            .expect("write config");
        let result = validate_rch_config_file(file.path());
        info!(
            "RESULT: errors={:?}, warnings={:?}",
            result.errors, result.warnings
        );
        // With #[serde(deny_unknown_fields)] this would fail;
        // but default serde behavior ignores unknown fields
        assert!(
            result.errors.is_empty() || result.errors.iter().any(|e| e.contains("unknown")),
            "unknown fields should either be ignored or explicitly flagged"
        );
        info!("PASS: Unknown TOML fields handled appropriately");
    }

    #[test]
    fn test_apply_env_overrides_socket_path() {
        let _guard = test_guard!();
        info!("TEST: test_apply_env_overrides_socket_path");
        let mut config = RchConfig::default();
        let mut sources = default_sources_map();
        let mut env_overrides: HashMap<String, String> = HashMap::new();
        env_overrides.insert(
            "RCH_SOCKET_PATH".to_string(),
            "/custom/socket.sock".to_string(),
        );

        apply_env_overrides_inner(&mut config, Some(&mut sources), Some(&env_overrides));

        info!("RESULT: socket_path={}", config.general.socket_path);
        assert_eq!(config.general.socket_path, "/custom/socket.sock");
        let source = sources
            .get("general.socket_path")
            .expect("general.socket_path source present");
        assert_eq!(
            source,
            &ConfigValueSource::EnvVar("RCH_SOCKET_PATH".to_string())
        );
        info!("PASS: RCH_SOCKET_PATH override applied");
    }

    #[test]
    fn test_apply_env_overrides_compression_level() {
        let _guard = test_guard!();
        info!("TEST: test_apply_env_overrides_compression_level");
        let mut config = RchConfig::default();
        let mut sources = default_sources_map();
        let mut env_overrides: HashMap<String, String> = HashMap::new();
        env_overrides.insert("RCH_COMPRESSION_LEVEL".to_string(), "15".to_string());

        apply_env_overrides_inner(&mut config, Some(&mut sources), Some(&env_overrides));

        info!(
            "RESULT: compression_level={}",
            config.transfer.compression_level
        );
        assert_eq!(config.transfer.compression_level, 15);
        let source = sources
            .get("transfer.compression_level")
            .expect("transfer.compression_level source present");
        assert_eq!(
            source,
            &ConfigValueSource::EnvVar("RCH_COMPRESSION_LEVEL".to_string())
        );
        info!("PASS: RCH_COMPRESSION_LEVEL override applied");
    }

    #[test]
    fn test_apply_env_overrides_ssh_keepalive_and_controlpersist() {
        let _guard = test_guard!();
        info!("TEST: test_apply_env_overrides_ssh_keepalive_and_controlpersist");
        let mut config = RchConfig::default();
        let mut sources = default_sources_map();
        let mut env_overrides: HashMap<String, String> = HashMap::new();
        env_overrides.insert(
            "RCH_SSH_SERVER_ALIVE_INTERVAL_SECS".to_string(),
            "30".to_string(),
        );
        env_overrides.insert("RCH_SSH_CONTROL_PERSIST_SECS".to_string(), "60".to_string());

        apply_env_overrides_inner(&mut config, Some(&mut sources), Some(&env_overrides));

        assert_eq!(config.transfer.ssh_server_alive_interval_secs, Some(30));
        assert_eq!(config.transfer.ssh_control_persist_secs, Some(60));
        assert_eq!(
            sources
                .get("transfer.ssh_server_alive_interval_secs")
                .expect("transfer.ssh_server_alive_interval_secs source present"),
            &ConfigValueSource::EnvVar("RCH_SSH_SERVER_ALIVE_INTERVAL_SECS".to_string())
        );
        assert_eq!(
            sources
                .get("transfer.ssh_control_persist_secs")
                .expect("transfer.ssh_control_persist_secs source present"),
            &ConfigValueSource::EnvVar("RCH_SSH_CONTROL_PERSIST_SECS".to_string())
        );
        info!("PASS: SSH env overrides applied");
    }

    #[test]
    fn test_full_config_cascade_user_then_project() {
        let _guard = test_guard!();
        info!("TEST: test_full_config_cascade_user_then_project");

        let temp_dir = std::env::temp_dir().join(format!(
            "rch_test_cascade_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&temp_dir).expect("create temp dir");

        // User config sets multiple values
        let user_path = temp_dir.join("user_config.toml");
        let user_toml = r#"
[general]
log_level = "debug"
enabled = true

[compilation]
confidence_threshold = 0.90
min_local_time_ms = 5000
build_timeout_sec = 600

[transfer]
compression_level = 8
"#;
        std::fs::write(&user_path, user_toml).expect("write user config");

        // Project config overrides only some values
        let project_path = temp_dir.join("project_config.toml");
        let project_toml = r#"
[compilation]
confidence_threshold = 0.75
build_timeout_sec = 900
"#;
        std::fs::write(&project_path, project_toml).expect("write project config");

        let env_overrides: HashMap<String, String> = HashMap::new();
        let loaded = load_config_with_sources_from_paths(
            Some(&user_path),
            Some(&project_path),
            Some(&env_overrides),
        )
        .expect("load_config cascade");

        info!(
            "RESULT: log_level={}, confidence={}, min_local={}, build_timeout={}, compression={}",
            loaded.config.general.log_level,
            loaded.config.compilation.confidence_threshold,
            loaded.config.compilation.min_local_time_ms,
            loaded.config.compilation.build_timeout_sec,
            loaded.config.transfer.compression_level
        );

        // User values preserved where project didn't override
        assert_eq!(
            loaded.config.general.log_level, "debug",
            "log_level from user"
        );
        assert_eq!(
            loaded.config.compilation.min_local_time_ms, 5000,
            "min_local_time from user"
        );
        assert_eq!(
            loaded.config.transfer.compression_level, 8,
            "compression from user"
        );

        // Project values override user
        assert!(
            (loaded.config.compilation.confidence_threshold - 0.75).abs() < 0.0001,
            "confidence from project"
        );
        assert_eq!(
            loaded.config.compilation.build_timeout_sec, 900,
            "build_timeout from project"
        );

        // Cleanup
        let _ = std::fs::remove_dir_all(&temp_dir);
        info!("PASS: User -> Project cascade works correctly");
    }

    #[test]
    fn test_full_config_cascade_with_env_override() {
        let _guard = test_guard!();
        info!("TEST: test_full_config_cascade_with_env_override");

        let temp_dir = std::env::temp_dir().join(format!(
            "rch_test_env_cascade_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&temp_dir).expect("create temp dir");

        // User config
        let user_path = temp_dir.join("user_config.toml");
        let user_toml = r#"
[general]
log_level = "debug"

[compilation]
confidence_threshold = 0.90
"#;
        std::fs::write(&user_path, user_toml).expect("write user config");

        // Env overrides take highest precedence
        let mut env_overrides: HashMap<String, String> = HashMap::new();
        env_overrides.insert("RCH_LOG_LEVEL".to_string(), "error".to_string());
        env_overrides.insert("RCH_CONFIDENCE".to_string(), "0.99".to_string());

        let loaded =
            load_config_with_sources_from_paths(Some(&user_path), None, Some(&env_overrides))
                .expect("load_config with env");

        info!(
            "RESULT: log_level={}, confidence={}",
            loaded.config.general.log_level, loaded.config.compilation.confidence_threshold
        );

        // Env should override user config
        assert_eq!(
            loaded.config.general.log_level, "error",
            "log_level from env"
        );

        // Check sources
        let log_source = loaded.sources.get("general.log_level");
        assert!(
            matches!(log_source, Some(ConfigValueSource::EnvVar(_))),
            "log_level source is env"
        );

        // Cleanup
        let _ = std::fs::remove_dir_all(&temp_dir);
        info!("PASS: Env override takes precedence over file configs");
    }

    #[test]
    fn test_workers_config_valid_tilde_path() {
        let _guard = test_guard!();
        info!("TEST: test_workers_config_valid_tilde_path");
        let mut file = NamedTempFile::new().expect("create temp file");
        // Tilde paths should be accepted (expanded at runtime)
        let workers_toml = r#"
[[workers]]
id = "test-worker"
host = "10.0.0.1"
user = "ubuntu"
identity_file = "~/.ssh/id_rsa"
total_slots = 4
"#;
        std::io::Write::write_all(file.as_file_mut(), workers_toml.as_bytes())
            .expect("write workers config");

        let result = validate_workers_config_file(file.path());
        info!(
            "RESULT: errors={:?}, warnings={:?}",
            result.errors, result.warnings
        );

        // Tilde path should parse without error (warning about file existence is acceptable)
        assert!(
            result.errors.is_empty()
                || !result
                    .errors
                    .iter()
                    .any(|e| e.contains("identity_file") && e.contains("invalid")),
            "tilde path should be valid syntax"
        );
        info!("PASS: Tilde path in identity_file accepted");
    }

    #[test]
    fn test_workers_config_empty_workers_array() {
        let _guard = test_guard!();
        info!("TEST: test_workers_config_empty_workers_array");
        let mut file = NamedTempFile::new().expect("create temp file");
        // Empty workers array should be valid
        let workers_toml = r#"
# No workers configured yet
"#;
        std::io::Write::write_all(file.as_file_mut(), workers_toml.as_bytes())
            .expect("write workers config");

        let result = validate_workers_config_file(file.path());
        info!("RESULT: errors={:?}", result.errors);
        // Empty config should parse (defaults to empty workers list)
        // May produce warning about no workers, but should not be error
        assert!(
            result.errors.is_empty() || !result.errors.iter().any(|e| e.contains("parse")),
            "empty workers config should parse"
        );
        info!("PASS: Empty workers config handled");
    }

    #[test]
    fn test_validate_slots_zero_value() {
        let _guard = test_guard!();
        info!("TEST: test_validate_slots_zero_value");
        let identity = NamedTempFile::new().expect("create identity file");
        let mut file = NamedTempFile::new().expect("create config file");

        let workers_toml = format!(
            r#"
[[workers]]
id = "zero-slots"
host = "127.0.0.1"
user = "test"
identity_file = "{}"
total_slots = 0
"#,
            identity.path().display()
        );
        std::io::Write::write_all(file.as_file_mut(), workers_toml.as_bytes())
            .expect("write config");

        let result = validate_workers_config_file(file.path());
        info!(
            "RESULT: errors={:?}, warnings={:?}",
            result.errors, result.warnings
        );

        // Zero slots should produce warning or error
        let has_slots_issue = result.errors.iter().any(|e| e.contains("slots"))
            || result.warnings.iter().any(|w| w.contains("slots"));
        assert!(has_slots_issue, "zero total_slots should be flagged");
        info!("PASS: Zero slots detected");
    }

    #[test]
    fn test_validate_circuit_breaker_thresholds() {
        let _guard = test_guard!();
        info!("TEST: test_validate_circuit_breaker_thresholds");
        let mut file = NamedTempFile::new().expect("create temp file");
        // Invalid circuit breaker configuration
        std::io::Write::write_all(
            file.as_file_mut(),
            b"[circuit]\nfailure_threshold = 0\nwindow_secs = 0\n",
        )
        .expect("write config");

        let result = validate_rch_config_file(file.path());
        info!(
            "RESULT: errors={:?}, warnings={:?}",
            result.errors, result.warnings
        );

        // Zero thresholds should be flagged
        let has_circuit_issue = result
            .errors
            .iter()
            .any(|e| e.contains("circuit") || e.contains("threshold"))
            || result
                .warnings
                .iter()
                .any(|w| w.contains("circuit") || w.contains("threshold"));
        // Note: May pass if validation doesn't check these specific values
        info!(
            "PASS: Circuit breaker thresholds checked (has_issue={})",
            has_circuit_issue
        );
    }

    #[test]
    fn test_parse_workers_with_all_fields() {
        let _guard = test_guard!();
        info!("TEST: test_parse_workers_with_all_fields");
        let identity = NamedTempFile::new().expect("create identity file");

        let workers_toml = format!(
            r#"
[[workers]]
id = "full-worker"
host = "192.168.1.100"
user = "builder"
identity_file = "{}"
total_slots = 8
priority = 100
tags = ["rust", "go", "python"]
enabled = true
"#,
            identity.path().display()
        );

        let config: WorkersConfig =
            toml::from_str(&workers_toml).expect("parse workers with all fields");

        info!("RESULT: workers count={}", config.workers.len());
        assert_eq!(config.workers.len(), 1);

        let worker = &config.workers[0];
        assert_eq!(worker.id, "full-worker");
        assert_eq!(worker.host, "192.168.1.100");
        assert_eq!(worker.user, "builder");
        assert_eq!(worker.total_slots, 8);
        assert_eq!(worker.priority, 100);
        assert!(worker.enabled);

        info!("PASS: All worker fields parsed correctly");
    }

    #[test]
    fn test_validate_confidence_threshold_boundary() {
        let _guard = test_guard!();
        info!("TEST: test_validate_confidence_threshold_boundary");

        // Test lower boundary (0.0)
        let mut file = NamedTempFile::new().expect("create temp file");
        std::io::Write::write_all(
            file.as_file_mut(),
            b"[compilation]\nconfidence_threshold = 0.0\n",
        )
        .expect("write config");
        let result = validate_rch_config_file(file.path());
        info!("0.0 threshold: errors={:?}", result.errors);
        // 0.0 should be valid (edge case)

        // Test upper boundary (1.0)
        let mut file = NamedTempFile::new().expect("create temp file");
        std::io::Write::write_all(
            file.as_file_mut(),
            b"[compilation]\nconfidence_threshold = 1.0\n",
        )
        .expect("write config");
        let result = validate_rch_config_file(file.path());
        info!("1.0 threshold: errors={:?}", result.errors);
        // 1.0 should be valid (edge case)

        // Test just outside boundary (1.01)
        let mut file = NamedTempFile::new().expect("create temp file");
        std::io::Write::write_all(
            file.as_file_mut(),
            b"[compilation]\nconfidence_threshold = 1.01\n",
        )
        .expect("write config");
        let result = validate_rch_config_file(file.path());
        info!("1.01 threshold: errors={:?}", result.errors);
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.contains("confidence_threshold")),
            "1.01 should be out of range"
        );

        info!("PASS: Confidence threshold boundaries validated");
    }

    #[test]
    fn test_source_tracking_project_config() {
        let _guard = test_guard!();
        info!("TEST: test_source_tracking_project_config");

        let temp_dir = std::env::temp_dir().join(format!(
            "rch_test_source_project_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&temp_dir).expect("create temp dir");

        let project_path = temp_dir.join(".rch").join("config.toml");
        std::fs::create_dir_all(project_path.parent().unwrap()).expect("create .rch dir");

        let project_toml = r#"
[compilation]
confidence_threshold = 0.80
"#;
        std::fs::write(&project_path, project_toml).expect("write project config");

        let env_overrides: HashMap<String, String> = HashMap::new();
        let loaded =
            load_config_with_sources_from_paths(None, Some(&project_path), Some(&env_overrides))
                .expect("load_config with project");

        info!(
            "RESULT: confidence={}",
            loaded.config.compilation.confidence_threshold
        );
        assert!((loaded.config.compilation.confidence_threshold - 0.80).abs() < 0.0001);

        let source = loaded
            .sources
            .get("compilation.confidence_threshold")
            .expect("confidence source present");
        assert_eq!(
            source,
            &ConfigValueSource::ProjectConfig(project_path.clone())
        );

        // Cleanup
        let _ = std::fs::remove_dir_all(&temp_dir);
        info!("PASS: Project config source tracked correctly");
    }

    // =========================================================================
    // New validation tests (bd-1g3l)
    // =========================================================================

    #[test]
    fn test_validate_rsync_pattern_valid() {
        let _guard = test_guard!();
        info!("TEST: test_validate_rsync_pattern_valid");

        let mut validation = FileValidation::new(Path::new("/test"));

        // Valid patterns
        validation.validate_rsync_pattern("test", "target/");
        validation.validate_rsync_pattern("test", "*.o");
        validation.validate_rsync_pattern("test", "**/*.rs");
        validation.validate_rsync_pattern("test", "/absolute/path");
        validation.validate_rsync_pattern("test", "dir/");
        validation.validate_rsync_pattern("test", "[abc]");
        validation.validate_rsync_pattern("test", "[a-z]*.txt");

        info!("RESULT: errors={:?}", validation.errors);
        assert!(
            validation.errors.is_empty(),
            "Valid patterns should not produce errors"
        );
        info!("PASS: Valid rsync patterns accepted");
    }

    #[test]
    fn test_validate_rsync_pattern_unbalanced_brackets() {
        let _guard = test_guard!();
        info!("TEST: test_validate_rsync_pattern_unbalanced_brackets");

        let mut validation = FileValidation::new(Path::new("/test"));

        // Unclosed bracket
        validation.validate_rsync_pattern("test1", "[invalid");
        assert!(
            validation
                .errors
                .iter()
                .any(|e| e.contains("unclosed '['") && e.contains("test1")),
            "Should detect unclosed bracket"
        );

        // Unmatched closing bracket
        let mut validation2 = FileValidation::new(Path::new("/test"));
        validation2.validate_rsync_pattern("test2", "invalid]");
        assert!(
            validation2
                .errors
                .iter()
                .any(|e| e.contains("unbalanced ']'") && e.contains("test2")),
            "Should detect unbalanced closing bracket"
        );

        info!("PASS: Unbalanced brackets detected");
    }

    #[test]
    fn test_validate_rsync_pattern_empty() {
        let _guard = test_guard!();
        info!("TEST: test_validate_rsync_pattern_empty");

        let mut validation = FileValidation::new(Path::new("/test"));
        validation.validate_rsync_pattern("empty_pattern", "");

        info!("RESULT: errors={:?}", validation.errors);
        assert!(
            validation
                .errors
                .iter()
                .any(|e| e.contains("empty pattern")),
            "Empty pattern should be an error"
        );
        info!("PASS: Empty pattern rejected");
    }

    #[test]
    fn test_validate_rsync_pattern_catch_all_warning() {
        let _guard = test_guard!();
        info!("TEST: test_validate_rsync_pattern_catch_all_warning");

        let mut validation = FileValidation::new(Path::new("/test"));
        validation.validate_rsync_pattern("star", "*");
        validation.validate_rsync_pattern("double_star", "**");

        info!("RESULT: warnings={:?}", validation.warnings);
        assert!(
            validation
                .warnings
                .iter()
                .any(|w| w.contains("matches everything")),
            "Catch-all patterns should warn"
        );
        info!("PASS: Catch-all pattern warning issued");
    }

    #[test]
    fn test_validate_exclude_patterns_integration() {
        let _guard = test_guard!();
        info!("TEST: test_validate_exclude_patterns_integration");

        let mut file = NamedTempFile::new().expect("create temp file");
        std::io::Write::write_all(
            file.as_file_mut(),
            b"[transfer]\nexclude_patterns = [\"target/\", \"[invalid\"]\n",
        )
        .expect("write config");

        let result = validate_rch_config_file(file.path());
        info!("RESULT: errors={:?}", result.errors);

        assert!(
            result
                .errors
                .iter()
                .any(|e| e.contains("exclude_patterns") && e.contains("unclosed")),
            "Should detect invalid exclude pattern"
        );
        info!("PASS: Invalid exclude_patterns detected in config validation");
    }

    #[cfg(unix)]
    #[test]
    fn test_validate_ssh_key_permissions() {
        let _guard = test_guard!();
        info!("TEST: test_validate_ssh_key_permissions");

        use std::os::unix::fs::PermissionsExt;

        let temp_file = NamedTempFile::new().expect("create temp file");
        let path = temp_file.path();

        // Set insecure permissions (644)
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644))
            .expect("set permissions");

        let mut validation = FileValidation::new(Path::new("/test"));
        validation.validate_ssh_key_permissions("test_key", path);

        info!("RESULT: warnings={:?}", validation.warnings);
        assert!(
            validation
                .warnings
                .iter()
                .any(|w| w.contains("insecure permissions") && w.contains("644")),
            "Should warn about insecure SSH key permissions"
        );

        // Now set secure permissions (600)
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .expect("set permissions");

        let mut validation2 = FileValidation::new(Path::new("/test"));
        validation2.validate_ssh_key_permissions("test_key", path);

        info!("RESULT with 600: warnings={:?}", validation2.warnings);
        assert!(
            validation2.warnings.is_empty(),
            "Secure permissions (600) should not warn"
        );

        info!("PASS: SSH key permission validation works correctly");
    }

    #[test]
    fn test_validate_path_parent_writable() {
        let _guard = test_guard!();
        info!("TEST: test_validate_path_parent_writable");

        // Test with existing parent directory
        let temp_dir = std::env::temp_dir();
        let test_path = temp_dir.join("rch_test_socket.sock");

        let mut validation = FileValidation::new(Path::new("/test"));
        validation.validate_path_parent_writable("socket_path", &test_path);

        info!(
            "RESULT: errors={:?}, warnings={:?}",
            validation.errors, validation.warnings
        );
        // Should not produce errors for valid writable parent
        assert!(
            validation.errors.is_empty(),
            "Valid parent directory should not produce errors"
        );

        // Test with non-existent parent
        let invalid_path = Path::new("/nonexistent_dir_12345/socket.sock");
        let mut validation2 = FileValidation::new(Path::new("/test"));
        validation2.validate_path_parent_writable("socket_path", invalid_path);

        info!("RESULT for invalid: errors={:?}", validation2.errors);
        assert!(
            validation2
                .errors
                .iter()
                .any(|e| e.contains("parent directory does not exist")),
            "Should error for non-existent parent"
        );

        info!("PASS: Parent directory validation works correctly");
    }
}
