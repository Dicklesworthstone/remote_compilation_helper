//! Configuration loading for RCH.

use anyhow::{Context, Result};
use directories::ProjectDirs;
use rch_common::{
    ConfigValueSource, OutputVisibility, RchConfig, SelfTestFailureAction, SelfTestWorkers,
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
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
    circuit: PartialCircuitConfig,
    #[serde(default)]
    output: PartialOutputConfig,
    #[serde(default)]
    self_test: PartialSelfTestConfig,
}

#[derive(Debug, Default, Deserialize)]
struct PartialGeneralConfig {
    enabled: Option<bool>,
    log_level: Option<String>,
    socket_path: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct PartialCompilationConfig {
    confidence_threshold: Option<f64>,
    min_local_time_ms: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
struct PartialTransferConfig {
    compression_level: Option<u32>,
    exclude_patterns: Option<Vec<String>>,
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
        debug!("Loading user config with sources from {:?}", path);
        let layer = load_partial_config(path)?;
        apply_layer(
            &mut config,
            &mut sources,
            &layer,
            &ConfigValueSource::UserConfig(path.to_path_buf()),
            &defaults,
        );
    }

    if let Some(path) = project_path {
        debug!("Loading project config with sources from {:?}", path);
        let layer = load_partial_config(path)?;
        apply_layer(
            &mut config,
            &mut sources,
            &layer,
            &ConfigValueSource::ProjectConfig(path.to_path_buf()),
            &defaults,
        );
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

    if config.transfer.compression_level > 19 {
        validation.warn("transfer.compression_level should be within [1, 19]".to_string());
    } else if config.transfer.compression_level == 0 {
        validation.warn("transfer.compression_level is 0 (compression disabled)".to_string());
    }

    if config.general.socket_path.trim().is_empty() {
        validation.error("general.socket_path cannot be empty".to_string());
    } else {
        let expanded = shellexpand::tilde(&config.general.socket_path);
        let socket_path = Path::new(expanded.as_ref());
        if !socket_path.exists() {
            validation.warn(format!(
                "general.socket_path does not exist: {}",
                socket_path.display()
            ));
        }
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
        "general.log_level",
        "general.socket_path",
        "compilation.confidence_threshold",
        "compilation.min_local_time_ms",
        "transfer.compression_level",
        "transfer.exclude_patterns",
        "circuit.failure_threshold",
        "circuit.success_threshold",
        "circuit.error_rate_threshold",
        "circuit.window_secs",
        "circuit.open_cooldown_secs",
        "circuit.half_open_max_probes",
        "output.visibility",
        "output.first_run_complete",
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

    if let Some(enabled) = layer.general.enabled {
        if enabled != defaults.general.enabled {
            config.general.enabled = enabled;
            set_source(sources, "general.enabled", source.clone());
        }
    }
    if let Some(log_level) = layer.general.log_level.as_ref() {
        if log_level != &defaults.general.log_level {
            config.general.log_level = log_level.clone();
            set_source(sources, "general.log_level", source.clone());
        }
    }
    if let Some(socket_path) = layer.general.socket_path.as_ref() {
        if socket_path != &defaults.general.socket_path {
            config.general.socket_path = socket_path.clone();
            set_source(sources, "general.socket_path", source.clone());
        }
    }

    if let Some(threshold) = layer.compilation.confidence_threshold {
        if (threshold - defaults.compilation.confidence_threshold).abs() > EPSILON {
            config.compilation.confidence_threshold = threshold;
            set_source(sources, "compilation.confidence_threshold", source.clone());
        }
    }
    if let Some(min_local) = layer.compilation.min_local_time_ms {
        if min_local != defaults.compilation.min_local_time_ms {
            config.compilation.min_local_time_ms = min_local;
            set_source(sources, "compilation.min_local_time_ms", source.clone());
        }
    }

    if let Some(compression) = layer.transfer.compression_level {
        if compression != defaults.transfer.compression_level {
            config.transfer.compression_level = compression;
            set_source(sources, "transfer.compression_level", source.clone());
        }
    }
    if let Some(patterns) = layer.transfer.exclude_patterns.as_ref() {
        if patterns != &defaults.transfer.exclude_patterns {
            config.transfer.exclude_patterns = patterns.clone();
            set_source(sources, "transfer.exclude_patterns", source.clone());
        }
    }

    if let Some(failure_threshold) = layer.circuit.failure_threshold {
        if failure_threshold != defaults.circuit.failure_threshold {
            config.circuit.failure_threshold = failure_threshold;
            set_source(sources, "circuit.failure_threshold", source.clone());
        }
    }
    if let Some(success_threshold) = layer.circuit.success_threshold {
        if success_threshold != defaults.circuit.success_threshold {
            config.circuit.success_threshold = success_threshold;
            set_source(sources, "circuit.success_threshold", source.clone());
        }
    }
    if let Some(error_rate_threshold) = layer.circuit.error_rate_threshold {
        if (error_rate_threshold - defaults.circuit.error_rate_threshold).abs() > EPSILON {
            config.circuit.error_rate_threshold = error_rate_threshold;
            set_source(sources, "circuit.error_rate_threshold", source.clone());
        }
    }
    if let Some(window_secs) = layer.circuit.window_secs {
        if window_secs != defaults.circuit.window_secs {
            config.circuit.window_secs = window_secs;
            set_source(sources, "circuit.window_secs", source.clone());
        }
    }
    if let Some(open_cooldown_secs) = layer.circuit.open_cooldown_secs {
        if open_cooldown_secs != defaults.circuit.open_cooldown_secs {
            config.circuit.open_cooldown_secs = open_cooldown_secs;
            set_source(sources, "circuit.open_cooldown_secs", source.clone());
        }
    }
    if let Some(half_open_max_probes) = layer.circuit.half_open_max_probes {
        if half_open_max_probes != defaults.circuit.half_open_max_probes {
            config.circuit.half_open_max_probes = half_open_max_probes;
            set_source(sources, "circuit.half_open_max_probes", source.clone());
        }
    }

    if let Some(visibility) = layer.output.visibility {
        if visibility != defaults.output.visibility {
            config.output.visibility = visibility;
            set_source(sources, "output.visibility", source.clone());
        }
    }
    if let Some(first_run_complete) = layer.output.first_run_complete {
        if first_run_complete != defaults.output.first_run_complete {
            config.output.first_run_complete = first_run_complete;
            set_source(sources, "output.first_run_complete", source.clone());
        }
    }

    if let Some(enabled) = layer.self_test.enabled {
        if enabled != defaults.self_test.enabled {
            config.self_test.enabled = enabled;
            set_source(sources, "self_test.enabled", source.clone());
        }
    }
    if let Some(schedule) = layer.self_test.schedule.as_ref() {
        if defaults.self_test.schedule.as_ref() != Some(schedule) {
            config.self_test.schedule = Some(schedule.clone());
            set_source(sources, "self_test.schedule", source.clone());
        }
    }
    if let Some(interval) = layer.self_test.interval.as_ref() {
        if defaults.self_test.interval.as_ref() != Some(interval) {
            config.self_test.interval = Some(interval.clone());
            set_source(sources, "self_test.interval", source.clone());
        }
    }
    if let Some(workers) = layer.self_test.workers.as_ref() {
        if workers != &defaults.self_test.workers {
            config.self_test.workers = workers.clone();
            set_source(sources, "self_test.workers", source.clone());
        }
    }
    if let Some(on_failure) = layer.self_test.on_failure {
        if on_failure != defaults.self_test.on_failure {
            config.self_test.on_failure = on_failure;
            set_source(sources, "self_test.on_failure", source.clone());
        }
    }
    if let Some(retry_count) = layer.self_test.retry_count {
        if retry_count != defaults.self_test.retry_count {
            config.self_test.retry_count = retry_count;
            set_source(sources, "self_test.retry_count", source.clone());
        }
    }
    if let Some(retry_delay) = layer.self_test.retry_delay.as_ref() {
        if defaults.self_test.retry_delay != *retry_delay {
            config.self_test.retry_delay = retry_delay.clone();
            set_source(sources, "self_test.retry_delay", source.clone());
        }
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

    // Merge circuit breaker section
    merge_circuit(&mut base.circuit, &overlay.circuit, &default.circuit);

    // Merge output section
    merge_output(&mut base.output, &overlay.output, &default.output);

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

    if let Some(val) = get_env("RCH_ENABLED") {
        config.general.enabled = val.parse().unwrap_or(true);
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

    if let Some(val) = get_env("RCH_CONFIDENCE_THRESHOLD") {
        if let Ok(threshold) = val.parse() {
            config.compilation.confidence_threshold = threshold;
            if let Some(ref mut sources) = sources {
                set_source(
                    sources,
                    "compilation.confidence_threshold",
                    ConfigValueSource::EnvVar("RCH_CONFIDENCE_THRESHOLD".to_string()),
                );
            }
        }
    }

    if let Some(val) = get_env("RCH_COMPRESSION") {
        if let Ok(level) = val.parse() {
            config.transfer.compression_level = level;
            if let Some(ref mut sources) = sources {
                set_source(
                    sources,
                    "transfer.compression_level",
                    ConfigValueSource::EnvVar("RCH_COMPRESSION".to_string()),
                );
            }
        }
    }

    let mut visibility_override: Option<(OutputVisibility, String)> = None;

    if let Some(val) = get_env("RCH_QUIET") {
        if parse_bool(&val).unwrap_or(false) {
            visibility_override = Some((OutputVisibility::None, "RCH_QUIET".to_string()));
        }
    }

    if visibility_override.is_none() {
        if let Some(val) = get_env("RCH_VISIBILITY") {
            if let Ok(mode) = val.parse::<OutputVisibility>() {
                visibility_override = Some((mode, "RCH_VISIBILITY".to_string()));
            }
        }
    }

    if visibility_override.is_none() {
        if let Some(val) = get_env("RCH_VERBOSE") {
            if parse_bool(&val).unwrap_or(false) {
                visibility_override = Some((OutputVisibility::Verbose, "RCH_VERBOSE".to_string()));
            }
        }
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

    anyhow::bail!("Config file is not valid RCH or workers configuration")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;
    use tracing::info;

    #[test]
    fn test_default_config() {
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
        info!("TEST: test_example_project_config_valid");
        let toml_str = example_project_config();
        let _: RchConfig = toml::from_str(&toml_str).expect("Example project config should parse");
        info!("PASS: Example project config parses successfully");
    }

    #[test]
    fn test_example_workers_config_valid() {
        info!("TEST: test_example_workers_config_valid");
        let toml_str = example_workers_config();
        let _: WorkersConfig =
            toml::from_str(&toml_str).expect("Example workers config should parse");
        info!("PASS: Example workers config parses successfully");
    }

    #[test]
    fn test_validate_valid_config() {
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
    fn test_validate_invalid_toml_syntax() {
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
    fn test_validate_file_path_exists() {
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
    fn test_merge_preserves_base_fields() {
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
    fn test_merge_boolean_enabled_field() {
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
        info!("TEST: test_apply_env_overrides_enabled_false");
        let mut config = RchConfig::default();
        let mut sources = default_sources_map();
        let mut env_overrides: HashMap<String, String> = HashMap::new();
        env_overrides.insert("RCH_ENABLED".to_string(), "false".to_string());

        apply_env_overrides_inner(&mut config, Some(&mut sources), Some(&env_overrides));

        info!("RESULT: enabled={}", config.general.enabled);
        assert!(
            !config.general.enabled,
            "expected RCH_ENABLED=false to disable"
        );
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
    fn test_validate_workers_duplicate_ids() {
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
}
