//! Configuration command implementations.

use anyhow::{Context, Result};
use rch_common::{ApiResponse, ConfigValueSource, RchConfig};
use std::path::{Path, PathBuf};

use crate::error::{ConfigError, EditorError};
use crate::ui::context::OutputContext;
use crate::ui::theme::StatusIndicator;
use crate::{config, ui};

use super::helpers::{config_dir, load_workers_from_config};
use super::types::{
    ConfigCircuitSection, ConfigCompilationSection, ConfigDiffEntry, ConfigDiffResponse,
    ConfigEnvironmentSection, ConfigGeneralSection, ConfigGetResponse, ConfigLintResponse,
    ConfigOutputSection, ConfigResetResponse, ConfigSelfHealingSection, ConfigSetResponse,
    ConfigShowResponse, ConfigTransferSection, ConfigValidationIssue, ConfigValidationResponse,
    ConfigValueSourceInfo, LintIssue, LintSeverity,
};

fn print_file_validation(
    label: &str,
    validations: &[config::FileValidation],
    style: &ui::theme::Theme,
    path: &Path,
) {
    let Some(validation) = validations.iter().find(|v| v.file == path) else {
        return;
    };

    if validation.errors.is_empty() && validation.warnings.is_empty() {
        println!(
            "{} {}: {}",
            StatusIndicator::Success.display(style),
            style.highlight(label),
            style.success("Valid")
        );
        return;
    }

    if validation.errors.is_empty() {
        println!(
            "{} {}: {}",
            StatusIndicator::Warning.display(style),
            style.highlight(label),
            style.warning("Valid (warnings)")
        );
    } else {
        println!(
            "{} {}: {}",
            StatusIndicator::Error.display(style),
            style.highlight(label),
            style.error("Invalid")
        );
    }

    for warning in &validation.warnings {
        println!(
            "  {} {}",
            StatusIndicator::Warning.display(style),
            style.muted(warning)
        );
    }
}

// =============================================================================
// Config Commands
// =============================================================================

/// Show effective configuration.
pub fn config_show(show_sources: bool, ctx: &OutputContext) -> Result<()> {
    let style = ctx.theme();

    // Load config (with source tracking when requested)
    let loaded = if show_sources {
        Some(config::load_config_with_sources()?)
    } else {
        None
    };
    let config = if let Some(loaded) = &loaded {
        loaded.config.clone()
    } else {
        config::load_config()?
    };

    // Build sources list
    let mut sources = vec![
        "Environment variables (RCH_*)".to_string(),
        "Project config: .rch/config.toml".to_string(),
    ];
    if let Some(dir) = config_dir() {
        sources.push(format!(
            "User config: {}",
            dir.join("config.toml").display()
        ));
    }
    sources.push("Built-in defaults".to_string());

    // Determine source for each value
    let value_sources = if show_sources {
        let sources = loaded
            .as_ref()
            .map(|loaded| &loaded.sources)
            .expect("sources available when show_sources is true");
        Some(collect_value_sources(&config, sources))
    } else {
        None
    };

    // JSON output mode
    if ctx.is_json() {
        let response = ConfigShowResponse {
            general: ConfigGeneralSection {
                enabled: config.general.enabled,
                force_local: config.general.force_local,
                force_remote: config.general.force_remote,
                log_level: config.general.log_level.clone(),
                socket_path: config.general.socket_path.clone(),
            },
            compilation: ConfigCompilationSection {
                confidence_threshold: config.compilation.confidence_threshold,
                min_local_time_ms: config.compilation.min_local_time_ms,
            },
            transfer: ConfigTransferSection {
                compression_level: config.transfer.compression_level,
                exclude_patterns: config.transfer.exclude_patterns.clone(),
                remote_base: config.transfer.remote_base.clone(),
                // Transfer optimization (bd-3hho)
                max_transfer_mb: config.transfer.max_transfer_mb,
                max_transfer_time_ms: config.transfer.max_transfer_time_ms,
                bwlimit_kbps: config.transfer.bwlimit_kbps,
                estimated_bandwidth_bps: config.transfer.estimated_bandwidth_bps,
                // Adaptive compression (bd-243w)
                adaptive_compression: config.transfer.adaptive_compression,
                min_compression_level: config.transfer.min_compression_level,
                max_compression_level: config.transfer.max_compression_level,
                // Artifact verification (bd-377q)
                verify_artifacts: config.transfer.verify_artifacts,
                verify_max_size_bytes: config.transfer.verify_max_size_bytes,
            },
            environment: ConfigEnvironmentSection {
                allowlist: config.environment.allowlist.clone(),
            },
            circuit: ConfigCircuitSection {
                failure_threshold: config.circuit.failure_threshold,
                success_threshold: config.circuit.success_threshold,
                error_rate_threshold: config.circuit.error_rate_threshold,
                window_secs: config.circuit.window_secs,
                open_cooldown_secs: config.circuit.open_cooldown_secs,
                half_open_max_probes: config.circuit.half_open_max_probes,
            },
            output: ConfigOutputSection {
                visibility: config.output.visibility,
                first_run_complete: config.output.first_run_complete,
            },
            self_healing: ConfigSelfHealingSection {
                hook_starts_daemon: config.self_healing.hook_starts_daemon,
                daemon_installs_hooks: config.self_healing.daemon_installs_hooks,
                auto_start_cooldown_secs: config.self_healing.auto_start_cooldown_secs,
                auto_start_timeout_secs: config.self_healing.auto_start_timeout_secs,
            },
            sources,
            value_sources,
        };
        let _ = ctx.json(&ApiResponse::ok("config show", response));
        return Ok(());
    }

    println!("{}", style.format_header("Effective RCH Configuration"));
    println!();

    // Helper closure to format value with source
    let format_with_source =
        |key: &str, value: &str, sources: &Option<Vec<ConfigValueSourceInfo>>| -> String {
            if let Some(vs) = sources
                && let Some(s) = vs.iter().find(|v| v.key == key)
            {
                return format!("{} {}", value, style.muted(&format!("# from {}", s.source)));
            }
            value.to_string()
        };

    println!("{}", style.highlight("[general]"));
    println!(
        "  {} = {}",
        style.key("enabled"),
        format_with_source(
            "general.enabled",
            &style.value(&config.general.enabled.to_string()),
            &value_sources
        )
    );
    println!(
        "  {} = {}",
        style.key("force_local"),
        format_with_source(
            "general.force_local",
            &style.value(&config.general.force_local.to_string()),
            &value_sources
        )
    );
    println!(
        "  {} = {}",
        style.key("force_remote"),
        format_with_source(
            "general.force_remote",
            &style.value(&config.general.force_remote.to_string()),
            &value_sources
        )
    );
    println!(
        "  {} = {}",
        style.key("log_level"),
        format_with_source(
            "general.log_level",
            &style.value(&format!("\"{}\"", config.general.log_level)),
            &value_sources
        )
    );
    println!(
        "  {} = {}",
        style.key("socket_path"),
        format_with_source(
            "general.socket_path",
            &style.value(&format!("\"{}\"", config.general.socket_path)),
            &value_sources
        )
    );

    println!("\n{}", style.highlight("[compilation]"));
    println!(
        "  {} = {}",
        style.key("confidence_threshold"),
        format_with_source(
            "compilation.confidence_threshold",
            &style.value(&config.compilation.confidence_threshold.to_string()),
            &value_sources
        )
    );
    println!(
        "  {} = {}",
        style.key("min_local_time_ms"),
        format_with_source(
            "compilation.min_local_time_ms",
            &style.value(&config.compilation.min_local_time_ms.to_string()),
            &value_sources
        )
    );

    println!("\n{}", style.highlight("[transfer]"));
    println!(
        "  {} = {}",
        style.key("compression_level"),
        format_with_source(
            "transfer.compression_level",
            &style.value(&config.transfer.compression_level.to_string()),
            &value_sources
        )
    );
    let exclude_source = source_label("transfer.exclude_patterns", &value_sources);
    if let Some(source) = exclude_source {
        println!(
            "  {} = [ {}",
            style.key("exclude_patterns"),
            style.muted(&format!("# from {}", source))
        );
    } else {
        println!("  {} = [", style.key("exclude_patterns"));
    }
    for pattern in &config.transfer.exclude_patterns {
        println!("    {},", style.value(&format!("\"{}\"", pattern)));
    }
    println!("  ]");
    println!(
        "  {} = {}",
        style.key("remote_base"),
        format_with_source(
            "transfer.remote_base",
            &style.value(&format!("\"{}\"", config.transfer.remote_base)),
            &value_sources
        )
    );

    println!("\n{}", style.highlight("[environment]"));
    let allowlist_source = source_label("environment.allowlist", &value_sources);
    if let Some(source) = allowlist_source {
        println!(
            "  {} = [ {}",
            style.key("allowlist"),
            style.muted(&format!("# from {}", source))
        );
    } else {
        println!("  {} = [", style.key("allowlist"));
    }
    for key in &config.environment.allowlist {
        println!("    {},", style.value(&format!("\"{}\"", key)));
    }
    println!("  ]");

    println!("\n{}", style.highlight("[circuit]"));
    println!(
        "  {} = {}",
        style.key("failure_threshold"),
        format_with_source(
            "circuit.failure_threshold",
            &style.value(&config.circuit.failure_threshold.to_string()),
            &value_sources
        )
    );
    println!(
        "  {} = {}",
        style.key("success_threshold"),
        format_with_source(
            "circuit.success_threshold",
            &style.value(&config.circuit.success_threshold.to_string()),
            &value_sources
        )
    );
    println!(
        "  {} = {}",
        style.key("error_rate_threshold"),
        format_with_source(
            "circuit.error_rate_threshold",
            &style.value(&config.circuit.error_rate_threshold.to_string()),
            &value_sources
        )
    );
    println!(
        "  {} = {}",
        style.key("window_secs"),
        format_with_source(
            "circuit.window_secs",
            &style.value(&config.circuit.window_secs.to_string()),
            &value_sources
        )
    );
    println!(
        "  {} = {}",
        style.key("open_cooldown_secs"),
        format_with_source(
            "circuit.open_cooldown_secs",
            &style.value(&config.circuit.open_cooldown_secs.to_string()),
            &value_sources
        )
    );
    println!(
        "  {} = {}",
        style.key("half_open_max_probes"),
        format_with_source(
            "circuit.half_open_max_probes",
            &style.value(&config.circuit.half_open_max_probes.to_string()),
            &value_sources
        )
    );

    println!("\n{}", style.highlight("[output]"));
    println!(
        "  {} = {}",
        style.key("visibility"),
        format_with_source(
            "output.visibility",
            &style.value(&config.output.visibility.to_string()),
            &value_sources
        )
    );
    println!(
        "  {} = {}",
        style.key("first_run_complete"),
        format_with_source(
            "output.first_run_complete",
            &style.value(&config.output.first_run_complete.to_string()),
            &value_sources
        )
    );

    println!("\n{}", style.highlight("[self_healing]"));
    println!(
        "  {} = {}",
        style.key("hook_starts_daemon"),
        format_with_source(
            "self_healing.hook_starts_daemon",
            &style.value(&config.self_healing.hook_starts_daemon.to_string()),
            &value_sources
        )
    );
    println!(
        "  {} = {}",
        style.key("daemon_installs_hooks"),
        format_with_source(
            "self_healing.daemon_installs_hooks",
            &style.value(&config.self_healing.daemon_installs_hooks.to_string()),
            &value_sources
        )
    );
    println!(
        "  {} = {}",
        style.key("auto_start_cooldown_secs"),
        format_with_source(
            "self_healing.auto_start_cooldown_secs",
            &style.value(&config.self_healing.auto_start_cooldown_secs.to_string()),
            &value_sources
        )
    );
    println!(
        "  {} = {}",
        style.key("auto_start_timeout_secs"),
        format_with_source(
            "self_healing.auto_start_timeout_secs",
            &style.value(&config.self_healing.auto_start_timeout_secs.to_string()),
            &value_sources
        )
    );

    // Show config file locations
    println!(
        "\n{}",
        style.muted("# Configuration sources (in priority order):")
    );
    println!("{}", style.muted("# 1. Environment variables (RCH_*)"));
    println!("{}", style.muted("# 2. Project config: .rch/config.toml"));
    if let Some(dir) = config_dir() {
        println!(
            "{}",
            style.muted(&format!(
                "# 3. User config: {}",
                dir.join("config.toml").display()
            ))
        );
    }
    println!("{}", style.muted("# 4. Built-in defaults"));

    Ok(())
}

/// Get a single configuration value.
pub fn config_get(key: &str, show_sources: bool, ctx: &OutputContext) -> Result<()> {
    let style = ctx.theme();

    let normalized_key = match key {
        "first_run_complete" => "output.first_run_complete",
        _ => key,
    };

    let loaded = config::load_config_with_sources()?;
    let values = collect_value_sources(&loaded.config, &loaded.sources);
    let entry = values.iter().find(|value| value.key == normalized_key);

    let entry = match entry {
        Some(value) => value,
        None => {
            let supported = values
                .iter()
                .map(|value| value.key.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            return Err(ConfigError::InvalidValue {
                field: key.to_string(),
                reason: "unknown configuration key".to_string(),
                suggestion: format!("Supported keys: {}", supported),
            }
            .into());
        }
    };

    if ctx.is_json() {
        let response = ConfigGetResponse {
            key: entry.key.clone(),
            value: entry.value.clone(),
            source: show_sources.then(|| entry.source.clone()),
        };
        let _ = ctx.json(&ApiResponse::ok("config get", response));
        return Ok(());
    }

    if show_sources {
        println!(
            "{} {} {}",
            style.value(&entry.value),
            style.muted("# from"),
            style.muted(&entry.source)
        );
    } else {
        println!("{}", entry.value);
    }

    Ok(())
}

/// Determine the source of each configuration value using tracked sources.
pub(super) fn collect_value_sources(
    config: &RchConfig,
    sources: &config::ConfigSourceMap,
) -> Vec<ConfigValueSourceInfo> {
    let mut values = Vec::new();

    push_value_source(
        &mut values,
        "general.enabled",
        config.general.enabled.to_string(),
        sources,
    );
    push_value_source(
        &mut values,
        "general.force_local",
        config.general.force_local.to_string(),
        sources,
    );
    push_value_source(
        &mut values,
        "general.force_remote",
        config.general.force_remote.to_string(),
        sources,
    );
    push_value_source(
        &mut values,
        "general.log_level",
        config.general.log_level.clone(),
        sources,
    );
    push_value_source(
        &mut values,
        "general.socket_path",
        config.general.socket_path.clone(),
        sources,
    );
    push_value_source(
        &mut values,
        "compilation.confidence_threshold",
        config.compilation.confidence_threshold.to_string(),
        sources,
    );
    push_value_source(
        &mut values,
        "compilation.min_local_time_ms",
        config.compilation.min_local_time_ms.to_string(),
        sources,
    );
    push_value_source(
        &mut values,
        "transfer.compression_level",
        config.transfer.compression_level.to_string(),
        sources,
    );
    push_value_source(
        &mut values,
        "transfer.exclude_patterns",
        format!("{:?}", config.transfer.exclude_patterns),
        sources,
    );
    push_value_source(
        &mut values,
        "environment.allowlist",
        format!("{:?}", config.environment.allowlist),
        sources,
    );
    push_value_source(
        &mut values,
        "circuit.failure_threshold",
        config.circuit.failure_threshold.to_string(),
        sources,
    );
    push_value_source(
        &mut values,
        "circuit.success_threshold",
        config.circuit.success_threshold.to_string(),
        sources,
    );
    push_value_source(
        &mut values,
        "circuit.error_rate_threshold",
        config.circuit.error_rate_threshold.to_string(),
        sources,
    );
    push_value_source(
        &mut values,
        "circuit.window_secs",
        config.circuit.window_secs.to_string(),
        sources,
    );
    push_value_source(
        &mut values,
        "circuit.open_cooldown_secs",
        config.circuit.open_cooldown_secs.to_string(),
        sources,
    );
    push_value_source(
        &mut values,
        "circuit.half_open_max_probes",
        config.circuit.half_open_max_probes.to_string(),
        sources,
    );
    push_value_source(
        &mut values,
        "output.visibility",
        config.output.visibility.to_string(),
        sources,
    );
    push_value_source(
        &mut values,
        "output.first_run_complete",
        config.output.first_run_complete.to_string(),
        sources,
    );
    push_value_source(
        &mut values,
        "self_healing.hook_starts_daemon",
        config.self_healing.hook_starts_daemon.to_string(),
        sources,
    );
    push_value_source(
        &mut values,
        "self_healing.daemon_installs_hooks",
        config.self_healing.daemon_installs_hooks.to_string(),
        sources,
    );
    push_value_source(
        &mut values,
        "self_healing.auto_start_cooldown_secs",
        config.self_healing.auto_start_cooldown_secs.to_string(),
        sources,
    );
    push_value_source(
        &mut values,
        "self_healing.auto_start_timeout_secs",
        config.self_healing.auto_start_timeout_secs.to_string(),
        sources,
    );

    values
}

fn push_value_source(
    values: &mut Vec<ConfigValueSourceInfo>,
    key: &str,
    value: String,
    sources: &config::ConfigSourceMap,
) {
    let source = sources
        .get(key)
        .map(|s| s.label())
        .unwrap_or_else(|| ConfigValueSource::Default.label());
    values.push(ConfigValueSourceInfo {
        key: key.to_string(),
        value,
        source,
    });
}

fn source_label(key: &str, sources: &Option<Vec<ConfigValueSourceInfo>>) -> Option<String> {
    sources.as_ref().and_then(|values| {
        values
            .iter()
            .find(|v| v.key == key)
            .map(|v| v.source.clone())
    })
}

/// Validate configuration files.
pub fn config_validate(ctx: &OutputContext) -> Result<()> {
    let style = ctx.theme();

    let mut validations: Vec<config::FileValidation> = Vec::new();

    let config_dir = match config_dir() {
        Some(d) => d,
        None => {
            if ctx.is_json() {
                let response = ConfigValidationResponse {
                    errors: vec![ConfigValidationIssue {
                        file: "config".to_string(),
                        message: "Could not determine config directory".to_string(),
                    }],
                    warnings: vec![],
                    valid: false,
                };
                let _ = ctx.json(&ApiResponse::ok("config validate", response));
                std::process::exit(1);
            }
            println!(
                "{} Could not determine config directory",
                StatusIndicator::Error.display(style)
            );
            std::process::exit(1);
        }
    };

    // config.toml
    let config_path = config_dir.join("config.toml");
    if config_path.exists() {
        validations.push(config::validate_rch_config_file(&config_path));
    }

    // workers.toml
    let workers_path = config_dir.join("workers.toml");
    if workers_path.exists() {
        validations.push(config::validate_workers_config_file(&workers_path));
    } else {
        let mut missing = config::FileValidation::new(&workers_path);
        missing.error("workers.toml not found (run `rch config init`)".to_string());
        validations.push(missing);
    }

    // project config
    let project_config = PathBuf::from(".rch/config.toml");
    if project_config.exists() {
        validations.push(config::validate_rch_config_file(&project_config));
    }

    let mut error_items = Vec::new();
    let mut warning_items = Vec::new();
    for validation in &validations {
        for error in &validation.errors {
            error_items.push(ConfigValidationIssue {
                file: validation.file.display().to_string(),
                message: error.clone(),
            });
        }
        for warning in &validation.warnings {
            warning_items.push(ConfigValidationIssue {
                file: validation.file.display().to_string(),
                message: warning.clone(),
            });
        }
    }

    let valid = error_items.is_empty();

    if ctx.is_json() {
        let response = ConfigValidationResponse {
            errors: error_items,
            warnings: warning_items,
            valid,
        };
        let _ = ctx.json(&ApiResponse::ok("config validate", response));
        if !valid {
            std::process::exit(1);
        }
        return Ok(());
    }

    println!("Validating RCH configuration...\n");

    if config_path.exists() {
        print_file_validation("config.toml", &validations, style, &config_path);
    } else {
        println!(
            "{} {}: {} {}",
            style.muted("-"),
            style.highlight("config.toml"),
            style.muted("Not found"),
            style.muted("(using defaults)")
        );
    }

    print_file_validation("workers.toml", &validations, style, &workers_path);

    if project_config.exists() {
        print_file_validation(".rch/config.toml", &validations, style, &project_config);
    }

    println!();
    if !valid {
        println!(
            "{} {} error(s), {} warning(s)",
            style.format_error("Validation failed:"),
            error_items.len(),
            warning_items.len()
        );
        std::process::exit(1);
    } else if !warning_items.is_empty() {
        println!(
            "{} with {} warning(s)",
            style.format_warning("Validation passed"),
            warning_items.len()
        );
    } else {
        println!("{}", style.format_success("Validation passed!"));
    }

    Ok(())
}

/// Set a configuration value.
pub fn config_set(key: &str, value: &str, ctx: &OutputContext) -> Result<()> {
    let config_dir = config_dir().context("Could not determine config directory")?;
    std::fs::create_dir_all(&config_dir)
        .with_context(|| format!("Failed to create config directory: {:?}", config_dir))?;
    let config_path = config_dir.join("config.toml");
    config_set_at(&config_path, key, value, ctx)
}

fn config_set_at(config_path: &Path, key: &str, value: &str, ctx: &OutputContext) -> Result<()> {
    let mut config = if config_path.exists() {
        let contents = std::fs::read_to_string(config_path)
            .with_context(|| format!("Failed to read {:?}", config_path))?;
        toml::from_str::<RchConfig>(&contents)
            .with_context(|| format!("Failed to parse {:?}", config_path))?
    } else {
        RchConfig::default()
    };

    match key {
        "general.enabled" => {
            config.general.enabled = parse_bool(value, key)?;
        }
        "general.force_local" => {
            config.general.force_local = parse_bool(value, key)?;
        }
        "general.force_remote" => {
            config.general.force_remote = parse_bool(value, key)?;
        }
        "general.log_level" => {
            config.general.log_level = value.trim().trim_matches(|c| c == '"').to_string();
        }
        "general.socket_path" => {
            config.general.socket_path = value.trim().trim_matches(|c| c == '"').to_string();
        }
        "compilation.confidence_threshold" => {
            let threshold = parse_f64(value, key)?;
            if !(0.0..=1.0).contains(&threshold) {
                return Err(ConfigError::InvalidValue {
                    field: "compilation.confidence_threshold".to_string(),
                    reason: format!("value {} is out of range", threshold),
                    suggestion: "Use a value between 0.0 and 1.0".to_string(),
                }
                .into());
            }
            config.compilation.confidence_threshold = threshold;
        }
        "compilation.min_local_time_ms" => {
            config.compilation.min_local_time_ms = parse_u64(value, key)?;
        }
        "transfer.compression_level" => {
            let level = parse_u32(value, key)?;
            if level > 19 {
                return Err(ConfigError::InvalidValue {
                    field: "transfer.compression_level".to_string(),
                    reason: format!("value {} exceeds maximum of 19", level),
                    suggestion: "Use a value between 0 and 19".to_string(),
                }
                .into());
            }
            config.transfer.compression_level = level;
        }
        "transfer.exclude_patterns" => {
            config.transfer.exclude_patterns = parse_string_list(value, key)?;
        }
        "environment.allowlist" => {
            config.environment.allowlist = parse_string_list(value, key)?;
        }
        "output.visibility" => {
            let trimmed = value.trim().trim_matches(|c| c == '"');
            let visibility = trimmed
                .parse::<rch_common::OutputVisibility>()
                .map_err(|_| {
                    anyhow::anyhow!("output.visibility must be one of: none, summary, verbose")
                })?;
            config.output.visibility = visibility;
        }
        "output.first_run_complete" | "first_run_complete" => {
            config.output.first_run_complete = parse_bool(value, key)?;
        }
        _ => {
            return Err(ConfigError::InvalidValue {
                field: key.to_string(),
                reason: "unknown configuration key".to_string(),
                suggestion: "Supported keys: general.enabled, general.force_local, general.force_remote, general.log_level, general.socket_path, compilation.confidence_threshold, compilation.min_local_time_ms, transfer.compression_level, transfer.exclude_patterns, environment.allowlist, output.visibility, output.first_run_complete".to_string(),
            }
            .into());
        }
    }

    if config.general.force_local && config.general.force_remote {
        return Err(ConfigError::InvalidValue {
            field: "general.force_local / general.force_remote".to_string(),
            reason: "both options cannot be true simultaneously".to_string(),
            suggestion: "Set only one of force_local or force_remote to true".to_string(),
        }
        .into());
    }

    let contents = toml::to_string_pretty(&config)?;
    std::fs::write(config_path, format!("{}\n", contents))
        .with_context(|| format!("Failed to write {:?}", config_path))?;

    if ctx.is_json() {
        let _ = ctx.json(&ApiResponse::ok(
            "config set",
            ConfigSetResponse {
                key: key.to_string(),
                value: value.to_string(),
                config_path: config_path.display().to_string(),
            },
        ));
    } else {
        println!("Updated {:?}: {} = {}", config_path, key, value);
    }
    Ok(())
}

/// Reset a configuration value to its default.
pub fn config_reset(key: &str, ctx: &OutputContext) -> Result<()> {
    let config_dir = config_dir().context("Could not determine config directory")?;
    std::fs::create_dir_all(&config_dir)
        .with_context(|| format!("Failed to create config directory: {:?}", config_dir))?;
    let config_path = config_dir.join("config.toml");
    config_reset_at(&config_path, key, ctx)
}

fn config_reset_at(config_path: &Path, key: &str, ctx: &OutputContext) -> Result<()> {
    let mut config = if config_path.exists() {
        let contents = std::fs::read_to_string(config_path)
            .with_context(|| format!("Failed to read {:?}", config_path))?;
        toml::from_str::<RchConfig>(&contents)
            .with_context(|| format!("Failed to parse {:?}", config_path))?
    } else {
        RchConfig::default()
    };

    let defaults = RchConfig::default();
    let mut value = String::new();

    match key {
        "general.enabled" => {
            config.general.enabled = defaults.general.enabled;
            value = config.general.enabled.to_string();
        }
        "general.force_local" => {
            config.general.force_local = defaults.general.force_local;
            value = config.general.force_local.to_string();
        }
        "general.force_remote" => {
            config.general.force_remote = defaults.general.force_remote;
            value = config.general.force_remote.to_string();
        }
        "general.log_level" => {
            config.general.log_level = defaults.general.log_level;
            value = config.general.log_level.clone();
        }
        "general.socket_path" => {
            config.general.socket_path = defaults.general.socket_path;
            value = config.general.socket_path.clone();
        }
        "compilation.confidence_threshold" => {
            config.compilation.confidence_threshold = defaults.compilation.confidence_threshold;
            value = config.compilation.confidence_threshold.to_string();
        }
        "compilation.min_local_time_ms" => {
            config.compilation.min_local_time_ms = defaults.compilation.min_local_time_ms;
            value = config.compilation.min_local_time_ms.to_string();
        }
        "transfer.compression_level" => {
            config.transfer.compression_level = defaults.transfer.compression_level;
            value = config.transfer.compression_level.to_string();
        }
        "transfer.exclude_patterns" => {
            config.transfer.exclude_patterns = defaults.transfer.exclude_patterns;
            value = format!("{:?}", config.transfer.exclude_patterns);
        }
        "environment.allowlist" => {
            config.environment.allowlist = defaults.environment.allowlist;
            value = format!("{:?}", config.environment.allowlist);
        }
        "output.visibility" => {
            config.output.visibility = defaults.output.visibility;
            value = config.output.visibility.to_string();
        }
        "output.first_run_complete" | "first_run_complete" => {
            config.output.first_run_complete = defaults.output.first_run_complete;
            value = config.output.first_run_complete.to_string();
        }
        _ => {
            return Err(ConfigError::InvalidValue {
                field: key.to_string(),
                reason: "unknown configuration key".to_string(),
                suggestion: "Supported keys: general.enabled, general.force_local, general.force_remote, general.log_level, general.socket_path, compilation.confidence_threshold, compilation.min_local_time_ms, transfer.compression_level, transfer.exclude_patterns, environment.allowlist, output.visibility, output.first_run_complete".to_string(),
            }
            .into());
        }
    }

    if config.general.force_local && config.general.force_remote {
        return Err(ConfigError::InvalidValue {
            field: "general.force_local / general.force_remote".to_string(),
            reason: "both options cannot be true simultaneously".to_string(),
            suggestion: "Set only one of force_local or force_remote to true".to_string(),
        }
        .into());
    }

    let contents = toml::to_string_pretty(&config)?;
    std::fs::write(config_path, format!("{}\n", contents))
        .with_context(|| format!("Failed to write {:?}", config_path))?;

    if ctx.is_json() {
        let _ = ctx.json(&ApiResponse::ok(
            "config reset",
            ConfigResetResponse {
                key: key.to_string(),
                value,
                config_path: config_path.display().to_string(),
            },
        ));
    } else {
        println!("Reset {:?}: {} = {}", config_path, key, value);
    }

    Ok(())
}

/// Export configuration as shell environment variables or .env format.
pub fn config_export(format: &str, ctx: &OutputContext) -> Result<()> {
    let config = config::load_config()?;

    match format {
        "shell" => {
            // Shell export format (for sourcing)
            println!("# RCH configuration export");
            println!("# Source this file: source <(rch config export)");
            println!();
            println!("export RCH_ENABLED={}", config.general.enabled);
            println!("export RCH_LOG_LEVEL=\"{}\"", config.general.log_level);
            println!("export RCH_VISIBILITY=\"{}\"", config.output.visibility);
            println!(
                "export RCH_DAEMON_SOCKET=\"{}\"",
                config.general.socket_path
            );
            println!(
                "export RCH_CONFIDENCE_THRESHOLD={}",
                config.compilation.confidence_threshold
            );
            println!(
                "export RCH_MIN_LOCAL_TIME_MS={}",
                config.compilation.min_local_time_ms
            );
            println!(
                "export RCH_TRANSFER_ZSTD_LEVEL={}",
                config.transfer.compression_level
            );
            println!(
                "export RCH_ENV_ALLOWLIST=\"{}\"",
                config.environment.allowlist.join(",")
            );
        }
        "env" => {
            // .env file format
            println!("# RCH configuration");
            println!("# Save to .rch.env in your project");
            println!();
            println!("RCH_ENABLED={}", config.general.enabled);
            println!("RCH_LOG_LEVEL={}", config.general.log_level);
            println!("RCH_VISIBILITY={}", config.output.visibility);
            println!("RCH_DAEMON_SOCKET={}", config.general.socket_path);
            println!(
                "RCH_CONFIDENCE_THRESHOLD={}",
                config.compilation.confidence_threshold
            );
            println!(
                "RCH_MIN_LOCAL_TIME_MS={}",
                config.compilation.min_local_time_ms
            );
            println!(
                "RCH_TRANSFER_ZSTD_LEVEL={}",
                config.transfer.compression_level
            );
            println!(
                "RCH_ENV_ALLOWLIST={}",
                config.environment.allowlist.join(",")
            );
        }
        "json" => {
            // JSON format (ignore ctx.is_json() since user explicitly requested JSON)
            let _ = ctx.json_force(&ApiResponse::ok(
                "config export",
                serde_json::json!({
                    "general": {
                        "enabled": config.general.enabled,
                        "log_level": config.general.log_level,
                        "socket_path": config.general.socket_path,
                    },
                    "output": {
                        "visibility": config.output.visibility.to_string(),
                    },
                    "compilation": {
                        "confidence_threshold": config.compilation.confidence_threshold,
                        "min_local_time_ms": config.compilation.min_local_time_ms,
                    },
                    "transfer": {
                        "compression_level": config.transfer.compression_level,
                        "exclude_patterns": config.transfer.exclude_patterns,
                    },
                    "environment": {
                        "allowlist": config.environment.allowlist,
                    }
                }),
            ));
        }
        _ => {
            return Err(ConfigError::InvalidValue {
                field: "format".to_string(),
                reason: format!("unknown export format '{}'", format),
                suggestion: "Supported formats: shell, env, json".to_string(),
            }
            .into());
        }
    }
    Ok(())
}

// =============================================================================
// Config Lint & Diff
// =============================================================================

/// Lint configuration for potential issues.
pub fn config_lint(ctx: &OutputContext) -> Result<()> {
    let style = ctx.theme();
    let config = config::load_config()?;
    let mut issues = Vec::new();

    // Check 1: Missing workers configuration
    let workers_path = config_dir()
        .map(|d| d.join("workers.toml"))
        .unwrap_or_else(|| PathBuf::from("~/.config/rch/workers.toml"));
    if !workers_path.exists() {
        issues.push(LintIssue {
            severity: LintSeverity::Error,
            code: "LINT-E001".to_string(),
            message: "No workers.toml configuration found".to_string(),
            remediation: "Run 'rch config init --wizard' to create workers configuration"
                .to_string(),
        });
    } else {
        // Check if workers.toml has any workers defined
        match load_workers_from_config() {
            Ok(workers) if workers.is_empty() => {
                issues.push(LintIssue {
                    severity: LintSeverity::Error,
                    code: "LINT-E002".to_string(),
                    message: "workers.toml exists but no workers are defined".to_string(),
                    remediation: "Add at least one [[workers]] section to workers.toml".to_string(),
                });
            }
            Err(e) => {
                issues.push(LintIssue {
                    severity: LintSeverity::Error,
                    code: "LINT-E003".to_string(),
                    message: format!("Failed to parse workers.toml: {}", e),
                    remediation:
                        "Fix the workers.toml file syntax or run 'rch config init --wizard'"
                            .to_string(),
                });
            }
            _ => {}
        }
    }

    // Check 2: Compression level warnings
    if config.transfer.compression_level == 0 {
        issues.push(LintIssue {
            severity: LintSeverity::Warning,
            code: "LINT-W001".to_string(),
            message: "Compression is disabled (level=0)".to_string(),
            remediation: "Consider setting compression_level to 3-6 for better transfer performance on slow networks".to_string(),
        });
    } else if config.transfer.compression_level > 19 {
        issues.push(LintIssue {
            severity: LintSeverity::Warning,
            code: "LINT-W002".to_string(),
            message: format!(
                "Compression level {} is very high",
                config.transfer.compression_level
            ),
            remediation: "High compression levels (>10) significantly slow down transfers. Consider 3-6 for balanced performance".to_string(),
        });
    }

    // Check 3: Risky exclude patterns
    let risky_excludes = ["src/", "Cargo.toml", "Cargo.lock", "package.json", "go.mod"];
    for pattern in &config.transfer.exclude_patterns {
        for risky in &risky_excludes {
            if pattern == *risky || pattern.ends_with(risky) {
                issues.push(LintIssue {
                    severity: LintSeverity::Warning,
                    code: "LINT-W003".to_string(),
                    message: format!("Exclude pattern '{}' may break builds", pattern),
                    remediation: format!(
                        "Remove '{}' from exclude_patterns unless you really intend to exclude it",
                        pattern
                    ),
                });
            }
        }
    }

    // Check 4: Low confidence threshold
    if config.compilation.confidence_threshold < 0.7 {
        issues.push(LintIssue {
            severity: LintSeverity::Warning,
            code: "LINT-W004".to_string(),
            message: format!(
                "Confidence threshold {} is very low",
                config.compilation.confidence_threshold
            ),
            remediation:
                "Low thresholds may intercept non-compilation commands. Consider 0.8 or higher"
                    .to_string(),
        });
    }

    // Check 5: RCH disabled
    if !config.general.enabled {
        issues.push(LintIssue {
            severity: LintSeverity::Info,
            code: "LINT-I001".to_string(),
            message: "RCH is disabled (general.enabled = false)".to_string(),
            remediation:
                "Set general.enabled = true or RCH_ENABLED=true to enable remote compilation"
                    .to_string(),
        });
    }

    // Check 6: Very short timeouts
    if config.compilation.build_timeout_sec < 60 {
        issues.push(LintIssue {
            severity: LintSeverity::Warning,
            code: "LINT-W005".to_string(),
            message: format!(
                "Build timeout {}s is very short",
                config.compilation.build_timeout_sec
            ),
            remediation:
                "Short timeouts may cause builds to fail prematurely. Consider at least 300s"
                    .to_string(),
        });
    }

    // Count by severity
    let error_count = issues
        .iter()
        .filter(|i| i.severity == LintSeverity::Error)
        .count();
    let warning_count = issues
        .iter()
        .filter(|i| i.severity == LintSeverity::Warning)
        .count();
    let info_count = issues
        .iter()
        .filter(|i| i.severity == LintSeverity::Info)
        .count();

    // Output
    if ctx.is_json() {
        let response = ConfigLintResponse {
            issues,
            error_count,
            warning_count,
            info_count,
        };
        ctx.json(&ApiResponse::ok("config lint", response))?;
    } else if issues.is_empty() {
        println!(
            "{} Configuration looks good!",
            StatusIndicator::Success.display(style)
        );
    } else {
        println!("{} Configuration Lint Results", style.highlight("RCH"));
        println!();

        for issue in &issues {
            let indicator = match issue.severity {
                LintSeverity::Error => StatusIndicator::Error,
                LintSeverity::Warning => StatusIndicator::Warning,
                LintSeverity::Info => StatusIndicator::Info,
            };
            println!(
                "{} [{}] {}",
                indicator.display(style),
                issue.code,
                issue.message
            );
            println!("   {}", style.muted(&format!("→ {}", issue.remediation)));
            println!();
        }

        // Summary
        let mut summary_parts = Vec::new();
        if error_count > 0 {
            summary_parts.push(format!("{} error(s)", error_count));
        }
        if warning_count > 0 {
            summary_parts.push(format!("{} warning(s)", warning_count));
        }
        if info_count > 0 {
            summary_parts.push(format!("{} info", info_count));
        }
        println!("Summary: {}", summary_parts.join(", "));
    }

    // Exit with non-zero if errors found
    if error_count > 0 {
        std::process::exit(1);
    }

    Ok(())
}

// =============================================================================
// Config Edit Command
// =============================================================================

/// Open a configuration file in the user's editor.
///
/// Determines which file to edit based on flags:
/// - `--project`: Edit .rch/config.toml in current directory
/// - `--user`: Edit ~/.config/rch/config.toml (default)
/// - `--workers`: Edit ~/.config/rch/workers.toml
pub fn config_edit(project: bool, user: bool, workers: bool, ctx: &OutputContext) -> Result<()> {
    let style = ctx.theme();

    // Determine which file to edit (user is default if no flag specified)
    let _user = user; // Mark as intentionally unused - it's the default behavior
    let (file_path, file_desc) = if workers {
        let path = config_dir()
            .ok_or_else(|| anyhow::anyhow!("Could not determine config directory"))?
            .join("workers.toml");
        (path, "workers configuration")
    } else if project {
        let path = std::env::current_dir()?.join(".rch").join("config.toml");
        (path, "project configuration")
    } else {
        // Default to user config (or explicit --user)
        let path = config_dir()
            .ok_or_else(|| anyhow::anyhow!("Could not determine config directory"))?
            .join("config.toml");
        (path, "user configuration")
    };

    // Check if file exists
    if !file_path.exists() {
        // Create parent directory if needed
        if let Some(parent) = file_path.parent()
            && !parent.exists()
        {
            std::fs::create_dir_all(parent)?;
        }

        // Create an empty config file with a helpful header
        let header = if workers {
            r#"# RCH Workers Configuration
# See: rch config init --wizard for guided setup
#
# Example worker:
# [[workers]]
# id = "remote-1"
# host = "192.168.1.100"
# user = "ubuntu"
# identity_file = "~/.ssh/id_ed25519"
# total_slots = 8
"#
        } else {
            r#"# RCH Configuration
# See: rch config show --sources for all available options
#
# [general]
# enabled = true
# log_level = "info"
#
# [compilation]
# offload_confidence_threshold = 80
"#
        };
        std::fs::write(&file_path, header)?;
        println!(
            "{} Created new {} at {}",
            style.info("i"),
            file_desc,
            style.highlight(&file_path.display().to_string())
        );
    }

    // Get editor from environment
    let editor = std::env::var("VISUAL")
        .or_else(|_| std::env::var("EDITOR"))
        .unwrap_or_else(|_| "nano".to_string());

    println!(
        "{} Opening {} in {}",
        style.muted("→"),
        file_desc,
        style.info(&editor)
    );
    println!("  {}", style.muted(&file_path.display().to_string()));

    // Open editor
    let status = std::process::Command::new(&editor)
        .arg(&file_path)
        .status()
        .map_err(|e| EditorError::LaunchFailed {
            editor: editor.clone(),
            source: e,
        })?;

    if !status.success() {
        return Err(EditorError::ExitedWithError {
            exit_code: status.code(),
        }
        .into());
    }

    println!();
    println!("{} Configuration saved", style.success("✓"));

    // Optionally validate the file after editing
    if workers {
        match load_workers_from_config() {
            Ok(w) => {
                println!(
                    "  {} {} worker{} configured",
                    style.muted("→"),
                    w.len(),
                    if w.len() == 1 { "" } else { "s" }
                );
            }
            Err(e) => {
                println!("  {} Validation warning: {}", style.warning("!"), e);
            }
        }
    } else {
        match config::load_config() {
            Ok(_) => {
                println!("  {} Configuration is valid", style.muted("→"));
            }
            Err(e) => {
                println!("  {} Validation warning: {}", style.warning("!"), e);
            }
        }
    }

    Ok(())
}

/// Show configuration values that differ from defaults.
pub fn config_diff(ctx: &OutputContext) -> Result<()> {
    use rch_common::RchConfig;

    let style = ctx.theme();
    let loaded = config::load_config_with_sources()?;
    let config = &loaded.config;
    let defaults = RchConfig::default();
    let sources = &loaded.sources;

    let mut entries = Vec::new();

    // Helper to add entry if different
    macro_rules! diff_field {
        ($key:expr, $current:expr, $default:expr, $source_key:expr) => {
            let current_str = format!("{}", $current);
            let default_str = format!("{}", $default);
            if current_str != default_str {
                let source = sources
                    .get($source_key)
                    .map(|s| format!("{:?}", s))
                    .unwrap_or_else(|| "unknown".to_string());
                entries.push(ConfigDiffEntry {
                    key: $key.to_string(),
                    current: current_str,
                    default: default_str,
                    source,
                });
            }
        };
    }

    // General section
    diff_field!(
        "general.enabled",
        config.general.enabled,
        defaults.general.enabled,
        "general.enabled"
    );
    diff_field!(
        "general.log_level",
        &config.general.log_level,
        &defaults.general.log_level,
        "general.log_level"
    );
    diff_field!(
        "general.socket_path",
        &config.general.socket_path,
        &defaults.general.socket_path,
        "general.socket_path"
    );

    // Compilation section
    diff_field!(
        "compilation.confidence_threshold",
        config.compilation.confidence_threshold,
        defaults.compilation.confidence_threshold,
        "compilation.confidence_threshold"
    );
    diff_field!(
        "compilation.min_local_time_ms",
        config.compilation.min_local_time_ms,
        defaults.compilation.min_local_time_ms,
        "compilation.min_local_time_ms"
    );
    diff_field!(
        "compilation.build_slots",
        config.compilation.build_slots,
        defaults.compilation.build_slots,
        "compilation.build_slots"
    );
    diff_field!(
        "compilation.test_slots",
        config.compilation.test_slots,
        defaults.compilation.test_slots,
        "compilation.test_slots"
    );
    diff_field!(
        "compilation.check_slots",
        config.compilation.check_slots,
        defaults.compilation.check_slots,
        "compilation.check_slots"
    );
    diff_field!(
        "compilation.build_timeout_sec",
        config.compilation.build_timeout_sec,
        defaults.compilation.build_timeout_sec,
        "compilation.build_timeout_sec"
    );
    diff_field!(
        "compilation.test_timeout_sec",
        config.compilation.test_timeout_sec,
        defaults.compilation.test_timeout_sec,
        "compilation.test_timeout_sec"
    );

    // Transfer section
    diff_field!(
        "transfer.compression_level",
        config.transfer.compression_level,
        defaults.transfer.compression_level,
        "transfer.compression_level"
    );

    // Compare exclude patterns
    let current_excludes = config.transfer.exclude_patterns.join(",");
    let default_excludes = defaults.transfer.exclude_patterns.join(",");
    if current_excludes != default_excludes {
        let source = sources
            .get("transfer.exclude_patterns")
            .map(|s| format!("{:?}", s))
            .unwrap_or_else(|| "unknown".to_string());
        entries.push(ConfigDiffEntry {
            key: "transfer.exclude_patterns".to_string(),
            current: format!("[{}]", current_excludes),
            default: format!("[{}]", default_excludes),
            source,
        });
    }

    // Circuit breaker section
    diff_field!(
        "circuit.failure_threshold",
        config.circuit.failure_threshold,
        defaults.circuit.failure_threshold,
        "circuit.failure_threshold"
    );
    diff_field!(
        "circuit.success_threshold",
        config.circuit.success_threshold,
        defaults.circuit.success_threshold,
        "circuit.success_threshold"
    );
    diff_field!(
        "circuit.error_rate_threshold",
        config.circuit.error_rate_threshold,
        defaults.circuit.error_rate_threshold,
        "circuit.error_rate_threshold"
    );
    diff_field!(
        "circuit.window_secs",
        config.circuit.window_secs,
        defaults.circuit.window_secs,
        "circuit.window_secs"
    );
    diff_field!(
        "circuit.open_cooldown_secs",
        config.circuit.open_cooldown_secs,
        defaults.circuit.open_cooldown_secs,
        "circuit.open_cooldown_secs"
    );
    diff_field!(
        "circuit.half_open_max_probes",
        config.circuit.half_open_max_probes,
        defaults.circuit.half_open_max_probes,
        "circuit.half_open_max_probes"
    );

    // Output section
    diff_field!(
        "output.visibility",
        config.output.visibility,
        defaults.output.visibility,
        "output.visibility"
    );
    diff_field!(
        "output.first_run_complete",
        config.output.first_run_complete,
        defaults.output.first_run_complete,
        "output.first_run_complete"
    );

    // Self-healing section
    diff_field!(
        "self_healing.hook_starts_daemon",
        config.self_healing.hook_starts_daemon,
        defaults.self_healing.hook_starts_daemon,
        "self_healing.hook_starts_daemon"
    );
    diff_field!(
        "self_healing.daemon_installs_hooks",
        config.self_healing.daemon_installs_hooks,
        defaults.self_healing.daemon_installs_hooks,
        "self_healing.daemon_installs_hooks"
    );
    diff_field!(
        "self_healing.auto_start_cooldown_secs",
        config.self_healing.auto_start_cooldown_secs,
        defaults.self_healing.auto_start_cooldown_secs,
        "self_healing.auto_start_cooldown_secs"
    );
    diff_field!(
        "self_healing.auto_start_timeout_secs",
        config.self_healing.auto_start_timeout_secs,
        defaults.self_healing.auto_start_timeout_secs,
        "self_healing.auto_start_timeout_secs"
    );

    // Environment allowlist (compare as sets)
    if !config.environment.allowlist.is_empty()
        && config.environment.allowlist != defaults.environment.allowlist
    {
        let source = sources
            .get("environment.allowlist")
            .map(|s| format!("{:?}", s))
            .unwrap_or_else(|| "unknown".to_string());
        entries.push(ConfigDiffEntry {
            key: "environment.allowlist".to_string(),
            current: format!("[{}]", config.environment.allowlist.join(", ")),
            default: format!("[{}]", defaults.environment.allowlist.join(", ")),
            source,
        });
    }

    let total_changes = entries.len();

    // Output
    if ctx.is_json() {
        let response = ConfigDiffResponse {
            entries,
            total_changes,
        };
        ctx.json(&ApiResponse::ok("config diff", response))?;
    } else if entries.is_empty() {
        println!(
            "{} All configuration values are at defaults",
            StatusIndicator::Success.display(style)
        );
    } else {
        println!(
            "{} Configuration Diff (non-default values)",
            style.highlight("RCH")
        );
        println!();

        // Print header
        println!(
            "{:<40} {:<20} {:<20} {}",
            style.highlight("Key"),
            style.highlight("Current"),
            style.highlight("Default"),
            style.highlight("Source")
        );
        println!("{}", "-".repeat(95));

        for entry in &entries {
            // Truncate long values
            let current = if entry.current.len() > 18 {
                format!("{}...", &entry.current[..15])
            } else {
                entry.current.clone()
            };
            let default = if entry.default.len() > 18 {
                format!("{}...", &entry.default[..15])
            } else {
                entry.default.clone()
            };

            println!(
                "{:<40} {:<20} {:<20} {}",
                entry.key,
                current,
                style.muted(&default),
                entry.source
            );
        }

        println!();
        println!("Total: {} non-default value(s)", total_changes);
    }

    Ok(())
}

fn parse_bool(value: &str, key: &str) -> Result<bool> {
    value.trim().parse::<bool>().map_err(|_| {
        ConfigError::InvalidValue {
            field: key.to_string(),
            reason: format!("'{}' is not a valid boolean", value.trim()),
            suggestion: "Use 'true' or 'false'".to_string(),
        }
        .into()
    })
}

fn parse_u32(value: &str, key: &str) -> Result<u32> {
    value.trim().parse::<u32>().map_err(|_| {
        ConfigError::InvalidValue {
            field: key.to_string(),
            reason: format!("'{}' is not a valid unsigned integer", value.trim()),
            suggestion: "Use a positive whole number (e.g., 0, 1, 42, 1000)".to_string(),
        }
        .into()
    })
}

fn parse_u64(value: &str, key: &str) -> Result<u64> {
    value.trim().parse::<u64>().map_err(|_| {
        ConfigError::InvalidValue {
            field: key.to_string(),
            reason: format!("'{}' is not a valid unsigned integer", value.trim()),
            suggestion: "Use a positive whole number (e.g., 0, 1, 42, 1000)".to_string(),
        }
        .into()
    })
}

fn parse_f64(value: &str, key: &str) -> Result<f64> {
    value.trim().parse::<f64>().map_err(|_| {
        ConfigError::InvalidValue {
            field: key.to_string(),
            reason: format!("'{}' is not a valid number", value.trim()),
            suggestion: "Use a decimal number (e.g., 0.5, 1.0, 3.14)".to_string(),
        }
        .into()
    })
}

fn parse_string_list(value: &str, key: &str) -> Result<Vec<String>> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }

    if trimmed.starts_with('[') {
        let wrapped = format!("value = {}", trimmed);
        let parsed: toml::Value =
            toml::from_str(&wrapped).with_context(|| format!("Invalid array for {}", key))?;
        let array = parsed
            .get("value")
            .and_then(|v| v.as_array())
            .ok_or_else(|| ConfigError::InvalidValue {
                field: key.to_string(),
                reason: format!("'{}' is not a valid array", trimmed),
                suggestion: "Use TOML array syntax: [\"item1\", \"item2\"]".to_string(),
            })?;
        let mut result = Vec::with_capacity(array.len());
        for item in array {
            let item_str = item.as_str().ok_or_else(|| ConfigError::InvalidValue {
                field: key.to_string(),
                reason: "Array contains non-string items".to_string(),
                suggestion: "All array items must be strings: [\"item1\", \"item2\"]".to_string(),
            })?;
            result.push(item_str.to_string());
        }
        return Ok(result);
    }

    if trimmed.contains(',') {
        let parts: Vec<String> = trimmed
            .split(',')
            .map(|part| part.trim())
            .filter(|part| !part.is_empty())
            .map(String::from)
            .collect();
        if !parts.is_empty() {
            return Ok(parts);
        }
    }

    Ok(vec![trimmed.to_string()])
}

#[cfg(test)]
mod tests {
    use super::*;
    use rch_common::test_guard;

    // -------------------------------------------------------------------------
    // parse_bool Tests
    // -------------------------------------------------------------------------

    #[test]
    fn parse_bool_true() {
        let _guard = test_guard!();
        assert!(parse_bool("true", "test_key").unwrap());
    }

    #[test]
    fn parse_bool_false() {
        let _guard = test_guard!();
        assert!(!parse_bool("false", "test_key").unwrap());
    }

    #[test]
    fn parse_bool_with_whitespace() {
        let _guard = test_guard!();
        assert!(parse_bool("  true  ", "test_key").unwrap());
    }

    #[test]
    fn parse_bool_invalid() {
        let _guard = test_guard!();
        let result = parse_bool("yes", "test_key");
        assert!(result.is_err());
    }

    // -------------------------------------------------------------------------
    // parse_u32 Tests
    // -------------------------------------------------------------------------

    #[test]
    fn parse_u32_valid() {
        let _guard = test_guard!();
        assert_eq!(parse_u32("42", "test_key").unwrap(), 42);
    }

    #[test]
    fn parse_u32_zero() {
        let _guard = test_guard!();
        assert_eq!(parse_u32("0", "test_key").unwrap(), 0);
    }

    #[test]
    fn parse_u32_with_whitespace() {
        let _guard = test_guard!();
        assert_eq!(parse_u32("  123  ", "test_key").unwrap(), 123);
    }

    #[test]
    fn parse_u32_negative() {
        let _guard = test_guard!();
        let result = parse_u32("-1", "test_key");
        assert!(result.is_err());
    }

    #[test]
    fn parse_u32_non_numeric() {
        let _guard = test_guard!();
        let result = parse_u32("abc", "test_key");
        assert!(result.is_err());
    }

    #[test]
    fn parse_u32_overflow() {
        let _guard = test_guard!();
        let result = parse_u32("4294967296", "test_key"); // u32::MAX + 1
        assert!(result.is_err());
    }

    // -------------------------------------------------------------------------
    // parse_u64 Tests
    // -------------------------------------------------------------------------

    #[test]
    fn parse_u64_valid() {
        let _guard = test_guard!();
        assert_eq!(parse_u64("9999999999", "test_key").unwrap(), 9999999999);
    }

    #[test]
    fn parse_u64_zero() {
        let _guard = test_guard!();
        assert_eq!(parse_u64("0", "test_key").unwrap(), 0);
    }

    #[test]
    fn parse_u64_with_whitespace() {
        let _guard = test_guard!();
        assert_eq!(parse_u64("  456  ", "test_key").unwrap(), 456);
    }

    #[test]
    fn parse_u64_negative() {
        let _guard = test_guard!();
        let result = parse_u64("-1", "test_key");
        assert!(result.is_err());
    }

    // -------------------------------------------------------------------------
    // parse_f64 Tests
    // -------------------------------------------------------------------------

    #[test]
    fn parse_f64_integer() {
        let _guard = test_guard!();
        let result = parse_f64("42", "test_key").unwrap();
        assert!((result - 42.0).abs() < f64::EPSILON);
    }

    #[test]
    fn parse_f64_decimal() {
        let _guard = test_guard!();
        let result = parse_f64("2.71", "test_key").unwrap();
        assert!((result - 2.71).abs() < 0.001);
    }

    #[test]
    fn parse_f64_with_whitespace() {
        let _guard = test_guard!();
        let result = parse_f64("  0.5  ", "test_key").unwrap();
        assert!((result - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn parse_f64_negative() {
        let _guard = test_guard!();
        let result = parse_f64("-1.5", "test_key").unwrap();
        assert!((result - (-1.5)).abs() < f64::EPSILON);
    }

    #[test]
    fn parse_f64_invalid() {
        let _guard = test_guard!();
        let result = parse_f64("not a number", "test_key");
        assert!(result.is_err());
    }

    // -------------------------------------------------------------------------
    // parse_string_list Tests
    // -------------------------------------------------------------------------

    #[test]
    fn parse_string_list_empty() {
        let _guard = test_guard!();
        let result = parse_string_list("", "test_key").unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn parse_string_list_single() {
        let _guard = test_guard!();
        let result = parse_string_list("item", "test_key").unwrap();
        assert_eq!(result, vec!["item"]);
    }

    #[test]
    fn parse_string_list_comma_separated() {
        let _guard = test_guard!();
        let result = parse_string_list("a, b, c", "test_key").unwrap();
        assert_eq!(result, vec!["a", "b", "c"]);
    }

    #[test]
    fn parse_string_list_toml_array() {
        let _guard = test_guard!();
        let result = parse_string_list(r#"["foo", "bar"]"#, "test_key").unwrap();
        assert_eq!(result, vec!["foo", "bar"]);
    }

    #[test]
    fn parse_string_list_toml_array_empty() {
        let _guard = test_guard!();
        let result = parse_string_list("[]", "test_key").unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn parse_string_list_with_whitespace() {
        let _guard = test_guard!();
        let result = parse_string_list("  a  ,  b  ", "test_key").unwrap();
        assert_eq!(result, vec!["a", "b"]);
    }
}
