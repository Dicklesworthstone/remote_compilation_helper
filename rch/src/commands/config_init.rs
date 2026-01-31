//! Configuration initialization wizard and helpers.
//!
//! This module handles the `rch config init` command, including both
//! the interactive wizard mode and simple template mode.

use anyhow::{Context, Result};
use rch_common::ApiResponse;

use crate::ui;
use crate::ui::context::OutputContext;
use crate::ui::theme::StatusIndicator;

use super::helpers::config_dir;
use super::types::ConfigInitResponse;

/// Initialize configuration files with optional interactive wizard.
///
/// When `wizard` is true and `use_defaults` is false, prompts the user interactively
/// for configuration values. When `use_defaults` is true, uses sensible defaults
/// without prompting.
pub fn config_init(ctx: &OutputContext, wizard: bool, use_defaults: bool) -> Result<()> {
    use dialoguer::Confirm;

    let style = ctx.theme();
    let config_dir = config_dir().context("Could not determine config directory")?;

    // Create config directory
    std::fs::create_dir_all(&config_dir)
        .with_context(|| format!("Failed to create config directory: {:?}", config_dir))?;

    let config_path = config_dir.join("config.toml");
    let workers_path = config_dir.join("workers.toml");

    let mut created = Vec::new();
    let mut already_existed = Vec::new();

    // Check if files exist and handle accordingly
    let config_exists = config_path.exists();
    let workers_exists = workers_path.exists();

    // If not using wizard, use simple template mode
    if !wizard {
        return config_init_simple(ctx, &config_path, &workers_path);
    }

    // Wizard mode
    if !ctx.is_json() {
        println!("{}", style.format_header("RCH Configuration Wizard"));
        println!();
        if use_defaults {
            println!(
                "  {} Using default values (non-interactive mode)",
                style.muted("→")
            );
        } else {
            println!(
                "  {} Interactive configuration - press Enter to accept defaults",
                style.muted("→")
            );
        }
        println!();
    }

    // Handle existing config.toml
    let should_write_config = if config_exists {
        if use_defaults {
            false // Don't overwrite in non-interactive mode
        } else {
            Confirm::new()
                .with_prompt(format!(
                    "{} already exists. Overwrite?",
                    config_path.display()
                ))
                .default(false)
                .interact()
                .unwrap_or(false)
        }
    } else {
        true
    };

    // Collect config values
    let config_values = if should_write_config {
        Some(collect_config_values(use_defaults, style)?)
    } else {
        None
    };

    // Handle existing workers.toml
    let should_write_workers = if workers_exists {
        if use_defaults {
            false // Don't overwrite in non-interactive mode
        } else {
            Confirm::new()
                .with_prompt(format!(
                    "{} already exists. Overwrite?",
                    workers_path.display()
                ))
                .default(false)
                .interact()
                .unwrap_or(false)
        }
    } else {
        true
    };

    // Collect worker values
    let workers = if should_write_workers {
        Some(collect_worker_values(use_defaults, style)?)
    } else {
        None
    };

    // Write config.toml
    if let Some(values) = config_values {
        let config_content = generate_config_toml(&values);
        std::fs::write(&config_path, config_content)?;
        created.push(config_path.display().to_string());
        if !ctx.is_json() {
            println!(
                "{} {} {}",
                StatusIndicator::Success.display(style),
                style.muted("Created:"),
                style.value(&config_path.display().to_string())
            );
        }
    } else if config_exists {
        already_existed.push(config_path.display().to_string());
        if !ctx.is_json() {
            println!(
                "{} {} {}",
                style.muted("-"),
                style.muted("Exists:"),
                style.muted(&config_path.display().to_string())
            );
        }
    }

    // Write workers.toml
    if let Some(workers) = workers.as_ref() {
        let workers_content = generate_workers_toml(workers);
        std::fs::write(&workers_path, workers_content)?;
        created.push(workers_path.display().to_string());
        if !ctx.is_json() {
            println!(
                "{} {} {}",
                StatusIndicator::Success.display(style),
                style.muted("Created:"),
                style.value(&workers_path.display().to_string())
            );
        }
    } else if workers_exists {
        already_existed.push(workers_path.display().to_string());
        if !ctx.is_json() {
            println!(
                "{} {} {}",
                style.muted("-"),
                style.muted("Exists:"),
                style.muted(&workers_path.display().to_string())
            );
        }
    }

    // JSON output
    if ctx.is_json() {
        let _ = ctx.json(&ApiResponse::ok(
            "config init",
            ConfigInitResponse {
                created,
                already_existed,
            },
        ));
        return Ok(());
    }

    // Success message and next steps
    println!("\n{}", style.format_success("Configuration initialized!"));
    println!("\n{}", style.highlight("Next steps:"));

    if workers.is_some() || !workers_exists {
        println!(
            "  {}. Edit {} with your actual worker details",
            style.muted("1"),
            style.info(&workers_path.display().to_string())
        );
        println!(
            "  {}. Or auto-discover workers: {}",
            style.muted("2"),
            style.highlight("rch workers discover --add")
        );
    }

    println!(
        "  {}. Test connectivity: {}",
        style.muted("3"),
        style.highlight("rch workers probe --all")
    );
    println!(
        "  {}. Start the daemon: {}",
        style.muted("4"),
        style.highlight("rch daemon start")
    );

    Ok(())
}

/// Simple config init without wizard (original behavior).
fn config_init_simple(
    ctx: &OutputContext,
    config_path: &std::path::Path,
    workers_path: &std::path::Path,
) -> Result<()> {
    let style = ctx.theme();
    let mut created = Vec::new();
    let mut already_existed = Vec::new();

    // Write example config.toml
    if !config_path.exists() {
        let config_content = r###"# RCH Configuration
# See documentation for all options

[general]
enabled = true
log_level = "info"
socket_path = "/tmp/rch.sock"

[compilation]
confidence_threshold = 0.85
min_local_time_ms = 2000

[transfer]
compression_level = 3
exclude_patterns = [
    "target/",
    ".git/objects/",
    "node_modules/",
    "*.rlib",
    "*.rmeta",
]
"###;
        std::fs::write(config_path, config_content)?;
        created.push(config_path.display().to_string());
        if !ctx.is_json() {
            println!(
                "{} {} {}",
                StatusIndicator::Success.display(style),
                style.muted("Created:"),
                style.value(&config_path.display().to_string())
            );
        }
    } else {
        already_existed.push(config_path.display().to_string());
        if !ctx.is_json() {
            println!(
                "{} {} {}",
                style.muted("-"),
                style.muted("Exists:"),
                style.muted(&config_path.display().to_string())
            );
        }
    }

    // Write example workers.toml
    if !workers_path.exists() {
        let workers_content = r###"# RCH Workers Configuration
# Define your remote compilation workers here

# Example worker definition
[[workers]]
id = "worker1"
host = "192.168.1.100"
user = "ubuntu"
identity_file = "~/.ssh/id_rsa"
total_slots = 16
priority = 100
tags = ["rust", "fast"]
enabled = true

# Add more workers as needed:
# [[workers]]
# id = "worker2"
# host = "192.168.1.101"
# ...
"###;
        std::fs::write(workers_path, workers_content)?;
        created.push(workers_path.display().to_string());
        if !ctx.is_json() {
            println!(
                "{} {} {}",
                StatusIndicator::Success.display(style),
                style.muted("Created:"),
                style.value(&workers_path.display().to_string())
            );
        }
    } else {
        already_existed.push(workers_path.display().to_string());
        if !ctx.is_json() {
            println!(
                "{} {} {}",
                style.muted("-"),
                style.muted("Exists:"),
                style.muted(&workers_path.display().to_string())
            );
        }
    }

    if ctx.is_json() {
        let _ = ctx.json(&ApiResponse::ok(
            "config init",
            ConfigInitResponse {
                created,
                already_existed,
            },
        ));
        return Ok(());
    }

    println!("\n{}", style.format_success("Configuration initialized!"));
    println!("\n{}", style.highlight("Next steps:"));
    println!(
        "  {}. Edit {} with your worker details",
        style.muted("1"),
        style.info(&workers_path.display().to_string())
    );
    println!(
        "  {}. Test connectivity: {}",
        style.muted("2"),
        style.highlight("rch workers probe --all")
    );
    println!(
        "  {}. Start the daemon: {}",
        style.muted("3"),
        style.highlight("rch daemon start")
    );

    Ok(())
}

/// Configuration values collected from wizard.
struct ConfigValues {
    log_level: String,
    socket_path: String,
    confidence_threshold: f64,
    min_local_time_ms: u32,
    compression_level: u8,
}

/// Worker definition collected from wizard.
struct WizardWorker {
    id: String,
    host: String,
    user: String,
    identity_file: String,
    total_slots: u16,
    priority: u16,
}

/// Collect configuration values interactively or with defaults.
fn collect_config_values(use_defaults: bool, style: &ui::theme::Theme) -> Result<ConfigValues> {
    use dialoguer::{Input, Select};

    if use_defaults {
        return Ok(ConfigValues {
            log_level: "info".to_string(),
            socket_path: "/tmp/rch.sock".to_string(),
            confidence_threshold: 0.85,
            min_local_time_ms: 2000,
            compression_level: 3,
        });
    }

    println!("\n{}", style.highlight("General Settings"));
    println!();

    // Log level
    let log_levels = vec!["error", "warn", "info", "debug", "trace"];
    let log_level_idx = Select::new()
        .with_prompt("Log level")
        .items(&log_levels)
        .default(2) // info
        .interact()
        .unwrap_or(2);
    let log_level = log_levels[log_level_idx].to_string();

    // Socket path
    let socket_path: String = Input::new()
        .with_prompt("Unix socket path")
        .default("/tmp/rch.sock".to_string())
        .interact_text()
        .unwrap_or_else(|_| "/tmp/rch.sock".to_string());

    println!("\n{}", style.highlight("Compilation Settings"));
    println!();

    // Confidence threshold
    let confidence_threshold: f64 = Input::new()
        .with_prompt("Classification confidence threshold (0.0-1.0)")
        .default(0.85)
        .validate_with(|input: &f64| {
            if *input >= 0.0 && *input <= 1.0 {
                Ok(())
            } else {
                Err("Must be between 0.0 and 1.0")
            }
        })
        .interact_text()
        .unwrap_or(0.85);

    // Min local time
    let min_local_time_ms: u32 = Input::new()
        .with_prompt("Minimum estimated local time (ms) to offload")
        .default(2000u32)
        .interact_text()
        .unwrap_or(2000);

    println!("\n{}", style.highlight("Transfer Settings"));
    println!();

    // Compression level
    let compression_level: u8 = Input::new()
        .with_prompt("Zstd compression level (1-19, lower=faster)")
        .default(3u8)
        .validate_with(|input: &u8| {
            if *input >= 1 && *input <= 19 {
                Ok(())
            } else {
                Err("Must be between 1 and 19")
            }
        })
        .interact_text()
        .unwrap_or(3);

    Ok(ConfigValues {
        log_level,
        socket_path,
        confidence_threshold,
        min_local_time_ms,
        compression_level,
    })
}

/// Collect worker definitions interactively or with defaults.
fn collect_worker_values(
    use_defaults: bool,
    style: &ui::theme::Theme,
) -> Result<Vec<WizardWorker>> {
    use dialoguer::{Confirm, Input};

    if use_defaults {
        return Ok(vec![WizardWorker {
            id: "worker1".to_string(),
            host: "192.168.1.100".to_string(),
            user: "ubuntu".to_string(),
            identity_file: "~/.ssh/id_rsa".to_string(),
            total_slots: 16,
            priority: 100,
        }]);
    }

    println!("\n{}", style.highlight("Worker Configuration"));
    println!();
    println!(
        "  {} Define your remote compilation workers.",
        style.muted("→")
    );
    println!(
        "  {} You can also auto-discover workers later with: {}",
        style.muted("→"),
        style.info("rch workers discover --add")
    );
    println!();

    let mut workers = Vec::new();
    let mut worker_num = 1;

    loop {
        println!("\n{} Worker #{}", style.muted("─────────────"), worker_num);

        let id: String = Input::new()
            .with_prompt("Worker ID (short name)")
            .default(format!("worker{}", worker_num))
            .interact_text()
            .unwrap_or_else(|_| format!("worker{}", worker_num));

        let host: String = Input::new()
            .with_prompt("Hostname or IP address")
            .interact_text()
            .context("Host is required")?;

        let user: String = Input::new()
            .with_prompt("SSH username")
            .default("ubuntu".to_string())
            .interact_text()
            .unwrap_or_else(|_| "ubuntu".to_string());

        let identity_file: String = Input::new()
            .with_prompt("SSH identity file path")
            .default("~/.ssh/id_rsa".to_string())
            .interact_text()
            .unwrap_or_else(|_| "~/.ssh/id_rsa".to_string());

        let total_slots: u16 = Input::new()
            .with_prompt("Total CPU slots (cores) available")
            .default(16u16)
            .interact_text()
            .unwrap_or(16);

        let priority: u16 = Input::new()
            .with_prompt("Priority (higher = preferred)")
            .default(100u16)
            .interact_text()
            .unwrap_or(100);

        workers.push(WizardWorker {
            id,
            host,
            user,
            identity_file,
            total_slots,
            priority,
        });

        worker_num += 1;

        let add_another = Confirm::new()
            .with_prompt("Add another worker?")
            .default(false)
            .interact()
            .unwrap_or(false);

        if !add_another {
            break;
        }
    }

    if workers.is_empty() {
        // Add a placeholder if no workers were defined
        workers.push(WizardWorker {
            id: "worker1".to_string(),
            host: "192.168.1.100".to_string(),
            user: "ubuntu".to_string(),
            identity_file: "~/.ssh/id_rsa".to_string(),
            total_slots: 16,
            priority: 100,
        });
    }

    Ok(workers)
}

/// Generate config.toml content from wizard values.
fn generate_config_toml(values: &ConfigValues) -> String {
    format!(
        r###"# RCH Configuration
# Generated by rch config init --wizard
# See documentation for all options

[general]
enabled = true
log_level = "{}"
socket_path = "{}"

[compilation]
# Minimum classification confidence to intercept (0.0-1.0)
confidence_threshold = {}
# Skip offloading if estimated local time is below this (milliseconds)
min_local_time_ms = {}

[transfer]
# Zstd compression level (1-19, lower=faster)
compression_level = {}
exclude_patterns = [
    "target/",
    ".git/objects/",
    "node_modules/",
    "*.rlib",
    "*.rmeta",
]
"###,
        values.log_level,
        values.socket_path,
        values.confidence_threshold,
        values.min_local_time_ms,
        values.compression_level
    )
}

/// Generate workers.toml content from wizard values.
fn generate_workers_toml(workers: &[WizardWorker]) -> String {
    let mut content = String::from(
        "# RCH Workers Configuration\n\
         # Generated by rch config init --wizard\n\
         # Define your remote compilation workers here\n\n",
    );

    for worker in workers {
        content.push_str(&format!(
            r#"[[workers]]
id = "{}"
host = "{}"
user = "{}"
identity_file = "{}"
total_slots = {}
priority = {}
enabled = true

"#,
            worker.id,
            worker.host,
            worker.user,
            worker.identity_file,
            worker.total_slots,
            worker.priority
        ));
    }

    content
}

#[cfg(test)]
mod tests {
    use super::*;
    use rch_common::test_guard;

    // -------------------------------------------------------------------------
    // generate_config_toml Tests
    // -------------------------------------------------------------------------

    #[test]
    fn generate_config_toml_contains_all_sections() {
        let _guard = test_guard!();
        let values = ConfigValues {
            log_level: "info".to_string(),
            socket_path: "/tmp/rch.sock".to_string(),
            confidence_threshold: 0.85,
            min_local_time_ms: 2000,
            compression_level: 3,
        };
        let toml = generate_config_toml(&values);
        assert!(toml.contains("[general]"));
        assert!(toml.contains("[compilation]"));
        assert!(toml.contains("[transfer]"));
        assert!(toml.contains("enabled = true"));
        assert!(toml.contains("log_level = \"info\""));
        assert!(toml.contains("confidence_threshold = 0.85"));
        assert!(toml.contains("min_local_time_ms = 2000"));
        assert!(toml.contains("compression_level = 3"));
    }

    // -------------------------------------------------------------------------
    // generate_workers_toml Tests
    // -------------------------------------------------------------------------

    #[test]
    fn generate_workers_toml_single_worker() {
        let _guard = test_guard!();
        let workers = vec![WizardWorker {
            id: "worker-1".to_string(),
            host: "192.168.1.100".to_string(),
            user: "ubuntu".to_string(),
            identity_file: "~/.ssh/id_rsa".to_string(),
            total_slots: 8,
            priority: 100,
        }];
        let toml = generate_workers_toml(&workers);
        assert!(toml.contains("[[workers]]"));
        assert!(toml.contains("id = \"worker-1\""));
        assert!(toml.contains("host = \"192.168.1.100\""));
        assert!(toml.contains("user = \"ubuntu\""));
        assert!(toml.contains("total_slots = 8"));
        assert!(toml.contains("priority = 100"));
    }

    #[test]
    fn generate_workers_toml_multiple_workers() {
        let _guard = test_guard!();
        let workers = vec![
            WizardWorker {
                id: "w1".to_string(),
                host: "host1".to_string(),
                user: "user1".to_string(),
                identity_file: "key1".to_string(),
                total_slots: 4,
                priority: 100,
            },
            WizardWorker {
                id: "w2".to_string(),
                host: "host2".to_string(),
                user: "user2".to_string(),
                identity_file: "key2".to_string(),
                total_slots: 8,
                priority: 50,
            },
        ];
        let toml = generate_workers_toml(&workers);
        // Should contain two [[workers]] blocks
        let worker_count = toml.matches("[[workers]]").count();
        assert_eq!(worker_count, 2);
        assert!(toml.contains("id = \"w1\""));
        assert!(toml.contains("id = \"w2\""));
    }

    #[test]
    fn generate_workers_toml_empty() {
        let _guard = test_guard!();
        let workers: Vec<WizardWorker> = vec![];
        let toml = generate_workers_toml(&workers);
        // Should have header but no [[workers]] blocks
        assert!(toml.contains("RCH Workers Configuration"));
        assert!(!toml.contains("[[workers]]"));
    }
}
