//! Worker initialization and discovery commands.
//!
//! This module contains commands for adding new workers interactively
//! and discovering potential workers from SSH config.

use crate::error::ConfigError;
use crate::ui::context::OutputContext;
use crate::ui::theme::StatusIndicator;
use anyhow::{Context, Result};
use rch_common::{ApiResponse, DiscoveredHost, WorkerConfig, WorkerId, discover_all};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::process::Command;

use super::helpers::{classify_ssh_error_message, ssh_key_path_from_identity};
use super::{config_dir, load_workers_from_config};

// =============================================================================
// Workers Init Command
// =============================================================================

/// Interactive wizard to add a new worker.
pub async fn workers_init(yes: bool, ctx: &OutputContext) -> Result<()> {
    use dialoguer::{Confirm, Input};

    let style = ctx.theme();

    println!();
    println!("{}", style.format_header("Add New Worker"));
    println!();
    println!(
        "  {} This wizard will guide you through adding a remote compilation worker.",
        style.muted("→")
    );
    println!();

    // Step 1: Get hostname
    println!("{}", style.highlight("Step 1/5: Connection Details"));
    let hostname: String = if yes {
        return Err(ConfigError::MissingField {
            field: "RCH_INIT_HOST environment variable (required with --yes flag)".to_string(),
        }
        .into());
    } else {
        Input::new()
            .with_prompt("Hostname or IP address")
            .interact_text()?
    };

    // Get username with default
    let default_user = std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "ubuntu".to_string());
    let username: String = if yes {
        default_user
    } else {
        Input::new()
            .with_prompt("SSH Username")
            .default(default_user)
            .interact_text()?
    };

    // Get SSH key path with default
    let default_key = dirs::home_dir()
        .map(|h| h.join(".ssh/id_rsa").display().to_string())
        .unwrap_or_else(|| "~/.ssh/id_rsa".to_string());
    let identity_file: String = if yes {
        default_key
    } else {
        Input::new()
            .with_prompt("SSH Key Path")
            .default(default_key)
            .interact_text()?
    };

    // Get worker ID with default based on hostname
    let default_id = hostname
        .split('.')
        .next()
        .unwrap_or(&hostname)
        .replace(|c: char| !c.is_alphanumeric() && c != '-', "-");
    let worker_id: String = if yes {
        default_id
    } else {
        Input::new()
            .with_prompt("Worker ID (short name)")
            .default(default_id)
            .interact_text()?
    };
    println!();

    // Step 2: Test SSH connection
    println!("{}", style.highlight("Step 2/5: Testing SSH Connection"));
    print!(
        "  {} Connecting to {}@{}... ",
        StatusIndicator::Info.display(style),
        style.highlight(&username),
        style.highlight(&hostname)
    );

    // Build SSH test command
    let mut cmd = Command::new("ssh");
    cmd.arg("-o").arg("BatchMode=yes");
    cmd.arg("-o").arg("ConnectTimeout=10");
    cmd.arg("-o").arg("StrictHostKeyChecking=accept-new");
    cmd.arg("-i").arg(&identity_file);

    let target = format!("{}@{}", username, hostname);
    cmd.arg(&target);
    cmd.arg("echo 'RCH_TEST_OK'");

    let output = cmd.output().await;
    match output {
        Ok(out) if out.status.success() => {
            println!("{}", style.success("OK"));
        }
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            println!("{}", style.error("FAILED"));
            println!();
            println!(
                "  {} SSH connection failed: {}",
                StatusIndicator::Error.display(style),
                style.error(stderr.trim())
            );
            println!();
            println!("  {} Check:", style.muted("→"));
            println!("      - SSH key exists and has correct permissions");
            println!("      - Hostname/IP is correct and reachable");
            println!("      - User has SSH access to the host");
            return Ok(());
        }
        Err(e) => {
            println!("{}", style.error("ERROR"));
            println!();
            println!(
                "  {} Failed to run SSH: {}",
                StatusIndicator::Error.display(style),
                style.error(&e.to_string())
            );
            return Ok(());
        }
    }
    println!();

    // Step 3: Check for Rust installation
    println!("{}", style.highlight("Step 3/5: Checking Rust Installation"));
    print!(
        "  {} Checking for Rust... ",
        StatusIndicator::Info.display(style)
    );

    let mut cmd = Command::new("ssh");
    cmd.arg("-o").arg("BatchMode=yes");
    cmd.arg("-o").arg("ConnectTimeout=10");
    cmd.arg("-i").arg(&identity_file);
    cmd.arg(&target);
    cmd.arg("rustc --version 2>/dev/null || echo 'NOT_INSTALLED'");

    let output = cmd.output().await;
    let rust_installed = match output {
        Ok(out) if out.status.success() => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            if stdout.contains("NOT_INSTALLED") {
                println!("{}", style.warning("NOT FOUND"));
                println!();
                println!(
                    "  {} Rust is not installed on the remote host.",
                    StatusIndicator::Warning.display(style)
                );
                println!(
                    "  {} You can install it later with: rch workers sync-toolchain",
                    style.muted("→")
                );
                false
            } else {
                let version = stdout.trim();
                println!("{} {}", style.success("OK"), style.muted(version));
                true
            }
        }
        _ => {
            println!("{}", style.warning("UNKNOWN"));
            false
        }
    };
    println!();

    // Step 4: Confirm and save
    println!("{}", style.highlight("Step 4/5: Review Configuration"));
    println!();
    println!("  {} {}", style.key("Worker ID:"), style.value(&worker_id));
    println!("  {} {}", style.key("Host:"), style.value(&hostname));
    println!("  {} {}", style.key("User:"), style.value(&username));
    println!(
        "  {} {}",
        style.key("SSH Key:"),
        style.value(&identity_file)
    );
    println!(
        "  {} {}",
        style.key("Rust:"),
        if rust_installed {
            style.success("Installed")
        } else {
            style.warning("Not installed")
        }
    );
    println!();

    let proceed = if yes {
        true
    } else {
        Confirm::new()
            .with_prompt("Save this worker configuration?")
            .default(true)
            .interact()
            .unwrap_or(false)
    };

    if !proceed {
        println!();
        println!(
            "  {} Configuration not saved.",
            StatusIndicator::Info.display(style)
        );
        return Ok(());
    }
    println!();

    // Step 5: Save to workers.toml
    println!("{}", style.highlight("Step 5/5: Saving Configuration"));

    // Load existing workers
    let mut workers = load_workers_from_config().unwrap_or_default();

    // Check for duplicate ID
    if workers.iter().any(|w| w.id.as_str() == worker_id) {
        println!(
            "  {} Worker ID '{}' already exists in configuration.",
            StatusIndicator::Warning.display(style),
            worker_id
        );
        let overwrite = if yes {
            false
        } else {
            Confirm::new()
                .with_prompt("Overwrite existing worker?")
                .default(false)
                .interact()
                .unwrap_or(false)
        };

        if !overwrite {
            println!();
            println!(
                "  {} Configuration not changed.",
                StatusIndicator::Info.display(style)
            );
            return Ok(());
        }

        workers.retain(|w| w.id.as_str() != worker_id);
    }

    // Create new worker config
    let new_worker = WorkerConfig {
        id: WorkerId::new(&worker_id),
        host: hostname.clone(),
        user: username.clone(),
        identity_file: identity_file.clone(),
        total_slots: 8, // Default
        priority: 100,  // Default
        tags: vec![],
    };

    workers.push(new_worker);

    // Save to file
    let config_path = config_dir()?.join("workers.toml");

    // Build TOML content
    let mut toml_content = String::new();
    for w in &workers {
        toml_content.push_str(&format!("[[workers]]\n"));
        toml_content.push_str(&format!("id = \"{}\"\n", w.id));
        toml_content.push_str(&format!("host = \"{}\"\n", w.host));
        toml_content.push_str(&format!("user = \"{}\"\n", w.user));
        toml_content.push_str(&format!("identity_file = \"{}\"\n", w.identity_file));
        toml_content.push_str(&format!("total_slots = {}\n", w.total_slots));
        toml_content.push_str(&format!("priority = {}\n", w.priority));
        if !w.tags.is_empty() {
            toml_content
                .push_str(&format!("tags = [{}]\n", w.tags.iter().map(|t| format!("\"{}\"", t)).collect::<Vec<_>>().join(", ")));
        }
        toml_content.push('\n');
    }

    std::fs::write(&config_path, toml_content).context("Failed to write workers.toml")?;

    println!(
        "  {} Worker '{}' added to {}",
        StatusIndicator::Success.display(style),
        style.highlight(&worker_id),
        style.muted(&config_path.display().to_string())
    );
    println!();

    // Next steps
    println!("{}", style.highlight("Next steps:"));
    if !rust_installed {
        println!(
            "  {} Install Rust: {}",
            style.muted("1."),
            style.highlight("rch workers sync-toolchain")
        );
        println!(
            "  {} Deploy worker: {}",
            style.muted("2."),
            style.highlight("rch workers deploy-binary")
        );
    } else {
        println!(
            "  {} Deploy worker: {}",
            style.muted("1."),
            style.highlight("rch workers deploy-binary")
        );
    }
    println!(
        "  {} Start daemon: {}",
        style.muted("→"),
        style.highlight("rch daemon start")
    );
    println!(
        "  {} Or run '{}' to list all workers.",
        style.muted("→"),
        style.highlight("rch workers list")
    );

    Ok(())
}

// =============================================================================
// Workers Discover Command
// =============================================================================

/// Discover potential workers from SSH config and shell aliases.
pub async fn workers_discover(
    probe: bool,
    add: bool,
    yes: bool,
    ctx: &OutputContext,
) -> Result<()> {
    let style = ctx.theme();

    // Discover hosts from SSH config and shell aliases
    let hosts = discover_all().context("Failed to discover hosts")?;

    if hosts.is_empty() {
        if ctx.is_json() {
            let _ = ctx.json(&ApiResponse::ok(
                "workers discover",
                serde_json::json!({
                    "discovered": [],
                    "message": "No potential workers found"
                }),
            ));
        } else {
            println!(
                "{} No potential workers found in SSH config or shell aliases.",
                StatusIndicator::Warning.display(style)
            );
            println!();
            println!("  {} Checked:", style.muted("→"));
            println!("      ~/.ssh/config");
            println!("      ~/.bashrc, ~/.zshrc");
            println!("      ~/.bash_aliases, ~/.zsh_aliases");
        }
        return Ok(());
    }

    // If probing, test each host
    let probed_hosts: Vec<(DiscoveredHost, Option<ProbeInfo>)> = if probe {
        let mut results = Vec::new();
        for host in &hosts {
            let info = probe_host(host).await.ok();
            results.push((host.clone(), info));
        }
        results
    } else {
        hosts.iter().map(|h| (h.clone(), None)).collect()
    };

    if ctx.is_json() {
        let discovered: Vec<_> = probed_hosts
            .iter()
            .map(|(host, info)| {
                serde_json::json!({
                    "hostname": host.hostname,
                    "user": host.user,
                    "identity_file": host.identity_file,
                    "source": format!("{:?}", host.source),
                    "probe_info": info.as_ref().map(|i| serde_json::json!({
                        "reachable": true,
                        "cores": i.cores,
                        "memory_gb": i.memory_gb,
                        "disk_gb": i.disk_gb,
                        "arch": i.arch,
                        "rust_version": i.rust_version,
                    }))
                })
            })
            .collect();

        let _ = ctx.json(&ApiResponse::ok(
            "workers discover",
            serde_json::json!({
                "discovered": discovered,
                "count": discovered.len()
            }),
        ));
        return Ok(());
    }

    // Human-readable output
    println!("{}", style.format_header("Discovered Potential Workers"));
    println!();

    for (i, (host, info)) in probed_hosts.iter().enumerate() {
        let status = if let Some(ref probe_info) = info {
            StatusIndicator::Success.display(style)
        } else if probe {
            StatusIndicator::Error.display(style)
        } else {
            StatusIndicator::Pending.display(style)
        };

        println!(
            "  {} {}. {}@{}",
            status,
            i + 1,
            style.highlight(&host.user),
            style.highlight(&host.hostname)
        );

        if let Some(ref identity) = host.identity_file {
            println!("      {} {}", style.muted("Key:"), style.value(identity));
        }
        println!(
            "      {} {:?}",
            style.muted("Source:"),
            host.source
        );

        if let Some(ref probe_info) = info {
            println!(
                "      {} {}",
                style.muted("System:"),
                style.value(&probe_info.summary())
            );
        }
        println!();
    }

    println!(
        "{} {} potential workers discovered",
        style.muted("Total:"),
        style.highlight(&hosts.len().to_string())
    );
    println!();

    if !probe {
        println!("  {} Next steps:", style.muted("Hint"));
        println!("      rch workers discover --probe   # Test SSH connectivity");
        println!("      rch workers discover --add --yes  # Add to workers.toml");
    }

    Ok(())
}

// =============================================================================
// Helper Types and Functions
// =============================================================================

/// Information gathered when probing a host.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ProbeInfo {
    cores: u32,
    memory_gb: u32,
    disk_gb: u32,
    arch: String,
    rust_version: Option<String>,
}

impl ProbeInfo {
    fn summary(&self) -> String {
        let rust = self.rust_version.as_deref().unwrap_or("not installed");
        format!(
            "{} cores, {}GB RAM, {}GB free, {} ({})",
            self.cores, self.memory_gb, self.disk_gb, self.arch, rust
        )
    }
}

/// Probe a discovered host to check connectivity and get comprehensive system info.
async fn probe_host(host: &DiscoveredHost) -> Result<ProbeInfo> {
    // Build SSH command with a comprehensive probe script
    let mut cmd = Command::new("ssh");
    cmd.arg("-o").arg("BatchMode=yes");
    cmd.arg("-o").arg("ConnectTimeout=10");
    cmd.arg("-o").arg("StrictHostKeyChecking=accept-new");

    if let Some(ref identity) = host.identity_file {
        cmd.arg("-i").arg(identity);
    }

    let target = format!("{}@{}", host.user, host.hostname);
    cmd.arg(&target);

    // Single command that gathers all info in a parseable format
    let probe_script = r#"echo "CORES:$(nproc 2>/dev/null || echo 0)"; \
echo "MEM:$(free -g 2>/dev/null | awk '/Mem:/{print $2}' || echo 0)"; \
echo "DISK:$(df -BG /tmp 2>/dev/null | awk 'NR==2{gsub("G","",$4); print $4}' || echo 0)"; \
echo "RUST:$(rustc --version 2>/dev/null || echo none)"; \
echo "ARCH:$(uname -m 2>/dev/null || echo unknown)""#;

    cmd.arg(probe_script);

    let output = cmd.output().await.context("Failed to execute SSH")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let message = if stderr.trim().is_empty() {
            stdout.trim()
        } else {
            stderr.trim()
        };
        let key_path = ssh_key_path_from_identity(host.identity_file.as_deref());
        let ssh_error = classify_ssh_error_message(
            &host.hostname,
            &host.user,
            key_path,
            message,
        );
        return Err(ssh_error.into());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Parse the output
    let mut cores = 0u32;
    let mut memory_gb = 0u32;
    let mut disk_gb = 0u32;
    let mut arch = "unknown".to_string();
    let mut rust_version = None;

    for line in stdout.lines() {
        if let Some(val) = line.strip_prefix("CORES:") {
            cores = val.trim().parse().unwrap_or(0);
        } else if let Some(val) = line.strip_prefix("MEM:") {
            memory_gb = val.trim().parse().unwrap_or(0);
        } else if let Some(val) = line.strip_prefix("DISK:") {
            disk_gb = val.trim().parse().unwrap_or(0);
        } else if let Some(val) = line.strip_prefix("ARCH:") {
            arch = val.trim().to_string();
        } else if let Some(val) = line.strip_prefix("RUST:") {
            if val.trim() != "none" {
                rust_version = Some(val.trim().to_string());
            }
        }
    }

    Ok(ProbeInfo {
        cores,
        memory_gb,
        disk_gb,
        arch,
        rust_version,
    })
}
