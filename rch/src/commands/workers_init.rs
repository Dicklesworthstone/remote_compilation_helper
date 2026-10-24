//! Worker initialization and discovery commands.
//!
//! This module contains commands for adding new workers interactively
//! and discovering potential workers from SSH config.

use crate::config::{WorkerEntry, WorkersConfig};
use crate::error::ConfigError;
use crate::ui::context::OutputContext;
use crate::ui::theme::StatusIndicator;
use anyhow::{Context, Result};
use rch_common::{ApiResponse, DiscoveredHost, WorkerConfig, WorkerId, discover_all};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::process::Command;

use super::config_dir;
use super::helpers::{classify_ssh_error_message, ssh_key_path_from_identity};

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
    if let Some(opts) = rch_common::ssh_utils::identities_only_args(&identity_file) {
        cmd.args(opts);
    }

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
    println!(
        "{}",
        style.highlight("Step 3/5: Checking Rust Installation")
    );
    print!(
        "  {} Checking for Rust... ",
        StatusIndicator::Info.display(style)
    );

    let mut cmd = Command::new("ssh");
    cmd.arg("-o").arg("BatchMode=yes");
    cmd.arg("-o").arg("ConnectTimeout=10");
    cmd.arg("-i").arg(&identity_file);
    if let Some(opts) = rch_common::ssh_utils::identities_only_args(&identity_file) {
        cmd.args(opts);
    }
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

    let config_path = config_dir()
        .ok_or_else(|| anyhow::anyhow!("Could not determine config directory"))?
        .join("workers.toml");
    // Work on the file itself, never on the loaded fleet: loading drops
    // disabled workers and `tools` declarations, and a parse error used to
    // become an empty fleet that was then written over the operator's file.
    let existing = match std::fs::read_to_string(&config_path) {
        Ok(text) => Some(text),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => {
            return Err(error).with_context(|| format!("Failed to read {}", config_path.display()));
        }
    };
    let already_configured = existing
        .as_deref()
        .map(|text| workers_toml_has_worker(text, &worker_id))
        .transpose()?
        .unwrap_or(false);

    // Check for duplicate ID (disabled workers included).
    if already_configured {
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
        tools: Vec::new(),
    };

    let toml_content = upsert_worker_entry(existing.as_deref(), &new_worker)?;
    write_file_atomically(&config_path, &toml_content).context("Failed to write workers.toml")?;

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

/// Whether `workers.toml` text already declares `worker_id`, enabled or not.
/// A file that does not parse is an error: never guess about it.
fn workers_toml_has_worker(text: &str, worker_id: &str) -> Result<bool> {
    let table: toml::Table = toml::from_str(text)
        .context("existing workers.toml does not parse; fix it before adding a worker")?;
    Ok(table
        .get("workers")
        .and_then(toml::Value::as_array)
        .is_some_and(|workers| {
            workers
                .iter()
                .any(|worker| worker.get("id").and_then(toml::Value::as_str) == Some(worker_id))
        }))
}

/// Return `existing` with `worker` added, or replacing the entry with the same
/// id.
///
/// Adding appends one `[[workers]]` table to the text unchanged, so comments,
/// disabled workers and every other field survive byte for byte. Replacing (an
/// explicit overwrite) edits the parsed table in place: every other worker keeps
/// all of its fields, though comments are not preserved.
fn upsert_worker_entry(existing: Option<&str>, worker: &WorkerConfig) -> Result<String> {
    let entry_text = serialize_workers_config(std::slice::from_ref(worker))?;
    let Some(text) = existing else {
        return Ok(entry_text);
    };
    let exists = workers_toml_has_worker(text, worker.id.as_str())?;
    if !exists {
        let mut out = text.to_string();
        if !out.is_empty() && !out.ends_with('\n') {
            out.push('\n');
        }
        if !out.is_empty() {
            out.push('\n');
        }
        out.push_str(&entry_text);
        // An inline `workers = [...]` array cannot take an appended
        // `[[workers]]` table; only a result that parses and lists the new
        // worker is kept, otherwise the parsed table is edited instead.
        if workers_toml_has_worker(&out, worker.id.as_str()).unwrap_or(false) {
            return Ok(out);
        }
    }
    let mut table: toml::Table = toml::from_str(text)?;
    let entry = toml::from_str::<toml::Table>(&entry_text)?
        .remove("workers")
        .and_then(|workers| workers.as_array().and_then(|list| list.first().cloned()))
        .ok_or_else(|| anyhow::anyhow!("serialized worker entry is missing"))?;
    let workers = table
        .entry("workers")
        .or_insert_with(|| toml::Value::Array(Vec::new()))
        .as_array_mut()
        .ok_or_else(|| anyhow::anyhow!("workers.toml `workers` is not an array"))?;
    if exists {
        for slot in workers
            .iter_mut()
            .filter(|slot| slot.get("id").and_then(toml::Value::as_str) == Some(worker.id.as_str()))
        {
            // Re-initialising a worker must not re-enable one an operator
            // parked, nor drop its declared tool requirements.
            let mut replacement = entry.clone();
            for key in ["enabled", "tools"] {
                if let (Some(kept), Some(fields)) = (slot.get(key), replacement.as_table_mut()) {
                    fields.insert(key.to_owned(), kept.clone());
                }
            }
            *slot = replacement;
        }
    } else {
        workers.push(entry);
    }
    toml::to_string_pretty(&table).context("Failed to serialize workers.toml")
}

/// Write via a sibling temp file and rename, so a crash or full disk never
/// leaves a truncated workers.toml behind. A symlinked config is written
/// through to its target and the existing file mode is kept.
fn write_file_atomically(path: &std::path::Path, contents: &str) -> std::io::Result<()> {
    // A dangling symlink does not canonicalize; write to its target instead.
    let target = std::fs::canonicalize(path).unwrap_or_else(|_| match std::fs::read_link(path) {
        Ok(link) => path
            .parent()
            .map_or(link.clone(), |parent| parent.join(&link)),
        Err(_) => path.to_path_buf(),
    });
    let tmp = target.with_extension(format!("toml.tmp-{}", std::process::id()));
    let result = std::fs::write(&tmp, contents)
        .and_then(|()| match std::fs::metadata(&target) {
            Ok(existing) => std::fs::set_permissions(&tmp, existing.permissions()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        })
        .and_then(|()| std::fs::rename(&tmp, &target));
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

fn serialize_workers_config(workers: &[WorkerConfig]) -> Result<String> {
    let config = WorkersConfig {
        workers: workers
            .iter()
            .map(|worker| WorkerEntry {
                id: worker.id.to_string(),
                host: worker.host.clone(),
                user: worker.user.clone(),
                identity_file: worker.identity_file.clone(),
                total_slots: worker.total_slots,
                priority: worker.priority,
                // Lift the declaration back out of the reserved tag so the
                // rewritten file keeps the `os = "..."` key an operator wrote,
                // and does not leak `os:windows` into the visible tag list.
                os: rch_common::declared_os(&worker.tags),
                tags: worker
                    .tags
                    .iter()
                    .filter(|tag| !tag.starts_with(rch_common::OS_TAG_PREFIX))
                    .cloned()
                    .collect(),
                enabled: true,
            })
            .collect(),
    };

    toml::to_string_pretty(&config).context("Failed to serialize workers.toml")
}

// =============================================================================
// Workers Discover Command
// =============================================================================

/// Discover potential workers from SSH config and shell aliases.
pub async fn workers_discover(
    probe: bool,
    _add: bool,
    _yes: bool,
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
        let status = if let Some(_probe_info) = info {
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
        println!("      {} {:?}", style.muted("Source:"), host.source);

        if let Some(probe_info) = info {
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
        if let Some(opts) = rch_common::ssh_utils::identities_only_args(identity) {
            cmd.args(opts);
        }
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
            Duration::from_secs(10), // ConnectTimeout used in probe
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
        } else if let Some(val) = line.strip_prefix("RUST:")
            && val.trim() != "none"
        {
            rust_version = Some(val.trim().to_string());
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

#[cfg(test)]
mod tests {
    use super::*;
    use rch_common::test_guard;

    const FLEET: &str = r#"# fleet comment the operator wrote
[[workers]]
id = "live"
host = "10.0.0.1"
user = "ubuntu"
identity_file = "~/.ssh/k"
total_slots = 16
tools = [{ name = "mutool", probe = "mutool -v" }]

[[workers]]
id = "parked"
host = "10.0.0.2"
user = "ubuntu"
identity_file = "~/.ssh/k"
total_slots = 4
enabled = false
"#;

    fn new_worker(id: &str) -> WorkerConfig {
        WorkerConfig {
            id: WorkerId::new(id),
            host: "10.0.0.9".to_string(),
            user: "root".to_string(),
            identity_file: "~/.ssh/new".to_string(),
            total_slots: 8,
            priority: 100,
            tags: vec![],
            tools: Vec::new(),
        }
    }

    /// Adding a worker must not drop disabled workers, `tools` declarations
    /// or the operator's comments (the old path rewrote the file from the
    /// loaded fleet, which filters all three out).
    #[test]
    fn upsert_worker_entry_appends_without_touching_existing_text() {
        let _guard = test_guard!();
        let out = upsert_worker_entry(Some(FLEET), &new_worker("added")).unwrap();
        assert!(
            out.starts_with(FLEET),
            "existing text must survive verbatim"
        );
        let table: toml::Table = toml::from_str(&out).unwrap();
        let workers = table["workers"].as_array().unwrap();
        let ids: Vec<&str> = workers.iter().map(|w| w["id"].as_str().unwrap()).collect();
        assert_eq!(ids, ["live", "parked", "added"]);
        assert_eq!(workers[1]["enabled"].as_bool(), Some(false));
        assert!(workers[0].get("tools").is_some());
    }

    #[test]
    fn upsert_worker_entry_replaces_only_the_matching_worker() {
        let _guard = test_guard!();
        assert!(workers_toml_has_worker(FLEET, "parked").unwrap());
        let out = upsert_worker_entry(Some(FLEET), &new_worker("parked")).unwrap();
        let table: toml::Table = toml::from_str(&out).unwrap();
        let workers = table["workers"].as_array().unwrap();
        assert_eq!(workers.len(), 2);
        assert!(
            workers[0].get("tools").is_some(),
            "other workers keep all fields"
        );
        assert_eq!(workers[1]["host"].as_str(), Some("10.0.0.9"));
        assert_eq!(
            workers[1]["enabled"].as_bool(),
            Some(false),
            "re-init must not re-enable a parked worker"
        );
    }

    #[test]
    fn upsert_worker_entry_adds_to_an_inline_workers_array() {
        let _guard = test_guard!();
        let inline = "workers = [{ id = \"a\", host = \"h\", user = \"u\", identity_file = \"~/.ssh/k\", total_slots = 2 }]\n";
        let out = upsert_worker_entry(Some(inline), &new_worker("b")).unwrap();
        let table: toml::Table = toml::from_str(&out).expect("result must parse");
        let ids: Vec<&str> = table["workers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|w| w["id"].as_str().unwrap())
            .collect();
        assert_eq!(ids, ["a", "b"]);
    }

    #[cfg(unix)]
    #[test]
    fn write_file_atomically_creates_the_target_of_a_dangling_symlink() {
        let _guard = test_guard!();
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("dotfiles")).unwrap();
        let link = dir.path().join("workers.toml");
        std::os::unix::fs::symlink("dotfiles/workers.toml", &link).unwrap();

        write_file_atomically(&link, "new").unwrap();

        assert!(
            std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(
            std::fs::read_to_string(dir.path().join("dotfiles/workers.toml")).unwrap(),
            "new"
        );
    }

    #[cfg(unix)]
    #[test]
    fn write_file_atomically_writes_through_a_symlink_and_keeps_the_mode() {
        use std::os::unix::fs::PermissionsExt;
        let _guard = test_guard!();
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real.toml");
        std::fs::write(&real, "old").unwrap();
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o600)).unwrap();
        let link = dir.path().join("workers.toml");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        write_file_atomically(&link, "new").unwrap();

        assert!(
            std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(std::fs::read_to_string(&real).unwrap(), "new");
        assert_eq!(
            std::fs::metadata(&real).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::read_dir(dir.path()).unwrap().count(),
            2,
            "temp file left behind"
        );
    }

    /// A workers.toml that does not parse must stop the write, not be
    /// replaced by a file holding only the new worker.
    #[test]
    fn upsert_worker_entry_refuses_unparseable_file() {
        let _guard = test_guard!();
        let broken = "[[workers]]\nid = \"a\"\nhost = \n";
        assert!(upsert_worker_entry(Some(broken), &new_worker("b")).is_err());
        assert!(upsert_worker_entry(None, &new_worker("b")).is_ok());
    }

    #[test]
    fn serialize_workers_config_escapes_toml_strings() {
        let _guard = test_guard!();
        let attempted_injection = "worker.example\"\n[[workers]]\nid = \"injected";
        let workers = vec![WorkerConfig {
            id: WorkerId::new("safe-worker"),
            host: attempted_injection.to_string(),
            user: "ubuntu\"admin".to_string(),
            identity_file: "/tmp/key path/with\\slash\"and-quote".to_string(),
            total_slots: 8,
            priority: 100,
            tags: vec!["rust\"fast".to_string(), "gpu\nprod".to_string()],
            tools: Vec::new(),
        }];

        let rendered = serialize_workers_config(&workers).expect("serialize workers config");
        let parsed: WorkersConfig =
            toml::from_str(&rendered).expect("serialized workers config must parse");

        assert_eq!(parsed.workers.len(), 1);
        assert_eq!(parsed.workers[0].id, "safe-worker");
        assert_eq!(parsed.workers[0].host, attempted_injection);
        assert_eq!(parsed.workers[0].user, "ubuntu\"admin");
        assert_eq!(
            parsed.workers[0].identity_file,
            "/tmp/key path/with\\slash\"and-quote"
        );
        assert_eq!(
            parsed.workers[0].tags,
            vec!["rust\"fast".to_string(), "gpu\nprod".to_string()]
        );
    }
}
