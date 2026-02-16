//! Daemon lifecycle management commands.
//!
//! This module contains commands for starting, stopping, restarting, and managing
//! the RCH daemon process.

use crate::status_types::extract_json_body;
use crate::ui::context::OutputContext;
use crate::ui::theme::StatusIndicator;
use anyhow::Result;
use rch_common::{ApiError, ApiResponse, ErrorCode};
use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use tokio::process::Command;

use super::helpers::default_socket_path;
use super::types::{
    DaemonActionResponse, DaemonLogsResponse, DaemonReloadResponse, DaemonStatusResponse,
};
use super::{config_dir, send_daemon_command};

#[derive(Debug, Deserialize)]
struct ReloadApiResponse {
    #[serde(default = "reload_success_default")]
    success: bool,
    #[serde(default)]
    added: usize,
    #[serde(default)]
    updated: usize,
    #[serde(default)]
    removed: usize,
    #[serde(default)]
    warnings: Vec<String>,
    #[serde(default)]
    error: Option<String>,
}

fn reload_success_default() -> bool {
    true
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Helper to get rchd path.
fn which_rchd() -> PathBuf {
    // Try to find rchd in same directory as current executable
    if let Ok(exe_path) = std::env::current_exe()
        && let Some(dir) = exe_path.parent()
    {
        let rchd = dir.join("rchd");
        if rchd.exists() {
            return rchd;
        }
    }

    // Fallback to path lookup
    which::which("rchd").unwrap_or_else(|_| PathBuf::from("rchd"))
}

// =============================================================================
// Daemon Commands
// =============================================================================

/// Check daemon status.
pub fn daemon_status(ctx: &OutputContext) -> Result<()> {
    let socket_path_str = default_socket_path();
    let socket_path = Path::new(&socket_path_str);
    let style = ctx.theme();

    let running = socket_path.exists();
    let uptime_seconds = if running {
        std::fs::metadata(socket_path)
            .ok()
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.elapsed().ok())
            .map(|d| d.as_secs())
    } else {
        None
    };

    if ctx.is_json() {
        let _ = ctx.json(&ApiResponse::ok(
            "daemon status",
            DaemonStatusResponse {
                running,
                socket_path: socket_path_str.clone(),
                uptime_seconds,
            },
        ));
        return Ok(());
    }

    println!("{}", style.format_header("RCH Daemon Status"));
    println!();

    if running {
        println!(
            "  {} {} {}",
            style.key("Status"),
            style.muted(":"),
            StatusIndicator::Success.with_label(style, "Running")
        );
        println!(
            "  {} {} {}",
            style.key("Socket"),
            style.muted(":"),
            style.value(&socket_path_str)
        );

        if let Some(secs) = uptime_seconds {
            let hours = secs / 3600;
            let mins = (secs % 3600) / 60;
            println!(
                "  {} {} ~{}h {}m",
                style.key("Uptime"),
                style.muted(":"),
                hours,
                mins
            );
        }
    } else {
        println!(
            "  {} {} {}",
            style.key("Status"),
            style.muted(":"),
            StatusIndicator::Error.with_label(style, "Not running")
        );
        println!(
            "  {} {} {} {}",
            style.key("Socket"),
            style.muted(":"),
            style.muted(&socket_path_str),
            style.muted("(not found)")
        );
        println!();
        println!(
            "  {} Start with: {}",
            StatusIndicator::Info.display(style),
            style.highlight("rch daemon start")
        );
    }

    Ok(())
}

/// Start the daemon.
pub async fn daemon_start(ctx: &OutputContext) -> Result<()> {
    let style = ctx.theme();
    let socket_path_str = default_socket_path();
    let socket_path = Path::new(&socket_path_str);

    if socket_path.exists() {
        if ctx.is_json() {
            let _ = ctx.json(&ApiResponse::ok(
                "daemon start",
                DaemonActionResponse {
                    action: "start".to_string(),
                    success: false,
                    socket_path: socket_path_str.clone(),
                    message: Some("Daemon already running".to_string()),
                },
            ));
        } else {
            println!(
                "{} Daemon appears to already be running.",
                StatusIndicator::Warning.display(style)
            );
            println!(
                "  {} {} {}",
                style.key("Socket"),
                style.muted(":"),
                style.value(&socket_path_str)
            );
            println!(
                "\n{} Use {} to restart it.",
                StatusIndicator::Info.display(style),
                style.highlight("rch daemon restart")
            );
        }
        return Ok(());
    }

    // Check if rchd binary exists
    let rchd_path = which_rchd();

    if !ctx.is_json() {
        println!("Starting RCH daemon...");
    }
    tracing::debug!("Using rchd binary: {:?}", rchd_path);

    // Spawn rchd in background using nohup to detach from terminal
    // This avoids needing unsafe code for setsid()
    let mut cmd = Command::new("nohup");
    cmd.arg(&rchd_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .stdin(Stdio::null())
        .kill_on_drop(false);

    match cmd.spawn() {
        Ok(_child) => {
            // Wait a moment for the socket to appear
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;

            if socket_path.exists() {
                if ctx.is_json() {
                    let _ = ctx.json(&ApiResponse::ok(
                        "daemon start",
                        DaemonActionResponse {
                            action: "start".to_string(),
                            success: true,
                            socket_path: socket_path_str.clone(),
                            message: Some("Daemon started successfully".to_string()),
                        },
                    ));
                } else {
                    println!(
                        "{}",
                        StatusIndicator::Success.with_label(style, "Daemon started successfully.")
                    );
                    println!(
                        "  {} {} {}",
                        style.key("Socket"),
                        style.muted(":"),
                        style.value(&socket_path_str)
                    );
                }
            } else if ctx.is_json() {
                let _ = ctx.json(&ApiResponse::ok(
                    "daemon start",
                    DaemonActionResponse {
                        action: "start".to_string(),
                        success: false,
                        socket_path: socket_path_str.clone(),
                        message: Some("Process started but socket not found".to_string()),
                    },
                ));
            } else {
                println!(
                    "{} Daemon process started but socket not found.",
                    StatusIndicator::Warning.display(style)
                );
                println!(
                    "  {} Check logs with: {}",
                    StatusIndicator::Info.display(style),
                    style.highlight("rch daemon logs")
                );
            }
        }
        Err(e) => {
            if ctx.is_json() {
                let _ = ctx.json(&ApiResponse::<()>::err(
                    "daemon start",
                    ApiError::internal(e.to_string()),
                ));
            } else {
                println!(
                    "{} Failed to start daemon: {}",
                    StatusIndicator::Error.display(style),
                    style.muted(&e.to_string())
                );
                println!(
                    "\n{} Make sure {} is in your PATH or installed.",
                    StatusIndicator::Info.display(style),
                    style.highlight("rchd")
                );
            }
        }
    }

    Ok(())
}

/// Stop the daemon.
///
/// If `skip_confirm` is false and there are active builds, prompts for confirmation.
pub async fn daemon_stop(skip_confirm: bool, ctx: &OutputContext) -> Result<()> {
    use dialoguer::Confirm;

    let style = ctx.theme();
    let socket_path_str = default_socket_path();
    let socket_path = Path::new(&socket_path_str);

    if !socket_path.exists() {
        if ctx.is_json() {
            let _ = ctx.json(&ApiResponse::ok(
                "daemon stop",
                DaemonActionResponse {
                    action: "stop".to_string(),
                    success: true,
                    socket_path: socket_path_str.clone(),
                    message: Some("Daemon was not running".to_string()),
                },
            ));
        } else {
            println!(
                "{} Daemon is not running {}",
                StatusIndicator::Pending.display(style),
                style.muted("(socket not found)")
            );
        }
        return Ok(());
    }

    // Check for active builds and prompt for confirmation
    if !skip_confirm
        && !ctx.is_json()
        && let Ok(response) = send_daemon_command("GET /status\n").await
        && let Some(json) = extract_json_body(&response)
        && let Ok(status) =
            serde_json::from_str::<crate::status_types::DaemonFullStatusResponse>(json)
    {
        let active_count = status.active_builds.len();
        if active_count > 0 {
            println!(
                "{} {} active build(s) will be interrupted.",
                StatusIndicator::Warning.display(style),
                style.highlight(&active_count.to_string())
            );
            let confirmed = Confirm::new()
                .with_prompt("Stop the daemon anyway?")
                .default(false)
                .interact()?;
            if !confirmed {
                println!("{} Aborted.", StatusIndicator::Info.display(style));
                return Ok(());
            }
        }
    }

    if !ctx.is_json() {
        println!("Stopping RCH daemon...");
    }

    // Try graceful shutdown via socket
    match send_daemon_command("POST /shutdown\n").await {
        Ok(_) => {
            // Wait for socket to disappear
            for _ in 0..10 {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                if !socket_path.exists() {
                    if ctx.is_json() {
                        let _ = ctx.json(&ApiResponse::ok(
                            "daemon stop",
                            DaemonActionResponse {
                                action: "stop".to_string(),
                                success: true,
                                socket_path: socket_path_str.clone(),
                                message: Some("Daemon stopped".to_string()),
                            },
                        ));
                    } else {
                        println!(
                            "{}",
                            StatusIndicator::Success.with_label(style, "Daemon stopped.")
                        );
                    }
                    return Ok(());
                }
            }
            if ctx.is_json() {
                let _ = ctx.json(&ApiResponse::ok(
                    "daemon stop",
                    DaemonActionResponse {
                        action: "stop".to_string(),
                        success: false,
                        socket_path: socket_path_str.clone(),
                        message: Some("Daemon may still be shutting down".to_string()),
                    },
                ));
            } else {
                println!(
                    "{} Daemon may still be shutting down...",
                    StatusIndicator::Warning.display(style)
                );
            }
        }
        Err(_) => {
            if ctx.is_json() {
                let _ = ctx.json(&ApiResponse::<()>::err(
                    "daemon stop",
                    ApiError::internal("Could not send shutdown command"),
                ));
            } else {
                println!(
                    "{} Could not send shutdown command.",
                    StatusIndicator::Warning.display(style)
                );
                println!("Attempting to find and kill daemon process...");
            }

            // Try pkill
            let output = Command::new("pkill").arg("-f").arg("rchd").output().await;

            match output {
                Ok(o) if o.status.success() => {
                    // Remove stale socket
                    let _ = std::fs::remove_file(socket_path);
                    if ctx.is_json() {
                        let _ = ctx.json(&ApiResponse::ok(
                            "daemon stop",
                            DaemonActionResponse {
                                action: "stop".to_string(),
                                success: true,
                                socket_path: socket_path_str.clone(),
                                message: Some("Daemon stopped via pkill".to_string()),
                            },
                        ));
                    } else {
                        println!(
                            "{}",
                            StatusIndicator::Success.with_label(style, "Daemon stopped.")
                        );
                    }
                }
                _ => {
                    if ctx.is_json() {
                        let _ = ctx.json(&ApiResponse::<()>::err(
                            "daemon stop",
                            ApiError::internal("Could not stop daemon"),
                        ));
                    } else {
                        println!(
                            "{} Could not stop daemon. You may need to kill it manually.",
                            StatusIndicator::Error.display(style)
                        );
                        println!(
                            "  {} Try: {}",
                            StatusIndicator::Info.display(style),
                            style.highlight("pkill -9 rchd")
                        );
                    }
                }
            }
        }
    }

    Ok(())
}

/// Restart the daemon.
///
/// If `skip_confirm` is false and there are active builds, prompts for confirmation.
pub async fn daemon_restart(skip_confirm: bool, ctx: &OutputContext) -> Result<()> {
    use dialoguer::Confirm;

    let style = ctx.theme();

    // Check for active builds and prompt for confirmation before restarting
    let socket_path_str = default_socket_path();
    let socket_path = Path::new(&socket_path_str);
    if !skip_confirm
        && !ctx.is_json()
        && socket_path.exists()
        && let Ok(response) = send_daemon_command("GET /status\n").await
        && let Some(json) = extract_json_body(&response)
        && let Ok(status) =
            serde_json::from_str::<crate::status_types::DaemonFullStatusResponse>(json)
    {
        let active_count = status.active_builds.len();
        if active_count > 0 {
            println!(
                "{} {} active build(s) will be interrupted.",
                StatusIndicator::Warning.display(style),
                style.highlight(&active_count.to_string())
            );
            let confirmed = Confirm::new()
                .with_prompt("Restart the daemon anyway?")
                .default(false)
                .interact()?;
            if !confirmed {
                println!("{} Aborted.", StatusIndicator::Info.display(style));
                return Ok(());
            }
        }
    }

    if !ctx.is_json() {
        println!(
            "{} Restarting RCH daemon...\n",
            StatusIndicator::Info.display(style)
        );
    }
    // Pass true for skip_confirm since we already prompted above
    daemon_stop(true, ctx).await?;
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    daemon_start(ctx).await?;
    Ok(())
}

/// Reload daemon configuration without restart.
pub async fn daemon_reload(ctx: &OutputContext) -> Result<()> {
    let style = ctx.theme();

    // Check if daemon is running
    if !Path::new(&default_socket_path()).exists() {
        if ctx.is_json() {
            let _ = ctx.json(&ApiResponse::<()>::err(
                "daemon reload",
                ApiError::new(ErrorCode::InternalDaemonNotRunning, "Daemon is not running"),
            ));
        } else {
            println!(
                "{} Daemon is not running. Start it with {}",
                StatusIndicator::Error.display(style),
                style.highlight("rch daemon start")
            );
        }
        return Ok(());
    }

    if !ctx.is_json() {
        println!(
            "{} Reloading daemon configuration...",
            StatusIndicator::Info.display(style)
        );
    }

    // Send reload command to daemon
    match send_daemon_command("POST /reload\n").await {
        Ok(response) => {
            let json = extract_json_body(&response)
                .unwrap_or(response.as_str())
                .trim();
            match serde_json::from_str::<ReloadApiResponse>(json) {
                Ok(reload) => {
                    if !reload.success {
                        let error_msg = reload
                            .error
                            .unwrap_or_else(|| "unknown reload error".to_string());
                        if ctx.is_json() {
                            let _ = ctx.json(&ApiResponse::<()>::err(
                                "daemon reload",
                                ApiError::internal(format!("Reload failed: {}", error_msg)),
                            ));
                        } else {
                            println!(
                                "{} Reload failed: {}",
                                StatusIndicator::Error.display(style),
                                error_msg
                            );
                        }
                        return Ok(());
                    }

                    let has_changes = reload.added > 0 || reload.updated > 0 || reload.removed > 0;

                    if ctx.is_json() {
                        let _ = ctx.json(&ApiResponse::ok(
                            "daemon reload",
                            DaemonReloadResponse {
                                success: true,
                                added: reload.added,
                                updated: reload.updated,
                                removed: reload.removed,
                                warnings: reload.warnings.clone(),
                                message: if has_changes {
                                    Some(format!(
                                        "Configuration reloaded: {} added, {} updated, {} removed",
                                        reload.added, reload.updated, reload.removed
                                    ))
                                } else {
                                    Some("No configuration changes detected".to_string())
                                },
                            },
                        ));
                    } else {
                        if has_changes {
                            println!(
                                "{} Configuration reloaded",
                                StatusIndicator::Success.display(style)
                            );
                            println!(
                                "  {} workers added, {} updated, {} removed",
                                reload.added, reload.updated, reload.removed
                            );
                        } else {
                            println!(
                                "{} No configuration changes detected",
                                StatusIndicator::Info.display(style)
                            );
                        }

                        for warning in &reload.warnings {
                            println!("{} {}", StatusIndicator::Warning.display(style), warning);
                        }
                    }
                }
                Err(e) => {
                    if ctx.is_json() {
                        let _ = ctx.json(&ApiResponse::<()>::err(
                            "daemon reload",
                            ApiError::internal(format!("Failed to parse reload response: {}", e)),
                        ));
                    } else {
                        println!(
                            "{} Failed to parse reload response: {}",
                            StatusIndicator::Error.display(style),
                            e
                        );
                    }
                }
            }
        }
        Err(e) => {
            if ctx.is_json() {
                let _ = ctx.json(&ApiResponse::<()>::err(
                    "daemon reload",
                    ApiError::internal(format!("Failed to communicate with daemon: {}", e)),
                ));
            } else {
                println!(
                    "{} Failed to communicate with daemon: {}",
                    StatusIndicator::Error.display(style),
                    e
                );
            }
        }
    }

    Ok(())
}

/// Show daemon logs.
pub fn daemon_logs(lines: usize, ctx: &OutputContext) -> Result<()> {
    let style = ctx.theme();

    // Try common log file locations first
    let log_paths = vec![
        PathBuf::from("/tmp/rchd.log"),
        config_dir()
            .map(|d| d.join("daemon.log"))
            .unwrap_or_default(),
        config_dir()
            .map(|d| d.join("logs").join("daemon.log"))
            .unwrap_or_default(),
        dirs::cache_dir()
            .map(|d| d.join("rch").join("daemon.log"))
            .unwrap_or_default(),
    ];

    for path in &log_paths {
        if path.exists() {
            let content = std::fs::read_to_string(path)?;
            let all_lines: Vec<&str> = content.lines().collect();
            let start = all_lines.len().saturating_sub(lines);
            let log_lines: Vec<String> = all_lines[start..].iter().map(|s| s.to_string()).collect();

            if ctx.is_json() {
                let _ = ctx.json(&ApiResponse::ok(
                    "daemon logs",
                    DaemonLogsResponse {
                        log_file: Some(path.display().to_string()),
                        lines: log_lines,
                        found: true,
                    },
                ));
            } else {
                println!(
                    "{} {} {}\n",
                    style.key("Log file"),
                    style.muted(":"),
                    style.value(&path.display().to_string())
                );

                for line in &all_lines[start..] {
                    println!("{}", line);
                }
            }

            return Ok(());
        }
    }

    // No log files found - try journald (for systemd service)
    if let Ok(output) = std::process::Command::new("journalctl")
        .args([
            "--user",
            "-u",
            "rchd",
            "-n",
            &lines.to_string(),
            "--no-pager",
        ])
        .output()
        && output.status.success()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let log_lines: Vec<String> = stdout.lines().map(|s| s.to_string()).collect();

        // Check if we got actual log output (not just "No entries")
        if !log_lines.is_empty()
            && !stdout.contains("-- No entries --")
            && !stdout.contains("No journal files were found")
        {
            if ctx.is_json() {
                let _ = ctx.json(&ApiResponse::ok(
                    "daemon logs",
                    DaemonLogsResponse {
                        log_file: Some("journalctl --user -u rchd".to_string()),
                        lines: log_lines,
                        found: true,
                    },
                ));
            } else {
                println!(
                    "{} {} {}\n",
                    style.key("Log source"),
                    style.muted(":"),
                    style.value("journalctl --user -u rchd")
                );

                for line in &log_lines {
                    println!("{}", line);
                }
            }

            return Ok(());
        }
    }

    // No logs found anywhere
    if ctx.is_json() {
        let _ = ctx.json(&ApiResponse::ok(
            "daemon logs",
            DaemonLogsResponse {
                log_file: None,
                lines: vec![],
                found: false,
            },
        ));
    } else {
        println!(
            "{} No log file found.",
            StatusIndicator::Warning.display(style)
        );
        println!("\n{}", style.key("Checked locations:"));
        for path in &log_paths {
            if !path.as_os_str().is_empty() {
                println!("  {}", style.muted(&format!("• {}", path.display())));
            }
        }
        println!("  {}", style.muted("• journalctl --user -u rchd"));
        println!();
        println!(
            "{} If running via systemd, use: {}",
            StatusIndicator::Info.display(style),
            style.highlight("journalctl --user -u rchd -f")
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rch_common::test_guard;

    #[test]
    fn reload_api_response_parses_http_10_with_headers() {
        let _guard = test_guard!();
        let response = "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n{\"success\":true,\"added\":1,\"updated\":2,\"removed\":3,\"warnings\":[\"warn\"]}\n";
        let json = extract_json_body(response).unwrap().trim();
        let parsed: ReloadApiResponse = serde_json::from_str(json).unwrap();
        assert!(parsed.success);
        assert_eq!(parsed.added, 1);
        assert_eq!(parsed.updated, 2);
        assert_eq!(parsed.removed, 3);
        assert_eq!(parsed.warnings, vec!["warn".to_string()]);
    }

    #[test]
    fn reload_api_response_uses_default_success_for_legacy_payloads() {
        let _guard = test_guard!();
        let response = "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n{\"added\":0,\"updated\":0,\"removed\":0,\"warnings\":[]}\n";
        let json = extract_json_body(response).unwrap().trim();
        let parsed: ReloadApiResponse = serde_json::from_str(json).unwrap();
        assert!(parsed.success);
        assert_eq!(parsed.added, 0);
        assert_eq!(parsed.updated, 0);
        assert_eq!(parsed.removed, 0);
        assert!(parsed.warnings.is_empty());
    }

    #[test]
    fn reload_api_response_parses_failure_payload() {
        let _guard = test_guard!();
        let response = "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n{\"success\":false,\"error\":\"bad config\"}\n";
        let json = extract_json_body(response).unwrap().trim();
        let parsed: ReloadApiResponse = serde_json::from_str(json).unwrap();
        assert!(!parsed.success);
        assert_eq!(parsed.error.as_deref(), Some("bad config"));
    }
}
