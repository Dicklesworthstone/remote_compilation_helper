//! Status display rendering for the rch CLI.
//!
//! This module contains helper functions for rendering daemon status
//! in both comprehensive (when daemon is running) and basic (when daemon
//! is stopped) modes.

use crate::status_types::{
    DaemonFullStatusResponse, extract_json_body, format_duration,
};
use crate::ui::style::Style;
use anyhow::{Context, Result};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tracing::debug;

/// Default daemon socket path.
pub const DEFAULT_SOCKET_PATH: &str = "/tmp/rch.sock";

/// Query daemon's /status API for comprehensive status.
pub async fn query_daemon_full_status() -> Result<DaemonFullStatusResponse> {
    let response = send_status_command().await?;

    // Extract JSON body from HTTP response
    let json_body = extract_json_body(&response)
        .ok_or_else(|| anyhow::anyhow!("Invalid response format"))?;

    let status: DaemonFullStatusResponse =
        serde_json::from_str(json_body).context("Failed to parse status response")?;

    Ok(status)
}

/// Send a status command to the daemon.
async fn send_status_command() -> Result<String> {
    let stream = UnixStream::connect(DEFAULT_SOCKET_PATH)
        .await
        .context("Failed to connect to daemon socket")?;

    let (reader, mut writer) = stream.into_split();

    writer.write_all(b"GET /status\n").await?;
    writer.flush().await?;
    writer.shutdown().await?;

    let mut buf_reader = BufReader::new(reader);
    let mut response = String::new();

    loop {
        let mut line = String::new();
        match buf_reader.read_line(&mut line).await {
            Ok(0) => break,
            Ok(_) => response.push_str(&line),
            Err(e) => return Err(e.into()),
        }
    }

    Ok(response)
}

/// Render comprehensive status from daemon API response.
pub fn render_full_status(
    status: &DaemonFullStatusResponse,
    show_workers: bool,
    show_jobs: bool,
    style: &Style,
) {
    println!("{}", style.format_header("RCH Status"));
    println!();

    // Daemon info
    println!(
        "  {} {} {} (PID {})",
        style.key("Daemon"),
        style.muted(":"),
        style.success("Running"),
        style.highlight(&status.daemon.pid.to_string())
    );
    println!(
        "  {} {} {}",
        style.key("Uptime"),
        style.muted(":"),
        style.info(&format_duration(status.daemon.uptime_secs))
    );
    println!(
        "  {} {} {}",
        style.key("Version"),
        style.muted(":"),
        style.info(&status.daemon.version)
    );

    // Worker summary
    println!(
        "  {} {} {}/{} healthy, {}/{} slots available",
        style.key("Workers"),
        style.muted(":"),
        style.highlight(&status.daemon.workers_healthy.to_string()),
        status.daemon.workers_total,
        style.highlight(&status.daemon.slots_available.to_string()),
        status.daemon.slots_total
    );

    // Build stats
    let success_rate = if status.stats.total_builds > 0 {
        (status.stats.success_count as f64 / status.stats.total_builds as f64) * 100.0
    } else {
        100.0
    };
    println!(
        "  {} {} {} total, {:.0}% success rate",
        style.key("Builds"),
        style.muted(":"),
        style.highlight(&status.stats.total_builds.to_string()),
        success_rate
    );

    // Hook status (check locally)
    let hook_installed = check_hook_installed();
    println!(
        "  {} {} {}",
        style.key("Hook"),
        style.muted(":"),
        if hook_installed {
            style.success("Installed")
        } else {
            style.warning("Not installed")
        }
    );

    // Issues section if any
    if !status.issues.is_empty() {
        println!("\n{}", style.format_header("Issues"));
        for issue in &status.issues {
            let severity_style = match issue.severity.as_str() {
                "critical" | "error" => style.error(&issue.severity),
                "warning" => style.warning(&issue.severity),
                _ => style.info(&issue.severity),
            };
            println!(
                "  {} [{}] {}",
                style.symbols.bullet_filled,
                severity_style,
                issue.summary
            );
            if let Some(remediation) = &issue.remediation {
                println!("    {} {}", style.muted("Fix:"), style.info(remediation));
            }
        }
    }

    // Workers section
    if show_workers {
        render_workers_table(status, style);
    }

    // Jobs/builds section
    if show_jobs {
        render_builds_section(status, style);
    }
}

/// Render the workers table.
fn render_workers_table(status: &DaemonFullStatusResponse, style: &Style) {
    println!("\n{}", style.format_header("Workers"));
    if status.workers.is_empty() {
        println!("  {}", style.muted("(none configured)"));
        return;
    }

    // Table header
    println!(
        "  {:12} {:8} {:10} {:6} {:10} {:8}",
        style.key("ID"),
        style.key("Status"),
        style.key("Circuit"),
        style.key("Slots"),
        style.key("Speed"),
        style.key("Host")
    );
    println!(
        "  {:12} {:8} {:10} {:6} {:10} {:8}",
        "────────────",
        "────────",
        "──────────",
        "──────",
        "──────────",
        "────────"
    );

    for worker in &status.workers {
        let status_display = match worker.status.as_str() {
            "healthy" => style.success("healthy"),
            "unhealthy" => style.error("unhealthy"),
            "draining" => style.warning("draining"),
            _ => style.muted(&worker.status),
        };
        let circuit_display = match worker.circuit_state.as_str() {
            "closed" => style.success("closed"),
            "open" => style.error("open"),
            "half_open" => style.warning("half-open"),
            _ => style.muted(&worker.circuit_state),
        };
        let slots = format!("{}/{}", worker.used_slots, worker.total_slots);
        let speed = format!("{:.1}", worker.speed_score);

        println!(
            "  {:12} {:8} {:10} {:6} {:10} {}@{}",
            style.highlight(&worker.id),
            status_display,
            circuit_display,
            slots,
            speed,
            style.muted(&worker.user),
            style.info(&worker.host)
        );
    }
}

/// Render the builds section (active and recent).
fn render_builds_section(status: &DaemonFullStatusResponse, style: &Style) {
    // Active builds
    println!("\n{}", style.format_header("Active Builds"));
    if status.active_builds.is_empty() {
        println!("  {}", style.muted("(no active builds)"));
    } else {
        for build in &status.active_builds {
            let cmd_display = if build.command.len() > 50 {
                format!("{}...", &build.command[..47])
            } else {
                build.command.clone()
            };
            println!(
                "  {} #{} on {} - {}",
                style.symbols.bullet_filled,
                style.highlight(&build.id.to_string()),
                style.info(&build.worker_id),
                style.muted(&cmd_display)
            );
        }
    }

    // Recent builds
    println!("\n{}", style.format_header("Recent Builds"));
    if status.recent_builds.is_empty() {
        println!("  {}", style.muted("(no recent builds)"));
    } else {
        for build in status.recent_builds.iter().take(10) {
            let status_indicator = if build.exit_code == 0 {
                style.success("✓")
            } else {
                style.error("✗")
            };
            let duration = format!("{:.1}s", build.duration_ms as f64 / 1000.0);
            let location_display = if build.location == "remote" {
                style.info(&build.location)
            } else {
                style.muted(&build.location)
            };
            let cmd_display = if build.command.len() > 40 {
                format!("{}...", &build.command[..37])
            } else {
                build.command.clone()
            };

            println!(
                "  {} {} {:8} {} {}",
                status_indicator,
                style.muted(&duration),
                location_display,
                build
                    .worker_id
                    .as_ref()
                    .map(|w| style.highlight(w))
                    .unwrap_or_else(|| style.muted("-")),
                style.muted(&cmd_display)
            );
        }
    }
}

/// Check if the Claude Code hook is installed.
pub fn check_hook_installed() -> bool {
    dirs::home_dir()
        .map(|h| h.join(".claude").join("settings.json"))
        .map(|p| {
            if p.exists() {
                std::fs::read_to_string(&p)
                    .ok()
                    .map(|c| c.contains("PreToolUse"))
                    .unwrap_or(false)
            } else {
                false
            }
        })
        .unwrap_or(false)
}

/// Render basic status when daemon is not running.
pub fn render_basic_status(daemon_running: bool, show_workers: bool, style: &Style) {
    println!("{}", style.format_header("RCH Status"));
    println!();

    // Daemon status
    println!(
        "  {} {} {}",
        style.key("Daemon"),
        style.muted(":"),
        if daemon_running {
            style.warning("Running (not responding)")
        } else {
            style.error("Stopped")
        }
    );

    if !daemon_running {
        println!(
            "    {} {}",
            style.symbols.bullet_filled,
            style.muted("Start with: rch daemon start")
        );
    }

    // Worker count from config - use a simple message since we don't have load_workers_from_config here
    println!(
        "  {} {} {}",
        style.key("Workers"),
        style.muted(":"),
        style.muted("(check config for details)")
    );

    // Hook status
    let hook_installed = check_hook_installed();
    println!(
        "  {} {} {}",
        style.key("Hook"),
        style.muted(":"),
        if hook_installed {
            style.success("Installed")
        } else {
            style.warning("Not installed")
        }
    );

    if show_workers {
        println!("\n{}", style.format_header("Workers"));
        println!(
            "  {} {}",
            style.symbols.info,
            style.muted("Start daemon for worker status: rch daemon start")
        );
    }

    println!();
    println!(
        "  {} {}",
        style.symbols.info,
        style.warning("Start daemon for live status: rch daemon start")
    );
}
