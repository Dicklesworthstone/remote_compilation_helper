//! Status display rendering for the rch CLI.
//!
//! This module contains helper functions for rendering daemon status
//! in both comprehensive (when daemon is running) and basic (when daemon
//! is stopped) modes.

#![allow(dead_code)]

use crate::status_types::{DaemonFullStatusResponse, extract_json_body, format_duration};
use crate::ui::theme::Theme;
use anyhow::{Context, Result};
use std::path::PathBuf;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

/// Default daemon socket path.
fn default_socket_path() -> PathBuf {
    PathBuf::from(rch_common::default_socket_path())
}

/// Query daemon's /status API for comprehensive status.
pub async fn query_daemon_full_status() -> Result<DaemonFullStatusResponse> {
    let response = send_status_command().await?;

    // Extract JSON body from HTTP response
    let json_body =
        extract_json_body(&response).ok_or_else(|| anyhow::anyhow!("Invalid response format"))?;

    let status: DaemonFullStatusResponse =
        serde_json::from_str(json_body).context("Failed to parse status response")?;

    Ok(status)
}

/// Send a status command to the daemon.
async fn send_status_command() -> Result<String> {
    let stream = UnixStream::connect(default_socket_path())
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
    style: &Theme,
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
                style.symbols.bullet_filled, severity_style, issue.summary
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
fn render_workers_table(status: &DaemonFullStatusResponse, style: &Theme) {
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
        "────────────", "────────", "──────────", "──────", "──────────", "────────"
    );

    for worker in &status.workers {
        let status_display = match worker.status.as_str() {
            "healthy" => style.success("healthy"),
            "unhealthy" => style.error("unhealthy"),
            "draining" => style.warning("draining"),
            _ => style.muted(&worker.status),
        };

        // Enhanced circuit display with recovery timing
        let circuit_display = match worker.circuit_state.as_str() {
            "closed" => style.success("closed"),
            "open" => {
                if let Some(secs) = worker.recovery_in_secs {
                    style.error(&format!("open ({}s)", secs))
                } else {
                    style.error("open")
                }
            }
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

        // Show detailed circuit info for workers with issues
        if worker.circuit_state != "closed" {
            render_circuit_details(worker, style);
        }
    }
}

/// Render detailed circuit breaker information for a worker.
fn render_circuit_details(worker: &crate::status_types::WorkerStatusFromApi, style: &Theme) {
    let (state_name, explanation, help_text) = circuit_state_explanation(
        &worker.circuit_state,
        worker.consecutive_failures,
        worker.recovery_in_secs,
        worker.last_error.as_deref(),
    );

    // Show explanation
    println!(
        "    {} {}",
        style.muted("Circuit:"),
        match worker.circuit_state.as_str() {
            "open" => style.error(state_name),
            "half_open" => style.warning(state_name),
            _ => style.muted(state_name),
        }
    );
    println!("      {}", style.muted(&explanation));

    // Show failure history if available
    if !worker.failure_history.is_empty() {
        let history_visual = format_failure_history(&worker.failure_history);
        println!(
            "    {} {} {}",
            style.muted("History:"),
            history_visual,
            style.muted(&format!("(last {} attempts)", worker.failure_history.len()))
        );
    }

    // Show last error if available
    if let Some(ref error) = worker.last_error {
        let error_truncated = if error.len() > 60 {
            format!("{}...", &error[..57])
        } else {
            error.clone()
        };
        println!(
            "    {} {}",
            style.muted("Reason:"),
            style.error(&error_truncated)
        );
    }

    // Show help text for non-closed circuits
    if !help_text.is_empty() {
        println!("    {} {}", style.muted("Help:"), style.info(help_text));
    }
}

/// Render the builds section (active and recent).
fn render_builds_section(status: &DaemonFullStatusResponse, style: &Theme) {
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

// ============================================================================
// Circuit Breaker Display Helpers
// ============================================================================

/// Format failure history as a visual pattern (e.g., "✗✗✗✓✓").
///
/// Uses ✓ for success (true), ✗ for failure (false).
/// If history is empty, returns "(no history)".
pub fn format_failure_history(history: &[bool]) -> String {
    if history.is_empty() {
        return "(no history)".to_string();
    }
    history
        .iter()
        .map(|&success| if success { '✓' } else { '✗' })
        .collect()
}

/// Get plain language explanation for circuit breaker state.
///
/// Returns a tuple of (state_name, explanation, help_text).
pub fn circuit_state_explanation(
    state: &str,
    consecutive_failures: u32,
    recovery_in_secs: Option<u64>,
    _last_error: Option<&str>,
) -> (&'static str, String, &'static str) {
    match state {
        "closed" => (
            "CLOSED",
            "Normal operation - requests are being routed".to_string(),
            "",
        ),
        "open" => {
            let reason = if consecutive_failures > 0 {
                format!("{} consecutive failures", consecutive_failures)
            } else {
                "repeated failures".to_string()
            };
            let timing = match recovery_in_secs {
                Some(secs) => format!(" (auto-recovery in {}s)", secs),
                None => " (cooldown elapsed, awaiting probe)".to_string(),
            };
            let explanation = format!("Circuit open due to {}{}", reason, timing);
            (
                "OPEN",
                explanation,
                "Wait for auto-recovery or run: rch workers probe <id> --force",
            )
        }
        "half_open" => (
            "HALF-OPEN",
            "Testing recovery - limited requests allowed".to_string(),
            "Probing in progress; success will close circuit",
        ),
        _ => ("UNKNOWN", "Unknown circuit state".to_string(), ""),
    }
}

/// Render basic status when daemon is not running.
pub fn render_basic_status(daemon_running: bool, show_workers: bool, style: &Theme) {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_failure_history_empty() {
        assert_eq!(format_failure_history(&[]), "(no history)");
    }

    #[test]
    fn test_format_failure_history_all_success() {
        assert_eq!(format_failure_history(&[true, true, true]), "✓✓✓");
    }

    #[test]
    fn test_format_failure_history_all_failure() {
        assert_eq!(format_failure_history(&[false, false, false]), "✗✗✗");
    }

    #[test]
    fn test_format_failure_history_mixed() {
        assert_eq!(
            format_failure_history(&[false, false, true, false, true]),
            "✗✗✓✗✓"
        );
    }

    #[test]
    fn test_circuit_state_explanation_closed() {
        let (state, explanation, help) = circuit_state_explanation("closed", 0, None, None);
        assert_eq!(state, "CLOSED");
        assert!(explanation.contains("Normal operation"));
        assert!(help.is_empty());
    }

    #[test]
    fn test_circuit_state_explanation_open_with_recovery() {
        let (state, explanation, help) =
            circuit_state_explanation("open", 3, Some(45), Some("SSH timeout"));
        assert_eq!(state, "OPEN");
        assert!(explanation.contains("3 consecutive failures"));
        assert!(explanation.contains("auto-recovery in 45s"));
        assert!(help.contains("rch workers probe"));
    }

    #[test]
    fn test_circuit_state_explanation_open_no_recovery() {
        let (state, explanation, _help) = circuit_state_explanation("open", 5, None, None);
        assert_eq!(state, "OPEN");
        assert!(explanation.contains("5 consecutive failures"));
        assert!(explanation.contains("awaiting probe"));
    }

    #[test]
    fn test_circuit_state_explanation_half_open() {
        let (state, explanation, help) = circuit_state_explanation("half_open", 0, None, None);
        assert_eq!(state, "HALF-OPEN");
        assert!(explanation.contains("Testing recovery"));
        assert!(help.contains("success will close"));
    }

    #[test]
    fn test_circuit_state_explanation_unknown() {
        let (state, explanation, _help) = circuit_state_explanation("weird_state", 0, None, None);
        assert_eq!(state, "UNKNOWN");
        assert!(explanation.contains("Unknown"));
    }
}
