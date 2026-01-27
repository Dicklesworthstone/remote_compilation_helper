//! Status display rendering for the rch CLI.
//!
//! This module contains helper functions for rendering daemon status
//! in both comprehensive (when daemon is running) and basic (when daemon
//! is stopped) modes.

#![allow(dead_code)]

use crate::status_types::{DaemonFullStatusResponse, extract_json_body, format_duration};
use crate::ui::theme::Theme;
use anyhow::{Context, Result};
use std::io::Write;
use std::path::PathBuf;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
#[cfg(unix)]
use tokio::net::UnixStream;

/// Default daemon socket path.
fn default_socket_path() -> PathBuf {
    PathBuf::from(rch_common::default_socket_path())
}

/// Format milliseconds as human-readable duration.
fn format_duration_ms(ms: u64) -> String {
    if ms < 1000 {
        format!("{}ms", ms)
    } else if ms < 60_000 {
        format!("{:.1}s", ms as f64 / 1000.0)
    } else if ms < 3_600_000 {
        let mins = ms / 60_000;
        let secs = (ms % 60_000) / 1000;
        if secs == 0 {
            format!("{}m", mins)
        } else {
            format!("{}m {}s", mins, secs)
        }
    } else {
        let hours = ms / 3_600_000;
        let mins = (ms % 3_600_000) / 60_000;
        if mins == 0 {
            format!("{}h", hours)
        } else {
            format!("{}h {}m", hours, mins)
        }
    }
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
#[cfg(not(unix))]
async fn send_status_command() -> Result<String> {
    anyhow::bail!("daemon status is only supported on Unix-like platforms");
}

#[cfg(unix)]
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
    let mut stdout = std::io::stdout();
    let _ = render_full_status_to(&mut stdout, status, show_workers, show_jobs, style);
}

fn render_full_status_to<W: Write>(
    out: &mut W,
    status: &DaemonFullStatusResponse,
    show_workers: bool,
    show_jobs: bool,
    style: &Theme,
) -> std::io::Result<()> {
    writeln!(out, "{}", style.format_header("RCH Status"))?;
    writeln!(out)?;

    // Daemon info
    writeln!(
        out,
        "  {} {} {} (PID {})",
        style.key("Daemon"),
        style.muted(":"),
        style.success("Running"),
        style.highlight(&status.daemon.pid.to_string())
    )?;
    writeln!(
        out,
        "  {} {} {}",
        style.key("Uptime"),
        style.muted(":"),
        style.info(&format_duration(status.daemon.uptime_secs))
    )?;
    writeln!(
        out,
        "  {} {} {}",
        style.key("Version"),
        style.muted(":"),
        style.info(&status.daemon.version)
    )?;

    // Worker summary
    writeln!(
        out,
        "  {} {} {}/{} healthy, {}/{} slots available",
        style.key("Workers"),
        style.muted(":"),
        style.highlight(&status.daemon.workers_healthy.to_string()),
        status.daemon.workers_total,
        style.highlight(&status.daemon.slots_available.to_string()),
        status.daemon.slots_total
    )?;

    // Build stats
    let success_rate = if status.stats.total_builds > 0 {
        (status.stats.success_count as f64 / status.stats.total_builds as f64) * 100.0
    } else {
        100.0
    };
    writeln!(
        out,
        "  {} {} {} total, {:.0}% success rate",
        style.key("Builds"),
        style.muted(":"),
        style.highlight(&status.stats.total_builds.to_string()),
        success_rate
    )?;

    if let Some(test_stats) = &status.test_stats {
        let pass_rate = if test_stats.total_runs > 0 {
            (test_stats.passed_runs as f64 / test_stats.total_runs as f64) * 100.0
        } else {
            100.0
        };
        let avg_duration = if test_stats.avg_duration_ms < 1000 {
            format!("{}ms", test_stats.avg_duration_ms)
        } else {
            format_duration((test_stats.avg_duration_ms + 500) / 1000)
        };
        writeln!(
            out,
            "  {} {} {} total, {:.0}% pass rate, avg {}",
            style.key("Tests"),
            style.muted(":"),
            style.highlight(&test_stats.total_runs.to_string()),
            pass_rate,
            style.info(&avg_duration)
        )?;
    }

    // Hook status (check locally)
    let hook_installed = check_hook_installed();
    writeln!(
        out,
        "  {} {} {}",
        style.key("Hook"),
        style.muted(":"),
        if hook_installed {
            style.success("Installed")
        } else {
            style.warning("Not installed")
        }
    )?;

    // Saved time statistics
    if let Some(saved_time) = &status.saved_time
        && saved_time.builds_counted > 0
    {
        let time_saved_str = format_duration_ms(saved_time.time_saved_ms);
        let speedup_str = if saved_time.avg_speedup > 0.0 {
            format!("{:.1}x", saved_time.avg_speedup)
        } else {
            "-".to_string()
        };
        writeln!(
            out,
            "  {} {} {} saved ({} speedup, {} builds)",
            style.key("Saved"),
            style.muted(":"),
            style.success(&time_saved_str),
            style.info(&speedup_str),
            saved_time.builds_counted
        )?;

        // Show daily stats if significant
        if saved_time.today_saved_ms > 0 {
            let today_str = format_duration_ms(saved_time.today_saved_ms);
            let week_str = format_duration_ms(saved_time.week_saved_ms);
            writeln!(
                out,
                "           {} today, {} this week",
                style.highlight(&today_str),
                style.info(&week_str)
            )?;
        }
    }

    // Alerts section if any
    if !status.alerts.is_empty() {
        writeln!(out, "\n{}", style.format_header("Alerts"))?;
        for alert in &status.alerts {
            let severity_style = match alert.severity.as_str() {
                "critical" | "error" => style.error(&alert.severity),
                "warning" => style.warning(&alert.severity),
                _ => style.info(&alert.severity),
            };

            if let Some(worker_id) = &alert.worker_id {
                writeln!(
                    out,
                    "  {} [{}] {} {}",
                    style.symbols.bullet_filled,
                    severity_style,
                    alert.message,
                    style.muted(&format!("({worker_id})")),
                )?;
            } else {
                writeln!(
                    out,
                    "  {} [{}] {}",
                    style.symbols.bullet_filled, severity_style, alert.message
                )?;
            }
        }
    }

    // Issues section if any
    if !status.issues.is_empty() {
        writeln!(out, "\n{}", style.format_header("Issues"))?;
        for issue in &status.issues {
            let severity_style = match issue.severity.as_str() {
                "critical" | "error" => style.error(&issue.severity),
                "warning" => style.warning(&issue.severity),
                _ => style.info(&issue.severity),
            };
            writeln!(
                out,
                "  {} [{}] {}",
                style.symbols.bullet_filled, severity_style, issue.summary
            )?;
            if let Some(remediation) = &issue.remediation {
                writeln!(
                    out,
                    "    {} {}",
                    style.muted("Fix:"),
                    style.info(remediation)
                )?;
            }
        }
    }

    // Workers section
    if show_workers {
        render_workers_table_to(out, status, style)?;
    }

    // Jobs/builds section
    if show_jobs {
        render_builds_section_to(out, status, style)?;
    }

    Ok(())
}

/// Render the workers table.
fn render_workers_table_to<W: Write>(
    out: &mut W,
    status: &DaemonFullStatusResponse,
    style: &Theme,
) -> std::io::Result<()> {
    writeln!(out, "\n{}", style.format_header("Workers"))?;
    if status.workers.is_empty() {
        writeln!(out, "  {}", style.muted("(none configured)"))?;
        return Ok(());
    }

    // Table header
    writeln!(
        out,
        "  {:12} {:8} {:10} {:6} {:10} {:8}",
        style.key("ID"),
        style.key("Status"),
        style.key("Circuit"),
        style.key("Slots"),
        style.key("Speed"),
        style.key("Host")
    )?;
    writeln!(
        out,
        "  {:12} {:8} {:10} {:6} {:10} {:8}",
        "────────────", "────────", "──────────", "──────", "──────────", "────────"
    )?;

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

        writeln!(
            out,
            "  {:12} {:8} {:10} {:6} {:10} {}@{}",
            style.highlight(&worker.id),
            status_display,
            circuit_display,
            slots,
            speed,
            style.muted(&worker.user),
            style.info(&worker.host)
        )?;

        // Show detailed circuit info for workers with issues
        if worker.circuit_state != "closed" {
            render_circuit_details_to(out, worker, style)?;
        }
    }

    Ok(())
}

/// Render detailed circuit breaker information for a worker.
fn render_circuit_details_to<W: Write>(
    out: &mut W,
    worker: &crate::status_types::WorkerStatusFromApi,
    style: &Theme,
) -> std::io::Result<()> {
    let (state_name, explanation, help_text) = circuit_state_explanation(
        &worker.circuit_state,
        worker.consecutive_failures,
        worker.recovery_in_secs,
        worker.last_error.as_deref(),
    );

    // Show explanation
    writeln!(
        out,
        "    {} {}",
        style.muted("Circuit:"),
        match worker.circuit_state.as_str() {
            "open" => style.error(state_name),
            "half_open" => style.warning(state_name),
            _ => style.muted(state_name),
        }
    )?;
    writeln!(out, "      {}", style.muted(&explanation))?;

    // Show failure history if available
    if !worker.failure_history.is_empty() {
        let history_visual = format_failure_history(&worker.failure_history);
        writeln!(
            out,
            "    {} {} {}",
            style.muted("History:"),
            history_visual,
            style.muted(&format!("(last {} attempts)", worker.failure_history.len()))
        )?;
    }

    // Show last error if available
    if let Some(ref error) = worker.last_error {
        let error_truncated = if error.len() > 60 {
            format!("{}...", &error[..57])
        } else {
            error.clone()
        };
        writeln!(
            out,
            "    {} {}",
            style.muted("Reason:"),
            style.error(&error_truncated)
        )?;
    }

    // Show help text for non-closed circuits
    if !help_text.is_empty() {
        writeln!(
            out,
            "    {} {}",
            style.muted("Help:"),
            style.info(help_text)
        )?;
    }

    Ok(())
}

/// Render the builds section (active and recent).
fn render_builds_section_to<W: Write>(
    out: &mut W,
    status: &DaemonFullStatusResponse,
    style: &Theme,
) -> std::io::Result<()> {
    // Active builds
    writeln!(out, "\n{}", style.format_header("Active Builds"))?;
    if status.active_builds.is_empty() {
        writeln!(out, "  {}", style.muted("(no active builds)"))?;
    } else {
        for build in &status.active_builds {
            let cmd_display = if build.command.len() > 50 {
                format!("{}...", &build.command[..47])
            } else {
                build.command.clone()
            };
            writeln!(
                out,
                "  {} #{} on {} - {}",
                style.symbols.bullet_filled,
                style.highlight(&build.id.to_string()),
                style.info(&build.worker_id),
                style.muted(&cmd_display)
            )?;
        }
    }

    // Recent builds
    writeln!(out, "\n{}", style.format_header("Recent Builds"))?;
    if status.recent_builds.is_empty() {
        writeln!(out, "  {}", style.muted("(no recent builds)"))?;
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

            writeln!(
                out,
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
            )?;
        }
    }

    Ok(())
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
    let mut stdout = std::io::stdout();
    let _ = render_basic_status_to(&mut stdout, daemon_running, show_workers, style);
}

fn render_basic_status_to<W: Write>(
    out: &mut W,
    daemon_running: bool,
    show_workers: bool,
    style: &Theme,
) -> std::io::Result<()> {
    writeln!(out, "{}", style.format_header("RCH Status"))?;
    writeln!(out)?;

    // Daemon status
    writeln!(
        out,
        "  {} {} {}",
        style.key("Daemon"),
        style.muted(":"),
        if daemon_running {
            style.warning("Running (not responding)")
        } else {
            style.error("Stopped")
        }
    )?;

    if !daemon_running {
        writeln!(
            out,
            "    {} {}",
            style.symbols.bullet_filled,
            style.muted("Start with: rch daemon start")
        )?;
    }

    // Worker count from config - use a simple message since we don't have load_workers_from_config here
    writeln!(
        out,
        "  {} {} {}",
        style.key("Workers"),
        style.muted(":"),
        style.muted("(check config for details)")
    )?;

    // Hook status
    let hook_installed = check_hook_installed();
    writeln!(
        out,
        "  {} {} {}",
        style.key("Hook"),
        style.muted(":"),
        if hook_installed {
            style.success("Installed")
        } else {
            style.warning("Not installed")
        }
    )?;

    if show_workers {
        writeln!(out, "\n{}", style.format_header("Workers"))?;
        writeln!(
            out,
            "  {} {}",
            style.symbols.info,
            style.muted("Start daemon for worker status: rch daemon start")
        )?;
    }

    writeln!(out)?;
    writeln!(
        out,
        "  {} {}",
        style.symbols.info,
        style.warning("Start daemon for live status: rch daemon start")
    )?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::status_types::{
        ActiveBuildFromApi, BuildRecordFromApi, BuildStatsFromApi, DaemonInfoFromApi, IssueFromApi,
        TestRunStatsFromApi, WorkerStatusFromApi,
    };
    use rch_common::test_guard;
    use tracing::info;

    fn sample_status() -> DaemonFullStatusResponse {
        DaemonFullStatusResponse {
            daemon: DaemonInfoFromApi {
                pid: 4242,
                uptime_secs: 90,
                version: "0.1.0".to_string(),
                socket_path: rch_common::default_socket_path(),
                started_at: "2026-01-17T00:00:00Z".to_string(),
                workers_total: 2,
                workers_healthy: 1,
                slots_total: 16,
                slots_available: 8,
            },
            workers: vec![
                WorkerStatusFromApi {
                    id: "worker-a".to_string(),
                    host: "10.0.0.1".to_string(),
                    user: "ubuntu".to_string(),
                    status: "healthy".to_string(),
                    circuit_state: "closed".to_string(),
                    used_slots: 2,
                    total_slots: 8,
                    speed_score: 92.5,
                    last_error: None,
                    consecutive_failures: 0,
                    recovery_in_secs: None,
                    failure_history: vec![true, true],
                },
                WorkerStatusFromApi {
                    id: "worker-b".to_string(),
                    host: "10.0.0.2".to_string(),
                    user: "ubuntu".to_string(),
                    status: "unhealthy".to_string(),
                    circuit_state: "open".to_string(),
                    used_slots: 8,
                    total_slots: 8,
                    speed_score: 12.3,
                    last_error: Some("SSH timeout".to_string()),
                    consecutive_failures: 3,
                    recovery_in_secs: Some(30),
                    failure_history: vec![false, false, true],
                },
            ],
            active_builds: vec![ActiveBuildFromApi {
                id: 1,
                project_id: "proj".to_string(),
                worker_id: "worker-a".to_string(),
                command: "cargo build".to_string(),
                started_at: "2026-01-17T00:00:01Z".to_string(),
            }],
            queued_builds: vec![],
            recent_builds: vec![
                BuildRecordFromApi {
                    id: 2,
                    started_at: "2026-01-17T00:00:02Z".to_string(),
                    completed_at: "2026-01-17T00:00:03Z".to_string(),
                    project_id: "proj".to_string(),
                    worker_id: Some("worker-a".to_string()),
                    command: "cargo test --release".to_string(),
                    exit_code: 0,
                    duration_ms: 1250,
                    location: "remote".to_string(),
                    bytes_transferred: Some(2048),
                    timing: None,
                },
                BuildRecordFromApi {
                    id: 3,
                    started_at: "2026-01-17T00:00:04Z".to_string(),
                    completed_at: "2026-01-17T00:00:05Z".to_string(),
                    project_id: "proj".to_string(),
                    worker_id: None,
                    command: "cargo check".to_string(),
                    exit_code: 1,
                    duration_ms: 540,
                    location: "local".to_string(),
                    bytes_transferred: None,
                    timing: None,
                },
            ],
            issues: vec![IssueFromApi {
                severity: "warning".to_string(),
                summary: "worker-b unreachable".to_string(),
                remediation: Some("Check SSH connectivity".to_string()),
            }],
            alerts: vec![],
            stats: BuildStatsFromApi {
                total_builds: 2,
                success_count: 1,
                failure_count: 1,
                remote_count: 1,
                local_count: 1,
                avg_duration_ms: 895,
            },
            test_stats: Some(TestRunStatsFromApi {
                total_runs: 3,
                passed_runs: 2,
                failed_runs: 1,
                build_error_runs: 0,
                avg_duration_ms: 1200,
                runs_by_kind: std::collections::HashMap::from([("cargo_test".to_string(), 3)]),
            }),
            saved_time: None,
        }
    }

    #[test]
    fn test_format_failure_history_empty() {
        let _guard = test_guard!();
        assert_eq!(format_failure_history(&[]), "(no history)");
    }

    #[test]
    fn test_format_failure_history_all_success() {
        let _guard = test_guard!();
        assert_eq!(format_failure_history(&[true, true, true]), "✓✓✓");
    }

    #[test]
    fn test_format_failure_history_all_failure() {
        let _guard = test_guard!();
        assert_eq!(format_failure_history(&[false, false, false]), "✗✗✗");
    }

    #[test]
    fn test_format_failure_history_mixed() {
        let _guard = test_guard!();
        assert_eq!(
            format_failure_history(&[false, false, true, false, true]),
            "✗✗✓✗✓"
        );
    }

    #[test]
    fn test_circuit_state_explanation_closed() {
        let _guard = test_guard!();
        let (state, explanation, help) = circuit_state_explanation("closed", 0, None, None);
        assert_eq!(state, "CLOSED");
        assert!(explanation.contains("Normal operation"));
        assert!(help.is_empty());
    }

    #[test]
    fn test_circuit_state_explanation_open_with_recovery() {
        let _guard = test_guard!();
        let (state, explanation, help) =
            circuit_state_explanation("open", 3, Some(45), Some("SSH timeout"));
        assert_eq!(state, "OPEN");
        assert!(explanation.contains("3 consecutive failures"));
        assert!(explanation.contains("auto-recovery in 45s"));
        assert!(help.contains("rch workers probe"));
    }

    #[test]
    fn test_circuit_state_explanation_open_no_recovery() {
        let _guard = test_guard!();
        let (state, explanation, _help) = circuit_state_explanation("open", 5, None, None);
        assert_eq!(state, "OPEN");
        assert!(explanation.contains("5 consecutive failures"));
        assert!(explanation.contains("awaiting probe"));
    }

    #[test]
    fn test_circuit_state_explanation_half_open() {
        let _guard = test_guard!();
        let (state, explanation, help) = circuit_state_explanation("half_open", 0, None, None);
        assert_eq!(state, "HALF-OPEN");
        assert!(explanation.contains("Testing recovery"));
        assert!(help.contains("success will close"));
    }

    #[test]
    fn test_circuit_state_explanation_unknown() {
        let _guard = test_guard!();
        let (state, explanation, _help) = circuit_state_explanation("weird_state", 0, None, None);
        assert_eq!(state, "UNKNOWN");
        assert!(explanation.contains("Unknown"));
    }

    #[test]
    fn test_render_full_status_includes_workers_and_circuits() {
        let _guard = test_guard!();
        info!("TEST: test_render_full_status_includes_workers_and_circuits");
        let status = sample_status();
        let style = Theme::new(false, true, false);
        let mut buf = Vec::new();
        render_full_status_to(&mut buf, &status, true, false, &style).expect("render");
        let output = String::from_utf8(buf).expect("utf8 output");

        assert!(output.contains("worker-a"));
        assert!(output.contains("healthy"));
        assert!(output.contains("worker-b"));
        assert!(output.contains("unhealthy"));
        assert!(output.contains("open (30s)"));
        info!("PASS: workers and circuit states rendered");
    }

    #[test]
    fn test_render_full_status_includes_build_sections() {
        let _guard = test_guard!();
        info!("TEST: test_render_full_status_includes_build_sections");
        let status = sample_status();
        let style = Theme::new(false, true, false);
        let mut buf = Vec::new();
        render_full_status_to(&mut buf, &status, false, true, &style).expect("render");
        let output = String::from_utf8(buf).expect("utf8 output");

        assert!(output.contains("Active Builds"));
        assert!(output.contains("Recent Builds"));
        assert!(output.contains("cargo build"));
        assert!(output.contains("cargo test --release"));
        assert!(output.contains("✓"));
        assert!(output.contains("✗"));
        info!("PASS: build sections rendered with status indicators");
    }

    #[test]
    fn test_render_full_status_includes_circuit_details() {
        let _guard = test_guard!();
        info!("TEST: test_render_full_status_includes_circuit_details");
        let status = sample_status();
        let style = Theme::new(false, true, false);
        let mut buf = Vec::new();
        render_full_status_to(&mut buf, &status, true, false, &style).expect("render");
        let output = String::from_utf8(buf).expect("utf8 output");

        assert!(output.contains("Circuit:"));
        assert!(output.contains("History:"));
        assert!(output.contains("Reason:"));
        assert!(output.contains("Help:"));
        info!("PASS: circuit details rendered");
    }

    #[test]
    fn test_render_basic_status_stopped() {
        let _guard = test_guard!();
        info!("TEST: test_render_basic_status_stopped");
        let style = Theme::new(false, true, false);
        let mut buf = Vec::new();
        render_basic_status_to(&mut buf, false, true, &style).expect("render");
        let output = String::from_utf8(buf).expect("utf8 output");

        assert!(output.contains("Stopped"));
        assert!(output.contains("Start with: rch daemon start"));
        assert!(output.contains("Start daemon for worker status"));
        info!("PASS: basic status stopped message rendered");
    }

    #[test]
    fn test_render_basic_status_running() {
        let _guard = test_guard!();
        info!("TEST: test_render_basic_status_running");
        let style = Theme::new(false, true, false);
        let mut buf = Vec::new();
        render_basic_status_to(&mut buf, true, false, &style).expect("render");
        let output = String::from_utf8(buf).expect("utf8 output");

        assert!(output.contains("Running (not responding)"));
        assert!(!output.contains("Start with: rch daemon start"));
        info!("PASS: basic status running message rendered");
    }
}
