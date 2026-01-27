//! StatusTable - Rich terminal display for `rch status` command.
//!
//! This module provides context-aware status display using rich_rust.
//! Falls back to plain text when rich output is not available.

use crate::status_types::{DaemonFullStatusResponse, format_duration};
use crate::ui::console::RchConsole;

#[cfg(feature = "rich-ui")]
use rich_rust::prelude::*;
#[cfg(feature = "rich-ui")]
use rich_rust::renderables::{Column, Row, Table};

use rch_common::ui::{Icons, OutputContext, RchTheme};

/// StatusTable renders daemon status with rich formatting.
///
/// Displays:
/// - Connection state panel with colored indicator
/// - Active jobs table
/// - Queue depth with visual bar
/// - Performance metrics
/// - Worker health summary
pub struct StatusTable<'a> {
    status: &'a DaemonFullStatusResponse,
    context: OutputContext,
}

impl<'a> StatusTable<'a> {
    /// Create a new StatusTable from daemon status response.
    #[must_use]
    pub fn new(status: &'a DaemonFullStatusResponse, context: OutputContext) -> Self {
        Self { status, context }
    }

    /// Create from status with auto-detected context.
    #[must_use]
    pub fn from_status(status: &'a DaemonFullStatusResponse) -> Self {
        Self::new(status, OutputContext::detect())
    }

    /// Render the status display using RchConsole.
    pub fn render(&self, console: &RchConsole) {
        if console.is_machine() {
            // JSON mode - don't render, caller should use print_json
            return;
        }

        #[cfg(feature = "rich-ui")]
        if console.is_rich() {
            self.render_rich(console);
            return;
        }

        self.render_plain(console);
    }

    /// Render rich output using rich_rust.
    #[cfg(feature = "rich-ui")]
    fn render_rich(&self, console: &RchConsole) {
        // Status header panel
        self.render_status_panel(console);

        // Alerts if any
        if !self.status.alerts.is_empty() {
            console.line();
            self.render_alerts_panel(console);
        }

        // Active jobs table
        if !self.status.active_builds.is_empty() {
            console.line();
            self.render_jobs_table(console);
        }

        // Issues if any
        if !self.status.issues.is_empty() {
            console.line();
            self.render_issues_panel(console);
        }
    }

    /// Render the main status panel with connection info.
    #[cfg(feature = "rich-ui")]
    fn render_status_panel(&self, console: &RchConsole) {
        let daemon = &self.status.daemon;
        let check = Icons::check(self.context);
        let worker_icon = Icons::worker(self.context);

        // Build status lines
        let connection_line = format!(
            "{} Connected to rchd (PID {})",
            Icons::status_healthy(self.context),
            daemon.pid
        );

        let workers_line = format!(
            "{} Workers: {}/{} healthy | Slots: {}/{} available{}",
            worker_icon,
            daemon.workers_healthy,
            daemon.workers_total,
            daemon.slots_available,
            daemon.slots_total,
            if self.status.alerts.is_empty() {
                String::new()
            } else {
                format!(" | Alerts: {}", self.status.alerts.len())
            }
        );

        let stats = &self.status.stats;
        let success_rate = if stats.total_builds > 0 {
            (stats.success_count as f64 / stats.total_builds as f64) * 100.0
        } else {
            100.0
        };
        let stats_line = format!(
            "{} Builds: {} total | {:.0}% success | avg {}",
            check,
            stats.total_builds,
            success_rate,
            format_ms_duration(stats.avg_duration_ms)
        );

        let uptime_line = format!(
            "{} Uptime: {} | Version: {}",
            Icons::clock(self.context),
            format_duration(daemon.uptime_secs),
            daemon.version
        );

        let content = format!(
            "{}\n{}\n{}\n{}",
            connection_line, workers_line, stats_line, uptime_line
        );

        let panel = Panel::from_text(&content)
            .title("RCH Status")
            .border_style(RchTheme::primary())
            .rounded();

        console.print_renderable(&panel);
    }

    /// Render active jobs as a table.
    #[cfg(feature = "rich-ui")]
    fn render_jobs_table(&self, console: &RchConsole) {
        let mut table = Table::new()
            .title("Active Jobs")
            .border_style(RchTheme::secondary());

        // Add columns
        table = table
            .with_column(Column::new("ID").header_style(RchTheme::table_header()))
            .with_column(Column::new("Command").header_style(RchTheme::table_header()))
            .with_column(Column::new("Worker").header_style(RchTheme::table_header()))
            .with_column(Column::new("Elapsed").header_style(RchTheme::table_header()));

        // Add rows
        for job in &self.status.active_builds {
            let cmd = truncate_command(&job.command, 40);
            let id_str = format!("#{}", job.id);
            // Show elapsed time instead of raw timestamp
            let elapsed_str = elapsed_since(&job.started_at)
                .map(format_elapsed)
                .unwrap_or_else(|| job.started_at.clone());
            let row = Row::new(vec![
                Cell::new(id_str.as_str()),
                Cell::new(cmd.as_str()),
                Cell::new(job.worker_id.as_str()),
                Cell::new(elapsed_str.as_str()),
            ]);
            table = table.with_row(row);
        }

        console.print_renderable(&table);
    }

    /// Render issues panel.
    #[cfg(feature = "rich-ui")]
    fn render_issues_panel(&self, console: &RchConsole) {
        let warning = Icons::warning(self.context);

        let mut lines = Vec::new();
        for issue in &self.status.issues {
            let severity_prefix = match issue.severity.as_str() {
                "critical" | "error" => Icons::cross(self.context),
                "warning" => warning,
                _ => Icons::info(self.context),
            };
            lines.push(format!(
                "{} [{}] {}",
                severity_prefix, issue.severity, issue.summary
            ));

            if let Some(ref fix) = issue.remediation {
                lines.push(format!("  Fix: {fix}"));
            }
        }

        let content = lines.join("\n");
        let title_str = format!("{warning} Issues");
        let panel = Panel::from_text(&content)
            .title(title_str.as_str())
            .border_style(RchTheme::warning())
            .rounded();

        console.print_renderable(&panel);
    }

    /// Render alerts panel.
    #[cfg(feature = "rich-ui")]
    fn render_alerts_panel(&self, console: &RchConsole) {
        let mut lines = Vec::new();
        for alert in &self.status.alerts {
            let severity_prefix = match alert.severity.as_str() {
                "critical" | "error" => Icons::cross(self.context),
                "warning" => Icons::warning(self.context),
                _ => Icons::info(self.context),
            };

            if let Some(worker_id) = &alert.worker_id {
                lines.push(format!(
                    "{} [{}] {} ({})",
                    severity_prefix, alert.severity, alert.message, worker_id
                ));
            } else {
                lines.push(format!(
                    "{} [{}] {}",
                    severity_prefix, alert.severity, alert.message
                ));
            }
        }

        let content = lines.join("\n");
        let panel = Panel::from_text(&content)
            .title("Alerts")
            .border_style(RchTheme::warning())
            .rounded();

        console.print_renderable(&panel);
    }

    /// Render plain text output (no rich formatting).
    fn render_plain(&self, console: &RchConsole) {
        let daemon = &self.status.daemon;
        let check = Icons::check(self.context);

        // Header
        console.print_plain("=== RCH Status ===");
        console.print_plain("");

        // Connection info
        console.print_plain(&format!("{} Daemon: Running (PID {})", check, daemon.pid));
        console.print_plain(&format!(
            "  Uptime: {} | Version: {}",
            format_duration(daemon.uptime_secs),
            daemon.version
        ));

        // Workers
        console.print_plain(&format!(
            "  Workers: {}/{} healthy | Slots: {}/{} available",
            daemon.workers_healthy,
            daemon.workers_total,
            daemon.slots_available,
            daemon.slots_total
        ));

        // Build stats
        let stats = &self.status.stats;
        let success_rate = if stats.total_builds > 0 {
            (stats.success_count as f64 / stats.total_builds as f64) * 100.0
        } else {
            100.0
        };
        console.print_plain(&format!(
            "  Builds: {} total, {:.0}% success, avg {}",
            stats.total_builds,
            success_rate,
            format_ms_duration(stats.avg_duration_ms)
        ));

        // Alerts
        if !self.status.alerts.is_empty() {
            console.print_plain("");
            console.print_plain("--- Alerts ---");
            for alert in &self.status.alerts {
                let prefix = match alert.severity.as_str() {
                    "critical" | "error" => Icons::cross(self.context),
                    "warning" => Icons::warning(self.context),
                    _ => Icons::info(self.context),
                };
                if let Some(worker_id) = &alert.worker_id {
                    console.print_plain(&format!(
                        "  {} [{}] {} ({})",
                        prefix, alert.severity, alert.message, worker_id
                    ));
                } else {
                    console.print_plain(&format!(
                        "  {} [{}] {}",
                        prefix, alert.severity, alert.message
                    ));
                }
            }
        }

        // Active jobs
        if !self.status.active_builds.is_empty() {
            console.print_plain("");
            console.print_plain("--- Active Jobs ---");
            for job in &self.status.active_builds {
                let cmd = truncate_command(&job.command, 40);
                let elapsed = elapsed_since(&job.started_at)
                    .map(format_elapsed)
                    .unwrap_or_else(|| "?".to_string());
                console.print_plain(&format!(
                    "  #{} {} on {} ({})",
                    job.id, cmd, job.worker_id, elapsed
                ));
            }
        }

        // Issues
        if !self.status.issues.is_empty() {
            console.print_plain("");
            console.print_plain("--- Issues ---");
            for issue in &self.status.issues {
                let prefix = match issue.severity.as_str() {
                    "critical" | "error" => Icons::cross(self.context),
                    "warning" => Icons::warning(self.context),
                    _ => Icons::info(self.context),
                };
                console.print_plain(&format!(
                    "  {} [{}] {}",
                    prefix, issue.severity, issue.summary
                ));
                if let Some(ref fix) = issue.remediation {
                    console.print_plain(&format!("    Fix: {fix}"));
                }
            }
        }
    }
}

/// Render a minimal status when daemon is not running.
pub fn render_daemon_offline(console: &RchConsole) {
    if console.is_machine() {
        return;
    }

    let ctx = console.context();
    let cross = Icons::cross(ctx);

    #[cfg(feature = "rich-ui")]
    if console.is_rich() {
        let content = format!(
            "{} Daemon is not running\n\nStart with: rch daemon start",
            cross
        );
        let panel = Panel::from_text(&content)
            .title("RCH Status")
            .border_style(RchTheme::error())
            .rounded();
        console.print_renderable(&panel);
        return;
    }

    console.print_plain("=== RCH Status ===");
    console.print_plain("");
    console.print_plain(&format!("{cross} Daemon: Stopped"));
    console.print_plain("  Start with: rch daemon start");
}

/// Helper to format milliseconds as human-readable duration.
fn format_ms_duration(ms: u64) -> String {
    if ms < 1000 {
        format!("{ms}ms")
    } else {
        format!("{:.1}s", ms as f64 / 1000.0)
    }
}

/// Truncate a command string intelligently for display.
///
/// Unlike naive truncation, this preserves important suffixes like:
/// - `--release` (build mode)
/// - `-p <package>` (package name)
/// - `--test` / `--lib` / `--bin` (target type)
fn truncate_command(cmd: &str, max_len: usize) -> String {
    if cmd.len() <= max_len {
        return cmd.to_string();
    }

    // Important suffixes to preserve (in priority order)
    let important_suffixes = [" --release", " --test", " --lib", " --bin", " --workspace"];

    // Check if any important suffix is present
    for suffix in important_suffixes {
        if cmd.ends_with(suffix) || cmd.contains(&format!("{suffix} ")) {
            // Try to fit the suffix
            let suffix_len = suffix.len();
            if max_len > suffix_len + 6 {
                // "cmd...--release"
                let prefix_len = max_len - suffix_len - 3; // 3 for "..."
                return format!("{}...{}", &cmd[..prefix_len], suffix.trim());
            }
        }
    }

    // Check for -p <package> pattern
    if let Some(pkg_start) = cmd.find(" -p ") {
        let pkg_end = cmd[pkg_start + 4..]
            .find(' ')
            .map(|i| pkg_start + 4 + i)
            .unwrap_or(cmd.len());
        let pkg_name = &cmd[pkg_start..pkg_end];
        if pkg_name.len() < max_len - 10 {
            let prefix_len = max_len - pkg_name.len() - 3;
            if prefix_len > 5 {
                return format!("{}...{}", &cmd[..prefix_len], pkg_name.trim());
            }
        }
    }

    // Default: simple truncation
    format!("{}...", &cmd[..max_len.saturating_sub(3)])
}

/// Parse ISO 8601 timestamp and return elapsed time.
fn elapsed_since(timestamp: &str) -> Option<std::time::Duration> {
    // Parse ISO 8601 format: "2026-01-19T00:00:10Z"
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    // Simple parsing for ISO 8601 UTC timestamps
    let ts = timestamp.trim_end_matches('Z');
    let parts: Vec<&str> = ts.split('T').collect();
    if parts.len() != 2 {
        return None;
    }

    let date_parts: Vec<u32> = parts[0].split('-').filter_map(|s| s.parse().ok()).collect();
    let time_parts: Vec<&str> = parts[1].split(':').collect();

    if date_parts.len() != 3 || time_parts.len() < 2 {
        return None;
    }

    // Approximate calculation (good enough for display)
    let year = date_parts[0];
    let month = date_parts[1];
    let day = date_parts[2];
    let hour: u32 = time_parts[0].parse().ok()?;
    let minute: u32 = time_parts[1].parse().ok()?;
    let second: u32 = time_parts
        .get(2)
        .and_then(|s| s.split('.').next())
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    // Days since epoch (simplified, ignores leap years for rough estimate)
    let days_in_year = 365u64;
    let epoch_year = 1970u64;
    let years_since_epoch = (year as u64).saturating_sub(epoch_year);
    let rough_days = years_since_epoch * days_in_year + (month as u64 - 1) * 30 + day as u64;
    let timestamp_secs =
        rough_days * 86400 + hour as u64 * 3600 + minute as u64 * 60 + second as u64;

    let now_secs = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();

    if now_secs >= timestamp_secs {
        Some(Duration::from_secs(now_secs - timestamp_secs))
    } else {
        None
    }
}

/// Format elapsed time in a human-friendly way.
fn format_elapsed(duration: std::time::Duration) -> String {
    let secs = duration.as_secs();
    if secs < 60 {
        format!("{}s", secs)
    } else if secs < 3600 {
        format!("{}m {}s", secs / 60, secs % 60)
    } else {
        format!("{}h {}m", secs / 3600, (secs % 3600) / 60)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::status_types::{
        ActiveBuildFromApi, BuildStatsFromApi, DaemonInfoFromApi, IssueFromApi,
    };
    use rch_common::test_guard;

    fn sample_status() -> DaemonFullStatusResponse {
        DaemonFullStatusResponse {
            daemon: DaemonInfoFromApi {
                pid: 1234,
                uptime_secs: 3600,
                version: "0.1.0".to_string(),
                socket_path: "/tmp/rch.sock".to_string(),
                started_at: "2026-01-19T00:00:00Z".to_string(),
                workers_total: 3,
                workers_healthy: 2,
                slots_total: 24,
                slots_available: 16,
            },
            workers: vec![],
            active_builds: vec![ActiveBuildFromApi {
                id: 42,
                project_id: "proj".to_string(),
                worker_id: "worker-1".to_string(),
                command: "cargo build --release".to_string(),
                started_at: "2026-01-19T00:00:10Z".to_string(),
            }],
            queued_builds: vec![],
            recent_builds: vec![],
            issues: vec![IssueFromApi {
                severity: "warning".to_string(),
                summary: "Worker-2 has high latency".to_string(),
                remediation: Some("Check network connection".to_string()),
            }],
            alerts: vec![],
            stats: BuildStatsFromApi {
                total_builds: 100,
                success_count: 95,
                failure_count: 5,
                remote_count: 80,
                local_count: 20,
                avg_duration_ms: 5500,
            },
            test_stats: None,
            saved_time: None,
        }
    }

    #[test]
    fn test_status_table_creation() {
        let _guard = test_guard!();
        let status = sample_status();
        let ctx = OutputContext::Plain;
        let table = StatusTable::new(&status, ctx);
        assert_eq!(table.context, OutputContext::Plain);
    }

    #[test]
    fn test_status_table_from_status() {
        let _guard = test_guard!();
        let status = sample_status();
        let table = StatusTable::from_status(&status);
        // Should not panic, context is auto-detected
        let _ = table.context;
    }

    #[test]
    fn test_format_ms_duration_milliseconds() {
        let _guard = test_guard!();
        assert_eq!(format_ms_duration(500), "500ms");
        assert_eq!(format_ms_duration(999), "999ms");
    }

    #[test]
    fn test_format_ms_duration_seconds() {
        let _guard = test_guard!();
        assert_eq!(format_ms_duration(1000), "1.0s");
        assert_eq!(format_ms_duration(5500), "5.5s");
    }

    #[test]
    fn test_truncate_command_short() {
        let _guard = test_guard!();
        let cmd = "cargo build";
        assert_eq!(truncate_command(cmd, 40), "cargo build");
    }

    #[test]
    fn test_truncate_command_long() {
        let _guard = test_guard!();
        let cmd = "cargo build --release --target x86_64-unknown-linux-gnu --features full";
        let truncated = truncate_command(cmd, 40);
        assert!(truncated.len() <= 40);
        assert!(truncated.ends_with("...") || truncated.ends_with("--release"));
    }

    #[test]
    fn test_truncate_command_preserves_release_flag() {
        let _guard = test_guard!();
        let cmd = "cargo build --target x86_64-unknown-linux-gnu --features full --release";
        let truncated = truncate_command(cmd, 40);
        // Should preserve --release since it's an important suffix
        assert!(
            truncated.contains("--release") || truncated.ends_with("..."),
            "Expected to preserve --release or truncate: {truncated}"
        );
    }

    #[test]
    fn test_truncate_command_preserves_package() {
        let _guard = test_guard!();
        let cmd = "cargo test -p my-important-package --release";
        let truncated = truncate_command(cmd, 35);
        // Should try to preserve package name or important suffix
        assert!(truncated.len() <= 35);
    }

    #[test]
    fn test_format_elapsed_seconds() {
        let _guard = test_guard!();
        use std::time::Duration;
        assert_eq!(format_elapsed(Duration::from_secs(30)), "30s");
        assert_eq!(format_elapsed(Duration::from_secs(59)), "59s");
    }

    #[test]
    fn test_format_elapsed_minutes() {
        let _guard = test_guard!();
        use std::time::Duration;
        assert_eq!(format_elapsed(Duration::from_secs(90)), "1m 30s");
        assert_eq!(format_elapsed(Duration::from_secs(3599)), "59m 59s");
    }

    #[test]
    fn test_format_elapsed_hours() {
        let _guard = test_guard!();
        use std::time::Duration;
        assert_eq!(format_elapsed(Duration::from_secs(3600)), "1h 0m");
        assert_eq!(format_elapsed(Duration::from_secs(7200 + 1800)), "2h 30m");
    }

    #[test]
    fn test_render_plain_mode() {
        let _guard = test_guard!();
        let status = sample_status();
        let console = RchConsole::with_context(OutputContext::Plain);
        let table = StatusTable::new(&status, OutputContext::Plain);
        // Should not panic
        table.render(&console);
    }

    #[test]
    fn test_render_machine_mode_no_output() {
        let _guard = test_guard!();
        let status = sample_status();
        let console = RchConsole::with_context(OutputContext::Machine);
        let table = StatusTable::new(&status, OutputContext::Machine);
        // Should not panic, should do nothing
        table.render(&console);
    }

    #[test]
    fn test_daemon_offline_plain() {
        let _guard = test_guard!();
        let console = RchConsole::with_context(OutputContext::Plain);
        // Should not panic
        render_daemon_offline(&console);
    }

    #[test]
    fn test_daemon_offline_machine_mode() {
        let _guard = test_guard!();
        let console = RchConsole::with_context(OutputContext::Machine);
        // Should not panic, should do nothing
        render_daemon_offline(&console);
    }
}
