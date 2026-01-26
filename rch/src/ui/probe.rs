//! ProbeResult display - Rich terminal display for `rch workers probe` command.
//!
//! This module provides context-aware worker probe result display using rich_rust.
//! Falls back to plain text when rich output is not available.
//!
//! # Display Features
//!
//! - Per-worker result panel showing probe status
//! - SSH connectivity, rsync availability, disk space, CPU count
//! - Latency measurement with color coding:
//!   - Green: <50ms (excellent)
//!   - Yellow: 50-200ms (acceptable)
//!   - Red: >200ms (degraded)
//! - Summary panel with pass/fail counts and recommendations

use crate::commands::WorkerProbeResult;
use crate::ui::console::RchConsole;

#[cfg(feature = "rich-ui")]
use rich_rust::prelude::*;
#[cfg(feature = "rich-ui")]
use rich_rust::renderables::{Column, Row, Table};

use rch_common::ui::{Icons, OutputContext, RchTheme};

/// Latency threshold for "excellent" (green) - under 50ms.
const LATENCY_EXCELLENT_MS: u64 = 50;

/// Latency threshold for "acceptable" (yellow) - under 200ms.
const LATENCY_ACCEPTABLE_MS: u64 = 200;

/// Extended probe result with detailed worker information.
///
/// This extends the basic `WorkerProbeResult` with additional probe details
/// that are gathered during the probe operation.
#[derive(Debug, Clone)]
pub struct DetailedProbeResult {
    /// Basic probe result.
    pub basic: WorkerProbeResult,

    /// SSH connectivity established.
    pub ssh_ok: bool,

    /// rsync is available on the worker.
    pub rsync_available: Option<bool>,

    /// Available disk space in bytes.
    pub disk_space_bytes: Option<u64>,

    /// Number of CPU cores.
    pub cpu_count: Option<u32>,

    /// Rust toolchain version (if available).
    pub rust_version: Option<String>,
}

impl DetailedProbeResult {
    /// Create from a basic probe result with SSH status.
    pub fn from_basic(basic: WorkerProbeResult, ssh_ok: bool) -> Self {
        Self {
            basic,
            ssh_ok,
            rsync_available: None,
            disk_space_bytes: None,
            cpu_count: None,
            rust_version: None,
        }
    }

    /// Check if the probe was successful.
    pub fn is_success(&self) -> bool {
        self.basic.status == "ok" || self.basic.status == "healthy"
    }

    /// Get latency category for color coding.
    pub fn latency_category(&self) -> LatencyCategory {
        match self.basic.latency_ms {
            Some(ms) if ms < LATENCY_EXCELLENT_MS => LatencyCategory::Excellent,
            Some(ms) if ms < LATENCY_ACCEPTABLE_MS => LatencyCategory::Acceptable,
            Some(_) => LatencyCategory::Degraded,
            None => LatencyCategory::Unknown,
        }
    }
}

/// Latency quality category for color coding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LatencyCategory {
    /// Under 50ms - excellent.
    Excellent,
    /// 50-200ms - acceptable.
    Acceptable,
    /// Over 200ms - degraded.
    Degraded,
    /// Unknown (probe failed).
    Unknown,
}

impl LatencyCategory {
    /// Get the display color for this category.
    #[cfg(feature = "rich-ui")]
    pub fn color(&self) -> &'static str {
        match self {
            Self::Excellent => RchTheme::SUCCESS,
            Self::Acceptable => RchTheme::WARNING,
            Self::Degraded => RchTheme::ERROR,
            Self::Unknown => RchTheme::MUTED,
        }
    }
}

/// ProbeResultTable renders worker probe results with rich formatting.
///
/// Displays:
/// - Worker ID and host
/// - Status with colored indicator
/// - Latency with color-coded value
/// - SSH/rsync availability
/// - Error message (if any)
pub struct ProbeResultTable<'a> {
    results: &'a [DetailedProbeResult],
    context: OutputContext,
    verbose: bool,
}

impl<'a> ProbeResultTable<'a> {
    /// Create a new ProbeResultTable from probe results.
    #[must_use]
    pub fn new(results: &'a [DetailedProbeResult], context: OutputContext) -> Self {
        Self {
            results,
            context,
            verbose: false,
        }
    }

    /// Create from results with auto-detected context.
    #[must_use]
    pub fn from_results(results: &'a [DetailedProbeResult]) -> Self {
        Self::new(results, OutputContext::detect())
    }

    /// Enable verbose mode for detailed output.
    #[must_use]
    pub fn verbose(mut self, verbose: bool) -> Self {
        self.verbose = verbose;
        self
    }

    /// Render the probe result table using RchConsole.
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
        if self.results.is_empty() {
            self.render_empty_rich(console);
            return;
        }

        let mut table = Table::new()
            .title("Probe Results")
            .border_style(RchTheme::secondary());

        // Add columns
        table = table
            .with_column(Column::new("Worker").header_style(RchTheme::table_header()))
            .with_column(Column::new("Host").header_style(RchTheme::table_header()))
            .with_column(Column::new("Status").header_style(RchTheme::table_header()))
            .with_column(Column::new("Latency").header_style(RchTheme::table_header()))
            .with_column(Column::new("SSH").header_style(RchTheme::table_header()));

        if self.verbose {
            table = table
                .with_column(Column::new("rsync").header_style(RchTheme::table_header()))
                .with_column(Column::new("CPUs").header_style(RchTheme::table_header()))
                .with_column(Column::new("Disk").header_style(RchTheme::table_header()));
        }

        // Add rows
        for result in self.results {
            let status_text = self.format_status_rich(result);
            let latency_text = self.format_latency_rich(result);
            let ssh_text = self.format_bool_status(result.ssh_ok);

            let mut cells = vec![
                Cell::new(result.basic.id.as_str()),
                Cell::new(result.basic.host.as_str()),
                Cell::new(status_text.as_str()),
                Cell::new(latency_text.as_str()),
                Cell::new(ssh_text.as_str()),
            ];

            if self.verbose {
                let rsync_text = result
                    .rsync_available
                    .map(|b| self.format_bool_status(b))
                    .unwrap_or_else(|| "-".to_string());
                let cpu_text = result
                    .cpu_count
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "-".to_string());
                let disk_text = result
                    .disk_space_bytes
                    .map(format_bytes)
                    .unwrap_or_else(|| "-".to_string());

                cells.push(Cell::new(rsync_text.as_str()));
                cells.push(Cell::new(cpu_text.as_str()));
                cells.push(Cell::new(disk_text.as_str()));
            }

            table = table.with_row(Row::new(cells));
        }

        console.print_renderable(&table);

        // Show errors if any
        self.render_errors_rich(console);

        // Summary footer
        self.render_summary_rich(console);
    }

    /// Render empty state with rich formatting.
    #[cfg(feature = "rich-ui")]
    fn render_empty_rich(&self, console: &RchConsole) {
        let info = Icons::info(self.context);
        let content = format!(
            "{} No workers to probe\n\nAdd workers with: rch workers add <host>",
            info
        );
        let panel = Panel::from_text(&content)
            .title("Probe Results")
            .border_style(RchTheme::muted())
            .rounded();
        console.print_renderable(&panel);
    }

    /// Render errors for failed probes.
    #[cfg(feature = "rich-ui")]
    fn render_errors_rich(&self, console: &RchConsole) {
        let errors: Vec<_> = self
            .results
            .iter()
            .filter(|r| r.basic.error.is_some())
            .collect();

        if errors.is_empty() {
            return;
        }

        console.line();

        for result in errors {
            if let Some(ref err) = result.basic.error {
                let icon = Icons::cross(self.context);
                console.print_or_plain(
                    &format!(
                        "[{}]{} {}[/]: {}",
                        RchTheme::ERROR,
                        icon,
                        result.basic.id,
                        err
                    ),
                    &format!("{} {}: {}", icon, result.basic.id, err),
                );
            }
        }
    }

    /// Format status for rich display.
    #[cfg(feature = "rich-ui")]
    fn format_status_rich(&self, result: &DetailedProbeResult) -> String {
        if result.is_success() {
            format!("{} OK", Icons::check(self.context))
        } else {
            format!("{} FAIL", Icons::cross(self.context))
        }
    }

    /// Format latency for rich display with color coding.
    #[cfg(feature = "rich-ui")]
    fn format_latency_rich(&self, result: &DetailedProbeResult) -> String {
        match result.basic.latency_ms {
            Some(ms) => {
                let category = result.latency_category();
                let color = category.color();
                format!("[{}]{}ms[/]", color, ms)
            }
            None => "-".to_string(),
        }
    }

    /// Format boolean status with icon.
    fn format_bool_status(&self, value: bool) -> String {
        if value {
            Icons::check(self.context).to_string()
        } else {
            Icons::cross(self.context).to_string()
        }
    }

    /// Render summary footer.
    #[cfg(feature = "rich-ui")]
    fn render_summary_rich(&self, console: &RchConsole) {
        let (passed, failed) = self.count_results();
        let total = self.results.len();
        let avg_latency = self.average_latency();

        let summary = ProbeSummary {
            total,
            passed,
            failed,
            average_latency_ms: avg_latency,
        };

        console.line();
        summary.render(console, self.context);
    }

    /// Render plain text output (no rich formatting).
    fn render_plain(&self, console: &RchConsole) {
        if self.results.is_empty() {
            console.print_plain("=== Probe Results ===");
            console.print_plain("");
            let info = Icons::info(self.context);
            console.print_plain(&format!("{info} No workers to probe"));
            console.print_plain("  Add workers with: rch workers add <host>");
            return;
        }

        console.print_plain("=== Probe Results ===");
        console.print_plain("");

        // Header
        if self.verbose {
            console.print_plain(&format!(
                "{:12} {:20} {:8} {:10} {:5} {:6} {:5} {:10}",
                "Worker", "Host", "Status", "Latency", "SSH", "rsync", "CPUs", "Disk"
            ));
            console.print_plain(&"-".repeat(80));
        } else {
            console.print_plain(&format!(
                "{:12} {:20} {:8} {:10} {:5}",
                "Worker", "Host", "Status", "Latency", "SSH"
            ));
            console.print_plain(&"-".repeat(60));
        }

        // Rows
        for result in self.results {
            let status_text = self.format_status_plain(result);
            let latency_text = self.format_latency_plain(result);
            let ssh_text = if result.ssh_ok {
                Icons::check(self.context)
            } else {
                Icons::cross(self.context)
            };

            if self.verbose {
                let rsync_text = result
                    .rsync_available
                    .map(|b| {
                        if b {
                            Icons::check(self.context)
                        } else {
                            Icons::cross(self.context)
                        }
                    })
                    .unwrap_or("-");
                let cpu_text = result
                    .cpu_count
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "-".to_string());
                let disk_text = result
                    .disk_space_bytes
                    .map(format_bytes)
                    .unwrap_or_else(|| "-".to_string());

                console.print_plain(&format!(
                    "{:12} {:20} {:8} {:10} {:5} {:6} {:5} {:10}",
                    truncate_str(&result.basic.id, 12),
                    truncate_str(&result.basic.host, 20),
                    status_text,
                    latency_text,
                    ssh_text,
                    rsync_text,
                    cpu_text,
                    disk_text
                ));
            } else {
                console.print_plain(&format!(
                    "{:12} {:20} {:8} {:10} {:5}",
                    truncate_str(&result.basic.id, 12),
                    truncate_str(&result.basic.host, 20),
                    status_text,
                    latency_text,
                    ssh_text
                ));
            }

            // Show error if present
            if let Some(ref err) = result.basic.error {
                let warning = Icons::warning(self.context);
                console.print_plain(&format!("  {warning} {err}"));
            }
        }

        // Summary
        console.print_plain("");
        let (passed, failed) = self.count_results();
        let total = self.results.len();
        let avg_latency = self.average_latency();

        let summary = ProbeSummary {
            total,
            passed,
            failed,
            average_latency_ms: avg_latency,
        };
        summary.render(console, self.context);
    }

    /// Format status for plain display.
    fn format_status_plain(&self, result: &DetailedProbeResult) -> String {
        let icon = if result.is_success() {
            Icons::check(self.context)
        } else {
            Icons::cross(self.context)
        };

        let label = if result.is_success() { "OK" } else { "FAIL" };

        format!("{} {}", icon, label)
    }

    /// Format latency for plain display.
    fn format_latency_plain(&self, result: &DetailedProbeResult) -> String {
        match result.basic.latency_ms {
            Some(ms) => {
                let indicator = match result.latency_category() {
                    LatencyCategory::Excellent => Icons::status_healthy(self.context),
                    LatencyCategory::Acceptable => Icons::warning(self.context),
                    LatencyCategory::Degraded => Icons::cross(self.context),
                    LatencyCategory::Unknown => " ",
                };
                format!("{} {}ms", indicator, ms)
            }
            None => "-".to_string(),
        }
    }

    /// Count passed and failed results.
    fn count_results(&self) -> (usize, usize) {
        let passed = self.results.iter().filter(|r| r.is_success()).count();
        let failed = self.results.len() - passed;
        (passed, failed)
    }

    /// Calculate average latency for successful probes.
    fn average_latency(&self) -> Option<u64> {
        let latencies: Vec<u64> = self
            .results
            .iter()
            .filter_map(|r| r.basic.latency_ms)
            .collect();

        if latencies.is_empty() {
            None
        } else {
            Some(latencies.iter().sum::<u64>() / latencies.len() as u64)
        }
    }
}

/// Summary of probe results.
#[derive(Debug, Clone)]
pub struct ProbeSummary {
    /// Total workers probed.
    pub total: usize,
    /// Workers that passed probe.
    pub passed: usize,
    /// Workers that failed probe.
    pub failed: usize,
    /// Average latency in milliseconds.
    pub average_latency_ms: Option<u64>,
}

impl ProbeSummary {
    /// Render the summary.
    pub fn render(&self, console: &RchConsole, context: OutputContext) {
        let status_icon = if self.failed == 0 {
            Icons::check(context)
        } else {
            Icons::warning(context)
        };

        let latency_str = self
            .average_latency_ms
            .map(|ms| format!(" | Avg latency: {}ms", ms))
            .unwrap_or_default();

        let summary = format!(
            "{} Passed: {}/{} | Failed: {}{}",
            status_icon, self.passed, self.total, self.failed, latency_str
        );

        console.print_plain(&summary);

        // Recommendations
        self.render_recommendations(console, context);
    }

    /// Render recommendations based on probe results.
    fn render_recommendations(&self, console: &RchConsole, context: OutputContext) {
        if self.failed > 0 {
            let info = Icons::info(context);
            console.print_plain(&format!(
                "\n{} Tip: Use 'rch workers probe --verbose' for detailed diagnostics",
                info
            ));

            if self.failed == self.total {
                let warning = Icons::warning(context);
                console.print_plain(&format!(
                    "{} All workers failed. Check SSH connectivity and worker configuration.",
                    warning
                ));
            }
        }

        if let Some(avg_ms) = self.average_latency_ms
            && avg_ms > LATENCY_ACCEPTABLE_MS
        {
            let warning = Icons::warning(context);
            console.print_plain(&format!(
                "{} High average latency ({}ms). Consider using workers with lower latency.",
                warning, avg_ms
            ));
        }
    }
}

/// Truncate a string for display.
fn truncate_str(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len.saturating_sub(3)])
    }
}

/// Format bytes as human-readable string.
fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    const TB: u64 = GB * 1024;

    if bytes >= TB {
        format!("{:.1}TB", bytes as f64 / TB as f64)
    } else if bytes >= GB {
        format!("{:.1}GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1}MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1}KB", bytes as f64 / KB as f64)
    } else {
        format!("{}B", bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::WorkerProbeResult;

    fn sample_probe_results() -> Vec<DetailedProbeResult> {
        vec![
            DetailedProbeResult {
                basic: WorkerProbeResult {
                    id: "worker-1".to_string(),
                    host: "192.168.1.10".to_string(),
                    status: "ok".to_string(),
                    latency_ms: Some(25),
                    error: None,
                },
                ssh_ok: true,
                rsync_available: Some(true),
                disk_space_bytes: Some(100 * 1024 * 1024 * 1024), // 100GB
                cpu_count: Some(8),
                rust_version: Some("1.75.0".to_string()),
            },
            DetailedProbeResult {
                basic: WorkerProbeResult {
                    id: "worker-2".to_string(),
                    host: "192.168.1.11".to_string(),
                    status: "ok".to_string(),
                    latency_ms: Some(120),
                    error: None,
                },
                ssh_ok: true,
                rsync_available: Some(true),
                disk_space_bytes: Some(50 * 1024 * 1024 * 1024), // 50GB
                cpu_count: Some(4),
                rust_version: Some("1.74.0".to_string()),
            },
            DetailedProbeResult {
                basic: WorkerProbeResult {
                    id: "worker-3".to_string(),
                    host: "192.168.1.12".to_string(),
                    status: "failed".to_string(),
                    latency_ms: None,
                    error: Some("Connection refused".to_string()),
                },
                ssh_ok: false,
                rsync_available: None,
                disk_space_bytes: None,
                cpu_count: None,
                rust_version: None,
            },
        ]
    }

    #[test]
    fn test_probe_result_table_creation() {
        let results = sample_probe_results();
        let ctx = OutputContext::Plain;
        let table = ProbeResultTable::new(&results, ctx);
        assert_eq!(table.context, OutputContext::Plain);
        assert_eq!(table.results.len(), 3);
    }

    #[test]
    fn test_probe_result_from_results() {
        let results = sample_probe_results();
        let table = ProbeResultTable::from_results(&results);
        let _ = table.context; // Should not panic
    }

    #[test]
    fn test_detailed_probe_result_is_success() {
        let results = sample_probe_results();
        assert!(results[0].is_success());
        assert!(results[1].is_success());
        assert!(!results[2].is_success());
    }

    #[test]
    fn test_latency_category_excellent() {
        let result = DetailedProbeResult {
            basic: WorkerProbeResult {
                id: "test".to_string(),
                host: "test".to_string(),
                status: "ok".to_string(),
                latency_ms: Some(25),
                error: None,
            },
            ssh_ok: true,
            rsync_available: None,
            disk_space_bytes: None,
            cpu_count: None,
            rust_version: None,
        };
        assert_eq!(result.latency_category(), LatencyCategory::Excellent);
    }

    #[test]
    fn test_latency_category_acceptable() {
        let result = DetailedProbeResult {
            basic: WorkerProbeResult {
                id: "test".to_string(),
                host: "test".to_string(),
                status: "ok".to_string(),
                latency_ms: Some(100),
                error: None,
            },
            ssh_ok: true,
            rsync_available: None,
            disk_space_bytes: None,
            cpu_count: None,
            rust_version: None,
        };
        assert_eq!(result.latency_category(), LatencyCategory::Acceptable);
    }

    #[test]
    fn test_latency_category_degraded() {
        let result = DetailedProbeResult {
            basic: WorkerProbeResult {
                id: "test".to_string(),
                host: "test".to_string(),
                status: "ok".to_string(),
                latency_ms: Some(300),
                error: None,
            },
            ssh_ok: true,
            rsync_available: None,
            disk_space_bytes: None,
            cpu_count: None,
            rust_version: None,
        };
        assert_eq!(result.latency_category(), LatencyCategory::Degraded);
    }

    #[test]
    fn test_latency_category_unknown() {
        let result = DetailedProbeResult {
            basic: WorkerProbeResult {
                id: "test".to_string(),
                host: "test".to_string(),
                status: "failed".to_string(),
                latency_ms: None,
                error: Some("Error".to_string()),
            },
            ssh_ok: false,
            rsync_available: None,
            disk_space_bytes: None,
            cpu_count: None,
            rust_version: None,
        };
        assert_eq!(result.latency_category(), LatencyCategory::Unknown);
    }

    #[test]
    fn test_count_results() {
        let results = sample_probe_results();
        let table = ProbeResultTable::new(&results, OutputContext::Plain);
        let (passed, failed) = table.count_results();
        assert_eq!(passed, 2);
        assert_eq!(failed, 1);
    }

    #[test]
    fn test_average_latency() {
        let results = sample_probe_results();
        let table = ProbeResultTable::new(&results, OutputContext::Plain);
        let avg = table.average_latency();
        // (25 + 120) / 2 = 72 (integer division)
        assert_eq!(avg, Some(72));
    }

    #[test]
    fn test_truncate_str_short() {
        assert_eq!(truncate_str("hello", 10), "hello");
    }

    #[test]
    fn test_truncate_str_long() {
        let result = truncate_str("hello_world_this_is_long", 10);
        assert!(result.len() <= 10);
        assert!(result.ends_with("..."));
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(500), "500B");
        assert_eq!(format_bytes(1024), "1.0KB");
        assert_eq!(format_bytes(1024 * 1024), "1.0MB");
        assert_eq!(format_bytes(1024 * 1024 * 1024), "1.0GB");
        assert_eq!(format_bytes(1024u64 * 1024 * 1024 * 1024), "1.0TB");
    }

    #[test]
    fn test_render_plain_mode() {
        let results = sample_probe_results();
        let console = RchConsole::with_context(OutputContext::Plain);
        let table = ProbeResultTable::new(&results, OutputContext::Plain);
        // Should not panic
        table.render(&console);
    }

    #[test]
    fn test_render_verbose_mode() {
        let results = sample_probe_results();
        let console = RchConsole::with_context(OutputContext::Plain);
        let table = ProbeResultTable::new(&results, OutputContext::Plain).verbose(true);
        // Should not panic
        table.render(&console);
    }

    #[test]
    fn test_render_machine_mode_no_output() {
        let results = sample_probe_results();
        let console = RchConsole::with_context(OutputContext::Machine);
        let table = ProbeResultTable::new(&results, OutputContext::Machine);
        // Should not panic, should do nothing
        table.render(&console);
    }

    #[test]
    fn test_render_empty_results_plain() {
        let results: Vec<DetailedProbeResult> = vec![];
        let console = RchConsole::with_context(OutputContext::Plain);
        let table = ProbeResultTable::new(&results, OutputContext::Plain);
        // Should not panic
        table.render(&console);
    }

    #[test]
    fn test_probe_summary_render() {
        let summary = ProbeSummary {
            total: 3,
            passed: 2,
            failed: 1,
            average_latency_ms: Some(72),
        };
        let console = RchConsole::with_context(OutputContext::Plain);
        // Should not panic
        summary.render(&console, OutputContext::Plain);
    }

    #[test]
    fn test_probe_summary_all_failed() {
        let summary = ProbeSummary {
            total: 3,
            passed: 0,
            failed: 3,
            average_latency_ms: None,
        };
        let console = RchConsole::with_context(OutputContext::Plain);
        // Should not panic and should show recommendations
        summary.render(&console, OutputContext::Plain);
    }

    #[test]
    fn test_detailed_probe_from_basic() {
        let basic = WorkerProbeResult {
            id: "test".to_string(),
            host: "test".to_string(),
            status: "ok".to_string(),
            latency_ms: Some(50),
            error: None,
        };
        let detailed = DetailedProbeResult::from_basic(basic, true);
        assert!(detailed.ssh_ok);
        assert!(detailed.rsync_available.is_none());
    }
}
