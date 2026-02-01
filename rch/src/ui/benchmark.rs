//! BenchmarkTable - Rich terminal display for `rch workers benchmark` command.
//!
//! This module provides context-aware benchmark results display using rich_rust.
//! Falls back to plain text when rich output is not available.

use crate::commands::WorkerBenchmarkResult;
use crate::ui::console::RchConsole;

#[cfg(all(feature = "rich-ui", unix))]
use rich_rust::prelude::*;
#[cfg(all(feature = "rich-ui", unix))]
use rich_rust::renderables::{Column, Row, Table};

use rch_common::ui::{Icons, OutputContext, RchTheme};

/// BenchmarkTable renders worker benchmark results with rich formatting.
///
/// Displays:
/// - Worker ID and host
/// - Status with colored indicator
/// - Duration (if available)
/// - Relative performance bar
/// - Error message (if failed)
pub struct BenchmarkTable<'a> {
    results: &'a [WorkerBenchmarkResult],
    context: OutputContext,
}

impl<'a> BenchmarkTable<'a> {
    /// Create a new BenchmarkTable from benchmark results.
    #[must_use]
    pub fn new(results: &'a [WorkerBenchmarkResult], context: OutputContext) -> Self {
        Self { results, context }
    }

    /// Create from results with auto-detected context.
    #[must_use]
    pub fn from_results(results: &'a [WorkerBenchmarkResult]) -> Self {
        Self::new(results, OutputContext::detect())
    }

    /// Render the benchmark table using RchConsole.
    pub fn render(&self, console: &RchConsole) {
        if console.is_machine() {
            // JSON mode - don't render, caller should use print_json
            return;
        }

        #[cfg(all(feature = "rich-ui", unix))]
        if console.is_rich() {
            self.render_rich(console);
            return;
        }

        self.render_plain(console);
    }

    /// Get the fastest duration for relative comparisons.
    fn fastest_duration(&self) -> Option<u64> {
        self.results.iter().filter_map(|r| r.duration_ms).min()
    }

    /// Render rich output using rich_rust.
    #[cfg(all(feature = "rich-ui", unix))]
    fn render_rich(&self, console: &RchConsole) {
        if self.results.is_empty() {
            self.render_empty_rich(console);
            return;
        }

        let fastest = self.fastest_duration();

        let mut table = Table::new()
            .title("Benchmark Results")
            .border_style(RchTheme::secondary());

        // Add columns
        table = table
            .with_column(Column::new("Worker").header_style(RchTheme::table_header()))
            .with_column(Column::new("Host").header_style(RchTheme::table_header()))
            .with_column(Column::new("Status").header_style(RchTheme::table_header()))
            .with_column(Column::new("Duration").header_style(RchTheme::table_header()))
            .with_column(Column::new("Relative").header_style(RchTheme::table_header()));

        // Add rows
        for result in self.results {
            let status_text = self.format_status_rich(result);
            let duration_text = self.format_duration(result);
            let relative_text = self.format_relative_bar(result, fastest);

            let row = Row::new(vec![
                Cell::new(result.id.as_str()),
                Cell::new(result.host.as_str()),
                Cell::new(status_text.as_str()),
                Cell::new(duration_text.as_str()),
                Cell::new(relative_text.as_str()),
            ]);
            table = table.with_row(row);
        }

        console.print_renderable(&table);

        // Summary panel
        self.render_summary_rich(console);
    }

    /// Render empty state with rich formatting.
    #[cfg(all(feature = "rich-ui", unix))]
    fn render_empty_rich(&self, console: &RchConsole) {
        let info = Icons::info(self.context);
        let content = format!(
            "{} No benchmark results\n\nRun with: rch workers benchmark",
            info
        );
        let panel = Panel::from_text(&content)
            .title("Benchmark Results")
            .border_style(RchTheme::muted())
            .rounded();
        console.print_renderable(&panel);
    }

    /// Format status for rich display.
    #[cfg(all(feature = "rich-ui", unix))]
    fn format_status_rich(&self, result: &WorkerBenchmarkResult) -> String {
        match result.status.as_str() {
            "ok" => format!("{} OK", Icons::check(self.context)),
            "failed" => format!("{} Failed", Icons::cross(self.context)),
            "error" | "connection_failed" => format!("{} Error", Icons::cross(self.context)),
            other => other.to_string(),
        }
    }

    /// Format duration for display.
    fn format_duration(&self, result: &WorkerBenchmarkResult) -> String {
        match result.duration_ms {
            Some(ms) => format_ms(ms),
            None => "-".to_string(),
        }
    }

    /// Format relative performance bar.
    fn format_relative_bar(&self, result: &WorkerBenchmarkResult, fastest: Option<u64>) -> String {
        match (result.duration_ms, fastest) {
            (Some(duration), Some(fast)) if fast > 0 => {
                let ratio = fast as f64 / duration as f64;
                let bar_len = (ratio * 10.0).round() as usize;
                let bar_len = bar_len.min(10);

                let filled = "█".repeat(bar_len);
                let empty = "░".repeat(10 - bar_len);

                if bar_len == 10 {
                    format!("{filled}{empty} ★") // Winner marker
                } else {
                    format!("{filled}{empty}")
                }
            }
            _ => "".to_string(),
        }
    }

    /// Render summary panel.
    #[cfg(all(feature = "rich-ui", unix))]
    fn render_summary_rich(&self, console: &RchConsole) {
        let total = self.results.len();
        let successful = self.results.iter().filter(|r| r.status == "ok").count();
        let failed = total - successful;

        let mut summary_lines = Vec::new();

        // Pass/fail counts
        let check = Icons::check(self.context);
        let cross = Icons::cross(self.context);
        summary_lines.push(format!(
            "{check} {successful} passed, {cross} {failed} failed"
        ));

        // Find and highlight the winner
        if let Some(winner) = self.find_winner() {
            let star = Icons::lightning(self.context);
            summary_lines.push(format!(
                "{star} Fastest: {} ({})",
                winner.id,
                self.format_duration(winner)
            ));
        }

        // Add recommendation if any failures
        if failed > 0 {
            let warning = Icons::warning(self.context);
            summary_lines.push(format!("{warning} Check connectivity for failed workers"));
        }

        let content = summary_lines.join("\n");
        console.print_plain(&content);
    }

    /// Find the benchmark winner (fastest).
    fn find_winner(&self) -> Option<&WorkerBenchmarkResult> {
        self.results
            .iter()
            .filter(|r| r.status == "ok" && r.duration_ms.is_some())
            .min_by_key(|r| r.duration_ms)
    }

    /// Render plain text output (no rich formatting).
    fn render_plain(&self, console: &RchConsole) {
        if self.results.is_empty() {
            console.print_plain("=== Benchmark Results ===");
            console.print_plain("");
            let info = Icons::info(self.context);
            console.print_plain(&format!("{info} No benchmark results"));
            console.print_plain("  Run with: rch workers benchmark");
            return;
        }

        let fastest = self.fastest_duration();

        console.print_plain("=== Benchmark Results ===");
        console.print_plain("");

        // Header
        console.print_plain(&format!(
            "{:12} {:20} {:10} {:12} {:12}",
            "Worker", "Host", "Status", "Duration", "Relative"
        ));
        console.print_plain(&"-".repeat(68));

        // Rows
        for result in self.results {
            let status_text = self.format_status_plain(result);
            let duration_text = self.format_duration(result);
            let relative_text = self.format_relative_bar(result, fastest);

            console.print_plain(&format!(
                "{:12} {:20} {:10} {:12} {:12}",
                truncate_str(&result.id, 12),
                truncate_str(&result.host, 20),
                status_text,
                duration_text,
                relative_text
            ));

            // Show error if present
            if let Some(ref err) = result.error {
                let warning = Icons::warning(self.context);
                console.print_plain(&format!("  {warning} {}", truncate_str(err, 60)));
            }
        }

        // Summary
        console.print_plain("");
        let total = self.results.len();
        let successful = self.results.iter().filter(|r| r.status == "ok").count();
        let failed = total - successful;

        let check = Icons::check(self.context);
        let cross = Icons::cross(self.context);
        console.print_plain(&format!(
            "{check} {successful} passed, {cross} {failed} failed"
        ));

        if let Some(winner) = self.find_winner() {
            let star = Icons::lightning(self.context);
            console.print_plain(&format!(
                "{star} Fastest: {} ({})",
                winner.id,
                self.format_duration(winner)
            ));
        }
    }

    /// Format status for plain display.
    fn format_status_plain(&self, result: &WorkerBenchmarkResult) -> String {
        let icon = match result.status.as_str() {
            "ok" => Icons::check(self.context),
            "failed" | "error" | "connection_failed" => Icons::cross(self.context),
            _ => " ",
        };

        let label = match result.status.as_str() {
            "ok" => "OK",
            "failed" => "Failed",
            "error" => "Error",
            "connection_failed" => "ConnFail",
            other => other,
        };

        format!("{} {}", icon, label)
    }
}

/// Format milliseconds as human-readable duration.
fn format_ms(ms: u64) -> String {
    if ms < 1000 {
        format!("{ms}ms")
    } else {
        format!("{:.1}s", ms as f64 / 1000.0)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_results() -> Vec<WorkerBenchmarkResult> {
        vec![
            WorkerBenchmarkResult {
                id: "worker-1".to_string(),
                host: "192.168.1.10".to_string(),
                status: "ok".to_string(),
                duration_ms: Some(1234),
                error: None,
            },
            WorkerBenchmarkResult {
                id: "worker-2".to_string(),
                host: "192.168.1.11".to_string(),
                status: "ok".to_string(),
                duration_ms: Some(2345),
                error: None,
            },
            WorkerBenchmarkResult {
                id: "worker-3".to_string(),
                host: "192.168.1.12".to_string(),
                status: "connection_failed".to_string(),
                duration_ms: None,
                error: Some("Connection refused".to_string()),
            },
        ]
    }

    #[test]
    fn test_benchmark_table_creation() {
        let results = sample_results();
        let ctx = OutputContext::Plain;
        let table = BenchmarkTable::new(&results, ctx);
        assert_eq!(table.context, OutputContext::Plain);
        assert_eq!(table.results.len(), 3);
    }

    #[test]
    fn test_benchmark_table_from_results() {
        let results = sample_results();
        let table = BenchmarkTable::from_results(&results);
        let _ = table.context; // Should not panic
    }

    #[test]
    fn test_fastest_duration() {
        let results = sample_results();
        let table = BenchmarkTable::new(&results, OutputContext::Plain);
        assert_eq!(table.fastest_duration(), Some(1234));
    }

    #[test]
    fn test_fastest_duration_empty() {
        let results: Vec<WorkerBenchmarkResult> = vec![];
        let table = BenchmarkTable::new(&results, OutputContext::Plain);
        assert_eq!(table.fastest_duration(), None);
    }

    #[test]
    fn test_find_winner() {
        let results = sample_results();
        let table = BenchmarkTable::new(&results, OutputContext::Plain);
        let winner = table.find_winner();
        assert!(winner.is_some());
        assert_eq!(winner.unwrap().id, "worker-1");
    }

    #[test]
    fn test_format_duration_ms() {
        let results = sample_results();
        let table = BenchmarkTable::new(&results, OutputContext::Plain);
        assert_eq!(table.format_duration(&results[0]), "1.2s");
    }

    #[test]
    fn test_format_duration_none() {
        let results = sample_results();
        let table = BenchmarkTable::new(&results, OutputContext::Plain);
        assert_eq!(table.format_duration(&results[2]), "-");
    }

    #[test]
    fn test_format_relative_bar_winner() {
        let results = sample_results();
        let table = BenchmarkTable::new(&results, OutputContext::Plain);
        let bar = table.format_relative_bar(&results[0], Some(1234));
        assert!(bar.contains("★")); // Winner marker
    }

    #[test]
    fn test_format_relative_bar_slower() {
        let results = sample_results();
        let table = BenchmarkTable::new(&results, OutputContext::Plain);
        let bar = table.format_relative_bar(&results[1], Some(1234));
        assert!(!bar.contains("★")); // Not winner
        assert!(bar.contains("█")); // Has some filled
    }

    #[test]
    fn test_format_ms_milliseconds() {
        assert_eq!(format_ms(500), "500ms");
        assert_eq!(format_ms(999), "999ms");
    }

    #[test]
    fn test_format_ms_seconds() {
        assert_eq!(format_ms(1000), "1.0s");
        assert_eq!(format_ms(2500), "2.5s");
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
    fn test_render_plain_mode() {
        let results = sample_results();
        let console = RchConsole::with_context(OutputContext::Plain);
        let table = BenchmarkTable::new(&results, OutputContext::Plain);
        // Should not panic
        table.render(&console);
    }

    #[test]
    fn test_render_machine_mode_no_output() {
        let results = sample_results();
        let console = RchConsole::with_context(OutputContext::Machine);
        let table = BenchmarkTable::new(&results, OutputContext::Machine);
        // Should not panic, should do nothing
        table.render(&console);
    }

    #[test]
    fn test_render_empty_results_plain() {
        let results: Vec<WorkerBenchmarkResult> = vec![];
        let console = RchConsole::with_context(OutputContext::Plain);
        let table = BenchmarkTable::new(&results, OutputContext::Plain);
        // Should not panic
        table.render(&console);
    }

    #[test]
    fn test_format_status_plain_ok() {
        let results = sample_results();
        let table = BenchmarkTable::new(&results, OutputContext::Plain);
        let status = table.format_status_plain(&results[0]);
        assert!(status.contains("OK"));
    }

    #[test]
    fn test_format_status_plain_failed() {
        let results = sample_results();
        let table = BenchmarkTable::new(&results, OutputContext::Plain);
        let status = table.format_status_plain(&results[2]);
        assert!(status.contains("ConnFail"));
    }
}
