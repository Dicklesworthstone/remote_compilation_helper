//! WorkerTable - Rich terminal display for `rch workers list` command.
//!
//! This module provides context-aware worker fleet display using rich_rust.
//! Falls back to plain text when rich output is not available.

use crate::status_types::WorkerStatusFromApi;
use crate::ui::console::RchConsole;

#[cfg(feature = "rich-ui")]
use rich_rust::prelude::*;
#[cfg(feature = "rich-ui")]
use rich_rust::renderables::{Column, Row, Table};

use rch_common::ui::{Icons, OutputContext, RchTheme};

/// WorkerTable renders worker fleet status with rich formatting.
///
/// Displays:
/// - Worker ID and host
/// - Status with colored indicator
/// - Slot usage (used/total)
/// - Speed score
/// - Circuit breaker state
/// - Last error (if any)
pub struct WorkerTable<'a> {
    workers: &'a [WorkerStatusFromApi],
    context: OutputContext,
}

impl<'a> WorkerTable<'a> {
    /// Create a new WorkerTable from worker status list.
    #[must_use]
    pub fn new(workers: &'a [WorkerStatusFromApi], context: OutputContext) -> Self {
        Self { workers, context }
    }

    /// Create from workers with auto-detected context.
    #[must_use]
    pub fn from_workers(workers: &'a [WorkerStatusFromApi]) -> Self {
        Self::new(workers, OutputContext::detect())
    }

    /// Render the worker table using RchConsole.
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
        if self.workers.is_empty() {
            self.render_empty_rich(console);
            return;
        }

        let mut table = Table::new()
            .title("Workers")
            .border_style(RchTheme::secondary());

        // Add columns
        table = table
            .with_column(Column::new("ID").header_style(RchTheme::table_header()))
            .with_column(Column::new("Host").header_style(RchTheme::table_header()))
            .with_column(Column::new("Status").header_style(RchTheme::table_header()))
            .with_column(Column::new("Slots").header_style(RchTheme::table_header()))
            .with_column(Column::new("Speed").header_style(RchTheme::table_header()))
            .with_column(Column::new("Circuit").header_style(RchTheme::table_header()));

        // Add rows
        for worker in self.workers {
            let status_text = self.format_status_rich(worker);
            let slots_text = format!("{}/{}", worker.used_slots, worker.total_slots);
            let speed_text = format!("{:.1}", worker.speed_score);
            let circuit_text = self.format_circuit_state(worker);

            let row = Row::new(vec![
                Cell::new(worker.id.as_str()),
                Cell::new(worker.host.as_str()),
                Cell::new(status_text.as_str()),
                Cell::new(slots_text.as_str()),
                Cell::new(speed_text.as_str()),
                Cell::new(circuit_text.as_str()),
            ]);
            table = table.with_row(row);
        }

        console.print_renderable(&table);

        // Summary footer
        self.render_summary_rich(console);
    }

    /// Render empty state with rich formatting.
    #[cfg(feature = "rich-ui")]
    fn render_empty_rich(&self, console: &RchConsole) {
        let info = Icons::info(self.context);
        let content = format!("{} No workers configured\n\nAdd workers with: rch workers add <host>", info);
        let panel = Panel::from_text(&content)
            .title("Workers")
            .border_style(RchTheme::muted())
            .rounded();
        console.print_renderable(&panel);
    }

    /// Format status for rich display.
    #[cfg(feature = "rich-ui")]
    fn format_status_rich(&self, worker: &WorkerStatusFromApi) -> String {
        match worker.status.as_str() {
            "healthy" | "online" => format!("{} Online", Icons::status_healthy(self.context)),
            "busy" => format!("{} Busy", Icons::worker(self.context)),
            "degraded" => format!("{} Degraded", Icons::warning(self.context)),
            "offline" | "unhealthy" => format!("{} Offline", Icons::cross(self.context)),
            "draining" => format!("{} Draining", Icons::info(self.context)),
            other => other.to_string(),
        }
    }

    /// Format circuit breaker state.
    fn format_circuit_state(&self, worker: &WorkerStatusFromApi) -> String {
        match worker.circuit_state.as_str() {
            "closed" => "OK".to_string(),
            "half_open" | "half-open" => "Testing".to_string(),
            "open" => {
                if let Some(secs) = worker.recovery_in_secs {
                    format!("Open ({secs}s)")
                } else {
                    "Open".to_string()
                }
            }
            other => other.to_string(),
        }
    }

    /// Render summary footer.
    #[cfg(feature = "rich-ui")]
    fn render_summary_rich(&self, console: &RchConsole) {
        let online = self.workers.iter().filter(|w| w.status == "healthy" || w.status == "online").count();
        let total = self.workers.len();
        let total_slots: u32 = self.workers.iter().map(|w| w.total_slots).sum();
        let used_slots: u32 = self.workers.iter().map(|w| w.used_slots).sum();

        let summary = format!(
            "Total: {} workers ({} online) | Slots: {}/{} available",
            total, online, total_slots - used_slots, total_slots
        );
        console.print_plain(&summary);
    }

    /// Render plain text output (no rich formatting).
    fn render_plain(&self, console: &RchConsole) {
        if self.workers.is_empty() {
            console.print_plain("=== Workers ===");
            console.print_plain("");
            let info = Icons::info(self.context);
            console.print_plain(&format!("{info} No workers configured"));
            console.print_plain("  Add workers with: rch workers add <host>");
            return;
        }

        console.print_plain("=== Workers ===");
        console.print_plain("");

        // Header
        console.print_plain(&format!(
            "{:12} {:20} {:12} {:8} {:6} {:10}",
            "ID", "Host", "Status", "Slots", "Speed", "Circuit"
        ));
        console.print_plain(&"-".repeat(70));

        // Rows
        for worker in self.workers {
            let status_text = self.format_status_plain(worker);
            let slots_text = format!("{}/{}", worker.used_slots, worker.total_slots);
            let speed_text = format!("{:.1}", worker.speed_score);
            let circuit_text = self.format_circuit_state(worker);

            console.print_plain(&format!(
                "{:12} {:20} {:12} {:8} {:6} {:10}",
                truncate_str(&worker.id, 12),
                truncate_str(&worker.host, 20),
                status_text,
                slots_text,
                speed_text,
                circuit_text
            ));

            // Show error if present
            if let Some(ref err) = worker.last_error {
                let warning = Icons::warning(self.context);
                console.print_plain(&format!("  {warning} {err}"));
            }
        }

        // Summary
        console.print_plain("");
        let online = self.workers.iter().filter(|w| w.status == "healthy" || w.status == "online").count();
        let total = self.workers.len();
        let total_slots: u32 = self.workers.iter().map(|w| w.total_slots).sum();
        let used_slots: u32 = self.workers.iter().map(|w| w.used_slots).sum();

        console.print_plain(&format!(
            "Total: {} workers ({} online) | Slots: {}/{} available",
            total, online, total_slots - used_slots, total_slots
        ));
    }

    /// Format status for plain display.
    fn format_status_plain(&self, worker: &WorkerStatusFromApi) -> String {
        let icon = match worker.status.as_str() {
            "healthy" | "online" => Icons::status_healthy(self.context),
            "busy" => Icons::worker(self.context),
            "degraded" => Icons::warning(self.context),
            "offline" | "unhealthy" => Icons::cross(self.context),
            "draining" => Icons::info(self.context),
            _ => " ",
        };

        let status_label = match worker.status.as_str() {
            "healthy" | "online" => "Online",
            "busy" => "Busy",
            "degraded" => "Degraded",
            "offline" | "unhealthy" => "Offline",
            "draining" => "Draining",
            other => other,
        };

        format!("{} {}", icon, status_label)
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

    fn sample_workers() -> Vec<WorkerStatusFromApi> {
        vec![
            WorkerStatusFromApi {
                id: "worker-1".to_string(),
                host: "192.168.1.10".to_string(),
                user: "ubuntu".to_string(),
                status: "healthy".to_string(),
                circuit_state: "closed".to_string(),
                used_slots: 2,
                total_slots: 8,
                speed_score: 1.5,
                last_error: None,
                consecutive_failures: 0,
                recovery_in_secs: None,
                failure_history: vec![],
            },
            WorkerStatusFromApi {
                id: "worker-2".to_string(),
                host: "192.168.1.11".to_string(),
                user: "ubuntu".to_string(),
                status: "offline".to_string(),
                circuit_state: "open".to_string(),
                used_slots: 0,
                total_slots: 8,
                speed_score: 0.0,
                last_error: Some("Connection refused".to_string()),
                consecutive_failures: 3,
                recovery_in_secs: Some(45),
                failure_history: vec![false, false, false],
            },
        ]
    }

    #[test]
    fn test_worker_table_creation() {
        let workers = sample_workers();
        let ctx = OutputContext::Plain;
        let table = WorkerTable::new(&workers, ctx);
        assert_eq!(table.context, OutputContext::Plain);
        assert_eq!(table.workers.len(), 2);
    }

    #[test]
    fn test_worker_table_from_workers() {
        let workers = sample_workers();
        let table = WorkerTable::from_workers(&workers);
        let _ = table.context; // Should not panic
    }

    #[test]
    fn test_format_circuit_state_closed() {
        let workers = sample_workers();
        let table = WorkerTable::new(&workers, OutputContext::Plain);
        let result = table.format_circuit_state(&workers[0]);
        assert_eq!(result, "OK");
    }

    #[test]
    fn test_format_circuit_state_open_with_recovery() {
        let workers = sample_workers();
        let table = WorkerTable::new(&workers, OutputContext::Plain);
        let result = table.format_circuit_state(&workers[1]);
        assert_eq!(result, "Open (45s)");
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
        let workers = sample_workers();
        let console = RchConsole::with_context(OutputContext::Plain);
        let table = WorkerTable::new(&workers, OutputContext::Plain);
        // Should not panic
        table.render(&console);
    }

    #[test]
    fn test_render_machine_mode_no_output() {
        let workers = sample_workers();
        let console = RchConsole::with_context(OutputContext::Machine);
        let table = WorkerTable::new(&workers, OutputContext::Machine);
        // Should not panic, should do nothing
        table.render(&console);
    }

    #[test]
    fn test_render_empty_workers_plain() {
        let workers: Vec<WorkerStatusFromApi> = vec![];
        let console = RchConsole::with_context(OutputContext::Plain);
        let table = WorkerTable::new(&workers, OutputContext::Plain);
        // Should not panic
        table.render(&console);
    }

    #[test]
    fn test_format_status_plain_online() {
        let workers = sample_workers();
        let table = WorkerTable::new(&workers, OutputContext::Plain);
        let result = table.format_status_plain(&workers[0]);
        assert!(result.contains("Online"));
    }

    #[test]
    fn test_format_status_plain_offline() {
        let workers = sample_workers();
        let table = WorkerTable::new(&workers, OutputContext::Plain);
        let result = table.format_status_plain(&workers[1]);
        assert!(result.contains("Offline"));
    }
}
