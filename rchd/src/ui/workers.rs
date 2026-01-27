//! WorkerStatusPanel - real-time worker fleet status output for rchd.
//!
//! Provides:
//! - Compact summary lines for log output
//! - Periodic full status table refresh
//! - Worker state change announcements
//! - Optional routing decision logging when debug enabled

#![allow(dead_code)]

use crate::workers::WorkerPool;
use chrono::Local;
use rch_common::ui::{Icons, OutputContext};
use rch_common::{SelectionStrategy, WorkerStatus};
use std::cmp::Ordering;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use std::time::{Duration, Instant};

#[cfg(feature = "rich-ui")]
use rch_common::ui::RchTheme;
#[cfg(feature = "rich-ui")]
use rich_rust::prelude::*;
#[cfg(feature = "rich-ui")]
use rich_rust::renderables::{Column, Row, Table};

const DEFAULT_REFRESH_SECS: u64 = 30;
const BULK_CHANGE_THRESHOLD: usize = 4;
const DEFAULT_TABLE_WIDTH: usize = 72;

static DEBUG_ROUTING_ENABLED: AtomicBool = AtomicBool::new(false);

/// Enable routing debug output from within the daemon process.
///
/// We prefer this over mutating environment variables, which is `unsafe` in
/// Rust 2024 due to potential races with other threads reading env.
pub fn set_debug_routing_enabled(enabled: bool) {
    DEBUG_ROUTING_ENABLED.store(enabled, AtomicOrdering::Relaxed);
}

#[derive(Debug, Clone)]
pub struct WorkerSnapshot {
    pub id: String,
    pub status: WorkerStatus,
    pub used_slots: u32,
    pub total_slots: u32,
    pub speed_score: f64,
    pub tags: Vec<String>,
}

impl WorkerSnapshot {
    pub fn new(
        id: impl Into<String>,
        status: WorkerStatus,
        used_slots: u32,
        total_slots: u32,
        speed_score: f64,
        tags: Vec<String>,
    ) -> Self {
        Self {
            id: id.into(),
            status,
            used_slots,
            total_slots,
            speed_score,
            tags,
        }
    }
}

#[derive(Debug)]
pub struct WorkerStatusPanel {
    ctx: OutputContext,
    refresh_interval: Duration,
    last_refresh: Instant,
    last_summary: Instant,
    last_statuses: HashMap<String, WorkerStatus>,
    verbose: bool,
    debug_routing: bool,
}

#[derive(Debug)]
pub struct WorkerStatusPlan {
    pub lines: Vec<String>,
    pub render_table: bool,
}

impl WorkerStatusPanel {
    #[must_use]
    pub fn new() -> Self {
        Self::with_context(OutputContext::detect())
    }

    #[must_use]
    pub fn with_context(ctx: OutputContext) -> Self {
        let refresh_interval = refresh_interval_from_env();
        let now = Instant::now();
        let last = now.checked_sub(refresh_interval).unwrap_or(now);
        Self {
            ctx,
            refresh_interval,
            last_refresh: last,
            last_summary: last,
            last_statuses: HashMap::new(),
            verbose: verbose_from_env(),
            debug_routing: debug_routing_enabled(),
        }
    }

    #[must_use]
    pub fn with_refresh_interval(mut self, interval: Duration) -> Self {
        self.refresh_interval = interval.max(Duration::from_secs(1));
        self
    }

    #[must_use]
    pub fn with_verbose(mut self, verbose: bool) -> Self {
        self.verbose = verbose;
        self
    }

    #[must_use]
    pub fn with_debug_routing(mut self, enabled: bool) -> Self {
        self.debug_routing = enabled;
        self
    }

    pub fn set_verbose(&mut self, verbose: bool) {
        self.verbose = verbose;
    }

    pub fn set_debug_routing(&mut self, enabled: bool) {
        self.debug_routing = enabled;
    }

    pub async fn collect_snapshot(pool: &WorkerPool) -> Vec<WorkerSnapshot> {
        let mut snapshots = Vec::new();
        let workers = pool.all_workers().await;
        for worker in workers {
            let config = worker.config.read().await;
            let id = config.id.as_str().to_string();
            let total_slots = config.total_slots;
            let tags = config.tags.clone();
            drop(config);

            let status = worker.status().await;
            let available_slots = worker.available_slots().await;
            let used_slots = total_slots.saturating_sub(available_slots);
            let speed_score = worker.get_speed_score().await;

            snapshots.push(WorkerSnapshot::new(
                id,
                status,
                used_slots,
                total_slots,
                speed_score,
                tags,
            ));
        }
        snapshots.sort_by(|a, b| a.id.cmp(&b.id));
        snapshots
    }

    #[must_use]
    pub fn render_update(
        &mut self,
        snapshot: &[WorkerSnapshot],
        queue_depth: usize,
    ) -> WorkerStatusPlan {
        let mut lines = Vec::new();
        let now = Instant::now();

        let changes = self.detect_changes(snapshot);
        if !changes.is_empty() {
            lines.extend(self.render_changes(&changes));
        }

        let summary_due = now.duration_since(self.last_summary) >= self.refresh_interval;
        if summary_due || !changes.is_empty() {
            lines.push(self.render_summary(snapshot, queue_depth));
            self.last_summary = now;
        }

        let refresh_due = now.duration_since(self.last_refresh) >= self.refresh_interval;
        let render_table = refresh_due && self.ctx.supports_rich();
        if refresh_due && !self.ctx.supports_rich() {
            lines.extend(self.render_table_plain(snapshot));
            self.last_refresh = now;
        } else if refresh_due {
            self.last_refresh = now;
        }

        if self.ctx.is_machine() {
            return WorkerStatusPlan {
                lines: Vec::new(),
                render_table: false,
            };
        }

        WorkerStatusPlan {
            lines,
            render_table,
        }
    }

    pub fn emit_update(&mut self, snapshot: &[WorkerSnapshot], queue_depth: usize) {
        let plan = self.render_update(snapshot, queue_depth);
        for line in plan.lines {
            eprintln!("{line}");
        }

        #[cfg(feature = "rich-ui")]
        if plan.render_table {
            self.render_table_rich(snapshot);
        }
    }

    fn detect_changes(&mut self, snapshot: &[WorkerSnapshot]) -> Vec<WorkerChange> {
        let mut changes = Vec::new();
        for worker in snapshot {
            let prev = self.last_statuses.get(&worker.id).copied();
            if prev != Some(worker.status) {
                let change = WorkerChange {
                    id: worker.id.clone(),
                    previous: prev,
                    current: worker.status,
                };
                changes.push(change);
                self.last_statuses.insert(worker.id.clone(), worker.status);
            }
        }
        changes
    }

    fn render_changes(&self, changes: &[WorkerChange]) -> Vec<String> {
        if changes.len() > BULK_CHANGE_THRESHOLD {
            return self.render_changes_aggregated(changes);
        }

        let mut lines = Vec::new();
        for change in changes {
            lines.push(self.render_change_line(change));
        }
        lines
    }

    fn render_changes_aggregated(&self, changes: &[WorkerChange]) -> Vec<String> {
        let mut groups: HashMap<(Option<&'static str>, &'static str), usize> = HashMap::new();
        for change in changes {
            let prev_label = change.previous.map(status_label);
            let current_label = status_label(change.current);
            *groups.entry((prev_label, current_label)).or_insert(0) += 1;
        }

        let mut lines = Vec::new();
        for ((prev_label, current_label), count) in groups {
            let prev_label = prev_label.unwrap_or("NEW");
            lines.push(format!(
                "{} {} workers: {} -> {}",
                prefix_now(),
                count,
                prev_label,
                current_label
            ));
        }
        lines
    }

    fn render_change_line(&self, change: &WorkerChange) -> String {
        let prev_label = change.previous.map(status_label).unwrap_or("NEW");
        let current_label = status_label(change.current);
        let event = connection_event(change.previous, change.current);

        if let Some(event) = event {
            format!(
                "{} {}: {} -> {} ({})",
                prefix_now(),
                change.id,
                prev_label,
                current_label,
                event
            )
        } else {
            format!(
                "{} {}: {} -> {}",
                prefix_now(),
                change.id,
                prev_label,
                current_label
            )
        }
    }

    fn render_summary(&self, snapshot: &[WorkerSnapshot], queue_depth: usize) -> String {
        let total = snapshot.len();
        let online = snapshot.iter().filter(|w| is_online(w.status)).count();

        let used_slots: u32 = snapshot.iter().map(|w| w.used_slots).sum();
        let load = if online == 0 {
            0.0
        } else {
            used_slots as f64 / online as f64
        };

        let jobs_label = if queue_depth == 1 { "job" } else { "jobs" };
        format!(
            "[WORKERS] {}/{} online | load: {:.1} | queue: {} {}",
            online, total, load, queue_depth, jobs_label
        )
    }

    fn render_table_plain(&self, snapshot: &[WorkerSnapshot]) -> Vec<String> {
        let mut lines = Vec::new();
        if self.verbose {
            lines.push(rule_line("Workers", DEFAULT_TABLE_WIDTH));
        }
        if snapshot.is_empty() {
            let info = Icons::info(self.ctx);
            lines.push(format!("{info} No workers configured"));
            return lines;
        }

        lines.push(format!(
            "{:12} {:12} {:10} {:6} {:18}",
            "ID", "Status", "Slots", "Speed", "Tags"
        ));
        lines.push("-".repeat(DEFAULT_TABLE_WIDTH));

        for worker in snapshot {
            let status_text = status_label(worker.status);
            let slots_text = format!("{}/{}", worker.used_slots, worker.total_slots);
            let speed_text = format!("{:.1}", worker.speed_score);
            let tags_text = if worker.tags.is_empty() {
                "-".to_string()
            } else {
                truncate(&worker.tags.join(","), 18)
            };

            lines.push(format!(
                "{:12} {:12} {:10} {:6} {:18}",
                truncate(&worker.id, 12),
                status_text,
                slots_text,
                speed_text,
                tags_text
            ));
        }
        lines
    }

    #[cfg(feature = "rich-ui")]
    fn render_table_rich(&self, snapshot: &[WorkerSnapshot]) {
        if snapshot.is_empty() {
            let info = Icons::info(self.ctx);
            let message = format!("{info} No workers configured");
            let panel = Panel::from_text(message.as_str())
                .title("Workers")
                .border_style(RchTheme::muted())
                .rounded();
            let console = Console::builder().force_terminal(true).build();
            console.print_renderable(&panel);
            return;
        }

        let mut table = Table::new()
            .title("Workers")
            .border_style(RchTheme::secondary());

        table = table
            .with_column(Column::new("ID").header_style(RchTheme::table_header()))
            .with_column(Column::new("Status").header_style(RchTheme::table_header()))
            .with_column(Column::new("Slots").header_style(RchTheme::table_header()))
            .with_column(Column::new("Speed").header_style(RchTheme::table_header()))
            .with_column(Column::new("Tags").header_style(RchTheme::table_header()));

        for worker in snapshot {
            let status_text = format_status_rich(self.ctx, worker.status);
            let slots_text = format!("{}/{}", worker.used_slots, worker.total_slots);
            let speed_text = format!("{:.1}", worker.speed_score);
            let tags_text = if worker.tags.is_empty() {
                "-".to_string()
            } else {
                worker.tags.join(",")
            };

            let row = Row::new(vec![
                Cell::new(worker.id.as_str()),
                Cell::new(status_text.as_str()),
                Cell::new(slots_text.as_str()),
                Cell::new(speed_text.as_str()),
                Cell::new(tags_text.as_str()),
            ]);
            table = table.with_row(row);
        }

        let console = Console::builder().force_terminal(true).build();
        if self.verbose {
            console.rule(Some("Workers"));
        }
        console.print_renderable(&table);
    }
}

#[derive(Debug, Clone)]
struct WorkerChange {
    id: String,
    previous: Option<WorkerStatus>,
    current: WorkerStatus,
}

pub fn log_routing_decision(
    strategy: SelectionStrategy,
    selected: &str,
    circuit_state: Option<&str>,
    scores: &[(String, f64)],
    eligible: usize,
) {
    if !debug_routing_enabled() {
        return;
    }

    let ctx = OutputContext::detect();
    if ctx.is_machine() {
        return;
    }

    let mut parts = Vec::new();
    parts.push(format!("strategy={strategy:?}"));
    parts.push(format!("selected={selected}"));
    parts.push(format!("eligible={eligible}"));
    if let Some(circuit) = circuit_state {
        parts.push(format!("circuit={circuit}"));
    }

    if !scores.is_empty() {
        let mut scored = scores.to_vec();
        scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(Ordering::Equal));
        let top = scored
            .iter()
            .take(3)
            .map(|(id, score)| format!("{id}:{score:.2}"))
            .collect::<Vec<_>>()
            .join(", ");
        parts.push(format!("scores={top}"));
    }

    eprintln!("[ROUTING] {}", parts.join(" | "));
}

pub fn debug_routing_enabled() -> bool {
    DEBUG_ROUTING_ENABLED.load(AtomicOrdering::Relaxed) || env_flag("RCHD_DEBUG_ROUTING")
}

fn is_online(status: WorkerStatus) -> bool {
    matches!(
        status,
        WorkerStatus::Healthy | WorkerStatus::Degraded | WorkerStatus::Draining
    )
}

fn status_label(status: WorkerStatus) -> &'static str {
    match status {
        WorkerStatus::Healthy => "HEALTHY",
        WorkerStatus::Degraded => "DEGRADED",
        WorkerStatus::Unreachable => "DOWN",
        WorkerStatus::Draining => "DRAINING",
        WorkerStatus::Disabled => "DISABLED",
    }
}

fn connection_event(previous: Option<WorkerStatus>, current: WorkerStatus) -> Option<&'static str> {
    match (previous, current) {
        (None, WorkerStatus::Healthy) | (None, WorkerStatus::Degraded) => Some("connected"),
        (Some(WorkerStatus::Unreachable), WorkerStatus::Healthy)
        | (Some(WorkerStatus::Unreachable), WorkerStatus::Degraded) => Some("reconnected"),
        (Some(WorkerStatus::Healthy), WorkerStatus::Unreachable)
        | (Some(WorkerStatus::Degraded), WorkerStatus::Unreachable) => Some("disconnected"),
        _ => None,
    }
}

fn format_status_rich(ctx: OutputContext, status: WorkerStatus) -> String {
    match status {
        WorkerStatus::Healthy => format!("{} Healthy", Icons::status_healthy(ctx)),
        WorkerStatus::Degraded => format!("{} Degraded", Icons::warning(ctx)),
        WorkerStatus::Unreachable => format!("{} Down", Icons::cross(ctx)),
        WorkerStatus::Draining => format!("{} Draining", Icons::info(ctx)),
        WorkerStatus::Disabled => format!("{} Disabled", Icons::lock(ctx)),
    }
}

fn prefix_now() -> String {
    format!("[{}] [WORKERS]", Local::now().format("%H:%M:%S"))
}

fn rule_line(title: &str, width: usize) -> String {
    let width = width.max(20);
    let padding = width.saturating_sub(title.len()).saturating_sub(2) / 2;
    format!("{} {} {}", "-".repeat(padding), title, "-".repeat(padding))
}

fn truncate(value: &str, max: usize) -> String {
    if value.len() <= max {
        value.to_string()
    } else {
        let slice = value
            .chars()
            .take(max.saturating_sub(3))
            .collect::<String>();
        format!("{slice}...")
    }
}

fn refresh_interval_from_env() -> Duration {
    let Ok(value) = std::env::var("RCHD_WORKER_STATUS_INTERVAL") else {
        return Duration::from_secs(DEFAULT_REFRESH_SECS);
    };

    if let Ok(secs) = value.trim().parse::<u64>() {
        return Duration::from_secs(secs.max(1));
    }

    if let Ok(duration) = humantime::parse_duration(value.trim()) {
        return duration.max(Duration::from_secs(1));
    }

    Duration::from_secs(DEFAULT_REFRESH_SECS)
}

fn verbose_from_env() -> bool {
    env_flag("RCHD_WORKER_STATUS_VERBOSE")
}

fn env_flag(key: &str) -> bool {
    match std::env::var(key) {
        Ok(value) => matches!(
            value.trim().to_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rch_common::test_guard;

    #[test]
    fn test_summary_format() {
        let _guard = test_guard!();
        let mut panel = WorkerStatusPanel::with_context(OutputContext::Plain)
            .with_refresh_interval(Duration::from_secs(1));
        let snapshot = vec![
            WorkerSnapshot::new("w1", WorkerStatus::Healthy, 2, 4, 88.0, vec![]),
            WorkerSnapshot::new("w2", WorkerStatus::Degraded, 1, 4, 70.0, vec![]),
        ];
        let plan = panel.render_update(&snapshot, 0);
        assert!(
            plan.lines
                .iter()
                .any(|line| line.contains("[WORKERS] 2/2 online"))
        );
    }

    #[test]
    fn test_change_line_includes_transition() {
        let _guard = test_guard!();
        let mut panel = WorkerStatusPanel::with_context(OutputContext::Plain)
            .with_refresh_interval(Duration::from_secs(1));
        let first = vec![WorkerSnapshot::new(
            "w1",
            WorkerStatus::Healthy,
            0,
            4,
            50.0,
            vec![],
        )];
        let _ = panel.render_update(&first, 0);

        let second = vec![WorkerSnapshot::new(
            "w1",
            WorkerStatus::Unreachable,
            0,
            4,
            50.0,
            vec![],
        )];
        let plan = panel.render_update(&second, 0);
        assert!(
            plan.lines
                .iter()
                .any(|line| line.contains("HEALTHY -> DOWN"))
        );
    }

    // WorkerSnapshot tests
    #[test]
    fn test_worker_snapshot_new() {
        let _guard = test_guard!();
        let snapshot = WorkerSnapshot::new(
            "worker-1",
            WorkerStatus::Healthy,
            3,
            8,
            95.5,
            vec!["gpu".to_string(), "fast".to_string()],
        );
        assert_eq!(snapshot.id, "worker-1");
        assert_eq!(snapshot.status, WorkerStatus::Healthy);
        assert_eq!(snapshot.used_slots, 3);
        assert_eq!(snapshot.total_slots, 8);
        assert!((snapshot.speed_score - 95.5).abs() < f64::EPSILON);
        assert_eq!(snapshot.tags, vec!["gpu", "fast"]);
    }

    #[test]
    fn test_worker_snapshot_empty_tags() {
        let _guard = test_guard!();
        let snapshot = WorkerSnapshot::new("w1", WorkerStatus::Degraded, 0, 4, 50.0, vec![]);
        assert!(snapshot.tags.is_empty());
    }

    #[test]
    fn test_worker_snapshot_clone() {
        let _guard = test_guard!();
        let original = WorkerSnapshot::new(
            "w1",
            WorkerStatus::Healthy,
            1,
            2,
            80.0,
            vec!["tag1".to_string()],
        );
        let cloned = original.clone();
        assert_eq!(original.id, cloned.id);
        assert_eq!(original.status, cloned.status);
    }

    // status_label tests
    #[test]
    fn test_status_label_healthy() {
        let _guard = test_guard!();
        assert_eq!(status_label(WorkerStatus::Healthy), "HEALTHY");
    }

    #[test]
    fn test_status_label_degraded() {
        let _guard = test_guard!();
        assert_eq!(status_label(WorkerStatus::Degraded), "DEGRADED");
    }

    #[test]
    fn test_status_label_unreachable() {
        let _guard = test_guard!();
        assert_eq!(status_label(WorkerStatus::Unreachable), "DOWN");
    }

    #[test]
    fn test_status_label_draining() {
        let _guard = test_guard!();
        assert_eq!(status_label(WorkerStatus::Draining), "DRAINING");
    }

    #[test]
    fn test_status_label_disabled() {
        let _guard = test_guard!();
        assert_eq!(status_label(WorkerStatus::Disabled), "DISABLED");
    }

    // is_online tests
    #[test]
    fn test_is_online_healthy() {
        let _guard = test_guard!();
        assert!(is_online(WorkerStatus::Healthy));
    }

    #[test]
    fn test_is_online_degraded() {
        let _guard = test_guard!();
        assert!(is_online(WorkerStatus::Degraded));
    }

    #[test]
    fn test_is_online_draining() {
        let _guard = test_guard!();
        assert!(is_online(WorkerStatus::Draining));
    }

    #[test]
    fn test_is_online_unreachable() {
        let _guard = test_guard!();
        assert!(!is_online(WorkerStatus::Unreachable));
    }

    #[test]
    fn test_is_online_disabled() {
        let _guard = test_guard!();
        assert!(!is_online(WorkerStatus::Disabled));
    }

    // connection_event tests
    #[test]
    fn test_connection_event_new_healthy() {
        let _guard = test_guard!();
        assert_eq!(
            connection_event(None, WorkerStatus::Healthy),
            Some("connected")
        );
    }

    #[test]
    fn test_connection_event_new_degraded() {
        let _guard = test_guard!();
        assert_eq!(
            connection_event(None, WorkerStatus::Degraded),
            Some("connected")
        );
    }

    #[test]
    fn test_connection_event_reconnected_from_unreachable_to_healthy() {
        let _guard = test_guard!();
        assert_eq!(
            connection_event(Some(WorkerStatus::Unreachable), WorkerStatus::Healthy),
            Some("reconnected")
        );
    }

    #[test]
    fn test_connection_event_reconnected_from_unreachable_to_degraded() {
        let _guard = test_guard!();
        assert_eq!(
            connection_event(Some(WorkerStatus::Unreachable), WorkerStatus::Degraded),
            Some("reconnected")
        );
    }

    #[test]
    fn test_connection_event_disconnected_from_healthy() {
        let _guard = test_guard!();
        assert_eq!(
            connection_event(Some(WorkerStatus::Healthy), WorkerStatus::Unreachable),
            Some("disconnected")
        );
    }

    #[test]
    fn test_connection_event_disconnected_from_degraded() {
        let _guard = test_guard!();
        assert_eq!(
            connection_event(Some(WorkerStatus::Degraded), WorkerStatus::Unreachable),
            Some("disconnected")
        );
    }

    #[test]
    fn test_connection_event_no_event_healthy_to_degraded() {
        let _guard = test_guard!();
        assert_eq!(
            connection_event(Some(WorkerStatus::Healthy), WorkerStatus::Degraded),
            None
        );
    }

    #[test]
    fn test_connection_event_no_event_new_unreachable() {
        let _guard = test_guard!();
        assert_eq!(connection_event(None, WorkerStatus::Unreachable), None);
    }

    #[test]
    fn test_connection_event_no_event_draining_to_disabled() {
        let _guard = test_guard!();
        assert_eq!(
            connection_event(Some(WorkerStatus::Draining), WorkerStatus::Disabled),
            None
        );
    }

    // truncate tests
    #[test]
    fn test_truncate_short_string() {
        let _guard = test_guard!();
        let result = truncate("hello", 10);
        assert_eq!(result, "hello");
    }

    #[test]
    fn test_truncate_exact_length() {
        let _guard = test_guard!();
        let result = truncate("hello", 5);
        assert_eq!(result, "hello");
    }

    #[test]
    fn test_truncate_long_string() {
        let _guard = test_guard!();
        let result = truncate("hello world", 8);
        assert_eq!(result, "hello...");
    }

    #[test]
    fn test_truncate_very_short_max() {
        let _guard = test_guard!();
        let result = truncate("hello", 3);
        assert_eq!(result, "...");
    }

    #[test]
    fn test_truncate_empty_string() {
        let _guard = test_guard!();
        let result = truncate("", 10);
        assert_eq!(result, "");
    }

    // rule_line tests
    #[test]
    fn test_rule_line_basic() {
        let _guard = test_guard!();
        let result = rule_line("Test", 40);
        assert!(result.contains("Test"));
        assert!(result.contains("-"));
    }

    #[test]
    fn test_rule_line_minimum_width() {
        let _guard = test_guard!();
        let result = rule_line("Title", 10);
        // Function uses max(width, 20) for calculation
        // With width=20 and "Title" (5 chars), padding = (20-5-2)/2 = 6
        // Result: "------" + " " + "Title" + " " + "------" = 19 chars
        assert!(result.contains("Title"));
        assert!(result.contains("-"));
        // Verify dashes are present on both sides
        assert!(result.starts_with('-'));
        assert!(result.ends_with('-'));
    }

    #[test]
    fn test_rule_line_contains_dashes() {
        let _guard = test_guard!();
        let result = rule_line("Workers", 72);
        assert!(result.starts_with('-') || result.contains("- "));
    }

    // WorkerStatusPanel builder tests
    #[test]
    fn test_panel_with_context() {
        let _guard = test_guard!();
        let panel = WorkerStatusPanel::with_context(OutputContext::Plain);
        assert!(!panel.verbose);
    }

    #[test]
    fn test_panel_with_refresh_interval() {
        let _guard = test_guard!();
        let panel = WorkerStatusPanel::with_context(OutputContext::Plain)
            .with_refresh_interval(Duration::from_secs(60));
        assert_eq!(panel.refresh_interval, Duration::from_secs(60));
    }

    #[test]
    fn test_panel_with_refresh_interval_minimum() {
        let _guard = test_guard!();
        let panel = WorkerStatusPanel::with_context(OutputContext::Plain)
            .with_refresh_interval(Duration::from_millis(100));
        // Should enforce minimum of 1 second
        assert_eq!(panel.refresh_interval, Duration::from_secs(1));
    }

    #[test]
    fn test_panel_with_verbose() {
        let _guard = test_guard!();
        let panel = WorkerStatusPanel::with_context(OutputContext::Plain).with_verbose(true);
        assert!(panel.verbose);
    }

    #[test]
    fn test_panel_with_debug_routing() {
        let _guard = test_guard!();
        let panel = WorkerStatusPanel::with_context(OutputContext::Plain).with_debug_routing(true);
        assert!(panel.debug_routing);
    }

    #[test]
    fn test_panel_set_verbose() {
        let _guard = test_guard!();
        let mut panel = WorkerStatusPanel::with_context(OutputContext::Plain);
        assert!(!panel.verbose);
        panel.set_verbose(true);
        assert!(panel.verbose);
    }

    #[test]
    fn test_panel_set_debug_routing() {
        let _guard = test_guard!();
        let mut panel = WorkerStatusPanel::with_context(OutputContext::Plain);
        panel.set_debug_routing(true);
        assert!(panel.debug_routing);
    }

    // render_summary tests
    #[test]
    fn test_render_summary_empty_snapshot() {
        let _guard = test_guard!();
        let panel = WorkerStatusPanel::with_context(OutputContext::Plain);
        let summary = panel.render_summary(&[], 5);
        assert!(summary.contains("[WORKERS] 0/0 online"));
        assert!(summary.contains("queue: 5 jobs"));
    }

    #[test]
    fn test_render_summary_single_job() {
        let _guard = test_guard!();
        let panel = WorkerStatusPanel::with_context(OutputContext::Plain);
        let summary = panel.render_summary(&[], 1);
        assert!(summary.contains("queue: 1 job"));
    }

    #[test]
    fn test_render_summary_with_mixed_workers() {
        let _guard = test_guard!();
        let panel = WorkerStatusPanel::with_context(OutputContext::Plain);
        let snapshot = vec![
            WorkerSnapshot::new("w1", WorkerStatus::Healthy, 2, 4, 80.0, vec![]),
            WorkerSnapshot::new("w2", WorkerStatus::Unreachable, 0, 4, 0.0, vec![]),
            WorkerSnapshot::new("w3", WorkerStatus::Draining, 1, 4, 60.0, vec![]),
        ];
        let summary = panel.render_summary(&snapshot, 0);
        assert!(summary.contains("[WORKERS] 2/3 online")); // Healthy + Draining
    }

    // render_table_plain tests
    #[test]
    fn test_render_table_plain_empty() {
        let _guard = test_guard!();
        let panel = WorkerStatusPanel::with_context(OutputContext::Plain);
        let lines = panel.render_table_plain(&[]);
        assert!(lines.iter().any(|l| l.contains("No workers configured")));
    }

    #[test]
    fn test_render_table_plain_with_workers() {
        let _guard = test_guard!();
        let panel = WorkerStatusPanel::with_context(OutputContext::Plain);
        let snapshot = vec![WorkerSnapshot::new(
            "worker-1",
            WorkerStatus::Healthy,
            2,
            8,
            95.0,
            vec!["gpu".to_string()],
        )];
        let lines = panel.render_table_plain(&snapshot);
        assert!(lines.iter().any(|l| l.contains("ID")));
        assert!(lines.iter().any(|l| l.contains("Status")));
        assert!(lines.iter().any(|l| l.contains("worker-1")));
        assert!(lines.iter().any(|l| l.contains("HEALTHY")));
    }

    #[test]
    fn test_render_table_plain_with_empty_tags() {
        let _guard = test_guard!();
        let panel = WorkerStatusPanel::with_context(OutputContext::Plain);
        let snapshot = vec![WorkerSnapshot::new(
            "w1",
            WorkerStatus::Healthy,
            0,
            4,
            50.0,
            vec![],
        )];
        let lines = panel.render_table_plain(&snapshot);
        // Empty tags should show "-"
        assert!(lines.iter().any(|l| l.contains("-")));
    }

    #[test]
    fn test_render_table_plain_verbose() {
        let _guard = test_guard!();
        let panel = WorkerStatusPanel::with_context(OutputContext::Plain).with_verbose(true);
        let snapshot = vec![WorkerSnapshot::new(
            "w1",
            WorkerStatus::Healthy,
            0,
            4,
            50.0,
            vec![],
        )];
        let lines = panel.render_table_plain(&snapshot);
        // Verbose mode adds a rule line with title
        assert!(lines.iter().any(|l| l.contains("Workers")));
    }

    // detect_changes tests
    #[test]
    fn test_detect_changes_new_worker() {
        let _guard = test_guard!();
        let mut panel = WorkerStatusPanel::with_context(OutputContext::Plain);
        let snapshot = vec![WorkerSnapshot::new(
            "w1",
            WorkerStatus::Healthy,
            0,
            4,
            50.0,
            vec![],
        )];
        let changes = panel.detect_changes(&snapshot);
        assert_eq!(changes.len(), 1);
        assert!(changes[0].previous.is_none());
        assert_eq!(changes[0].current, WorkerStatus::Healthy);
    }

    #[test]
    fn test_detect_changes_no_change() {
        let _guard = test_guard!();
        let mut panel = WorkerStatusPanel::with_context(OutputContext::Plain);
        let snapshot = vec![WorkerSnapshot::new(
            "w1",
            WorkerStatus::Healthy,
            0,
            4,
            50.0,
            vec![],
        )];
        // First update records the status
        let _ = panel.detect_changes(&snapshot);
        // Second update with same status should have no changes
        let changes = panel.detect_changes(&snapshot);
        assert!(changes.is_empty());
    }

    #[test]
    fn test_detect_changes_status_transition() {
        let _guard = test_guard!();
        let mut panel = WorkerStatusPanel::with_context(OutputContext::Plain);
        let initial = vec![WorkerSnapshot::new(
            "w1",
            WorkerStatus::Healthy,
            0,
            4,
            50.0,
            vec![],
        )];
        let _ = panel.detect_changes(&initial);

        let updated = vec![WorkerSnapshot::new(
            "w1",
            WorkerStatus::Degraded,
            0,
            4,
            50.0,
            vec![],
        )];
        let changes = panel.detect_changes(&updated);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].previous, Some(WorkerStatus::Healthy));
        assert_eq!(changes[0].current, WorkerStatus::Degraded);
    }

    // render_changes tests
    #[test]
    fn test_render_changes_few() {
        let _guard = test_guard!();
        let panel = WorkerStatusPanel::with_context(OutputContext::Plain);
        let changes = vec![WorkerChange {
            id: "w1".to_string(),
            previous: Some(WorkerStatus::Healthy),
            current: WorkerStatus::Unreachable,
        }];
        let lines = panel.render_changes(&changes);
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("HEALTHY -> DOWN"));
    }

    #[test]
    fn test_render_changes_bulk_threshold() {
        let _guard = test_guard!();
        let panel = WorkerStatusPanel::with_context(OutputContext::Plain);
        // Create more than BULK_CHANGE_THRESHOLD changes
        let changes: Vec<WorkerChange> = (0..5)
            .map(|i| WorkerChange {
                id: format!("w{}", i),
                previous: Some(WorkerStatus::Healthy),
                current: WorkerStatus::Unreachable,
            })
            .collect();
        let lines = panel.render_changes(&changes);
        // Should use aggregated format
        assert!(lines.iter().any(|l| l.contains("workers:")));
    }

    // render_change_line tests
    #[test]
    fn test_render_change_line_with_event() {
        let _guard = test_guard!();
        let panel = WorkerStatusPanel::with_context(OutputContext::Plain);
        let change = WorkerChange {
            id: "w1".to_string(),
            previous: Some(WorkerStatus::Healthy),
            current: WorkerStatus::Unreachable,
        };
        let line = panel.render_change_line(&change);
        assert!(line.contains("w1"));
        assert!(line.contains("HEALTHY -> DOWN"));
        assert!(line.contains("disconnected"));
    }

    #[test]
    fn test_render_change_line_without_event() {
        let _guard = test_guard!();
        let panel = WorkerStatusPanel::with_context(OutputContext::Plain);
        let change = WorkerChange {
            id: "w1".to_string(),
            previous: Some(WorkerStatus::Healthy),
            current: WorkerStatus::Draining,
        };
        let line = panel.render_change_line(&change);
        assert!(line.contains("w1"));
        assert!(line.contains("HEALTHY -> DRAINING"));
        assert!(!line.contains("(")); // No event in parentheses
    }

    #[test]
    fn test_render_change_line_new_worker() {
        let _guard = test_guard!();
        let panel = WorkerStatusPanel::with_context(OutputContext::Plain);
        let change = WorkerChange {
            id: "w1".to_string(),
            previous: None,
            current: WorkerStatus::Healthy,
        };
        let line = panel.render_change_line(&change);
        assert!(line.contains("NEW -> HEALTHY"));
        assert!(line.contains("connected"));
    }

    // render_update tests
    #[test]
    fn test_render_update_machine_mode() {
        let _guard = test_guard!();
        let mut panel = WorkerStatusPanel::with_context(OutputContext::Machine);
        let snapshot = vec![WorkerSnapshot::new(
            "w1",
            WorkerStatus::Healthy,
            0,
            4,
            50.0,
            vec![],
        )];
        let plan = panel.render_update(&snapshot, 0);
        // Machine mode should return empty plan
        assert!(plan.lines.is_empty());
        assert!(!plan.render_table);
    }

    #[test]
    fn test_render_update_initial() {
        let _guard = test_guard!();
        let mut panel = WorkerStatusPanel::with_context(OutputContext::Plain)
            .with_refresh_interval(Duration::from_secs(1));
        let snapshot = vec![WorkerSnapshot::new(
            "w1",
            WorkerStatus::Healthy,
            0,
            4,
            50.0,
            vec![],
        )];
        let plan = panel.render_update(&snapshot, 0);
        // Should have change line for new worker and summary
        assert!(!plan.lines.is_empty());
    }

    // format_status_rich tests
    #[test]
    fn test_format_status_rich_healthy() {
        let _guard = test_guard!();
        let result = format_status_rich(OutputContext::Plain, WorkerStatus::Healthy);
        assert!(result.contains("Healthy"));
    }

    #[test]
    fn test_format_status_rich_degraded() {
        let _guard = test_guard!();
        let result = format_status_rich(OutputContext::Plain, WorkerStatus::Degraded);
        assert!(result.contains("Degraded"));
    }

    #[test]
    fn test_format_status_rich_unreachable() {
        let _guard = test_guard!();
        let result = format_status_rich(OutputContext::Plain, WorkerStatus::Unreachable);
        assert!(result.contains("Down"));
    }

    #[test]
    fn test_format_status_rich_draining() {
        let _guard = test_guard!();
        let result = format_status_rich(OutputContext::Plain, WorkerStatus::Draining);
        assert!(result.contains("Draining"));
    }

    #[test]
    fn test_format_status_rich_disabled() {
        let _guard = test_guard!();
        let result = format_status_rich(OutputContext::Plain, WorkerStatus::Disabled);
        assert!(result.contains("Disabled"));
    }

    // prefix_now test
    #[test]
    fn test_prefix_now_format() {
        let _guard = test_guard!();
        let result = prefix_now();
        assert!(result.contains("[WORKERS]"));
        assert!(result.starts_with('['));
    }

    // set_debug_routing_enabled tests
    #[test]
    fn test_set_debug_routing_enabled() {
        let _guard = test_guard!();
        // Save original state
        let original = DEBUG_ROUTING_ENABLED.load(AtomicOrdering::Relaxed);

        set_debug_routing_enabled(true);
        assert!(DEBUG_ROUTING_ENABLED.load(AtomicOrdering::Relaxed));

        set_debug_routing_enabled(false);
        assert!(!DEBUG_ROUTING_ENABLED.load(AtomicOrdering::Relaxed));

        // Restore original state
        DEBUG_ROUTING_ENABLED.store(original, AtomicOrdering::Relaxed);
    }

    // WorkerChange struct tests
    #[test]
    fn test_worker_change_clone() {
        let _guard = test_guard!();
        let change = WorkerChange {
            id: "worker-1".to_string(),
            previous: Some(WorkerStatus::Healthy),
            current: WorkerStatus::Unreachable,
        };
        let cloned = change.clone();
        assert_eq!(change.id, cloned.id);
        assert_eq!(change.previous, cloned.previous);
        assert_eq!(change.current, cloned.current);
    }

    // WorkerStatusPlan struct tests
    #[test]
    fn test_worker_status_plan_fields() {
        let _guard = test_guard!();
        let plan = WorkerStatusPlan {
            lines: vec!["line1".to_string(), "line2".to_string()],
            render_table: true,
        };
        assert_eq!(plan.lines.len(), 2);
        assert!(plan.render_table);
    }

    // env_flag tests
    #[test]
    fn test_env_flag_missing() {
        let _guard = test_guard!();
        // Non-existent env var should return false
        let result = env_flag("RCHD_TEST_NONEXISTENT_VAR_12345");
        assert!(!result);
    }

    // render_changes_aggregated tests
    #[test]
    fn test_render_changes_aggregated() {
        let _guard = test_guard!();
        let panel = WorkerStatusPanel::with_context(OutputContext::Plain);
        let changes: Vec<WorkerChange> = (0..5)
            .map(|i| WorkerChange {
                id: format!("w{}", i),
                previous: None,
                current: WorkerStatus::Healthy,
            })
            .collect();
        let lines = panel.render_changes_aggregated(&changes);
        assert!(!lines.is_empty());
        assert!(lines[0].contains("5 workers"));
        assert!(lines[0].contains("NEW -> HEALTHY"));
    }

    #[test]
    fn test_render_changes_aggregated_mixed() {
        let _guard = test_guard!();
        let panel = WorkerStatusPanel::with_context(OutputContext::Plain);
        let changes = vec![
            WorkerChange {
                id: "w1".to_string(),
                previous: Some(WorkerStatus::Healthy),
                current: WorkerStatus::Unreachable,
            },
            WorkerChange {
                id: "w2".to_string(),
                previous: Some(WorkerStatus::Healthy),
                current: WorkerStatus::Unreachable,
            },
            WorkerChange {
                id: "w3".to_string(),
                previous: None,
                current: WorkerStatus::Healthy,
            },
        ];
        let lines = panel.render_changes_aggregated(&changes);
        // Should have multiple lines for different transition types
        assert!(!lines.is_empty());
    }

    // log_routing_decision tests (when debug is disabled)
    #[test]
    fn test_log_routing_decision_disabled() {
        let _guard = test_guard!();
        // Save original state
        let original = DEBUG_ROUTING_ENABLED.load(AtomicOrdering::Relaxed);
        DEBUG_ROUTING_ENABLED.store(false, AtomicOrdering::Relaxed);

        // Should not panic when disabled
        log_routing_decision(
            SelectionStrategy::Balanced,
            "worker-1",
            Some("closed"),
            &[("w1".to_string(), 95.0), ("w2".to_string(), 80.0)],
            2,
        );

        // Restore original state
        DEBUG_ROUTING_ENABLED.store(original, AtomicOrdering::Relaxed);
    }

    // Constants tests
    #[test]
    fn test_constants() {
        let _guard = test_guard!();
        assert_eq!(DEFAULT_REFRESH_SECS, 30);
        assert_eq!(BULK_CHANGE_THRESHOLD, 4);
        assert_eq!(DEFAULT_TABLE_WIDTH, 72);
    }
}
