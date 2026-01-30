//! TUI state management.
//!
//! Maintains the dashboard state including worker status, active builds, and UI state.

use chrono::{DateTime, Utc};
use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::path::PathBuf;
use std::time::{Duration, Instant};

/// Which panel is currently selected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Panel {
    #[default]
    Workers,
    ActiveBuilds,
    BuildHistory,
    Logs,
}

impl Panel {
    pub fn next(self) -> Self {
        match self {
            Panel::Workers => Panel::ActiveBuilds,
            Panel::ActiveBuilds => Panel::BuildHistory,
            Panel::BuildHistory => Panel::Logs,
            Panel::Logs => Panel::Workers,
        }
    }

    pub fn prev(self) -> Self {
        match self {
            Panel::Workers => Panel::Logs,
            Panel::ActiveBuilds => Panel::Workers,
            Panel::BuildHistory => Panel::ActiveBuilds,
            Panel::Logs => Panel::BuildHistory,
        }
    }
}

/// Color blind accessibility modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ValueEnum, Default)]
#[value(rename_all = "kebab_case")]
#[serde(rename_all = "kebab-case")]
pub enum ColorBlindMode {
    /// Default palette.
    #[default]
    None,
    /// Red-green (deuteranopia) friendly palette.
    Deuteranopia,
    /// Red-green (protanopia) friendly palette.
    Protanopia,
    /// Blue-yellow (tritanopia) friendly palette.
    Tritanopia,
}

/// Sort order for build history panel.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum BuildHistorySort {
    /// Most recent first (default).
    #[default]
    TimeDesc,
    /// Oldest first.
    TimeAsc,
    /// Longest builds first.
    DurationDesc,
    /// Shortest builds first.
    DurationAsc,
    /// Grouped by worker ID.
    WorkerAsc,
    /// Failures first, then successes.
    StatusFailFirst,
}

impl BuildHistorySort {
    /// Get display name for the sort option.
    pub fn display_name(&self) -> &'static str {
        match self {
            BuildHistorySort::TimeDesc => "time \u{2193}",
            BuildHistorySort::TimeAsc => "time \u{2191}",
            BuildHistorySort::DurationDesc => "duration \u{2193}",
            BuildHistorySort::DurationAsc => "duration \u{2191}",
            BuildHistorySort::WorkerAsc => "worker",
            BuildHistorySort::StatusFailFirst => "status",
        }
    }

    /// Cycle to next sort option. All variants are reachable from the main cycle.
    pub fn next(self) -> Self {
        match self {
            BuildHistorySort::TimeDesc => BuildHistorySort::DurationDesc,
            BuildHistorySort::TimeAsc => BuildHistorySort::DurationDesc,
            BuildHistorySort::DurationDesc => BuildHistorySort::WorkerAsc,
            BuildHistorySort::DurationAsc => BuildHistorySort::WorkerAsc,
            BuildHistorySort::WorkerAsc => BuildHistorySort::StatusFailFirst,
            BuildHistorySort::StatusFailFirst => BuildHistorySort::TimeDesc,
        }
    }

    /// Reverse current sort direction.
    pub fn reverse(self) -> Self {
        match self {
            BuildHistorySort::TimeDesc => BuildHistorySort::TimeAsc,
            BuildHistorySort::TimeAsc => BuildHistorySort::TimeDesc,
            BuildHistorySort::DurationDesc => BuildHistorySort::DurationAsc,
            BuildHistorySort::DurationAsc => BuildHistorySort::DurationDesc,
            BuildHistorySort::WorkerAsc => BuildHistorySort::WorkerAsc, // no reverse
            BuildHistorySort::StatusFailFirst => BuildHistorySort::StatusFailFirst, // no reverse
        }
    }
}

/// Main TUI state container.
#[derive(Debug, Clone)]
pub struct TuiState {
    pub daemon: DaemonState,
    pub workers: Vec<WorkerState>,
    pub active_builds: Vec<ActiveBuild>,
    pub build_history: VecDeque<HistoricalBuild>,
    pub selected_panel: Panel,
    pub selected_index: usize,
    pub last_update: Instant,
    pub error: Option<String>,
    pub filter: FilterState,
    pub log_view: Option<LogViewState>,
    pub should_quit: bool,
    /// Show help overlay.
    pub show_help: bool,
    /// Filter mode active.
    pub filter_mode: bool,
    /// High contrast mode for accessibility.
    pub high_contrast: bool,
    /// Color blind palette selection.
    pub color_blind: ColorBlindMode,
    /// Last copied text (for feedback).
    pub last_copied: Option<String>,
    /// Pending confirmation dialog for destructive actions.
    pub confirm_dialog: Option<ConfirmDialog>,
    /// Build history sort order.
    pub build_history_sort: BuildHistorySort,
    /// Show detail bar for selected item (full untruncated content).
    pub show_detail: bool,
}

impl Default for TuiState {
    fn default() -> Self {
        Self {
            daemon: DaemonState::default(),
            workers: Vec::new(),
            active_builds: Vec::new(),
            build_history: VecDeque::with_capacity(100),
            selected_panel: Panel::Workers,
            selected_index: 0,
            last_update: Instant::now(),
            error: None,
            filter: FilterState::default(),
            log_view: None,
            build_history_sort: BuildHistorySort::default(),
            should_quit: false,
            show_help: false,
            filter_mode: false,
            high_contrast: false,
            color_blind: ColorBlindMode::None,
            last_copied: None,
            confirm_dialog: None,
            show_detail: true,
        }
    }
}

impl TuiState {
    /// Create new TUI state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Move selection up.
    pub fn select_up(&mut self) {
        if self.selected_index > 0 {
            self.selected_index -= 1;
        }
    }

    /// Move selection down.
    pub fn select_down(&mut self) {
        let max_index = self.current_list_len().saturating_sub(1);
        if self.selected_index < max_index {
            self.selected_index += 1;
        }
    }

    /// Get length of current selected list.
    fn current_list_len(&self) -> usize {
        match self.selected_panel {
            Panel::Workers => self.workers.len(),
            Panel::ActiveBuilds => self.active_builds.len(),
            Panel::BuildHistory => self.build_history.len(),
            Panel::Logs => 0,
        }
    }

    /// Get the currently selected worker, if Workers panel is selected and has items.
    pub fn selected_worker(&self) -> Option<&WorkerState> {
        if self.selected_panel == Panel::Workers {
            self.workers.get(self.selected_index)
        } else {
            None
        }
    }

    /// Get the currently selected active build, if ActiveBuilds panel is selected.
    pub fn selected_active_build(&self) -> Option<&ActiveBuild> {
        if self.selected_panel == Panel::ActiveBuilds {
            self.active_builds.get(self.selected_index)
        } else {
            None
        }
    }

    /// Get detail text for the currently selected item (untruncated).
    ///
    /// Returns `None` if no item is selected or the panel is empty.
    pub fn selected_detail(&self) -> Option<String> {
        match self.selected_panel {
            Panel::Workers => {
                let w = self.workers.get(self.selected_index)?;
                Some(format!(
                    "{} | host: {} | status: {:?} | slots: {}/{} | latency: {}ms | builds: {}",
                    w.id,
                    w.host,
                    w.status,
                    w.used_slots,
                    w.total_slots,
                    w.latency_ms,
                    w.builds_completed,
                ))
            }
            Panel::ActiveBuilds => {
                let b = self.active_builds.get(self.selected_index)?;
                let worker = b.worker.as_deref().unwrap_or("pending");
                let progress = b
                    .progress
                    .as_ref()
                    .and_then(|p| p.percent)
                    .map(|p| format!(" ({}%)", p))
                    .unwrap_or_default();
                Some(format!("{} → {} | {}{}", b.command, worker, b.id, progress,))
            }
            Panel::BuildHistory => {
                let b = self.build_history.get(self.selected_index)?;
                let worker = b.worker.as_deref().unwrap_or("local");
                let status = if b.success { "ok" } else { "FAIL" };
                let exit = b
                    .exit_code
                    .map(|c| format!(" exit={}", c))
                    .unwrap_or_default();
                Some(format!(
                    "{} @ {} | {} | {}ms{}",
                    b.command, worker, status, b.duration_ms, exit,
                ))
            }
            Panel::Logs => None,
        }
    }

    /// Switch to next panel.
    pub fn next_panel(&mut self) {
        self.selected_panel = self.selected_panel.next();
        self.selected_index = 0;
    }

    /// Switch to previous panel.
    pub fn prev_panel(&mut self) {
        self.selected_panel = self.selected_panel.prev();
        self.selected_index = 0;
    }

    /// Jump to a specific panel by index (0=Workers, 1=ActiveBuilds, 2=BuildHistory, 3=Logs).
    pub fn jump_to_panel(&mut self, index: u8) {
        let panel = match index {
            0 => Panel::Workers,
            1 => Panel::ActiveBuilds,
            2 => Panel::BuildHistory,
            _ => Panel::Logs,
        };
        self.selected_panel = panel;
        self.selected_index = 0;
    }

    /// Jump selection to first item in current list.
    pub fn select_first(&mut self) {
        self.selected_index = 0;
    }

    /// Jump selection to last item in current list.
    pub fn select_last(&mut self) {
        self.selected_index = self.current_list_len().saturating_sub(1);
    }

    /// Handle selection action on current item.
    pub fn handle_select(&mut self) {
        match self.selected_panel {
            Panel::Workers => {
                // Could expand worker details or toggle drain
            }
            Panel::ActiveBuilds => {
                // Open log view for selected build
                if let Some(build) = self.active_builds.get(self.selected_index) {
                    self.log_view = Some(LogViewState {
                        build_id: build.id.clone(),
                        lines: std::collections::VecDeque::new(),
                        scroll_offset: 0,
                        auto_scroll: true,
                    });
                }
            }
            Panel::BuildHistory => {
                // Could show build details
            }
            Panel::Logs => {
                // Toggle auto-scroll
                if let Some(ref mut log_view) = self.log_view {
                    log_view.auto_scroll = !log_view.auto_scroll;
                }
            }
        }
    }

    /// Copy selected item info to clipboard (or store for display).
    pub fn copy_selected(&mut self) {
        let text = match self.selected_panel {
            Panel::Workers => self
                .workers
                .get(self.selected_index)
                .map(|w| format!("{}@{}", w.id, w.host)),
            Panel::ActiveBuilds => self
                .active_builds
                .get(self.selected_index)
                .map(|b| b.command.clone()),
            Panel::BuildHistory => self
                .build_history
                .get(self.selected_index)
                .map(|b| b.command.clone()),
            Panel::Logs => self
                .log_view
                .as_ref()
                .map(|l| l.lines.iter().cloned().collect::<Vec<_>>().join("\n")),
        };
        self.last_copied = text;
    }

    /// Cycle through build history sort options.
    pub fn cycle_build_history_sort(&mut self) {
        self.build_history_sort = self.build_history_sort.next();
        // Reset selection when sort changes
        self.selected_index = 0;
    }

    /// Reverse current build history sort direction.
    pub fn reverse_build_history_sort(&mut self) {
        self.build_history_sort = self.build_history_sort.reverse();
        // Reset selection when sort changes
        self.selected_index = 0;
    }

    /// Get filtered and sorted build history based on current filter and sort state.
    pub fn filtered_build_history(&self) -> Vec<&HistoricalBuild> {
        let mut history: Vec<&HistoricalBuild> = self
            .build_history
            .iter()
            .filter(|b| {
                // Apply query filter
                if !self.filter.query.is_empty()
                    && !b
                        .command
                        .to_lowercase()
                        .contains(&self.filter.query.to_lowercase())
                {
                    return false;
                }
                // Apply worker filter
                if let Some(ref worker) = self.filter.worker_filter
                    && b.worker.as_ref() != Some(worker)
                {
                    return false;
                }
                // Apply success/failed filter
                if self.filter.success_only && !b.success {
                    return false;
                }
                if self.filter.failed_only && b.success {
                    return false;
                }
                true
            })
            .collect();

        // Apply sorting
        match self.build_history_sort {
            BuildHistorySort::TimeDesc => {
                // Default order - most recent first (already in this order from VecDeque)
            }
            BuildHistorySort::TimeAsc => {
                history.reverse();
            }
            BuildHistorySort::DurationDesc => {
                history.sort_by(|a, b| b.duration_ms.cmp(&a.duration_ms));
            }
            BuildHistorySort::DurationAsc => {
                history.sort_by(|a, b| a.duration_ms.cmp(&b.duration_ms));
            }
            BuildHistorySort::WorkerAsc => {
                history.sort_by(|a, b| {
                    let a_worker = a.worker.as_deref().unwrap_or("");
                    let b_worker = b.worker.as_deref().unwrap_or("");
                    a_worker.cmp(b_worker)
                });
            }
            BuildHistorySort::StatusFailFirst => {
                history.sort_by(|a, b| a.success.cmp(&b.success));
            }
        }

        history
    }
}

/// Daemon status information.
#[derive(Debug, Clone, Default)]
pub struct DaemonState {
    pub status: Status,
    pub uptime: Duration,
    pub version: String,
    pub config_path: PathBuf,
    pub socket_path: PathBuf,
    pub builds_today: u32,
    pub bytes_transferred: u64,
}

/// Service status.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Status {
    #[default]
    Unknown,
    Running,
    Stopped,
    Error,
}

/// Worker status information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerState {
    pub id: String,
    pub host: String,
    pub status: WorkerStatus,
    pub circuit: CircuitState,
    pub total_slots: u32,
    pub used_slots: u32,
    pub latency_ms: u32,
    pub last_seen: DateTime<Utc>,
    pub builds_completed: u32,
}

/// Worker availability status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WorkerStatus {
    Healthy,
    Degraded,
    Unreachable,
    Draining,
    Drained,
    Disabled,
}

/// Circuit breaker state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CircuitState {
    Closed,
    HalfOpen,
    Open,
}

/// Active build information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveBuild {
    pub id: String,
    pub command: String,
    pub worker: Option<String>,
    pub started_at: DateTime<Utc>,
    pub progress: Option<BuildProgress>,
    pub status: BuildStatus,
}

/// Build progress information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildProgress {
    pub phase: String,
    pub percent: Option<u8>,
    pub current_file: Option<String>,
}

/// Build execution status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BuildStatus {
    Pending,
    Syncing,
    Compiling,
    Downloading,
    Completed,
    Failed,
}

/// Historical build record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoricalBuild {
    pub id: String,
    pub command: String,
    pub worker: Option<String>,
    pub started_at: DateTime<Utc>,
    pub completed_at: DateTime<Utc>,
    pub duration_ms: u64,
    pub success: bool,
    pub exit_code: Option<i32>,
}

/// Filter state for build history.
#[derive(Debug, Clone, Default)]
pub struct FilterState {
    pub query: String,
    pub worker_filter: Option<String>,
    pub success_only: bool,
    pub failed_only: bool,
}

/// A pending confirmation dialog for destructive TUI actions.
#[derive(Debug, Clone)]
pub struct ConfirmDialog {
    /// Title shown in the modal header.
    pub title: String,
    /// Description of the action and its consequences.
    pub message: String,
    /// The action to execute on confirmation.
    pub action: ConfirmAction,
}

/// Actions that can be confirmed via the dialog.
#[derive(Debug, Clone)]
pub enum ConfirmAction {
    /// Drain a single worker by ID.
    DrainWorker(String),
    /// Drain all workers.
    DrainAllWorkers,
    /// Cancel a build (SIGTERM) by ID.
    CancelBuild(String),
    /// Force kill a build (SIGKILL) by ID.
    ForceKillBuild(String),
}

/// Log view state for active build logs.
#[derive(Debug, Clone)]
pub struct LogViewState {
    pub build_id: String,
    pub lines: VecDeque<String>,
    pub scroll_offset: usize,
    pub auto_scroll: bool,
}

impl Default for LogViewState {
    fn default() -> Self {
        Self {
            build_id: String::new(),
            lines: VecDeque::with_capacity(1000),
            scroll_offset: 0,
            auto_scroll: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing::info;

    fn init_test_logging() {
        let _ = tracing_subscriber::fmt()
            .with_test_writer()
            .with_max_level(tracing::Level::DEBUG)
            .try_init();
    }

    fn make_worker(id: &str) -> WorkerState {
        WorkerState {
            id: id.to_string(),
            host: "host".to_string(),
            status: WorkerStatus::Healthy,
            circuit: CircuitState::Closed,
            total_slots: 8,
            used_slots: 1,
            latency_ms: 10,
            last_seen: Utc::now(),
            builds_completed: 0,
        }
    }

    fn make_active_build(id: &str, command: &str) -> ActiveBuild {
        ActiveBuild {
            id: id.to_string(),
            command: command.to_string(),
            worker: Some("worker-1".to_string()),
            started_at: Utc::now(),
            progress: Some(BuildProgress {
                phase: "compiling".to_string(),
                percent: Some(50),
                current_file: None,
            }),
            status: BuildStatus::Compiling,
        }
    }

    fn make_history(
        id: &str,
        command: &str,
        worker: Option<&str>,
        success: bool,
    ) -> HistoricalBuild {
        HistoricalBuild {
            id: id.to_string(),
            command: command.to_string(),
            worker: worker.map(|w| w.to_string()),
            started_at: Utc::now(),
            completed_at: Utc::now(),
            duration_ms: 1200,
            success,
            exit_code: Some(if success { 0 } else { 1 }),
        }
    }

    #[test]
    fn test_state_default_values() {
        init_test_logging();
        info!("TEST START: test_state_default_values");
        let state = TuiState::default();
        info!(
            "VERIFY: panel={:?} index={} show_help={} filter_mode={} color_blind={:?}",
            state.selected_panel,
            state.selected_index,
            state.show_help,
            state.filter_mode,
            state.color_blind
        );
        assert_eq!(state.selected_panel, Panel::Workers);
        assert_eq!(state.selected_index, 0);
        assert!(state.workers.is_empty());
        assert!(state.active_builds.is_empty());
        assert!(state.build_history.is_empty());
        assert!(state.filter.query.is_empty());
        assert!(state.log_view.is_none());
        assert_eq!(state.color_blind, ColorBlindMode::None);
        info!("TEST PASS: test_state_default_values");
    }

    #[test]
    fn test_panel_cycle_next_prev() {
        init_test_logging();
        info!("TEST START: test_panel_cycle_next_prev");
        let mut state = TuiState::default();
        assert_eq!(state.selected_panel, Panel::Workers);
        state.next_panel();
        assert_eq!(state.selected_panel, Panel::ActiveBuilds);
        state.next_panel();
        assert_eq!(state.selected_panel, Panel::BuildHistory);
        state.next_panel();
        assert_eq!(state.selected_panel, Panel::Logs);
        state.next_panel();
        assert_eq!(state.selected_panel, Panel::Workers);

        state.prev_panel();
        assert_eq!(state.selected_panel, Panel::Logs);
        state.prev_panel();
        assert_eq!(state.selected_panel, Panel::BuildHistory);
        info!("TEST PASS: test_panel_cycle_next_prev");
    }

    #[test]
    fn test_selection_bounds_for_workers() {
        init_test_logging();
        info!("TEST START: test_selection_bounds_for_workers");
        let mut state = TuiState {
            workers: vec![make_worker("w1"), make_worker("w2")],
            selected_panel: Panel::Workers,
            selected_index: 0,
            ..Default::default()
        };
        state.select_up();
        assert_eq!(state.selected_index, 0);
        state.select_down();
        assert_eq!(state.selected_index, 1);
        state.select_down();
        assert_eq!(state.selected_index, 1);
        info!("TEST PASS: test_selection_bounds_for_workers");
    }

    #[test]
    fn test_handle_select_active_build_opens_logs() {
        init_test_logging();
        info!("TEST START: test_handle_select_active_build_opens_logs");
        let mut state = TuiState {
            active_builds: vec![make_active_build("b1", "cargo build")],
            selected_panel: Panel::ActiveBuilds,
            ..Default::default()
        };
        state.handle_select();
        assert!(state.log_view.is_some());
        let log_view = state.log_view.as_ref().unwrap();
        assert_eq!(log_view.build_id, "b1");
        assert!(log_view.auto_scroll);
        info!("TEST PASS: test_handle_select_active_build_opens_logs");
    }

    #[test]
    fn test_handle_select_logs_toggles_auto_scroll() {
        init_test_logging();
        info!("TEST START: test_handle_select_logs_toggles_auto_scroll");
        let mut state = TuiState {
            log_view: Some(LogViewState::default()),
            selected_panel: Panel::Logs,
            ..Default::default()
        };
        let before = state.log_view.as_ref().unwrap().auto_scroll;
        state.handle_select();
        let after = state.log_view.as_ref().unwrap().auto_scroll;
        assert_ne!(before, after);
        info!("TEST PASS: test_handle_select_logs_toggles_auto_scroll");
    }

    #[test]
    fn test_copy_selected_variants() {
        init_test_logging();
        info!("TEST START: test_copy_selected_variants");
        let mut worker_state = TuiState {
            workers: vec![make_worker("w1")],
            selected_panel: Panel::Workers,
            ..Default::default()
        };
        worker_state.copy_selected();
        assert_eq!(worker_state.last_copied.as_deref(), Some("w1@host"));

        let mut build_state = TuiState {
            active_builds: vec![make_active_build("b1", "cargo test")],
            selected_panel: Panel::ActiveBuilds,
            ..Default::default()
        };
        build_state.copy_selected();
        assert_eq!(build_state.last_copied.as_deref(), Some("cargo test"));

        let mut history_state = TuiState {
            build_history: VecDeque::from([make_history("h1", "cargo check", Some("w1"), true)]),
            selected_panel: Panel::BuildHistory,
            ..Default::default()
        };
        history_state.copy_selected();
        assert_eq!(history_state.last_copied.as_deref(), Some("cargo check"));
        info!("TEST PASS: test_copy_selected_variants");
    }

    #[test]
    fn test_copy_selected_logs_joined_lines() {
        init_test_logging();
        info!("TEST START: test_copy_selected_logs_joined_lines");
        let mut log_view = LogViewState::default();
        log_view.lines.push_back("line1".to_string());
        log_view.lines.push_back("line2".to_string());
        let mut state = TuiState {
            log_view: Some(log_view),
            selected_panel: Panel::Logs,
            ..Default::default()
        };
        state.copy_selected();
        assert_eq!(state.last_copied.as_deref(), Some("line1\nline2"));
        info!("TEST PASS: test_copy_selected_logs_joined_lines");
    }

    #[test]
    fn test_filtered_build_history_filters() {
        init_test_logging();
        info!("TEST START: test_filtered_build_history_filters");
        let mut state = TuiState {
            build_history: VecDeque::from([
                make_history("h1", "cargo build", Some("w1"), true),
                make_history("h2", "cargo test", Some("w2"), false),
            ]),
            ..Default::default()
        };

        state.filter.query = "build".to_string();
        let filtered = state.filtered_build_history();
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].id, "h1");

        state.filter.query.clear();
        state.filter.worker_filter = Some("w2".to_string());
        let filtered = state.filtered_build_history();
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].id, "h2");

        state.filter.worker_filter = None;
        state.filter.success_only = true;
        let filtered = state.filtered_build_history();
        assert_eq!(filtered.len(), 1);
        assert!(filtered[0].success);

        state.filter.success_only = false;
        state.filter.failed_only = true;
        let filtered = state.filtered_build_history();
        assert_eq!(filtered.len(), 1);
        assert!(!filtered[0].success);
        info!("TEST PASS: test_filtered_build_history_filters");
    }

    // ==================== Selection bounds for all panel types ====================

    #[test]
    fn test_selection_bounds_for_active_builds() {
        init_test_logging();
        info!("TEST START: test_selection_bounds_for_active_builds");
        let mut state = TuiState {
            active_builds: vec![
                make_active_build("b1", "cmd1"),
                make_active_build("b2", "cmd2"),
                make_active_build("b3", "cmd3"),
            ],
            selected_panel: Panel::ActiveBuilds,
            selected_index: 0,
            ..Default::default()
        };
        // Try to go above first item
        state.select_up();
        assert_eq!(state.selected_index, 0);
        // Navigate down to last item
        state.select_down();
        assert_eq!(state.selected_index, 1);
        state.select_down();
        assert_eq!(state.selected_index, 2);
        // Try to go beyond last item
        state.select_down();
        assert_eq!(state.selected_index, 2);
        info!("TEST PASS: test_selection_bounds_for_active_builds");
    }

    #[test]
    fn test_selection_bounds_for_build_history() {
        init_test_logging();
        info!("TEST START: test_selection_bounds_for_build_history");
        let mut state = TuiState {
            build_history: VecDeque::from([
                make_history("h1", "cmd1", Some("w1"), true),
                make_history("h2", "cmd2", Some("w1"), true),
            ]),
            selected_panel: Panel::BuildHistory,
            selected_index: 0,
            ..Default::default()
        };
        state.select_up();
        assert_eq!(state.selected_index, 0);
        state.select_down();
        assert_eq!(state.selected_index, 1);
        state.select_down();
        assert_eq!(state.selected_index, 1);
        info!("TEST PASS: test_selection_bounds_for_build_history");
    }

    #[test]
    fn test_selection_bounds_for_logs() {
        init_test_logging();
        info!("TEST START: test_selection_bounds_for_logs");
        let mut log_view = LogViewState::default();
        for i in 0..50 {
            log_view.lines.push_back(format!("line {}", i));
        }
        let mut state = TuiState {
            log_view: Some(log_view),
            selected_panel: Panel::Logs,
            selected_index: 0,
            ..Default::default()
        };
        // In logs panel, navigation should work (scroll)
        state.select_up();
        state.select_down();
        info!("TEST PASS: test_selection_bounds_for_logs");
    }

    // ==================== Empty panel behavior ====================

    #[test]
    fn test_selection_on_empty_workers() {
        init_test_logging();
        info!("TEST START: test_selection_on_empty_workers");
        let mut state = TuiState {
            workers: vec![],
            selected_panel: Panel::Workers,
            selected_index: 0,
            ..Default::default()
        };
        state.select_up();
        assert_eq!(state.selected_index, 0);
        state.select_down();
        assert_eq!(state.selected_index, 0);
        info!("TEST PASS: test_selection_on_empty_workers");
    }

    #[test]
    fn test_selection_on_empty_active_builds() {
        init_test_logging();
        info!("TEST START: test_selection_on_empty_active_builds");
        let mut state = TuiState {
            active_builds: vec![],
            selected_panel: Panel::ActiveBuilds,
            selected_index: 0,
            ..Default::default()
        };
        state.select_down();
        assert_eq!(state.selected_index, 0);
        info!("TEST PASS: test_selection_on_empty_active_builds");
    }

    #[test]
    fn test_selection_on_empty_build_history() {
        init_test_logging();
        info!("TEST START: test_selection_on_empty_build_history");
        let mut state = TuiState {
            build_history: VecDeque::new(),
            selected_panel: Panel::BuildHistory,
            selected_index: 0,
            ..Default::default()
        };
        state.select_down();
        assert_eq!(state.selected_index, 0);
        info!("TEST PASS: test_selection_on_empty_build_history");
    }

    // ==================== Panel switch resets index ====================

    #[test]
    fn test_panel_switch_resets_selected_index() {
        init_test_logging();
        info!("TEST START: test_panel_switch_resets_selected_index");
        let mut state = TuiState {
            workers: vec![make_worker("w1"), make_worker("w2"), make_worker("w3")],
            active_builds: vec![make_active_build("b1", "cmd")],
            selected_panel: Panel::Workers,
            selected_index: 2,
            ..Default::default()
        };
        assert_eq!(state.selected_index, 2);
        state.next_panel();
        assert_eq!(state.selected_panel, Panel::ActiveBuilds);
        assert_eq!(state.selected_index, 0);
        info!("TEST PASS: test_panel_switch_resets_selected_index");
    }

    // ==================== Log view state tests ====================

    #[test]
    fn test_log_view_state_default() {
        init_test_logging();
        info!("TEST START: test_log_view_state_default");
        let log_view = LogViewState::default();
        assert!(log_view.build_id.is_empty());
        assert!(log_view.lines.is_empty());
        assert_eq!(log_view.scroll_offset, 0);
        assert!(log_view.auto_scroll);
        info!("TEST PASS: test_log_view_state_default");
    }

    #[test]
    fn test_handle_select_on_build_history_no_op() {
        init_test_logging();
        info!("TEST START: test_handle_select_on_build_history_no_op");
        // BuildHistory select is currently a no-op (placeholder for future functionality)
        let mut state = TuiState {
            build_history: VecDeque::from([make_history("hist-1", "cargo test", Some("w1"), true)]),
            selected_panel: Panel::BuildHistory,
            selected_index: 0,
            ..Default::default()
        };
        state.handle_select();
        // Log view should NOT be opened for build history (unlike active builds)
        assert!(state.log_view.is_none());
        info!("TEST PASS: test_handle_select_on_build_history_no_op");
    }

    #[test]
    fn test_handle_select_on_workers_no_op() {
        init_test_logging();
        info!("TEST START: test_handle_select_on_workers_no_op");
        let mut state = TuiState {
            workers: vec![make_worker("w1")],
            selected_panel: Panel::Workers,
            ..Default::default()
        };
        state.handle_select();
        // Selecting a worker doesn't open log view
        assert!(state.log_view.is_none());
        info!("TEST PASS: test_handle_select_on_workers_no_op");
    }

    // ==================== Filter state tests ====================

    #[test]
    fn test_filter_state_default() {
        init_test_logging();
        info!("TEST START: test_filter_state_default");
        let filter = FilterState::default();
        assert!(filter.query.is_empty());
        assert!(filter.worker_filter.is_none());
        assert!(!filter.success_only);
        assert!(!filter.failed_only);
        info!("TEST PASS: test_filter_state_default");
    }

    #[test]
    fn test_filtered_build_history_case_insensitive() {
        init_test_logging();
        info!("TEST START: test_filtered_build_history_case_insensitive");
        let mut state = TuiState {
            build_history: VecDeque::from([
                make_history("h1", "CARGO BUILD", Some("w1"), true),
                make_history("h2", "cargo test", Some("w2"), false),
            ]),
            ..Default::default()
        };
        state.filter.query = "cargo".to_string();
        let filtered = state.filtered_build_history();
        // Should match both due to case-insensitive search
        assert_eq!(filtered.len(), 2);
        info!("TEST PASS: test_filtered_build_history_case_insensitive");
    }

    #[test]
    fn test_filtered_build_history_empty_query() {
        init_test_logging();
        info!("TEST START: test_filtered_build_history_empty_query");
        let mut state = TuiState {
            build_history: VecDeque::from([
                make_history("h1", "cmd1", Some("w1"), true),
                make_history("h2", "cmd2", Some("w2"), false),
            ]),
            ..Default::default()
        };
        state.filter.query = "".to_string();
        let filtered = state.filtered_build_history();
        // Empty query returns all
        assert_eq!(filtered.len(), 2);
        info!("TEST PASS: test_filtered_build_history_empty_query");
    }

    #[test]
    fn test_filtered_build_history_combined_filters() {
        init_test_logging();
        info!("TEST START: test_filtered_build_history_combined_filters");
        let mut state = TuiState {
            build_history: VecDeque::from([
                make_history("h1", "cargo build", Some("worker-a"), true),
                make_history("h2", "cargo test", Some("worker-a"), false),
                make_history("h3", "cargo build", Some("worker-b"), true),
            ]),
            ..Default::default()
        };
        // Filter by query + worker + success
        state.filter.query = "build".to_string();
        state.filter.worker_filter = Some("worker-a".to_string());
        state.filter.success_only = true;
        let filtered = state.filtered_build_history();
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].id, "h1");
        info!("TEST PASS: test_filtered_build_history_combined_filters");
    }

    // ==================== Copy selected tests ====================

    #[test]
    fn test_copy_selected_empty_panels() {
        init_test_logging();
        info!("TEST START: test_copy_selected_empty_panels");
        let mut state = TuiState {
            workers: vec![],
            active_builds: vec![],
            build_history: VecDeque::new(),
            selected_panel: Panel::Workers,
            ..Default::default()
        };
        state.copy_selected();
        assert!(state.last_copied.is_none());

        state.selected_panel = Panel::ActiveBuilds;
        state.copy_selected();
        assert!(state.last_copied.is_none());

        state.selected_panel = Panel::BuildHistory;
        state.copy_selected();
        assert!(state.last_copied.is_none());
        info!("TEST PASS: test_copy_selected_empty_panels");
    }

    #[test]
    fn test_copy_selected_empty_log_view() {
        init_test_logging();
        info!("TEST START: test_copy_selected_empty_log_view");
        let log_view = LogViewState::default();
        let mut state = TuiState {
            log_view: Some(log_view),
            selected_panel: Panel::Logs,
            ..Default::default()
        };
        state.copy_selected();
        // Empty lines joins to empty string
        assert_eq!(state.last_copied.as_deref(), Some(""));
        info!("TEST PASS: test_copy_selected_empty_log_view");
    }

    // ==================== Status enum tests ====================

    #[test]
    fn test_status_enum_variants() {
        init_test_logging();
        info!("TEST START: test_status_enum_variants");
        let running = Status::Running;
        let stopped = Status::Stopped;
        let error = Status::Error;
        let unknown = Status::Unknown;
        // Test that variants are distinct
        assert_ne!(running, stopped);
        assert_ne!(stopped, error);
        assert_ne!(error, unknown);
        info!("TEST PASS: test_status_enum_variants");
    }

    // ==================== WorkerStatus enum tests ====================

    #[test]
    fn test_worker_status_enum_variants() {
        init_test_logging();
        info!("TEST START: test_worker_status_enum_variants");
        let healthy = WorkerStatus::Healthy;
        let degraded = WorkerStatus::Degraded;
        let unreachable = WorkerStatus::Unreachable;
        let draining = WorkerStatus::Draining;
        assert_ne!(healthy, degraded);
        assert_ne!(unreachable, draining);
        info!("TEST PASS: test_worker_status_enum_variants");
    }

    // ==================== CircuitState enum tests ====================

    #[test]
    fn test_circuit_state_enum_variants() {
        init_test_logging();
        info!("TEST START: test_circuit_state_enum_variants");
        let closed = CircuitState::Closed;
        let half_open = CircuitState::HalfOpen;
        let open = CircuitState::Open;
        assert_ne!(closed, half_open);
        assert_ne!(half_open, open);
        info!("TEST PASS: test_circuit_state_enum_variants");
    }

    // ==================== BuildStatus enum tests ====================

    #[test]
    fn test_build_status_enum_variants() {
        init_test_logging();
        info!("TEST START: test_build_status_enum_variants");
        let pending = BuildStatus::Pending;
        let syncing = BuildStatus::Syncing;
        let compiling = BuildStatus::Compiling;
        let downloading = BuildStatus::Downloading;
        let completed = BuildStatus::Completed;
        let failed = BuildStatus::Failed;
        assert_ne!(pending, syncing);
        assert_ne!(compiling, downloading);
        assert_ne!(completed, failed);
        info!("TEST PASS: test_build_status_enum_variants");
    }

    // ==================== ColorBlindMode enum tests ====================

    #[test]
    fn test_color_blind_mode_enum_variants() {
        init_test_logging();
        info!("TEST START: test_color_blind_mode_enum_variants");
        let none = ColorBlindMode::None;
        let deuter = ColorBlindMode::Deuteranopia;
        let proto = ColorBlindMode::Protanopia;
        let tritan = ColorBlindMode::Tritanopia;
        assert_ne!(none, deuter);
        assert_ne!(proto, tritan);
        info!("TEST PASS: test_color_blind_mode_enum_variants");
    }

    // ==================== Panel enum tests ====================

    #[test]
    fn test_panel_enum_variants() {
        init_test_logging();
        info!("TEST START: test_panel_enum_variants");
        let workers = Panel::Workers;
        let active = Panel::ActiveBuilds;
        let history = Panel::BuildHistory;
        let logs = Panel::Logs;
        assert_ne!(workers, active);
        assert_ne!(history, logs);
        info!("TEST PASS: test_panel_enum_variants");
    }

    // ==================== DaemonState tests ====================

    #[test]
    fn test_daemon_state_default() {
        init_test_logging();
        info!("TEST START: test_daemon_state_default");
        let daemon = DaemonState::default();
        assert_eq!(daemon.status, Status::Unknown);
        assert!(daemon.version.is_empty());
        info!("TEST PASS: test_daemon_state_default");
    }

    // ==================== Selected worker tests ====================

    #[test]
    fn test_selected_worker_when_workers_panel() {
        init_test_logging();
        info!("TEST START: test_selected_worker_when_workers_panel");
        let mut state = TuiState::new();
        state.workers.push(WorkerState {
            id: "worker-1".to_string(),
            host: "localhost".to_string(),
            status: WorkerStatus::Healthy,
            circuit: CircuitState::Closed,
            total_slots: 8,
            used_slots: 2,
            latency_ms: 10,
            last_seen: chrono::Utc::now(),
            builds_completed: 5,
        });
        state.selected_panel = Panel::Workers;
        state.selected_index = 0;

        let selected = state.selected_worker();
        assert!(selected.is_some());
        assert_eq!(selected.unwrap().id, "worker-1");
        info!("TEST PASS: test_selected_worker_when_workers_panel");
    }

    #[test]
    fn test_selected_worker_when_other_panel() {
        init_test_logging();
        info!("TEST START: test_selected_worker_when_other_panel");
        let mut state = TuiState::new();
        state.workers.push(WorkerState {
            id: "worker-1".to_string(),
            host: "localhost".to_string(),
            status: WorkerStatus::Healthy,
            circuit: CircuitState::Closed,
            total_slots: 8,
            used_slots: 2,
            latency_ms: 10,
            last_seen: chrono::Utc::now(),
            builds_completed: 5,
        });
        state.selected_panel = Panel::ActiveBuilds;
        state.selected_index = 0;

        let selected = state.selected_worker();
        assert!(selected.is_none());
        info!("TEST PASS: test_selected_worker_when_other_panel");
    }

    #[test]
    fn test_selected_worker_empty_list() {
        init_test_logging();
        info!("TEST START: test_selected_worker_empty_list");
        let state = TuiState::new();
        let selected = state.selected_worker();
        assert!(selected.is_none());
        info!("TEST PASS: test_selected_worker_empty_list");
    }

    // ==================== Vim navigation: jump_to_panel ====================

    #[test]
    fn test_jump_to_panel_workers() {
        init_test_logging();
        info!("TEST START: test_jump_to_panel_workers");
        let mut state = TuiState {
            selected_panel: Panel::Logs,
            selected_index: 5,
            ..Default::default()
        };
        state.jump_to_panel(0);
        assert_eq!(state.selected_panel, Panel::Workers);
        assert_eq!(state.selected_index, 0);
        info!("TEST PASS: test_jump_to_panel_workers");
    }

    #[test]
    fn test_jump_to_panel_active_builds() {
        init_test_logging();
        info!("TEST START: test_jump_to_panel_active_builds");
        let mut state = TuiState::default();
        state.jump_to_panel(1);
        assert_eq!(state.selected_panel, Panel::ActiveBuilds);
        assert_eq!(state.selected_index, 0);
        info!("TEST PASS: test_jump_to_panel_active_builds");
    }

    #[test]
    fn test_jump_to_panel_build_history() {
        init_test_logging();
        info!("TEST START: test_jump_to_panel_build_history");
        let mut state = TuiState::default();
        state.jump_to_panel(2);
        assert_eq!(state.selected_panel, Panel::BuildHistory);
        info!("TEST PASS: test_jump_to_panel_build_history");
    }

    #[test]
    fn test_jump_to_panel_logs() {
        init_test_logging();
        info!("TEST START: test_jump_to_panel_logs");
        let mut state = TuiState::default();
        state.jump_to_panel(3);
        assert_eq!(state.selected_panel, Panel::Logs);
        info!("TEST PASS: test_jump_to_panel_logs");
    }

    #[test]
    fn test_jump_to_panel_invalid_index_defaults_to_logs() {
        init_test_logging();
        info!("TEST START: test_jump_to_panel_invalid_index_defaults_to_logs");
        let mut state = TuiState::default();
        state.jump_to_panel(99);
        assert_eq!(state.selected_panel, Panel::Logs);
        info!("TEST PASS: test_jump_to_panel_invalid_index_defaults_to_logs");
    }

    // ==================== Vim navigation: select_first / select_last ====================

    #[test]
    fn test_select_first() {
        init_test_logging();
        info!("TEST START: test_select_first");
        let mut state = TuiState {
            workers: vec![make_worker("w1"), make_worker("w2"), make_worker("w3")],
            selected_panel: Panel::Workers,
            selected_index: 2,
            ..Default::default()
        };
        state.select_first();
        assert_eq!(state.selected_index, 0);
        info!("TEST PASS: test_select_first");
    }

    #[test]
    fn test_select_last() {
        init_test_logging();
        info!("TEST START: test_select_last");
        let mut state = TuiState {
            workers: vec![make_worker("w1"), make_worker("w2"), make_worker("w3")],
            selected_panel: Panel::Workers,
            selected_index: 0,
            ..Default::default()
        };
        state.select_last();
        assert_eq!(state.selected_index, 2);
        info!("TEST PASS: test_select_last");
    }

    #[test]
    fn test_select_last_empty_list() {
        init_test_logging();
        info!("TEST START: test_select_last_empty_list");
        let mut state = TuiState {
            workers: vec![],
            selected_panel: Panel::Workers,
            selected_index: 0,
            ..Default::default()
        };
        state.select_last();
        assert_eq!(state.selected_index, 0);
        info!("TEST PASS: test_select_last_empty_list");
    }

    #[test]
    fn test_select_first_already_at_first() {
        init_test_logging();
        info!("TEST START: test_select_first_already_at_first");
        let mut state = TuiState {
            workers: vec![make_worker("w1")],
            selected_panel: Panel::Workers,
            selected_index: 0,
            ..Default::default()
        };
        state.select_first();
        assert_eq!(state.selected_index, 0);
        info!("TEST PASS: test_select_first_already_at_first");
    }

    // ==================== Selected active build tests ====================

    #[test]
    fn test_selected_active_build_returns_build_when_panel_selected() {
        init_test_logging();
        let state = TuiState {
            active_builds: vec![
                make_active_build("b1", "cargo build"),
                make_active_build("b2", "cargo test"),
            ],
            selected_panel: Panel::ActiveBuilds,
            selected_index: 1,
            ..Default::default()
        };
        let build = state.selected_active_build();
        assert!(build.is_some());
        assert_eq!(build.unwrap().id, "b2");
    }

    #[test]
    fn test_selected_active_build_returns_none_when_wrong_panel() {
        init_test_logging();
        let state = TuiState {
            active_builds: vec![make_active_build("b1", "cargo build")],
            selected_panel: Panel::Workers,
            selected_index: 0,
            ..Default::default()
        };
        assert!(state.selected_active_build().is_none());
    }

    #[test]
    fn test_selected_active_build_returns_none_when_empty() {
        init_test_logging();
        let state = TuiState {
            active_builds: vec![],
            selected_panel: Panel::ActiveBuilds,
            selected_index: 0,
            ..Default::default()
        };
        assert!(state.selected_active_build().is_none());
    }

    // ==================== Confirm dialog state tests ====================

    #[test]
    fn test_confirm_dialog_default_is_none() {
        init_test_logging();
        let state = TuiState::default();
        assert!(state.confirm_dialog.is_none());
    }

    #[test]
    fn test_confirm_dialog_can_be_set() {
        init_test_logging();
        let state = TuiState {
            confirm_dialog: Some(ConfirmDialog {
                title: "Drain worker 'css'?".into(),
                message: "This will stop routing new\njobs to this worker.".into(),
                action: ConfirmAction::DrainWorker("css".into()),
            }),
            ..Default::default()
        };
        assert!(state.confirm_dialog.is_some());
        let dialog = state.confirm_dialog.as_ref().unwrap();
        assert_eq!(dialog.title, "Drain worker 'css'?");
        match &dialog.action {
            ConfirmAction::DrainWorker(id) => assert_eq!(id, "css"),
            _ => panic!("Expected DrainWorker action"),
        }
    }

    #[test]
    fn test_confirm_dialog_take_clears() {
        init_test_logging();
        let mut state = TuiState {
            confirm_dialog: Some(ConfirmDialog {
                title: "Test".into(),
                message: "Test message".into(),
                action: ConfirmAction::DrainAllWorkers,
            }),
            ..Default::default()
        };
        let dialog = state.confirm_dialog.take();
        assert!(dialog.is_some());
        assert!(state.confirm_dialog.is_none());
    }
}
