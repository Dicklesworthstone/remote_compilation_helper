//! TUI state management.
//!
//! Maintains the dashboard state including worker status, active builds, and UI state.

use chrono::{DateTime, Utc};
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
    /// Last copied text (for feedback).
    pub last_copied: Option<String>,
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
            should_quit: false,
            show_help: false,
            filter_mode: false,
            high_contrast: false,
            last_copied: None,
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

    /// Get filtered build history based on current filter state.
    pub fn filtered_build_history(&self) -> Vec<&HistoricalBuild> {
        self.build_history
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
                if let Some(ref worker) = self.filter.worker_filter {
                    if b.worker.as_ref() != Some(worker) {
                        return false;
                    }
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
            .collect()
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
            "VERIFY: panel={:?} index={} show_help={} filter_mode={}",
            state.selected_panel, state.selected_index, state.show_help, state.filter_mode
        );
        assert_eq!(state.selected_panel, Panel::Workers);
        assert_eq!(state.selected_index, 0);
        assert!(state.workers.is_empty());
        assert!(state.active_builds.is_empty());
        assert!(state.build_history.is_empty());
        assert!(state.filter.query.is_empty());
        assert!(state.log_view.is_none());
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
}
