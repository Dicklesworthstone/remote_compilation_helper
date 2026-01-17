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
