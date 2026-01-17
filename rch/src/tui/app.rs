//! TUI application runner.
//!
//! Main entry point for the interactive dashboard.

use crate::status_display::query_daemon_full_status;
use crate::status_types::DaemonFullStatusResponse;
use crate::tui::{
    event::{poll_event_with_mode, Action},
    state::{
        ActiveBuild, BuildProgress, BuildStatus, CircuitState, DaemonState, HistoricalBuild,
        Status, TuiState, WorkerState, WorkerStatus,
    },
    widgets,
};
use anyhow::Result;
use chrono::{DateTime, Utc};
use crossterm::{
    event::{DisableMouseCapture, EnableMouseCapture},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};
use std::io::{self, Stdout};
use std::path::PathBuf;
use std::time::{Duration, Instant};

/// Configuration for the TUI dashboard.
#[derive(Debug, Clone)]
pub struct TuiConfig {
    /// Refresh interval in milliseconds.
    pub refresh_interval_ms: u64,
    /// Enable mouse support.
    pub mouse_support: bool,
    /// High contrast mode for accessibility.
    pub high_contrast: bool,
}

impl Default for TuiConfig {
    fn default() -> Self {
        Self {
            refresh_interval_ms: 1000,
            mouse_support: true,
            high_contrast: false,
        }
    }
}

/// Run the TUI dashboard.
pub async fn run_tui(config: TuiConfig) -> Result<()> {
    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    if config.mouse_support {
        execute!(stdout, EnableMouseCapture)?;
    }

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Initialize state and fetch initial data
    let mut state = TuiState::new();
    state.high_contrast = config.high_contrast;
    refresh_state(&mut state).await;

    // Run main loop
    let result = run_app(&mut terminal, &mut state, &config).await;

    // Restore terminal
    disable_raw_mode()?;
    if config.mouse_support {
        execute!(terminal.backend_mut(), DisableMouseCapture)?;
    }
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    result
}

/// Fetch fresh data from daemon and update TUI state.
async fn refresh_state(state: &mut TuiState) {
    match query_daemon_full_status().await {
        Ok(response) => {
            update_state_from_daemon(state, response);
            state.error = None;
        }
        Err(e) => {
            state.daemon.status = Status::Stopped;
            state.error = Some(format!("Failed to connect to daemon: {}", e));
        }
    }
    state.last_update = Instant::now();
}

/// Convert daemon API response to TUI state types.
fn update_state_from_daemon(state: &mut TuiState, response: DaemonFullStatusResponse) {
    // Update daemon state
    state.daemon = DaemonState {
        status: Status::Running,
        uptime: Duration::from_secs(response.daemon.uptime_secs),
        version: response.daemon.version,
        config_path: PathBuf::new(),
        socket_path: PathBuf::from(&response.daemon.socket_path),
        builds_today: response.stats.total_builds as u32,
        bytes_transferred: 0,
    };

    // Update workers
    state.workers = response
        .workers
        .into_iter()
        .map(|w| {
            let status = match w.status.as_str() {
                "healthy" => WorkerStatus::Healthy,
                "degraded" => WorkerStatus::Degraded,
                "draining" => WorkerStatus::Draining,
                _ => WorkerStatus::Unreachable,
            };
            let circuit = match w.circuit_state.as_str() {
                "closed" => CircuitState::Closed,
                "half_open" => CircuitState::HalfOpen,
                _ => CircuitState::Open,
            };
            WorkerState {
                id: w.id,
                host: w.host,
                status,
                circuit,
                total_slots: w.total_slots,
                used_slots: w.used_slots,
                latency_ms: 0,
                last_seen: Utc::now(),
                builds_completed: 0,
            }
        })
        .collect();

    // Update active builds
    state.active_builds = response
        .active_builds
        .into_iter()
        .map(|b| {
            let started_at = DateTime::parse_from_rfc3339(&b.started_at)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now());
            ActiveBuild {
                id: b.id.to_string(),
                command: b.command,
                worker: Some(b.worker_id),
                started_at,
                progress: Some(BuildProgress {
                    phase: "compiling".to_string(),
                    percent: None,
                    current_file: None,
                }),
                status: BuildStatus::Compiling,
            }
        })
        .collect();

    // Update build history
    state.build_history.clear();
    for b in response.recent_builds.into_iter().take(100) {
        let started_at = DateTime::parse_from_rfc3339(&b.started_at)
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now());
        let completed_at = DateTime::parse_from_rfc3339(&b.completed_at)
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now());
        state.build_history.push_back(HistoricalBuild {
            id: b.id.to_string(),
            command: b.command,
            worker: b.worker_id,
            started_at,
            completed_at,
            duration_ms: b.duration_ms,
            success: b.exit_code == 0,
            exit_code: Some(b.exit_code),
        });
    }
}

/// Main application loop.
async fn run_app(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    state: &mut TuiState,
    config: &TuiConfig,
) -> Result<()> {
    let tick_rate = Duration::from_millis(config.refresh_interval_ms);
    let refresh_interval = Duration::from_millis(config.refresh_interval_ms * 5); // Refresh every 5 ticks

    loop {
        // Draw UI
        terminal.draw(|f| widgets::render(f, state))?;

        // Handle events - use input mode when filter_mode is active
        if let Some(action) = poll_event_with_mode(tick_rate, state.filter_mode)? {
            match action {
                Action::Quit => {
                    // If help overlay is open, close it; otherwise quit
                    if state.show_help {
                        state.show_help = false;
                    } else if state.filter_mode {
                        state.filter_mode = false;
                    } else {
                        state.should_quit = true;
                    }
                }
                Action::Up => {
                    if !state.show_help && !state.filter_mode {
                        if let Some(ref mut log_view) = state.log_view {
                            // Scroll log view up
                            log_view.scroll_offset = log_view.scroll_offset.saturating_sub(1);
                            log_view.auto_scroll = false;
                        } else {
                            state.select_up();
                        }
                    }
                }
                Action::Down => {
                    if !state.show_help && !state.filter_mode {
                        if let Some(ref mut log_view) = state.log_view {
                            // Scroll log view down
                            log_view.scroll_offset = log_view.scroll_offset.saturating_add(1);
                        } else {
                            state.select_down();
                        }
                    }
                }
                Action::PageUp => {
                    if let Some(ref mut log_view) = state.log_view {
                        log_view.scroll_offset = log_view.scroll_offset.saturating_sub(20);
                        log_view.auto_scroll = false;
                    }
                }
                Action::PageDown => {
                    if let Some(ref mut log_view) = state.log_view {
                        log_view.scroll_offset = log_view.scroll_offset.saturating_add(20);
                    }
                }
                Action::JumpTop => {
                    if let Some(ref mut log_view) = state.log_view {
                        log_view.scroll_offset = 0;
                        log_view.auto_scroll = false;
                    }
                }
                Action::JumpBottom => {
                    if let Some(ref mut log_view) = state.log_view {
                        // Set to max, will be clamped on render
                        log_view.scroll_offset = usize::MAX;
                        log_view.auto_scroll = true;
                    }
                }
                Action::NextPanel => {
                    if !state.show_help && !state.filter_mode {
                        state.next_panel();
                    }
                }
                Action::PrevPanel => {
                    if !state.show_help && !state.filter_mode {
                        state.prev_panel();
                    }
                }
                Action::Refresh => {
                    // Fetch fresh data from daemon
                    refresh_state(state).await;
                }
                Action::Select => {
                    if state.filter_mode {
                        // Apply filter and exit filter mode
                        state.filter_mode = false;
                        state.selected_index = 0; // Reset selection after filtering
                    } else if !state.show_help {
                        state.handle_select();
                    }
                }
                Action::Back => {
                    // Handle back action - close overlays or go back
                    if state.show_help {
                        state.show_help = false;
                    } else if state.filter_mode {
                        state.filter_mode = false;
                        // Optionally clear filter when cancelled
                        // state.filter.query.clear();
                    } else if state.log_view.is_some() {
                        state.log_view = None;
                    }
                }
                Action::Help => {
                    // Toggle help overlay
                    state.show_help = !state.show_help;
                }
                Action::Filter => {
                    // Toggle filter mode
                    if !state.show_help {
                        state.filter_mode = !state.filter_mode;
                    }
                }
                Action::Copy => {
                    // Copy selected item to clipboard
                    state.copy_selected();
                }
                Action::TextInput(c) => {
                    // Append character to filter query (only active in filter_mode)
                    if state.filter_mode {
                        state.filter.query.push(c);
                    }
                }
                Action::DeleteChar => {
                    // Delete last character from filter query
                    if state.filter_mode {
                        state.filter.query.pop();
                    }
                }
                Action::Tick => {
                    // Regular tick - refresh data periodically
                    if state.last_update.elapsed() >= refresh_interval {
                        refresh_state(state).await;
                    }
                }
            }
        }

        if state.should_quit {
            break;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tui_config_default() {
        let config = TuiConfig::default();
        assert_eq!(config.refresh_interval_ms, 1000);
        assert!(config.mouse_support);
        assert!(!config.high_contrast);
    }
}
