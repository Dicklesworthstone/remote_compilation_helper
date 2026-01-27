//! TUI application runner.
//!
//! Main entry point for the interactive dashboard.

use crate::status_display::query_daemon_full_status;
use crate::status_types::DaemonFullStatusResponse;
use crate::tui::{
    event::{Action, poll_event_with_mode},
    state::{
        ActiveBuild, BuildProgress, BuildStatus, CircuitState, ColorBlindMode, DaemonState,
        HistoricalBuild, Panel, Status, TuiState, WorkerState, WorkerStatus,
    },
    widgets,
};
use anyhow::Result;
use chrono::{DateTime, Utc};
use crossterm::{
    event::{DisableMouseCapture, EnableMouseCapture},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{Terminal, backend::CrosstermBackend};
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
    /// Render once and exit (CI-friendly).
    pub test_mode: bool,
    /// Populate dashboard state with deterministic mock data (no daemon required).
    pub mock_data: bool,
    /// Dump dashboard state as JSON and exit (automation).
    pub dump_state: bool,
    /// High contrast mode for accessibility.
    pub high_contrast: bool,
    /// Color blind palette selection.
    pub color_blind: ColorBlindMode,
}

impl Default for TuiConfig {
    fn default() -> Self {
        Self {
            refresh_interval_ms: 1000,
            mouse_support: true,
            test_mode: false,
            mock_data: false,
            dump_state: false,
            high_contrast: false,
            color_blind: ColorBlindMode::None,
        }
    }
}

/// Run the TUI dashboard.
pub async fn run_tui(config: TuiConfig) -> Result<()> {
    // Non-interactive modes MUST NOT manipulate the terminal.
    if config.dump_state {
        let state = build_initial_state(&config).await;
        let json = state_to_json(&state);
        println!("{}", serde_json::to_string_pretty(&json)?);
        return Ok(());
    }
    if config.test_mode {
        let state = build_initial_state(&config).await;
        let (width, height) = test_backend_size();
        let snapshot = render_snapshot(&state, width, height);
        print!("{snapshot}");
        return Ok(());
    }

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
    state.color_blind = config.color_blind;
    refresh_state(&mut state, &config).await;

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
async fn refresh_state(state: &mut TuiState, config: &TuiConfig) {
    if config.mock_data {
        apply_mock_data(state);
        state.error = None;
        state.last_update = Instant::now();
        return;
    }

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

async fn build_initial_state(config: &TuiConfig) -> TuiState {
    let mut state = TuiState::new();
    state.high_contrast = config.high_contrast;
    state.color_blind = config.color_blind;
    refresh_state(&mut state, config).await;
    state
}

fn test_backend_size() -> (u16, u16) {
    let width = std::env::var("COLUMNS")
        .ok()
        .and_then(|v| v.parse::<u16>().ok())
        .unwrap_or(80);
    let height = std::env::var("LINES")
        .ok()
        .and_then(|v| v.parse::<u16>().ok())
        .unwrap_or(24);
    (width.max(40), height.max(12))
}

fn render_snapshot(state: &TuiState, width: u16, height: u16) -> String {
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).expect("create test terminal");
    terminal
        .draw(|f| widgets::render(f, state))
        .expect("render snapshot");
    buffer_to_string(terminal.backend().buffer())
}

fn buffer_to_string(buffer: &ratatui::buffer::Buffer) -> String {
    let mut out = String::new();
    let width = buffer.area.width;
    let height = buffer.area.height;
    for y in 0..height {
        for x in 0..width {
            if let Some(cell) = buffer.cell((x, y)) {
                out.push_str(cell.symbol());
            } else {
                out.push(' ');
            }
        }
        out.push('\n');
    }
    out
}

fn state_to_json(state: &TuiState) -> serde_json::Value {
    let daemon_status = match state.daemon.status {
        Status::Unknown => "unknown",
        Status::Running => "running",
        Status::Stopped => "stopped",
        Status::Error => "error",
    };
    let selected_panel = match state.selected_panel {
        Panel::Workers => "workers",
        Panel::ActiveBuilds => "active_builds",
        Panel::BuildHistory => "build_history",
        Panel::Logs => "logs",
    };

    serde_json::json!({
        "daemon": {
            "status": daemon_status,
            "version": &state.daemon.version,
            "uptime_ms": state.daemon.uptime.as_millis() as u64,
            "socket_path": state.daemon.socket_path.display().to_string(),
            "builds_today": state.daemon.builds_today,
            "bytes_transferred": state.daemon.bytes_transferred,
        },
        "workers": &state.workers,
        "active_builds": &state.active_builds,
        "build_history": state.build_history.iter().cloned().collect::<Vec<_>>(),
        "selected_panel": selected_panel,
        "selected_index": state.selected_index,
        "filter": {
            "query": &state.filter.query,
            "worker_filter": &state.filter.worker_filter,
            "success_only": state.filter.success_only,
            "failed_only": state.filter.failed_only,
        },
        "high_contrast": state.high_contrast,
        "color_blind": state.color_blind,
        "error": &state.error,
    })
}

fn apply_mock_data(state: &mut TuiState) {
    use crate::tui::state::{BuildStatus, CircuitState, WorkerStatus};
    use chrono::Utc;

    state.daemon = DaemonState {
        status: Status::Running,
        uptime: Duration::from_secs(123),
        version: "mock".to_string(),
        config_path: PathBuf::new(),
        socket_path: PathBuf::from("/tmp/rch.sock"),
        builds_today: 7,
        bytes_transferred: 42_000_000,
    };

    state.workers = vec![
        WorkerState {
            id: "worker-1".to_string(),
            host: "127.0.0.1".to_string(),
            status: WorkerStatus::Healthy,
            circuit: CircuitState::Closed,
            total_slots: 16,
            used_slots: 4,
            latency_ms: 12,
            last_seen: Utc::now(),
            builds_completed: 3,
        },
        WorkerState {
            id: "worker-2".to_string(),
            host: "127.0.0.2".to_string(),
            status: WorkerStatus::Degraded,
            circuit: CircuitState::HalfOpen,
            total_slots: 32,
            used_slots: 20,
            latency_ms: 25,
            last_seen: Utc::now(),
            builds_completed: 9,
        },
        WorkerState {
            id: "worker-3".to_string(),
            host: "127.0.0.3".to_string(),
            status: WorkerStatus::Draining,
            circuit: CircuitState::Open,
            total_slots: 8,
            used_slots: 7,
            latency_ms: 40,
            last_seen: Utc::now(),
            builds_completed: 1,
        },
    ];

    state.active_builds = vec![ActiveBuild {
        id: "1234".to_string(),
        command: "cargo build --release".to_string(),
        worker: Some("worker-2".to_string()),
        started_at: Utc::now(),
        progress: Some(BuildProgress {
            phase: "compiling".to_string(),
            percent: Some(42),
            current_file: Some("serde_derive".to_string()),
        }),
        status: BuildStatus::Compiling,
    }];

    state.build_history.clear();
    for i in 0..5 {
        state.build_history.push_back(HistoricalBuild {
            id: format!("h{}", 1000 + i),
            command: "cargo test".to_string(),
            worker: Some("worker-1".to_string()),
            started_at: Utc::now(),
            completed_at: Utc::now(),
            duration_ms: 1200 + (i as u64 * 100),
            success: true,
            exit_code: Some(0),
        });
    }
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
                    refresh_state(state, config).await;
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
                        refresh_state(state, config).await;
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
    use crate::status_types::{
        ActiveBuildFromApi, BuildRecordFromApi, BuildStatsFromApi, DaemonInfoFromApi, IssueFromApi,
        WorkerStatusFromApi,
    };
    use rch_common::test_guard;
    use tracing::info;

    fn init_test_logging() {
        let _ = tracing_subscriber::fmt()
            .with_test_writer()
            .with_max_level(tracing::Level::DEBUG)
            .try_init();
    }

    fn make_response(
        workers: Vec<WorkerStatusFromApi>,
        active_builds: Vec<ActiveBuildFromApi>,
        recent_builds: Vec<BuildRecordFromApi>,
    ) -> DaemonFullStatusResponse {
        DaemonFullStatusResponse {
            daemon: DaemonInfoFromApi {
                pid: 1234,
                uptime_secs: 3600,
                version: "0.1.0".to_string(),
                socket_path: rch_common::default_socket_path(),
                started_at: "2026-01-17T00:00:00Z".to_string(),
                workers_total: workers.len(),
                workers_healthy: workers.len(),
                slots_total: 32,
                slots_available: 24,
            },
            workers,
            active_builds,
            queued_builds: vec![],
            recent_builds,
            issues: vec![IssueFromApi {
                severity: "info".to_string(),
                summary: "all good".to_string(),
                remediation: None,
            }],
            alerts: vec![],
            stats: BuildStatsFromApi {
                total_builds: 42,
                success_count: 40,
                failure_count: 2,
                remote_count: 40,
                local_count: 2,
                avg_duration_ms: 1200,
            },
            test_stats: None,
            saved_time: None,
        }
    }

    fn worker_status(id: &str, status: &str, circuit: &str) -> WorkerStatusFromApi {
        WorkerStatusFromApi {
            id: id.to_string(),
            host: "worker.local".to_string(),
            user: "builder".to_string(),
            status: status.to_string(),
            circuit_state: circuit.to_string(),
            used_slots: 2,
            total_slots: 8,
            speed_score: 75.0,
            last_error: None,
            consecutive_failures: 0,
            recovery_in_secs: None,
            failure_history: vec![],
        }
    }

    fn active_build(id: u64, worker_id: &str, command: &str) -> ActiveBuildFromApi {
        ActiveBuildFromApi {
            id,
            project_id: "proj".to_string(),
            worker_id: worker_id.to_string(),
            command: command.to_string(),
            started_at: "2026-01-17T00:00:00Z".to_string(),
        }
    }

    fn build_record(id: u64, exit_code: i32, command: &str) -> BuildRecordFromApi {
        BuildRecordFromApi {
            id,
            started_at: "2026-01-17T00:00:00Z".to_string(),
            completed_at: "2026-01-17T00:00:05Z".to_string(),
            project_id: "proj".to_string(),
            worker_id: Some("worker-1".to_string()),
            command: command.to_string(),
            exit_code,
            duration_ms: 5000,
            location: "remote".to_string(),
            bytes_transferred: Some(1234),
            timing: None,
        }
    }

    #[test]
    fn test_tui_config_default() {
        let _guard = test_guard!();
        init_test_logging();
        info!("TEST START: test_tui_config_default");
        let config = TuiConfig::default();
        info!(
            "VERIFY: refresh_interval_ms={} mouse_support={} high_contrast={} color_blind={:?}",
            config.refresh_interval_ms,
            config.mouse_support,
            config.high_contrast,
            config.color_blind
        );
        assert_eq!(config.refresh_interval_ms, 1000);
        assert!(config.mouse_support);
        assert!(!config.test_mode);
        assert!(!config.mock_data);
        assert!(!config.dump_state);
        assert!(!config.high_contrast);
        assert_eq!(config.color_blind, ColorBlindMode::None);
        info!("TEST PASS: test_tui_config_default");
    }

    #[test]
    fn test_dump_state_json_mock_data_has_expected_shape() {
        let _guard = test_guard!();
        init_test_logging();
        info!("TEST START: test_dump_state_json_mock_data_has_expected_shape");
        let mut state = TuiState::new();
        apply_mock_data(&mut state);
        let json = state_to_json(&state);
        info!("VERIFY: daemon.status=running and workers array present");
        assert_eq!(json["daemon"]["status"], "running");
        assert!(json["workers"].is_array());
        assert!(json["active_builds"].is_array());
        assert!(json["build_history"].is_array());
        info!("TEST PASS: test_dump_state_json_mock_data_has_expected_shape");
    }

    #[test]
    fn test_render_snapshot_contains_header() {
        let _guard = test_guard!();
        init_test_logging();
        info!("TEST START: test_render_snapshot_contains_header");
        let mut state = TuiState::new();
        apply_mock_data(&mut state);
        let snapshot = render_snapshot(&state, 80, 24);
        info!("VERIFY: snapshot contains dashboard title");
        assert!(snapshot.contains("RCH Dashboard"));
        info!("TEST PASS: test_render_snapshot_contains_header");
    }

    #[test]
    fn test_update_state_sets_daemon_running() {
        let _guard = test_guard!();
        init_test_logging();
        info!("TEST START: test_update_state_sets_daemon_running");
        let response = make_response(vec![], vec![], vec![]);
        let mut state = TuiState::new();
        update_state_from_daemon(&mut state, response);
        info!(
            "VERIFY: status={:?} uptime={:?}",
            state.daemon.status, state.daemon.uptime
        );
        assert_eq!(state.daemon.status, Status::Running);
        assert_eq!(state.daemon.uptime, Duration::from_secs(3600));
        info!("TEST PASS: test_update_state_sets_daemon_running");
    }

    #[test]
    fn test_update_state_worker_status_mapping() {
        let _guard = test_guard!();
        init_test_logging();
        info!("TEST START: test_update_state_worker_status_mapping");
        let workers = vec![
            worker_status("w1", "healthy", "closed"),
            worker_status("w2", "degraded", "half_open"),
            worker_status("w3", "draining", "open"),
            worker_status("w4", "unknown", "closed"),
        ];
        let response = make_response(workers, vec![], vec![]);
        let mut state = TuiState::new();
        update_state_from_daemon(&mut state, response);
        info!("VERIFY: worker_count={}", state.workers.len());
        assert_eq!(state.workers.len(), 4);
        assert_eq!(state.workers[0].status, WorkerStatus::Healthy);
        assert_eq!(state.workers[1].status, WorkerStatus::Degraded);
        assert_eq!(state.workers[2].status, WorkerStatus::Draining);
        assert_eq!(state.workers[3].status, WorkerStatus::Unreachable);
        info!("TEST PASS: test_update_state_worker_status_mapping");
    }

    #[test]
    fn test_update_state_circuit_mapping() {
        let _guard = test_guard!();
        init_test_logging();
        info!("TEST START: test_update_state_circuit_mapping");
        let workers = vec![
            worker_status("w1", "healthy", "closed"),
            worker_status("w2", "healthy", "half_open"),
            worker_status("w3", "healthy", "open"),
            worker_status("w4", "healthy", "mystery"),
        ];
        let response = make_response(workers, vec![], vec![]);
        let mut state = TuiState::new();
        update_state_from_daemon(&mut state, response);
        assert_eq!(state.workers[0].circuit, CircuitState::Closed);
        assert_eq!(state.workers[1].circuit, CircuitState::HalfOpen);
        assert_eq!(state.workers[2].circuit, CircuitState::Open);
        assert_eq!(state.workers[3].circuit, CircuitState::Open);
        info!("TEST PASS: test_update_state_circuit_mapping");
    }

    #[test]
    fn test_update_state_active_builds_mapping() {
        let _guard = test_guard!();
        init_test_logging();
        info!("TEST START: test_update_state_active_builds_mapping");
        let active = vec![active_build(1, "worker-1", "cargo build --release")];
        let response = make_response(vec![], active, vec![]);
        let mut state = TuiState::new();
        update_state_from_daemon(&mut state, response);
        info!("VERIFY: active_builds={}", state.active_builds.len());
        assert_eq!(state.active_builds.len(), 1);
        assert_eq!(state.active_builds[0].status, BuildStatus::Compiling);
        assert_eq!(
            state.active_builds[0].progress.as_ref().unwrap().phase,
            "compiling"
        );
        assert_eq!(state.active_builds[0].worker.as_deref(), Some("worker-1"));
        info!("TEST PASS: test_update_state_active_builds_mapping");
    }

    #[test]
    fn test_update_state_build_history_limit() {
        let _guard = test_guard!();
        init_test_logging();
        info!("TEST START: test_update_state_build_history_limit");
        let mut history = Vec::new();
        for i in 0..120u64 {
            history.push(build_record(i, 0, "cargo build"));
        }
        let response = make_response(vec![], vec![], history);
        let mut state = TuiState::new();
        update_state_from_daemon(&mut state, response);
        info!("VERIFY: history_len={}", state.build_history.len());
        assert_eq!(state.build_history.len(), 100);
        info!("TEST PASS: test_update_state_build_history_limit");
    }

    #[test]
    fn test_update_state_build_history_success_flag() {
        let _guard = test_guard!();
        init_test_logging();
        info!("TEST START: test_update_state_build_history_success_flag");
        let history = vec![
            build_record(1, 0, "cargo build"),
            build_record(2, 1, "cargo test"),
        ];
        let response = make_response(vec![], vec![], history);
        let mut state = TuiState::new();
        update_state_from_daemon(&mut state, response);
        assert_eq!(state.build_history.len(), 2);
        assert!(state.build_history[0].success);
        assert!(!state.build_history[1].success);
        info!("TEST PASS: test_update_state_build_history_success_flag");
    }

    #[test]
    fn test_update_state_daemon_socket_path() {
        let _guard = test_guard!();
        init_test_logging();
        info!("TEST START: test_update_state_daemon_socket_path");
        let response = make_response(vec![], vec![], vec![]);
        let mut state = TuiState::new();
        update_state_from_daemon(&mut state, response);
        info!(
            "VERIFY: socket_path={:?} version={}",
            state.daemon.socket_path, state.daemon.version
        );
        assert_eq!(
            state.daemon.socket_path,
            PathBuf::from(rch_common::default_socket_path())
        );
        assert_eq!(state.daemon.version, "0.1.0");
        info!("TEST PASS: test_update_state_daemon_socket_path");
    }
}
