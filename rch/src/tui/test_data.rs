//! Mock data generators for TUI testing.
//!
//! Provides factory functions to create test instances of TUI state
//! structures with sensible defaults. These are useful for unit tests
//! that need realistic but deterministic test data.
//!
//! # Example
//!
//! ```ignore
//! use crate::tui::test_data::*;
//!
//! let state = mock_state_with_workers(3);
//! assert_eq!(state.workers.len(), 3);
//!
//! let worker = mock_worker("test-1");
//! assert_eq!(worker.id, "test-1");
//! ```

use chrono::{Duration as ChronoDuration, Utc};
use std::collections::VecDeque;
use std::path::PathBuf;
use std::time::Duration;
use tracing::debug;

use super::state::{
    ActiveBuild, BuildProgress, BuildStatus, CircuitState, ColorBlindMode, DaemonState,
    FilterState, HistoricalBuild, LogViewState, Panel, Status, TuiState, WorkerState,
    WorkerStatus,
};

// ============================================================================
// Worker Mock Generators
// ============================================================================

/// Create a mock worker with sensible defaults.
///
/// # Arguments
///
/// * `id` - The worker identifier
///
/// # Returns
///
/// A `WorkerState` with healthy status and default values.
pub fn mock_worker(id: &str) -> WorkerState {
    debug!("TEST DATA: creating mock worker '{}'", id);
    WorkerState {
        id: id.to_string(),
        host: format!("{}.local", id),
        status: WorkerStatus::Healthy,
        circuit: CircuitState::Closed,
        total_slots: 8,
        used_slots: 1,
        latency_ms: 10,
        last_seen: Utc::now(),
        builds_completed: 0,
    }
}

/// Create a mock worker with specific status.
///
/// # Arguments
///
/// * `id` - The worker identifier
/// * `status` - The worker status
/// * `circuit` - The circuit breaker state
pub fn mock_worker_with_status(
    id: &str,
    status: WorkerStatus,
    circuit: CircuitState,
) -> WorkerState {
    debug!(
        "TEST DATA: creating mock worker '{}' status={:?} circuit={:?}",
        id, status, circuit
    );
    WorkerState {
        id: id.to_string(),
        host: format!("{}.local", id),
        status,
        circuit,
        total_slots: 8,
        used_slots: 2,
        latency_ms: 15,
        last_seen: Utc::now(),
        builds_completed: 5,
    }
}

/// Create a mock worker with specific slot configuration.
///
/// # Arguments
///
/// * `id` - The worker identifier
/// * `used_slots` - Number of slots currently in use
/// * `total_slots` - Total available slots
pub fn mock_worker_with_slots(id: &str, used_slots: u32, total_slots: u32) -> WorkerState {
    debug!(
        "TEST DATA: creating mock worker '{}' slots={}/{}",
        id, used_slots, total_slots
    );
    WorkerState {
        id: id.to_string(),
        host: format!("{}.local", id),
        status: WorkerStatus::Healthy,
        circuit: CircuitState::Closed,
        total_slots,
        used_slots,
        latency_ms: 10,
        last_seen: Utc::now(),
        builds_completed: 0,
    }
}

/// Create a healthy worker with a specific host.
pub fn mock_worker_with_host(id: &str, host: &str) -> WorkerState {
    WorkerState {
        id: id.to_string(),
        host: host.to_string(),
        status: WorkerStatus::Healthy,
        circuit: CircuitState::Closed,
        total_slots: 8,
        used_slots: 0,
        latency_ms: 10,
        last_seen: Utc::now(),
        builds_completed: 0,
    }
}

// ============================================================================
// Build Mock Generators
// ============================================================================

/// Create a mock active build.
///
/// # Arguments
///
/// * `id` - Build identifier
/// * `command` - The command being executed
pub fn mock_active_build(id: &str, command: &str) -> ActiveBuild {
    debug!("TEST DATA: creating mock active build '{}' cmd='{}'", id, command);
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

/// Create a mock active build with specific status.
///
/// # Arguments
///
/// * `id` - Build identifier
/// * `command` - The command being executed
/// * `status` - The build status
/// * `progress_percent` - Optional progress percentage
pub fn mock_active_build_with_status(
    id: &str,
    command: &str,
    status: BuildStatus,
    progress_percent: Option<u8>,
) -> ActiveBuild {
    debug!(
        "TEST DATA: creating mock active build '{}' status={:?} progress={:?}",
        id, status, progress_percent
    );
    ActiveBuild {
        id: id.to_string(),
        command: command.to_string(),
        worker: Some("worker-1".to_string()),
        started_at: Utc::now(),
        progress: progress_percent.map(|p| BuildProgress {
            phase: format!("{:?}", status).to_lowercase(),
            percent: Some(p),
            current_file: None,
        }),
        status,
    }
}

/// Create a mock active build with specific worker.
pub fn mock_active_build_with_worker(id: &str, command: &str, worker_id: &str) -> ActiveBuild {
    ActiveBuild {
        id: id.to_string(),
        command: command.to_string(),
        worker: Some(worker_id.to_string()),
        started_at: Utc::now(),
        progress: Some(BuildProgress {
            phase: "compiling".to_string(),
            percent: Some(50),
            current_file: None,
        }),
        status: BuildStatus::Compiling,
    }
}

/// Create a mock active build with no worker (pending).
pub fn mock_pending_build(id: &str, command: &str) -> ActiveBuild {
    ActiveBuild {
        id: id.to_string(),
        command: command.to_string(),
        worker: None,
        started_at: Utc::now(),
        progress: None,
        status: BuildStatus::Pending,
    }
}

// ============================================================================
// Historical Build Mock Generators
// ============================================================================

/// Create a mock historical build record.
///
/// # Arguments
///
/// * `id` - Build identifier
/// * `command` - The command that was executed
/// * `worker` - Optional worker that executed the build
/// * `success` - Whether the build succeeded
pub fn mock_historical_build(
    id: &str,
    command: &str,
    worker: Option<&str>,
    success: bool,
) -> HistoricalBuild {
    debug!(
        "TEST DATA: creating mock history '{}' worker={:?} success={}",
        id, worker, success
    );
    let started_at = Utc::now() - ChronoDuration::seconds(5);
    let completed_at = Utc::now();
    HistoricalBuild {
        id: id.to_string(),
        command: command.to_string(),
        worker: worker.map(|w| w.to_string()),
        started_at,
        completed_at,
        duration_ms: 5000,
        success,
        exit_code: Some(if success { 0 } else { 1 }),
    }
}

/// Create a mock historical build with specific duration.
///
/// # Arguments
///
/// * `id` - Build identifier
/// * `command` - The command that was executed
/// * `duration_ms` - Build duration in milliseconds
/// * `success` - Whether the build succeeded
pub fn mock_historical_build_with_duration(
    id: &str,
    command: &str,
    duration_ms: u64,
    success: bool,
) -> HistoricalBuild {
    debug!(
        "TEST DATA: creating mock history '{}' duration={}ms success={}",
        id, duration_ms, success
    );
    let started_at = Utc::now() - ChronoDuration::milliseconds(duration_ms as i64);
    let completed_at = Utc::now();
    HistoricalBuild {
        id: id.to_string(),
        command: command.to_string(),
        worker: Some("worker-1".to_string()),
        started_at,
        completed_at,
        duration_ms,
        success,
        exit_code: Some(if success { 0 } else { 1 }),
    }
}

/// Create a mock historical build with specific exit code.
pub fn mock_historical_build_with_exit_code(
    id: &str,
    command: &str,
    exit_code: i32,
) -> HistoricalBuild {
    let success = exit_code == 0;
    let started_at = Utc::now() - ChronoDuration::seconds(3);
    HistoricalBuild {
        id: id.to_string(),
        command: command.to_string(),
        worker: Some("worker-1".to_string()),
        started_at,
        completed_at: Utc::now(),
        duration_ms: 3000,
        success,
        exit_code: Some(exit_code),
    }
}

/// Create a mock historical build executed locally (no worker).
pub fn mock_local_build(id: &str, command: &str, success: bool) -> HistoricalBuild {
    mock_historical_build(id, command, None, success)
}

// ============================================================================
// Daemon State Mock Generators
// ============================================================================

/// Create a mock daemon state with running status.
pub fn mock_daemon_running() -> DaemonState {
    debug!("TEST DATA: creating mock daemon (running)");
    DaemonState {
        status: Status::Running,
        uptime: Duration::from_secs(3600),
        version: "0.1.0-test".to_string(),
        config_path: PathBuf::from("/etc/rch/config.toml"),
        socket_path: PathBuf::from("/tmp/rch.sock"),
        builds_today: 42,
        bytes_transferred: 1_000_000,
    }
}

/// Create a mock daemon state with stopped status.
pub fn mock_daemon_stopped() -> DaemonState {
    debug!("TEST DATA: creating mock daemon (stopped)");
    DaemonState {
        status: Status::Stopped,
        uptime: Duration::ZERO,
        version: String::new(),
        config_path: PathBuf::new(),
        socket_path: PathBuf::from("/tmp/rch.sock"),
        builds_today: 0,
        bytes_transferred: 0,
    }
}

/// Create a mock daemon state with error status.
pub fn mock_daemon_error() -> DaemonState {
    DaemonState {
        status: Status::Error,
        uptime: Duration::from_secs(100),
        version: "0.1.0-test".to_string(),
        config_path: PathBuf::new(),
        socket_path: PathBuf::from("/tmp/rch.sock"),
        builds_today: 5,
        bytes_transferred: 50_000,
    }
}

// ============================================================================
// Log View State Mock Generators
// ============================================================================

/// Create a mock log view state.
///
/// # Arguments
///
/// * `build_id` - The build ID being viewed
/// * `line_count` - Number of log lines to generate
pub fn mock_log_view(build_id: &str, line_count: usize) -> LogViewState {
    debug!(
        "TEST DATA: creating mock log view '{}' with {} lines",
        build_id, line_count
    );
    let mut lines = VecDeque::with_capacity(line_count);
    for i in 0..line_count {
        let line = if i % 10 == 0 {
            format!("   Compiling crate-{} v1.0.0", i)
        } else if i % 15 == 0 {
            format!("warning: unused variable `x` in line {}", i)
        } else if i % 20 == 0 {
            format!("error[E0425]: cannot find value `y` in line {}", i)
        } else {
            format!("Building [{}/{}] target/debug/lib{}.rlib", i, line_count, i)
        };
        lines.push_back(line);
    }
    LogViewState {
        build_id: build_id.to_string(),
        lines,
        scroll_offset: 0,
        auto_scroll: true,
    }
}

/// Create an empty log view state.
pub fn mock_log_view_empty(build_id: &str) -> LogViewState {
    LogViewState {
        build_id: build_id.to_string(),
        lines: VecDeque::new(),
        scroll_offset: 0,
        auto_scroll: true,
    }
}

/// Create a log view with scroll position.
pub fn mock_log_view_scrolled(build_id: &str, line_count: usize, scroll_offset: usize) -> LogViewState {
    let mut view = mock_log_view(build_id, line_count);
    view.scroll_offset = scroll_offset;
    view.auto_scroll = false;
    view
}

// ============================================================================
// Filter State Mock Generators
// ============================================================================

/// Create a filter state with query.
pub fn mock_filter_with_query(query: &str) -> FilterState {
    FilterState {
        query: query.to_string(),
        worker_filter: None,
        success_only: false,
        failed_only: false,
    }
}

/// Create a filter state with worker filter.
pub fn mock_filter_with_worker(worker_id: &str) -> FilterState {
    FilterState {
        query: String::new(),
        worker_filter: Some(worker_id.to_string()),
        success_only: false,
        failed_only: false,
    }
}

/// Create a filter state for success-only builds.
pub fn mock_filter_success_only() -> FilterState {
    FilterState {
        query: String::new(),
        worker_filter: None,
        success_only: true,
        failed_only: false,
    }
}

/// Create a filter state for failed-only builds.
pub fn mock_filter_failed_only() -> FilterState {
    FilterState {
        query: String::new(),
        worker_filter: None,
        success_only: false,
        failed_only: true,
    }
}

// ============================================================================
// Full TuiState Mock Generators
// ============================================================================

/// Create a default TUI state (empty).
pub fn mock_state() -> TuiState {
    debug!("TEST DATA: creating default mock state");
    TuiState::new()
}

/// Create a TUI state with specified number of workers.
///
/// # Arguments
///
/// * `count` - Number of workers to create
pub fn mock_state_with_workers(count: usize) -> TuiState {
    debug!("TEST DATA: creating mock state with {} workers", count);
    let mut state = TuiState::new();
    state.daemon = mock_daemon_running();
    state.workers = (0..count)
        .map(|i| mock_worker(&format!("worker-{}", i + 1)))
        .collect();
    state
}

/// Create a TUI state with workers and active builds.
///
/// # Arguments
///
/// * `worker_count` - Number of workers to create
/// * `build_count` - Number of active builds to create
pub fn mock_state_with_builds(worker_count: usize, build_count: usize) -> TuiState {
    debug!(
        "TEST DATA: creating mock state with {} workers and {} builds",
        worker_count, build_count
    );
    let mut state = mock_state_with_workers(worker_count);
    state.active_builds = (0..build_count)
        .map(|i| mock_active_build(&format!("build-{}", i + 1), "cargo build"))
        .collect();
    state
}

/// Create a TUI state with build history.
///
/// # Arguments
///
/// * `history_count` - Number of historical builds to create
pub fn mock_state_with_history(history_count: usize) -> TuiState {
    debug!(
        "TEST DATA: creating mock state with {} history items",
        history_count
    );
    let mut state = mock_state_with_workers(2);
    state.build_history = (0..history_count)
        .map(|i| {
            mock_historical_build(
                &format!("h{}", i + 1),
                &format!("cargo build --release ({})", i),
                Some("worker-1"),
                i % 3 != 0, // Every 3rd build fails
            )
        })
        .collect();
    state
}

/// Create a complete TUI state with all features populated.
///
/// This creates a realistic state similar to what the `--mock-data` flag produces.
pub fn mock_state_complete() -> TuiState {
    debug!("TEST DATA: creating complete mock state");
    let mut state = TuiState::new();

    state.daemon = DaemonState {
        status: Status::Running,
        uptime: Duration::from_secs(7200),
        version: "0.1.0-mock".to_string(),
        config_path: PathBuf::from("/etc/rch/config.toml"),
        socket_path: PathBuf::from("/tmp/rch.sock"),
        builds_today: 25,
        bytes_transferred: 500_000_000,
    };

    state.workers = vec![
        mock_worker_with_status("worker-1", WorkerStatus::Healthy, CircuitState::Closed),
        mock_worker_with_status("worker-2", WorkerStatus::Degraded, CircuitState::HalfOpen),
        mock_worker_with_status("worker-3", WorkerStatus::Draining, CircuitState::Open),
        mock_worker_with_slots("worker-4", 7, 8),
    ];

    state.active_builds = vec![
        mock_active_build_with_status("b1", "cargo build --release", BuildStatus::Compiling, Some(65)),
        mock_active_build_with_status("b2", "cargo test", BuildStatus::Syncing, Some(20)),
    ];

    state.build_history = (0..10)
        .map(|i| {
            mock_historical_build_with_duration(
                &format!("h{}", i + 1),
                "cargo test --workspace",
                1000 + (i as u64) * 500,
                i % 5 != 0,
            )
        })
        .collect();

    state
}

/// Create a TUI state with error condition.
pub fn mock_state_with_error(error_msg: &str) -> TuiState {
    let mut state = TuiState::new();
    state.daemon = mock_daemon_stopped();
    state.error = Some(error_msg.to_string());
    state
}

/// Create a TUI state with help overlay visible.
pub fn mock_state_with_help() -> TuiState {
    let mut state = mock_state_complete();
    state.show_help = true;
    state
}

/// Create a TUI state in filter mode.
pub fn mock_state_filter_mode(query: &str) -> TuiState {
    let mut state = mock_state_with_history(10);
    state.filter_mode = true;
    state.filter = mock_filter_with_query(query);
    state
}

/// Create a TUI state with log view open.
pub fn mock_state_with_logs(line_count: usize) -> TuiState {
    let mut state = mock_state_complete();
    state.log_view = Some(mock_log_view("build-log-test", line_count));
    state.selected_panel = Panel::Logs;
    state
}

/// Create a TUI state with specific panel selected.
pub fn mock_state_with_panel(panel: Panel) -> TuiState {
    let mut state = mock_state_complete();
    state.selected_panel = panel;
    state.selected_index = 0;
    state
}

/// Create a TUI state with accessibility options.
pub fn mock_state_accessible(high_contrast: bool, color_blind: ColorBlindMode) -> TuiState {
    let mut state = mock_state_complete();
    state.high_contrast = high_contrast;
    state.color_blind = color_blind;
    state
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

    // ==================== Worker Tests ====================

    #[test]
    fn test_mock_worker_basic() {
        init_test_logging();
        info!("TEST START: test_mock_worker_basic");
        let worker = mock_worker("test-1");
        assert_eq!(worker.id, "test-1");
        assert_eq!(worker.host, "test-1.local");
        assert_eq!(worker.status, WorkerStatus::Healthy);
        assert_eq!(worker.circuit, CircuitState::Closed);
        assert_eq!(worker.total_slots, 8);
        assert_eq!(worker.used_slots, 1);
        info!("TEST PASS: test_mock_worker_basic");
    }

    #[test]
    fn test_mock_worker_with_status() {
        init_test_logging();
        info!("TEST START: test_mock_worker_with_status");
        let worker = mock_worker_with_status("w1", WorkerStatus::Degraded, CircuitState::HalfOpen);
        assert_eq!(worker.status, WorkerStatus::Degraded);
        assert_eq!(worker.circuit, CircuitState::HalfOpen);
        info!("TEST PASS: test_mock_worker_with_status");
    }

    #[test]
    fn test_mock_worker_with_slots() {
        init_test_logging();
        info!("TEST START: test_mock_worker_with_slots");
        let worker = mock_worker_with_slots("w1", 5, 16);
        assert_eq!(worker.used_slots, 5);
        assert_eq!(worker.total_slots, 16);
        info!("TEST PASS: test_mock_worker_with_slots");
    }

    #[test]
    fn test_mock_worker_with_host() {
        init_test_logging();
        info!("TEST START: test_mock_worker_with_host");
        let worker = mock_worker_with_host("w1", "192.168.1.100");
        assert_eq!(worker.host, "192.168.1.100");
        info!("TEST PASS: test_mock_worker_with_host");
    }

    // ==================== Active Build Tests ====================

    #[test]
    fn test_mock_active_build_basic() {
        init_test_logging();
        info!("TEST START: test_mock_active_build_basic");
        let build = mock_active_build("b1", "cargo build");
        assert_eq!(build.id, "b1");
        assert_eq!(build.command, "cargo build");
        assert_eq!(build.status, BuildStatus::Compiling);
        assert!(build.worker.is_some());
        assert!(build.progress.is_some());
        info!("TEST PASS: test_mock_active_build_basic");
    }

    #[test]
    fn test_mock_active_build_with_status() {
        init_test_logging();
        info!("TEST START: test_mock_active_build_with_status");
        let build = mock_active_build_with_status("b1", "cmd", BuildStatus::Syncing, Some(30));
        assert_eq!(build.status, BuildStatus::Syncing);
        assert_eq!(build.progress.as_ref().unwrap().percent, Some(30));
        info!("TEST PASS: test_mock_active_build_with_status");
    }

    #[test]
    fn test_mock_pending_build() {
        init_test_logging();
        info!("TEST START: test_mock_pending_build");
        let build = mock_pending_build("b1", "cargo test");
        assert_eq!(build.status, BuildStatus::Pending);
        assert!(build.worker.is_none());
        assert!(build.progress.is_none());
        info!("TEST PASS: test_mock_pending_build");
    }

    // ==================== Historical Build Tests ====================

    #[test]
    fn test_mock_historical_build_success() {
        init_test_logging();
        info!("TEST START: test_mock_historical_build_success");
        let build = mock_historical_build("h1", "cargo build", Some("w1"), true);
        assert_eq!(build.id, "h1");
        assert!(build.success);
        assert_eq!(build.exit_code, Some(0));
        assert_eq!(build.worker, Some("w1".to_string()));
        info!("TEST PASS: test_mock_historical_build_success");
    }

    #[test]
    fn test_mock_historical_build_failure() {
        init_test_logging();
        info!("TEST START: test_mock_historical_build_failure");
        let build = mock_historical_build("h1", "cargo test", Some("w1"), false);
        assert!(!build.success);
        assert_eq!(build.exit_code, Some(1));
        info!("TEST PASS: test_mock_historical_build_failure");
    }

    #[test]
    fn test_mock_local_build() {
        init_test_logging();
        info!("TEST START: test_mock_local_build");
        let build = mock_local_build("h1", "cargo check", true);
        assert!(build.worker.is_none());
        info!("TEST PASS: test_mock_local_build");
    }

    #[test]
    fn test_mock_historical_build_with_duration() {
        init_test_logging();
        info!("TEST START: test_mock_historical_build_with_duration");
        let build = mock_historical_build_with_duration("h1", "cmd", 5000, true);
        assert_eq!(build.duration_ms, 5000);
        info!("TEST PASS: test_mock_historical_build_with_duration");
    }

    // ==================== Daemon State Tests ====================

    #[test]
    fn test_mock_daemon_running() {
        init_test_logging();
        info!("TEST START: test_mock_daemon_running");
        let daemon = mock_daemon_running();
        assert_eq!(daemon.status, Status::Running);
        assert!(!daemon.version.is_empty());
        assert!(daemon.uptime > Duration::ZERO);
        info!("TEST PASS: test_mock_daemon_running");
    }

    #[test]
    fn test_mock_daemon_stopped() {
        init_test_logging();
        info!("TEST START: test_mock_daemon_stopped");
        let daemon = mock_daemon_stopped();
        assert_eq!(daemon.status, Status::Stopped);
        assert_eq!(daemon.uptime, Duration::ZERO);
        info!("TEST PASS: test_mock_daemon_stopped");
    }

    #[test]
    fn test_mock_daemon_error() {
        init_test_logging();
        info!("TEST START: test_mock_daemon_error");
        let daemon = mock_daemon_error();
        assert_eq!(daemon.status, Status::Error);
        info!("TEST PASS: test_mock_daemon_error");
    }

    // ==================== Log View Tests ====================

    #[test]
    fn test_mock_log_view() {
        init_test_logging();
        info!("TEST START: test_mock_log_view");
        let log_view = mock_log_view("b1", 50);
        assert_eq!(log_view.build_id, "b1");
        assert_eq!(log_view.lines.len(), 50);
        assert!(log_view.auto_scroll);
        info!("TEST PASS: test_mock_log_view");
    }

    #[test]
    fn test_mock_log_view_empty() {
        init_test_logging();
        info!("TEST START: test_mock_log_view_empty");
        let log_view = mock_log_view_empty("b1");
        assert!(log_view.lines.is_empty());
        info!("TEST PASS: test_mock_log_view_empty");
    }

    #[test]
    fn test_mock_log_view_scrolled() {
        init_test_logging();
        info!("TEST START: test_mock_log_view_scrolled");
        let log_view = mock_log_view_scrolled("b1", 100, 25);
        assert_eq!(log_view.scroll_offset, 25);
        assert!(!log_view.auto_scroll);
        info!("TEST PASS: test_mock_log_view_scrolled");
    }

    // ==================== Filter State Tests ====================

    #[test]
    fn test_mock_filter_with_query() {
        init_test_logging();
        info!("TEST START: test_mock_filter_with_query");
        let filter = mock_filter_with_query("cargo");
        assert_eq!(filter.query, "cargo");
        assert!(filter.worker_filter.is_none());
        info!("TEST PASS: test_mock_filter_with_query");
    }

    #[test]
    fn test_mock_filter_with_worker() {
        init_test_logging();
        info!("TEST START: test_mock_filter_with_worker");
        let filter = mock_filter_with_worker("worker-1");
        assert_eq!(filter.worker_filter, Some("worker-1".to_string()));
        info!("TEST PASS: test_mock_filter_with_worker");
    }

    #[test]
    fn test_mock_filter_success_only() {
        init_test_logging();
        info!("TEST START: test_mock_filter_success_only");
        let filter = mock_filter_success_only();
        assert!(filter.success_only);
        assert!(!filter.failed_only);
        info!("TEST PASS: test_mock_filter_success_only");
    }

    #[test]
    fn test_mock_filter_failed_only() {
        init_test_logging();
        info!("TEST START: test_mock_filter_failed_only");
        let filter = mock_filter_failed_only();
        assert!(!filter.success_only);
        assert!(filter.failed_only);
        info!("TEST PASS: test_mock_filter_failed_only");
    }

    // ==================== Full State Tests ====================

    #[test]
    fn test_mock_state_empty() {
        init_test_logging();
        info!("TEST START: test_mock_state_empty");
        let state = mock_state();
        assert!(state.workers.is_empty());
        assert!(state.active_builds.is_empty());
        assert!(state.build_history.is_empty());
        info!("TEST PASS: test_mock_state_empty");
    }

    #[test]
    fn test_mock_state_with_workers() {
        init_test_logging();
        info!("TEST START: test_mock_state_with_workers");
        let state = mock_state_with_workers(5);
        assert_eq!(state.workers.len(), 5);
        assert_eq!(state.daemon.status, Status::Running);
        for (i, w) in state.workers.iter().enumerate() {
            assert_eq!(w.id, format!("worker-{}", i + 1));
        }
        info!("TEST PASS: test_mock_state_with_workers");
    }

    #[test]
    fn test_mock_state_with_builds() {
        init_test_logging();
        info!("TEST START: test_mock_state_with_builds");
        let state = mock_state_with_builds(2, 3);
        assert_eq!(state.workers.len(), 2);
        assert_eq!(state.active_builds.len(), 3);
        info!("TEST PASS: test_mock_state_with_builds");
    }

    #[test]
    fn test_mock_state_with_history() {
        init_test_logging();
        info!("TEST START: test_mock_state_with_history");
        let state = mock_state_with_history(10);
        assert_eq!(state.build_history.len(), 10);
        info!("TEST PASS: test_mock_state_with_history");
    }

    #[test]
    fn test_mock_state_complete() {
        init_test_logging();
        info!("TEST START: test_mock_state_complete");
        let state = mock_state_complete();
        assert!(!state.workers.is_empty());
        assert!(!state.active_builds.is_empty());
        assert!(!state.build_history.is_empty());
        assert_eq!(state.daemon.status, Status::Running);
        info!("TEST PASS: test_mock_state_complete");
    }

    #[test]
    fn test_mock_state_with_error() {
        init_test_logging();
        info!("TEST START: test_mock_state_with_error");
        let state = mock_state_with_error("Connection refused");
        assert_eq!(state.error, Some("Connection refused".to_string()));
        assert_eq!(state.daemon.status, Status::Stopped);
        info!("TEST PASS: test_mock_state_with_error");
    }

    #[test]
    fn test_mock_state_with_help() {
        init_test_logging();
        info!("TEST START: test_mock_state_with_help");
        let state = mock_state_with_help();
        assert!(state.show_help);
        info!("TEST PASS: test_mock_state_with_help");
    }

    #[test]
    fn test_mock_state_filter_mode() {
        init_test_logging();
        info!("TEST START: test_mock_state_filter_mode");
        let state = mock_state_filter_mode("test");
        assert!(state.filter_mode);
        assert_eq!(state.filter.query, "test");
        info!("TEST PASS: test_mock_state_filter_mode");
    }

    #[test]
    fn test_mock_state_with_logs() {
        init_test_logging();
        info!("TEST START: test_mock_state_with_logs");
        let state = mock_state_with_logs(50);
        assert!(state.log_view.is_some());
        assert_eq!(state.log_view.as_ref().unwrap().lines.len(), 50);
        assert_eq!(state.selected_panel, Panel::Logs);
        info!("TEST PASS: test_mock_state_with_logs");
    }

    #[test]
    fn test_mock_state_with_panel() {
        init_test_logging();
        info!("TEST START: test_mock_state_with_panel");
        let state = mock_state_with_panel(Panel::BuildHistory);
        assert_eq!(state.selected_panel, Panel::BuildHistory);
        assert_eq!(state.selected_index, 0);
        info!("TEST PASS: test_mock_state_with_panel");
    }

    #[test]
    fn test_mock_state_accessible() {
        init_test_logging();
        info!("TEST START: test_mock_state_accessible");
        let state = mock_state_accessible(true, ColorBlindMode::Deuteranopia);
        assert!(state.high_contrast);
        assert_eq!(state.color_blind, ColorBlindMode::Deuteranopia);
        info!("TEST PASS: test_mock_state_accessible");
    }
}
