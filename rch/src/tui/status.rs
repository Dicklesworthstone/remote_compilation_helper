//! TUI status indicator mappings.
//!
//! Maps TUI state types to StatusIndicator and provides consistent symbols
//! and colors for the TUI display.

use crate::tui::state::{BuildStatus, CircuitState, Status, WorkerStatus};
use crate::ui::theme::{StatusIndicator, Symbols};

/// Get the display symbol and status indicator for daemon status.
pub fn daemon_status(status: &Status) -> (StatusIndicator, &'static str) {
    match status {
        Status::Running => (StatusIndicator::Info, "Running"),
        Status::Stopped => (StatusIndicator::Pending, "Stopped"),
        Status::Error => (StatusIndicator::Error, "Error"),
        Status::Unknown => (StatusIndicator::Pending, "Unknown"),
    }
}

/// Get the symbol for daemon status.
pub fn daemon_symbol(status: &Status) -> &'static str {
    match status {
        Status::Running => StatusIndicator::Info.unicode_symbol(),
        Status::Stopped => StatusIndicator::Pending.unicode_symbol(),
        Status::Error => StatusIndicator::Error.unicode_symbol(),
        Status::Unknown => Symbols::UNICODE.unknown,
    }
}

/// Get the status indicator for worker status.
///
/// Useful for future color mapping based on indicator semantics.
#[allow(dead_code)]
pub fn worker_indicator(status: &WorkerStatus) -> StatusIndicator {
    match status {
        WorkerStatus::Healthy => StatusIndicator::Success,
        WorkerStatus::Degraded => StatusIndicator::Warning,
        WorkerStatus::Unreachable => StatusIndicator::Error,
        WorkerStatus::Draining => StatusIndicator::InProgress,
        WorkerStatus::Drained => StatusIndicator::Info,
        WorkerStatus::Disabled => StatusIndicator::Pending,
    }
}

/// Get the symbol for worker status.
pub fn worker_symbol(status: &WorkerStatus) -> &'static str {
    match status {
        WorkerStatus::Healthy => StatusIndicator::Info.unicode_symbol(), // ●
        WorkerStatus::Degraded => StatusIndicator::InProgress.unicode_symbol(), // ◐
        WorkerStatus::Unreachable => StatusIndicator::Pending.unicode_symbol(), // ○
        WorkerStatus::Draining => Symbols::UNICODE.draining,             // ◑
        WorkerStatus::Drained => StatusIndicator::Pending.unicode_symbol(), // ○ (empty)
        WorkerStatus::Disabled => StatusIndicator::Disabled.unicode_symbol(), // ⊘ (disabled)
    }
}

/// Get the status indicator for build status.
///
/// Useful for future color mapping based on indicator semantics.
#[allow(dead_code)]
pub fn build_indicator(status: &BuildStatus) -> StatusIndicator {
    match status {
        BuildStatus::Pending => StatusIndicator::Pending,
        BuildStatus::Syncing => StatusIndicator::InProgress,
        BuildStatus::Compiling => StatusIndicator::InProgress,
        BuildStatus::Downloading => StatusIndicator::InProgress,
        BuildStatus::Completed => StatusIndicator::Success,
        BuildStatus::Failed => StatusIndicator::Error,
    }
}

/// Get the symbol for build status.
pub fn build_symbol(status: &BuildStatus) -> &'static str {
    match status {
        BuildStatus::Pending => Symbols::UNICODE.waiting, // ◷
        BuildStatus::Syncing => Symbols::UNICODE.syncing, // ↑
        BuildStatus::Compiling => Symbols::UNICODE.compiling, // ⚙
        BuildStatus::Downloading => Symbols::UNICODE.downloading, // ↓
        BuildStatus::Completed => StatusIndicator::Success.unicode_symbol(), // ✓
        BuildStatus::Failed => StatusIndicator::Error.unicode_symbol(), // ✗
    }
}

/// Get the symbol for circuit breaker state.
pub fn circuit_symbol(state: &CircuitState) -> &'static str {
    match state {
        CircuitState::Closed => "",
        CircuitState::HalfOpen => Symbols::UNICODE.circuit_half_open, // ↻
        CircuitState::Open => StatusIndicator::Info.unicode_symbol(), // ●
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_daemon_symbols_not_empty() {
        assert!(!daemon_symbol(&Status::Running).is_empty());
        assert!(!daemon_symbol(&Status::Stopped).is_empty());
        assert!(!daemon_symbol(&Status::Error).is_empty());
        assert!(!daemon_symbol(&Status::Unknown).is_empty());
    }

    #[test]
    fn test_worker_symbols_not_empty() {
        assert!(!worker_symbol(&WorkerStatus::Healthy).is_empty());
        assert!(!worker_symbol(&WorkerStatus::Degraded).is_empty());
        assert!(!worker_symbol(&WorkerStatus::Unreachable).is_empty());
        assert!(!worker_symbol(&WorkerStatus::Draining).is_empty());
    }

    #[test]
    fn test_build_symbols_not_empty() {
        assert!(!build_symbol(&BuildStatus::Pending).is_empty());
        assert!(!build_symbol(&BuildStatus::Syncing).is_empty());
        assert!(!build_symbol(&BuildStatus::Compiling).is_empty());
        assert!(!build_symbol(&BuildStatus::Downloading).is_empty());
        assert!(!build_symbol(&BuildStatus::Completed).is_empty());
        assert!(!build_symbol(&BuildStatus::Failed).is_empty());
    }

    #[test]
    fn test_circuit_symbols() {
        assert_eq!(circuit_symbol(&CircuitState::Closed), "");
        assert!(!circuit_symbol(&CircuitState::HalfOpen).is_empty());
        assert!(!circuit_symbol(&CircuitState::Open).is_empty());
    }

    #[test]
    fn test_worker_indicator_mappings() {
        assert_eq!(
            worker_indicator(&WorkerStatus::Healthy),
            StatusIndicator::Success
        );
        assert_eq!(
            worker_indicator(&WorkerStatus::Degraded),
            StatusIndicator::Warning
        );
        assert_eq!(
            worker_indicator(&WorkerStatus::Unreachable),
            StatusIndicator::Error
        );
        assert_eq!(
            worker_indicator(&WorkerStatus::Draining),
            StatusIndicator::InProgress
        );
    }

    #[test]
    fn test_build_indicator_mappings() {
        assert_eq!(
            build_indicator(&BuildStatus::Pending),
            StatusIndicator::Pending
        );
        assert_eq!(
            build_indicator(&BuildStatus::Syncing),
            StatusIndicator::InProgress
        );
        assert_eq!(
            build_indicator(&BuildStatus::Compiling),
            StatusIndicator::InProgress
        );
        assert_eq!(
            build_indicator(&BuildStatus::Downloading),
            StatusIndicator::InProgress
        );
        assert_eq!(
            build_indicator(&BuildStatus::Completed),
            StatusIndicator::Success
        );
        assert_eq!(
            build_indicator(&BuildStatus::Failed),
            StatusIndicator::Error
        );
    }
}
