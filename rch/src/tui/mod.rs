//! Interactive TUI dashboard for RCH monitoring.
//!
//! Provides real-time worker status, active build monitoring, and operator actions
//! using ratatui for terminal UI rendering.
//!
//! # Test Infrastructure
//!
//! The TUI module provides shared test utilities for testing components:
//!
//! - [`test_harness`]: Test terminal creation, rendering utilities, and assertion helpers
//! - [`test_data`]: Mock data generators for workers, builds, and state
//!
//! These are only compiled when running tests (`#[cfg(test)]`).

mod app;
mod event;
mod state;
mod widgets;

// Test infrastructure modules - only compiled for tests
#[cfg(test)]
pub mod test_data;
#[cfg(test)]
pub mod test_harness;

pub use app::{TuiConfig, run_tui};
pub use state::{ColorBlindMode, Panel, TuiState};

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

    #[test]
    fn test_reexports_accessible() {
        init_test_logging();
        info!("TEST START: test_reexports_accessible");
        let config = TuiConfig::default();
        let state = TuiState::new();
        info!(
            "VERIFY: refresh_interval_ms={} panel={:?}",
            config.refresh_interval_ms, state.selected_panel
        );
        assert_eq!(config.refresh_interval_ms, 1000);
        assert_eq!(state.selected_panel, Panel::Workers);
        info!("TEST PASS: test_reexports_accessible");
    }

    #[test]
    fn test_panel_next_prev_roundtrip() {
        init_test_logging();
        info!("TEST START: test_panel_next_prev_roundtrip");
        let panel = Panel::Workers;
        let next = panel.next();
        let prev = next.prev();
        assert_eq!(prev, Panel::Workers);
        info!("TEST PASS: test_panel_next_prev_roundtrip");
    }
}
