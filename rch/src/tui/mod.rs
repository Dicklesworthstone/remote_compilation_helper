//! Interactive TUI dashboard for RCH monitoring.
//!
//! Provides real-time worker status, active build monitoring, and operator actions
//! using ratatui for terminal UI rendering.

mod app;
mod event;
mod state;
mod widgets;

pub use app::{TuiConfig, run_tui};
pub use state::{Panel, TuiState};

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
