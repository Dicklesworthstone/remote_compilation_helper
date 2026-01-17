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
