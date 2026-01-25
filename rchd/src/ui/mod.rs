//! UI utilities for rchd daemon output.
//!
//! This module provides context-aware output utilities for the daemon,
//! including shutdown sequence display and session summaries.
//!
//! # Design Philosophy
//!
//! - Output goes to stderr (daemon logs, status messages)
//! - Must complete even if rich output partially initialized
//! - Plain text fallback for degraded terminal state
//! - Version included in final message for troubleshooting

pub mod shutdown;

#[allow(unused_imports)]
pub use shutdown::{JobDrainEvent, SessionStats, ShutdownSequence};
