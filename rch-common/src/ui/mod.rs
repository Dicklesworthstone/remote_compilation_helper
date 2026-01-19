//! UI utilities for RCH terminal output.
//!
//! This module provides context-aware output utilities that automatically
//! adapt to the current environment (interactive terminal, hook mode, piped, etc.).
//!
//! # Key Components
//!
//! - [`OutputContext`]: Detects and represents the current output context
//! - [`Icons`]: Unicode icons with automatic ASCII fallbacks
//! - [`RchTheme`]: Brand colors and semantic styles
//!
//! # Design Philosophy
//!
//! - **stdout** is for DATA (JSON, compilation output, etc.)
//! - **stderr** is for DIAGNOSTICS (status, progress, errors)
//!
//! Rich output goes to stderr so that:
//! 1. Agents can parse stdout reliably
//! 2. Piping `rch status | jq` works correctly
//! 3. Compilation output passthrough is unaffected
//!
//! # Example
//!
//! ```ignore
//! use rch_common::ui::{Icons, OutputContext, RchTheme};
//!
//! let ctx = OutputContext::detect();
//! eprintln!("{} Build successful", Icons::check(ctx));
//!
//! // With rich-ui feature enabled:
//! let style = RchTheme::success();
//! ```

pub mod context;
pub mod icons;
pub mod theme;

pub use context::OutputContext;
pub use icons::Icons;
pub use theme::RchTheme;
