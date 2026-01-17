//! UI output abstraction layer for the RCH CLI.
//!
//! This module provides a consistent interface for CLI output that handles:
//! - Color detection and NO_COLOR compliance
//! - TTY vs piped output detection
//! - JSON output mode for machine consumption
//! - Quiet/verbose modes
//! - Unicode vs ASCII fallback
//! - Thread-safe output for concurrent operations
//! - Adaptive colors for light/dark terminal backgrounds
//!
//! # Usage
//!
//! ```rust,ignore
//! use rch::ui::{OutputConfig, OutputContext};
//!
//! // Create from CLI args
//! let config = OutputConfig {
//!     json: args.json,
//!     verbose: args.verbose,
//!     quiet: args.quiet,
//!     color: ColorChoice::from_str(&args.color),
//!     ..Default::default()
//! };
//! let ctx = OutputContext::new(config);
//!
//! // Use for output
//! ctx.header("Workers");
//! ctx.key_value("Status", "Healthy");
//! ctx.success("Operation completed");
//!
//! // Or JSON mode
//! ctx.json(&WorkersResponse { workers })?;
//! ```
//!
//! # Output Modes
//!
//! - **Human**: Colored output with unicode symbols
//! - **Plain**: No colors, ASCII fallback, for dumb terminals or pipes
//! - **JSON**: Machine-readable JSON to stdout
//! - **Quiet**: Errors only
//!
//! # Standards Compliance
//!
//! - Respects `NO_COLOR` environment variable (https://no-color.org/)
//! - Respects `CLICOLOR_FORCE` for forcing colors
//! - Respects `TERM=dumb` for plain output
//! - Detects pipe/redirection to disable colors
//! - Detects terminal background (light/dark) via COLORFGBG
//! - Detects color level (16/256/true color)

pub mod adaptive;
pub mod context;
pub mod markdown;
pub mod progress;
pub mod styled;
pub mod test_utils;
pub mod theme;
pub mod writer;

// Re-export main types for convenience
pub use adaptive::{
    AdaptiveColor, Background, ColorLevel, detect_background, detect_color_level,
    detect_hyperlink_support, palette,
};
pub use context::{
    ColorChoice, OutputConfig, OutputContext, OutputMode, TerminalCaps, Verbosity, default_context,
};
pub use markdown::{render_markdown, strip_markdown};
pub use progress::{
    MultiProgressManager, Spinner, StepProgress, TransferProgress, with_spinner,
    with_spinner_result,
};
pub use styled::{
    Align, BorderChars, BorderStyle, BoxStyle, Margin, Padding, Spacing, join_horizontal,
    join_vertical, place, presets,
};
pub use theme::{SemanticColors, StatusIndicator, Symbols, Theme};
pub use writer::{OutputBuffer, OutputWriter, SharedOutputBuffer};

// Test utilities are public for integration tests
pub use test_utils::{
    OutputCapture, OutputContextBuilder, assert_has_ansi, assert_no_ansi, assert_stderr_contains,
    assert_stderr_not_contains, assert_stdout_contains, assert_stdout_not_contains,
    assert_valid_json, strip_ansi,
};
