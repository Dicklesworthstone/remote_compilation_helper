//! RchConsole - Context-aware wrapper around rich_rust's Console.
//!
//! This module provides the primary interface for rich terminal output in RCH commands.
//! It automatically respects output context (interactive, piped, hook, etc.) and
//! routes output to stderr by design (stdout is reserved for data).
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
//! use rch::ui::console::{RchConsole, CONSOLE};
//!
//! // Using global instance
//! CONSOLE.print_success("Operation completed");
//!
//! // Using local instance with explicit context
//! let console = RchConsole::new();
//! if console.is_machine() {
//!     console.print_json(&data)?;
//! } else {
//!     console.print_rich("[bold]Status[/bold]");
//! }
//! ```

#[cfg(feature = "rich-ui")]
use rich_rust::prelude::*;
#[cfg(feature = "rich-ui")]
use rich_rust::renderables::Renderable;

use rch_common::ui::{Icons, OutputContext, RchTheme};

/// Context-aware console wrapper that respects output mode.
///
/// This is the primary interface for rich output in RCH commands.
/// It automatically:
/// - Detects output context (interactive, piped, hook, etc.)
/// - Routes output to stderr (stdout reserved for data)
/// - Falls back to plain text when appropriate
/// - Respects NO_COLOR and FORCE_COLOR
pub struct RchConsole {
    /// The underlying rich_rust Console (only when rich-ui feature enabled).
    #[cfg(feature = "rich-ui")]
    inner: Console,

    /// Detected output context.
    context: OutputContext,
}

impl RchConsole {
    /// Create a new RchConsole with automatic context detection.
    #[must_use]
    pub fn new() -> Self {
        let context = OutputContext::detect();
        Self::with_context(context)
    }

    /// Create with explicit context (useful for testing).
    #[must_use]
    pub fn with_context(context: OutputContext) -> Self {
        #[cfg(feature = "rich-ui")]
        let inner = Self::build_console(context);

        Self {
            #[cfg(feature = "rich-ui")]
            inner,
            context,
        }
    }

    #[cfg(feature = "rich-ui")]
    fn build_console(context: OutputContext) -> Console {
        Console::builder()
            .force_terminal(context.supports_rich())
            // Output to stderr by default for rich content
            // stdout is reserved for machine-readable data
            .build()
    }

    // ========================================================================
    // CONTEXT QUERIES
    // ========================================================================

    /// Check if rich output is available.
    #[must_use]
    pub fn is_rich(&self) -> bool {
        self.context.supports_rich()
    }

    /// Check if colors are available.
    #[must_use]
    pub fn is_colored(&self) -> bool {
        self.context.supports_color()
    }

    /// Check if in machine output mode (Hook or Machine).
    #[must_use]
    pub fn is_machine(&self) -> bool {
        self.context.is_machine()
    }

    /// Get the detected context.
    #[must_use]
    pub fn context(&self) -> OutputContext {
        self.context
    }

    /// Get terminal width (or default 80).
    #[must_use]
    pub fn width(&self) -> usize {
        #[cfg(feature = "rich-ui")]
        {
            self.inner.width()
        }
        #[cfg(not(feature = "rich-ui"))]
        {
            terminal_size::terminal_size()
                .map(|(w, _)| w.0 as usize)
                .unwrap_or(80)
        }
    }

    // ========================================================================
    // RICH OUTPUT METHODS (only work in rich mode)
    // ========================================================================

    /// Print with markup parsing (only if interactive).
    ///
    /// Does nothing in machine/plain modes.
    #[cfg(feature = "rich-ui")]
    pub fn print_rich(&self, content: &str) {
        if self.context.supports_rich() {
            self.inner.print(content);
        }
    }

    /// Print a renderable (table, panel, etc.).
    ///
    /// Does nothing in machine/plain modes.
    #[cfg(feature = "rich-ui")]
    pub fn print_renderable<R: Renderable>(&self, renderable: &R) {
        if self.context.supports_rich() {
            self.inner.print_renderable(renderable);
        }
    }

    /// Print a horizontal rule.
    ///
    /// Falls back to dashes in non-rich modes.
    pub fn rule(&self, title: Option<&str>) {
        #[cfg(feature = "rich-ui")]
        if self.context.supports_rich() {
            self.inner.rule(title);
            return;
        }

        if !self.context.is_machine() {
            // Plain fallback
            let width: usize = 60;
            if let Some(t) = title {
                let padding = width.saturating_sub(t.len()).saturating_sub(2) / 2;
                eprintln!("{} {} {}", "-".repeat(padding), t, "-".repeat(padding));
            } else {
                eprintln!("{}", "-".repeat(width));
            }
        }
    }

    /// Print a blank line.
    pub fn line(&self) {
        if !self.context.is_machine() {
            #[cfg(feature = "rich-ui")]
            {
                self.inner.line();
            }
            #[cfg(not(feature = "rich-ui"))]
            {
                eprintln!();
            }
        }
    }

    // ========================================================================
    // FALLBACK OUTPUT METHODS
    // ========================================================================

    /// Print with rich/plain fallback.
    ///
    /// - In rich mode: prints rich content
    /// - In plain mode: prints plain content
    /// - In machine mode: prints nothing
    pub fn print_or_plain(&self, _rich: &str, plain: &str) {
        #[cfg(feature = "rich-ui")]
        if self.context.supports_rich() {
            self.inner.print(_rich);
            return;
        }

        if !self.context.is_machine() {
            eprintln!("{plain}");
        }
    }

    /// Print plain text to stderr (always, unless machine mode).
    ///
    /// Use for messages that should appear in plain mode too.
    pub fn print_plain(&self, content: &str) {
        if !self.context.is_machine() {
            eprintln!("{content}");
        }
    }

    /// Print error with rich panel or plain fallback.
    ///
    /// Always prints (errors should show even in machine mode to stderr).
    #[cfg(feature = "rich-ui")]
    pub fn print_error(&self, title: &str, message: &str) {
        if self.context.supports_rich() {
            let icon = Icons::cross(self.context);
            let title_text = format!("{icon} {title}");
            let panel = Panel::from_text(message)
                .title(title_text.as_str())
                .border_style(RchTheme::error())
                .rounded();
            self.inner.print_renderable(&panel);
        } else {
            let icon = Icons::cross(self.context);
            eprintln!("{icon} Error: {title}");
            eprintln!("{message}");
        }
    }

    /// Print error with plain fallback (non-rich-ui version).
    #[cfg(not(feature = "rich-ui"))]
    pub fn print_error(&self, title: &str, message: &str) {
        let icon = Icons::cross(self.context);
        eprintln!("{icon} Error: {title}");
        eprintln!("{message}");
    }

    /// Print success message.
    pub fn print_success(&self, message: &str) {
        let icon = Icons::check(self.context);

        #[cfg(feature = "rich-ui")]
        if self.context.supports_rich() {
            self.inner
                .print(&format!("[bold {}]{icon}[/] {message}", RchTheme::SUCCESS));
            return;
        }

        if !self.context.is_machine() {
            eprintln!("{icon} {message}");
        }
    }

    /// Print warning message.
    pub fn print_warning(&self, message: &str) {
        let icon = Icons::warning(self.context);

        #[cfg(feature = "rich-ui")]
        if self.context.supports_rich() {
            self.inner
                .print(&format!("[bold {}]{icon}[/] {message}", RchTheme::WARNING));
            return;
        }

        if !self.context.is_machine() {
            eprintln!("{icon} {message}");
        }
    }

    /// Print info message.
    pub fn print_info(&self, message: &str) {
        let icon = Icons::info(self.context);

        #[cfg(feature = "rich-ui")]
        if self.context.supports_rich() {
            self.inner
                .print(&format!("[bold {}]{icon}[/] {message}", RchTheme::INFO));
            return;
        }

        if !self.context.is_machine() {
            eprintln!("{icon} {message}");
        }
    }

    // ========================================================================
    // MACHINE OUTPUT (to stdout)
    // ========================================================================

    /// Print JSON to stdout (for --json flag).
    ///
    /// This goes to stdout, not stderr!
    pub fn print_json<T: serde::Serialize>(&self, value: &T) -> serde_json::Result<()> {
        let json = serde_json::to_string_pretty(value)?;
        println!("{json}");
        Ok(())
    }

    // ========================================================================
    // ACCESS TO UNDERLYING CONSOLE
    // ========================================================================

    /// Get the underlying rich_rust Console.
    ///
    /// Use sparingly - prefer the wrapper methods.
    #[cfg(feature = "rich-ui")]
    #[must_use]
    pub fn inner(&self) -> &Console {
        &self.inner
    }
}

impl Default for RchConsole {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// CONVENIENCE FUNCTION
// ============================================================================

/// Create a new console instance with automatic context detection.
///
/// Use this for quick access in command handlers:
/// ```ignore
/// use rch::ui::console::console;
/// console().print_success("Done!");
/// ```
///
/// Note: This creates a new instance each time. If you need to reuse
/// the same instance across multiple calls, create one with `RchConsole::new()`
/// and store it locally.
#[must_use]
pub fn console() -> RchConsole {
    RchConsole::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_machine_mode_no_rich() {
        let console = RchConsole::with_context(OutputContext::Machine);
        // These should do nothing (not panic)
        console.print_plain("test"); // Should be suppressed
        assert!(console.is_machine());
        assert!(!console.is_rich());
    }

    #[test]
    fn test_hook_mode_is_machine() {
        let console = RchConsole::with_context(OutputContext::Hook);
        assert!(console.is_machine());
        assert!(!console.is_rich());
        assert!(!console.is_colored());
    }

    #[test]
    fn test_plain_mode_no_markup() {
        let console = RchConsole::with_context(OutputContext::Plain);
        // Should work but without markup
        assert!(!console.is_machine());
        assert!(!console.is_rich());
    }

    #[test]
    fn test_context_queries_interactive() {
        let console = RchConsole::with_context(OutputContext::Interactive);
        assert!(console.is_rich());
        assert!(console.is_colored());
        assert!(!console.is_machine());
    }

    #[test]
    fn test_context_queries_colored() {
        let console = RchConsole::with_context(OutputContext::Colored);
        assert!(!console.is_rich()); // FORCE_COLOR doesn't mean we have a rich terminal
        assert!(console.is_colored());
        assert!(!console.is_machine());
    }

    #[test]
    fn test_width_returns_reasonable_value() {
        let console = RchConsole::new();
        let width = console.width();
        assert!(width >= 40, "Width should be at least 40: {width}");
        assert!(width <= 500, "Width should be at most 500: {width}");
    }

    #[test]
    fn test_default_creates_valid_console() {
        let console = RchConsole::default();
        // Should not panic and context should be valid
        let _ = console.context();
    }

    #[test]
    fn test_console_function() {
        let c1 = console();
        let c2 = console();
        // Both should have the same context detection result
        assert_eq!(c1.context(), c2.context());
    }

    #[test]
    fn test_print_json_succeeds() {
        let console = RchConsole::with_context(OutputContext::Machine);
        #[derive(serde::Serialize)]
        struct TestData {
            value: i32,
        }
        // Should not panic (output goes to stdout)
        let result = console.print_json(&TestData { value: 42 });
        assert!(result.is_ok());
    }

    #[test]
    fn test_rule_plain_mode() {
        let console = RchConsole::with_context(OutputContext::Plain);
        // Should not panic
        console.rule(None);
        console.rule(Some("Test Title"));
    }

    #[test]
    fn test_rule_machine_mode_silent() {
        let console = RchConsole::with_context(OutputContext::Machine);
        // Should not panic, should do nothing
        console.rule(None);
        console.rule(Some("Test Title"));
    }

    #[test]
    fn test_line_plain_mode() {
        let console = RchConsole::with_context(OutputContext::Plain);
        // Should not panic
        console.line();
    }

    #[test]
    fn test_print_or_plain_modes() {
        // Machine mode: should print nothing
        let console = RchConsole::with_context(OutputContext::Machine);
        console.print_or_plain("[bold]rich[/]", "plain");

        // Plain mode: should print plain
        let console = RchConsole::with_context(OutputContext::Plain);
        console.print_or_plain("[bold]rich[/]", "plain");
    }

    #[test]
    fn test_status_messages_machine_mode() {
        let console = RchConsole::with_context(OutputContext::Machine);
        // These should be suppressed in machine mode (except print_error)
        console.print_success("success");
        console.print_warning("warning");
        console.print_info("info");
    }

    #[test]
    fn test_print_error_always_outputs() {
        // Even in machine mode, errors should output to stderr
        let console = RchConsole::with_context(OutputContext::Machine);
        console.print_error("Test Error", "This is a test error message");
        // Should not panic - error output always happens
    }
}
