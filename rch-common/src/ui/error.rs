//! ErrorPanel - Consistent, actionable error display for RCH.
//!
//! This module provides the base error display component with:
//! - Red-bordered panel with error icon and title
//! - Error code in header (RCH-Exxx format)
//! - Context section with relevant details
//! - Suggestion section with remediation steps
//! - Optional stack trace (collapsed by default)
//! - JSON serialization for machine output
//!
//! # Example
//!
//! ```ignore
//! use rch_common::ui::error::{ErrorPanel, ErrorSeverity};
//!
//! let error = ErrorPanel::new("RCH-E042", "Worker Connection Failed")
//!     .message("Could not establish SSH connection to worker 'build1'")
//!     .context("Host", "build1.internal (192.168.1.50:22)")
//!     .context("Timeout", "30s elapsed")
//!     .context("Last successful", "2h 15m ago")
//!     .suggestion("Check if worker is online: ssh build1.internal")
//!     .suggestion("Verify SSH key: ssh-add -l")
//!     .suggestion("Run: rch workers probe build1 --verbose");
//!
//! // Render to console
//! error.render(&console);
//!
//! // Or serialize to JSON
//! let json = serde_json::to_string(&error)?;
//! ```

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[cfg(feature = "rich-ui")]
use rich_rust::prelude::*;
#[cfg(feature = "rich-ui")]
use rich_rust::r#box::HEAVY;

use super::{Icons, OutputContext, RchTheme};

/// Error severity level.
///
/// Determines the color and icon used for display.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ErrorSeverity {
    /// Critical/error level - red border, cross icon.
    #[default]
    Error,
    /// Warning level - amber border, warning icon.
    Warning,
    /// Informational level - blue border, info icon.
    Info,
}

impl ErrorSeverity {
    /// Get the color hex code for this severity level.
    #[must_use]
    pub const fn color(&self) -> &'static str {
        match self {
            Self::Error => RchTheme::ERROR,
            Self::Warning => RchTheme::WARNING,
            Self::Info => RchTheme::INFO,
        }
    }

    /// Get the icon function for this severity level.
    #[must_use]
    pub fn icon(&self, ctx: OutputContext) -> &'static str {
        match self {
            Self::Error => Icons::cross(ctx),
            Self::Warning => Icons::warning(ctx),
            Self::Info => Icons::info(ctx),
        }
    }

    /// Get the severity name for display.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Error => "ERROR",
            Self::Warning => "WARN",
            Self::Info => "INFO",
        }
    }
}

impl std::fmt::Display for ErrorSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// A key-value context item for error details.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorContext {
    /// The context key (e.g., "Host", "Timeout").
    pub key: String,
    /// The context value (e.g., "build1.internal", "30s").
    pub value: String,
}

/// An error that caused this error (for error chaining).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CausedBy {
    /// Brief description of the cause.
    pub message: String,
    /// Optional error code of the cause.
    pub code: Option<String>,
}

/// ErrorPanel - The base error display component for RCH.
///
/// Provides consistent, actionable error messages with:
/// - Error code and title
/// - Main message
/// - Context key-value pairs
/// - Remediation suggestions
/// - Error chaining support
/// - Timestamp for debugging
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorPanel {
    /// Error code in RCH-Exxx format.
    pub code: String,

    /// Short error title (e.g., "Worker Connection Failed").
    pub title: String,

    /// Main error message with details.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,

    /// Error severity level.
    pub severity: ErrorSeverity,

    /// Context key-value pairs (e.g., Host, Timeout).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub context: Vec<ErrorContext>,

    /// Remediation suggestions (numbered list).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub suggestions: Vec<String>,

    /// Error chain (caused by).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub caused_by: Vec<CausedBy>,

    /// Stack trace (usually collapsed/hidden).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stack_trace: Option<String>,

    /// Timestamp when the error occurred.
    pub timestamp: DateTime<Utc>,

    /// Whether the message was truncated (show --verbose hint).
    #[serde(default)]
    pub truncated: bool,
}

impl ErrorPanel {
    /// Create a new ErrorPanel with code and title.
    ///
    /// # Arguments
    ///
    /// * `code` - Error code (e.g., "RCH-E042")
    /// * `title` - Short error title (e.g., "Worker Connection Failed")
    #[must_use]
    pub fn new(code: impl Into<String>, title: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            title: title.into(),
            message: None,
            severity: ErrorSeverity::Error,
            context: Vec::new(),
            suggestions: Vec::new(),
            caused_by: Vec::new(),
            stack_trace: None,
            timestamp: Utc::now(),
            truncated: false,
        }
    }

    /// Create an error-level ErrorPanel (red, cross icon).
    #[must_use]
    pub fn error(code: impl Into<String>, title: impl Into<String>) -> Self {
        Self::new(code, title).with_severity(ErrorSeverity::Error)
    }

    /// Create a warning-level ErrorPanel (amber, warning icon).
    #[must_use]
    pub fn warning(code: impl Into<String>, title: impl Into<String>) -> Self {
        Self::new(code, title).with_severity(ErrorSeverity::Warning)
    }

    /// Create an info-level ErrorPanel (blue, info icon).
    #[must_use]
    pub fn info(code: impl Into<String>, title: impl Into<String>) -> Self {
        Self::new(code, title).with_severity(ErrorSeverity::Info)
    }

    /// Set the severity level.
    #[must_use]
    pub fn with_severity(mut self, severity: ErrorSeverity) -> Self {
        self.severity = severity;
        self
    }

    /// Set the main error message.
    #[must_use]
    pub fn message(mut self, message: impl Into<String>) -> Self {
        self.message = Some(message.into());
        self
    }

    /// Set the main error message, truncating if too long.
    ///
    /// If the message exceeds `max_len` characters, it will be truncated
    /// and `truncated` will be set to true (shows --verbose hint).
    #[must_use]
    pub fn message_truncated(mut self, message: impl Into<String>, max_len: usize) -> Self {
        let msg = message.into();
        if msg.len() > max_len {
            self.message = Some(format!("{}...", &msg[..max_len.saturating_sub(3)]));
            self.truncated = true;
        } else {
            self.message = Some(msg);
        }
        self
    }

    /// Add a context key-value pair.
    #[must_use]
    pub fn context(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.context.push(ErrorContext {
            key: key.into(),
            value: value.into(),
        });
        self
    }

    /// Add a remediation suggestion.
    #[must_use]
    pub fn suggestion(mut self, suggestion: impl Into<String>) -> Self {
        self.suggestions.push(suggestion.into());
        self
    }

    /// Add multiple suggestions at once.
    #[must_use]
    pub fn suggestions<I, S>(mut self, suggestions: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.suggestions
            .extend(suggestions.into_iter().map(Into::into));
        self
    }

    /// Add a caused-by error (for error chaining).
    #[must_use]
    pub fn caused_by(mut self, message: impl Into<String>, code: Option<String>) -> Self {
        self.caused_by.push(CausedBy {
            message: message.into(),
            code,
        });
        self
    }

    /// Add a stack trace (shown in verbose mode or dim).
    #[must_use]
    pub fn stack_trace(mut self, trace: impl Into<String>) -> Self {
        self.stack_trace = Some(trace.into());
        self
    }

    /// Set the timestamp explicitly.
    #[must_use]
    pub fn with_timestamp(mut self, timestamp: DateTime<Utc>) -> Self {
        self.timestamp = timestamp;
        self
    }

    // ========================================================================
    // RENDERING
    // ========================================================================

    /// Render the error panel to stderr.
    ///
    /// Automatically selects rich or plain output based on context.
    pub fn render(&self, ctx: OutputContext) {
        if ctx.is_machine() {
            // Machine mode - render nothing, caller should use to_json()
            return;
        }

        #[cfg(feature = "rich-ui")]
        if ctx.supports_rich() {
            self.render_rich(ctx);
            return;
        }

        self.render_plain(ctx);
    }

    /// Render using rich_rust Panel.
    #[cfg(feature = "rich-ui")]
    fn render_rich(&self, ctx: OutputContext) {
        let content = self.build_content(ctx, true);
        let icon = self.severity.icon(ctx);
        let title_text = format!("{icon} {}: {}", self.code, self.title);

        let border_color = Color::parse(self.severity.color()).unwrap_or_else(|_| Color::default());
        let border_style = Style::new().bold().color(border_color);

        let panel = Panel::from_text(&content)
            .title(title_text.as_str())
            .border_style(border_style)
            .box_style(&HEAVY);

        // Print to stderr via Console
        let console = Console::builder().force_terminal(true).build();
        console.print_renderable(&panel);
    }

    /// Render plain text to stderr.
    fn render_plain(&self, ctx: OutputContext) {
        let icon = self.severity.icon(ctx);
        let severity = self.severity.name();

        // Header line
        eprintln!("{icon} [{severity}] {}: {}", self.code, self.title);

        // Main message
        if let Some(ref msg) = self.message {
            eprintln!();
            eprintln!("{msg}");
        }

        // Context section
        if !self.context.is_empty() {
            eprintln!();
            eprintln!("Context:");
            for item in &self.context {
                eprintln!("  {}: {}", item.key, item.value);
            }
        }

        // Error chain
        if !self.caused_by.is_empty() {
            eprintln!();
            eprintln!("Caused by:");
            for cause in &self.caused_by {
                if let Some(ref code) = cause.code {
                    eprintln!("  [{code}] {}", cause.message);
                } else {
                    eprintln!("  {}", cause.message);
                }
            }
        }

        // Suggestions
        if !self.suggestions.is_empty() {
            eprintln!();
            eprintln!("Suggestions:");
            for (i, suggestion) in self.suggestions.iter().enumerate() {
                eprintln!("  {}. {suggestion}", i + 1);
            }
        }

        // Truncation hint
        if self.truncated {
            eprintln!();
            eprintln!("(Use --verbose for full message)");
        }

        // Stack trace (dim)
        if let Some(ref trace) = self.stack_trace {
            eprintln!();
            eprintln!("Stack trace:");
            for line in trace.lines() {
                eprintln!("  {line}");
            }
        }

        // Timestamp
        eprintln!();
        eprintln!("[{}]", self.timestamp.format("%Y-%m-%d %H:%M:%S UTC"));
    }

    /// Build content string for panel body.
    #[cfg(feature = "rich-ui")]
    fn build_content(&self, ctx: OutputContext, _use_markup: bool) -> String {
        let mut lines = Vec::new();

        // Main message
        if let Some(ref msg) = self.message {
            lines.push(msg.clone());
        }

        // Context section
        if !self.context.is_empty() {
            lines.push(String::new());
            lines.push(format!("[{}]Context:[/]", RchTheme::DIM));
            for item in &self.context {
                lines.push(format!(
                    "  [{}]{}:[/] {}",
                    RchTheme::DIM,
                    item.key,
                    item.value
                ));
            }
        }

        // Error chain
        if !self.caused_by.is_empty() {
            lines.push(String::new());
            lines.push(format!("[{}]Caused by:[/]", RchTheme::DIM));
            for cause in &self.caused_by {
                if let Some(ref code) = cause.code {
                    lines.push(format!("  [{code}] {}", cause.message));
                } else {
                    lines.push(format!("  {}", cause.message));
                }
            }
        }

        // Suggestions
        if !self.suggestions.is_empty() {
            lines.push(String::new());
            lines.push(format!("[{}]Suggestions:[/]", RchTheme::SECONDARY));
            for (i, suggestion) in self.suggestions.iter().enumerate() {
                lines.push(format!(
                    "  [{}]{}.[/] {}",
                    RchTheme::SECONDARY,
                    i + 1,
                    suggestion
                ));
            }
        }

        // Truncation hint
        if self.truncated {
            lines.push(String::new());
            lines.push(format!(
                "[{}](Use --verbose for full message)[/]",
                RchTheme::DIM
            ));
        }

        // Stack trace (dim)
        if let Some(ref trace) = self.stack_trace {
            lines.push(String::new());
            lines.push(format!("[{}]Stack trace:[/]", RchTheme::DIM));
            for line in trace.lines() {
                lines.push(format!("[{}]  {line}[/]", RchTheme::DIM));
            }
        }

        // Timestamp
        lines.push(String::new());
        let timestamp_icon = Icons::clock(ctx);
        lines.push(format!(
            "[{}]{timestamp_icon} {}[/]",
            RchTheme::DIM,
            self.timestamp.format("%Y-%m-%d %H:%M:%S UTC")
        ));

        lines.join("\n")
    }

    /// Serialize to JSON string.
    ///
    /// Use this for --json mode output.
    pub fn to_json(&self) -> serde_json::Result<String> {
        serde_json::to_string_pretty(self)
    }

    /// Serialize to compact JSON string.
    pub fn to_json_compact(&self) -> serde_json::Result<String> {
        serde_json::to_string(self)
    }
}

impl std::fmt::Display for ErrorPanel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}: {}", self.severity, self.code, self.title)?;
        if let Some(ref msg) = self.message {
            write!(f, " - {msg}")?;
        }
        Ok(())
    }
}

impl std::error::Error for ErrorPanel {}

// ============================================================================
// CONVENIENCE FUNCTIONS
// ============================================================================

/// Create an error panel and render it immediately.
///
/// For quick error display without building the full panel manually.
pub fn show_error(code: &str, title: &str, message: &str, ctx: OutputContext) {
    ErrorPanel::error(code, title).message(message).render(ctx);
}

/// Create a warning panel and render it immediately.
pub fn show_warning(code: &str, title: &str, message: &str, ctx: OutputContext) {
    ErrorPanel::warning(code, title)
        .message(message)
        .render(ctx);
}

/// Create an info panel and render it immediately.
pub fn show_info(code: &str, title: &str, message: &str, ctx: OutputContext) {
    ErrorPanel::info(code, title).message(message).render(ctx);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_panel_creation() {
        let error = ErrorPanel::new("RCH-E042", "Test Error");
        assert_eq!(error.code, "RCH-E042");
        assert_eq!(error.title, "Test Error");
        assert_eq!(error.severity, ErrorSeverity::Error);
        assert!(error.message.is_none());
        assert!(error.context.is_empty());
        assert!(error.suggestions.is_empty());
    }

    #[test]
    fn test_error_panel_builder() {
        let error = ErrorPanel::error("RCH-E001", "Connection Failed")
            .message("Could not connect to worker")
            .context("Host", "192.168.1.10")
            .context("Port", "22")
            .suggestion("Check if worker is online")
            .suggestion("Verify SSH key");

        assert_eq!(error.severity, ErrorSeverity::Error);
        assert_eq!(
            error.message.as_deref(),
            Some("Could not connect to worker")
        );
        assert_eq!(error.context.len(), 2);
        assert_eq!(error.suggestions.len(), 2);
    }

    #[test]
    fn test_warning_panel() {
        let warning = ErrorPanel::warning("RCH-W001", "Slow Response");
        assert_eq!(warning.severity, ErrorSeverity::Warning);
    }

    #[test]
    fn test_info_panel() {
        let info = ErrorPanel::info("RCH-I001", "Build Complete");
        assert_eq!(info.severity, ErrorSeverity::Info);
    }

    #[test]
    fn test_message_truncation() {
        let long_message = "a".repeat(1000);
        let error = ErrorPanel::new("RCH-E001", "Test").message_truncated(long_message, 100);

        assert!(error.truncated);
        assert!(error.message.as_ref().unwrap().len() <= 100);
        assert!(error.message.as_ref().unwrap().ends_with("..."));
    }

    #[test]
    fn test_message_no_truncation_needed() {
        let short_message = "Short message";
        let error = ErrorPanel::new("RCH-E001", "Test").message_truncated(short_message, 100);

        assert!(!error.truncated);
        assert_eq!(error.message.as_deref(), Some("Short message"));
    }

    #[test]
    fn test_error_chaining() {
        let error = ErrorPanel::error("RCH-E042", "Connection Failed")
            .caused_by("SSH handshake failed", Some("SSH-001".to_string()))
            .caused_by("Network unreachable", None);

        assert_eq!(error.caused_by.len(), 2);
        assert_eq!(error.caused_by[0].code, Some("SSH-001".to_string()));
        assert!(error.caused_by[1].code.is_none());
    }

    #[test]
    fn test_json_serialization() {
        let error = ErrorPanel::error("RCH-E001", "Test Error")
            .message("Test message")
            .context("Key", "Value");

        let json = error.to_json().expect("JSON serialization failed");
        assert!(json.contains("RCH-E001"));
        assert!(json.contains("Test Error"));
        assert!(json.contains("Test message"));
    }

    #[test]
    fn test_json_compact_serialization() {
        let error = ErrorPanel::error("RCH-E001", "Test");
        let json = error.to_json_compact().expect("JSON serialization failed");
        // Compact JSON should not have newlines
        assert!(!json.contains('\n'));
    }

    #[test]
    fn test_display_implementation() {
        let error = ErrorPanel::error("RCH-E001", "Test Error").message("Details here");
        let display = format!("{error}");
        assert!(display.contains("ERROR"));
        assert!(display.contains("RCH-E001"));
        assert!(display.contains("Test Error"));
        assert!(display.contains("Details here"));
    }

    #[test]
    fn test_severity_colors() {
        assert_eq!(ErrorSeverity::Error.color(), RchTheme::ERROR);
        assert_eq!(ErrorSeverity::Warning.color(), RchTheme::WARNING);
        assert_eq!(ErrorSeverity::Info.color(), RchTheme::INFO);
    }

    #[test]
    fn test_severity_names() {
        assert_eq!(ErrorSeverity::Error.name(), "ERROR");
        assert_eq!(ErrorSeverity::Warning.name(), "WARN");
        assert_eq!(ErrorSeverity::Info.name(), "INFO");
    }

    #[test]
    fn test_severity_icons_plain() {
        let ctx = OutputContext::Plain;
        // Just verify they don't panic and return something
        assert!(!ErrorSeverity::Error.icon(ctx).is_empty());
        assert!(!ErrorSeverity::Warning.icon(ctx).is_empty());
        assert!(!ErrorSeverity::Info.icon(ctx).is_empty());
    }

    #[test]
    fn test_render_plain_mode() {
        let error = ErrorPanel::error("RCH-E001", "Test")
            .message("Message")
            .context("Key", "Value")
            .suggestion("Do something");

        // Should not panic
        error.render(OutputContext::Plain);
    }

    #[test]
    fn test_render_machine_mode_silent() {
        let error = ErrorPanel::error("RCH-E001", "Test");
        // Should not output anything in machine mode
        error.render(OutputContext::Machine);
    }

    #[test]
    fn test_render_hook_mode_silent() {
        let error = ErrorPanel::error("RCH-E001", "Test");
        // Should not output anything in hook mode
        error.render(OutputContext::Hook);
    }

    #[test]
    fn test_stack_trace() {
        let error =
            ErrorPanel::error("RCH-E001", "Test").stack_trace("at main.rs:42\nat lib.rs:100");

        assert!(error.stack_trace.is_some());
        assert!(error.stack_trace.as_ref().unwrap().contains("main.rs:42"));
    }

    #[test]
    fn test_multiple_suggestions() {
        let error = ErrorPanel::error("RCH-E001", "Test").suggestions([
            "First suggestion",
            "Second suggestion",
            "Third suggestion",
        ]);

        assert_eq!(error.suggestions.len(), 3);
    }

    #[test]
    fn test_default_severity() {
        let severity = ErrorSeverity::default();
        assert_eq!(severity, ErrorSeverity::Error);
    }

    #[test]
    fn test_convenience_functions_dont_panic() {
        // These should not panic even in Plain mode
        show_error("E001", "Test", "Message", OutputContext::Plain);
        show_warning("W001", "Test", "Message", OutputContext::Plain);
        show_info("I001", "Test", "Message", OutputContext::Plain);
    }

    #[test]
    fn test_error_panel_is_error_trait() {
        let error: Box<dyn std::error::Error> = Box::new(ErrorPanel::error("RCH-E001", "Test"));
        // Should be usable as a std::error::Error
        let _ = format!("{error}");
    }
}
